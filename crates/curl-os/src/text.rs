//! The C library's text mode. C's tool and library open some files and
//! streams as text (`FOPEN_READTEXT`, `FOPEN_WRITETEXT`, standard error,
//! standard output until it is made binary), and on Windows the UCRT
//! translates their line ends there: a write puts a carriage return
//! before each line feed, and a read takes a carriage return before a
//! line feed as the line feed alone and ends at a Ctrl-Z, after which the
//! file reads as ended. On Unix text is binary.
//!
//! [`Writer`] and [`Reader`] translate what passes through them as the
//! UCRT does, in [`Mode::Text`]; in [`Mode::Binary`] they pass it as it
//! is. Their translation is the same on every platform, so it is tested
//! everywhere; what is opened as text is [`Mode::TEXT`], binary but on
//! Windows.

use std::io;

/// How a file or a stream is opened: as text, its line ends translated,
/// or as binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Text,
    Binary,
}

impl Mode {
    /// What C's text modes open a file in (`"rt"`, `"wt"`, `"at"`): text
    /// on Windows, where the C library translates line ends, and binary
    /// on Unix, where it has nothing to translate.
    pub const TEXT: Mode = if cfg!(windows) {
        Mode::Text
    } else {
        Mode::Binary
    };
}

/// The byte that ends a file read as text (`CTRLZ`).
const CTRL_Z: u8 = 0x1a;

/// What a translated write is built in before it is written.
const CHUNK: usize = 1024;

/// A writer that writes each line feed as a carriage return and a line
/// feed in [`Mode::Text`], as the UCRT's `_write` does in text mode; any
/// other byte, a carriage return or a Ctrl-Z among them, goes as it is.
#[derive(Debug)]
pub struct Writer<W> {
    inner: W,
    mode: Mode,
}

impl<W> Writer<W> {
    pub fn new(inner: W, mode: Mode) -> Writer<W> {
        Writer { inner, mode }
    }

    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: io::Write> io::Write for Writer<W> {
    /// Some of `buf`, translated and written whole: how much of `buf`
    /// that was.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.mode == Mode::Binary {
            return self.inner.write(buf);
        }
        let mut out = [0u8; CHUNK];
        let mut n = 0;
        let mut took = 0;
        for &b in buf {
            let need = if b == b'\n' { 2 } else { 1 };
            if n + need > out.len() {
                break;
            }
            if b == b'\n' {
                out[n] = b'\r';
                n += 1;
            }
            out[n] = b;
            n += 1;
            took += 1;
        }
        self.inner.write_all(&out[..n])?;
        Ok(took)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A reader that, in [`Mode::Text`], gives a carriage return before a line
/// feed as the line feed alone and ends at the first Ctrl-Z, as the
/// UCRT's `_read` reads a file in text mode: a carriage return before
/// anything else, or at the end, is kept, and nothing is read past the
/// Ctrl-Z, then or later.
#[derive(Debug)]
pub struct Reader<R> {
    inner: R,
    mode: Mode,
    /// Read from `inner`, not given yet: `buf[at..end]`.
    buf: [u8; CHUNK],
    at: usize,
    end: usize,
    /// A Ctrl-Z was read: the file has ended.
    ended: bool,
}

impl<R> Reader<R> {
    pub fn new(inner: R, mode: Mode) -> Reader<R> {
        Reader {
            inner,
            mode,
            buf: [0; CHUNK],
            at: 0,
            end: 0,
            ended: false,
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }
}

impl<R: io::Read> io::Read for Reader<R> {
    /// What is there to give, translated, reading `inner` only when
    /// nothing is held and once more for a carriage return held last.
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.mode == Mode::Binary {
            return self.inner.read(out);
        }
        let mut n = 0;
        while n < out.len() && !self.ended {
            if self.at == self.end {
                if n > 0 {
                    break;
                }
                self.end = self.inner.read(&mut self.buf)?;
                self.at = 0;
                if self.end == 0 {
                    break;
                }
            }
            let b = self.buf[self.at];
            if b == CTRL_Z {
                self.ended = true;
                break;
            }
            if b == b'\r' && self.at + 1 == self.end {
                // What follows is not read yet: the carriage return is
                // kept for it.
                self.buf[0] = b'\r';
                self.at = 0;
                self.end = 1 + self.inner.read(&mut self.buf[1..])?;
            }
            if b == b'\r' && self.at + 1 < self.end && self.buf[self.at + 1] == b'\n' {
                out[n] = b'\n';
                self.at += 2;
            } else {
                out[n] = b;
                self.at += 1;
            }
            n += 1;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use super::*;
    use std::io::{Read as _, Write as _};

    fn written(mode: Mode, writes: &[&[u8]]) -> Vec<u8> {
        let mut w = Writer::new(Vec::new(), mode);
        for bytes in writes {
            w.write_all(bytes).unwrap();
        }
        w.into_inner()
    }

    /// As the UCRT writes `"wt"` (measured on Windows 11): each line feed
    /// after a carriage return, one already before it, or one written
    /// before in a write of its own; nothing else changes.
    #[test]
    fn writes_each_line_feed_after_a_carriage_return() {
        let writes: &[&[u8]] = &[b"a\nb\r\nc\rd", b"\r", b"\ne\x1af\n"];
        assert_eq!(
            written(Mode::Text, writes),
            b"a\r\nb\r\r\nc\rd\r\r\ne\x1af\r\n"
        );
        assert_eq!(written(Mode::Binary, writes), b"a\nb\r\nc\rd\r\ne\x1af\n");
    }

    /// A write longer than the chunk is taken in parts, each line feed
    /// whole in one.
    #[test]
    fn a_long_write_goes_in_parts() {
        let line = [b'\n'; CHUNK];
        let mut w = Writer::new(Vec::new(), Mode::Text);
        assert_eq!(w.write(&line).unwrap(), CHUNK / 2);
        let mut odd = vec![b'x'; CHUNK - 1];
        odd.push(b'\n');
        let mut w = Writer::new(Vec::new(), Mode::Text);
        assert_eq!(w.write(&odd).unwrap(), CHUNK - 1);
        assert_eq!(written(Mode::Text, &[&odd]).len(), CHUNK + 1);
    }

    /// A sink that takes at most `each` bytes a read.
    struct Trickle<'a> {
        bytes: &'a [u8],
        each: usize,
    }

    impl io::Read for Trickle<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.each.min(out.len()).min(self.bytes.len());
            out[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Ok(n)
        }
    }

    fn read(mode: Mode, bytes: &[u8], each: usize, out: usize) -> Vec<u8> {
        let mut r = Reader::new(Trickle { bytes, each }, mode);
        let mut got = Vec::new();
        let mut buf = vec![0; out];
        loop {
            match r.read(&mut buf).unwrap() {
                0 => return got,
                n => got.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// As the UCRT reads `"rt"` (measured on Windows 11): a carriage
    /// return before a line feed is left out, one before anything else or
    /// at the end is kept, and a Ctrl-Z ends the file, whatever the reads
    /// of the file and of the reader are cut into.
    #[test]
    fn reads_a_line_end_as_its_line_feed_up_to_a_ctrl_z() {
        let file = b"a\r\nb\rc\r\r\nd\x1ae\r\n";
        for each in [1, 2, 3, 5, CHUNK] {
            for out in [1, 2, 7, 4096] {
                assert_eq!(
                    read(Mode::Text, file, each, out),
                    b"a\nb\rc\r\nd",
                    "{each} {out}"
                );
                assert_eq!(read(Mode::Binary, file, each, out), file);
                assert_eq!(read(Mode::Text, b"x\r", each, out), b"x\r");
                assert_eq!(read(Mode::Text, b"\r\r", each, out), b"\r\r");
            }
        }
    }

    /// Nothing is read past a Ctrl-Z, however often it is asked.
    #[test]
    fn a_ctrl_z_ends_the_file_for_good() {
        let mut r = Reader::new(&b"a\x1ab"[..], Mode::Text);
        let mut buf = [0; 8];
        assert_eq!(r.read(&mut buf).unwrap(), 1);
        assert_eq!(r.read(&mut buf).unwrap(), 0);
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }

    /// Only Windows opens text as text.
    #[test]
    fn text_is_binary_but_on_windows() {
        assert_eq!(Mode::TEXT == Mode::Text, cfg!(windows));
    }
}
