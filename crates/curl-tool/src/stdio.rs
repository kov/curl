//! A stream written as glibc's stdio writes a `FILE`: C's tool writes its
//! output with `fwrite` and finds out a write failed from what `fwrite`
//! returns, or only at `fflush` or `fclose`, so the rewrite holds bytes and
//! writes them in the same pieces at the same moments (glibc's
//! `libio/fileops.c`, `_IO_new_file_xsputn` and what it calls).

use std::fs::File;
use std::io::{self, IsTerminal as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

use curl_alloc::TryVec as _;

/// glibc's `BUFSIZ`: the largest buffer it gives a stream.
const BUFSIZ: usize = 8192;

/// A block size under this is not kept to whole blocks when writing past
/// the buffer.
const SMALL_BLOCK: usize = 128;

/// Where the bytes go: one `write(2)` at a time.
pub(crate) trait Sink {
    /// Write some of `bytes`, as one `write(2)` does.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize>;
    /// How glibc buffers it (`_IO_file_doallocate`): `BUFSIZ`, or the
    /// file's block size when smaller; a line at a time on a terminal.
    fn layout(&self) -> Layout;
    /// Let go of it (`close(2)`): whether that went.
    fn close(self) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    pub(crate) size: usize,
    /// Written as each line ends (`_IO_LINE_BUF`).
    pub(crate) line: bool,
}

impl Layout {
    /// What glibc gives a stream it cannot `fstat`.
    pub(crate) const UNKNOWN: Layout = Layout {
        size: BUFSIZ,
        line: false,
    };
}

impl Sink for File {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        io::Write::write(self, bytes)
    }

    fn layout(&self) -> Layout {
        let mut layout = Layout::UNKNOWN;
        if let Ok(meta) = self.metadata() {
            layout.line = meta.file_type().is_char_device() && self.is_terminal();
            let block = meta.blksize();
            if block > 0 && block < BUFSIZ as u64 {
                layout.size = block as usize;
            }
        }
        layout
    }

    fn close(self) -> io::Result<()> {
        curl_os::fs::close(self)
    }
}

/// A write, or the write of what was held, failed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Failed;

/// A stream opened for writing, as stdio keeps one (`FILE`).
pub(crate) struct Stdio<S: Sink> {
    /// Taken only as the stream is closed.
    sink: Option<S>,
    /// What is held, allocated at the first write.
    buf: Option<Buffer>,
    /// A write failed since the stream was opened (`ferror`).
    failed: bool,
}

struct Buffer {
    held: Vec<u8>,
    layout: Layout,
}

impl<S: Sink> Stdio<S> {
    pub(crate) fn new(sink: S) -> Stdio<S> {
        Stdio {
            sink: Some(sink),
            buf: None,
            failed: false,
        }
    }

    pub(crate) fn get_ref(&self) -> &S {
        self.sink.as_ref().expect("open until closed")
    }

    /// The sink, for calls on the stream's descriptor; what is held is
    /// for the caller to have flushed.
    pub(crate) fn get_mut(&mut self) -> &mut S {
        self.sink.as_mut().expect("open until closed")
    }

    /// A write failed since the stream was opened (`ferror`).
    pub(crate) fn failed(&self) -> bool {
        self.failed
    }

    /// Write `data`: how much of it was taken (`fwrite`, whose count may
    /// say all was taken though writing it failed).
    pub(crate) fn fwrite(&mut self, data: &[u8]) -> usize {
        let n = data.len();
        if n == 0 {
            return 0;
        }
        let mut to_do = n;
        let mut at = 0;
        let mut must_flush = false;
        // First what fits in the buffer, up to the last line end of a
        // line buffer.
        let mut count = 0;
        if let Some(buf) = &self.buf {
            count = buf.layout.size - buf.held.len();
            if buf.layout.line
                && count >= n
                && let Some(p) = data.iter().rposition(|&b| b == b'\n')
            {
                count = p + 1;
                must_flush = true;
            }
        }
        if count > 0 {
            let count = count.min(to_do);
            let buf = self.buf.as_mut().expect("space is counted in a buffer");
            buf.held
                .try_extend_from_slice(&data[..count])
                .expect("the buffer is reserved whole");
            at += count;
            to_do -= count;
        }
        if to_do > 0 || must_flush {
            // The buffer written out, or made.
            let block = match &self.buf {
                Some(buf) => {
                    let size = buf.layout.size;
                    if self.write_held().is_err() {
                        // A count of all reads as all taken.
                        return if to_do == 0 { n } else { n - to_do };
                    }
                    size
                }
                None => match self.allocate() {
                    Some(size) => size,
                    // Unbuffered.
                    None => return self.write_out(data),
                },
            };
            // Then whole blocks, past the buffer.
            let direct = if block >= SMALL_BLOCK {
                to_do - to_do % block
            } else {
                to_do
            };
            if direct > 0 {
                let wrote = self.write_out(&data[at..at + direct]);
                to_do -= wrote;
                if wrote < direct {
                    return n - to_do;
                }
                at += direct;
            }
            if to_do > 0 {
                to_do -= self.put(&data[at..]);
            }
        }
        n - to_do
    }

    /// Write what is held (`fflush`).
    pub(crate) fn flush(&mut self) -> Result<(), Failed> {
        match &self.buf {
            Some(buf) if !buf.held.is_empty() => self.write_held(),
            _ => Ok(()),
        }
    }

    /// The buffer, as glibc sizes it; `None` if it cannot be had, and the
    /// stream is then unbuffered.
    fn allocate(&mut self) -> Option<usize> {
        let layout = self.get_ref().layout();
        let mut held = Vec::new();
        held.try_reserve_exact(layout.size).ok()?;
        self.buf = Some(Buffer { held, layout });
        Some(layout.size)
    }

    /// The rest of `data`, less than a block, into the buffer; on a line
    /// buffer a byte at a time, written as each line ends
    /// (`_IO_default_xsputn`). How much was taken.
    fn put(&mut self, data: &[u8]) -> usize {
        let mut at = 0;
        loop {
            let buf = self.buf.as_mut().expect("allocated before");
            if !buf.layout.line {
                let space = buf.layout.size - buf.held.len();
                let count = space.min(data.len() - at);
                buf.held
                    .try_extend_from_slice(&data[at..at + count])
                    .expect("the buffer is reserved whole");
                at += count;
            }
            if at == data.len() {
                return at;
            }
            // `_IO_new_file_overflow` with the next byte, which is not
            // counted taken if a write fails.
            let ch = data[at];
            if buf.held.len() == buf.layout.size && self.write_held().is_err() {
                return at;
            }
            let buf = self.buf.as_mut().expect("allocated before");
            buf.held.try_push(ch).expect("the buffer is reserved whole");
            if buf.layout.line && ch == b'\n' && self.write_held().is_err() {
                return at;
            }
            at += 1;
        }
    }

    /// Write what is held; it is dropped whether or not it all went
    /// (`_IO_new_do_write`).
    fn write_held(&mut self) -> Result<(), Failed> {
        let mut buf = self.buf.take().expect("allocated before");
        let wrote = self.write_out(&buf.held);
        let all = wrote == buf.held.len();
        buf.held.clear();
        self.buf = Some(buf);
        if all { Ok(()) } else { Err(Failed) }
    }

    /// Write `data` straight through until done or a write fails, which
    /// is not tried again (`_IO_new_file_write`). How much was written.
    fn write_out(&mut self, data: &[u8]) -> usize {
        let mut at = 0;
        while at < data.len() {
            match self.get_mut().write(&data[at..]) {
                // A write that takes nothing would be tried forever.
                Ok(0) | Err(_) => {
                    self.failed = true;
                    break;
                }
                Ok(wrote) => at += wrote,
            }
        }
        at
    }
}

impl<S: Sink> Drop for Stdio<S> {
    /// What is held is written at the end, as `fclose` and `exit` do; a
    /// failure then is for whoever flushed or closed first to report.
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Close `stream` (`fclose`): what is held written, then the sink let
/// go of, whichever fails; whether both went.
pub(crate) fn close<S: Sink>(mut stream: Stdio<S>) -> Result<(), Failed> {
    let flushed = stream.flush();
    let sink = stream.sink.take().expect("open until closed");
    let closed = sink.close().map_err(|_| Failed);
    flushed.and(closed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that takes up to `room` bytes, then fails; each write is
    /// recorded. Its close fails if `close_fails`.
    struct Script {
        layout: Layout,
        room: usize,
        writes: Vec<usize>,
        close_fails: bool,
    }

    impl Sink for Script {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.room == 0 {
                return Err(io::Error::from_raw_os_error(28));
            }
            let n = bytes.len().min(self.room);
            self.room -= n;
            self.writes.push(n);
            Ok(n)
        }
        fn layout(&self) -> Layout {
            self.layout
        }
        fn close(self) -> io::Result<()> {
            match self.close_fails {
                true => Err(io::Error::from_raw_os_error(5)),
                false => Ok(()),
            }
        }
    }

    fn stream(size: usize, line: bool, room: usize) -> Stdio<Script> {
        Stdio::new(Script {
            layout: Layout { size, line },
            room,
            writes: Vec::new(),
            close_fails: false,
        })
    }

    /// A close fails if writing what is held fails, or if letting go of
    /// the sink does though all was written (`fclose` returning `EOF`
    /// when `close(2)` fails).
    #[test]
    fn a_close_fails_with_the_sink_s() {
        let mut s = stream(4096, false, usize::MAX);
        s.fwrite(b"held");
        assert_eq!(close(s), Ok(()));
        let mut s = stream(4096, false, usize::MAX);
        s.fwrite(b"held");
        s.get_mut().close_fails = true;
        assert_eq!(close(s), Err(Failed));
        let mut s = stream(4096, false, 2);
        s.fwrite(b"held");
        assert_eq!(close(s), Err(Failed));
    }

    /// The first write makes the buffer and writes the whole blocks past
    /// it; the rest waits. Later writes fill the buffer first.
    #[test]
    fn writes_whole_blocks_and_holds_the_rest() {
        let mut s = stream(4096, false, usize::MAX);
        assert_eq!(s.fwrite(&[1; 16384]), 16384);
        assert_eq!(s.get_ref().writes, [16384]);
        assert_eq!(s.fwrite(&[1; 3000]), 3000);
        assert_eq!(s.get_ref().writes, [16384]);
        // 1096 fill the buffer, which goes; then two blocks, 1000 held.
        assert_eq!(s.fwrite(&[1; 10288]), 10288);
        assert_eq!(s.get_ref().writes, [16384, 4096, 8192]);
        assert_eq!(s.flush(), Ok(()));
        assert_eq!(s.get_ref().writes, [16384, 4096, 8192, 1000]);
        assert!(!s.failed());
    }

    /// What a failed write leaves `fwrite` to return, as on the C build:
    /// nothing, with the buffer new; what fit in the buffer, when writing
    /// it fails; what the descriptor took before it failed.
    #[test]
    fn counts_what_was_taken_as_glibc_does() {
        // `-o /dev/full`, the first piece.
        let mut s = stream(4096, false, 0);
        assert_eq!(s.fwrite(&[1; 16384]), 0);
        assert!(s.failed());
        // The next fills the buffer, whose write fails.
        assert_eq!(s.fwrite(&[1; 16384]), 4096);
        // A file system with 4096 bytes free.
        let mut s = stream(4096, false, 4096);
        assert_eq!(s.fwrite(&[1; 16384]), 4096);
        // Less than a block is held, and fails only when written.
        let mut s = stream(4096, false, 0);
        assert_eq!(s.fwrite(&[1; 3000]), 3000);
        assert!(!s.failed());
        assert_eq!(s.flush(), Err(Failed));
        assert!(s.failed());
        // What could not be written is dropped.
        assert_eq!(s.flush(), Ok(()));
    }

    /// A line buffer writes through the last line end of what fits, and
    /// holds the rest.
    #[test]
    fn a_line_buffer_writes_each_line() {
        let mut s = stream(4096, true, usize::MAX);
        assert_eq!(s.fwrite(b"a\nb"), 3);
        // The first write makes the buffer: its bytes go a byte at a time,
        // written at the line's end.
        assert_eq!(s.get_ref().writes, [2]);
        assert_eq!(s.fwrite(b"c\nd\ne"), 5);
        assert_eq!(s.get_ref().writes, [2, 5]);
        assert_eq!(s.fwrite(b"f"), 1);
        assert_eq!(s.get_ref().writes, [2, 5]);
        assert_eq!(s.flush(), Ok(()));
        assert_eq!(s.get_ref().writes, [2, 5, 2]);
        // A line end whose write fails is not counted, nor what follows.
        let mut s = stream(4096, true, 0);
        assert_eq!(s.fwrite(b"x"), 1);
        assert_eq!(s.fwrite(&[b'y'; 4096]), 4095);
        // Whatever fit up to the line end reads as all taken.
        let mut s = stream(4096, true, 0);
        assert_eq!(s.fwrite(b"x"), 1);
        assert_eq!(s.fwrite(b"y\n"), 2);
        assert!(s.failed());
    }

    /// The buffer is `BUFSIZ`, or the file's block size when smaller.
    #[test]
    fn sizes_the_buffer_by_the_block() {
        let file = File::open("/dev/null").unwrap();
        let layout = Sink::layout(&file);
        let block = file.metadata().unwrap().blksize() as usize;
        assert_eq!(
            layout.size,
            if block > 0 { block.min(BUFSIZ) } else { BUFSIZ }
        );
        assert!(!layout.line);
    }
}
