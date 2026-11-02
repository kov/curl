//! `--ssl-sessions`: TLS sessions loaded from a file before the transfers
//! and saved to it after them (`src/tool_ssls.c`), a line for each, the
//! salted HMAC of its peer's key and the session, both in base64, with a
//! colon between. The file is the user's to edit: a line that makes no
//! sense is warned of and passed over.

use std::cell::RefCell;
use std::fs::File;
use std::io::Write as _;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::easy::Easy;
use curl_core::error::ErrorKind;
use curl_core::handler::DebugKind;
use curl_core::multi::ExportFailed;
use curl_core::tls::{SessionExport, SessionFor};
use curl_os::fs::{self, Keep};

use super::Shared;
use crate::easysrc::{Pointer, Setopt};
use crate::vars::{base64, base64_decode};

/// The longest line, its newline and a zero byte counted (`MAX_SSLS_LINE`).
const MAX_LINE: usize = 64 * 1024;

/// What a file is created with, before the umask, as `fopen` does.
const NEW_FILE_MODE: u32 = 0o666;

/// `fgets`'s buffer in `get_line`, less its zero byte.
const CHUNK: usize = 127;

/// A handle to reach the share with (`tool_ssls_easy`).
fn easy(run: &Shared<'_, '_>) -> Result<Easy, ErrorKind> {
    let mut easy = Easy::new();
    easy.set_share(Some(run.share.clone()))
        .expect("a handle made now holds no connection");
    easy.set_libraries(run.linked.for_handle(run.claims));
    easy.set_components(run.global.components.clone());
    if run.tracer.is_some() {
        // A program `--libcurl` writes says so, as C's `my_setopt` does. The
        // notes stand for the debug function, which reaches no transfer.
        let mut source = run.libcurl.map(RefCell::borrow_mut);
        let mut set = Setopt::new(&mut easy, source.as_deref_mut());
        set.ptr("CURLOPT_DEBUGFUNCTION", Pointer::Function, |_| Ok(()))?;
        set.ptr("CURLOPT_DEBUGDATA", Pointer::Object, |_| Ok(()))?;
        set.long("CURLOPT_VERBOSE", 1, |o| {
            o.output.verbose = true;
            Ok(())
        })?;
    }
    Ok(easy)
}

/// What the handle traces, to the tool's trace.
fn notes(run: &Shared<'_, '_>) -> impl FnMut(DebugKind, &[u8]) {
    let tracer = run.tracer;
    move |kind, bytes| {
        if let Some(tracer) = tracer {
            tracer.note(kind, bytes);
        }
    }
}

/// Load the sessions in the file `name`, into the share (`tool_ssls_load`).
/// A file that is not there is no error. A line too long ends it all.
pub(super) fn load(run: &Shared<'_, '_>, name: &[u8]) -> Result<(), ErrorKind> {
    let opened = fs::with_c_name(name, fs::open_read);
    let Ok(file) = opened else {
        run.msgs
            .note(&[b"SSL session file does not exist (yet?): ", name]);
        return Ok(());
    };
    let easy = easy(run)?;
    let mut notes = notes(run);
    let mut lines = Lines::new(file);
    let mut line = Vec::new();
    let mut number = 0u64;
    loop {
        match lines.next_line(&mut line) {
            Got::Line => {}
            Got::End => return Ok(()),
            Got::TooLong => return Err(ErrorKind::FailedInit),
        }
        number += 1;
        import_line(run, &easy, &line, number, name, &mut notes);
    }
}

/// `n` in decimal, for a message; left out if there is no room for it.
fn digits(n: u64) -> Vec<u8> {
    curl_alloc::try_format(format_args!("{n}"))
        .map(String::into_bytes)
        .unwrap_or_default()
}

fn import_line(
    run: &Shared<'_, '_>,
    easy: &Easy,
    line: &[u8],
    number: u64,
    name: &[u8],
    notes: &mut dyn FnMut(DebugKind, &[u8]),
) {
    let n = digits(number);
    let n = n.as_slice();
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        run.msgs
            .warn(&[b"unrecognized line ", n, b" in SSL session file ", name]);
        return;
    };
    let (shmac, rest) = (&line[..colon], &line[colon + 1..]);
    let Ok(Some(shmac)) = base64_decode(shmac) else {
        run.msgs
            .warn(&[b"invalid shmax base64 encoding in line ", n]);
        return;
    };
    let rest = trimmed(rest);
    let Ok(Some(packed)) = base64_decode(rest) else {
        run.msgs
            .warn(&[b"invalid sdata base64 encoding in line ", n, b": ", rest]);
        return;
    };
    if let Err(kind) = easy.ssls_import(SessionFor::SaltedHmac(&shmac), &packed, notes) {
        let code = digits(u64::from(kind.number()));
        run.msgs.warn(&[
            b"import of session from line ",
            n,
            b" rejected(",
            &code,
            b")",
        ]);
    }
}

/// What ends a line's second part is cut: its line ending, and, if the part
/// starts with a blank, all but its first byte, as C's test has it.
fn trimmed(part: &[u8]) -> &[u8] {
    let blank_first = matches!(part.first(), Some(b' ' | b'\t'));
    let mut len = part.len();
    while len > 1 && (matches!(part[len - 1], b'\n' | b'\r') || blank_first) {
        len -= 1;
    }
    &part[..len]
}

/// What a read of a line got.
#[derive(Debug, PartialEq, Eq)]
enum Got {
    Line,
    End,
    TooLong,
}

/// The lines of a file as C's `my_get_line` reads them.
struct Lines<R> {
    file: R,
    held: [u8; 4096],
    at: usize,
    len: usize,
    eof: bool,
}

impl<R: std::io::Read> Lines<R> {
    fn new(file: R) -> Self {
        Lines {
            file,
            held: [0; 4096],
            at: 0,
            len: 0,
            eof: false,
        }
    }

    /// `fgets`: up to a whole `chunk`, ending after a newline. A read that
    /// fails reads as the end of the file, as C does not ask.
    fn fgets(&mut self, chunk: &mut [u8; CHUNK]) -> usize {
        let mut n = 0;
        while n < CHUNK {
            if self.at == self.len {
                match self.file.read(&mut self.held) {
                    Ok(got) if got > 0 => (self.at, self.len) = (0, got),
                    Ok(_) | Err(_) => {
                        self.eof = true;
                        break;
                    }
                }
            }
            let b = self.held[self.at];
            self.at += 1;
            chunk[n] = b;
            n += 1;
            if b == b'\n' {
                break;
            }
        }
        n
    }

    /// `get_line`, whose text ends at a chunk's first zero byte, the rest
    /// of the chunk lost; one that starts with it ends the file.
    fn get_line(&mut self, line: &mut Vec<u8>) -> Got {
        line.clear();
        let mut chunk = [0; CHUNK];
        loop {
            let n = self.fgets(&mut chunk);
            if n == 0 {
                return if line.is_empty() { Got::End } else { Got::Line };
            }
            let text = chunk[..n].split(|&b| b == 0).next().unwrap_or_default();
            let Some(&last) = text.last() else {
                return Got::End;
            };
            if line.len() + text.len() + 1 > MAX_LINE || line.try_extend_from_slice(text).is_err() {
                return Got::TooLong;
            }
            if last == b'\n' {
                line.pop();
                return Got::Line;
            }
            if self.eof {
                return Got::Line;
            }
        }
    }

    /// `my_get_line`: the next that is not empty, blank or a comment.
    fn next_line(&mut self, line: &mut Vec<u8>) -> Got {
        loop {
            match self.get_line(line) {
                Got::Line => {
                    let first = line.iter().find(|&&b| !matches!(b, b' ' | b'\t'));
                    if !matches!(first, None | Some(b'#')) {
                        return Got::Line;
                    }
                }
                other => return other,
            }
        }
    }
}

/// Save the sessions the share has to the file `name` (`tool_ssls_save`).
/// A file that cannot be made is warned of, and is no error.
pub(super) fn save(run: &Shared<'_, '_>, name: &[u8]) -> Result<(), ErrorKind> {
    let opened = fs::with_c_name(name, |c| fs::open_write(c, Keep::Nothing, NEW_FILE_MODE));
    let Ok(mut file) = opened else {
        run.msgs
            .warn(&[b"Warning: Failed to create SSL session file ", name]);
        return Ok(());
    };
    let easy = easy(run)?;
    let mut first = true;
    let done = easy
        .ssls_export()
        .deliver(&mut |session| save_session(run, &mut file, session, &mut first));
    let mut notes = notes(run);
    match done.end(&easy, &mut notes) {
        Ok(()) => Ok(()),
        Err(ExportFailed::Library(kind) | ExportFailed::Stopped(kind)) => Err(kind),
    }
}

/// One line, after the file's head if it is the first (`tool_ssls_exp`).
fn save_session(
    run: &Shared<'_, '_>,
    file: &mut File,
    session: SessionExport<'_>,
    first: &mut bool,
) -> Result<(), ErrorKind> {
    let said = |kind: ErrorKind| {
        let code = digits(u64::from(kind.number()));
        let key = session.key.unwrap_or(b"(nil)");
        run.msgs.warn(&[
            b"Warning: error saving SSL session for '",
            key,
            b"': ",
            &code,
        ]);
        kind
    };
    let oom = |OutOfMemory| said(ErrorKind::OutOfMemory);
    let mut line = Vec::new();
    if *first {
        line.try_extend_from_slice(
            b"# Your SSL session cache. https://curl.se/docs/ssl-sessions.html\n\
              # This file was generated by libcurl! Edit at your own risk.\n",
        )
        .map_err(oom)?;
    }
    let hmac = base64(session.salted_hmac).map_err(oom)?;
    let packed = base64(session.packed).map_err(oom)?;
    for part in [&hmac[..], b":", &packed[..], b"\n"] {
        line.try_extend_from_slice(part).map_err(oom)?;
    }
    file.write_all(&line)
        .map_err(|_| said(ErrorKind::WriteError))?;
    *first = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines_of(text: &[u8]) -> (Vec<Vec<u8>>, Got) {
        let mut lines = Lines::new(text);
        let mut line = Vec::new();
        let mut all = Vec::new();
        loop {
            match lines.next_line(&mut line) {
                Got::Line => all.push(line.clone()),
                other => return (all, other),
            }
        }
    }

    /// Empty lines, blank ones and comments are passed over, and a last
    /// line needs no newline, as `my_get_line` has it.
    #[test]
    fn lines_read_as_c_reads_them() {
        let (lines, end) = lines_of(b"# head\n\n  \t\n  # blanks first\na:b\r\nc:d");
        assert_eq!(lines, [b"a:b\r".to_vec(), b"c:d".to_vec()]);
        assert_eq!(end, Got::End);
    }

    /// A line of the most a dynbuf holds is read; one byte more is an error
    /// that ends the file, however it arrives in chunks.
    #[test]
    fn a_line_past_the_most_ends_it_all() {
        // Its newline counts, and a zero byte: 65535 with the newline fits.
        let mut most = vec![b'a'; MAX_LINE - 2];
        most.push(b'\n');
        assert_eq!(lines_of(&most).1, Got::End);
        assert_eq!(lines_of(&most).0[0].len(), MAX_LINE - 2);
        let over = [vec![b'a'; MAX_LINE - 1], vec![b'\n']].concat();
        assert_eq!(lines_of(&over).1, Got::TooLong);
    }

    /// A chunk's text ends at a zero byte, what follows in the chunk lost,
    /// its newline with it, so the next chunk joins the line; a chunk that
    /// starts with one ends the file.
    #[test]
    fn a_zero_byte_ends_a_chunk() {
        assert_eq!(lines_of(b"a\0lost\nb:c\n").0, [b"ab:c".to_vec()]);
        let (lines, end) = lines_of(b"a:b\n\0c:d\n");
        assert_eq!((lines, end), (vec![b"a:b".to_vec()], Got::End));
    }

    /// The line ending goes; if the part starts with a blank so does all
    /// else but that blank, as C's test reads the wrong end.
    #[test]
    fn the_second_part_is_cut_as_c_cuts_it() {
        assert_eq!(trimmed(b"abcd\r\n"), b"abcd");
        assert_eq!(trimmed(b"ab cd "), b"ab cd ");
        assert_eq!(trimmed(b" abcd"), b" ");
        assert_eq!(trimmed(b""), b"");
        assert_eq!(trimmed(b"\n"), b"\n");
    }
}
