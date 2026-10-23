//! The built-in manual: all of it for `--manual` (`hugehelp`), or one
//! option's part for `--help <option>` (`showhelp`, `helpscan` in
//! `src/tool_help.c`). The text is inflated as it is shown, a piece at a
//! time, as C's is.

use std::fmt;
use std::io::Write as _;

use curl_core::coding::Sink;
use curl_core::error::ErrorKind;

use crate::manual::GZIPPED;

/// Hands each piece the inflater makes to `each`, which says whether
/// to go on.
struct Pieces<'f>(&'f mut dyn FnMut(&[u8]) -> bool);

impl Sink for Pieces<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        // Stopping is a failure to the inflater, which then stops.
        if (self.0)(bytes) {
            Ok(())
        } else {
            Err(ErrorKind::WriteError)
        }
    }

    fn timed_out(&self) -> bool {
        false
    }

    fn fail(&mut self, kind: ErrorKind, _: fmt::Arguments<'_>) -> ErrorKind {
        kind
    }
}

/// Give the manual to `each` a piece at a time, until it says stop or
/// the text ends. One that cannot be inflated ends where it fails, as
/// C's does, unsaid.
fn inflate(each: &mut dyn FnMut(&[u8]) -> bool) {
    let Ok(mut gzip) = curl_zlib::gzip() else {
        return;
    };
    // Nothing is said of a failure, as in C.
    let _ = gzip.decode(GZIPPED, &mut Pieces(each));
}

/// `--manual`: the whole manual on standard output. A failed write has
/// nowhere to be said, as in C.
pub(crate) fn show_all() {
    let mut stdout = std::io::stdout().lock();
    inflate(&mut |piece| stdout.write_all(piece).is_ok());
    let _ = stdout.flush();
}

/// Where in the manual one option's text is: after `trigger`, from
/// `arg` (shown without its first byte) to before `end`
/// (`struct scan_ctx`).
struct Scan<'a> {
    trigger: &'a [u8],
    arg: &'a [u8],
    end: &'a [u8],
    /// 0 before the trigger, 1 before the option, 2 in its text.
    show: u8,
    /// The last bytes read, in a buffer each search shifts through as
    /// far as its own length (`rbuf`).
    recent: [u8; 40],
    /// The line being shown (`obuf`).
    line: [u8; 160],
    line_len: usize,
}

impl<'a> Scan<'a> {
    fn new(trigger: &'a [u8], arg: &'a [u8], end: &'a [u8]) -> Scan<'a> {
        for s in [trigger, arg, end] {
            assert!(!s.is_empty() && s.len() < 40, "the searches fit the buffer");
        }
        Scan {
            trigger,
            arg,
            end,
            show: 0,
            recent: [0; 40],
            line: [0; 160],
            line_len: 0,
        }
    }

    /// Shift `b` into the first `len` bytes of the buffer; whether they
    /// are then `want`.
    fn shift(&mut self, b: u8, want: &[u8]) -> bool {
        let len = want.len();
        self.recent.copy_within(1..len, 0);
        self.recent[len - 1] = b;
        self.recent[..len] == *want
    }

    /// Read `piece`, writing what is shown to `out`; whether to go on
    /// (`helpscan`).
    fn scan(&mut self, piece: &[u8], out: &mut dyn FnMut(&[u8])) -> bool {
        for &b in piece {
            match self.show {
                0 => {
                    if self.shift(b, self.trigger) {
                        self.show = 1;
                    }
                }
                1 => {
                    if self.shift(b, self.arg) {
                        out(&self.arg[1..]);
                        self.show = 2;
                    }
                }
                _ => {
                    if self.shift(b, self.end) {
                        return false;
                    }
                    // A line longer than the buffer ends it.
                    if self.line_len == self.line.len() {
                        return false;
                    }
                    if b == b'\n' {
                        out(&self.line[..self.line_len]);
                        out(b"\n");
                        self.line_len = 0;
                    } else {
                        self.line[self.line_len] = b;
                        self.line_len += 1;
                    }
                }
            }
        }
        true
    }
}

/// `--help <option>`: the manual's text of the option that starts with
/// `arg`, up to `end` (`showhelp`).
pub(crate) fn show_option(arg: &[u8], end: &[u8]) {
    let mut scan = Scan::new(b"\nALL OPTIONS\n", arg, end);
    let mut stdout = std::io::stdout().lock();
    inflate(&mut |piece| {
        scan.scan(piece, &mut |shown| {
            let _ = stdout.write_all(shown);
        })
    });
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text() -> Vec<u8> {
        let mut all = Vec::new();
        inflate(&mut |piece| {
            all.extend_from_slice(piece);
            true
        });
        all
    }

    /// The manual inflates to the text the generator made.
    #[test]
    fn inflates_to_the_generated_text() {
        let all = text();
        assert_eq!(all.len(), crate::manual::LEN);
        let hash = all.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, &b| {
            (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
        });
        assert_eq!(hash, crate::manual::HASH);
        assert!(all.starts_with(b"          _   _ ____  _\n"));
    }

    fn scanned(text: &[u8], arg: &[u8], end: &[u8], piece: usize) -> String {
        let mut scan = Scan::new(b"\nALL OPTIONS\n", arg, end);
        let mut out = Vec::new();
        for chunk in text.chunks(piece) {
            if !scan.scan(chunk, &mut |s| out.extend_from_slice(s)) {
                break;
            }
        }
        String::from_utf8(out).unwrap()
    }

    /// An option's text runs from its line to the next option's, read in
    /// pieces of any size; one named before the trigger is not found.
    #[test]
    fn shows_an_option_as_c_does() {
        let text = b"\n    -a, --all\n\nALL OPTIONS\n\n    -a, --all\n\tA text.\n\n    -b, --b\n\tB.\n\nFILES\n";
        for piece in [1, 3, 1000] {
            assert_eq!(
                scanned(text, b"\n    -a, --", b"\n    -", piece),
                "    -a, --all\n\tA text.\n\n"
            );
            assert_eq!(
                scanned(text, b"\n    -b, --", b"\nFILES", piece),
                "    -b, --b\n\tB.\n\n"
            );
            assert_eq!(scanned(text, b"\n    --c", b"\n    -", piece), "");
        }
        // A line longer than C's buffer ends the text.
        let mut long = b"\nALL OPTIONS\n\n    --x\n".to_vec();
        long.extend_from_slice(&[b'y'; 200]);
        long.extend_from_slice(b"\nmore\n");
        assert_eq!(scanned(&long, b"\n    --x", b"\n    -", 64), "    --x\n");
    }
}
