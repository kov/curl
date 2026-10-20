//! Messages to the user on standard error, as `src/tool_msgs.c` writes
//! them: `curl: ` errors, `Warning: ` warnings, each wrapped at the
//! terminal's width, and the hint after a command-line error.
//!
//! A message is a list of byte strings, written as they are: parts of it
//! come from the command line, which need not be UTF-8.

use std::io::Write as _;

/// Whether this build has the built-in manual. It has not: `--manual` says
/// so, and the hint after an error does not offer it.
pub(crate) const MANUAL: bool = false;

/// The width used when the terminal's is unknown, as C's.
const DEFAULT_COLUMNS: usize = 79;

/// Where messages go, and which are muted.
pub(crate) struct Messages {
    /// `--silent`: no warnings, and no errors unless `--show-error`.
    pub(crate) silent: bool,
    /// `--show-error`.
    pub(crate) show_error: bool,
    columns: usize,
}

impl Messages {
    /// Messages wrapped at `COLUMNS` when it holds a width over 20, as
    /// `get_terminal_columns` reads it.
    ///
    /// C then asks the terminal; this falls back to 79 columns, C's value
    /// when that fails too, until the tool has an interface to the
    /// terminal.
    pub(crate) fn new() -> Self {
        let columns = std::env::var_os("COLUMNS")
            .and_then(|c| {
                let c = c.as_encoded_bytes();
                let digits = c.iter().take_while(|b| b.is_ascii_digit()).count();
                std::str::from_utf8(&c[..digits])
                    .ok()?
                    .parse::<usize>()
                    .ok()
            })
            .filter(|&n| n > 20 && n <= 10000)
            .unwrap_or(DEFAULT_COLUMNS);
        Messages {
            silent: false,
            show_error: false,
            columns,
        }
    }

    /// The terminal's width.
    pub(crate) fn columns(&self) -> usize {
        self.columns
    }

    /// `errorf`: `curl: ` and the message, unless muted.
    pub(crate) fn error(&self, message: &[&[u8]]) {
        if !self.silent || self.show_error {
            self.wrapped(b"curl: ", message);
        }
    }

    /// `warnf`: `Warning: ` and the message, unless muted.
    pub(crate) fn warn(&self, message: &[&[u8]]) {
        if !self.silent {
            self.wrapped(b"Warning: ", message);
        }
    }

    /// `helpf`: a command-line error, never muted, then where to look for
    /// help. An empty message prints only the hint.
    pub(crate) fn help(&self, message: &[&[u8]]) {
        let mut out = Text::new();
        if !message.is_empty() {
            out.push(b"curl: ");
            for part in message {
                out.push(part);
            }
            out.push(b"\n");
        }
        out.push(if MANUAL {
            b"curl: try 'curl --help' or 'curl --manual' for more information\n"
        } else {
            b"curl: try 'curl --help' for more information\n"
        });
        emit(out.bytes());
    }

    /// `voutf`: the message, cut into lines that fit the terminal after
    /// `prefix`, breaking at blanks where it can.
    fn wrapped(&self, prefix: &[u8], message: &[&[u8]]) {
        let mut text = Text::new();
        for part in message {
            text.push(part);
        }
        let width = self
            .columns
            .checked_sub(prefix.len())
            .filter(|&w| w > 0)
            .unwrap_or(usize::MAX);
        let mut out = Text::new();
        let mut rest = text.bytes();
        while !rest.is_empty() {
            out.push(prefix);
            if rest.len() > width {
                let blank = |b: &u8| *b == b' ' || *b == b'\t';
                let cut = (1..width)
                    .rev()
                    .find(|&i| blank(&rest[i]))
                    .unwrap_or(width - 1);
                out.push(&rest[..=cut]);
                out.push(b"\n");
                rest = &rest[cut + 1..];
            } else {
                out.push(rest);
                out.push(b"\n");
                rest = b"";
            }
            emit(out.bytes());
            out.clear();
        }
    }
}

/// Write to standard error. A failed write has nowhere to be reported,
/// as in C.
fn emit(bytes: &[u8]) {
    let _ = std::io::stderr().write_all(bytes);
}

/// A message, built on the stack and cut at 1023 bytes as C's buffer cuts
/// it.
struct Text {
    buf: [u8; 1024],
    len: usize,
}

impl Text {
    fn new() -> Self {
        Text {
            buf: [0; 1024],
            len: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(self.buf.len() - 1 - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}
