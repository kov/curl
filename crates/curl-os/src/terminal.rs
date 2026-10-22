//! The terminal the process writes to, and reads a password from.

#![allow(unsafe_code)]

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

/// The width of the terminal on standard input, output or error, the
/// first that is one, as `get_terminal_columns` asks in C. `None` when
/// none is a terminal.
pub fn columns() -> Option<u16> {
    [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]
        .into_iter()
        .find_map(|fd| {
            let mut size = libc::winsize {
                ws_row: 0,
                ws_col: 0,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            // SAFETY: `TIOCGWINSZ` writes a `winsize` to the pointer, which
            // points to one; any descriptor is accepted, and one that is
            // not a terminal fails.
            let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &raw mut size) };
            (rc == 0).then_some(size.ws_col)
        })
}

/// Where a password is typed (`getpass_r`): the controlling terminal,
/// `/dev/tty`, or standard input when there is none, with the terminal's
/// echo off until this is dropped.
#[derive(Debug)]
pub struct Unechoed {
    /// `/dev/tty`, or `None` for standard input, which is not ours to
    /// close.
    tty: Option<OwnedFd>,
    /// The settings echo was turned off from, put back on drop; `None`
    /// when they could not be read, as from a pipe.
    saved: Option<libc::termios>,
}

impl Unechoed {
    /// Open `/dev/tty`, or else take standard input, and turn its echo
    /// off.
    pub fn open() -> Unechoed {
        // SAFETY: the path is a NUL-terminated string that outlives the
        // call; `open` makes a new descriptor or fails.
        let fd = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        // SAFETY: a descriptor `open` returned is new, owned by nothing
        // else.
        let tty = (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) });
        let mut this = Unechoed { tty, saved: None };
        // SAFETY: `termios` is plain integers and arrays, for which all
        // zeros is a value; `tcgetattr` overwrites it.
        let mut settings: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: the descriptor is open for the call (ours, or standard
        // input's), and `tcgetattr` writes a `termios` to the pointer,
        // which points to one; one that is not a terminal fails.
        if unsafe { libc::tcgetattr(this.fd(), &raw mut settings) } == 0 {
            let mut quiet = settings;
            quiet.c_lflag &= !libc::ECHO;
            // SAFETY: as above, and `tcsetattr` only reads the `termios`.
            // A failure leaves echo on, as it does in C.
            unsafe { libc::tcsetattr(this.fd(), libc::TCSANOW, &raw const quiet) };
            this.saved = Some(settings);
        }
        this
    }

    fn fd(&self) -> RawFd {
        self.tty
            .as_ref()
            .map_or(libc::STDIN_FILENO, |tty| tty.as_raw_fd())
    }

    /// One read into `buf`, as much as one `read` gives: the bytes read,
    /// none at the end or on any failure.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        // SAFETY: the descriptor is open for the call, and `read` writes
        // at most `buf.len()` bytes to `buf`, which is borrowed mutably
        // for it.
        let n = unsafe { libc::read(self.fd(), buf.as_mut_ptr().cast(), buf.len()) };
        usize::try_from(n).unwrap_or(0)
    }
}

impl Drop for Unechoed {
    /// Put echo back as it was, dropping what was typed and not read
    /// (`TCSAFLUSH`, as C restores it).
    fn drop(&mut self) {
        if let Some(saved) = self.saved {
            // SAFETY: the descriptor is still open, `tty` is dropped after
            // this; `tcsetattr` only reads the `termios`.
            unsafe { libc::tcsetattr(self.fd(), libc::TCSAFLUSH, &raw const saved) };
        }
    }
}

#[cfg(test)]
mod tests {
    /// Under `cargo test` the standard streams are pipes or files at
    /// least some of the time; whatever they are, the answer is a width or
    /// nothing, never a failure.
    #[test]
    fn answers() {
        let _ = super::columns();
    }
}
