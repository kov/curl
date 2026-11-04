//! The terminal the process writes to, and reads a password from: on
//! Windows the console, as C's tool reads and measures it there.

#![allow(unsafe_code)]

#[cfg(unix)]
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

/// The width of the console standard error writes to, its window's less
/// one, as `get_terminal_columns` measures it on Windows: a character in
/// the last column wraps the line. `None` when it is not a console.
#[cfg(windows)]
pub fn columns() -> Option<u16> {
    use windows_sys::Win32::System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo, GetStdHandle, STD_ERROR_HANDLE,
    };
    // SAFETY: `GetStdHandle` takes no pointer; it gives a handle, null or
    // invalid, which the next call refuses.
    let stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    // SAFETY: all zeros is a value of the plain record the call fills.
    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { core::mem::zeroed() };
    // SAFETY: `info` is the record the call writes, alive through it; a
    // handle that is not a console's fails.
    if unsafe { GetConsoleScreenBufferInfo(stderr, &raw mut info) } == 0 {
        return None;
    }
    u16::try_from(info.srWindow.Right - info.srWindow.Left).ok()
}

/// The width of the terminal on standard input, output or error, the
/// first that is one, as `get_terminal_columns` asks in C. `None` when
/// none is a terminal.
#[cfg(unix)]
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
///
/// On Windows the console's keys are read one at a time without echo
/// (`_getch`), as C's `getpass_r` reads them there; there is nothing to
/// open or put back.
#[derive(Debug)]
pub struct Unechoed {
    /// `/dev/tty`, or `None` for standard input, which is not ours to
    /// close.
    #[cfg(unix)]
    tty: Option<OwnedFd>,
    /// The settings echo was turned off from, put back on drop; `None`
    /// when they could not be read, as from a pipe.
    #[cfg(unix)]
    saved: Option<libc::termios>,
}

#[cfg(windows)]
unsafe extern "C" {
    /// The next key typed at the console, not echoed.
    fn _getch() -> core::ffi::c_int;
}

#[cfg(windows)]
impl Unechoed {
    pub fn open() -> Unechoed {
        Unechoed {}
    }

    /// The keys typed into `buf` up to Enter, as C's `getpass_r` reads
    /// them: a backspace takes back the key before it, and Enter, or the
    /// last byte of a `buf` filled without it, is the last byte, as one
    /// read of a terminal ends with the line's end. How many bytes.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        read_keys(buf, || {
            // SAFETY: `_getch` takes no arguments and waits for a key.
            unsafe { _getch() }
        })
    }
}

/// [`Unechoed::read`], from the keys `key` gives.
#[cfg(windows)]
fn read_keys(buf: &mut [u8], mut key: impl FnMut() -> core::ffi::c_int) -> usize {
    let mut i = 0;
    while i < buf.len() {
        // C keeps the low byte, as a `char`.
        let b = key() as u8;
        match b {
            b'\r' | b'\n' => {
                buf[i] = b;
                return i + 1;
            }
            8 => i = i.saturating_sub(1),
            _ => {
                buf[i] = b;
                i += 1;
            }
        }
    }
    buf.len()
}

#[cfg(unix)]
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

#[cfg(unix)]
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
    /// Enter ends the keys, kept last; a backspace takes back the key
    /// before it, or nothing at the start; a buffer filled without Enter
    /// is all read, its last byte taken for the end as C cuts it there.
    #[test]
    #[cfg(windows)]
    fn keys_are_read_as_c_reads_them() {
        let read = |keys: &[u8], room: usize| {
            let mut keys = keys.iter().map(|&k| core::ffi::c_int::from(k));
            let mut buf = vec![0u8; room];
            let n = super::read_keys(&mut buf, || keys.next().expect("a key"));
            buf.truncate(n);
            buf
        };
        assert_eq!(read(b"secret\r", 16), b"secret\r");
        assert_eq!(read(b"ab\x08c\n", 16), b"ac\n");
        assert_eq!(read(b"\x08\x08a\r", 16), b"a\r");
        assert_eq!(read(b"abcd", 3), b"abc");
        assert_eq!(read(b"\r", 16), b"\r");
    }

    /// Under `cargo test` the standard streams are pipes or files at
    /// least some of the time; whatever they are, the answer is a width or
    /// nothing, never a failure.
    #[test]
    fn answers() {
        let _ = super::columns();
    }
}
