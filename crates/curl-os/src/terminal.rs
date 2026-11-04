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

/// Whether `handle` is a character device, as the C library's `_isatty`
/// tells it on Windows: a console, and devices such as `NUL`, but not a
/// pipe, whatever is at its other end.
#[cfg(windows)]
pub fn is_character_device(handle: std::os::windows::io::BorrowedHandle<'_>) -> bool {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_CHAR, GetFileType};
    // SAFETY: the handle is open for the borrow; the call only asks the
    // system what it is.
    unsafe { GetFileType(handle.as_raw_handle()) == FILE_TYPE_CHAR }
}

/// A console's screen buffer, which C's tool writes a body to as UTF-16
/// rather than through the C library (`win_console`).
#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
pub struct Console<'a>(std::os::windows::io::BorrowedHandle<'a>);

#[cfg(windows)]
impl<'a> Console<'a> {
    /// `handle`, if it is a console's screen buffer: one the system tells
    /// about (`GetConsoleScreenBufferInfo`).
    pub fn of(handle: std::os::windows::io::BorrowedHandle<'a>) -> Option<Console<'a>> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::Console::{
            CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo,
        };
        // SAFETY: all zeros is a value of the plain record the call fills.
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { core::mem::zeroed() };
        // SAFETY: the handle is open for the borrow, and `info` is the
        // record the call writes, alive through it; a handle that is not
        // a console's fails.
        let ok = unsafe { GetConsoleScreenBufferInfo(handle.as_raw_handle(), &raw mut info) };
        (ok != 0).then_some(Console(handle))
    }

    /// Write `units` to it (`WriteConsoleW`).
    pub fn write(&self, units: &[u16]) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::Console::WriteConsoleW;
        let count = u32::try_from(units.len()).map_err(|_| std::io::ErrorKind::InvalidInput)?;
        let mut written = 0u32;
        // SAFETY: the handle is open for the borrow; `units` is `count`
        // readable units and `written` a writable count, both alive
        // through the call, which reserves nothing.
        let ok = unsafe {
            WriteConsoleW(
                self.0.as_raw_handle(),
                units.as_ptr().cast(),
                count,
                &raw mut written,
                core::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// A console screen buffer of its own, on the process's console (one is
/// made for it if it has none), which a child may be given to write to
/// and whose first line can be read back: for tests of what is written to
/// a console.
#[cfg(windows)]
#[derive(Debug)]
pub struct ScreenBuffer(std::os::windows::io::OwnedHandle);

#[cfg(windows)]
impl ScreenBuffer {
    pub fn new() -> std::io::Result<ScreenBuffer> {
        use std::os::windows::io::FromRawHandle as _;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Console::{
            AllocConsole, CONSOLE_TEXTMODE_BUFFER, CreateConsoleScreenBuffer,
        };
        // SAFETY: the call takes nothing, and fails when the process has a
        // console already, which is then the one used.
        unsafe { AllocConsole() };
        // SAFETY: no security attributes or data are passed; the call
        // makes a new handle or fails.
        let raw = unsafe {
            CreateConsoleScreenBuffer(
                GENERIC_READ | GENERIC_WRITE,
                0,
                core::ptr::null(),
                CONSOLE_TEXTMODE_BUFFER,
                core::ptr::null(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the handle is new, owned by nothing else.
        Ok(ScreenBuffer(unsafe {
            std::os::windows::io::OwnedHandle::from_raw_handle(raw)
        }))
    }

    pub fn handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        use std::os::windows::io::AsHandle as _;
        self.0.as_handle()
    }

    /// The first `n` units of its first line.
    pub fn read(&self, n: usize) -> std::io::Result<Vec<u16>> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::Console::{COORD, ReadConsoleOutputCharacterW};
        let mut back: Vec<u16> = Vec::new();
        curl_alloc::TryVec::try_resize(&mut back, n, 0)
            .map_err(|_| std::io::ErrorKind::OutOfMemory)?;
        let count = u32::try_from(n).map_err(|_| std::io::ErrorKind::InvalidInput)?;
        let mut read = 0u32;
        // SAFETY: the handle is open; `back` has room for the `count` units
        // the call is told and `read` is a writable count, both alive
        // through the call.
        let ok = unsafe {
            ReadConsoleOutputCharacterW(
                self.0.as_raw_handle(),
                back.as_mut_ptr(),
                count,
                COORD { X: 0, Y: 0 },
                &raw mut read,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        back.truncate(usize::try_from(read).expect("a u32 fits"));
        Ok(back)
    }
}

/// `utf8` in UTF-16, as Windows converts it (`MultiByteToWideChar` with
/// `CP_UTF8`, which puts U+FFFD for what is not UTF-8), into `out`: how
/// many units it wrote, 0 when they do not fit; with `out` empty, how many
/// it would write. 0 for an empty `utf8`.
#[cfg(windows)]
pub fn utf8_to_wide(utf8: &[u8], out: &mut [u16]) -> usize {
    to_wide(windows_sys::Win32::Globalization::CP_UTF8, utf8, out)
}

/// `ansi`, text in the ANSI code page (`CP_ACP`), in UTF-16, as
/// [`utf8_to_wide`] converts UTF-8: the code page the C library takes
/// text in once the tool has set the environment's locale.
#[cfg(windows)]
pub fn ansi_to_wide(ansi: &[u8], out: &mut [u16]) -> usize {
    to_wide(windows_sys::Win32::Globalization::CP_ACP, ansi, out)
}

#[cfg(windows)]
fn to_wide(page: u32, bytes: &[u8], out: &mut [u16]) -> usize {
    use windows_sys::Win32::Globalization::MultiByteToWideChar;
    let (Ok(len), Ok(room)) = (i32::try_from(bytes.len()), i32::try_from(out.len())) else {
        return 0;
    };
    if len == 0 {
        return 0;
    }
    let to = if out.is_empty() {
        core::ptr::null_mut()
    } else {
        out.as_mut_ptr()
    };
    // SAFETY: `bytes` is `len` readable bytes, and `to` is null (asking for
    // the room needed) or `room` writable units, both alive through the
    // call, which writes no further.
    let n = unsafe { MultiByteToWideChar(page, 0, bytes.as_ptr(), len, to, room) };
    usize::try_from(n).unwrap_or(0)
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
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

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

    /// UTF-8 is converted as Windows converts it: what is not UTF-8 is
    /// U+FFFD, an empty `out` asks for the room, and too little room
    /// converts nothing.
    #[test]
    #[cfg(windows)]
    fn converts_utf8_as_windows_does() {
        let wide = |utf8: &[u8]| {
            let mut out = vec![0u16; super::utf8_to_wide(utf8, &mut [])];
            let n = super::utf8_to_wide(utf8, &mut out);
            out.truncate(n);
            out
        };
        assert_eq!(wide(b"caf\xc3\xa9"), [0x63, 0x61, 0x66, 0xe9]);
        assert_eq!(wide(b"\xf0\x9f\x98\x80\0"), [0xd83d, 0xde00, 0]);
        assert_eq!(wide(b"a\xc3"), [0x61, 0xfffd]);
        assert_eq!(wide(b""), []);
        assert_eq!(super::utf8_to_wide(b"abc", &mut [0; 2]), 0);
    }

    /// `NUL` and a console are character devices; a file and a pipe are
    /// not. Only a console's screen buffer is a console, and what is
    /// written to it reads back as written.
    #[test]
    #[cfg(windows)]
    fn tells_a_console_from_a_device_and_writes_to_it() {
        use std::os::windows::io::AsHandle as _;
        let nul = std::fs::OpenOptions::new().write(true).open("NUL").unwrap();
        assert!(super::is_character_device(nul.as_handle()));
        assert!(super::Console::of(nul.as_handle()).is_none());
        let path = std::env::temp_dir().join(format!("curl-console-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        assert!(!super::is_character_device(file.as_handle()));
        drop(file);
        std::fs::remove_file(&path).unwrap();
        let (read, write) = std::io::pipe().unwrap();
        assert!(!super::is_character_device(write.as_handle()));
        drop((read, write));
        let screen = super::ScreenBuffer::new().unwrap();
        assert!(super::is_character_device(screen.handle()));
        let console = super::Console::of(screen.handle()).expect("a console");
        let text: Vec<u16> = "caf\u{e9}".encode_utf16().collect();
        console.write(&text).unwrap();
        assert_eq!(screen.read(4).unwrap(), text);
    }

    /// Under `cargo test` the standard streams are pipes or files at
    /// least some of the time; whatever they are, the answer is a width or
    /// nothing, never a failure.
    #[test]
    fn answers() {
        let _ = super::columns();
    }
}
