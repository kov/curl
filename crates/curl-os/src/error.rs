//! The text of an operating-system error, as `curlx_strerror` gives it:
//! `strerror_r` into a buffer on the stack, so that making it allocates
//! nothing. std's display of an `io::Error` copies the text to the heap
//! with an allocation that cannot fail.

#![allow(unsafe_code)]

use core::fmt;
use std::io;

/// C's `STRERROR_LEN`, the terminating NUL included.
const LEN: usize = 256;

/// An error's text, held in place.
pub struct ErrorText {
    text: [u8; LEN],
    len: usize,
}

impl ErrorText {
    /// The text of `e`: for an operating-system error, the system's text
    /// for its number; for another, std's text of it, cut to fit. On
    /// Windows the number is the system's (`GetLastError`), which the C
    /// library turns into the `errno` C reads after a failed call
    /// (`_dosmaperr`): a file not found is `ENOENT`, not `ESRCH`, which
    /// the system's 3 would read as.
    pub fn of(e: &io::Error) -> ErrorText {
        match e.raw_os_error() {
            #[cfg(windows)]
            Some(code) => ErrorText::of_code(errno_of_system_error(code).unwrap_or(code)),
            #[cfg(unix)]
            Some(code) => ErrorText::of_code(code),
            None => {
                let mut text = ErrorText::empty();
                // A full buffer cuts the text, as C's snprintf would.
                let _ = fmt::write(&mut text, format_args!("{e}"));
                text
            }
        }
    }

    /// The system's text for error number `code`: an `errno`, or on
    /// Windows any of the three numbers the system has, taken in C's
    /// order (`curlx_strerror`): the C library's, then Winsock's, then
    /// the system's (`GetLastError`).
    #[cfg(windows)]
    pub fn of_code(code: i32) -> ErrorText {
        let mut text = ErrorText::empty();
        // SAFETY: the pointer and length name `text.text`, writable for
        // its whole length and alive for the call; `strerror_s` writes at
        // most that many bytes, a NUL among them.
        let failed = unsafe { strerror_s(text.text.as_mut_ptr().cast(), LEN, code) } != 0;
        text.len = text.text.iter().position(|&b| b == 0).unwrap_or(0);
        if failed || text.as_bytes() == b"Unknown error" {
            text.len = 0;
            if let Some(said) = winsock_text(code) {
                // Short enough for the buffer.
                let _ = fmt::write(&mut text, format_args!("{said}"));
            } else if !text.system_text(code.cast_unsigned()) {
                // Short enough for the buffer whatever the number; `{:#x}`
                // is C's `%#x` for all but 0, which the C library names.
                let _ = fmt::write(
                    &mut text,
                    format_args!("Unknown error {code} ({:#x})", code.cast_unsigned()),
                );
            }
        }
        text.strip_line_end();
        text
    }

    /// The system's text for `code` (`curlx_get_winapi_error`), its first
    /// line, in the ANSI code page; false if it has none.
    #[cfg(windows)]
    fn system_text(&mut self, code: u32) -> bool {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageA,
        };
        /// `LANG_NEUTRAL`, as C asks it.
        const LANG_NEUTRAL: u32 = 0;
        let room = u32::try_from(LEN).expect("fits");
        // SAFETY: the buffer is `text.text`, writable for the `room` bytes
        // the call is told, and alive for it; no source and no inserts are
        // read.
        let n = unsafe {
            FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                core::ptr::null(),
                code,
                LANG_NEUTRAL,
                self.text.as_mut_ptr(),
                room,
                core::ptr::null(),
            )
        };
        if n == 0 {
            self.len = 0;
            return false;
        }
        self.len = self.text.iter().position(|&b| b == 0).unwrap_or(0);
        // Its first line only, without the carriage return before the end.
        if let Some(at) = self.as_bytes().iter().position(|&b| b == b'\n') {
            self.len = if at > 0 && self.text[at - 1] == b'\r' {
                at - 1
            } else {
                at
            };
        }
        self.len > 0
    }

    /// The system's text for error number `code` (an `errno`).
    #[cfg(unix)]
    pub fn of_code(code: i32) -> ErrorText {
        let mut text = ErrorText::empty();
        // SAFETY: the pointer and length name `text.text`, which is
        // writable for its whole length and alive for the call;
        // `strerror_r` writes at most that many bytes, a NUL among them
        // whenever it writes any.
        let failed = unsafe { libc::strerror_r(code, text.text.as_mut_ptr().cast(), LEN) } != 0;
        text.len = text.text.iter().position(|&b| b == 0).unwrap_or(0);
        // glibc writes this itself; a libc that writes nothing for a
        // number it does not know gets it from C's fallback.
        if failed && text.len == 0 {
            // Short enough for the buffer whatever the number.
            let _ = fmt::write(&mut text, format_args!("Unknown error {code}"));
        }
        text.strip_line_end();
        text
    }

    fn empty() -> ErrorText {
        ErrorText {
            text: [0; LEN],
            len: 0,
        }
    }

    /// C's: a last line feed with two bytes before it ends the text, and
    /// then a last carriage return with one byte before it.
    fn strip_line_end(&mut self) {
        for (end, before) in [(b'\n', 2), (b'\r', 1)] {
            if let Some(at) = self.as_bytes().iter().rposition(|&b| b == end)
                && at >= before
            {
                self.len = at;
            }
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.text[..self.len]
    }
}

/// The `errno` the C library sets for system error `code`, as its
/// `_dosmaperr` maps it; `None` for no error, and for Winsock's numbers
/// and those past them, which are no file call's: each is named as it is.
#[cfg(windows)]
fn errno_of_system_error(code: i32) -> Option<i32> {
    /// Winsock's numbers start here (`WSABASEERR`).
    const WSABASEERR: i32 = 10_000;
    if !(1..WSABASEERR).contains(&code) {
        return None;
    }
    Some(match code {
        1 | 12 | 13 | 87 | 131 => libc::EINVAL,
        2 | 3 | 15 | 18 | 53 | 67 | 161 | 206 => libc::ENOENT,
        4 => libc::EMFILE,
        5 | 16 | 33 | 65 | 82 | 83 | 108 | 132 | 158 | 167 => libc::EACCES,
        6 | 114 | 130 => libc::EBADF,
        7..=9 => libc::ENOMEM,
        10 => libc::E2BIG,
        11 => libc::ENOEXEC,
        17 => libc::EXDEV,
        80 | 183 => libc::EEXIST,
        89 | 164 | 215 => libc::EAGAIN,
        109 => libc::EPIPE,
        112 => libc::ENOSPC,
        128 | 129 => libc::ECHILD,
        145 => libc::ENOTEMPTY,
        // `ERROR_WRITE_PROTECT` to `ERROR_SHARING_BUFFER_EXCEEDED`.
        19..=36 => libc::EACCES,
        // `ERROR_INVALID_STARTING_CODESEG` to
        // `ERROR_INFLOOP_IN_RELOC_CHAIN`.
        188..=202 => libc::ENOEXEC,
        // `ERROR_NOT_ENOUGH_QUOTA`.
        1816 => libc::ENOMEM,
        _ => libc::EINVAL,
    })
}

#[cfg(windows)]
unsafe extern "C" {
    /// The C library's text for `errnum`, into `buf`.
    fn strerror_s(buf: *mut core::ffi::c_char, size: usize, errnum: i32) -> i32;
}

/// C's text for a Winsock error (`get_winsock_error`), its own words
/// rather than the system's.
#[cfg(windows)]
fn winsock_text(code: i32) -> Option<&'static str> {
    use windows_sys::Win32::Networking::WinSock as ws;
    Some(match code {
        ws::WSAEINTR => "Call interrupted",
        ws::WSAEBADF => "Bad file",
        ws::WSAEACCES => "Bad access",
        ws::WSAEFAULT => "Bad argument",
        ws::WSAEINVAL => "Invalid arguments",
        ws::WSAEMFILE => "Out of file descriptors",
        ws::WSAEWOULDBLOCK => "Call would block",
        ws::WSAEINPROGRESS | ws::WSAEALREADY => "Blocking call in progress",
        ws::WSAENOTSOCK => "Descriptor is not a socket",
        ws::WSAEDESTADDRREQ => "Need destination address",
        ws::WSAEMSGSIZE => "Bad message size",
        ws::WSAEPROTOTYPE => "Bad protocol",
        ws::WSAENOPROTOOPT => "Protocol option is unsupported",
        ws::WSAEPROTONOSUPPORT => "Protocol is unsupported",
        ws::WSAESOCKTNOSUPPORT => "Socket is unsupported",
        ws::WSAEOPNOTSUPP => "Operation not supported",
        ws::WSAEAFNOSUPPORT => "Address family not supported",
        ws::WSAEPFNOSUPPORT => "Protocol family not supported",
        ws::WSAEADDRINUSE => "Address already in use",
        ws::WSAEADDRNOTAVAIL => "Address not available",
        ws::WSAENETDOWN => "Network down",
        ws::WSAENETUNREACH => "Network unreachable",
        ws::WSAENETRESET => "Network has been reset",
        ws::WSAECONNABORTED => "Connection was aborted",
        ws::WSAECONNRESET => "Connection was reset",
        ws::WSAENOBUFS => "No buffer space",
        ws::WSAEISCONN => "Socket is already connected",
        ws::WSAENOTCONN => "Socket is not connected",
        ws::WSAESHUTDOWN => "Socket has been shut down",
        ws::WSAETOOMANYREFS => "Too many references",
        ws::WSAETIMEDOUT => "Timed out",
        ws::WSAECONNREFUSED => "Connection refused",
        ws::WSAELOOP => "Loop??",
        ws::WSAENAMETOOLONG => "Name too long",
        ws::WSAEHOSTDOWN => "Host down",
        ws::WSAEHOSTUNREACH => "Host unreachable",
        ws::WSAENOTEMPTY => "Not empty",
        ws::WSAEPROCLIM => "Process limit reached",
        ws::WSAEUSERS => "Too many users",
        ws::WSAEDQUOT => "Bad quota",
        ws::WSAESTALE => "Something is stale",
        ws::WSAEREMOTE => "Remote error",
        ws::WSAEDISCON => "Disconnected",
        ws::WSASYSNOTREADY => "Winsock library is not ready",
        ws::WSANOTINITIALISED => "Winsock library not initialized",
        ws::WSAVERNOTSUPPORTED => "Winsock version not supported",
        ws::WSAHOST_NOT_FOUND => "Host not found",
        ws::WSATRY_AGAIN => "Host not found, try again",
        ws::WSANO_RECOVERY => "Unrecoverable error in call to nameserver",
        ws::WSANO_DATA => "No data record of requested type",
        _ => return None,
    })
}

impl fmt::Write for ErrorText {
    /// Append `s`, as much of it as fits before the NUL C keeps room for.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = LEN - 1 - self.len;
        let take = s.len().min(room);
        self.text[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        if take < s.len() {
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]

    use super::*;

    #[test]
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "Miri's strerror_r has its own text")]
    fn gives_the_system_text() {
        assert_eq!(
            ErrorText::of_code(libc::ENOENT).as_bytes(),
            b"No such file or directory"
        );
        assert_eq!(ErrorText::of_code(libc::EEXIST).as_bytes(), b"File exists");
        assert_eq!(ErrorText::of_code(0).as_bytes(), b"Success");
    }

    #[test]
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "Miri's strerror_r has its own text")]
    fn names_an_unknown_number() {
        assert_eq!(
            ErrorText::of_code(99_999).as_bytes(),
            b"Unknown error 99999"
        );
        assert_eq!(ErrorText::of_code(-3).as_bytes(), b"Unknown error -3");
    }

    #[test]
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "Miri's strerror_r has its own text")]
    fn takes_an_io_error_s_number_or_its_text() {
        let os = io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(ErrorText::of(&os).as_bytes(), b"Permission denied");
        let other = io::Error::from(io::ErrorKind::InvalidInput);
        assert_eq!(ErrorText::of(&other).as_bytes(), b"invalid input parameter");
    }

    /// The three kinds of number, each in C's words: the C library's,
    /// Winsock's (C's own table), and the system's, its first line.
    #[test]
    #[cfg(windows)]
    fn gives_the_text_of_each_kind_of_number() {
        assert_eq!(
            ErrorText::of_code(libc::ENOENT).as_bytes(),
            b"No such file or directory"
        );
        assert_eq!(ErrorText::of_code(0).as_bytes(), b"No error");
        assert_eq!(
            ErrorText::of_code(10061).as_bytes(),
            b"Connection refused",
            "WSAECONNREFUSED"
        );
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(ErrorText::of(&refused).as_bytes(), b"connection refused");
        // A system number the C library does not know: ERROR_INVALID_HANDLE.
        let system = ErrorText::of_code(6);
        assert!(!system.as_bytes().is_empty());
        assert!(!system.as_bytes().contains(&b'\n'), "one line");
        assert_eq!(
            ErrorText::of_code(99_999).as_bytes(),
            b"Unknown error 99999 (0x1869f)"
        );
        assert_eq!(
            ErrorText::of_code(-3).as_bytes(),
            b"Unknown error -3 (0xfffffffd)"
        );
    }

    /// A system error is named by the `errno` the C library makes of it,
    /// as C names a failed file call's; Winsock's by its own.
    #[test]
    #[cfg(windows)]
    fn names_a_system_error_as_the_c_library_s_errno() {
        let text = |code| ErrorText::of(&io::Error::from_raw_os_error(code));
        // ERROR_FILE_NOT_FOUND and ERROR_PATH_NOT_FOUND.
        assert_eq!(text(2).as_bytes(), b"No such file or directory");
        assert_eq!(text(3).as_bytes(), b"No such file or directory");
        // ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION.
        assert_eq!(text(5).as_bytes(), b"Permission denied");
        assert_eq!(text(32).as_bytes(), b"Permission denied");
        // ERROR_FILE_EXISTS and ERROR_DISK_FULL.
        assert_eq!(text(80).as_bytes(), b"File exists");
        assert_eq!(text(112).as_bytes(), b"No space left on device");
        // ERROR_DIRECTORY, which the table does not list.
        assert_eq!(text(267).as_bytes(), b"Invalid argument");
        assert_eq!(text(10061).as_bytes(), b"Connection refused");
        assert_eq!(text(0).as_bytes(), b"No error");
        // The number itself is still read as an `errno`.
        assert_eq!(ErrorText::of_code(3).as_bytes(), b"No such process");
    }

    /// Some text for any number, known or not: the call Miri checks.
    #[test]
    fn gives_a_text_for_any_number() {
        for code in [0, libc::EINTR, libc::ENOENT, 4_095, 10_035, 99_999, -1] {
            assert!(!ErrorText::of_code(code).as_bytes().is_empty(), "{code}");
        }
    }

    #[test]
    fn cuts_a_long_text_to_c_s_buffer() {
        let mut text = ErrorText::empty();
        assert!(fmt::write(&mut text, format_args!("{}", "x".repeat(300))).is_err());
        assert_eq!(text.as_bytes().len(), LEN - 1);
        // After some text, what fits behind it.
        let mut text = ErrorText::empty();
        fmt::write(&mut text, format_args!("abc")).unwrap();
        assert!(fmt::write(&mut text, format_args!("{}", "x".repeat(300))).is_err());
        assert_eq!(text.as_bytes().len(), LEN - 1);
        assert!(text.as_bytes().starts_with(b"abcx"));
    }

    #[test]
    fn strips_the_line_end_as_c_does() {
        let stripped = |s: &str| {
            let mut text = ErrorText::empty();
            fmt::write(&mut text, format_args!("{s}")).unwrap();
            text.strip_line_end();
            text.as_bytes().to_vec()
        };
        assert_eq!(stripped("No way\r\n"), b"No way");
        assert_eq!(stripped("No way\n"), b"No way");
        assert_eq!(stripped("a\n"), b"a\n");
        assert_eq!(stripped("\r"), b"\r");
    }
}
