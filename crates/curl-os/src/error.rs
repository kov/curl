//! The text of an operating-system error, as `curlx_strerror` gives it:
//! `strerror_r` into a buffer on the stack, so that making it allocates
//! nothing. std's display of an `io::Error` copies the text to the heap
//! with an allocation that cannot fail. And the error left as the
//! thread's last, for a C library that reads it there.

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

    /// The text of a system error (`curlx_winapi_strerror`): the
    /// system's, or `Unknown error <n> (0x<n>)` where it has none.
    #[cfg(windows)]
    pub fn winapi(code: u32) -> ErrorText {
        let mut text = ErrorText::empty();
        if !text.system_text(code) {
            // Short enough for the buffer whatever the number.
            let _ = fmt::write(
                &mut text,
                format_args!("Unknown error {code} (0x{code:08x})"),
            );
        }
        text
    }

    /// The text of an SSPI status (`Curl_sspi_strerror`): its name, its
    /// number and the system's text for it, as `SEC_E_X (0x80090325) -
    /// <text>`, without the text where the system has none.
    #[cfg(windows)]
    pub fn sspi(status: i32) -> ErrorText {
        let code = status.cast_unsigned();
        let mut text = ErrorText::empty();
        let name = sspi_name(code);
        if code == 0x8009_0326 {
            // Short enough for the buffer.
            let _ = fmt::write(
                &mut text,
                format_args!(
                    "SEC_E_ILLEGAL_MESSAGE (0x{code:08x}) - This error usually occurs when a fatal \
                     SSL/TLS alert is received (e.g. handshake failed). More detail may be \
                     available in the Windows System event log."
                ),
            );
            return text;
        }
        let mut system = ErrorText::empty();
        if system.system_text(code) {
            // Cut to the buffer, as C's snprintf cuts it.
            let _ = fmt::write(
                &mut text,
                format_args!("{name} (0x{code:08x}) - {}", ansi_text(system.as_bytes())),
            );
        } else {
            let _ = fmt::write(&mut text, format_args!("{name} (0x{code:08x})"));
        }
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

/// The `errno` C reads after the call that failed with `e`: on Unix the
/// error's own number; on Windows the system's, as the C library maps it
/// (`_dosmaperr`). `None` for an error the system did not give.
pub fn c_errno(e: &io::Error) -> Option<i32> {
    #[cfg(windows)]
    return e.raw_os_error().and_then(errno_of_system_error);
    #[cfg(unix)]
    return e.raw_os_error();
}

/// Leave `e`'s number as this thread's last error, where a C library
/// reads why the call it made back into us failed: `errno` on Unix, the
/// system's (`GetLastError`, which is Winsock's too) on Windows. C's
/// failed system call leaves it so, and OpenSSL queues it as the system's
/// error. An error the system did not give leaves it as it was.
pub fn set_last_error(e: &io::Error) {
    let Some(code) = e.raw_os_error() else {
        return;
    };
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    {
        #[cfg(target_os = "linux")]
        // SAFETY: a call of no arguments, for this thread's `errno`.
        let errno = unsafe { libc::__errno_location() };
        #[cfg(target_vendor = "apple")]
        // SAFETY: as above.
        let errno = unsafe { libc::__error() };
        // SAFETY: it points to this thread's `errno`, valid to write for
        // the thread's life.
        unsafe { *errno = code };
    }
    #[cfg(windows)]
    // SAFETY: `SetLastError` only sets the thread's error.
    unsafe {
        windows_sys::Win32::Foundation::SetLastError(code.cast_unsigned());
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

/// Bytes of the ANSI code page shown as C's `%s` shows them: each byte
/// that is not UTF-8 as the character of its number.
#[cfg(windows)]
fn ansi_text(bytes: &[u8]) -> impl fmt::Display + '_ {
    struct Shown<'a>(&'a [u8]);
    impl fmt::Display for Shown<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            for chunk in self.0.utf8_chunks() {
                f.write_str(chunk.valid())?;
                for &b in chunk.invalid() {
                    fmt::Write::write_char(f, char::from(b))?;
                }
            }
            Ok(())
        }
    }
    Shown(bytes)
}

/// The name C gives an SSPI status (`Curl_sspi_strerror`'s `SEC2TXT`).
#[cfg(windows)]
fn sspi_name(code: u32) -> &'static str {
    match code {
        0 => "No error",
        0x8009_2010 => "CRYPT_E_REVOKED",
        0x8009_2011 => "CRYPT_E_NO_REVOCATION_DLL",
        0x8009_2012 => "CRYPT_E_NO_REVOCATION_CHECK",
        0x8009_2013 => "CRYPT_E_REVOCATION_OFFLINE",
        0x8009_2014 => "CRYPT_E_NOT_IN_REVOCATION_DATABASE",
        0x8009_0331 => "SEC_E_ALGORITHM_MISMATCH",
        0x8009_0346 => "SEC_E_BAD_BINDINGS",
        0x8009_0316 => "SEC_E_BAD_PKGID",
        0x8009_0321 => "SEC_E_BUFFER_TOO_SMALL",
        0x8009_0307 => "SEC_E_CANNOT_INSTALL",
        0x8009_0309 => "SEC_E_CANNOT_PACK",
        0x8009_0328 => "SEC_E_CERT_EXPIRED",
        0x8009_0327 => "SEC_E_CERT_UNKNOWN",
        0x8009_0349 => "SEC_E_CERT_WRONG_USAGE",
        0x8009_0317 => "SEC_E_CONTEXT_EXPIRED",
        0x8009_0357 => "SEC_E_CROSSREALM_DELEGATION_FAILURE",
        0x8009_0337 => "SEC_E_CRYPTO_SYSTEM_INVALID",
        0x8009_0330 => "SEC_E_DECRYPT_FAILURE",
        0x8009_035e => "SEC_E_DELEGATION_POLICY",
        0x8009_0345 => "SEC_E_DELEGATION_REQUIRED",
        0x8009_0350 => "SEC_E_DOWNGRADE_DETECTED",
        0x8009_0329 => "SEC_E_ENCRYPT_FAILURE",
        0x8009_0326 => "SEC_E_ILLEGAL_MESSAGE",
        0x8009_0320 => "SEC_E_INCOMPLETE_CREDENTIALS",
        0x8009_0318 => "SEC_E_INCOMPLETE_MESSAGE",
        0x8009_0300 => "SEC_E_INSUFFICIENT_MEMORY",
        0x8009_0304 => "SEC_E_INTERNAL_ERROR",
        0x8009_0301 => "SEC_E_INVALID_HANDLE",
        0x8009_035d => "SEC_E_INVALID_PARAMETER",
        0x8009_0308 => "SEC_E_INVALID_TOKEN",
        0x8009_0352 => "SEC_E_ISSUING_CA_UNTRUSTED",
        0x8009_0359 => "SEC_E_ISSUING_CA_UNTRUSTED_KDC",
        0x8009_035a => "SEC_E_KDC_CERT_EXPIRED",
        0x8009_035b => "SEC_E_KDC_CERT_REVOKED",
        0x8009_0340 => "SEC_E_KDC_INVALID_REQUEST",
        0x8009_0341 => "SEC_E_KDC_UNABLE_TO_REFER",
        0x8009_0342 => "SEC_E_KDC_UNKNOWN_ETYPE",
        0x8009_030c => "SEC_E_LOGON_DENIED",
        0x8009_0338 => "SEC_E_MAX_REFERRALS_EXCEEDED",
        0x8009_030f => "SEC_E_MESSAGE_ALTERED",
        0x8009_0347 => "SEC_E_MULTIPLE_ACCOUNTS",
        0x8009_0339 => "SEC_E_MUST_BE_KDC",
        0x8009_0306 => "SEC_E_NOT_OWNER",
        0x8009_0311 => "SEC_E_NO_AUTHENTICATING_AUTHORITY",
        0x8009_030e => "SEC_E_NO_CREDENTIALS",
        0x8009_030b => "SEC_E_NO_IMPERSONATION",
        0x8009_0335 => "SEC_E_NO_IP_ADDRESSES",
        0x8009_0348 => "SEC_E_NO_KERB_KEY",
        0x8009_033c => "SEC_E_NO_PA_DATA",
        0x8009_0356 => "SEC_E_NO_S4U_PROT_SUPPORT",
        0x8009_0334 => "SEC_E_NO_TGT_REPLY",
        0x8009_0310 => "SEC_E_OUT_OF_SEQUENCE",
        0x8009_0354 => "SEC_E_PKINIT_CLIENT_FAILURE",
        0x8009_033d => "SEC_E_PKINIT_NAME_MISMATCH",
        0x8009_035f => "SEC_E_POLICY_NLTM_ONLY",
        0x8009_030a => "SEC_E_QOP_NOT_SUPPORTED",
        0x8009_0353 => "SEC_E_REVOCATION_OFFLINE_C",
        0x8009_0358 => "SEC_E_REVOCATION_OFFLINE_KDC",
        0x8009_0305 => "SEC_E_SECPKG_NOT_FOUND",
        0x8009_0332 => "SEC_E_SECURITY_QOS_FAILED",
        0x8009_033f => "SEC_E_SHUTDOWN_IN_PROGRESS",
        0x8009_0355 => "SEC_E_SMARTCARD_CERT_EXPIRED",
        0x8009_0351 => "SEC_E_SMARTCARD_CERT_REVOKED",
        0x8009_033e => "SEC_E_SMARTCARD_LOGON_REQUIRED",
        0x8009_033a => "SEC_E_STRONG_CRYPTO_NOT_SUPPORTED",
        0x8009_0303 => "SEC_E_TARGET_UNKNOWN",
        0x8009_0324 => "SEC_E_TIME_SKEW",
        0x8009_033b => "SEC_E_TOO_MANY_PRINCIPALS",
        0x8009_0333 => "SEC_E_UNFINISHED_CONTEXT_DELETED",
        0x8009_030d => "SEC_E_UNKNOWN_CREDENTIALS",
        0x8009_0302 => "SEC_E_UNSUPPORTED_FUNCTION",
        0x8009_0343 => "SEC_E_UNSUPPORTED_PREAUTH",
        0x8009_0325 => "SEC_E_UNTRUSTED_ROOT",
        0x8009_0336 => "SEC_E_WRONG_CREDENTIAL_HANDLE",
        0x8009_0322 => "SEC_E_WRONG_PRINCIPAL",
        0x0009_0314 => "SEC_I_COMPLETE_AND_CONTINUE",
        0x0009_0313 => "SEC_I_COMPLETE_NEEDED",
        0x0009_0317 => "SEC_I_CONTEXT_EXPIRED",
        0x0009_0312 => "SEC_I_CONTINUE_NEEDED",
        0x0009_0320 => "SEC_I_INCOMPLETE_CREDENTIALS",
        0x0009_0315 => "SEC_I_LOCAL_LOGON",
        0x0009_0323 => "SEC_I_NO_LSA_CONTEXT",
        0x0009_0321 => "SEC_I_RENEGOTIATE",
        0x0009_035c => "SEC_I_SIGNATURE_NEEDED",
        _ => "Unknown error",
    }
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

    /// The `errno` of a failed call is the system's own on Unix, and the
    /// C library's mapping of it on Windows; an error the system did not
    /// report has none. `EPERM` stays apart from `EACCES`, though std
    /// gives both one kind.
    #[test]
    fn reads_errno_as_c_does() {
        let raw = |n| c_errno(&io::Error::from_raw_os_error(n));
        assert_eq!(c_errno(&io::Error::other("not the system's")), None);
        if cfg!(windows) {
            // ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_INVALID_NAME,
            // ERROR_FILENAME_EXCED_RANGE.
            assert_eq!(raw(5), Some(libc::EACCES));
            assert_eq!(raw(183), Some(libc::EEXIST));
            assert_eq!(raw(123), Some(libc::EINVAL));
            assert_eq!(raw(206), Some(libc::ENOENT));
        } else {
            assert_eq!(raw(libc::EACCES), Some(libc::EACCES));
            assert_eq!(raw(libc::EPERM), Some(libc::EPERM));
        }
    }

    /// A system error is left as the thread's last; another leaves what
    /// was there.
    #[test]
    fn leaves_a_system_error_as_the_thread_s_last() {
        let raw = 10_054;
        set_last_error(&io::Error::from_raw_os_error(raw));
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(raw));
        set_last_error(&io::Error::other("not the system's"));
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(raw));
    }

    #[test]
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "Miri's strerror_r has its own text")]
    fn gives_the_system_text() {
        assert_eq!(
            ErrorText::of_code(libc::ENOENT).as_bytes(),
            b"No such file or directory"
        );
        assert_eq!(ErrorText::of_code(libc::EEXIST).as_bytes(), b"File exists");
        #[cfg(target_os = "linux")]
        assert_eq!(ErrorText::of_code(0).as_bytes(), b"Success");
        #[cfg(target_vendor = "apple")]
        assert_eq!(ErrorText::of_code(0).as_bytes(), b"Undefined error: 0");
    }

    #[test]
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "Miri's strerror_r has its own text")]
    fn names_an_unknown_number() {
        // The system's text, macOS's with a colon.
        let (far, negative): (&[u8], &[u8]) = if cfg!(target_vendor = "apple") {
            (b"Unknown error: 99999", b"Unknown error: -3")
        } else {
            (b"Unknown error 99999", b"Unknown error -3")
        };
        assert_eq!(ErrorText::of_code(99_999).as_bytes(), far);
        assert_eq!(ErrorText::of_code(-3).as_bytes(), negative);
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
