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
    /// for its number; for another, std's text of it, cut to fit.
    pub fn of(e: &io::Error) -> ErrorText {
        match e.raw_os_error() {
            Some(code) => ErrorText::of_code(code),
            None => {
                let mut text = ErrorText::empty();
                // A full buffer cuts the text, as C's snprintf would.
                let _ = fmt::write(&mut text, format_args!("{e}"));
                text
            }
        }
    }

    /// The system's text for error number `code` (an `errno`).
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
    #[cfg_attr(miri, ignore = "Miri's strerror_r has its own text")]
    fn names_an_unknown_number() {
        assert_eq!(
            ErrorText::of_code(99_999).as_bytes(),
            b"Unknown error 99999"
        );
        assert_eq!(ErrorText::of_code(-3).as_bytes(), b"Unknown error -3");
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's strerror_r has its own text")]
    fn takes_an_io_error_s_number_or_its_text() {
        let os = io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(ErrorText::of(&os).as_bytes(), b"Permission denied");
        let other = io::Error::from(io::ErrorKind::InvalidInput);
        assert_eq!(ErrorText::of(&other).as_bytes(), b"invalid input parameter");
    }

    /// Some text for any number, known or not: the call Miri checks.
    #[test]
    fn gives_a_text_for_any_number() {
        for code in [0, libc::EINTR, libc::ENOENT, 4_095, 99_999, -1] {
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
