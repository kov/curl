//! Where an FTP reply ends (`ftp_endofresp`).

use super::{Ends, ReplyCode};

/// FTP's replies: a line of three digits and a space ends one, whatever
/// the lines before it said. A multi-line reply's `123-` and the lines
/// inside it that start otherwise, other codes too, end nothing; the
/// first line of digits and a space does, even with another code than
/// the `-` line's (ftp.c:580, `LASTLINE`). In any state.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ftp;

impl Ends for Ftp {
    type Reply = ReplyCode;

    fn ends(&self, line: &[u8]) -> Option<ReplyCode> {
        // `len > 3` and `LASTLINE`: three digits, then a space.
        match line {
            [a, b, c, b' ', ..] if [a, b, c].iter().all(|d| d.is_ascii_digit()) => {
                Some(ReplyCode(digits(&[*a, *b, *c])))
            }
            _ => None,
        }
    }
}

/// The number ASCII digits say.
pub(super) fn digits(ds: &[u8]) -> u32 {
    ds.iter().fold(0, |n, d| n * 10 + u32::from(d - b'0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(line: &[u8]) -> Option<u32> {
        Ftp.ends(line).map(ReplyCode::get)
    }

    #[test]
    fn three_digits_and_a_space_end_a_reply() {
        assert_eq!(code(b"220 Welcome\r\n"), Some(220));
        assert_eq!(code(b"220 \n"), Some(220));
        assert_eq!(code(b"999 x\n"), Some(999));
        // Zero is read as C reads it; its steps take it for no reply.
        assert_eq!(code(b"000 x\r\n"), Some(0));
        assert_eq!(code(b"007 x\r\n"), Some(7));
    }

    #[test]
    fn other_lines_end_nothing() {
        // A multi-line reply's first and inner lines (ftp.c:86).
        assert_eq!(code(b"220-Welcome\r\n"), None);
        assert_eq!(code(b" 220 indented\r\n"), None);
        assert_eq!(code(b"220\r\n"), None);
        assert_eq!(code(b"220\n"), None);
        assert_eq!(code(b"22 x\n"), None);
        assert_eq!(code(b"2a0 x\n"), None);
        assert_eq!(code(b"2200 x\n"), None);
        assert_eq!(code(b"220\t\n"), None);
        assert_eq!(code(b"\n"), None);
        assert_eq!(code(b"220"), None);
    }
}
