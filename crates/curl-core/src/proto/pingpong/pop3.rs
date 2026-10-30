//! Where a POP3 reply ends (`pop3_endofresp`).
//!
//! A message's lines after `+OK` to `RETR` or `LIST`, up to the line of a
//! single dot, are its body, read by the transfer and not here
//! (`pop3_write`); only the list `CAPA` answers is read line by line.

use super::Ends;

/// POP3's replies, in the state the transfer is in.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Pop3 {
    /// The transfer reads the answer to `CAPA` (C's `POP3_CAPA`): each
    /// line is a reply of its own.
    pub(crate) capa: bool,
}

/// What a POP3 line says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pop3Reply {
    /// `+OK`, or the dot ending the capabilities (C's `'+'`).
    Ok,
    /// `-ERR` (C's `'-'`).
    Err,
    /// A capability, or a `+` line that is not `+OK`: a SASL challenge
    /// (C's `'*'`).
    More,
}

impl Ends for Pop3 {
    type Reply = Pop3Reply;

    fn ends(&self, line: &[u8]) -> Option<Pop3Reply> {
        // pop3.c:302: an error, in any state, before the capabilities.
        if line.starts_with(b"-ERR") {
            return Some(Pop3Reply::Err);
        }
        if self.capa {
            // pop3.c:312: RFC 2449's line of a single dot ends the list.
            return Some(match line {
                b".\r\n" | b".\n" => Pop3Reply::Ok,
                _ => Pop3Reply::More,
            });
        }
        if line.starts_with(b"+OK") {
            Some(Pop3Reply::Ok)
        } else if line.starts_with(b"+") {
            Some(Pop3Reply::More)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPA: Pop3 = Pop3 { capa: true };
    const USER: Pop3 = Pop3 { capa: false };

    #[test]
    fn status_lines_end_a_reply() {
        assert_eq!(USER.ends(b"+OK ready\r\n"), Some(Pop3Reply::Ok));
        assert_eq!(USER.ends(b"+OK\n"), Some(Pop3Reply::Ok));
        // `+OK` is a prefix: no space needed after it.
        assert_eq!(USER.ends(b"+OKAY\r\n"), Some(Pop3Reply::Ok));
        assert_eq!(USER.ends(b"-ERR no\r\n"), Some(Pop3Reply::Err));
        assert_eq!(USER.ends(b"-ERRx\r\n"), Some(Pop3Reply::Err));
        // pop3.c:327: any other `+` line is a continuation.
        assert_eq!(USER.ends(b"+ dGVzdA==\r\n"), Some(Pop3Reply::More));
        assert_eq!(USER.ends(b"+\r\n"), Some(Pop3Reply::More));
        assert_eq!(USER.ends(b"+O\r\n"), Some(Pop3Reply::More));
    }

    #[test]
    fn other_lines_end_nothing() {
        for line in [&b"-ER\r\n"[..], b"OK\r\n", b" +OK\r\n", b".\r\n", b"\r\n"] {
            assert_eq!(USER.ends(line), None, "{line:?}");
        }
    }

    #[test]
    fn every_capability_is_a_reply_until_the_dot() {
        assert_eq!(CAPA.ends(b"TOP\r\n"), Some(Pop3Reply::More));
        assert_eq!(CAPA.ends(b"+OK List follows\r\n"), Some(Pop3Reply::More));
        assert_eq!(CAPA.ends(b"\r\n"), Some(Pop3Reply::More));
        assert_eq!(CAPA.ends(b".\r\n"), Some(Pop3Reply::Ok));
        assert_eq!(CAPA.ends(b".\n"), Some(Pop3Reply::Ok));
        // Only a dot alone ends it.
        assert_eq!(CAPA.ends(b"..\r\n"), Some(Pop3Reply::More));
        assert_eq!(CAPA.ends(b". \r\n"), Some(Pop3Reply::More));
        assert_eq!(CAPA.ends(b".\r\r\n"), Some(Pop3Reply::More));
        // An error ends the list too, before the state is looked at.
        assert_eq!(CAPA.ends(b"-ERR no\r\n"), Some(Pop3Reply::Err));
    }
}
