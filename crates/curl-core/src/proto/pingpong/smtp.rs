//! Where an SMTP reply ends (`smtp_endofresp`).

use super::ftp::digits;
use super::{Ends, ReplyCode};

/// SMTP's replies, in the state the transfer is in.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Smtp {
    /// The transfer reads each line of a multi-line reply as a reply of
    /// its own (C's states `SMTP_EHLO` and `SMTP_COMMAND`, where its
    /// internal code 1 says so).
    pub(crate) continuations: bool,
}

/// What an SMTP line says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SmtpReply {
    /// The line ends a reply with this code. A server's code 1 reads as
    /// 0, as 1 is C's own (smtp.c:522).
    Final(ReplyCode),
    /// A `250-` line, where continuations are asked for.
    Continuation,
}

impl Ends for Smtp {
    type Reply = SmtpReply;

    fn ends(&self, line: &[u8]) -> Option<SmtpReply> {
        // smtp.c:503: four bytes at least, three digits first.
        let [a, b, c, fourth, ..] = *line else {
            return None;
        };
        if ![a, b, c].iter().all(u8::is_ascii_digit) {
            return None;
        }
        // smtp.c:510: a space after the code, or a line of five bytes
        // whatever its fourth (`250\r\n`, and so `250-\n` too), whose
        // code is every digit it starts with (`2500\n` is 2500).
        if fourth == b' ' || line.len() == 5 {
            let n = if line.len() == 5 { 5 } else { 3 };
            let len = line[..n].iter().take_while(|d| d.is_ascii_digit()).count();
            let code = match digits(&line[..len]) {
                1 => 0,
                code => code,
            };
            return Some(SmtpReply::Final(ReplyCode(code)));
        }
        (fourth == b'-' && self.continuations).then_some(SmtpReply::Continuation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EHLO: Smtp = Smtp {
        continuations: true,
    };
    const MAIL: Smtp = Smtp {
        continuations: false,
    };

    fn code(smtp: Smtp, line: &[u8]) -> Option<SmtpReply> {
        smtp.ends(line)
    }

    fn fin(code: u32) -> Option<SmtpReply> {
        Some(SmtpReply::Final(ReplyCode(code)))
    }

    #[test]
    fn a_code_and_a_space_end_a_reply() {
        assert_eq!(code(MAIL, b"250 OK\r\n"), fin(250));
        assert_eq!(code(EHLO, b"250 OK\r\n"), fin(250));
        assert_eq!(code(MAIL, b"250 \n"), fin(250));
    }

    #[test]
    fn a_bare_code_ends_a_reply_on_a_line_of_five() {
        // smtp.c:510, RFC 5321 section 4.2: some servers send the code
        // alone.
        assert_eq!(code(MAIL, b"250\r\n"), fin(250));
        // The fourth byte is not looked at on a line of five.
        assert_eq!(code(EHLO, b"250-\n"), fin(250));
        assert_eq!(code(MAIL, b"2500\n"), fin(2500));
        assert_eq!(code(MAIL, b"250x\n"), fin(250));
        // With LF alone the line is four bytes: no reply.
        assert_eq!(code(MAIL, b"250\n"), None);
        assert_eq!(code(EHLO, b"250\n"), None);
    }

    #[test]
    fn continuations_are_replies_only_where_asked_for() {
        assert_eq!(
            code(EHLO, b"250-SIZE 1000\r\n"),
            Some(SmtpReply::Continuation)
        );
        assert_eq!(code(MAIL, b"250-SIZE 1000\r\n"), None);
        assert_eq!(code(EHLO, b"250_x\r\n"), None);
    }

    #[test]
    fn a_servers_code_1_reads_as_none() {
        // smtp.c:522.
        assert_eq!(code(MAIL, b"001 x\r\n"), fin(0));
        assert_eq!(code(MAIL, b"000 x\r\n"), fin(0));
        assert_eq!(code(MAIL, b"0001\n"), fin(0));
        assert_eq!(code(MAIL, b"002 x\r\n"), fin(2));
    }

    #[test]
    fn other_lines_end_nothing() {
        for line in [
            &b"25 x\r\n"[..],
            b" 250 x\r\n",
            b"2x0 x\r\n",
            b"250",
            b"\r\n",
            b"25\r\n",
        ] {
            assert_eq!(code(EHLO, line), None, "{line:?}");
        }
    }
}
