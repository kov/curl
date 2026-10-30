//! Where an IMAP reply ends (`imap_endofresp`), the tag a command goes
//! with (`imap_sendf`), and the size of a literal a line announces
//! (`imap_find_literal`).

use crate::conn::ConnNumber;

use super::Ends;

/// The tag a command is sent with and its tagged reply carries: `*`
/// while the server's greeting is read, then a letter for the connection
/// and three digits counting its commands (`resptag`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tag {
    text: [u8; 4],
    len: u8,
}

impl Tag {
    /// The greeting's (imap.c:1966).
    pub(crate) const GREETING: Tag = Tag {
        text: *b"*\0\0\0",
        len: 1,
    };

    /// The tag of a connection's command `id`: `A` and on by the
    /// connection's number modulo 26, then the id in three digits
    /// (imap.c:168). C counts in an `unsigned char`, so A255 is followed
    /// by A000.
    pub(crate) fn command(conn: ConnNumber, id: u8) -> Tag {
        let letter = b'A' + u8::try_from(conn.get() % 26).expect("below 26");
        Tag {
            text: [letter, b'0' + id / 100, b'0' + id / 10 % 10, b'0' + id % 10],
            len: 4,
        }
    }

    /// The tag as sent, the prefix of its command.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.text[..usize::from(self.len)]
    }
}

/// Which untagged responses (`* ...`) the transfer reads as replies, by
/// its state; the others end nothing.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Untagged<'a> {
    /// None (the states not listed in imap.c:330).
    Ignored,
    /// Every one: a `SELECT`'s have no common name (imap.c:362).
    Any,
    /// Those naming this response, after an optional number:
    /// `CAPABILITY`, `FETCH`, `SEARCH`, and a plain request's `LIST`.
    Named(&'static [u8]),
    /// A custom request's (`CURLOPT_CUSTOMREQUEST`, C's `IMAP_LIST`
    /// state): those naming it, `FETCH`'s for a `STORE`, and every one for
    /// the commands whose answers name another (imap.c:342).
    Custom(&'a [u8]),
}

/// What the transfer makes of a continuation (`+ ...`), by its state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Continuations {
    /// Not looked for: a custom request is under way (imap.c:381's
    /// `!imap->custom`), so a `+` line ends nothing.
    Ignored,
    /// `AUTHENTICATE` and `APPEND` wait for one.
    Expected,
    /// Any other state: one fails the transfer ("Unexpected continuation
    /// response", C's code -1).
    Unexpected,
}

/// IMAP's replies, in the state the transfer is in.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Imap<'a> {
    /// The tag of the command whose reply is waited for.
    pub(crate) tag: Tag,
    pub(crate) untagged: Untagged<'a>,
    pub(crate) continuations: Continuations,
}

/// What an IMAP line says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImapReply {
    /// The command's tagged reply, `OK` (`IMAP_RESP_OK`).
    Ok,
    /// Its tagged reply, `PREAUTH` (`IMAP_RESP_PREAUTH`).
    Preauth,
    /// Its tagged reply, anything else (`IMAP_RESP_NOT_OK`).
    NotOk,
    /// An untagged response the state reads (C's `'*'`).
    Untagged,
    /// A continuation the state waits for (C's `'+'`).
    Continuation,
    /// A continuation no state waits for: the transfer fails, once the
    /// line is traced, with "Unexpected continuation response".
    UnexpectedContinuation,
}

impl Ends for Imap<'_> {
    type Reply = ImapReply;

    fn ends(&self, line: &[u8]) -> Option<ImapReply> {
        // imap.c:314: the tag, case and all, then a space; then `OK` or
        // `PREAUTH`, case and all, as a prefix.
        let tag = self.tag.bytes();
        if let Some(rest) = line.strip_prefix(tag).and_then(|r| r.strip_prefix(b" ")) {
            return Some(if rest.starts_with(b"OK") {
                ImapReply::Ok
            } else if rest.starts_with(b"PREAUTH") {
                ImapReply::Preauth
            } else {
                ImapReply::NotOk
            });
        }
        if line.starts_with(b"* ") {
            return self.reads(line).then_some(ImapReply::Untagged);
        }
        // imap.c:381: `+` alone on a CRLF line, or `+ ` and anything.
        let plus = (line.len() == 3 && line[0] == b'+') || line.starts_with(b"+ ");
        match self.continuations {
            _ if !plus => None,
            Continuations::Ignored => None,
            Continuations::Expected => Some(ImapReply::Continuation),
            Continuations::Unexpected => Some(ImapReply::UnexpectedContinuation),
        }
    }
}

/// The commands whose untagged answers a custom request reads, whatever
/// they name (imap.c:345).
const ANSWERED_OTHERWISE: &[&[u8]] = &[
    b"SELECT",
    b"EXAMINE",
    b"SEARCH",
    b"EXPUNGE",
    b"LSUB",
    b"UID",
    b"GETQUOTAROOT",
    b"NOOP",
];

impl Imap<'_> {
    /// Whether the state reads the untagged `line`.
    fn reads(&self, line: &[u8]) -> bool {
        match self.untagged {
            Untagged::Ignored => false,
            Untagged::Any => true,
            Untagged::Named(name) => names(line, name),
            Untagged::Custom(custom) => {
                names(line, custom)
                    || (custom.eq_ignore_ascii_case(b"STORE") && names(line, b"FETCH"))
                    || ANSWERED_OTHERWISE
                        .iter()
                        .any(|c| custom.eq_ignore_ascii_case(c))
            }
        }
    }
}

/// Whether the untagged `line` is `* ` and `name`, or `* `, a number, a
/// space and `name`, in any case, then a space or the line's end
/// (`imap_matchresp`). The end is two bytes from it, as C counts a CRLF:
/// a line ended by LF alone matches only if a space follows the name.
fn names(line: &[u8], name: &[u8]) -> bool {
    let mut rest = &line[2..];
    let number = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    if number > 0 {
        match rest[number..].strip_prefix(b" ") {
            Some(r) => rest = r,
            None => return false,
        }
    }
    rest.len() >= name.len()
        && rest[..name.len()].eq_ignore_ascii_case(name)
        && (rest.get(name.len()) == Some(&b' ') || rest.len() == name.len() + 2)
}

/// The size of the literal `line` announces, `{N}` outside a quoted
/// string, or none if it announces none or its size is not a number of
/// at most 63 bits closed by `}` (imap.c:1395, `imap_find_literal`). A
/// `FETCH`'s line is looked through whole, the line of a custom request
/// up to its first CR (imap.c:1223): the caller cuts it.
pub(crate) fn literal(line: &[u8]) -> Option<u64> {
    let open = find_literal(line)?;
    let after = &line[open + 1..];
    let len = after.iter().take_while(|b| b.is_ascii_digit()).count();
    if len == 0 || after.get(len) != Some(&b'}') {
        return None;
    }
    after[..len].iter().try_fold(0u64, |n, d| {
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(d - b'0')))
            .filter(|&n| i64::try_from(n).is_ok())
    })
}

/// Where the first `{` outside a quoted string is, a backslash in one
/// escaping the byte after it (`imap_find_literal`). C escapes nothing
/// with a backslash that ends the line; skipping past the end instead
/// finds nothing all the same.
fn find_literal(line: &[u8]) -> Option<usize> {
    let mut quoted = false;
    let mut at = 0;
    while at < line.len() {
        let b = line[at];
        if quoted {
            if b == b'\\' {
                at += 2;
                continue;
            }
            if b == b'"' {
                quoted = false;
            }
        } else if b == b'"' {
            quoted = true;
        } else if b == b'{' {
            return Some(at);
        }
        at += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(n: u64) -> ConnNumber {
        ConnNumber::for_tests(n)
    }

    fn imap(untagged: Untagged<'_>, continuations: Continuations) -> Imap<'_> {
        Imap {
            tag: Tag::command(conn(0), 3),
            untagged,
            continuations,
        }
    }

    #[test]
    fn tags_are_a_letter_and_three_digits() {
        assert_eq!(Tag::command(conn(0), 1).bytes(), b"A001");
        assert_eq!(Tag::command(conn(1), 42).bytes(), b"B042");
        assert_eq!(Tag::command(conn(25), 255).bytes(), b"Z255");
        assert_eq!(Tag::command(conn(26), 0).bytes(), b"A000");
        assert_eq!(Tag::command(conn(27 + 26 * 1000), 100).bytes(), b"B100");
        assert_eq!(Tag::GREETING.bytes(), b"*");
    }

    #[test]
    fn the_tagged_reply_ends_one() {
        let i = imap(Untagged::Ignored, Continuations::Unexpected);
        assert_eq!(i.ends(b"A003 OK done\r\n"), Some(ImapReply::Ok));
        assert_eq!(i.ends(b"A003 OKAY\r\n"), Some(ImapReply::Ok));
        assert_eq!(i.ends(b"A003 PREAUTH hi\r\n"), Some(ImapReply::Preauth));
        assert_eq!(i.ends(b"A003 NO way\r\n"), Some(ImapReply::NotOk));
        assert_eq!(i.ends(b"A003 BAD\r\n"), Some(ImapReply::NotOk));
        assert_eq!(i.ends(b"A003 \n"), Some(ImapReply::NotOk));
        // imap.c:320: memcmp, so case counts.
        assert_eq!(i.ends(b"A003 ok\r\n"), Some(ImapReply::NotOk));
        assert_eq!(i.ends(b"a003 OK\r\n"), None);
        // Another command's tag, or the tag with no space.
        assert_eq!(i.ends(b"A002 OK\r\n"), None);
        assert_eq!(i.ends(b"A003OK\r\n"), None);
        assert_eq!(i.ends(b"A0031 OK\r\n"), None);
    }

    #[test]
    fn the_greeting_is_tagged_with_a_star() {
        let i = Imap {
            tag: Tag::GREETING,
            untagged: Untagged::Ignored,
            continuations: Continuations::Unexpected,
        };
        assert_eq!(i.ends(b"* OK ready\r\n"), Some(ImapReply::Ok));
        assert_eq!(i.ends(b"* PREAUTH ready\r\n"), Some(ImapReply::Preauth));
        assert_eq!(i.ends(b"* BYE\r\n"), Some(ImapReply::NotOk));
    }

    #[test]
    fn untagged_responses_end_one_where_the_state_reads_them() {
        let none = imap(Untagged::Ignored, Continuations::Unexpected);
        assert_eq!(none.ends(b"* CAPABILITY IMAP4\r\n"), None);
        let any = imap(Untagged::Any, Continuations::Unexpected);
        assert_eq!(any.ends(b"* 3 EXISTS\r\n"), Some(ImapReply::Untagged));
        assert_eq!(any.ends(b"* \r\n"), Some(ImapReply::Untagged));
        let caps = imap(Untagged::Named(b"CAPABILITY"), Continuations::Unexpected);
        assert_eq!(
            caps.ends(b"* CAPABILITY IMAP4\r\n"),
            Some(ImapReply::Untagged)
        );
        assert_eq!(
            caps.ends(b"* capability IMAP4\r\n"),
            Some(ImapReply::Untagged)
        );
        assert_eq!(caps.ends(b"* CAPABILITY\r\n"), Some(ImapReply::Untagged));
        // imap.c:286 counts the end as two bytes on: with LF alone, the
        // name must be followed by a space.
        assert_eq!(caps.ends(b"* CAPABILITY\n"), None);
        assert_eq!(caps.ends(b"* CAPABILITY \n"), Some(ImapReply::Untagged));
        assert_eq!(caps.ends(b"* CAPABILITYX\r\n"), None);
        assert_eq!(caps.ends(b"* CAPABILIT\r\n"), None);
        assert_eq!(caps.ends(b"*  CAPABILITY\r\n"), None);
        let fetch = imap(Untagged::Named(b"FETCH"), Continuations::Unexpected);
        assert_eq!(
            fetch.ends(b"* 12 FETCH (BODY {3}\r\n"),
            Some(ImapReply::Untagged)
        );
        assert_eq!(fetch.ends(b"* 12  FETCH (\r\n"), None);
        assert_eq!(fetch.ends(b"* 12FETCH (\r\n"), None);
        assert_eq!(fetch.ends(b"* 12\r\n"), None);
        assert_eq!(fetch.ends(b"* FETCH x\r\n"), Some(ImapReply::Untagged));
    }

    #[test]
    fn a_custom_request_reads_what_c_lets_it() {
        let store = imap(Untagged::Custom(b"store"), Continuations::Ignored);
        assert_eq!(store.ends(b"* 1 STORE x\r\n"), Some(ImapReply::Untagged));
        assert_eq!(
            store.ends(b"* 1 FETCH (FLAGS)\r\n"),
            Some(ImapReply::Untagged)
        );
        assert_eq!(store.ends(b"* 1 EXISTS\r\n"), None);
        let other = imap(Untagged::Custom(b"XLIST"), Continuations::Ignored);
        assert_eq!(other.ends(b"* XLIST () x\r\n"), Some(ImapReply::Untagged));
        assert_eq!(other.ends(b"* 1 FETCH (FLAGS)\r\n"), None);
        for c in ANSWERED_OTHERWISE {
            let i = imap(Untagged::Custom(c), Continuations::Ignored);
            assert_eq!(i.ends(b"* 3 EXISTS\r\n"), Some(ImapReply::Untagged));
        }
        let noop = imap(Untagged::Custom(b"noop"), Continuations::Ignored);
        assert_eq!(noop.ends(b"* 3 EXISTS\r\n"), Some(ImapReply::Untagged));
    }

    #[test]
    fn continuations_by_state() {
        let auth = imap(Untagged::Ignored, Continuations::Expected);
        assert_eq!(auth.ends(b"+ \r\n"), Some(ImapReply::Continuation));
        assert_eq!(auth.ends(b"+ dGVzdA==\r\n"), Some(ImapReply::Continuation));
        // imap.c:381: a lone `+` on a CRLF line, RFC 4959's servers.
        assert_eq!(auth.ends(b"+\r\n"), Some(ImapReply::Continuation));
        assert_eq!(auth.ends(b"+x\n"), Some(ImapReply::Continuation));
        assert_eq!(auth.ends(b"+\n"), None);
        assert_eq!(auth.ends(b"+x\r\n"), None);
        let other = imap(Untagged::Ignored, Continuations::Unexpected);
        assert_eq!(
            other.ends(b"+ go\r\n"),
            Some(ImapReply::UnexpectedContinuation)
        );
        let custom = imap(Untagged::Custom(b"X"), Continuations::Ignored);
        assert_eq!(custom.ends(b"+ go\r\n"), None);
    }

    #[test]
    fn literals_are_found_outside_quotes() {
        assert_eq!(literal(b"* 1 FETCH (BODY[TEXT] {2021}\r\n"), Some(2021));
        assert_eq!(literal(b"{0}"), Some(0));
        assert_eq!(literal(b"* 1 FETCH (X \"{9}\" {4}\r\n"), Some(4));
        assert_eq!(literal(b"\"ab{9}\" {4}"), Some(4));
        // An escaped quote leaves the string open.
        assert_eq!(literal(b"\"\\\"{9}"), None);
        assert_eq!(literal(b"\"a\\\"{9}"), None);
        assert_eq!(literal(b"\"a\\"), None);
        // A backslash escapes the quote after it.
        assert_eq!(literal(b"\"a\\\"{9}\" {5}"), Some(5));
        // Only the first `{` outside quotes counts.
        assert_eq!(literal(b"{x} {5}"), None);
        assert_eq!(literal(b"{5"), None);
        assert_eq!(literal(b"{}"), None);
        assert_eq!(literal(b"{+5}"), None);
        assert_eq!(literal(b"{ 5}"), None);
        assert_eq!(literal(b"\"{5}"), None);
        assert_eq!(literal(b"\"\\"), None);
        assert_eq!(literal(b"no literal\r\n"), None);
        assert_eq!(literal(b"{9223372036854775807}"), Some(i64::MAX as u64));
        assert_eq!(literal(b"{9223372036854775808}"), None);
        assert_eq!(literal(b"{99999999999999999999999}"), None);
    }
}
