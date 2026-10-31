//! What FTP's replies say, read from the reply's line as C reads it: the
//! peer a passive data connection goes to, the entry path, a size, a
//! file's time and the server's system. Each is the server's word, at the
//! trust boundary: a reply that does not say what it should says nothing
//! here, and the state machine decides what that fails.

use curl_alloc::TryVec as _;

/// The decimal number `s` starts with, no more than `max`, and what
/// follows it (`curlx_str_number`): none without a digit, or past `max`.
pub(crate) fn number(s: &[u8], max: u64) -> Option<(u64, &[u8])> {
    let digits = s.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mut n: u64 = 0;
    for &d in &s[..digits] {
        n = n.checked_mul(10)?.checked_add(u64::from(d - b'0'))?;
        if n > max {
            return None;
        }
    }
    Some((n, &s[digits..]))
}

/// The text after a reply's code and its space: from its fifth byte, as C
/// reads `recvbuf + 4`.
fn text(line: &[u8]) -> &[u8] {
    line.get(4..).unwrap_or_default()
}

/// The port an `EPSV` answer gives, `(|||port|)` with any separator
/// (229); `Err` for a port number that does not fit, `None` for a reply
/// formatted otherwise (`ftp_state_pasv_resp`).
pub(crate) fn epsv_port(line: &[u8]) -> Result<Option<u16>, ()> {
    let s = text(line);
    let Some(open) = s.iter().position(|&b| b == b'(') else {
        return Ok(None);
    };
    let p = &s[open + 1..];
    match p {
        [sep, a, b, d, ..] if *sep != 0 && a == sep && b == sep && d.is_ascii_digit() => {
            match number(&p[3..], 0xffff) {
                Some((n, [next, ..])) if next == sep => Ok(Some(n as u16)),
                _ => Err(()),
            }
        }
        _ => Ok(None),
    }
}

/// The six numbers of a `PASV` answer (227), the first run of them in its
/// text: an IPv4 address and a port's two bytes (`match_pasv_6nums`).
pub(crate) fn pasv_numbers(line: &[u8]) -> Option<[u8; 6]> {
    let s = text(line);
    (0..s.len()).find_map(|at| six(&s[at..]))
}

fn six(mut p: &[u8]) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        if i > 0 {
            p = p.strip_prefix(b",")?;
        }
        let (n, rest) = number(p, 0xff)?;
        *slot = n as u8;
        p = rest;
    }
    Some(out)
}

/// What a `PWD` answer's quoted directory says (257): the name, its
/// doubled quotes undone; none if there is none, or it is empty; `Err`
/// for a control byte in it (`ftp_pwd_resp`).
pub(crate) fn entry_path(line: &[u8]) -> Result<Option<Vec<u8>>, ReplyError> {
    let s = text(line);
    // The first quote, or the line's end.
    let Some(open) = s.iter().position(|&b| b == b'"' || b == b'\n') else {
        return Ok(None);
    };
    if s[open] != b'"' {
        return Ok(None);
    }
    let mut out = Vec::new();
    let mut i = open + 1;
    while i < s.len() {
        match s[i] {
            b'"' if s.get(i + 1) == Some(&b'"') => {
                out.try_push(b'"').map_err(|_| ReplyError::OutOfMemory)?;
                i += 2;
                continue;
            }
            b'"' => return Ok((!out.is_empty()).then_some(out)),
            c if c.is_ascii_control() => return Err(ReplyError::Weird),
            c => out.try_push(c).map_err(|_| ReplyError::OutOfMemory)?,
        }
        i += 1;
    }
    // No closing quote: the name is not taken.
    Ok(None)
}

/// A reply's word that cannot be taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyError {
    /// It is malformed (`CURLE_WEIRD_SERVER_REPLY`).
    Weird,
    OutOfMemory,
}

/// The size a `SIZE` answer gives (213): the digits before the line's
/// first CR, whatever comes before them, or else its text's first
/// number; none if that is no number (`ftp_state_size_resp`).
pub(crate) fn size(line: &[u8]) -> Option<u64> {
    let s = text(line);
    let start = match s.iter().position(|&b| b == b'\r') {
        Some(cr) => {
            let mut at = cr;
            while at > 0 && s[at - 1].is_ascii_digit() {
                at -= 1;
            }
            at
        }
        None => 0,
    };
    number(&s[start..], i64::MAX as u64).map(|(n, _)| n)
}

/// The size a `RETR` answer's `(N bytes)` says, the first number in the
/// line followed by a space and `bytes` (`ftp_state_get_resp`).
pub(crate) fn transfer_size(line: &[u8]) -> Option<u64> {
    (0..line.len().saturating_sub(7)).find_map(|i| {
        let (n, rest) = number(&line[i..], i64::MAX as u64)?;
        rest.strip_prefix(b" ")?.starts_with(b"bytes").then_some(n)
    })
}

/// A file's time an `MDTM` answer gives (213), `YYYYMMDDHHMMSS` at its
/// text's start, each field in its range (`ftp_213_date`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileTime {
    pub(crate) year: u32,
    pub(crate) month: u32,
    pub(crate) day: u32,
    pub(crate) hour: u32,
    pub(crate) minute: u32,
    pub(crate) second: u32,
}

pub(crate) fn file_time(line: &[u8]) -> Option<FileTime> {
    let p = text(line);
    if p.len() < 14 {
        return None;
    }
    let two = |at: usize| -> Option<u32> {
        let (a, b) = (p[at], p[at + 1]);
        (a.is_ascii_digit() && b.is_ascii_digit())
            .then(|| u32::from(a - b'0') * 10 + u32::from(b - b'0'))
    };
    let t = FileTime {
        year: two(0)? * 100 + two(2)?,
        month: two(4)?,
        day: two(6)?,
        hour: two(8)?,
        minute: two(10)?,
        second: two(12)?,
    };
    (t.month <= 12 && t.day <= 31 && t.hour <= 23 && t.minute <= 59 && t.second <= 60).then_some(t)
}

/// The system a `SYST` answer names (215): its text's first word, after
/// any spaces.
pub(crate) fn system(line: &[u8]) -> &[u8] {
    let mut s = text(line);
    while let [b' ', rest @ ..] = s {
        s = rest;
    }
    let end = s
        .iter()
        .position(|&b| b == b' ' || b == 0)
        .unwrap_or(s.len());
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_read_as_c_reads_them() {
        assert_eq!(number(b"12x", 99), Some((12, &b"x"[..])));
        assert_eq!(number(b"100", 99), None);
        assert_eq!(number(b"x1", 99), None);
        assert_eq!(number(b"", 99), None);
        assert_eq!(number(b"007", 9), Some((7, &b""[..])));
    }

    #[test]
    fn an_epsv_answer_gives_its_port() {
        let port = |l: &[u8]| epsv_port(l);
        assert_eq!(
            port(b"229 Entering Passive Mode (|||1234|)\r\n"),
            Ok(Some(1234))
        );
        assert_eq!(port(b"229 x (!!!65535!)\r\n"), Ok(Some(65535)));
        assert_eq!(port(b"229 x (|||65536|)\r\n"), Err(()));
        // What follows the closing separator is not looked at.
        assert_eq!(port(b"229 x (|||12|x)\r\n"), Ok(Some(12)));
        assert_eq!(port(b"229 x (|||12x|)\r\n"), Err(()));
        assert_eq!(port(b"229 x (||12|)\r\n"), Ok(None));
        assert_eq!(port(b"229 x |||12|\r\n"), Ok(None));
        assert_eq!(port(b"229 x (|||x|)\r\n"), Ok(None));
    }

    #[test]
    fn a_pasv_answer_gives_six_numbers_anywhere() {
        assert_eq!(
            pasv_numbers(b"227 Entering Passive Mode (127,0,0,1,4,51)\r\n"),
            Some([127, 0, 0, 1, 4, 51])
        );
        assert_eq!(
            pasv_numbers(b"227 Data transfer will passively listen to 127,0,0,1,4,51\r\n"),
            Some([127, 0, 0, 1, 4, 51])
        );
        // A number past 255 is no part of a run: the next run counts.
        assert_eq!(
            pasv_numbers(b"227 (256,0,0,1,4,51) 1,2,3,4,5,6\r\n"),
            Some([56, 0, 0, 1, 4, 51])
        );
        assert_eq!(pasv_numbers(b"227 (1,2,3,4,5)\r\n"), None);
    }

    #[test]
    fn the_entry_path_is_the_quoted_name() {
        let path = |l: &[u8]| entry_path(l).map(|p| p.map(|p| String::from_utf8(p).unwrap()));
        assert_eq!(
            path(b"257 \"/\" is current directory\r\n"),
            Ok(Some("/".into()))
        );
        assert_eq!(
            path(b"257 rubbish \"/a\"\"b\" x\r\n"),
            Ok(Some("/a\"b".into()))
        );
        assert_eq!(path(b"257 \"\" empty\r\n"), Ok(None));
        assert_eq!(path(b"257 no quote\r\n"), Ok(None));
        assert_eq!(path(b"257 \"open\r\n"), Err(ReplyError::Weird));
        assert_eq!(path(b"257 \"open"), Ok(None));
        assert_eq!(path(b"257 \"a\tb\"\r\n"), Err(ReplyError::Weird));
    }

    #[test]
    fn a_size_is_the_digits_before_the_line_s_end() {
        assert_eq!(size(b"213 51\r\n"), Some(51));
        assert_eq!(size(b"213 rubbish 51\r\n"), Some(51));
        assert_eq!(size(b"213 51\n"), Some(51));
        assert_eq!(size(b"213 x\r\n"), None);
        assert_eq!(size(b"213 99999999999999999999\r\n"), None);
    }

    #[test]
    fn a_retrieval_s_size_is_its_bytes() {
        assert_eq!(
            transfer_size(b"150 Binary data connection for 102 () (51 bytes).\r\n"),
            Some(51)
        );
        assert_eq!(
            transfer_size(b"150 Opening (0.0.0.0,0) (545 bytes)\r\n"),
            Some(545)
        );
        assert_eq!(transfer_size(b"150 ok\r\n"), None);
        assert_eq!(transfer_size(b"150"), None);
        assert_eq!(transfer_size(b""), None);
    }

    #[test]
    fn a_file_s_time_is_read_in_range() {
        assert_eq!(
            file_time(b"213 20040912163218\r\n"),
            Some(FileTime {
                year: 2004,
                month: 9,
                day: 12,
                hour: 16,
                minute: 32,
                second: 18
            })
        );
        assert_eq!(file_time(b"213 20041312163218\r\n"), None);
        assert_eq!(file_time(b"213 2004091216321\r\n"), None);
        // The digits alone, without the line's end, are enough.
        assert!(file_time(b"213 20040912163218").is_some());
        assert_eq!(file_time(b"213 2004091216321"), None);
        assert_eq!(file_time(b"213 2004x912163218\r\n"), None);
    }

    #[test]
    fn the_system_is_the_first_word() {
        assert_eq!(system(b"215 UNIX Type: L8\r\n"), b"UNIX");
        assert_eq!(system(b"215   OS/400 is the remote\r\n"), b"OS/400");
    }
}
