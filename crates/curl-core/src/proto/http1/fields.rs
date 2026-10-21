//! Reading one header line of a response (`lib/http.c`): its value, whether
//! it names a token, and whether it is a line at all.

use std::fmt;

/// The most a response's headers may be together (`MAX_HTTP_RESP_HEADER_SIZE`).
pub(crate) const MAX_HEADERS: usize = 300 * 1024;

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn is_newline(b: u8) -> bool {
    b == b'\r' || b == b'\n'
}

fn trim_blanks(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| !is_blank(b))
        .unwrap_or(bytes.len());
    let stop = bytes
        .iter()
        .rposition(|&b| !is_blank(b))
        .map_or(start, |p| p + 1);
    &bytes[start..stop]
}

/// The line up to a NUL byte, where C's string ends.
fn c_string(line: &[u8]) -> &[u8] {
    line.iter()
        .position(|&b| b == 0)
        .map_or(line, |end| &line[..end])
}

/// The value of the header `line`, blanks trimmed, up to its line end
/// (`Curl_copy_header_value`); `None` if no name precedes a colon.
pub(crate) fn header_value(line: &[u8]) -> Option<&[u8]> {
    let line = c_string(line);
    let colon = line.iter().position(|&b| b == b':')?;
    if colon == 0 || colon > MAX_HEADERS {
        return None;
    }
    let rest = &line[colon + 1..];
    let end = rest
        .iter()
        .position(|&b| is_newline(b))
        .unwrap_or(rest.len());
    if end > MAX_HEADERS {
        return Some(b"");
    }
    Some(trim_blanks(&rest[..end]))
}

/// Whether `line` is the header `name` (with its colon, case-blind) and
/// its value lists `token` among its comma-separated words, case-blind
/// (`Curl_compareheader`).
pub(crate) fn header_says(line: &[u8], name: &[u8], token: &[u8]) -> bool {
    assert!(!name.is_empty() && !token.is_empty());
    let line = c_string(line);
    if line.len() < name.len() || !line[..name.len()].eq_ignore_ascii_case(name) {
        return false;
    }
    let after = &line[name.len()..];
    let end = after
        .iter()
        .position(|&b| is_newline(b))
        .unwrap_or(after.len());
    let value = trim_blanks(&after[..end]);
    if value.is_empty() {
        return false;
    }
    // Where the value starts in `after`: a match may look one byte past
    // the value's end, at what the line has there.
    let mut p = value.as_ptr() as usize - after.as_ptr() as usize;
    let mut len = value.len();
    while len >= token.len() {
        let o = p;
        let here = &after[p..];
        if here[..token.len()].eq_ignore_ascii_case(token)
            && here
                .get(token.len())
                .is_none_or(|&b| b == b',' || is_blank(b) || is_newline(b))
        {
            return true;
        }
        // On to the next comma, within the value's length.
        let Some(comma) = here.iter().take(len + 1).position(|&b| b == b',') else {
            break;
        };
        if comma == 0 {
            break;
        }
        p += comma + 1;
        // Blanks and empty words after it.
        loop {
            while after.get(p).is_some_and(|&b| is_blank(b)) {
                p += 1;
            }
            if after.get(p) == Some(&b',') {
                p += 1;
            } else {
                break;
            }
        }
        if p - o > len {
            break;
        }
        len -= p - o;
    }
    false
}

/// What makes a response's line no line (`Curl_verify_header`), each a
/// weird server reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BadLine {
    Nul,
    StrayCr,
    NoColon,
}

impl fmt::Display for BadLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BadLine::Nul => "NUL byte in header",
            BadLine::StrayCr => "Carriage return found in header",
            BadLine::NoColon => "Header without colon",
        })
    }
}

/// Check the response's line numbered `number` from 1, the status line:
/// no NUL, a CR only before the line end, and a colon in a header unless
/// it continues the one before.
pub(crate) fn verify_line(line: &[u8], number: u32) -> Result<(), BadLine> {
    let mut colon = false;
    for (i, &b) in line.iter().enumerate() {
        match b {
            0 => return Err(BadLine::Nul),
            b'\r' if i + 2 < line.len() => return Err(BadLine::StrayCr),
            b':' => colon = true,
            _ => {}
        }
    }
    if number < 2 || colon || (number > 2 && line.first().is_some_and(|&b| is_blank(b))) {
        return Ok(());
    }
    Err(BadLine::NoColon)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C's limits (`curlx_str_until`, `curlx_str_untilnl` at 300 KiB): a
    /// name of 300 KiB is one, a byte more is none; a value of 300 KiB is
    /// read, a byte more reads as empty.
    #[test]
    fn values_are_read_within_c_s_limits() {
        let line = |name: usize, value: usize| {
            let mut l = vec![b'n'; name];
            l.push(b':');
            l.resize(name + 1 + value, b'v');
            l.extend_from_slice(b"\r\n");
            l
        };
        let max = MAX_HEADERS;
        assert_eq!(header_value(&line(max, 1)), Some(&b"v"[..]));
        assert_eq!(header_value(&line(max + 1, 1)), None);
        assert_eq!(header_value(&line(1, max)).map(<[u8]>::len), Some(max));
        assert_eq!(header_value(&line(1, max + 1)), Some(&b""[..]));
    }

    /// Lines `Curl_compareheader` refuses without reading past them: one
    /// shorter than the name, and values whose commas and blanks take
    /// the search to or past their end.
    #[test]
    fn says_reads_no_further_than_the_value() {
        let says = |line: &[u8]| header_says(line, b"Connection:", b"close");
        assert!(!says(b"Conn"));
        assert!(!says(b"Connection:      x,   \r\n"));
        assert!(!says(b"Connection: a,b"));
        assert!(!says(b"Connection: a,b\r\n"));
        assert!(says(b"Connection: a,  close\r\n"));
    }

    /// Unit 1626's table.
    #[test]
    fn values_are_read_as_c_reads_them() {
        let cases: [(&str, &str); 28] = [
            ("Header: value", "value"),
            ("Header:value", "value"),
            ("Header:    value", "value"),
            ("Header: \tvalue", "value"),
            ("Header: value  ", "value"),
            ("Header:    value   ", "value"),
            ("Header:", ""),
            ("Header:  ", ""),
            ("Header: \t ", ""),
            ("Header: one two", "one two"),
            ("Header: one two a b c ", "one two a b c"),
            ("Header: text/html", "text/html"),
            ("Header: value\r", "value"),
            ("Header: value\n", "value"),
            ("Header: \"value\"\n", "\"value\""),
            ("Header: \"value\"  ", "\"value\""),
            (" Header: value", "value"),
            ("Header\t: value", "value"),
            ("Header:\t  value", "value"),
            ("Header: foo:bar", "foo:bar"),
            ("Header: foo:bar:baz", "foo:bar:baz"),
            ("Header:\t\t", ""),
            ("Header: value\r\n", "value"),
            ("Header: foo\tbar", "foo\tbar"),
            ("Header:\tfoo", "foo"),
            ("Header : value", "value"),
            ("Header    : value", "value"),
            ("Header :    value", "value"),
        ];
        for (line, value) in cases {
            assert_eq!(
                header_value(line.as_bytes()),
                Some(value.as_bytes()),
                "{line:?}"
            );
        }
        assert_eq!(header_value(b"no colon"), None);
        assert_eq!(header_value(b": value"), None);
    }

    /// Unit 1625's table.
    #[test]
    fn tokens_are_found_as_c_finds_them() {
        let cases: [(&str, &str, &str, bool); 34] = [
            ("Encoding: gzip, chunked", "Encoding:", "chunked", true),
            ("Encoding: chunked", "Encoding:", "chunked", true),
            ("Encoding: a, b, chunked", "Encoding:", "chunked", true),
            ("Encoding: a, b, c, chunked", "Encoding:", "chunked", true),
            ("Encoding: a, chunked, ninja", "Encoding:", "chunked", true),
            ("Encoding:", "Encoding:", "chunked", false),
            ("Encoding:   ", "Encoding:", "chunked", false),
            ("Encoding: ab,cd,ef,gh,ig,kl", "Encoding:", "kl", true),
            ("Encoding: ab,,kl", "Encoding:", "kl", true),
            ("Encoding: ab,cd,,,,kl", "Encoding:", "kl", true),
            ("Encoding: chunked, a, b, c", "Encoding:", "chunked", true),
            ("Encoding: gzip, chunked", "Encoding:", "CHUNKED", true),
            ("Encoding: gzip, CHUNKED", "Encoding:", "chunked", true),
            ("encoDING: gzip, CHUNKED", "encoding:", "chunked", true),
            ("ENCODING: gzip, chunked", "encoding:", "chunked", true),
            ("Encoding: gzip, chunked", "Encoding:", "gzip", true),
            ("Encoding: gzip,chunked", "Encoding:", "gzip", true),
            (
                "Encoding:    gzip,     chunked",
                "Encoding:",
                "chunked",
                true,
            ),
            ("Encoding: gzip, \tchunked", "Encoding:", "chunked", true),
            ("Encoding: gzip\r\n", "Encoding:", "gzip", true),
            ("Encoding: gzip\n", "Encoding:", "gzip", true),
            ("Encoding: gzip\t", "Encoding:", "gzip", true),
            ("Encoding: gzip \n", "Encoding:", "gzip", true),
            ("Encoding: gzip, chunked", "Encoding:", "br", false),
            ("Encoding: gzip, chunked", "Encodin:", "chunked", false),
            ("Encoding: gzip2, chunked", "Encoding:", "gzip", false),
            ("Encoding: gzipp, chunked", "Encoding:", "gzip", false),
            ("Encoding: agzip, chunked", "Encoding:", "gzip", false),
            ("Decoding: gzip, chunked", "Encoding:", "gzip", false),
            ("Encoding: super-nice", "Encoding:", "super-nice", true),
            (
                "Encoding: extra-good, super-nice",
                "Encoding:",
                "super-nice",
                true,
            ),
            ("Encoding: gzipped,  ", "Encoding:", "gzip", false),
            (
                "Encoding: gzipped,  \r\nEncoding: gzip, chunked",
                "Encoding:",
                "chunked",
                false,
            ),
            ("Encoding: , chunked", "Encoding:", "chunked", false),
        ];
        for (line, name, token, says) in cases {
            assert_eq!(
                header_says(line.as_bytes(), name.as_bytes(), token.as_bytes()),
                says,
                "{line:?} {name:?} {token:?}"
            );
        }
        let mut large = b"Encoding: ".to_vec();
        large.resize(large.len() + MAX_HEADERS, b'a');
        large.extend_from_slice(b", chunked");
        assert!(
            header_says(&large, b"Encoding:", b"chunked"),
            "after 300 KiB"
        );
    }

    #[test]
    fn lines_are_verified_as_c_verifies_them() {
        assert_eq!(verify_line(b"HTTP/1.1 200 OK\r\n", 1), Ok(()));
        assert_eq!(
            verify_line(b"no colon at all\r\n", 1),
            Ok(()),
            "the status line"
        );
        assert_eq!(verify_line(b"A: b\r\n", 2), Ok(()));
        assert_eq!(verify_line(b"A: b\n", 2), Ok(()));
        assert_eq!(verify_line(b"A: \0b\r\n", 2), Err(BadLine::Nul));
        assert_eq!(verify_line(b"A: b\rc\r\n", 2), Err(BadLine::StrayCr));
        assert_eq!(verify_line(b"A: b\r\r\n", 3), Err(BadLine::StrayCr));
        assert_eq!(verify_line(b"A: b\r\r", 3), Ok(()), "a CR two from the end");
        assert_eq!(verify_line(b"no colon\r\n", 2), Err(BadLine::NoColon));
        assert_eq!(verify_line(b" folded\r\n", 3), Ok(()));
        assert_eq!(
            verify_line(b" folded\r\n", 2),
            Err(BadLine::NoColon),
            "nothing to continue on line 2"
        );
        assert_eq!(
            BadLine::StrayCr.to_string(),
            "Carriage return found in header"
        );
    }
}
