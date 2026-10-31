//! What SCP and SFTP read of what they are given (`lib/vssh/vssh.c`): the
//! path a request works on, the paths of an SFTP quote command, and a
//! download's range. All of it at the trust boundary: a URL's path and an
//! application's commands may be anything.

use curl_alloc::TryVec as _;

use crate::error::ErrorKind;

/// The longest path a request works on, less its zero byte
/// (`MAX_SSHPATH_LEN`): one longer is out of memory, as C's buffer
/// reports it.
const MAX_PATH: usize = 100_000;

/// The longest path of a quote command (`MAX_PATHLENGTH`).
const MAX_QUOTED: usize = 65_535;

/// What a request's path is relative to: SCP's home is the server's own,
/// SFTP's the directory its session found.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Home<'h> {
    Scp,
    Sftp(&'h [u8]),
}

/// The path a request works on (`Curl_getworkingpath`), from its URL's,
/// decoded: `/~/` at its start is the home directory, for SFTP `/~` too,
/// and a path with a zero byte in it is malformed.
pub(crate) fn working_path(url_path: &[u8], home: Home<'_>) -> Result<Vec<u8>, ErrorKind> {
    let path = crate::url::decode_but_zero(url_path)
        .map_err(crate::error::url_error)?
        .ok_or(ErrorKind::UrlMalformat)?;
    let mut out = Vec::new();
    let add = |out: &mut Vec<u8>, bytes: &[u8]| {
        if out.len() + bytes.len() >= MAX_PATH {
            return Err(ErrorKind::OutOfMemory);
        }
        out.try_extend_from_slice(bytes)
            .map_err(|_| ErrorKind::OutOfMemory)
    };
    match home {
        Home::Scp if path.len() > 3 && path.starts_with(b"/~/") => add(&mut out, &path[3..])?,
        Home::Sftp(home) if path == b"/~" || (path.len() > 2 && path.starts_with(b"/~/")) => {
            add(&mut out, home)?;
            if path.len() > 2 {
                // The home's own slash, if it ends with one, separates.
                let from = if out.last().is_some_and(|&b| b != b'/') {
                    2
                } else {
                    3
                };
                add(&mut out, &path[from..])?;
            } else {
                add(&mut out, b"/")?;
            }
        }
        _ => {}
    }
    if out.is_empty() {
        return Ok(path);
    }
    Ok(out)
}

/// A quote command's next path, from `cp`, and what follows it, blanks
/// skipped (`Curl_get_pathname`): in quotes, `\` escaping a quote or
/// itself, or up to the next space, `/~/` at its start the home
/// directory's. None is a quote error.
pub(crate) fn quoted_path<'c>(cp: &'c [u8], home: &[u8]) -> Result<(Vec<u8>, &'c [u8]), ErrorKind> {
    let mut cp = cp.split(|&b| b == 0).next().unwrap_or_default();
    if cp.is_empty() {
        return Err(ErrorKind::QuoteError);
    }
    cp = blanks_passed(cp);
    let mut out = Vec::new();
    let add = |out: &mut Vec<u8>, bytes: &[u8]| {
        if out.len() + bytes.len() >= MAX_QUOTED {
            return Err(ErrorKind::TooLarge);
        }
        out.try_extend_from_slice(bytes)
            .map_err(|_| ErrorKind::OutOfMemory)
    };
    match cp.first() {
        Some(&quote @ (b'"' | b'\'')) => {
            let mut i = 1;
            loop {
                match cp.get(i) {
                    None => return Err(ErrorKind::QuoteError),
                    Some(&b) if b == quote => break,
                    Some(b'\\') => {
                        i += 1;
                        match cp.get(i) {
                            Some(&b @ (b'\'' | b'"' | b'\\')) => add(&mut out, &[b])?,
                            _ => return Err(ErrorKind::QuoteError),
                        }
                    }
                    Some(&b) => add(&mut out, &[b])?,
                }
                i += 1;
            }
            cp = &cp[i + 1..];
            if out.is_empty() {
                return Err(ErrorKind::QuoteError);
            }
        }
        _ => {
            let mut content = false;
            if cp.starts_with(b"/~/") {
                add(&mut out, home)?;
                add(&mut out, b"/")?;
                cp = &cp[3..];
                content = true;
            }
            let len = cp.iter().take_while(|&&b| b != b' ').count();
            if len > MAX_QUOTED {
                return Err(ErrorKind::TooLarge);
            }
            if len == 0 {
                if !content {
                    return Err(ErrorKind::QuoteError);
                }
            } else {
                add(&mut out, &cp[..len])?;
                cp = &cp[len..];
            }
        }
    }
    Ok((out, blanks_passed(cp)))
}

/// `s` past its spaces and tabs (`curlx_str_passblanks`).
fn blanks_passed(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
    &s[n..]
}

/// Why a number did not read (`STRE_NO_NUM`, `STRE_OVERFLOW`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NumError {
    NoNumber,
    Overflow,
}

/// A number in `base` at the start of `s`, no greater than `max`, and
/// what follows it (`curlx_str_number`, `curlx_str_octal`): digits only,
/// no sign, no blanks before.
pub(crate) fn number(s: &[u8], max: i64, base: u32) -> Result<(i64, &[u8]), NumError> {
    let digit = |b: u8| char::from(b).to_digit(base);
    let len = s.iter().take_while(|&&b| digit(b).is_some()).count();
    if len == 0 {
        return Err(NumError::NoNumber);
    }
    let mut n: i64 = 0;
    for &b in &s[..len] {
        let d = i64::from(digit(b).expect("a digit, counted above"));
        n = n
            .checked_mul(i64::from(base))
            .and_then(|n| n.checked_add(d))
            .filter(|&n| n <= max)
            .ok_or(NumError::Overflow)?;
    }
    Ok((n, &s[len..]))
}

/// Why a range was refused, and what C says of it, if anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RangeError {
    /// Refused with nothing said.
    Silent,
    /// Its start is past the file's end.
    Beyond { from: i64, size: i64 },
    /// It ends before it starts.
    Backwards,
}

/// The part of a file of `size` bytes a download's `range` asks for: its
/// start and its length (`Curl_ssh_range`). `X-Y`, `X-` or `-Y`, the last
/// bytes; an end past the file's is the file's.
pub(crate) fn range(range: &[u8], size: i64) -> Result<(i64, i64), RangeError> {
    let range = range.split(|&b| b == 0).next().unwrap_or_default();
    let (from, rest, from_err) = match number(range, i64::MAX, 10) {
        Ok((n, rest)) => (n, rest, None),
        Err(e) => (0, range, Some(e)),
    };
    if from_err == Some(NumError::Overflow) {
        return Err(RangeError::Silent);
    }
    let mut rest = blanks_passed(rest);
    if let [b'-', after @ ..] = rest {
        rest = after;
    }
    let rest = blanks_passed(rest);
    let (to, rest, to_err) = match number(rest, i64::MAX, 10) {
        Ok((n, rest)) => (n, rest, None),
        Err(e) => (0, rest, Some(e)),
    };
    if to_err == Some(NumError::Overflow)
        || (to_err.is_some() && from_err.is_some())
        || !rest.is_empty()
    {
        return Err(RangeError::Silent);
    }
    let (from, to) = if from_err.is_some() {
        // The last `to` bytes.
        if to == 0 {
            return Err(RangeError::Silent);
        }
        let to = to.min(size);
        (size - to, size - 1)
    } else if from > size {
        return Err(RangeError::Beyond { from, size });
    } else if to_err == Some(NumError::NoNumber) || to >= size {
        (from, size - 1)
    } else {
        (from, to)
    };
    if from > to {
        return Err(RangeError::Backwards);
    }
    if to - from == i64::MAX {
        return Err(RangeError::Silent);
    }
    Ok((from, to - from + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A URL's path is decoded and taken from the home directory as C
    /// takes it: SCP's `/~/` strips, SFTP's names the session's home,
    /// with one slash between whether the home ends with one or not.
    #[test]
    fn a_request_s_path_is_c_s() {
        let sftp = |p: &[u8], home: &[u8]| working_path(p, Home::Sftp(home)).unwrap();
        let scp = |p: &[u8]| working_path(p, Home::Scp).unwrap();
        assert_eq!(scp(b"/~/a%20b"), b"a b");
        assert_eq!(scp(b"/~/"), b"/~/");
        assert_eq!(scp(b"/tmp/x"), b"/tmp/x");
        assert_eq!(sftp(b"/~", b"/home/u"), b"/home/u/");
        assert_eq!(sftp(b"/~/f", b"/home/u"), b"/home/u/f");
        assert_eq!(sftp(b"/~/f", b"/"), b"/f");
        assert_eq!(sftp(b"/~/", b"/home/u"), b"/home/u/");
        assert_eq!(sftp(b"/~f", b"/home/u"), b"/~f");
        assert_eq!(sftp(b"/x/~/", b"/home/u"), b"/x/~/");
        assert_eq!(
            working_path(b"/a%00b", Home::Scp),
            Err(ErrorKind::UrlMalformat)
        );
        let long = vec![b'a'; MAX_PATH];
        assert_eq!(
            working_path(b"/~/x", Home::Sftp(&long)),
            Err(ErrorKind::OutOfMemory)
        );
    }

    /// A quote command's paths read as C reads them.
    #[test]
    fn a_quote_command_s_paths_are_c_s() {
        let home = b"/home/u";
        let read = |cp: &[u8]| quoted_path(cp, home).map(|(p, rest)| (p, rest.to_vec()));
        assert_eq!(read(b"  a b"), Ok((b"a".to_vec(), b"b".to_vec())));
        assert_eq!(read(b"\"a b\"  c"), Ok((b"a b".to_vec(), b"c".to_vec())));
        assert_eq!(read(b"'a\\'b'"), Ok((b"a'b".to_vec(), b"".to_vec())));
        assert_eq!(read(b"'a\\xb'"), Err(ErrorKind::QuoteError));
        assert_eq!(read(b"'ab"), Err(ErrorKind::QuoteError));
        assert_eq!(read(b"''"), Err(ErrorKind::QuoteError));
        assert_eq!(read(b"/~/f g"), Ok((b"/home/u/f".to_vec(), b"g".to_vec())));
        assert_eq!(read(b"/~/ g"), Ok((b"/home/u/".to_vec(), b"g".to_vec())));
        assert_eq!(read(b""), Err(ErrorKind::QuoteError));
        assert_eq!(read(b"   "), Err(ErrorKind::QuoteError));
        // A tab is no separator, though blanks before are passed.
        assert_eq!(read(b"\ta\tb"), Ok((b"a\tb".to_vec(), b"".to_vec())));
    }

    /// A range reads as C's `Curl_ssh_range` reads it, against a file of
    /// 100 bytes.
    #[test]
    fn a_range_is_c_s() {
        let r = |s: &[u8]| range(s, 100);
        assert_eq!(r(b"0-9"), Ok((0, 10)));
        assert_eq!(r(b"10-"), Ok((10, 90)));
        assert_eq!(r(b"-10"), Ok((90, 10)));
        assert_eq!(r(b"-200"), Ok((0, 100)));
        assert_eq!(r(b"90-200"), Ok((90, 10)));
        assert_eq!(r(b" 5 - 7 "), Err(RangeError::Silent));
        assert_eq!(r(b"5 - 7"), Ok((5, 3)));
        assert_eq!(r(b"-0"), Err(RangeError::Silent));
        assert_eq!(r(b"-"), Err(RangeError::Silent));
        assert_eq!(r(b"1-2x"), Err(RangeError::Silent));
        assert_eq!(
            r(b"101-"),
            Err(RangeError::Beyond {
                from: 101,
                size: 100
            })
        );
        assert_eq!(r(b"100-"), Err(RangeError::Backwards));
        assert_eq!(r(b"9-5"), Err(RangeError::Backwards));
        assert_eq!(r(b"99999999999999999999-"), Err(RangeError::Silent));
        // The longest ranges there are read whole.
        let max = i64::MAX;
        let last = |s: &str| range(s.as_bytes(), max);
        assert_eq!(last(&format!("1-{}", max - 1)), Ok((1, max - 1)));
        assert_eq!(last(&format!("0-{max}")), Ok((0, max)));
    }

    /// A path from the home directory is refused at `MAX_PATH` bytes, the
    /// home's and the rest's together, and a quote command's at
    /// `MAX_QUOTED`, as C's buffers limit them.
    #[test]
    fn paths_are_limited_as_c_s() {
        let rest = vec![b'r'; MAX_PATH - 4];
        let url = [&b"/~/"[..], &rest].concat();
        assert_eq!(
            working_path(&url, Home::Sftp(b"/h")).map(|p| p.len()),
            Ok(MAX_PATH - 1)
        );
        let rest = vec![b'r'; MAX_PATH - 3];
        let url = [&b"/~/"[..], &rest].concat();
        assert_eq!(
            working_path(&url, Home::Sftp(b"/h")),
            Err(ErrorKind::OutOfMemory)
        );
        let quoted = |n: usize| {
            let cp = [&b"\""[..], &vec![b'q'; n], b"\""].concat();
            quoted_path(&cp, b"/h").map(|(p, _)| p.len())
        };
        assert_eq!(quoted(MAX_QUOTED - 1), Ok(MAX_QUOTED - 1));
        assert_eq!(quoted(MAX_QUOTED), Err(ErrorKind::TooLarge));
    }

    /// unit2604's cases for `Curl_get_pathname`: a command, its home, and
    /// the path and the rest it gives.
    #[test]
    fn unit2604_s_paths() {
        let sa540 = "a".repeat(540);
        let too_long = "a".repeat(90_720);
        let quoted = format!("\" {sa540}\" c");
        let spaced = format!(" {sa540}");
        let word = format!("{sa540} c");
        type Want = Result<(Vec<u8>, Vec<u8>), ErrorKind>;
        let ok = |p: &str, rest: &str| -> Want { Ok((p.into(), rest.into())) };
        let quote = Err(ErrorKind::QuoteError);
        let cases: Vec<(&str, &str, Want)> = vec![
            (&too_long, "", Err(ErrorKind::TooLarge)),
            (&word, "/", ok(&sa540, "c")),
            (&quoted, "/", ok(&spaced, "c")),
            ("a a", "/home/", ok("a", "a")),
            ("b a", "/", ok("b", "a")),
            ("a", "/home/", ok("a", "")),
            ("b", "/", ok("b", "")),
            ("\"foo bar\"\tb", "/", ok("foo bar", "b")),
            ("/~/hej", "/home/user", ok("/home/user/hej", "")),
            ("\"foo bar", "/", quote.clone()),
            ("\"foo\\\"bar\" a", "/", ok("foo\"bar", "a")),
            ("\"foo\\'bar\" b", "/", ok("foo'bar", "b")),
            ("\"foo\\\\bar\" c", "/", ok("foo\\bar", "c")),
            ("\"foo\\pbar\" c", "/", quote.clone()),
            ("\"\" c", "", quote.clone()),
            ("foo\"", "/", ok("foo\"", "")),
            ("foo \"", "/", ok("foo", "\"")),
            ("   \t\t   \t  ", "/", quote.clone()),
            ("              ", "/", quote.clone()),
            ("", "/", quote),
            ("       \r \n  ", "/", ok("\r", "\n  ")),
        ];
        for (i, (cp, home, want)) in cases.into_iter().enumerate() {
            let got = quoted_path(cp.as_bytes(), home.as_bytes()).map(|(p, r)| (p, r.to_vec()));
            assert_eq!(got, want, "case {i}");
        }
    }

    /// unit2605's cases for `Curl_ssh_range`: a range, the file's size,
    /// and the start and length it gives.
    #[test]
    fn unit2605_s_ranges() {
        /// The start and length a range gives, or none.
        type Gives = Result<(i64, i64), ()>;
        let bad = Err(());
        let cases: [(&str, i64, Gives); 26] = [
            ("0-9", 100, Ok((0, 10))),
            ("1-10", 100, Ok((1, 10))),
            ("222222-222222", 300_000, Ok((222_222, 1))),
            (
                "4294967296 - 4294967297",
                4_294_967_298,
                Ok((4_294_967_296, 2)),
            ),
            ("-10", 100, Ok((90, 10))),
            ("-20", 100, Ok((80, 20))),
            ("-1", 100, Ok((99, 1))),
            ("-0", 100, bad),
            ("--2", 100, bad),
            ("-100", 100, Ok((0, 100))),
            ("-101", 100, Ok((0, 100))),
            ("-1000", 100, Ok((0, 100))),
            ("2-1000", 100, Ok((2, 98))),
            (".2-3", 100, bad),
            ("+2-3", 100, bad),
            ("2 - 3", 100, Ok((2, 2))),
            (" 2 - 3", 100, bad),
            ("2 - 3 ", 100, bad),
            ("3-2", 100, bad),
            ("2.-3", 100, bad),
            ("-3-2", 100, bad),
            ("101-102", 100, bad),
            ("0-", 100, Ok((0, 100))),
            ("1-", 100, Ok((1, 99))),
            ("99-", 100, Ok((99, 1))),
            ("100-", 100, bad),
        ];
        for (i, (r, size, want)) in cases.into_iter().enumerate() {
            assert_eq!(range(r.as_bytes(), size).map_err(drop), want, "case {i}");
        }
    }

    /// Numbers read as `curlx_str_number` and `curlx_str_octal` read
    /// them: none, too big, or the digits and what follows.
    #[test]
    fn numbers_are_c_s() {
        assert_eq!(number(b"644 x", 0o7777, 8), Ok((0o644, &b" x"[..])));
        assert_eq!(number(b"8", 0o7777, 8), Err(NumError::NoNumber));
        assert_eq!(number(b"17777", 0o7777, 8), Err(NumError::Overflow));
        assert_eq!(
            number(b"4294967295", u32::MAX.into(), 10).map(|n| n.0),
            Ok(4_294_967_295)
        );
        assert_eq!(
            number(b"4294967296", u32::MAX.into(), 10),
            Err(NumError::Overflow)
        );
        assert_eq!(number(b"-1", 10, 10), Err(NumError::NoNumber));
    }
}
