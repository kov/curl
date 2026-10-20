//! Percent-encoding as the URL parser applies it, from `lib/urlapi.c` and
//! `lib/escape.c`.

use curl_alloc::TryVec;

use super::{Bytes, MAX_INPUT};
use crate::error::UrlErrorKind;

/// Bytes of `s` up to the limit C's dynamic buffers hold, or the error C
/// gives: `TooLarge` past the limit, `OutOfMemory` if allocation fails.
pub(super) fn push(out: &mut Bytes, s: &[u8]) -> Result<(), UrlErrorKind> {
    // C's buffers keep room for a terminating zero.
    if out.len() + s.len() >= MAX_INPUT {
        return Err(UrlErrorKind::TooLarge);
    }
    out.try_extend_from_slice(s)
        .map_err(|_| UrlErrorKind::OutOfMemory)
}

/// A copy of `s`.
pub(super) fn copy(s: &[u8]) -> Result<Bytes, UrlErrorKind> {
    let mut out = Bytes::new();
    out.try_extend_from_slice(s)
        .map_err(|_| UrlErrorKind::OutOfMemory)?;
    Ok(out)
}

/// Whether `s` holds a control byte, DEL, or a space unless allowed
/// (`badoctets`).
pub(super) fn bad_octets(s: &[u8], allow_space: bool) -> bool {
    let control = if allow_space { 0x1f } else { 0x20 };
    s.iter().any(|&b| b <= control || b == 0x7f)
}

/// Whether a re-encoded part may turn `?` into the start of a query.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Query {
    /// Not a query: a space is `%20`.
    No,
    /// A query: a space is `+`.
    Yes,
}

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

fn hex_value(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// A `%xx` escape's byte; re-encoding writes it with uppercase digits.
fn escaped_byte(s: &[u8]) -> Option<u8> {
    match s {
        [b'%', h, l, ..] => Some(hex_value(*h)? << 4 | hex_value(*l)?),
        _ => None,
    }
}

/// Re-encode `s` onto `out` as `urlencode_str` does for a relative part:
/// encode what has to be, leave valid escapes as they are and uppercase
/// their hex.
pub(super) fn reencode(out: &mut Bytes, mut s: &[u8], query: Query) -> Result<(), UrlErrorKind> {
    while let Some(&b) = s.first() {
        if b == b' ' {
            push(out, if query == Query::Yes { b"+" } else { b"%20" })?;
            s = &s[1..];
        } else if !(b' '..0x7f).contains(&b) {
            push(
                out,
                &[
                    b'%',
                    UPPER_HEX[usize::from(b >> 4)],
                    UPPER_HEX[usize::from(b & 0xf)],
                ],
            )?;
            s = &s[1..];
        } else if let Some(v) = escaped_byte(s) {
            push(
                out,
                &[
                    b'%',
                    UPPER_HEX[usize::from(v >> 4)],
                    UPPER_HEX[usize::from(v & 0xf)],
                ],
            )?;
            s = &s[3..];
        } else {
            let run = (1..s.len())
                .find(|&i| {
                    let c = s[i];
                    c == b' ' || !(b' '..0x7f).contains(&c) || escaped_byte(&s[i..]).is_some()
                })
                .unwrap_or(s.len());
            push(out, &s[..run])?;
            s = &s[run..];
        }
    }
    Ok(())
}

/// `s` with `%xx` escapes decoded, rejecting control bytes whether escaped
/// or not (`Curl_urldecode` with `REJECT_CTRL`). `None` on such a byte.
pub(super) fn decode(s: &[u8]) -> Result<Option<Bytes>, UrlErrorKind> {
    let mut out = Bytes::new();
    out.try_reserve_exact(s.len())
        .map_err(|_| UrlErrorKind::OutOfMemory)?;
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        let escaped = match s.get(i..i + 3) {
            Some([b'%', h, l]) => hex_value(*h).zip(hex_value(*l)).map(|(h, l)| h << 4 | l),
            _ => None,
        };
        let (byte, used) = match escaped {
            Some(v) => (v, 3),
            None => (b, 1),
        };
        if byte < 0x20 {
            return Ok(None);
        }
        // Within the capacity reserved above: no allocation.
        out.try_push(byte).map_err(|_| UrlErrorKind::OutOfMemory)?;
        i += used;
    }
    Ok(Some(out))
}

/// `s` with every byte but letters, digits and `-._~` escaped
/// (`curl_easy_escape`).
pub(super) fn escape(s: &[u8]) -> Result<Bytes, UrlErrorKind> {
    let mut out = Bytes::new();
    for &b in s {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            push(&mut out, &[b])?;
        } else {
            push(
                &mut out,
                &[
                    b'%',
                    UPPER_HEX[usize::from(b >> 4)],
                    UPPER_HEX[usize::from(b & 0xf)],
                ],
            )?;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reencoded(s: &[u8], query: Query) -> Vec<u8> {
        let mut out = Vec::new();
        reencode(&mut out, s, query).unwrap();
        out
    }

    #[test]
    fn reencodes_what_must_be() {
        assert_eq!(
            reencoded(b"a b%2fc%2F\x01\xff", Query::No),
            b"a%20b%2Fc%2F%01%FF"
        );
        assert_eq!(reencoded(b"a b", Query::Yes), b"a+b");
        assert_eq!(
            reencoded(b"%zz%", Query::No),
            b"%zz%",
            "invalid escapes stay"
        );
    }

    #[test]
    fn decodes_and_rejects_control_bytes() {
        assert_eq!(decode(b"a%41%4a%%2").unwrap().unwrap(), b"aAJ%%2");
        assert_eq!(decode(b"a%0a").unwrap(), None);
        assert_eq!(decode(b"a\tb").unwrap(), None);
        assert_eq!(escape(b"a b/~").unwrap(), b"a%20b%2F~");
    }

    #[test]
    fn push_stops_short_of_the_input_limit() {
        let mut out = Vec::new();
        push(&mut out, &vec![b'a'; MAX_INPUT - 2]).unwrap();
        push(&mut out, b"a").unwrap();
        assert_eq!(push(&mut out, b"a"), Err(UrlErrorKind::TooLarge));
        assert_eq!(out.len(), MAX_INPUT - 1);
    }
}
