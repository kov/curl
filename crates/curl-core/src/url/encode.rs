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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Query {
    /// Not a query: a space is `%20`.
    No,
    /// A query: a space is `+`.
    Yes,
    /// Not a query until a `?`, which starts one (`QUERY_NOT_YET`).
    NotYet,
}

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Each byte's value as a hex digit, 0xff for none (C's `hextable`): two
/// digits' values or'ed have no high bits set exactly when both are
/// digits. A static, not a const: indexing a const array copies it.
static HEX_VALUES: [u8; 256] = {
    let mut values = [0xff; 256];
    let mut b = 0;
    while b < 256 {
        values[b] = match b as u8 {
            d @ b'0'..=b'9' => d - b'0',
            d @ b'a'..=b'f' => d - b'a' + 10,
            d @ b'A'..=b'F' => d - b'A' + 10,
            _ => 0xff,
        };
        b += 1;
    }
    values
};

fn hex_value(b: u8) -> Option<u8> {
    let v = HEX_VALUES[usize::from(b)];
    (v != 0xff).then_some(v)
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
pub(super) fn reencode(
    out: &mut Bytes,
    mut s: &[u8],
    mut query: Query,
) -> Result<(), UrlErrorKind> {
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
            let mut run = 0;
            while let Some(&c) = s.get(run) {
                let escape = run > 0 && escaped_byte(&s[run..]).is_some();
                if c == b' ' || !(b' '..0x7f).contains(&c) || escape {
                    break;
                }
                run += 1;
                if c == b'?' && query == Query::NotYet {
                    query = Query::Yes;
                    break;
                }
            }
            push(out, &s[..run])?;
            s = &s[run..];
        }
    }
    Ok(())
}

/// Whether `reencode` would give `s` back unchanged, whatever its query
/// state: no byte it encodes and no escape with lowercase hex.
pub(super) fn reencodes_to_itself(s: &[u8]) -> bool {
    s.iter().enumerate().all(|(i, &b)| {
        let lower = |c: u8| c.is_ascii_lowercase();
        (b'!'..0x7f).contains(&b)
            && !(b == b'%'
                && escaped_byte(&s[i..]).is_some()
                && (lower(s[i + 1]) || lower(s[i + 2])))
    })
}

/// `s` onto `out` with every byte but letters, digits and `-._~` escaped,
/// as `url_encode_part` encodes a part set alone: a space as `+` if
/// `plus`, a path's own punctuation kept if `path`, and the first `=`
/// kept if `equals`. Not limited in length, as C sizes the buffer for the
/// worst case.
pub(super) fn encode_part(
    out: &mut Bytes,
    s: &[u8],
    plus: bool,
    path: bool,
    mut equals: bool,
) -> Result<(), UrlErrorKind> {
    for &b in s {
        let kept = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || (path && b"!$&'(){}[]*+,;=:@/".contains(&b))
            || (b == b'=' && equals);
        let res = if b == b' ' && plus {
            out.try_push(b'+')
        } else if kept {
            if b == b'=' {
                equals = false;
            }
            out.try_push(b)
        } else {
            out.try_extend_from_slice(&[
                b'%',
                UPPER_HEX[usize::from(b >> 4)],
                UPPER_HEX[usize::from(b & 0xf)],
            ])
        };
        res.map_err(|_| UrlErrorKind::OutOfMemory)?;
    }
    Ok(())
}

/// `s` onto `out` with the hex of its `%xx` escapes uppercase
/// (`url_uppercasehex_part`).
pub(super) fn uppercase_hex(out: &mut Bytes, s: &[u8]) -> Result<(), UrlErrorKind> {
    let start = out.len();
    out.try_extend_from_slice(s)
        .map_err(|_| UrlErrorKind::OutOfMemory)?;
    let mut i = start;
    while i < out.len() {
        if escaped_byte(&out[i..]).is_some() {
            out[i + 1].make_ascii_uppercase();
            out[i + 2].make_ascii_uppercase();
            i += 3;
        } else {
            i += 1;
        }
    }
    Ok(())
}

/// `s` with `%xx` escapes decoded, rejecting control bytes whether escaped
/// or not (`Curl_urldecode` with `REJECT_CTRL`). `None` on such a byte.
pub(crate) fn decode(s: &[u8]) -> Result<Option<Bytes>, UrlErrorKind> {
    decode_rejecting(s, |b| b < 0x20)
}

/// `s` with `%xx` escapes decoded, rejecting a zero byte whether escaped
/// or not (`Curl_urldecode` with `REJECT_ZERO`). `None` on one.
pub(crate) fn decode_but_zero(s: &[u8]) -> Result<Option<Bytes>, UrlErrorKind> {
    decode_rejecting(s, |b| b == 0)
}

pub(super) fn decode_rejecting(
    s: &[u8],
    reject: fn(u8) -> bool,
) -> Result<Option<Bytes>, UrlErrorKind> {
    let mut out = Bytes::new();
    out.try_reserve_exact(s.len())
        .map_err(|_| UrlErrorKind::OutOfMemory)?;
    out.try_resize(s.len(), 0)
        .map_err(|_| UrlErrorKind::OutOfMemory)?;
    let Some(len) = decode_into(s, reject, &mut out) else {
        return Ok(None);
    };
    out.truncate(len);
    Ok(Some(out))
}

/// Decode `s` into the start of `out`, at least as long as `s` (the
/// decoded bytes are never more), as `Curl_urldecode` does: `%` with two
/// hex digits is the byte they name, anything else is itself, and runs
/// without a `%` are copied whole. How many bytes were written, or
/// `None` at the first decoded byte `reject` refuses.
pub(super) fn decode_into(s: &[u8], reject: impl Fn(u8) -> bool, out: &mut [u8]) -> Option<usize> {
    assert!(out.len() >= s.len(), "room for every byte of the input");
    let (mut i, mut o) = (0, 0);
    while i < s.len() {
        if s[i] == b'%' {
            // Each outcome advances in its own branch, as C's does: a
            // step chosen without a branch would make every next read
            // wait for this escape's table lookups.
            if let Some(&[h, l]) = s.get(i + 1..i + 3) {
                let (h, l) = (HEX_VALUES[usize::from(h)], HEX_VALUES[usize::from(l)]);
                if (h | l) & 0xf0 == 0 {
                    let byte = h << 4 | l;
                    if reject(byte) {
                        return None;
                    }
                    out[o] = byte;
                    o += 1;
                    i += 3;
                    continue;
                }
            }
            if reject(b'%') {
                return None;
            }
            out[o] = b'%';
            o += 1;
            i += 1;
        } else {
            let run = s[i + 1..]
                .iter()
                .position(|&b| b == b'%')
                .map_or(s.len(), |n| i + 1 + n);
            let plain = &s[i..run];
            if plain.iter().any(|&b| reject(b)) {
                return None;
            }
            out[o..o + plain.len()].copy_from_slice(plain);
            o += plain.len();
            i = run;
        }
    }
    Some(o)
}

/// `s` with every byte but letters, digits and `-._~` escaped
/// (`curl_easy_escape`).
pub(super) fn escape(s: &[u8]) -> Result<Bytes, UrlErrorKind> {
    // The bytes kept as they are: letters, digits and `-._~`.
    const KEPT: [bool; 256] = {
        let mut kept = [false; 256];
        let mut b = 0;
        while b < 256 {
            let c = b as u8;
            kept[b] = c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~');
            b += 1;
        }
        kept
    };
    // The whole length first, so the buffer is allocated once: C's limit
    // is passed exactly when the last byte would pass it.
    let len: usize = s
        .iter()
        .map(|&b| if KEPT[usize::from(b)] { 1 } else { 3 })
        .sum();
    if len >= MAX_INPUT {
        return Err(UrlErrorKind::TooLarge);
    }
    let mut out = Bytes::new();
    out.try_reserve_exact(len)
        .map_err(|_| UrlErrorKind::OutOfMemory)?;
    out.try_resize(len, 0)
        .map_err(|_| UrlErrorKind::OutOfMemory)?;
    let mut rest = &mut out[..];
    for &b in s {
        if KEPT[usize::from(b)] {
            let [first, tail @ ..] = rest else {
                unreachable!("the length counted holds every byte")
            };
            *first = b;
            rest = tail;
        } else {
            let [percent, high, low, tail @ ..] = rest else {
                unreachable!("the length counted holds every escape")
            };
            *percent = b'%';
            *high = UPPER_HEX[usize::from(b >> 4)];
            *low = UPPER_HEX[usize::from(b & 0xf)];
            rest = tail;
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
            reencoded(b"a b?c d?e f", Query::NotYet),
            b"a%20b?c+d?e+f",
            "a query from the first `?`"
        );
        assert_eq!(
            reencoded(b"%zz%", Query::No),
            b"%zz%",
            "invalid escapes stay"
        );
    }

    /// The shortcut agrees with `reencode` on every string it waves
    /// through and every one it does not, in each query state.
    #[test]
    fn reencodes_to_itself_as_reencode_says() {
        let cases: &[&[u8]] = &[
            b"",
            b"/a/b?c=d",
            b"%2F%C3",
            b"%2f",
            b"%C3%a9",
            b"%zz%",
            b"%",
            b"%a",
            b"a%",
            b" ",
            b"a b",
            b"\x01",
            b"\x7f",
            b"\xc3\xa9",
            b"%%2f",
            b"~!$&'()*+,;=:@[]",
        ];
        for &s in cases {
            for query in [Query::No, Query::Yes, Query::NotYet] {
                assert_eq!(
                    encode_unchanged(s, query),
                    reencodes_to_itself(s),
                    "{:?} in {query:?}",
                    String::from_utf8_lossy(s)
                );
            }
        }
    }

    fn encode_unchanged(s: &[u8], query: Query) -> bool {
        reencoded(s, query) == s
    }

    #[test]
    fn decodes_and_rejects_control_bytes() {
        assert_eq!(decode(b"a%41%4a%%2").unwrap().unwrap(), b"aAJ%%2");
        assert_eq!(decode(b"a%0a").unwrap(), None);
        assert_eq!(decode(b"a\tb").unwrap(), None);
        assert_eq!(
            decode_but_zero(b"a%01%41\tb").unwrap().unwrap(),
            b"a\x01A\tb"
        );
        assert_eq!(decode_but_zero(b"a%00b").unwrap(), None);
        assert_eq!(decode_but_zero(b"a\0b").unwrap(), None);
        assert_eq!(escape(b"a b/~").unwrap(), b"a%20b%2F~");
    }

    /// Decoding reads `%` with two hex digits as the byte they name and
    /// anything else as itself, rejecting by the decoded byte, as
    /// `Curl_urldecode` does: checked one byte at a time against every
    /// string of up to five bytes from an alphabet of the edge cases
    /// (a `%` at the end or before one digit, digits of both cases, a
    /// non-digit, a control byte).
    #[test]
    fn decodes_as_c_byte_by_byte() {
        fn one_by_one(s: &[u8], reject: fn(u8) -> bool) -> Option<Vec<u8>> {
            let mut out = Vec::new();
            let mut i = 0;
            while i < s.len() {
                let (byte, used) = match s.get(i..i + 3) {
                    Some([b'%', h, l]) => match hex_value(*h).zip(hex_value(*l)) {
                        Some((h, l)) => (h << 4 | l, 3),
                        None => (s[i], 1),
                    },
                    _ => (s[i], 1),
                };
                if reject(byte) {
                    return None;
                }
                out.push(byte);
                i += used;
            }
            Some(out)
        }
        const ALPHABET: &[u8] = b"%41aFg\x01";
        let mut strings: Vec<Vec<u8>> = vec![Vec::new()];
        let mut last = strings.clone();
        for _ in 0..5 {
            let next: Vec<Vec<u8>> = last
                .iter()
                .flat_map(|s| {
                    ALPHABET.iter().map(move |&b| {
                        let mut t = s.clone();
                        t.push(b);
                        t
                    })
                })
                .collect();
            strings.extend(next.iter().cloned());
            last = next;
        }
        let rejects: [fn(u8) -> bool; 3] = [|_| false, |b| b < 0x20, |b| b == 0x1a];
        for s in &strings {
            for reject in rejects {
                let got = decode_rejecting(s, reject).unwrap();
                assert_eq!(got.as_deref(), one_by_one(s, reject).as_deref(), "{s:?}");
            }
        }
    }

    /// Every byte is kept or written `%XX`, as `curl_easy_escape` writes
    /// it, and a result reaching C's buffer limit is too large.
    #[test]
    fn escapes_every_byte_up_to_the_limit() {
        let all: Vec<u8> = (0..=255).collect();
        let mut want = Vec::new();
        for &b in &all {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                want.push(b);
            } else {
                want.extend_from_slice(format!("%{b:02X}").as_bytes());
            }
        }
        assert_eq!(escape(&all).unwrap(), want);
        assert_eq!(escape(b"").unwrap(), b"");
        let kept = vec![b'a'; MAX_INPUT - 1];
        assert_eq!(escape(&kept).unwrap().len(), MAX_INPUT - 1);
        assert_eq!(escape(&vec![b'a'; MAX_INPUT]), Err(UrlErrorKind::TooLarge));
        let mut escaped = vec![b'a'; MAX_INPUT - 3];
        escaped.push(b' ');
        assert_eq!(escape(&escaped), Err(UrlErrorKind::TooLarge));
        escaped.truncate(MAX_INPUT - 4);
        escaped.push(b' ');
        assert_eq!(escape(&escaped).unwrap().len(), MAX_INPUT - 1);
    }

    #[test]
    fn encodes_a_part_set_alone() {
        let enc = |s: &[u8], plus, path, equals| {
            let mut out = Vec::new();
            encode_part(&mut out, s, plus, path, equals).unwrap();
            out
        };
        assert_eq!(enc(b"a b/=", false, false, false), b"a%20b%2F%3D");
        assert_eq!(enc(b"a b/=", true, true, false), b"a+b/=");
        assert_eq!(enc(b"a==b", false, false, true), b"a=%3Db");
        let mut out = Vec::new();
        uppercase_hex(&mut out, b"%2f%zz%a%41x%e9").unwrap();
        assert_eq!(out, b"%2F%zz%a%41x%E9");
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
