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
    use super::{ONES, has_below};
    let control = if allow_space { 0x1f } else { 0x20 };
    // Eight bytes at a time: one below the control limit, or DEL, which
    // xor'ed with DEL is zero.
    let (words, tail) = s.as_chunks::<8>();
    words.iter().any(|&w| {
        let word = u64::from_ne_bytes(w);
        has_below(word, control + 1) || has_below(word ^ (ONES * 0x7f), 1)
    }) || tail.iter().any(|&b| b <= control || b == 0x7f)
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
            let run = super::find_byte(&s[i + 1..], b'%').map_or(s.len(), |n| i + 1 + n);
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
    // The whole length first, so the buffer is allocated once. No limit
    // but memory: C's `curl_easy_escape` has none.
    let len: usize = s
        .iter()
        .map(|&b| usize::from(ESCAPED[usize::from(b)][3]))
        .sum();
    let mut out = Bytes::new();
    out.try_reserve_exact(len)
        .map_err(|_| UrlErrorKind::OutOfMemory)?;
    out.try_resize(len, 0)
        .map_err(|_| UrlErrorKind::OutOfMemory)?;
    let written = escape_into(s, &mut out[..]);
    assert_eq!(written, len, "the length counted is the length written");
    Ok(out)
}

/// Each byte as [`escape`] writes it, in the first bytes, and how many
/// those are, in the last: the byte itself and 1 for letters, digits and
/// `-._~`, `%XX` and 3 for the rest.
static ESCAPED: [[u8; 4]; 256] = {
    let mut table = [[0; 4]; 256];
    let mut b = 0;
    while b < 256 {
        let c = b as u8;
        table[b] = if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~') {
            [c, 0, 0, 1]
        } else {
            [b'%', UPPER_HEX[b >> 4], UPPER_HEX[b & 0xf], 3]
        };
        b += 1;
    }
    table
};

/// A byte of an output buffer, set or not before it is written.
pub(super) trait Slot: Copy {
    fn new(b: u8) -> Self;
}

impl Slot for u8 {
    fn new(b: u8) -> Self {
        b
    }
}

impl Slot for core::mem::MaybeUninit<u8> {
    fn new(b: u8) -> Self {
        core::mem::MaybeUninit::new(b)
    }
}

/// [`escape`] into the start of `out`: how many bytes it wrote. Bytes of
/// `out` past those may be written too.
///
/// # Panics
///
/// If `out` is shorter than the escaped string.
pub(super) fn escape_into<T: Slot>(s: &[u8], out: &mut [T]) -> usize {
    let (mut i, mut o) = (0, 0);
    // Eight bytes at a time while their escapes surely fit, into a window
    // the compiler can see they stay within: no byte's entry is longer
    // than three, and every store is four.
    while let (Some(chunk), Some(window)) = (s.get(i..i + 8), out.get_mut(o..o + 28)) {
        let window: &mut [T; 28] = window.try_into().expect("28 bytes");
        let mut at = 0;
        for &b in chunk {
            let e = &ESCAPED[usize::from(b)];
            let dst: &mut [T; 4] = (&mut window[at..at + 4]).try_into().expect("four bytes");
            *dst = e.map(T::new);
            at += usize::from(e[3] & 3);
        }
        i += 8;
        o += at;
    }
    for &b in &s[i..] {
        let e = &ESCAPED[usize::from(b)];
        let n = usize::from(e[3]);
        // All four bytes in one store while they fit, whatever the
        // entry's length: the next byte's overwrites the rest.
        if let Some(dst) = out.get_mut(o..o + 4) {
            let dst: &mut [T; 4] = dst.try_into().expect("four bytes");
            *dst = e.map(T::new);
        } else {
            for (d, &v) in out[o..o + n].iter_mut().zip(e) {
                *d = T::new(v);
            }
        }
        o += n;
    }
    o
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

    /// Eight bytes at a time, a control byte, DEL or (unless allowed) a
    /// space is found wherever it is, and no other byte is taken for one.
    #[test]
    fn bad_octets_are_found_in_words_as_byte_by_byte() {
        for allow_space in [false, true] {
            let bad = |b: u8| b < 0x20 || b == 0x7f || (b == b' ' && !allow_space);
            for b in 0..=255u8 {
                for len in 1..20 {
                    for at in 0..len {
                        let mut s = vec![b'a'; len];
                        s[at] = b;
                        assert_eq!(bad_octets(&s, allow_space), bad(b), "{b} at {at} of {len}");
                        // Bytes around it that are not bad leave it alone.
                        s.fill(0x80 | b);
                        s[at] = b;
                        assert_eq!(bad_octets(&s, allow_space), bad(b), "{b} in high bytes");
                    }
                }
            }
        }
    }

    /// Escaping eight bytes at a time writes what escaping one by one
    /// does, at every length and mix of kept and escaped bytes around the
    /// chunks' edges, into a buffer of the exact length or of three times
    /// the input's.
    #[test]
    fn escapes_in_chunks_as_byte_by_byte() {
        let one_by_one = |s: &[u8]| -> Vec<u8> {
            s.iter()
                .flat_map(|&b| {
                    if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                        vec![b]
                    } else {
                        format!("%{b:02X}").into_bytes()
                    }
                })
                .collect()
        };
        // Bytes in an order mixing runs of each kind.
        let pool: Vec<u8> = (0..=255u8).map(|b| b.wrapping_mul(167)).collect();
        for len in 0..48 {
            for start in [0, 7, 48, 97, 200] {
                let s: Vec<u8> = pool.iter().cycle().skip(start).take(len).copied().collect();
                let want = one_by_one(&s);
                assert_eq!(escape(&s).unwrap(), want, "{s:?}");
                let mut wide = vec![0xaa; 3 * len];
                let n = escape_into(&s, &mut wide[..]);
                assert_eq!(wide[..n], want, "{s:?}");
            }
        }
        for kind in *b"a " {
            for len in 0..48 {
                let s = vec![kind; len];
                assert_eq!(escape(&s).unwrap(), one_by_one(&s));
            }
        }
    }

    /// Every byte is kept or written `%XX`, as `curl_easy_escape` writes
    /// it, and a result past the URL parser's limit is still made: C's
    /// escaping has no limit.
    #[test]
    fn escapes_every_byte_without_a_limit() {
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
        let kept = vec![b'a'; MAX_INPUT + 1];
        assert_eq!(escape(&kept).unwrap(), kept);
        let spaces = vec![b' '; MAX_INPUT / 3 + 1];
        let escaped = escape(&spaces).unwrap();
        assert_eq!(escaped.len(), 3 * spaces.len());
        assert!(escaped.chunks(3).all(|c| c == b"%20"));
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
