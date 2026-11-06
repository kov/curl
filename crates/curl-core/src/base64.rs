//! Base64 as C's `curlx_base64_decode` reads it and
//! `curlx_base64_encode` writes it, and base64url as
//! `curlx_base64url_encode` writes it.

use curl_alloc::{OutOfMemory, TryVec as _};

/// What `DIGITS` holds for a byte that is no base64 digit.
const NOT_DIGIT: u8 = 0xff;

/// The value of each byte as a base64 digit, or `NOT_DIGIT`.
const DIGITS: [u8; 256] = {
    let mut digits = [NOT_DIGIT; 256];
    let mut i = 0;
    while i < 64 {
        digits[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    digits
};

/// The 24 bits of a group of base64 digits, none if one is no digit.
fn group_bits(group: &[u8]) -> Option<u32> {
    let mut n = 0u32;
    for &b in group {
        let v = DIGITS[usize::from(b)];
        if v == NOT_DIGIT {
            return None;
        }
        n = n << 6 | u32::from(v);
    }
    Some(n << (6 * (4 - group.len())))
}

/// `text` decoded as base64 as `curlx_base64_decode` takes it: whole
/// groups of four, at most two `=` and only at the end; none if not.
pub(crate) fn decode(text: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return Ok(None);
    }
    let padding = text.iter().rev().take_while(|&&b| b == b'=').count();
    if padding > 2 {
        return Ok(None);
    }
    // Allocated once, at its length, and written in place: appending
    // three bytes at a time costs a copy call each.
    let len = text.len() / 4 * 3 - padding;
    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|_| OutOfMemory)?;
    out.try_resize(len, 0)?;
    let (whole, last) = text.split_at(text.len() - 4);
    let mut rest = &mut out[..];
    for group in whole.as_chunks::<4>().0 {
        let Some(n) = group_bits(group) else {
            return Ok(None);
        };
        let [a, b, c, tail @ ..] = rest else {
            unreachable!("the length counted holds every group")
        };
        [*a, *b, *c] = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        rest = tail;
    }
    let Some(n) = group_bits(&last[..4 - padding]) else {
        return Ok(None);
    };
    rest.copy_from_slice(&n.to_be_bytes()[1..4 - padding]);
    Ok(Some(out))
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `len` bytes from `bytes` in base64 with padding, into `out`, as
/// `curlx_base64_encode` writes them.
pub(crate) fn encode(
    mut bytes: impl Iterator<Item = u8>,
    len: usize,
    out: &mut Vec<u8>,
) -> Result<(), OutOfMemory> {
    // Grown once, to its length, and written in place.
    let groups = len.div_ceil(3);
    let start = out.len();
    let end = groups
        .checked_mul(4)
        .and_then(|n| n.checked_add(start))
        .ok_or(OutOfMemory)?;
    out.try_reserve_exact(end - start)
        .map_err(|_| OutOfMemory)?;
    out.try_resize(end, 0)?;
    for chunk in out[start..].as_chunks_mut::<4>().0 {
        let group = [bytes.next(), bytes.next(), bytes.next()];
        let n = group
            .iter()
            .fold(0u32, |n, b| n << 8 | u32::from(b.unwrap_or(0)));
        let have = group.iter().filter(|b| b.is_some()).count();
        for (i, c) in chunk.iter_mut().enumerate() {
            *c = if i <= have {
                ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize]
            } else {
                b'='
            };
        }
    }
    Ok(())
}

/// `bytes` in base64url without padding, as `curlx_base64url_encode`
/// writes it.
pub(crate) fn encode_url(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    out.try_reserve_exact((bytes.len() * 4).div_ceil(3))
        .map_err(|_| OutOfMemory)?;
    for group in bytes.chunks(3) {
        let n = group.iter().fold(0u32, |n, &b| n << 8 | u32::from(b)) << (8 * (3 - group.len()));
        for i in 0..=group.len() {
            out.try_push(URL[(n >> (18 - 6 * i) & 0x3f) as usize])?;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table of unit1302's: each row's input, as long as it says,
    /// and its output, as long as it says.
    fn unit1302(name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        let rows = crate::c_source::table("tests/unit/unit1302.c", name, |c| panic!("{c}"));
        assert!(rows.len() > 10, "{name} was read");
        rows.iter()
            .map(|row| {
                let [input, ilen, output, olen] = row.group() else {
                    panic!("{row:?}")
                };
                let cut = |v: &crate::c_source::Value, n: &crate::c_source::Value| {
                    v.str()[..usize::try_from(n.int()).unwrap()].to_vec()
                };
                (cut(input, ilen), cut(output, olen))
            })
            .collect()
    }

    /// unit1302's base64 table: each encoded, and decoded back.
    #[test]
    fn unit1302_encode() {
        for (bytes, want) in unit1302("struct etest encode[]") {
            let mut out = Vec::new();
            encode(bytes.iter().copied(), bytes.len(), &mut out).unwrap();
            assert_eq!(out, want, "{bytes:?}");
            assert_eq!(decode(&want).unwrap(), Some(bytes), "{want:?}");
        }
    }

    /// unit1302: every length of the bytes 0 to 255, encoded to a whole
    /// number of quads and decoded back.
    #[test]
    fn unit1302_binary() {
        let binary: Vec<u8> = (0..=255).collect();
        for len in 1..=binary.len() {
            let mut out = Vec::new();
            encode(binary[..len].iter().copied(), len, &mut out).unwrap();
            assert_eq!(out.len(), len.div_ceil(3) * 4, "{len}");
            assert_eq!(decode(&out).unwrap().as_deref(), Some(&binary[..len]));
        }
    }

    /// unit1302's base64url table.
    #[test]
    fn unit1302_url() {
        for (bytes, want) in unit1302("struct etest url[]") {
            assert_eq!(encode_url(&bytes).unwrap(), want, "{bytes:?}");
        }
    }

    /// unit1302's bad inputs, each refused: the text whole, as C's
    /// decoder reads it to its end.
    #[test]
    fn unit1302_bad() {
        let rows = crate::c_source::table("tests/unit/unit1302.c", "badecode[]", |c| panic!("{c}"));
        assert!(rows.len() > 10, "badecode was read");
        for row in rows {
            let text = row.group()[2].str();
            assert_eq!(decode(text).unwrap(), None, "{text:?}");
        }
    }

    /// unit1302's base64 cases, written after what the buffer held, and
    /// decoded back.
    #[test]
    fn base64_is_written_as_curlx_writes_it() {
        for (bytes, want) in [
            (&b"iiiiii"[..], &b"aWlpaWlp"[..]),
            (b"iiiii", b"aWlpaWk="),
            (b"iiii", b"aWlpaQ=="),
            (b"iii", b"aWlp"),
            (b"ii", b"aWk="),
            (b"i", b"aQ=="),
            (b"\xff\x01\xfe\x02", b"/wH+Ag=="),
            (b"", b""),
        ] {
            let mut out = b"held".to_vec();
            encode(bytes.iter().copied(), bytes.len(), &mut out).unwrap();
            assert_eq!(&out[..4], b"held");
            assert_eq!(&out[4..], want, "{bytes:?}");
            if !bytes.is_empty() {
                assert_eq!(decode(want).unwrap().as_deref(), Some(bytes));
            }
        }
    }

    #[test]
    fn base64_is_decoded_as_curlx_decodes_it() {
        for (text, want) in [
            (&b"TWFu"[..], Some(&b"Man"[..])),
            (b"TWE=", Some(b"Ma")),
            (b"TQ==", Some(b"M")),
            (b"TWFuTWE=", Some(b"ManMa")),
            (b"TQ=", None),
            (b"T===", None),
            (b"TW=u", None),
            (b"TW!u", None),
            (b"", None),
        ] {
            assert_eq!(decode(text).unwrap().as_deref(), want, "{text:?}");
        }
    }
}

/// The counterparts of `tests/perf/base64enc.c` and `base64dec.c`: the
/// same input, loop count and output lines, timing this module. Run by
/// `inventory/measure/perf.py` from a release build of the crate's tests
/// (`--ignored --exact base64::perf::<name> --nocapture`).
#[cfg(test)]
mod perf {
    use std::hint::black_box;
    use std::time::Instant;

    /// `tests/perf`'s default loop count for both.
    const LOOPS: u64 = 10_000_000;

    /// The 256 octets 0-255, base64 encoded (`BLOB64`).
    const BLOB64: &[u8] = b"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMD\
EyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFi\
Y2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5\
SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TF\
xsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19v\
f4+fr7/P3+/w==";

    /// The lines C's programs print, from microseconds as `curlx_now`
    /// measures them.
    fn report(loops: u64, start: Instant) {
        let us = u64::try_from(start.elapsed().as_micros()).unwrap();
        let hn = us * 100_000 / loops;
        println!("Loops:     {loops}");
        println!("Time:      {us} usecs");
        println!("Time/loop: {}.{:02} ns", hn / 100, hn % 100);
    }

    #[test]
    #[ignore = "a benchmark, run by inventory/measure/perf.py"]
    fn base64enc() {
        let array: Vec<u8> = (0..=255).collect();
        let start = Instant::now();
        for _ in 0..LOOPS {
            // As the callers do: a new buffer for each encoding.
            let mut out = Vec::new();
            let bytes = black_box(&array[..]);
            super::encode(bytes.iter().copied(), bytes.len(), &mut out).unwrap();
            black_box(out);
        }
        report(LOOPS, start);
    }

    #[test]
    #[ignore = "a benchmark, run by inventory/measure/perf.py"]
    fn base64dec() {
        assert_eq!(super::decode(BLOB64).unwrap().unwrap().len(), 256);
        let start = Instant::now();
        for _ in 0..LOOPS {
            black_box(super::decode(black_box(BLOB64)).unwrap().unwrap());
        }
        report(LOOPS, start);
    }
}
