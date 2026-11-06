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

/// What `PLACED` holds for a byte that is no base64 digit: a bit no group
/// of digits sets.
const NOT_PLACED: u32 = 1 << 31;

/// The value of each byte as the first, second, third and fourth digit of
/// a group, shifted to its place in the group's 24 bits, or `NOT_PLACED`:
/// a group's bits are its digits' or'ed, a lookup each.
static PLACED: [[u32; 256]; 4] = {
    let mut placed = [[NOT_PLACED; 256]; 4];
    let mut b = 0;
    while b < 256 {
        if DIGITS[b] != NOT_DIGIT {
            let v = DIGITS[b] as u32;
            placed[0][b] = v << 18;
            placed[1][b] = v << 12;
            placed[2][b] = v << 6;
            placed[3][b] = v;
        }
        b += 1;
    }
    placed
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
    // Allocated once, at its length, and appended to within it: eight
    // groups at a time, decoded on the stack.
    let len = text.len() / 4 * 3 - padding;
    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|_| OutOfMemory)?;
    let (whole, last) = text.split_at(text.len() - 4);
    let bits = |g: &[u8; 4]| {
        PLACED[0][usize::from(g[0])]
            | PLACED[1][usize::from(g[1])]
            | PLACED[2][usize::from(g[2])]
            | PLACED[3][usize::from(g[3])]
    };
    let (eights, groups) = whole.as_chunks::<32>();
    for eight in eights {
        // Each group's three bytes are one four-byte store, the next
        // group's overwriting the fourth; their bits checked together.
        let mut decoded = [0u8; 25];
        let mut all = 0;
        for (k, group) in eight.as_chunks::<4>().0.iter().enumerate() {
            let n = bits(group);
            all |= n;
            let dst: &mut [u8; 4] = (&mut decoded[3 * k..3 * k + 4])
                .try_into()
                .expect("four bytes");
            *dst = (n << 8).to_be_bytes();
        }
        if all & NOT_PLACED != 0 {
            return Ok(None);
        }
        out.try_extend_from_slice(&decoded[..24])?;
    }
    for group in groups.as_chunks::<4>().0 {
        let n = bits(group);
        if n & NOT_PLACED != 0 {
            return Ok(None);
        }
        out.try_extend_from_slice(&n.to_be_bytes()[1..])?;
    }
    let Some(n) = group_bits(&last[..4 - padding]) else {
        return Ok(None);
    };
    out.try_extend_from_slice(&n.to_be_bytes()[1..4 - padding])?;
    Ok(Some(out))
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Each 12 bits as the two base64 digits they are: a group of three bytes
/// is two lookups.
static PAIRS: [[u8; 2]; 4096] = {
    let mut pairs = [[0; 2]; 4096];
    let mut n = 0;
    while n < 4096 {
        pairs[n] = [ALPHABET[n >> 6], ALPHABET[n & 0x3f]];
        n += 1;
    }
    pairs
};

/// `bytes` in base64 with padding, after what `out` holds, as
/// `curlx_base64_encode` writes them.
pub(crate) fn encode(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), OutOfMemory> {
    // Grown once, to its length, and written in place.
    let groups = bytes.len().div_ceil(3);
    let start = out.len();
    let end = groups
        .checked_mul(4)
        .and_then(|n| n.checked_add(start))
        .ok_or(OutOfMemory)?;
    out.try_reserve_exact(end - start)
        .map_err(|_| OutOfMemory)?;
    out.try_resize(end, 0)?;
    let digit = |n: u32, shift: u32| ALPHABET[(n >> shift & 0x3f) as usize];
    let (triples, rest) = bytes.as_chunks::<3>();
    let (quads, _) = out[start..].as_chunks_mut::<4>();
    let (whole, last) = quads.split_at_mut(triples.len());
    for (&[a, b, c], quad) in triples.iter().zip(whole) {
        let n = u32::from(a) << 16 | u32::from(b) << 8 | u32::from(c);
        let ([d0, d1], [d2, d3]) = (PAIRS[(n >> 12) as usize], PAIRS[(n & 0xfff) as usize]);
        *quad = [d0, d1, d2, d3];
    }
    match (last, rest) {
        ([], []) => {}
        ([quad], &[a]) => {
            let n = u32::from(a) << 16;
            *quad = [digit(n, 18), digit(n, 12), b'=', b'='];
        }
        ([quad], &[a, b]) => {
            let n = u32::from(a) << 16 | u32::from(b) << 8;
            *quad = [digit(n, 18), digit(n, 12), digit(n, 6), b'='];
        }
        _ => unreachable!("one group for each three bytes, and one for what is left"),
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
            encode(&bytes, &mut out).unwrap();
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
            encode(&binary[..len], &mut out).unwrap();
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
            encode(bytes, &mut out).unwrap();
            assert_eq!(&out[..4], b"held");
            assert_eq!(&out[4..], want, "{bytes:?}");
            if !bytes.is_empty() {
                assert_eq!(decode(want).unwrap().as_deref(), Some(bytes));
            }
        }
    }

    /// A byte that is no digit, or a `=` before the padding, anywhere in
    /// a text of eight groups at a time and more, refuses it whole, as
    /// C's decoder does; the text untouched decodes.
    #[test]
    fn a_bad_digit_anywhere_is_refused() {
        let binary: Vec<u8> = (0..=255).collect();
        let mut text = Vec::new();
        encode(&binary, &mut text).unwrap();
        assert_eq!(decode(&text).unwrap().as_deref(), Some(&binary[..]));
        let digits = text.len() - 2;
        for at in 0..digits {
            for bad in [b'!', b'=', b'\0', 0x80] {
                let mut broken = text.clone();
                broken[at] = bad;
                assert_eq!(decode(&broken).unwrap(), None, "{bad} at {at}");
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
            super::encode(bytes, &mut out).unwrap();
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
