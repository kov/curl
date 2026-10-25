//! Base64 as C's `curlx_base64_decode` reads it, and base64url as
//! `curlx_base64url_encode` writes it.

use curl_alloc::{OutOfMemory, TryVec as _};

/// The value of a base64 digit, or none.
fn digit(b: u8) -> Option<u8> {
    Some(match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
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
    let mut out = Vec::new();
    out.try_reserve_exact(text.len() / 4 * 3 - padding)
        .map_err(|_| OutOfMemory)?;
    for (i, group) in text.chunks(4).enumerate() {
        let last = i == text.len() / 4 - 1;
        let pads = if last { padding } else { 0 };
        let mut n = 0u32;
        for &b in &group[..4 - pads] {
            let Some(v) = digit(b) else {
                return Ok(None);
            };
            n = n << 6 | u32::from(v);
        }
        n <<= 6 * pads;
        let bytes = n.to_be_bytes();
        out.try_extend_from_slice(&bytes[1..4 - pads])?;
    }
    Ok(Some(out))
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

    /// unit1302's base64url cases.
    #[test]
    fn base64url_is_written_as_curlx_writes_it() {
        for (bytes, want) in [
            (&b"\xff\x01\xfe\x02"[..], &b"_wH-Ag"[..]),
            (b"\xff\xff\xff\xff", b"_____w"),
            (b"\x00\xff\x00\xff", b"AP8A_w"),
            (b"\x00\x00\x00\x00", b"AAAAAA"),
            (b"\x01", b"AQ"),
            (b"\x0f", b"Dw"),
            (b"Man", b"TWFu"),
            (b"", b""),
        ] {
            assert_eq!(encode_url(bytes).unwrap(), want, "{bytes:?}");
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
