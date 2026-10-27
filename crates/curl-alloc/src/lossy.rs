//! Bytes shown as text without allocating.

use std::fmt;

/// Bytes shown as `String::from_utf8_lossy` shows them, each run of bytes
/// that is not UTF-8 written as one U+FFFD, but written straight to the
/// formatter instead of into a `String` that cannot fail to allocate.
///
/// The text is written as it is, without the formatter's width or
/// precision; nothing formats these bytes with either.
pub struct Lossy<'a>(pub &'a [u8]);

impl fmt::Display for Lossy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty() {
                f.write_str("\u{FFFD}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Lossy;

    fn same(bytes: &[u8]) {
        let want = String::from_utf8_lossy(bytes);
        assert_eq!(Lossy(bytes).to_string(), want, "{bytes:02x?}");
    }

    /// Invalid, truncated and valid bytes read as `from_utf8_lossy` reads
    /// them: one U+FFFD for each maximal invalid run, not for each byte.
    #[test]
    fn shows_bytes_as_from_utf8_lossy() {
        for bytes in [
            &b""[..],
            b"plain ascii",
            "caf\u{e9} \u{1f600}".as_bytes(),
            b"\xe2\x82",
            b"a\xe2\x82",
            b"\xff\xff",
            b"\xed\xa0\x80",
            b"\xc0\x80",
            b"x\xf0\x9f\x98",
            b"caf\xe9 au lait",
            b"\x80abc\xfe\xfd\xf4\x90\x80\x80z",
        ] {
            same(bytes);
        }
        assert_eq!(Lossy(b"\xe2\x82").to_string(), "\u{FFFD}");
        assert_eq!(Lossy(b"\xff\xff").to_string(), "\u{FFFD}\u{FFFD}");
    }

    /// Every input of up to two bytes, and many three-byte ones starting
    /// at a lead byte, agree with `from_utf8_lossy`.
    #[test]
    fn agrees_on_every_short_input() {
        for a in 0..=255u8 {
            same(&[a]);
            for b in 0..=255u8 {
                same(&[a, b]);
                if a >= 0xc0 {
                    for c in [0x00, 0x7f, 0x80, 0xbf, 0xc0, 0xff] {
                        same(&[a, b, c]);
                    }
                }
            }
        }
    }
}
