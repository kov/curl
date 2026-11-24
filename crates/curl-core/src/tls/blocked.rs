//! A write a TLS library could not finish, which it wants made again.

use std::hash::{DefaultHasher, Hasher as _};

/// A write a TLS library took and could not finish: it wants the same
/// write made again, with at least as many bytes, the first of them the
/// same, and sends what it took whatever it is given then. Kept as their
/// length and a digest of them, so that a retry with other bytes is
/// refused rather than reported as sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockedWrite {
    len: usize,
    digest: u64,
}

/// Why a retry of a blocked write is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    /// Fewer bytes than were blocked.
    Shorter,
    /// As many or more, but not the ones that were blocked.
    Other,
}

impl BlockedWrite {
    /// The write of `bytes` that could not finish.
    pub fn of(bytes: &[u8]) -> BlockedWrite {
        BlockedWrite {
            len: bytes.len(),
            digest: digest(bytes),
        }
    }

    /// How many bytes it was.
    pub fn len(self) -> usize {
        self.len
    }

    /// Whether it was of no bytes.
    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    /// The bytes of `given` to write again: as many as were blocked, if
    /// they are the ones that were.
    pub fn again(self, given: &[u8]) -> Result<&[u8], Retry> {
        let again = given.get(..self.len).ok_or(Retry::Shorter)?;
        if digest(again) != self.digest {
            return Err(Retry::Other);
        }
        Ok(again)
    }
}

fn digest(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    h.write(bytes);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A retry goes with the blocked bytes from what it is given, as
    /// many or more; fewer, or others, are refused. A write of no bytes
    /// is an empty one.
    #[test]
    fn a_retry_is_the_blocked_bytes_or_refused() {
        let b = BlockedWrite::of(b"01234");
        assert_eq!(b.len(), 5);
        assert!(!b.is_empty());
        assert!(BlockedWrite::of(b"").is_empty());
        assert_eq!(b.again(b"01234"), Ok(&b"01234"[..]));
        assert_eq!(b.again(b"0123456789"), Ok(&b"01234"[..]));
        assert_eq!(b.again(b"0123"), Err(Retry::Shorter));
        assert_eq!(b.again(b""), Err(Retry::Shorter));
        assert_eq!(b.again(b"01235"), Err(Retry::Other));
        assert_eq!(b.again(b"x1234abc"), Err(Retry::Other));
        assert_eq!(BlockedWrite::of(b"").again(b"any"), Ok(&b""[..]));
    }
}
