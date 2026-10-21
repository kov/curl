//! What a connection received and no request has used yet.

use curl_alloc::OutOfMemory;

/// Received bytes no request has used yet.
#[derive(Debug, Default)]
pub(crate) struct RecvBuf {
    bytes: Vec<u8>,
}

impl RecvBuf {
    /// What is waiting to be used.
    pub(crate) fn filled(&self) -> &[u8] {
        &self.bytes
    }

    /// The first `n` bytes were used.
    pub(crate) fn consume(&mut self, n: usize) {
        self.bytes.drain(..n);
    }

    /// Room for `n` more bytes, behind what is waiting, to be filled and
    /// then kept with `commit`.
    pub(crate) fn room(&mut self, n: usize) -> Result<&mut [u8], OutOfMemory> {
        let len = self.bytes.len();
        self.bytes.try_reserve_exact(n).map_err(|_| OutOfMemory)?;
        #[expect(clippy::disallowed_methods, reason = "reserved just above")]
        self.bytes.resize(len + n, 0);
        Ok(&mut self.bytes[len..])
    }

    /// Of the room just made, keep the first `n` bytes, which were filled.
    pub(crate) fn commit(&mut self, room: usize, n: usize) {
        assert!(n <= room, "filled more than the room");
        self.bytes.truncate(self.bytes.len() - room + n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn received_bytes_wait_until_used() {
        let mut rx = RecvBuf::default();
        rx.room(8).unwrap()[..3].copy_from_slice(b"abc");
        rx.commit(8, 3);
        assert_eq!(rx.filled(), b"abc");
        rx.room(4).unwrap()[..2].copy_from_slice(b"de");
        rx.commit(4, 2);
        assert_eq!(rx.filled(), b"abcde", "behind what waits");
        rx.consume(2);
        assert_eq!(rx.filled(), b"cde");
    }
}
