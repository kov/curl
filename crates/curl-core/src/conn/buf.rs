//! A connection's bytes between the network and its requests: what was
//! received and not yet used, and what was queued and not yet sent.

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the http protocol moves bytes from step 14b")
)]

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

/// Bytes queued to send and not yet sent.
#[derive(Debug, Default)]
pub(crate) struct SendBuf {
    bytes: Vec<u8>,
    /// How many of `bytes` went.
    sent: usize,
}

impl SendBuf {
    /// What is still to send.
    pub(crate) fn pending(&self) -> &[u8] {
        &self.bytes[self.sent..]
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending().is_empty()
    }

    /// Queue what `fill` appends, behind what is pending.
    pub(crate) fn queue<E>(
        &mut self,
        fill: impl FnOnce(&mut Vec<u8>) -> Result<(), E>,
    ) -> Result<(), E> {
        if self.is_empty() {
            self.bytes.clear();
            self.sent = 0;
        }
        let len = self.bytes.len();
        let filled = fill(&mut self.bytes);
        if filled.is_err() {
            self.bytes.truncate(len);
        }
        filled
    }

    /// The first `n` pending bytes went.
    pub(crate) fn sent(&mut self, n: usize) {
        assert!(n <= self.pending().len(), "sent more than was pending");
        self.sent += n;
    }
}

#[cfg(test)]
mod tests {
    use curl_alloc::TryVec as _;

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

    #[test]
    fn queued_bytes_go_in_order() {
        let mut tx = SendBuf::default();
        tx.queue(|b| b.try_extend_from_slice(b"head")).unwrap();
        tx.sent(2);
        tx.queue(|b| b.try_extend_from_slice(b"body")).unwrap();
        assert_eq!(tx.pending(), b"adbody");
        tx.sent(6);
        assert!(tx.is_empty());
        let failed: Result<(), ()> = tx.queue(|b| {
            b.extend_from_slice(b"half");
            Err(())
        });
        assert!(failed.is_err());
        assert!(tx.is_empty(), "a failed fill queues nothing");
    }
}
