//! What a connection received and no request has used yet.

use std::io;

use super::RecvFailed;
use super::io::Recv;

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

    /// Read up to `max` bytes behind what is waiting, with `read`, which
    /// is given that much room and says how much of it it filled. A read
    /// that says it filled more than its room is the socket's error, and
    /// keeps nothing.
    pub(crate) fn fill(
        &mut self,
        max: usize,
        read: impl FnOnce(&mut [u8]) -> io::Result<Recv>,
    ) -> Result<Recv, RecvFailed> {
        let len = self.bytes.len();
        self.bytes
            .try_reserve_exact(max)
            .map_err(|_| RecvFailed::OutOfMemory)?;
        #[expect(clippy::disallowed_methods, reason = "reserved just above")]
        self.bytes.resize(len + max, 0);
        let got = read(&mut self.bytes[len..]);
        let n = match &got {
            Ok(Recv::Data(n)) => n.get(),
            Ok(Recv::Eof | Recv::WouldBlock) | Err(_) => 0,
        };
        if n > max {
            self.bytes.truncate(len);
            return Err(RecvFailed::Os(io::ErrorKind::InvalidData.into()));
        }
        self.bytes.truncate(len + n);
        got.map_err(RecvFailed::Os)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;

    fn data(n: usize) -> io::Result<Recv> {
        Ok(Recv::Data(NonZeroUsize::new(n).unwrap()))
    }

    #[test]
    fn received_bytes_wait_until_used() {
        let mut rx = RecvBuf::default();
        let got = rx.fill(8, |room| {
            room[..3].copy_from_slice(b"abc");
            data(3)
        });
        assert!(matches!(got, Ok(Recv::Data(_))));
        assert_eq!(rx.filled(), b"abc");
        rx.fill(4, |room| {
            room[..2].copy_from_slice(b"de");
            data(2)
        })
        .unwrap();
        assert_eq!(rx.filled(), b"abcde", "behind what waits");
        assert!(matches!(
            rx.fill(4, |_| Ok(Recv::WouldBlock)),
            Ok(Recv::WouldBlock)
        ));
        assert_eq!(rx.filled(), b"abcde", "nothing read keeps nothing");
        rx.consume(2);
        assert_eq!(rx.filled(), b"cde");
    }

    /// A socket that says it read more than the room it was given is in
    /// error: what it says is not believed, and nothing is kept.
    #[test]
    fn a_read_past_its_room_is_an_error() {
        let mut rx = RecvBuf::default();
        rx.fill(2, |room| {
            room.copy_from_slice(b"ab");
            data(2)
        })
        .unwrap();
        let got = rx.fill(4, |room| data(room.len() + 1));
        let Err(RecvFailed::Os(e)) = got else {
            panic!("{got:?}");
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert_eq!(rx.filled(), b"ab");
    }
}
