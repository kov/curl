//! What a connection received and no request has used yet.

use std::io;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::RecvFailed;
use super::io::Recv;

/// Received bytes no request has used yet.
#[derive(Debug, Default)]
pub(crate) struct RecvBuf {
    /// What waits, then the room earlier reads made: room is zeroed as
    /// it is first made, not again for each read, which may be many in a
    /// step, each taking a few bytes of a large room.
    bytes: Vec<u8>,
    /// How much of `bytes` waits to be used.
    filled: usize,
}

impl RecvBuf {
    /// Holding `bytes`, received elsewhere and not used yet.
    pub(crate) fn holding(bytes: Vec<u8>) -> RecvBuf {
        let filled = bytes.len();
        RecvBuf { bytes, filled }
    }

    /// What is waiting to be used.
    pub(crate) fn filled(&self) -> &[u8] {
        &self.bytes[..self.filled]
    }

    /// The first `n` bytes were used.
    pub(crate) fn consume(&mut self, n: usize) {
        assert!(n <= self.filled, "only what waits is used");
        self.bytes.copy_within(n..self.filled, 0);
        self.filled -= n;
    }

    /// What is waiting, taken out whole, leaving it empty: no copy.
    pub(crate) fn take(&mut self) -> Vec<u8> {
        self.bytes.truncate(self.filled);
        self.filled = 0;
        std::mem::take(&mut self.bytes)
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
        let len = self.filled;
        let end = len.checked_add(max).ok_or(RecvFailed::OutOfMemory)?;
        if let Some(more) = end.checked_sub(self.bytes.len()) {
            self.bytes
                .try_reserve_exact(more)
                .map_err(|_| RecvFailed::OutOfMemory)?;
            #[expect(clippy::disallowed_methods, reason = "reserved just above")]
            self.bytes.resize(end, 0);
        }
        let got = read(&mut self.bytes[len..end]);
        let n = match &got {
            Ok(Recv::Data(n)) => n.get(),
            Ok(Recv::Eof | Recv::WouldBlock) | Err(_) => 0,
        };
        if n > max {
            return Err(RecvFailed::Os(io::ErrorKind::InvalidData.into()));
        }
        self.filled = len + n;
        got.map_err(RecvFailed::Os)
    }
}

/// Bytes received and held until the layer above takes them, what it took
/// let go of as more comes, as C's `bufq` frees each chunk read: what is
/// stored stays within about twice what is held plus what comes at once,
/// however much passes through.
///
/// The bytes are one slice behind what was taken, moved to the front
/// before more are added once what was taken is at least as much as
/// what is held, or the more would not fit beside it: each byte is moved
/// at most once for every byte taken, never on a take, and never to make
/// room the storage already has. A queue of chunks would free as it goes
/// too, but splits what is held where the layer above reads it whole;
/// draining the front on each take moves everything held on every read.
#[derive(Debug, Default)]
pub(crate) struct HeldBytes {
    /// `bytes[taken..]` is what is held.
    bytes: Vec<u8>,
    taken: usize,
}

impl HeldBytes {
    /// What is held, not taken yet.
    pub(crate) fn held(&self) -> &[u8] {
        &self.bytes[self.taken..]
    }

    /// Take as much of what is held as `buf` has room for into it: how
    /// much.
    pub(crate) fn take(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.held().len());
        buf[..n].copy_from_slice(&self.held()[..n]);
        self.taken += n;
        n
    }

    /// Hold `more` behind what is held, what was taken let go of first.
    pub(crate) fn push(&mut self, more: &[u8]) -> Result<(), OutOfMemory> {
        let held = self.bytes.len() - self.taken;
        let room = self.bytes.capacity() - self.bytes.len();
        if self.taken > 0 && (self.taken >= held || more.len() > room) {
            self.bytes.copy_within(self.taken.., 0);
            self.bytes.truncate(held);
            self.taken = 0;
        }
        self.bytes.try_extend_from_slice(more)
    }

    /// The bytes stored to hold what is held.
    #[cfg(test)]
    pub(crate) fn stored(&self) -> usize {
        self.bytes.capacity()
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

    /// Bytes held come out in the order they came, whatever the sizes
    /// of what comes and of what is taken, and what was taken is let go
    /// of: the storage stays within twice the most ever held.
    #[test]
    fn held_bytes_come_out_in_order_and_what_was_taken_goes() {
        let mut held = HeldBytes::default();
        let mut model = std::collections::VecDeque::new();
        let (mut next, mut most, mut buf) = (0u32, 0, vec![0; 5000]);
        for round in 0..2000usize {
            let more: Vec<u8> = (0..(round * 7919) % 3001)
                .map(|_| {
                    next += 1;
                    (next % 251) as u8
                })
                .collect();
            held.push(&more).unwrap();
            model.extend(&more);
            most = most.max(held.held().len());
            let want = (round * 104_729) % 4001;
            let n = held.take(&mut buf[..want]);
            assert_eq!(n, want.min(model.len()));
            let expected: Vec<u8> = model.drain(..n).collect();
            assert_eq!(buf[..n], expected, "round {round}");
            assert_eq!(held.held(), model.make_contiguous());
            assert!(
                held.stored() <= 2 * most,
                "round {round}: {} stored for at most {most} held",
                held.stored()
            );
        }
    }
}
