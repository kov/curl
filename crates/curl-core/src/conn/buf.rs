//! What a connection received and no request has used yet.

use std::io;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::RecvFailed;
use super::io::Recv;
use super::layer::LayerCx;
use super::quic::RecvRoom;

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

    /// The room reads have made, waiting bytes and all.
    #[cfg(test)]
    pub(crate) fn room(&self) -> usize {
        self.bytes.len()
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

    /// Hold `bytes`, its own emptied first: what a read in the multi's
    /// buffer left, kept by the connection it was read from.
    fn hold(&mut self, bytes: &[u8]) -> Result<(), OutOfMemory> {
        self.bytes.clear();
        self.filled = 0;
        self.bytes.try_extend_from_slice(bytes)?;
        self.filled = bytes.len();
        Ok(())
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

/// The multi's buffer its transfers' connections receive in (C's
/// `xfer_buf`): made at the first receive, grown to the most any read in
/// it has asked for, and lent to one receive at a time, its room warm
/// for each where a buffer of each connection's own would be cold
/// whenever many take turns. Nothing waits in it between loans.
#[derive(Debug)]
pub(crate) enum XferBuf {
    Kept(RecvBuf),
    /// A receive has it.
    Lent,
}

impl Default for XferBuf {
    fn default() -> XferBuf {
        XferBuf::Kept(RecvBuf::default())
    }
}

impl XferBuf {
    /// The buffer, lent until [`XferBuf::give`]. Lending it twice is a
    /// receive inside a receive, which nothing does: C refuses it
    /// (`attempt to borrow xfer_buf when already borrowed`), and no input
    /// can make one.
    fn lend(&mut self) -> RecvBuf {
        match std::mem::replace(self, XferBuf::Lent) {
            XferBuf::Kept(buf) => buf,
            XferBuf::Lent => panic!("the multi's receive buffer is lent to one receive at a time"),
        }
    }

    /// The buffer lent, given back empty: what one connection received
    /// is never read as another's.
    fn give(&mut self, buf: RecvBuf) {
        assert!(
            matches!(self, XferBuf::Lent),
            "only a buffer lent is given back"
        );
        assert!(
            buf.filled().is_empty(),
            "the multi's receive buffer goes back empty"
        );
        *self = XferBuf::Kept(buf);
    }
}

/// What the multi lends a receive: the room QUIC's datagrams are read
/// into, and the buffer a stream's bytes are.
#[derive(Debug, Default)]
pub(crate) struct Rooms {
    pub(crate) datagrams: RecvRoom,
    pub(crate) bytes: XferBuf,
}

/// What holds a connection's received bytes, for the multi's buffer to
/// take their place while a read is in it.
pub(crate) trait HoldsRx {
    /// Put `rx` in place of the bytes held, which are given back.
    fn swap_rx(&mut self, rx: RecvBuf) -> RecvBuf;
}

impl HoldsRx for super::ConnLease {
    fn swap_rx(&mut self, rx: RecvBuf) -> RecvBuf {
        std::mem::replace(self.get().rx_mut(), rx)
    }
}

impl HoldsRx for super::mux::Carrier<'_> {
    fn swap_rx(&mut self, rx: RecvBuf) -> RecvBuf {
        std::mem::replace(self.rx_mut(), rx)
    }
}

/// Run `read`, which reads `conn` once and uses what came, with the
/// multi's buffer, if `cx` lends one, in place of the connection's own
/// (`Curl_multi_xfer_buf_borrow`): the buffer is the call's and no
/// longer, and goes back to the multi as it ends. What `read` left unused
/// moves to the connection's own buffer, to be given first by its next
/// read. Bytes already waiting in its own are read from there, nothing
/// lent; with no multi, a read is in the connection's own.
pub(crate) fn lending<C, T, R>(
    cx: &mut C,
    conn: &mut T,
    read: impl FnOnce(&mut C, &mut T) -> R,
) -> Result<R, OutOfMemory>
where
    C: LayerCx + ?Sized,
    T: HoldsRx + ?Sized,
{
    let Some(lender) = cx.recv_buf() else {
        return Ok(read(cx, conn));
    };
    let lent = lender.lend();
    let own = conn.swap_rx(lent);
    if !own.filled().is_empty() {
        let lent = conn.swap_rx(own);
        give_back(cx, lent);
        return Ok(read(cx, conn));
    }
    let mut own = own;
    let r = read(cx, conn);
    let mut lent = conn.swap_rx(RecvBuf::default());
    let kept = own.hold(lent.filled());
    lent.filled = 0;
    conn.swap_rx(own);
    give_back(cx, lent);
    kept.map(|()| r)
}

fn give_back<C: LayerCx + ?Sized>(cx: &mut C, buf: RecvBuf) {
    cx.recv_buf()
        .expect("the context that lent the buffer takes it back")
        .give(buf);
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

    /// A connection's received bytes, as a test holds them.
    #[derive(Default)]
    struct Held(RecvBuf);

    impl HoldsRx for Held {
        fn swap_rx(&mut self, rx: RecvBuf) -> RecvBuf {
            std::mem::replace(&mut self.0, rx)
        }
    }

    /// Work done for a multi that lends `rooms`, or for none.
    fn work(rooms: Option<&mut Rooms>) -> crate::trace::InternalCx<'_> {
        let clock = crate::time::ManualClock::new().unwrap();
        crate::trace::InternalCx {
            now: crate::time::Clock::now(&clock),
            trace: None,
            room: rooms,
        }
    }

    /// `bytes` arrive on `conn`, read in whatever buffer it holds now:
    /// where they were read.
    fn arrive(conn: &mut Held, bytes: &[u8]) -> *const u8 {
        conn.0
            .fill(64, |room| {
                room[..bytes.len()].copy_from_slice(bytes);
                data(bytes.len())
            })
            .unwrap();
        conn.0.filled().as_ptr()
    }

    fn kept(rooms: &Rooms) -> &RecvBuf {
        match &rooms.bytes {
            XferBuf::Kept(buf) => buf,
            XferBuf::Lent => panic!("the buffer is still lent"),
        }
    }

    /// A read is in the multi's buffer, which goes back to the multi
    /// empty as the read ends; what the read left is the connection's,
    /// given first by its next read, which borrows nothing for it.
    #[test]
    fn a_read_is_in_the_multis_buffer_and_what_it_left_in_the_connections() {
        let mut rooms = Rooms::default();
        let mut conn = Held::default();
        let at = lending(&mut work(Some(&mut rooms)), &mut conn, |_, conn| {
            let at = arrive(conn, b"abcdef");
            conn.0.consume(4);
            at
        })
        .unwrap();
        assert_eq!(kept(&rooms).bytes.as_ptr(), at, "read in the multi's");
        assert_eq!(kept(&rooms).filled(), b"", "given back empty");
        assert_eq!(conn.0.filled(), b"ef", "what was left stays");
        assert_ne!(conn.0.filled().as_ptr(), at, "in the connection's own");
        lending(&mut work(Some(&mut rooms)), &mut conn, |cx, conn| {
            assert!(
                matches!(cx.recv_buf(), Some(XferBuf::Kept(_))),
                "nothing is lent for what waits"
            );
            assert_eq!(conn.0.filled(), b"ef");
            conn.0.consume(2);
        })
        .unwrap();
        let again = lending(&mut work(Some(&mut rooms)), &mut conn, |_, conn| {
            let at = arrive(conn, b"gh");
            conn.0.consume(2);
            at
        })
        .unwrap();
        assert_eq!(again, at, "the multi's, warm, again");
        assert_eq!(conn.0.filled(), b"");
    }

    /// What one connection's read left in the multi's buffer is never
    /// read as the next connection's.
    #[test]
    fn one_connections_bytes_are_never_anothers() {
        let mut rooms = Rooms::default();
        let (mut a, mut b) = (Held::default(), Held::default());
        lending(&mut work(Some(&mut rooms)), &mut a, |_, a| {
            arrive(a, b"abc");
            a.0.consume(1);
        })
        .unwrap();
        let seen = lending(&mut work(Some(&mut rooms)), &mut b, |_, b| {
            arrive(b, b"xyz");
            let seen = b.0.filled().to_vec();
            b.0.consume(3);
            seen
        })
        .unwrap();
        assert_eq!(seen, b"xyz");
        assert_eq!(a.0.filled(), b"bc");
    }

    /// With no multi to lend one, a read is in the connection's own.
    #[test]
    fn with_no_multi_a_read_is_in_the_connections_own() {
        let mut conn = Held::default();
        let at = lending(&mut work(None), &mut conn, |_, conn| {
            let at = arrive(conn, b"abc");
            conn.0.consume(1);
            at
        })
        .unwrap();
        assert_eq!(conn.0.filled(), b"bc");
        assert_eq!(conn.0.filled().as_ptr(), at, "where it was read");
    }

    /// A receive inside a receive on the multi's buffer is a bug of
    /// ours, which nothing makes: it fails loudly.
    #[test]
    #[should_panic(expected = "lent to one receive at a time")]
    fn a_receive_inside_a_receive_is_refused() {
        let mut rooms = Rooms::default();
        let (mut a, mut b) = (Held::default(), Held::default());
        lending(&mut work(Some(&mut rooms)), &mut a, |cx, _| {
            lending(cx, &mut b, |_, _| ()).unwrap();
        })
        .unwrap();
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
