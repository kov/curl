//! HTTP Datagrams in capsules (RFC 9297), as a CONNECT-UDP tunnel carries
//! each UDP datagram (RFC 9298; `vquic/capsule.c`): a DATAGRAM capsule,
//! type 0, its length as a QUIC variable-length integer, then context id
//! 0 and the datagram. A capsule the peer sent is read here and nowhere
//! else: whatever it holds, a read says what came or why it is refused,
//! as C's does, and never trusts a length past what is there.

use std::fmt;
use std::io;
use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::RecvFailed;
use super::buf::RecvBuf;
use super::io::{Events, Recv, Sent};
use super::layer::{Below, Handshake, Layer, LayerAnswer, LayerCx, LayerQuery};
use super::part::Part;
use crate::components::Component;
use crate::error::ErrorKind;

/// What each way holds before it waits: four chunks of 16 KiB
/// (`CAPSULE_RECV_CHUNKS`, `CAPSULE_SEND_CHUNKS`). A limit only to taking
/// more: a capsule always fits whole (`BUFQ_OPT_SOFT_LIMIT`).
const HOLD: usize = 4 * CHUNK;

/// What one read from below fills at most (`CAPSULE_CHUNK_SIZE`).
const CHUNK: usize = 16 * 1024;

/// The most a capsule's header takes: its type, an 8-byte length and the
/// context id (`HTTP_CAPSULE_HEADER_MAX_SIZE`).
pub(crate) const HEADER_MAX: usize = 10;

/// The largest value a variable-length integer holds (RFC 9000, 16).
const VARINT_MAX: u64 = (1 << 62) - 1;

/// The header of a capsule carrying a datagram of `payload` bytes, and how
/// much of it there is (`capsule_encap_udp_hdr`).
pub(crate) fn header(payload: usize) -> ([u8; HEADER_MAX], usize) {
    let mut hdr = [0; HEADER_MAX];
    // The context id counts in the length.
    let length = u64::try_from(payload).map_or(u64::MAX, |n| n.saturating_add(1));
    assert!(length <= VARINT_MAX, "a datagram is far smaller");
    let n: usize = match length {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    };
    // The top two bits say the size: 0, 1, 2 or 3 for 1, 2, 4 or 8 bytes.
    let tag = u64::from(n.trailing_zeros()) << (8 * n - 2);
    let bytes = (length | tag).to_be_bytes();
    // hdr[0] is the type, DATAGRAM's 0; the context id after the length is 0.
    hdr[1..1 + n].copy_from_slice(&bytes[8 - n..]);
    (hdr, 1 + n + 1)
}

/// What the bytes at the front of a capsule stream hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// Not a whole capsule yet.
    More,
    /// A datagram, `len` bytes from `at`; the capsule ends with it.
    Datagram { at: usize, len: usize },
    /// A capsule with no datagram in it, its `skip` bytes to be passed
    /// over: what C reads as nothing, its tunnel closed.
    Empty { skip: usize },
    /// A capsule refused, the first `skip` bytes to be passed over.
    Bad { skip: usize, why: Bad },
}

/// Why a capsule is refused, said as C says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bad {
    /// Not a DATAGRAM capsule.
    Type(u8),
    /// A context id other than the tunnel's one, 0.
    Context(u8),
    /// No room even for the context id.
    ZeroLength,
    /// More than memory can hold.
    TooLarge(u64),
    /// A datagram larger than the room to read it into.
    DoesNotFit { len: usize, room: usize },
    /// A capsule larger than the receive buffer, which is full.
    Overflows(usize),
}

impl fmt::Display for Bad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Bad::Type(t) => write!(f, "Error! Invalid capsule type: {t}"),
            Bad::Context(id) => write!(f, "Error! Invalid context ID: {id:02x}"),
            Bad::ZeroLength => write!(f, "Error! Invalid capsule length: 0"),
            Bad::TooLarge(length) => write!(f, "Error! Capsule length too large: {length}"),
            Bad::DoesNotFit { len, room } => {
                write!(
                    f,
                    "UDP payload does not fit destination buffer: {len} > {room}"
                )
            }
            Bad::Overflows(len) => {
                write!(f, "Error! Capsule does not fit the receive buffer: {len}")
            }
        }
    }
}

/// The capsule at the front of `buf`, a datagram read into `room` bytes
/// at most, `full` if the buffer can take no more
/// (`Curl_capsule_process_udp_raw`).
pub(crate) fn next(buf: &[u8], room: usize, full: bool) -> Next {
    let Some(&kind) = buf.first() else {
        return Next::More;
    };
    if kind != 0 {
        return Next::Bad {
            skip: 1,
            why: Bad::Type(kind),
        };
    }
    let Some((length, n)) = varint(&buf[1..]) else {
        return Next::More;
    };
    let offset = 1 + n;
    let Some(&context) = buf.get(offset) else {
        return Next::More;
    };
    if context != 0 {
        return Next::Bad {
            skip: offset + 1,
            why: Bad::Context(context),
        };
    }
    let offset = offset + 1;
    if length == 0 {
        return Next::Bad {
            skip: offset,
            why: Bad::ZeroLength,
        };
    }
    let Some(len) = usize::try_from(length - 1)
        .ok()
        .filter(|len| len.checked_add(offset).is_some())
    else {
        return Next::Bad {
            skip: 0,
            why: Bad::TooLarge(length),
        };
    };
    if len > room {
        // C passes over what of the datagram is there.
        return Next::Bad {
            skip: (offset + len).min(buf.len()),
            why: Bad::DoesNotFit { len, room },
        };
    }
    if buf.len() < offset + len {
        if full {
            return Next::Bad {
                skip: 0,
                why: Bad::Overflows(len),
            };
        }
        return Next::More;
    }
    if len == 0 {
        return Next::Empty { skip: offset };
    }
    Next::Datagram { at: offset, len }
}

/// The variable-length integer at the front of `buf`, and how many bytes
/// it took; none if it is not all there.
fn varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let n = 1usize << (first >> 6);
    let bytes = buf.get(..n)?;
    let value = bytes[1..]
        .iter()
        .fold(u64::from(first & 0x3f), |v, &b| (v << 8) | u64::from(b));
    Some((value, n))
}

/// The layer that carries datagrams in capsules over a CONNECT-UDP
/// tunnel's stream (`cf-capsule.c`): each datagram sent is one capsule,
/// taken whole and sent as the layers below take it; each read gives one
/// datagram, from the capsules read from below.
#[derive(Debug, Default)]
pub(crate) struct CapsuleLayer {
    rx: RecvBuf,
    /// Capsules taken to send, the first `sent` bytes of them sent.
    out: Vec<u8>,
    sent: usize,
    /// Why it failed, if it failed of its own.
    failure: Option<ErrorKind>,
}

impl CapsuleLayer {
    /// The layer over a tunnel whose proxy sent `received` after its
    /// answer, which are the first capsules' bytes.
    pub(crate) fn holding(received: Vec<u8>) -> CapsuleLayer {
        CapsuleLayer {
            rx: RecvBuf::holding(received),
            ..CapsuleLayer::default()
        }
    }

    /// Its failure, kept to be asked for.
    fn failed(&mut self, kind: ErrorKind) -> io::Error {
        self.failure.get_or_insert(kind);
        io::Error::other("the capsule layer failed")
    }

    /// Bytes taken to send and not yet sent.
    fn unsent(&self) -> usize {
        self.out.len() - self.sent
    }

    /// Send what it holds as far as the layers below take it
    /// (`cf_capsule_flush`): whether all of it went.
    fn send_held(&mut self, cx: &mut dyn LayerCx, mut below: Below<'_>) -> io::Result<bool> {
        while self.unsent() > 0 {
            match below.reborrow().send(cx, &self.out[self.sent..])? {
                Sent::Bytes(n) => self.sent += n.get(),
                Sent::WouldBlock => return Ok(false),
            }
        }
        self.out.clear();
        self.sent = 0;
        Ok(true)
    }

    /// `bytes` taken as a capsule (`Curl_capsule_encap_udp_datagram`).
    fn take(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        // What was sent goes first, so the buffer holds what waits.
        self.out.drain(..self.sent);
        self.sent = 0;
        let (hdr, n) = header(bytes.len());
        // Room for both first, so a capsule is taken whole or not at all.
        self.out
            .try_reserve(n + bytes.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let oom = |OutOfMemory| ErrorKind::OutOfMemory;
        self.out.try_extend_from_slice(&hdr[..n]).map_err(oom)?;
        self.out.try_extend_from_slice(bytes).map_err(oom)
    }
}

impl Layer for CapsuleLayer {
    /// What came from below, as much as it holds room for, then the first
    /// capsule's datagram (`cf_capsule_recv`).
    fn recv(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
        buf: &mut [u8],
    ) -> io::Result<Recv> {
        while self.rx.filled().len() < HOLD {
            let room = CHUNK - self.rx.filled().len() % CHUNK;
            match self.rx.fill(room, |room| below.reborrow().recv(cx, room)) {
                Ok(Recv::Data(_)) => {}
                Ok(Recv::WouldBlock | Recv::Eof) => break,
                Err(RecvFailed::OutOfMemory) => return Err(self.failed(ErrorKind::OutOfMemory)),
                Err(RecvFailed::Os(e)) => return Err(e),
            }
        }
        let full = self.rx.filled().len() >= HOLD;
        match next(self.rx.filled(), buf.len(), full) {
            Next::More => Ok(Recv::WouldBlock),
            Next::Datagram { at, len } => {
                buf[..len].copy_from_slice(&self.rx.filled()[at..at + len]);
                self.rx.consume(at + len);
                Ok(Recv::Data(
                    NonZeroUsize::new(len).expect("a datagram is not empty"),
                ))
            }
            // Nothing read, and no error: what C's QUIC filter takes for
            // its tunnel closed.
            Next::Empty { skip } => {
                self.rx.consume(skip);
                Ok(Recv::Eof)
            }
            Next::Bad { skip, why } => {
                self.rx.consume(skip);
                cx.info(format_args!("{why}"));
                Err(self.failed(ErrorKind::RecvError))
            }
        }
    }

    /// `bytes`, one datagram, taken whole as a capsule and sent as far as
    /// the layers below take it; when it already holds all it may, what
    /// it holds goes first (`cf_capsule_send`).
    fn send(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
        bytes: &[u8],
    ) -> io::Result<Sent> {
        if self.unsent() >= HOLD && !self.send_held(cx, below.reborrow())? {
            return Ok(Sent::WouldBlock);
        }
        if let Err(kind) = self.take(bytes) {
            return Err(self.failed(kind));
        }
        // What the layers below do not take now waits here.
        self.send_held(cx, below)?;
        Ok(Sent::Bytes(
            NonZeroUsize::new(bytes.len()).expect("a send is not empty"),
        ))
    }

    fn flush(&mut self, cx: &mut dyn LayerCx, mut below: Below<'_>) -> io::Result<bool> {
        Ok(self.send_held(cx, below.reborrow())? && below.flush(cx)?)
    }
}

impl Part<Below<'_>> for CapsuleLayer {
    /// It wants to write while it holds capsules to send
    /// (`cf_capsule_adjust_pollset`).
    fn adjust_pollset(&self, wanted: Events) -> Events {
        if self.unsent() > 0 {
            wanted | Events::OUT
        } else {
            wanted
        }
    }

    fn data_pending(&self, below: Below<'_>) -> bool {
        !self.rx.filled().is_empty() || below.data_pending()
    }

    /// What it holds to send goes, as far as it can now
    /// (`cf_capsule_shutdown`).
    fn shutdown(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        match self.send_held(cx, below) {
            Ok(_) => Ok(Handshake::Done),
            Err(_) => Err(self.failure.unwrap_or(ErrorKind::SendError)),
        }
    }

    fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        match (q, self.failure) {
            (LayerQuery::Failure, Some(kind)) => Some(LayerAnswer::Failure(kind)),
            _ => None,
        }
    }

    fn filter(&self) -> Option<Component> {
        Some(Component::Capsule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capsule(payload: &[u8]) -> Vec<u8> {
        let (hdr, n) = header(payload.len());
        [&hdr[..n], payload].concat()
    }

    /// A header's length takes as few bytes as its value needs, with the
    /// context id counted in it (RFC 9000's examples of each size).
    #[test]
    fn a_header_s_length_is_the_shortest_varint() {
        assert_eq!(header(0), ([0, 1, 0, 0, 0, 0, 0, 0, 0, 0], 3));
        let (hdr, n) = header(62);
        assert_eq!(&hdr[..n], [0, 0x3f, 0]);
        let (hdr, n) = header(63);
        assert_eq!(&hdr[..n], [0, 0x40, 0x40, 0]);
        let (hdr, n) = header(0x3ffe);
        assert_eq!(&hdr[..n], [0, 0x7f, 0xff, 0]);
        let (hdr, n) = header(0x3fff);
        assert_eq!(&hdr[..n], [0, 0x80, 0, 0x40, 0, 0]);
        let (hdr, n) = header(0x4000_0000 - 1);
        assert_eq!(&hdr[..n], [0, 0xc0, 0, 0, 0, 0x40, 0, 0, 0, 0]);
        for len in [0, 1, 62, 63, 1200, 0x3fff, 70_000] {
            let (hdr, n) = header(len);
            assert_eq!(varint(&hdr[1..n]), Some(((len + 1) as u64, n - 2)));
        }
    }

    /// A capsule read back gives its datagram; one cut short anywhere
    /// is more to wait for.
    #[test]
    fn a_whole_capsule_is_its_datagram_and_a_part_waits() {
        let c = capsule(b"quic packet");
        assert_eq!(next(&c, 64, false), Next::Datagram { at: 3, len: 11 });
        for cut in 0..c.len() {
            assert_eq!(next(&c[..cut], 64, false), Next::More, "cut at {cut}");
        }
        let big = capsule(&[7; 300]);
        assert_eq!(next(&big, 300, false), Next::Datagram { at: 4, len: 300 });
        assert_eq!(
            next(&big[..2], 300, false),
            Next::More,
            "a varint cut short"
        );
    }

    /// Only a DATAGRAM capsule for context 0 with room for its id is
    /// read; each refusal passes over what C passes over.
    #[test]
    fn a_capsule_of_another_kind_is_refused() {
        assert_eq!(
            next(&[1, 1, 0], 64, false),
            Next::Bad {
                skip: 1,
                why: Bad::Type(1)
            }
        );
        assert_eq!(
            next(&[0, 2, 9, 7], 64, false),
            Next::Bad {
                skip: 3,
                why: Bad::Context(9)
            }
        );
        assert_eq!(
            next(&[0, 0, 0], 64, false),
            Next::Bad {
                skip: 3,
                why: Bad::ZeroLength
            }
        );
        assert_eq!(next(&[0, 1, 0, 0xff], 64, false), Next::Empty { skip: 3 });
        assert_eq!(Bad::Context(9).to_string(), "Error! Invalid context ID: 09");
    }

    /// A length past the room, or past a full buffer, is refused, never
    /// read: the bytes it claims need not be there.
    #[test]
    fn a_length_past_the_room_or_the_buffer_is_refused() {
        let c = capsule(&[1; 100]);
        assert_eq!(
            next(&c, 50, false),
            Next::Bad {
                skip: 104,
                why: Bad::DoesNotFit { len: 100, room: 50 }
            }
        );
        assert_eq!(
            next(&c[..40], 50, false),
            Next::Bad {
                skip: 40,
                why: Bad::DoesNotFit { len: 100, room: 50 }
            },
            "only what is there is passed over"
        );
        assert_eq!(
            next(&c[..40], 100, true),
            Next::Bad {
                skip: 0,
                why: Bad::Overflows(100)
            }
        );
        let huge = [0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0];
        // A length any `usize` holds, here, waits for its bytes.
        #[cfg(target_pointer_width = "64")]
        assert_eq!(next(&huge, usize::MAX, false), Next::More);
        assert_eq!(
            next(&huge, 1 << 20, false),
            Next::Bad {
                skip: 10,
                why: Bad::DoesNotFit {
                    len: (VARINT_MAX - 1) as usize,
                    room: 1 << 20
                }
            }
        );
        assert_eq!(
            Bad::TooLarge(VARINT_MAX).to_string(),
            "Error! Capsule length too large: 4611686018427387903"
        );
    }

    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use crate::conn::io::{Conversation, FakeNet, Peer};
    use crate::time::ManualClock;

    /// The layers under the capsule layer, as scripted: its receives give
    /// what comes, its sends take as much as each step allows.
    #[derive(Debug, Default)]
    struct Script {
        incoming: VecDeque<Vec<u8>>,
        /// How much each send takes; all, once the steps are used.
        takes: VecDeque<usize>,
        sent: Vec<u8>,
    }

    #[derive(Debug)]
    struct Wire(Arc<Mutex<Script>>);

    impl Part<Below<'_>> for Wire {}

    impl Layer for Wire {
        fn recv(&mut self, _: &mut dyn LayerCx, _: Below<'_>, buf: &mut [u8]) -> io::Result<Recv> {
            let mut s = self.0.lock().unwrap();
            let Some(mut chunk) = s.incoming.pop_front() else {
                return Ok(Recv::WouldBlock);
            };
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            if n < chunk.len() {
                s.incoming.push_front(chunk.split_off(n));
            }
            Ok(Recv::Data(NonZeroUsize::new(n).unwrap()))
        }

        fn send(&mut self, _: &mut dyn LayerCx, _: Below<'_>, bytes: &[u8]) -> io::Result<Sent> {
            let mut s = self.0.lock().unwrap();
            let n = s.takes.pop_front().unwrap_or(bytes.len()).min(bytes.len());
            s.sent.extend(&bytes[..n]);
            Ok(NonZeroUsize::new(n).map_or(Sent::WouldBlock, Sent::Bytes))
        }
    }

    /// A context noting what is said.
    #[derive(Default)]
    struct Said(Vec<String>);

    impl LayerCx for Said {
        fn now(&self) -> crate::time::Instant {
            crate::time::Clock::now(&ManualClock::new().unwrap())
        }
        fn of(&mut self, _: Component, _: fmt::Arguments<'_>) {}
        fn info(&mut self, line: fmt::Arguments<'_>) {
            self.0.push(line.to_string());
        }
    }

    /// Run `f` on a capsule layer over the scripted layers.
    fn over(
        script: &Arc<Mutex<Script>>,
        f: impl FnOnce(&mut dyn FnMut(&mut dyn FnMut(&mut CapsuleLayer, Below<'_>, &mut Said))),
    ) {
        over_with(script, CapsuleLayer::default(), f);
    }

    /// `over`, the layer `capsules`.
    fn over_with(
        script: &Arc<Mutex<Script>>,
        mut capsules: CapsuleLayer,
        f: impl FnOnce(&mut dyn FnMut(&mut dyn FnMut(&mut CapsuleLayer, Below<'_>, &mut Said))),
    ) {
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(ManualClock::new().unwrap())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, Conversation::new(b"", false));
        let socket = crate::conn::io::dial(&mut net, at);
        let mut layers: [Box<dyn Layer>; 1] = [Box::new(Wire(script.clone()))];
        let mut cx = Said::default();
        f(&mut |call| call(&mut capsules, Below::new(&mut layers, &*socket), &mut cx));
    }

    /// Each datagram sent is one capsule, taken whole; what the layers
    /// below do not take waits, goes before the next, and goes on a
    /// flush, which the poll asks for meanwhile.
    #[test]
    fn a_datagram_sent_is_a_capsule_taken_whole() {
        let script = Arc::new(Mutex::new(Script::default()));
        script.lock().unwrap().takes.extend([2, 0]);
        over(&script, |call| {
            call(&mut |c, below, cx| {
                assert_eq!(
                    c.send(cx, below, b"one").unwrap(),
                    Sent::Bytes(NonZeroUsize::new(3).unwrap())
                );
                assert_eq!(c.adjust_pollset(Events::IN), Events::IN | Events::OUT);
            });
            call(&mut |c, below, cx| {
                assert_eq!(
                    c.send(cx, below, b"two").unwrap(),
                    Sent::Bytes(NonZeroUsize::new(3).unwrap())
                );
                assert_eq!(c.adjust_pollset(Events::IN), Events::IN);
            });
            assert_eq!(
                script.lock().unwrap().sent,
                [capsule(b"one"), capsule(b"two")].concat()
            );
            script.lock().unwrap().takes.push_back(0);
            call(&mut |c, below, cx| {
                c.send(cx, below, b"three").unwrap();
            });
            call(&mut |c, below, cx| assert!(c.flush(cx, below).unwrap()));
            assert!(script.lock().unwrap().sent.ends_with(&capsule(b"three")));
        });
    }

    /// A send while all it may hold waits goes nowhere, until what it
    /// holds goes (`cf_capsule_send` over a full buffer).
    #[test]
    fn a_send_while_full_waits() {
        let script = Arc::new(Mutex::new(Script::default()));
        script.lock().unwrap().takes.extend([0; HOLD / 1200 + 2]);
        over(&script, |call| {
            call(&mut |c, mut below, cx| {
                let big = vec![1; 1200];
                while c.unsent() < HOLD {
                    c.send(cx, below.reborrow(), &big).unwrap();
                }
                assert_eq!(c.send(cx, below, &big).unwrap(), Sent::WouldBlock);
            });
        });
    }

    /// Capsules read from below give a datagram each, however the bytes
    /// came; a bad one fails the read, said as C says it, and the
    /// failure is the layer's.
    #[test]
    fn capsules_read_give_a_datagram_each() {
        let script = Arc::new(Mutex::new(Script::default()));
        let both = [capsule(b"first"), capsule(b"second")].concat();
        script
            .lock()
            .unwrap()
            .incoming
            .extend([both[..4].to_vec(), both[4..].to_vec()]);
        over(&script, |call| {
            call(&mut |c, mut below, cx| {
                let mut buf = [0; 64];
                assert_eq!(
                    c.recv(cx, below.reborrow(), &mut buf).unwrap(),
                    Recv::Data(NonZeroUsize::new(5).unwrap())
                );
                assert_eq!(&buf[..5], b"first");
                assert!(c.data_pending(below.reborrow()), "the second waits");
                assert_eq!(
                    c.recv(cx, below.reborrow(), &mut buf).unwrap(),
                    Recv::Data(NonZeroUsize::new(6).unwrap())
                );
                assert_eq!(&buf[..6], b"second");
                assert_eq!(c.recv(cx, below, &mut buf).unwrap(), Recv::WouldBlock);
            });
            script.lock().unwrap().incoming.push_back(vec![5, 1, 0]);
            call(&mut |c, below, cx| {
                let mut buf = [0; 64];
                assert!(c.recv(cx, below, &mut buf).is_err());
                assert_eq!(cx.0, ["Error! Invalid capsule type: 5"]);
                assert_eq!(
                    c.query(LayerQuery::Failure),
                    Some(LayerAnswer::Failure(ErrorKind::RecvError))
                );
            });
        });
    }

    /// What the proxy sent after its answer, held when the layer goes on,
    /// is the first capsules', read before anything below.
    #[test]
    fn what_came_with_the_answer_is_read_first() {
        let script = Arc::new(Mutex::new(Script::default()));
        // A capsule cut between what was held and what comes after.
        let too = capsule(b"too");
        script
            .lock()
            .unwrap()
            .incoming
            .extend([[&too[2..], &capsule(b"after")].concat()]);
        let held = [capsule(b"held"), too[..2].to_vec()].concat();
        over_with(&script, CapsuleLayer::holding(held), |call| {
            call(&mut |c, mut below, cx| {
                let mut buf = [0; 64];
                assert!(c.data_pending(below.reborrow()));
                for want in [&b"held"[..], b"too", b"after"] {
                    let got = c.recv(cx, below.reborrow(), &mut buf).unwrap();
                    assert_eq!(got, Recv::Data(NonZeroUsize::new(want.len()).unwrap()));
                    assert_eq!(&buf[..want.len()], want);
                }
            });
        });
    }
}
