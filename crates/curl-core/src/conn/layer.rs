//! The layers a connection's bytes pass through between the socket and
//! the protocol (C's connection filters, `cfilters.h`), as a pull chain: a
//! read asks the top layer for at most the caller's length, and each layer
//! reads from the one below it as it needs, down to the socket. A layer
//! that works on the bytes (TLS) is boxed on the stream; those that only
//! pass them once connected (SOCKS, an HTTP proxy's tunnel) are kinds kept
//! inline, so a stream over TCP, a SOCKS proxy or a tunnel allocates
//! nothing for its layers.

use std::fmt;
use std::io;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use super::io::{Events, Recv, Sent, Socket, SocketPoll, poll_together};
use crate::components::Component;
use crate::error::ErrorKind;
use crate::time::Instant;

/// What a layer's handshake, or its shutdown, came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handshake {
    Done,
    /// It waits for the socket.
    Waiting,
}

/// Whether a connection seems usable, as its layers and its socket say
/// (`Curl_conn_is_alive`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Alive {
    Dead,
    /// Usable; with input waiting, which an idle HTTP/1 connection must
    /// not have.
    Alive {
        input_pending: bool,
    },
}

/// A question one layer asks another (C's `cf->cft->query`); TLS's come
/// with it.
#[expect(dead_code, reason = "TLS's ALPN and certificates, step 43")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LayerQuery {}

/// What a layer answers a `LayerQuery`.
#[expect(dead_code, reason = "TLS's ALPN and certificates, step 43")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LayerAnswer {}

/// What a layer reaches while it works: the time, and the trace of the
/// transfer it works for. An argument, never stored. A pool's section,
/// which works for no transfer, has a silent one.
pub(crate) trait LayerCx {
    fn now(&self) -> Instant;

    /// Trace a line of `component`'s, if it is.
    fn of(&mut self, component: Component, line: fmt::Arguments<'_>);

    /// A line of the transfer's verbose output (`infof`).
    fn info(&mut self, line: fmt::Arguments<'_>);

    /// A call on the socket failed with `e`: a connect, a send or a
    /// receive; the transfer keeps its number (`state.os_errno`). Work
    /// done for no transfer keeps nothing.
    fn socket_failed(&mut self, _e: &io::Error) {}

    /// The transfer fails with `kind`, for the reason `why` (`failf`):
    /// kept if it is the first given, and traced. Work done for no
    /// transfer says nothing.
    fn fails(&mut self, kind: ErrorKind, _why: fmt::Arguments<'_>) -> ErrorKind {
        kind
    }

    /// Bytes for the transfer's debug handler (`Curl_debug`), if it is
    /// verbose.
    fn bytes(&mut self, _kind: crate::handler::DebugKind, _bytes: &[u8]) {}

    /// The transfer traces to a debug handler (C's `data->set.fdebug`
    /// and `verbose`).
    fn debugs(&self) -> bool {
        false
    }

    /// The report of the transfer, if it asked for its peer's chain
    /// (`CURLOPT_CERTINFO`). Work done for no transfer reports none.
    fn certinfo_report(&mut self) -> Option<&mut crate::report::TransferReport> {
        None
    }

    /// What the TLS library made of the origin's certificate, for the
    /// transfer's report (`set.ssl.certverifyresult`). Work done for no
    /// transfer keeps nothing.
    fn tls_verified(&mut self, _result: i64) {}
}

/// The context of work done for no transfer: it traces nothing, as C's
/// internal handle is not traced.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Silent(pub(crate) Instant);

impl LayerCx for Silent {
    fn now(&self) -> Instant {
        self.0
    }

    fn of(&mut self, _: Component, _: fmt::Arguments<'_>) {}

    fn info(&mut self, _: fmt::Arguments<'_>) {}
}

/// A layer that works on a connection's bytes (C's `Curl_cftype`). Its
/// `destroy` is `Drop`; its `cntrl` codes are methods of their own.
pub(crate) trait Layer: Send + fmt::Debug {
    /// Move its handshake on: TLS's, which may take more than one pass.
    /// A layer that has none is connected at once.
    fn connect(
        &mut self,
        _cx: &mut dyn LayerCx,
        _below: Below<'_>,
    ) -> Result<Handshake, ErrorKind> {
        Ok(Handshake::Done)
    }

    /// Read into `buf`, which is not empty, at most its length, from
    /// what it holds or from below.
    fn recv(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, buf: &mut [u8]) -> io::Result<Recv>;

    /// Send from `bytes`, which is not empty, through the layers below.
    fn send(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, bytes: &[u8]) -> io::Result<Sent>;

    /// What the transfer is to wait for on the socket, given what it
    /// wants (TLS wants to write while it reads).
    fn adjust_pollset(&self, wanted: Events) -> Events {
        wanted
    }

    /// Whether it, or a layer below, holds bytes a poll of the socket
    /// cannot see.
    fn data_pending(&self, below: Below<'_>) -> bool {
        below.data_pending()
    }

    /// Whether the connection seems usable, asking below.
    fn is_alive(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Alive {
        below.alive(cx)
    }

    /// Move its shutdown on: say goodbye to the peer, which may take
    /// more than one pass (TLS's close_notify). Only a test's layer has
    /// one yet.
    fn shutdown(
        &mut self,
        _cx: &mut dyn LayerCx,
        _below: Below<'_>,
    ) -> Result<Handshake, ErrorKind> {
        Ok(Handshake::Done)
    }

    /// Answer another layer's question, if it can. None asks one yet.
    #[expect(dead_code, reason = "TLS's ALPN and certificates, step 43")]
    fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        match q {}
    }
}

/// The layers below one, then the socket: the stack split at the layer
/// being called, so a layer reads and writes the ones below without
/// aliasing itself.
pub(crate) struct Below<'a> {
    /// Bottom first.
    layers: &'a mut [Box<dyn Layer>],
    socket: &'a dyn Socket,
}

impl<'a> Below<'a> {
    /// The layers `layers`, bottom first, over `socket`, for a test.
    #[cfg(test)]
    pub(crate) fn new(layers: &'a mut [Box<dyn Layer>], socket: &'a dyn Socket) -> Below<'a> {
        Below { layers, socket }
    }
}

impl Below<'_> {
    /// The same layers and socket, for one call that leaves them to the
    /// caller after.
    pub(crate) fn reborrow(&mut self) -> Below<'_> {
        Below {
            layers: &mut *self.layers,
            socket: self.socket,
        }
    }

    pub(crate) fn recv(self, cx: &mut dyn LayerCx, buf: &mut [u8]) -> io::Result<Recv> {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.recv(cx, Below { layers, ..self }, buf),
            None => self.socket.recv(buf).inspect_err(|e| cx.socket_failed(e)),
        }
    }

    pub(crate) fn send(self, cx: &mut dyn LayerCx, bytes: &[u8]) -> io::Result<Sent> {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.send(cx, Below { layers, ..self }, bytes),
            None => self.socket.send(bytes).inspect_err(|e| cx.socket_failed(e)),
        }
    }

    /// The socket holds nothing a poll cannot see.
    pub(crate) fn data_pending(self) -> bool {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.data_pending(Below { layers, ..self }),
            None => false,
        }
    }

    /// The socket polled at once for anything to read, priority and
    /// urgent data among it (`cf_socket_conn_is_alive`).
    pub(crate) fn alive(self, cx: &mut dyn LayerCx) -> Alive {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.is_alive(cx, Below { layers, ..self }),
            None => {
                let asked = Events::RDNORM | Events::IN | Events::RDBAND | Events::PRI;
                let mut watch = [SocketPoll::new(self.socket, asked)];
                let polled = poll_together(&mut watch, &mut [], Duration::ZERO);
                alive_of(polled.map(|_| watch[0].revents()))
            }
        }
    }
}

/// What a poll of the socket for input says of the connection: a failed
/// poll, an error, a hang-up, urgent data or a bad descriptor is dead;
/// nothing at all is alive; anything else is input pending
/// (`cf_socket_conn_is_alive`).
fn alive_of(revents: io::Result<Events>) -> Alive {
    let dead = Events::ERR | Events::HUP | Events::PRI | Events::NVAL;
    match revents {
        Err(_) => Alive::Dead,
        Ok(r) if r.is_empty() => Alive::Alive {
            input_pending: false,
        },
        Ok(r) if r.intersects(dead) => Alive::Dead,
        Ok(_) => Alive::Alive {
            input_pending: true,
        },
    }
}

/// A stream's layers that work on its bytes, bottom first. Empty, it
/// allocates nothing; it is held by one pointer, as every transfer's
/// state holds a connection's inline and the first layer, TLS's, is
/// rare.
#[derive(Debug, Default)]
pub(crate) struct LayerStack {
    #[expect(
        clippy::box_collection,
        reason = "one pointer in every transfer's state"
    )]
    layers: Option<Box<Vec<Box<dyn Layer>>>>,
}

impl LayerStack {
    /// The stack over `socket`, from its top.
    pub(crate) fn over<'a>(&'a mut self, socket: &'a dyn Socket) -> Below<'a> {
        Below {
            layers: self
                .layers
                .as_deref_mut()
                .map_or(&mut [], Vec::as_mut_slice),
            socket,
        }
    }

    /// Put `layer` on top.
    pub(crate) fn push(&mut self, layer: Box<dyn Layer>) -> Result<(), OutOfMemory> {
        let layers = match &mut self.layers {
            Some(layers) => layers,
            None => self.layers.insert(try_box(Vec::new())?),
        };
        layers.try_push(layer)
    }

    /// Move the top layer's handshake on over the layers below it and
    /// `socket`, as the setup adds and connects one filter at a time;
    /// with no layer, there is none to make.
    pub(crate) fn connect(
        &mut self,
        socket: &dyn Socket,
        cx: &mut dyn LayerCx,
    ) -> Result<Handshake, ErrorKind> {
        let Below { layers, socket } = self.over(socket);
        match layers.split_last_mut() {
            Some((top, layers)) => top.connect(cx, Below { layers, socket }),
            None => Ok(Handshake::Done),
        }
    }

    /// What the transfer is to wait for, given what it wants, each layer
    /// adjusting it from the top down (`Curl_conn_cf_adjust_pollset`).
    pub(crate) fn adjust_pollset(&self, wanted: Events) -> Events {
        self.layers
            .iter()
            .flat_map(|l| l.iter())
            .rev()
            .fold(wanted, |wanted, layer| layer.adjust_pollset(wanted))
    }

    /// Shut its layers down over `socket` from the top, past the `shut`
    /// done already, counting each that finishes: a layer starts once the
    /// one above is done (`Curl_cshutdn_try_once_idx`).
    pub(crate) fn shutdown(
        &mut self,
        socket: &dyn Socket,
        cx: &mut dyn LayerCx,
        shut: &mut usize,
    ) -> Result<Handshake, ErrorKind> {
        let layers = self
            .layers
            .as_deref_mut()
            .map_or(&mut [][..], Vec::as_mut_slice);
        while *shut < layers.len() {
            let (below, top) = layers.split_at_mut(layers.len() - 1 - *shut);
            let below = Below {
                layers: below,
                socket,
            };
            if top[0].shutdown(cx, below)? == Handshake::Waiting {
                return Ok(Handshake::Waiting);
            }
            *shut += 1;
        }
        Ok(Handshake::Done)
    }

    /// What the layers not shut down yet wait on, `shut` from the top
    /// being done: each says, from the top, with nothing wanted to start
    /// from; a layer shut down says nothing (`Curl_conn_cf_adjust_pollset`).
    pub(crate) fn shutdown_pollset(&self, shut: usize) -> Events {
        self.layers
            .iter()
            .flat_map(|l| l.iter())
            .rev()
            .skip(shut)
            .fold(Events::NONE, |wanted, layer| layer.adjust_pollset(wanted))
    }
}

/// How a connection's `Lingering` layer shuts down.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Linger {
    /// It waits this many tries, then is done.
    Passes(u32),
    /// It waits until its peer sends something or closes.
    UntilPeer,
}

/// A layer whose shutdown waits, as TLS's does for the peer's
/// close_notify: what arms a closing connection before TLS can. It passes
/// the bytes, and while it shuts down waits to read.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub(crate) struct Lingering {
    how: Linger,
    shutting: bool,
}

#[cfg(any(test, feature = "test-util"))]
impl Lingering {
    pub(crate) fn boxed(how: Linger) -> Result<Box<dyn Layer>, OutOfMemory> {
        Ok(try_box(Lingering {
            how,
            shutting: false,
        })?)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Layer for Lingering {
    fn recv(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        below.recv(cx, buf)
    }

    fn send(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, bytes: &[u8]) -> io::Result<Sent> {
        below.send(cx, bytes)
    }

    fn adjust_pollset(&self, wanted: Events) -> Events {
        if self.shutting {
            wanted | Events::IN
        } else {
            wanted
        }
    }

    fn shutdown(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        self.shutting = true;
        match &mut self.how {
            Linger::Passes(0) => Ok(Handshake::Done),
            Linger::Passes(n) => {
                *n -= 1;
                Ok(Handshake::Waiting)
            }
            Linger::UntilPeer => match below.recv(cx, &mut [0u8; 64]) {
                Ok(Recv::WouldBlock) => Ok(Handshake::Waiting),
                Ok(Recv::Data(_) | Recv::Eof) => Ok(Handshake::Done),
                Err(_) => Err(ErrorKind::RecvError),
            },
        }
    }
}

/// Layers for the tests of what the stack asks of its layers.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Passes the bytes, and asks to write whenever the transfer waits,
    /// as TLS does with bytes to flush.
    #[derive(Debug)]
    pub(crate) struct WantsOut;

    pub(crate) fn wants_out() -> Box<dyn Layer> {
        try_box(WantsOut).unwrap()
    }

    impl Layer for WantsOut {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            below.recv(cx, buf)
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            below.send(cx, bytes)
        }

        fn adjust_pollset(&self, wanted: Events) -> Events {
            wanted | Events::OUT
        }
    }

    /// Makes the letters it passes upper case, both ways.
    #[derive(Debug)]
    pub(crate) struct Upper;

    pub(crate) fn upper() -> Box<dyn Layer> {
        try_box(Upper).unwrap()
    }

    impl Layer for Upper {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            let got = below.recv(cx, buf)?;
            if let Recv::Data(n) = got {
                buf[..n.get()].make_ascii_uppercase();
            }
            Ok(got)
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            let mut upper = [0u8; 4096];
            let n = bytes.len().min(upper.len());
            upper[..n].copy_from_slice(&bytes[..n]);
            upper[..n].make_ascii_uppercase();
            below.send(cx, &upper[..n])
        }
    }

    /// Reads what is below, and gives it only at the next read: the read
    /// that took it would block, as TLS's may with a record half read.
    #[derive(Debug, Default)]
    pub(crate) struct Holdback {
        held: Vec<u8>,
    }

    pub(crate) fn holdback() -> Box<dyn Layer> {
        try_box(Holdback::default()).unwrap()
    }

    impl Layer for Holdback {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            if let Some(n) = std::num::NonZeroUsize::new(self.held.len().min(buf.len())) {
                buf[..n.get()].copy_from_slice(&self.held[..n.get()]);
                self.held.drain(..n.get());
                return Ok(Recv::Data(n));
            }
            let got = below.recv(cx, buf)?;
            match got {
                Recv::Data(n) => {
                    self.held.try_extend_from_slice(&buf[..n.get()]).unwrap();
                    Ok(Recv::WouldBlock)
                }
                Recv::Eof | Recv::WouldBlock => Ok(got),
            }
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            below.send(cx, bytes)
        }

        fn data_pending(&self, below: Below<'_>) -> bool {
            !self.held.is_empty() || below.data_pending()
        }
    }

    /// A `Holdback` holding `bytes` already.
    pub(crate) fn holding(bytes: &[u8]) -> Box<dyn Layer> {
        try_box(Holdback {
            held: bytes.to_vec(),
        })
        .unwrap()
    }

    /// Passes the bytes, and says the connection is dead.
    #[derive(Debug)]
    pub(crate) struct Dying;

    pub(crate) fn dying() -> Box<dyn Layer> {
        try_box(Dying).unwrap()
    }

    impl Layer for Dying {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            below.recv(cx, buf)
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            below.send(cx, bytes)
        }

        fn is_alive(&mut self, _: &mut dyn LayerCx, _: Below<'_>) -> Alive {
            Alive::Dead
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{holdback, holding, upper};
    use super::*;
    use crate::conn::io::{Conversation, FakeNet, Peer};
    use crate::time::{Clock as _, ManualClock};

    /// A socket of the fake network's to a peer that does as `peer` says,
    /// holding `talk` if it accepts.
    fn socket(peer: Peer, talk: &Conversation) -> (Box<dyn Socket>, Silent) {
        let clock = ManualClock::new().unwrap();
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(clock.clone())
            .with_peer(at, peer)
            .with_conversation(at, talk.clone());
        (crate::conn::io::dial(&mut net, at), Silent(clock.now()))
    }

    /// The socket at the bottom is polled as `cf_socket_conn_is_alive`
    /// polls it: nothing is alive; something to read alone is input
    /// pending; an error or a hang-up is dead, whatever else is there.
    #[test]
    fn the_socket_says_whether_the_connection_is_alive() {
        let talk = Conversation::replies(&[b"x"], false).per_send();
        let (s, mut cx) = socket(Peer::Accepts, &talk);
        let below = || Below {
            layers: &mut [],
            socket: &*s,
        };
        assert_eq!(
            below().alive(&mut cx),
            Alive::Alive {
                input_pending: false
            }
        );
        below().send(&mut cx, b"hello").unwrap();
        assert_eq!(
            below().alive(&mut cx),
            Alive::Alive {
                input_pending: true
            }
        );
        let (refused, mut cx) = socket(Peer::Refuses, &talk);
        let below = Below {
            layers: &mut [],
            socket: &*refused,
        };
        assert_eq!(below.alive(&mut cx), Alive::Dead);
    }

    /// A socket that is ready for `0` now, and polls as nothing else.
    #[derive(Debug)]
    struct Ready(Events);

    impl Socket for Ready {
        fn key(&self) -> crate::conn::io::SocketKey {
            crate::conn::io::SocketKey::new(3)
        }
        fn readiness(&self) -> crate::conn::io::Readiness<'_> {
            crate::conn::io::Readiness::Known {
                now: self.0,
                later: None,
            }
        }
        fn take_error(&self) -> io::Result<Option<io::Error>> {
            unreachable!()
        }
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            unreachable!()
        }
        fn set(&self, _: crate::conn::io::SocketOption) -> io::Result<()> {
            unreachable!()
        }
        fn set_nonblocking(&self) -> io::Result<()> {
            unreachable!()
        }
        fn connect(&self, _: std::net::SocketAddr) -> io::Result<crate::conn::io::Connect> {
            unreachable!()
        }
        fn recv(&self, _: &mut [u8]) -> io::Result<Recv> {
            unreachable!()
        }
        fn send(&self, _: &[u8]) -> io::Result<Sent> {
            unreachable!()
        }
        fn release(self: Box<Self>) -> crate::conn::io::SocketKey {
            unreachable!()
        }
    }

    /// The health check asks for urgent and priority data as well as
    /// normal data, as C's does: urgent data, as TCP's out-of-band byte,
    /// is dead; priority band data alone, or normal data said both ways,
    /// is input pending (`cf_socket_conn_is_alive`).
    #[test]
    fn urgent_data_is_dead_and_any_other_input_pending() {
        let alive = |ready: Events| {
            let s = Ready(ready);
            let below = Below {
                layers: &mut [],
                socket: &s,
            };
            below.alive(&mut Silent(ManualClock::new().unwrap().now()))
        };
        let pending = Alive::Alive {
            input_pending: true,
        };
        assert_eq!(alive(Events::PRI), Alive::Dead);
        assert_eq!(alive(Events::IN | Events::PRI), Alive::Dead);
        assert_eq!(alive(Events::RDBAND), pending);
        assert_eq!(alive(Events::IN | Events::RDNORM), pending);
        assert_eq!(alive(Events::RDNORM), pending);
        assert_eq!(alive(Events::IN | Events::HUP), Alive::Dead);
        assert_eq!(alive(Events::NVAL), Alive::Dead);
        // Ready only to send is asked nothing of.
        assert_eq!(
            alive(Events::OUT),
            Alive::Alive {
                input_pending: false
            }
        );
        assert_eq!(alive_of(Err(io::ErrorKind::Other.into())), Alive::Dead);
    }

    /// A real socket with bytes to read is input pending: the kernel says
    /// `IN` and `RDNORM` together once both are asked.
    #[test]
    fn a_real_socket_with_bytes_to_read_is_input_pending() {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = listener.local_addr().unwrap();
        let socket = curl_os::net::open(at, curl_os::net::Protocol::Tcp, true).unwrap();
        socket.connect(at).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let below = || Below {
            layers: &mut [],
            socket: &socket,
        };
        let mut cx = Silent(ManualClock::new().unwrap().now());
        assert_eq!(
            below().alive(&mut cx),
            Alive::Alive {
                input_pending: false
            }
        );
        peer.write_all(b"x").unwrap();
        // Loopback delivers before the write returns; the poll is at once.
        assert_eq!(
            below().alive(&mut cx),
            Alive::Alive {
                input_pending: true
            }
        );
    }

    /// A layer that keeps the defaults passes the question below: the
    /// pollset as it is wanted, and data pending as the layers below hold
    /// it.
    #[test]
    fn a_layer_s_defaults_ask_below() {
        let talk = Conversation::replies(&[], false);
        let (s, _) = socket(Peer::Accepts, &talk);
        assert_eq!(upper().adjust_pollset(Events::IN), Events::IN);
        let mut holds = [holding(b"x"), upper()];
        let below = Below {
            layers: &mut holds,
            socket: &*s,
        };
        assert!(below.data_pending());
        let mut empty = [holdback(), upper()];
        let below = Below {
            layers: &mut empty,
            socket: &*s,
        };
        assert!(!below.data_pending());
    }
}
