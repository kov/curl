//! The layer a TLS session makes of a connection (C's SSL filter,
//! `lib/vtls/vtls.c`): it hands each call to the session with the layers
//! below, the caller's buffer and length as they are, so the session's
//! own reads are the sizes below it. A handshake the session puts off
//! for early data goes on as the first bytes are sent, which it sends
//! early, or as the first read, with none (`ssl_cf_connect_deferred`).

use std::fmt;
use std::io;
use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use super::io::{Events, Recv, Sent};
use super::layer::{Below, Handshake, Layer, LayerAnswer, LayerCx, LayerQuery};
use crate::components::Component;
use crate::error::ErrorKind;
use crate::tls::{SessionPeer, TlsIo, TlsSession, TlsWait};

pub(crate) struct TlsLayer {
    session: Box<dyn TlsSession>,
    /// What the connection received before the layer was put on it,
    /// after a proxy's answer: the peer's first bytes, read before any
    /// from below.
    early: Vec<u8>,
    /// Who the session's tickets are kept for.
    peer: SessionPeer,
    /// The filter C's chain holds for it: the origin's (`SSL`) or an
    /// HTTPS proxy's (`SSL-PROXY`).
    filter: Component,
    deferral: Deferral,
}

/// Where a handshake put off for early data is (C's `earlydata_state`,
/// with its `earlydata` and `earlydata_skip`).
#[derive(Debug)]
enum Deferral {
    /// None was put off, or it is over and nothing of it is left to skip.
    None,
    /// Put off until the first bytes are sent, of which `most` may go
    /// early.
    Awaiting { most: usize },
    /// It goes on, `early` going first as early data.
    Going { early: Vec<u8> },
    /// It is over and the peer took the early data: the sends after
    /// start again with `early[at..]`, which went already, and are taken
    /// without sending them (`earlydata_skip`).
    Skipping { early: Vec<u8>, at: usize },
    /// It failed with `kind`: so does each send and receive after.
    Failed(ErrorKind),
}

impl TlsLayer {
    /// The layer over a connection that received `early` and has not
    /// used it, its sessions kept for `peer`, the filter `filter` of C's
    /// chain: `SSL` for the origin's, `SSL-PROXY` for an HTTPS proxy's.
    pub(crate) fn boxed(
        session: Box<dyn TlsSession>,
        early: Vec<u8>,
        peer: SessionPeer,
        filter: Component,
    ) -> Result<Box<dyn Layer>, OutOfMemory> {
        assert!(
            matches!(filter, Component::Ssl | Component::SslProxy),
            "a TLS filter"
        );
        Ok(try_box(TlsLayer {
            session,
            early,
            peer,
            filter,
            deferral: Deferral::None,
        })?)
    }

    /// The session, and what it reaches for one call.
    fn parts<'a>(
        &'a mut self,
        cx: &'a mut dyn LayerCx,
        below: Below<'a>,
    ) -> (&'a mut dyn TlsSession, TlsIo<'a>) {
        let TlsLayer {
            session,
            early,
            peer,
            filter,
            ..
        } = self;
        let io = TlsIo::new(below, cx, early, *filter, peer);
        (&mut **session, io)
    }

    /// Move a handshake put off on, once it has its early data: whether
    /// it is over, as a send or receive may go on. Over, the peer took the
    /// early data or not, the origin's says so to the transfer.
    fn go_on(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> io::Result<bool> {
        let TlsLayer {
            session,
            early,
            peer,
            filter,
            deferral,
        } = self;
        let bytes = match deferral {
            Deferral::Going { early } => early,
            Deferral::Failed(_) => return Err(io::ErrorKind::Other.into()),
            Deferral::None | Deferral::Skipping { .. } => return Ok(true),
            Deferral::Awaiting { .. } => unreachable!("given its early data first"),
        };
        let mut io = TlsIo::new(below, cx, early, *filter, peer);
        let shaken = session.handshake_early(&mut io, bytes);
        match shaken {
            Ok(Handshake::Waiting) => Ok(false),
            Ok(Handshake::Done) => {
                let n = bytes.len();
                let sent = i64::try_from(n).expect("at most what a session allows");
                let origin = *filter == Component::Ssl;
                if session.early_accepted() {
                    cx.info(format_args!("Server accepted {n} bytes of TLS early data."));
                    if origin {
                        cx.early_done(sent);
                    }
                    *deferral = match n {
                        0 => Deferral::None,
                        _ => Deferral::Skipping {
                            early: std::mem::take(bytes),
                            at: 0,
                        },
                    };
                } else {
                    // Refused, it is all sent again.
                    cx.info(format_args!("Server rejected TLS early data."));
                    if origin {
                        cx.early_done(-sent);
                    }
                    *deferral = Deferral::None;
                }
                Ok(true)
            }
            Err(kind) => {
                *deferral = Deferral::Failed(kind);
                Err(io::ErrorKind::Other.into())
            }
        }
    }
}

impl fmt::Debug for TlsLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsLayer")
            .field("early", &self.early.len())
            .field("peer", &self.peer)
            .field("filter", &self.filter)
            .field("deferral", &self.deferral)
            .finish_non_exhaustive()
    }
}

impl Layer for TlsLayer {
    /// A handshake the session puts off is done as far as the connection
    /// goes: it goes on as the connection is used.
    fn connect(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        if let Deferral::Awaiting { .. } = self.deferral {
            return Ok(Handshake::Done);
        }
        let (session, mut io) = self.parts(cx, below);
        let shaken = session.handshake(&mut io)?;
        if shaken == Handshake::Done
            && let Some(deferred) = self.session.deferred()
        {
            self.deferral = Deferral::Awaiting {
                most: deferred.most,
            };
        }
        Ok(shaken)
    }

    /// A handshake put off goes on with no early data (`ssl_cf_recv`).
    fn recv(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
        buf: &mut [u8],
    ) -> io::Result<Recv> {
        if let Deferral::Awaiting { .. } = self.deferral {
            self.deferral = Deferral::Going { early: Vec::new() };
        }
        if !self.go_on(cx, below.reborrow())? {
            return Ok(Recv::WouldBlock);
        }
        let (session, mut io) = self.parts(cx, below);
        session.recv(&mut io, buf)
    }

    /// A handshake put off goes on with the first bytes sent as early
    /// data, as many as it allows (`ssl_cf_set_earlydata`); the sends
    /// after the peer took them begin with them again, and are taken
    /// without sending them again (`ssl_cf_send`).
    fn send(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
        bytes: &[u8],
    ) -> io::Result<Sent> {
        if let Deferral::Awaiting { most } = self.deferral {
            let n = bytes.len().min(most);
            let mut early = Vec::new();
            early
                .try_extend_from_slice(&bytes[..n])
                .map_err(|OutOfMemory| io::Error::from(io::ErrorKind::OutOfMemory))?;
            if n > 0 {
                let line = format_args!("ssl_cf_set_earlydata(len={n}) -> {n}");
                cx.of(self.filter, line);
            }
            self.deferral = Deferral::Going { early };
        }
        if !self.go_on(cx, below.reborrow())? {
            return Ok(Sent::WouldBlock);
        }
        let mut skipped = 0;
        if let Deferral::Skipping { early, at } = &mut self.deferral {
            let left = &early[*at..];
            let n = left.len().min(bytes.len());
            assert!(
                bytes[..n] == left[..n],
                "what went early is sent again as it was"
            );
            *at += n;
            skipped = n;
            if *at == early.len() {
                self.deferral = Deferral::None;
            }
        }
        let skip = NonZeroUsize::new(skipped);
        if skipped == bytes.len() {
            return Ok(Sent::Bytes(skip.expect("a send has bytes")));
        }
        let (session, mut io) = self.parts(cx, below);
        match (session.send(&mut io, &bytes[skipped..]), skip) {
            (Ok(Sent::Bytes(n)), _) => Ok(Sent::Bytes(n.saturating_add(skipped))),
            (Ok(Sent::WouldBlock), Some(skip)) => Ok(Sent::Bytes(skip)),
            (sent, _) => sent,
        }
    }

    /// What the session waits for replaces what the transfer wants
    /// (`Curl_ssl_adjust_pollset`'s `set_out_only` and `set_in_only`).
    fn adjust_pollset(&self, wanted: Events) -> Events {
        match self.session.waits() {
            TlsWait::Nothing => wanted,
            TlsWait::Recv => Events::IN,
            TlsWait::Send => Events::OUT,
        }
    }

    /// What the session waits for, said as C's filter says it.
    fn pollset_said(&self) -> Option<Events> {
        match self.session.waits() {
            TlsWait::Nothing => None,
            TlsWait::Recv => Some(Events::IN),
            TlsWait::Send => Some(Events::OUT),
        }
    }

    /// The bytes received before the layer, those the session holds
    /// (`SSL_pending`), or those below (`ssl_cf_data_pending`).
    fn data_pending(&self, below: Below<'_>) -> bool {
        !self.early.is_empty() || self.session.pending() || below.data_pending()
    }

    fn filter(&self) -> Option<Component> {
        Some(self.filter)
    }

    fn shutdown(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        let (session, mut io) = self.parts(cx, below);
        let r = session.shutdown(&mut io);
        let (code, done) = match &r {
            Ok(done) => (0, u8::from(*done == Handshake::Done)),
            Err(kind) => (kind.number(), 0),
        };
        cx.of(
            self.filter,
            format_args!("cf_shutdown -> {code}, done={done}"),
        );
        r
    }

    /// The session's objects, once its library made them, the origin's
    /// alone: an HTTPS proxy's layer passes the question down, as C's
    /// answers only for the origin (`ssl_cf_query`). Either answers what
    /// was agreed by ALPN, saying it is the one that answers, and what it
    /// waits for, the proxy's asked apart.
    /// The origin's alone: an HTTPS proxy's is never bound to.
    fn channel_binding(
        &self,
        notes: &mut dyn crate::tls::BindingNotes,
    ) -> Option<Result<Option<Vec<u8>>, ErrorKind>> {
        (self.filter == Component::Ssl).then(|| self.session.channel_binding(notes))
    }

    fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        let origin = self.filter == Component::Ssl;
        match q {
            LayerQuery::TlsNative if origin => self.session.native().map(LayerAnswer::TlsNative),
            LayerQuery::TlsNative => None,
            LayerQuery::Alpn => Some(LayerAnswer::Alpn(self.session.chosen(), self.filter)),
            LayerQuery::TlsWaits if origin => Some(LayerAnswer::TlsWaits(self.session.waits())),
            LayerQuery::ProxyTlsWaits if !origin => {
                Some(LayerAnswer::TlsWaits(self.session.waits()))
            }
            LayerQuery::TlsWaits | LayerQuery::ProxyTlsWaits => None,
            LayerQuery::TlsDeferred if origin => match self.deferral {
                Deferral::Awaiting { .. } | Deferral::Going { .. } => {
                    Some(LayerAnswer::TlsDeferred)
                }
                Deferral::None | Deferral::Skipping { .. } | Deferral::Failed(_) => None,
            },
            LayerQuery::TlsDeferred | LayerQuery::Tunnel => None,
            LayerQuery::Failure => match self.deferral {
                Deferral::Failed(kind) => Some(LayerAnswer::Failure(kind)),
                _ => None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::io::{Conversation, FakeNet, Peer};
    use crate::time::ManualClock;

    /// A session that holds bytes, or not, and waits as it is told.
    struct Holding(bool, TlsWait);

    impl TlsSession for Holding {
        fn handshake(&mut self, _: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
            Ok(Handshake::Done)
        }
        fn recv(&mut self, _: &mut TlsIo<'_>, _: &mut [u8]) -> io::Result<Recv> {
            Ok(Recv::WouldBlock)
        }
        fn send(&mut self, _: &mut TlsIo<'_>, _: &[u8]) -> io::Result<Sent> {
            Ok(Sent::WouldBlock)
        }
        fn shutdown(&mut self, _: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
            Ok(Handshake::Done)
        }
        fn waits(&self) -> TlsWait {
            self.1
        }
        fn pending(&self) -> bool {
            self.0
        }
        fn channel_binding(
            &self,
            _: &mut dyn crate::tls::BindingNotes,
        ) -> Result<Option<Vec<u8>>, ErrorKind> {
            Ok(None)
        }
    }

    /// Bytes are pending, which a poll of the socket cannot see, while the
    /// session holds some or the bytes received before it are unread;
    /// and the transfer waits on what the session waits for, in place of
    /// what it wants.
    #[test]
    fn the_layer_says_what_its_session_holds_and_waits_for() {
        let clock = ManualClock::new().unwrap();
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(clock)
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, Conversation::new(b"", false));
        let socket = crate::conn::io::dial(&mut net, at);
        let pending = |session: Holding, early: &[u8]| {
            let peer = crate::tls::SessionPeer::testing();
            let layer = TlsLayer::boxed(
                try_box(session).unwrap(),
                early.to_vec(),
                peer,
                Component::Ssl,
            )
            .unwrap();
            let mut layers = [layer];
            let (top, rest) = layers.split_last_mut().unwrap();
            top.data_pending(Below::new(rest, &*socket))
        };
        assert!(!pending(Holding(false, TlsWait::Nothing), b""));
        assert!(pending(Holding(true, TlsWait::Nothing), b""));
        assert!(pending(Holding(false, TlsWait::Nothing), b"early"));
        let waits = |w| {
            let peer = crate::tls::SessionPeer::testing();
            let layer = TlsLayer::boxed(
                try_box(Holding(false, w)).unwrap(),
                Vec::new(),
                peer,
                Component::Ssl,
            )
            .unwrap();
            layer.adjust_pollset(Events::IN)
        };
        assert_eq!(waits(TlsWait::Nothing), Events::IN);
        assert_eq!(waits(TlsWait::Send), Events::OUT);
        assert_eq!(waits(TlsWait::Recv), Events::IN);
    }

    /// A session whose handshake is put off for `most` bytes of early
    /// data: it notes what it was given early and what it sent, its
    /// peer taking the early data if `takes`, its handshake failing if
    /// `fails`.
    #[derive(Debug, Default)]
    struct Deferring {
        most: usize,
        takes: bool,
        fails: bool,
        going: bool,
        given: Option<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl TlsSession for Deferring {
        fn handshake(&mut self, _: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
            Ok(Handshake::Done)
        }
        fn deferred(&self) -> Option<crate::tls::Deferred> {
            let alpn = crate::tls::Chosen::Http11;
            (!self.going).then_some(crate::tls::Deferred {
                most: self.most,
                alpn,
            })
        }
        fn handshake_early(
            &mut self,
            _: &mut TlsIo<'_>,
            early: &[u8],
        ) -> Result<Handshake, ErrorKind> {
            self.going = true;
            if let Some(given) = &self.given {
                assert_eq!(given, early, "given the same bytes each call");
            }
            self.given = Some(early.to_vec());
            if self.fails {
                return Err(ErrorKind::SslConnectError);
            }
            Ok(Handshake::Done)
        }
        fn early_accepted(&self) -> bool {
            self.takes
        }
        fn recv(&mut self, _: &mut TlsIo<'_>, _: &mut [u8]) -> io::Result<Recv> {
            Ok(Recv::WouldBlock)
        }
        fn send(&mut self, _: &mut TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent> {
            self.sent.extend_from_slice(bytes);
            Ok(Sent::Bytes(NonZeroUsize::new(bytes.len()).unwrap()))
        }
        fn shutdown(&mut self, _: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
            Ok(Handshake::Done)
        }
        fn waits(&self) -> TlsWait {
            TlsWait::Nothing
        }
        fn pending(&self) -> bool {
            false
        }
        fn channel_binding(
            &self,
            _: &mut dyn crate::tls::BindingNotes,
        ) -> Result<Option<Vec<u8>>, ErrorKind> {
            Ok(None)
        }
    }

    /// A context noting what the layer tells the transfer of its early
    /// data.
    struct Noting(Option<i64>);

    impl LayerCx for Noting {
        fn now(&self) -> crate::time::Instant {
            crate::time::Clock::now(&ManualClock::new().unwrap())
        }
        fn of(&mut self, _: Component, _: fmt::Arguments<'_>) {}
        fn info(&mut self, _: fmt::Arguments<'_>) {}
        fn early_done(&mut self, sent: i64) {
            assert_eq!(self.0.replace(sent), None, "told once");
        }
    }

    /// Run `f` on a layer over `session`, connected, with the stream
    /// below it and a context noting what it is told.
    fn deferring(session: Deferring, f: impl FnOnce(&mut dyn Layer, Below<'_>, &mut Noting)) {
        let clock = ManualClock::new().unwrap();
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(clock)
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, Conversation::new(b"", false));
        let socket = crate::conn::io::dial(&mut net, at);
        let peer = crate::tls::SessionPeer::testing();
        let session = try_box(session).unwrap();
        let mut layers = [TlsLayer::boxed(session, Vec::new(), peer, Component::Ssl).unwrap()];
        let (top, rest) = layers.split_last_mut().unwrap();
        let mut cx = Noting(None);
        let shaken = top.connect(&mut cx, Below::new(rest, &*socket));
        assert_eq!(shaken, Ok(Handshake::Done), "connected, put off");
        assert_eq!(
            top.query(LayerQuery::TlsDeferred),
            Some(LayerAnswer::TlsDeferred)
        );
        f(&mut **top, Below::new(rest, &*socket), &mut cx);
    }

    /// The first send gives the handshake its early data, as much as the
    /// session allows; taken, the sends after skip what went early, even
    /// a send of less than that; refused, it is all sent.
    #[test]
    fn a_handshake_put_off_takes_the_first_bytes_sent_early() {
        let taken = Deferring {
            most: 4,
            takes: true,
            ..Deferring::default()
        };
        deferring(taken, |layer, mut below, cx| {
            let sent = layer.send(cx, below.reborrow(), b"ab").unwrap();
            assert_eq!(sent, Sent::Bytes(NonZeroUsize::new(2).unwrap()));
            assert_eq!(cx.0, Some(2));
            assert_eq!(layer.query(LayerQuery::TlsDeferred), None, "over");
            let sent = layer.send(cx, below.reborrow(), b"abcd").unwrap();
            assert_eq!(sent, Sent::Bytes(NonZeroUsize::new(4).unwrap()));
            let sent = layer.send(cx, below.reborrow(), b"cd").unwrap();
            assert_eq!(sent, Sent::Bytes(NonZeroUsize::new(2).unwrap()));
            let mut out = [0u8; 4];
            assert!(matches!(
                layer.recv(cx, below, &mut out),
                Ok(Recv::WouldBlock)
            ));
        });
        let clipped = Deferring {
            most: 4,
            takes: true,
            ..Deferring::default()
        };
        deferring(clipped, |layer, below, cx| {
            let sent = layer.send(cx, below, b"abcdef").unwrap();
            assert_eq!(sent, Sent::Bytes(NonZeroUsize::new(6).unwrap()));
            assert_eq!(cx.0, Some(4));
        });
        let refused = Deferring {
            most: 4,
            ..Deferring::default()
        };
        deferring(refused, |layer, below, cx| {
            let sent = layer.send(cx, below, b"abcdef").unwrap();
            assert_eq!(sent, Sent::Bytes(NonZeroUsize::new(6).unwrap()));
            assert_eq!(cx.0, Some(-4));
        });
    }

    /// A receive before any send lets the handshake go on with no early
    /// data (`ssl_cf_recv`).
    #[test]
    fn a_receive_first_lets_a_handshake_put_off_go_on_without_early_data() {
        let session = Deferring {
            most: 4,
            takes: true,
            ..Deferring::default()
        };
        deferring(session, |layer, mut below, cx| {
            let mut out = [0u8; 4];
            assert!(matches!(
                layer.recv(cx, below.reborrow(), &mut out),
                Ok(Recv::WouldBlock)
            ));
            assert_eq!(cx.0, Some(0));
            let sent = layer.send(cx, below, b"ab").unwrap();
            assert_eq!(sent, Sent::Bytes(NonZeroUsize::new(2).unwrap()));
        });
    }

    /// A handshake put off that fails fails the send that let it go on,
    /// and each use after, naming the handshake's error.
    #[test]
    fn a_handshake_put_off_that_fails_names_its_error() {
        let session = Deferring {
            most: 4,
            fails: true,
            ..Deferring::default()
        };
        deferring(session, |layer, mut below, cx| {
            assert!(layer.send(cx, below.reborrow(), b"ab").is_err());
            let failure = Some(LayerAnswer::Failure(ErrorKind::SslConnectError));
            assert_eq!(layer.query(LayerQuery::Failure), failure);
            let mut out = [0u8; 4];
            assert!(layer.recv(cx, below, &mut out).is_err());
            assert_eq!(cx.0, None, "nothing told of a handshake that failed");
        });
    }
}
