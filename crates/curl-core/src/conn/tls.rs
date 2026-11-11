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
use super::layer::{Below, Handshake, Layer, LayerAnswer, LayerCx, LayerQuery, Part};
use crate::components::Component;
use crate::conn::layer::LayerCalls as _;
use crate::error::ErrorKind;
use crate::tls::{
    Checked, OwnSessions, SessionPeer, Shaken, TlsIo, TlsSession, TlsTicket, TlsWait,
};

pub(crate) struct TlsLayer {
    session: Box<dyn TlsSession>,
    /// What the connection received before the layer was put on it,
    /// after a proxy's answer: the peer's first bytes, read before any
    /// from below.
    early: Vec<u8>,
    /// Who the session's tickets are kept for.
    peer: SessionPeer,
    /// What it keeps of its sessions apart from the cache.
    own: OwnSessions,
    /// The filter C's chain holds for it: the origin's (`SSL`) or an
    /// HTTPS proxy's (`SSL-PROXY`).
    filter: Component,
    peer_state: PeerState,
}

/// Where the session's handshake and the check of its peer are (C's
/// `cf->connected` and `earlydata_state`, with its `earlydata` and
/// `earlydata_skip`). Only an open session is read from or written to.
#[derive(Debug)]
enum PeerState {
    /// The handshake goes on.
    Shaking,
    /// It is put off until the first bytes are sent, of which `most` may
    /// go early: done as far as the connection goes.
    Awaiting { most: usize },
    /// It goes on, `early` going first as early data.
    Going { early: Vec<u8> },
    /// It is done and the peer checked, as `checked` says. If the peer
    /// took early data, the sends after start again with `early[at..]`,
    /// which went already, and are taken without sending them
    /// (`earlydata_skip`).
    Open {
        #[expect(
            dead_code,
            reason = "held as the proof the session is open; asked of nothing yet"
        )]
        checked: Checked,
        skip: Option<(Vec<u8>, usize)>,
    },
    /// It failed with `kind`: so does each send and receive after.
    Failed(ErrorKind),
}

impl PeerState {
    /// The handshake is done as far as the connection goes (C's
    /// `cf->connected`).
    fn connected(&self) -> bool {
        !matches!(self, PeerState::Shaking)
    }
}

/// The handshake is done with `checked`, made for the session of
/// `peer`: open, or failed if made for another (said to `cx`).
fn opened(
    cx: &mut dyn LayerCx,
    peer: &SessionPeer,
    checked: Checked,
    skip: Option<(Vec<u8>, usize)>,
) -> PeerState {
    if checked.is_for(peer) {
        return PeerState::Open { checked, skip };
    }
    let kind = cx.fails(
        ErrorKind::PeerFailedVerification,
        format_args!("internal: a check made for another session"),
    );
    PeerState::Failed(kind)
}

impl TlsLayer {
    /// The layer over a connection that received `early` and has not
    /// used it, its sessions kept for `peer` and as `own` says, the
    /// filter `filter` of C's chain: `SSL` for the origin's, `SSL-PROXY`
    /// for an HTTPS proxy's.
    pub(crate) fn boxed(
        session: Box<dyn TlsSession>,
        early: Vec<u8>,
        peer: SessionPeer,
        own: OwnSessions,
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
            own,
            filter,
            peer_state: PeerState::Shaking,
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
            own,
            filter,
            ..
        } = self;
        let io = TlsIo::new(below, cx, early, *filter, peer, own);
        (&mut **session, io)
    }

    /// Move a handshake put off on, once it has its early data: whether
    /// the session is open, as a send or receive may go on. Over, the peer
    /// took the early data or not, the origin's says so to the transfer.
    /// A session not open nor going on is used by no send or receive.
    fn go_on(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> io::Result<bool> {
        let TlsLayer {
            session,
            early,
            peer,
            own,
            filter,
            peer_state,
        } = self;
        let bytes = match peer_state {
            PeerState::Going { early } => early,
            PeerState::Open { .. } => return Ok(true),
            PeerState::Failed(_) | PeerState::Shaking => return Err(io::ErrorKind::Other.into()),
            PeerState::Awaiting { .. } => unreachable!("given its early data first"),
        };
        let mut io = TlsIo::new(below, cx, early, *filter, peer, own);
        let shaken = session.handshake_early(&mut io, bytes);
        match shaken {
            Ok(Shaken::Waiting) => Ok(false),
            Ok(Shaken::Done(checked)) => {
                let n = bytes.len();
                let sent = i64::try_from(n).expect("at most what a session allows");
                let origin = *filter == Component::Ssl;
                let skip = if session.early_accepted() {
                    cx.info(format_args!("Server accepted {n} bytes of TLS early data."));
                    if origin {
                        cx.early_done(sent);
                    }
                    (n > 0).then(|| (std::mem::take(bytes), 0))
                } else {
                    // Refused, it is all sent again.
                    cx.info(format_args!("Server rejected TLS early data."));
                    if origin {
                        cx.early_done(-sent);
                    }
                    None
                };
                *peer_state = opened(cx, peer, checked, skip);
                match peer_state {
                    PeerState::Open { .. } => Ok(true),
                    _ => Err(io::ErrorKind::Other.into()),
                }
            }
            Ok(Shaken::Deferred(_)) => {
                // Put off once only: a session putting it off again
                // never checks its peer.
                let kind = ErrorKind::SslConnectError;
                let kind = cx.fails(kind, format_args!("internal: a handshake put off twice"));
                *peer_state = PeerState::Failed(kind);
                Err(io::ErrorKind::Other.into())
            }
            Err(kind) => {
                *peer_state = PeerState::Failed(kind);
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
            .field("peer_state", &self.peer_state)
            .finish_non_exhaustive()
    }
}

impl Part<Below<'_>> for TlsLayer {
    /// A handshake the session puts off is done as far as the connection
    /// goes: it goes on as the connection is used.
    fn connect(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        match self.peer_state {
            PeerState::Shaking => {}
            PeerState::Awaiting { .. } | PeerState::Going { .. } | PeerState::Open { .. } => {
                return Ok(Handshake::Done);
            }
            PeerState::Failed(kind) => return Err(kind),
        }
        let (session, mut io) = self.parts(cx, below);
        match session.handshake(&mut io)? {
            Shaken::Waiting => Ok(Handshake::Waiting),
            Shaken::Deferred(deferred) => {
                self.peer_state = PeerState::Awaiting {
                    most: deferred.most,
                };
                Ok(Handshake::Done)
            }
            Shaken::Done(checked) => {
                self.peer_state = opened(cx, &self.peer, checked, None);
                match self.peer_state {
                    PeerState::Failed(kind) => Err(kind),
                    _ => Ok(Handshake::Done),
                }
            }
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
    /// (`SSL_pending`), or those below (`ssl_cf_data_pending`). A layer
    /// still shaking hands is passed over for the one below, as C's
    /// connection asks only its connected filters
    /// (`Curl_conn_data_pending`): what its handshake fed the session is
    /// no input a read could give yet.
    fn data_pending(&self, below: Below<'_>) -> bool {
        if !self.peer_state.connected() {
            return below.data_pending();
        }
        !self.early.is_empty() || self.session.pending() || below.data_pending()
    }

    fn filter(&self) -> Option<Component> {
        Some(self.filter)
    }

    fn shutdown(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        let (session, mut io) = self.parts(cx, below);
        let r = session.shutdown(&mut io, crate::tls::Goodbye::Mutual);
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
            LayerQuery::TlsDeferred if origin => match self.peer_state {
                PeerState::Awaiting { .. } | PeerState::Going { .. } => {
                    Some(LayerAnswer::TlsDeferred)
                }
                PeerState::Shaking | PeerState::Open { .. } | PeerState::Failed(_) => None,
            },
            LayerQuery::TlsDeferred | LayerQuery::Tunnel => None,
            LayerQuery::Failure => match self.peer_state {
                PeerState::Failed(kind) => Some(LayerAnswer::Failure(kind)),
                _ => None,
            },
        }
    }
}

impl Layer for TlsLayer {
    /// A handshake put off goes on with no early data (`ssl_cf_recv`).
    fn recv(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
        buf: &mut [u8],
    ) -> io::Result<Recv> {
        if let PeerState::Awaiting { .. } = self.peer_state {
            self.peer_state = PeerState::Going { early: Vec::new() };
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
        if let PeerState::Awaiting { most } = self.peer_state {
            let n = bytes.len().min(most);
            let mut early = Vec::new();
            early
                .try_extend_from_slice(&bytes[..n])
                .map_err(|OutOfMemory| io::Error::from(io::ErrorKind::OutOfMemory))?;
            if n > 0 {
                let line = format_args!("ssl_cf_set_earlydata(len={n}) -> {n}");
                cx.of(self.filter, line);
            }
            self.peer_state = PeerState::Going { early };
        }
        if !self.go_on(cx, below.reborrow())? {
            return Ok(Sent::WouldBlock);
        }
        let mut skipped = 0;
        if let PeerState::Open { skip, .. } = &mut self.peer_state
            && let Some((early, at)) = skip
        {
            let left = &early[*at..];
            let n = left.len().min(bytes.len());
            assert!(
                bytes[..n] == left[..n],
                "what went early is sent again as it was"
            );
            *at += n;
            skipped = n;
            if *at == early.len() {
                *skip = None;
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

    fn latest_session(&self) -> Option<&TlsTicket> {
        (self.filter == Component::Ssl)
            .then(|| self.own.latest())
            .flatten()
    }

    fn clear_tls(
        &mut self,
        cx: &mut dyn LayerCx,
        below: Below<'_>,
        goodbye: crate::tls::Goodbye,
    ) -> Option<Result<Handshake, ErrorKind>> {
        if self.filter != Component::Ssl {
            return None;
        }
        let (session, mut io) = self.parts(cx, below);
        Some(session.shutdown(&mut io, goodbye))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::io::{Conversation, FakeNet, Peer};
    use crate::time::ManualClock;

    /// A session that holds bytes, or not, waits as it is told, and has
    /// its handshake done or not.
    struct Holding(bool, TlsWait, bool);

    impl TlsSession for Holding {
        fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Shaken, ErrorKind> {
            Ok(match self.2 {
                true => Shaken::Done(Checked::testing(io)),
                false => Shaken::Waiting,
            })
        }
        fn recv(&mut self, _: &mut TlsIo<'_>, _: &mut [u8]) -> io::Result<Recv> {
            Ok(Recv::WouldBlock)
        }
        fn send(&mut self, _: &mut TlsIo<'_>, _: &[u8]) -> io::Result<Sent> {
            Ok(Sent::WouldBlock)
        }
        fn shutdown(
            &mut self,
            _: &mut TlsIo<'_>,
            _: crate::tls::Goodbye,
        ) -> Result<Handshake, ErrorKind> {
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
    /// session holds some or the bytes received before it are unread,
    /// once its handshake is done: what a handshake under way holds is no
    /// input yet, as C asks only a connected filter. And the transfer
    /// waits on what the session waits for, in place of what it wants.
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
                crate::tls::OwnSessions::default(),
                Component::Ssl,
            )
            .unwrap();
            let mut layers = [layer];
            let (top, rest) = layers.split_last_mut().unwrap();
            let before = top.data_pending(Below::new(rest, &*socket));
            let shaken = top.connect(&mut Noting(None), Below::new(rest, &*socket));
            assert!(shaken.is_ok());
            (before, top.data_pending(Below::new(rest, &*socket)))
        };
        let done = true;
        assert_eq!(
            pending(Holding(false, TlsWait::Nothing, done), b""),
            (false, false)
        );
        assert_eq!(
            pending(Holding(true, TlsWait::Nothing, done), b""),
            (false, true)
        );
        assert_eq!(
            pending(Holding(false, TlsWait::Nothing, done), b"early"),
            (false, true)
        );
        let shaking = Holding(true, TlsWait::Recv, false);
        assert_eq!(pending(shaking, b"early"), (false, false));
        let waits = |w| {
            let peer = crate::tls::SessionPeer::testing();
            let layer = TlsLayer::boxed(
                try_box(Holding(false, w, true)).unwrap(),
                Vec::new(),
                peer,
                crate::tls::OwnSessions::default(),
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
        fn handshake(&mut self, _: &mut TlsIo<'_>) -> Result<Shaken, ErrorKind> {
            assert!(!self.going, "a handshake put off goes on early");
            Ok(Shaken::Deferred(crate::tls::Deferred {
                most: self.most,
                alpn: crate::tls::Chosen::Http11,
            }))
        }
        fn handshake_early(
            &mut self,
            io: &mut TlsIo<'_>,
            early: &[u8],
        ) -> Result<Shaken, ErrorKind> {
            self.going = true;
            if let Some(given) = &self.given {
                assert_eq!(given, early, "given the same bytes each call");
            }
            self.given = Some(early.to_vec());
            if self.fails {
                return Err(ErrorKind::SslConnectError);
            }
            Ok(Shaken::Done(Checked::testing(io)))
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
        fn shutdown(
            &mut self,
            _: &mut TlsIo<'_>,
            _: crate::tls::Goodbye,
        ) -> Result<Handshake, ErrorKind> {
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

        fn trace(&mut self) -> Option<&mut dyn crate::conn::layer::Trace> {
            None
        }

        fn failures(&mut self) -> Option<&mut dyn crate::conn::layer::Failures> {
            None
        }

        fn transfer(&mut self) -> Option<&mut dyn crate::conn::layer::ForTransfer> {
            None
        }

        fn tls_sessions(&mut self) -> Option<&mut dyn crate::conn::layer::TlsSessions> {
            None
        }

        fn early_data(&mut self) -> Option<&mut dyn crate::conn::layer::EarlyData> {
            Some(self)
        }

        fn quic_timer(&mut self) -> Option<&mut dyn crate::conn::layer::QuicTimer> {
            None
        }

        fn h3_streams(&mut self) -> Option<&mut dyn crate::conn::layer::H3Streams> {
            None
        }

        fn recv_room(&mut self) -> Option<&mut crate::conn::quic::RecvRoom> {
            None
        }

        fn recv_buf(&mut self) -> Option<&mut crate::conn::buf::XferBuf> {
            None
        }
    }

    impl crate::conn::layer::EarlyData for Noting {
        fn early_sent(&mut self, sent: i64) {
            assert_eq!(self.0.replace(sent), None, "told once");
        }

        fn connected_late(&mut self) {
            assert!(self.0.is_some(), "told after the count");
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
        let mut layers = [TlsLayer::boxed(
            session,
            Vec::new(),
            peer,
            OwnSessions::default(),
            Component::Ssl,
        )
        .unwrap()];
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

    /// A session whose handshake is done with a check made for another
    /// session than the layer's, or not done, and which reads and writes
    /// as if open: neither may be read from or written to.
    struct Unopened(Option<SessionPeer>);

    impl TlsSession for Unopened {
        fn handshake(&mut self, _: &mut TlsIo<'_>) -> Result<Shaken, ErrorKind> {
            Ok(match &self.0 {
                Some(other) => Shaken::Done(Checked::testing_for(other)),
                None => Shaken::Waiting,
            })
        }
        fn recv(&mut self, _: &mut TlsIo<'_>, buf: &mut [u8]) -> io::Result<Recv> {
            buf[0] = b'x';
            Ok(Recv::Data(NonZeroUsize::MIN))
        }
        fn send(&mut self, _: &mut TlsIo<'_>, _: &[u8]) -> io::Result<Sent> {
            Ok(Sent::Bytes(NonZeroUsize::MIN))
        }
        fn shutdown(
            &mut self,
            _: &mut TlsIo<'_>,
            _: crate::tls::Goodbye,
        ) -> Result<Handshake, ErrorKind> {
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

    /// Connect the layer over `session` once, then read and write
    /// through it: what the connect gave, and whether the read or the
    /// write reached the session.
    fn used(session: Unopened) -> (Result<Handshake, ErrorKind>, bool, bool) {
        let clock = ManualClock::new().unwrap();
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(clock)
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, Conversation::new(b"", false));
        let socket = crate::conn::io::dial(&mut net, at);
        let mut layers = [TlsLayer::boxed(
            try_box(session).unwrap(),
            Vec::new(),
            SessionPeer::testing(),
            OwnSessions::default(),
            Component::Ssl,
        )
        .unwrap()];
        let (top, rest) = layers.split_last_mut().unwrap();
        let mut cx = Noting(None);
        let shaken = top.connect(&mut cx, Below::new(rest, &*socket));
        let mut out = [0u8; 4];
        let read = top.recv(&mut cx, Below::new(rest, &*socket), &mut out);
        let written = top.send(&mut cx, Below::new(rest, &*socket), b"ab");
        (
            shaken,
            matches!(read, Ok(Recv::Data(_))),
            matches!(written, Ok(Sent::Bytes(_))),
        )
    }

    /// A check made for another session's identity fails the handshake
    /// it ends, and the session is neither read from nor written to; nor
    /// is one whose handshake is not done.
    #[test]
    fn only_a_session_checked_for_its_own_peer_is_read_or_written() {
        let other = SessionPeer::testing();
        let (shaken, read, written) = used(Unopened(Some(other)));
        assert_eq!(shaken, Err(ErrorKind::PeerFailedVerification));
        assert!(
            !read && !written,
            "a session checked for another is not used"
        );
        let (shaken, read, written) = used(Unopened(None));
        assert_eq!(shaken, Ok(Handshake::Waiting));
        assert!(
            !read && !written,
            "a session still shaking hands is not used"
        );
    }
}
