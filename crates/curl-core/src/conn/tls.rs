//! The layer a TLS session makes of a connection (C's SSL filter,
//! `lib/vtls/vtls.c`): it hands each call to the session with the layers
//! below, the caller's buffer and length as they are, so the session's
//! own reads are the sizes below it.

use std::fmt;
use std::io;

use curl_alloc::{OutOfMemory, try_box};

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
        } = self;
        let io = TlsIo::new(below, cx, early, *filter, peer);
        (&mut **session, io)
    }
}

impl fmt::Debug for TlsLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsLayer")
            .field("early", &self.early.len())
            .field("peer", &self.peer)
            .field("filter", &self.filter)
            .finish_non_exhaustive()
    }
}

impl Layer for TlsLayer {
    fn connect(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        let (session, mut io) = self.parts(cx, below);
        session.handshake(&mut io)
    }

    fn recv(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        let (session, mut io) = self.parts(cx, below);
        session.recv(&mut io, buf)
    }

    fn send(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, bytes: &[u8]) -> io::Result<Sent> {
        let (session, mut io) = self.parts(cx, below);
        session.send(&mut io, bytes)
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

    /// The bytes received before the layer, those the session holds
    /// (`SSL_pending`), or those below (`ssl_cf_data_pending`).
    fn data_pending(&self, below: Below<'_>) -> bool {
        !self.early.is_empty() || self.session.pending() || below.data_pending()
    }

    fn shutdown(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        let (session, mut io) = self.parts(cx, below);
        session.shutdown(&mut io)
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
}
