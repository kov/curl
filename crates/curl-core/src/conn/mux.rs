//! The session a connection multiplexes its requests over, once one of
//! them found it speaks a version that does (C's `cf-h2` filter and, with
//! HTTP/3, its QUIC filter): what the pool and the engine ask of it are the
//! same whatever the version, and the version's own code reaches its
//! session by matching.

use super::io::Recv;
use super::layer::{Alive, Handshake, LayerAnswer, LayerCx, LayerQuery, Lower, Part};
use super::{Datagrams, RecvBuf, RecvFailed, Stream};
use crate::components::Component;
use crate::error::ErrorKind;
use crate::proto::http2::H2Conn;
use crate::proto::http3::H3Conn;
use crate::report::ResponseVersion;

/// What a session that multiplexes answers, whatever its version.
pub(crate) trait Mux {
    /// The version it speaks.
    fn version(&self) -> ResponseVersion;

    /// How many transfers it takes at once, with `attached` on it and the
    /// multi's own limit `default` (`CF_QUERY_MAX_CONCURRENT`): none once
    /// it is shut down.
    fn max_concurrent(&self, attached: u32, default: u32) -> u32;

    /// Whether its answer is traced, as C's QUIC filter traces it.
    fn says_max_concurrent(&self) -> bool;
}

/// A connection's session.
#[derive(Debug)]
pub(crate) enum Session {
    H2(Box<H2Conn>),
    H3(Box<H3Conn>),
}

/// What a connection speaks, as far as a session goes: one fact, which
/// the connection's readers see as a session or none.
#[derive(Debug)]
pub(crate) enum Speaks {
    /// No request found what it speaks yet: an HTTP connection's first
    /// request finds it (`http_check_new_conn`), and one of another
    /// protocol stays so. Read as no session.
    Unmade,
    /// No session: HTTP/1, as its first request found, or a connection
    /// that moves no bytes over a network.
    Http1,
    /// The session it multiplexes over, HTTP/2's or HTTP/3's.
    Made(Session),
    /// No session, but a protocol's own state: what FTP and the like
    /// keep of the connection, and their goodbye.
    Line(Box<super::line::LineConn>),
    /// Its session, of `version`, taken out for a step to drive beside
    /// the connection, and given back after. Read as no session, as the
    /// step holds it.
    Out(SessionVersion),
}

/// The version of a session taken out of its connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionVersion {
    H2,
    H3,
}

impl Speaks {
    /// The session, if it has one on it now.
    pub(crate) fn session(&self) -> Option<&Session> {
        match self {
            Speaks::Made(session) => Some(session),
            Speaks::Unmade | Speaks::Http1 | Speaks::Line(_) | Speaks::Out(_) => None,
        }
    }

    pub(crate) fn session_mut(&mut self) -> Option<&mut Session> {
        match self {
            Speaks::Made(session) => Some(session),
            Speaks::Unmade | Speaks::Http1 | Speaks::Line(_) | Speaks::Out(_) => None,
        }
    }
}

impl Mux for Session {
    fn version(&self) -> ResponseVersion {
        match self {
            Session::H2(h2) => h2.version(),
            Session::H3(h3) => h3.version(),
        }
    }

    fn max_concurrent(&self, attached: u32, default: u32) -> u32 {
        match self {
            Session::H2(h2) => h2.max_concurrent(attached),
            Session::H3(h3) => h3.max_concurrent(attached, default),
        }
    }

    fn says_max_concurrent(&self) -> bool {
        matches!(self, Session::H3(_))
    }
}

impl<'a> Part<Carrier<'a>> for Session {
    fn is_alive(&mut self, cx: &mut dyn LayerCx, below: Carrier<'a>) -> Alive {
        match self {
            Session::H2(h2) => h2.is_alive(cx, below),
            Session::H3(h3) => h3.is_alive(cx, below),
        }
    }

    fn keep_alive(&mut self, cx: &mut dyn LayerCx, below: Carrier<'a>) -> Result<(), ErrorKind> {
        match self {
            Session::H2(h2) => h2.keep_alive(cx, below),
            Session::H3(h3) => h3.keep_alive(cx, below),
        }
    }

    fn data_pending(&self, below: Carrier<'a>) -> bool {
        match self {
            Session::H2(h2) => h2.data_pending(below),
            Session::H3(h3) => h3.data_pending(below),
        }
    }

    fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        match self {
            Session::H2(_) => None,
            Session::H3(h3) => h3.query(q),
        }
    }

    fn shutdown(
        &mut self,
        cx: &mut dyn LayerCx,
        below: Carrier<'a>,
    ) -> Result<Handshake, ErrorKind> {
        match self {
            Session::H2(h2) => h2.shutdown(cx, below),
            Session::H3(h3) => h3.shutdown(cx, below),
        }
    }
}

/// What a session works over: the connection's stream or its datagram
/// socket, the socket's sends and receives traced as `socket`'s, and the
/// connection's mark to close, which a protocol sets at the stream's end
/// if it closes there.
pub(crate) struct Carrier<'a> {
    pub(super) over: Over<'a>,
    pub(super) socket: Component,
    pub(super) close: &'a mut bool,
}

/// The bytes a carrier is: a stream, or a QUIC connection's datagrams
/// dialed to its peer.
pub(super) enum Over<'a> {
    Stream(&'a mut Stream),
    Datagrams(&'a mut Datagrams),
}

impl<'a> Carrier<'a> {
    /// What a stream no connection holds carries, its socket's sends and
    /// receives traced as `socket`'s, its end marked in `close`: FTP's
    /// data connection.
    pub(crate) fn over(
        stream: &'a mut Stream,
        socket: Component,
        close: &'a mut bool,
    ) -> Carrier<'a> {
        Carrier {
            over: Over::Stream(stream),
            socket,
            close,
        }
    }
}

impl Carrier<'_> {
    /// The stream's layers over its socket, which a QUIC connection
    /// layered over a tunnel sends its datagrams through, or the datagram
    /// socket of one dialed straight; the socket's sends and receives
    /// traced.
    pub(crate) fn layers(&mut self) -> super::layer::Below<'_> {
        match &mut self.over {
            Over::Stream(stream) => stream.below(Some(self.socket)),
            Over::Datagrams(datagrams) => datagrams.below(Some(self.socket)),
        }
    }

    /// Run `f` in the context of a call on a QUIC connection over it,
    /// `cx`'s, its datagrams going where the transport says: on the
    /// datagram socket of one dialed straight, or through the stream's
    /// layers for one layered over a tunnel.
    pub(crate) fn quic_call<R>(
        &mut self,
        cx: &mut dyn LayerCx,
        f: impl FnOnce(&mut dyn super::quic::QuicIo) -> R,
    ) -> R {
        match &mut self.over {
            Over::Stream(stream) => f(&mut super::quic::Over {
                cx,
                on: stream.below(Some(self.socket)),
            }),
            Over::Datagrams(datagrams) => f(&mut super::quic::Over {
                cx,
                on: datagrams.socket(),
            }),
        }
    }

    /// The same, for one call that leaves it to the caller after.
    pub(crate) fn reborrow(&mut self) -> Carrier<'_> {
        Carrier {
            over: match &mut self.over {
                Over::Stream(stream) => Over::Stream(stream),
                Over::Datagrams(datagrams) => Over::Datagrams(datagrams),
            },
            socket: self.socket,
            close: &mut *self.close,
        }
    }

    /// The stream, which a session over bytes, HTTP/2's, works over.
    fn stream(&mut self) -> &mut Stream {
        match &mut self.over {
            Over::Stream(stream) => stream,
            Over::Datagrams(_) => unreachable!("bytes go over a stream, not datagrams"),
        }
    }

    /// Read once from the network, up to `max` bytes, into the stream's
    /// buffer; bytes received and not used are given first, the socket
    /// not asked (`Conn::recv`).
    pub(crate) fn recv(&mut self, cx: &mut dyn LayerCx, max: usize) -> Result<Recv, RecvFailed> {
        let socket = self.socket;
        let stream = self.stream();
        if let Some(n) = std::num::NonZeroUsize::new(stream.received().len()) {
            return Ok(Recv::Data(n));
        }
        stream.recv(cx, max, Some(socket))
    }

    /// The connection is not to be reused: its server closed it under a
    /// protocol that closes on its end, as HTTP does.
    pub(crate) fn mark_close(&mut self) {
        *self.close = true;
    }

    /// Send from `bytes`, which is not empty, what the network takes now.
    pub(crate) fn send(
        &mut self,
        cx: &mut dyn LayerCx,
        bytes: &[u8],
    ) -> std::io::Result<super::io::Sent> {
        let socket = self.socket;
        self.stream().send(cx, bytes, Some(socket))
    }

    /// The bytes received and not used yet.
    pub(crate) fn rx_mut(&mut self) -> &mut RecvBuf {
        self.stream().rx_mut()
    }

    /// Whether its socket is ready now for `events`, polled without
    /// waiting (`Curl_socket_check` with no time): a failed poll is
    /// readiness, for the read or write after to say why.
    pub(crate) fn ready_now(&mut self, events: super::io::Events) -> bool {
        let socket = match &self.over {
            Over::Stream(stream) => stream.socket(),
            Over::Datagrams(datagrams) => datagrams.socket(),
        };
        let mut watch = [super::io::SocketPoll::new(socket, events)];
        match super::io::poll_together(&mut watch, &mut [], std::time::Duration::ZERO) {
            Ok(_) => !watch[0].revents().is_empty(),
            Err(_) => true,
        }
    }

    /// The stream it is, for a layer to go on it as the connection is
    /// upgraded to TLS (STARTTLS).
    pub(crate) fn stream_mut(&mut self) -> &mut Stream {
        self.stream()
    }

    /// What its socket's sends and receives are traced as.
    pub(crate) fn socket_component(&self) -> Component {
        self.socket
    }

    /// Whether the origin's bytes go through TLS now, as its layers say,
    /// not as its route was made: a connection upgraded to TLS does; a
    /// proxy's tunnel's TLS is not counted (`Curl_conn_is_ssl`).
    pub(crate) fn over_tls(&self) -> bool {
        let Over::Stream(stream) = &self.over else {
            // QUIC's datagrams are always under TLS.
            return true;
        };
        stream.query(super::layer::LayerQuery::TlsWaits).is_some()
    }

    /// The latest session of the origin's TLS, if it keeps a copy: FTP's
    /// control connection's.
    pub(crate) fn latest_session(&self) -> Option<&crate::tls::TlsTicket> {
        match &self.over {
            Over::Stream(stream) => stream.latest_session(),
            Over::Datagrams(_) => None,
        }
    }
}

impl Lower for Carrier<'_> {
    fn data_pending(self) -> bool {
        match self.over {
            Over::Stream(stream) => stream.data_pending(),
            // Nothing is held between the socket and its QUIC connection.
            Over::Datagrams(_) => false,
        }
    }

    fn alive(self, cx: &mut dyn LayerCx) -> Alive {
        match self.over {
            Over::Stream(stream) => stream.is_alive(cx),
            Over::Datagrams(datagrams) => datagrams.is_alive(cx),
        }
    }
}

/// Each open stream of a session and the transfer whose request opened
/// it, with what the session keeps of the stream, until the request is
/// over (C's stream user data).
#[derive(Debug)]
pub(crate) struct Routes<S, X> {
    routes: Vec<Route<S, X>>,
}

#[derive(Debug)]
struct Route<S, X> {
    stream: S,
    to: crate::multi::TransferId,
    kept: X,
}

impl<S: Copy + Eq + std::fmt::Debug, X> Routes<S, X> {
    pub(crate) fn new() -> Self {
        Routes { routes: Vec::new() }
    }

    /// Stream `stream` is transfer `to`'s, from its opening on, the
    /// session keeping `kept` of it.
    pub(crate) fn route(
        &mut self,
        stream: S,
        to: crate::multi::TransferId,
        kept: X,
    ) -> Result<(), curl_alloc::OutOfMemory> {
        debug_assert!(self.route_of(stream).is_none(), "{stream:?} routed twice");
        curl_alloc::TryVec::try_push(&mut self.routes, Route { stream, to, kept })
    }

    /// Stream `stream` is no transfer's any more: its request is over.
    pub(crate) fn unroute(&mut self, stream: S) {
        self.routes.retain(|r| r.stream != stream);
    }

    /// The transfer stream `stream` is for, while its request runs.
    pub(crate) fn route_of(&self, stream: S) -> Option<crate::multi::TransferId> {
        self.routes
            .iter()
            .find(|r| r.stream == stream)
            .map(|r| r.to)
    }

    /// What the session keeps of `stream`, while it is routed.
    pub(crate) fn kept_mut(&mut self, stream: S) -> Option<&mut X> {
        self.routes
            .iter_mut()
            .find(|r| r.stream == stream)
            .map(|r| &mut r.kept)
    }

    /// The transfers of the streams open, but `but`'s.
    pub(crate) fn others(
        &self,
        but: crate::multi::TransferId,
    ) -> impl Iterator<Item = crate::multi::TransferId> + '_ {
        self.routes
            .iter()
            .map(|r| r.to)
            .filter(move |&to| to != but)
    }

    /// How many streams are open.
    pub(crate) fn len(&self) -> usize {
        self.routes.len()
    }
}
