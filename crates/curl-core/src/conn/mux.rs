//! The session a connection multiplexes its requests over, once one of
//! them found it speaks a version that does (C's `cf-h2` filter and, with
//! HTTP/3, its QUIC filter): what the pool and the engine ask of it are the
//! same whatever the version, and the version's own code reaches its
//! session by matching.

use super::io::Recv;
use super::layer::{Alive, Handshake, LayerAnswer, LayerCx, LayerQuery, Lower, Part};
use super::{RecvBuf, RecvFailed, Stream};
use crate::components::Component;
use crate::error::ErrorKind;
use crate::proto::http2::H2Conn;
use crate::proto::http3::H3Conn;
use crate::report::ResponseVersion;

/// What a session that multiplexes answers, whatever its version.
pub(crate) trait Mux {
    /// The version it speaks.
    fn version(&self) -> ResponseVersion;

    /// The peer's limit on streams open at once.
    fn max_concurrent(&self) -> u32;
}

/// A connection's session.
#[derive(Debug)]
pub(crate) enum Session {
    H2(Box<H2Conn>),
    H3(Box<H3Conn>),
}

impl Mux for Session {
    fn version(&self) -> ResponseVersion {
        match self {
            Session::H2(h2) => h2.version(),
            Session::H3(h3) => h3.version(),
        }
    }

    fn max_concurrent(&self) -> u32 {
        match self {
            Session::H2(h2) => h2.max_concurrent(),
            Session::H3(h3) => h3.max_concurrent(),
        }
    }
}

impl<'a> Part<Carrier<'a>> for Session {
    fn is_alive(&mut self, cx: &mut dyn LayerCx, below: Carrier<'a>) -> Alive {
        match self {
            Session::H2(h2) => h2.is_alive(cx, below),
            Session::H3(h3) => h3.is_alive(cx, below),
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

/// What a session works over: the connection's stream, its socket's
/// sends and receives traced as `socket`'s, and the connection's mark to
/// close, which the stream's end sets.
pub(crate) struct Carrier<'a> {
    pub(super) stream: &'a mut Stream,
    pub(super) socket: Component,
    pub(super) close: &'a mut bool,
}

impl Carrier<'_> {
    /// The same, for one call that leaves it to the caller after.
    pub(crate) fn reborrow(&mut self) -> Carrier<'_> {
        Carrier {
            stream: &mut *self.stream,
            socket: self.socket,
            close: &mut *self.close,
        }
    }

    /// Read once from the network, up to `max` bytes, into the stream's
    /// buffer; bytes received and not used are given first, the socket
    /// not asked (`Conn::recv`).
    pub(crate) fn recv(&mut self, cx: &mut dyn LayerCx, max: usize) -> Result<Recv, RecvFailed> {
        if let Some(n) = std::num::NonZeroUsize::new(self.stream.received().len()) {
            return Ok(Recv::Data(n));
        }
        let got = self.stream.recv(cx, max, Some(self.socket));
        if let Ok(Recv::Eof) = got {
            // Shut down by the server, not reused (`multi_done`).
            *self.close = true;
        }
        got
    }

    /// Send from `bytes`, which is not empty, what the network takes now.
    pub(crate) fn send(
        &mut self,
        cx: &mut dyn LayerCx,
        bytes: &[u8],
    ) -> std::io::Result<super::io::Sent> {
        self.stream.send(cx, bytes, Some(self.socket))
    }

    /// The bytes received and not used yet.
    pub(crate) fn rx_mut(&mut self) -> &mut RecvBuf {
        self.stream.rx_mut()
    }
}

impl Lower for Carrier<'_> {
    fn data_pending(self) -> bool {
        self.stream.data_pending()
    }

    fn alive(self, cx: &mut dyn LayerCx) -> Alive {
        self.stream.is_alive(cx)
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
