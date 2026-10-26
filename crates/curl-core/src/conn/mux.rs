//! The session a connection multiplexes its requests over, once one of
//! them found it speaks a version that does (C's `cf-h2` filter and, with
//! HTTP/3, its QUIC filter): what the pool and the engine ask of it are the
//! same whatever the version, and the version's own code reaches its
//! session by matching.

use super::io::Recv;
use super::layer::{Alive, Handshake, LayerCx, Lower, Part};
use super::{RecvBuf, RecvFailed, Stream};
use crate::components::Component;
use crate::error::ErrorKind;
use crate::proto::http2::H2Conn;
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
}

impl Mux for Session {
    fn version(&self) -> ResponseVersion {
        match self {
            Session::H2(h2) => h2.version(),
        }
    }

    fn max_concurrent(&self) -> u32 {
        match self {
            Session::H2(h2) => h2.max_concurrent(),
        }
    }
}

impl<'a> Part<Carrier<'a>> for Session {
    fn is_alive(&mut self, cx: &mut dyn LayerCx, below: Carrier<'a>) -> Alive {
        match self {
            Session::H2(h2) => h2.is_alive(cx, below),
        }
    }

    fn shutdown(
        &mut self,
        cx: &mut dyn LayerCx,
        below: Carrier<'a>,
    ) -> Result<Handshake, ErrorKind> {
        match self {
            Session::H2(h2) => h2.shutdown(cx, below),
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
