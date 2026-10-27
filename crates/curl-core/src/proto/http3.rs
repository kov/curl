//! HTTP/3 over a QUIC connection (the HTTP/3 half of C's `cf-ngtcp2.c`):
//! the session a connection dialed over QUIC has from its handshake on.

use crate::conn::layer::{LayerAnswer, LayerQuery};
use crate::conn::mux::Carrier;
use crate::conn::part::Part;
use crate::conn::quic::Quic;
use crate::report::ResponseVersion;
use crate::tls::Chosen;

/// A connection's HTTP/3 session.
#[derive(Debug)]
pub(crate) struct H3Conn {
    quic: Box<Quic>,
}

impl H3Conn {
    /// The session over `quic`, its handshake done.
    pub(crate) fn new(quic: Box<Quic>) -> H3Conn {
        H3Conn { quic }
    }

    /// When its handshake completed.
    pub(crate) fn handshake_at(&self) -> Option<crate::time::Instant> {
        self.quic.handshake_at()
    }

    pub(crate) fn version(&self) -> ResponseVersion {
        ResponseVersion::Http3
    }

    /// The streams it may have open at once: those the peer allows that
    /// are not used yet (`CF_QUERY_MAX_CONCURRENT`).
    pub(crate) fn max_concurrent(&self) -> u32 {
        u32::try_from(self.quic.streams_left()).unwrap_or(u32::MAX)
    }
}

impl<'a> Part<Carrier<'a>> for H3Conn {
    /// It agreed on HTTP/3, saying nothing of it (`cf_ngtcp2_query`).
    fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        match q {
            LayerQuery::Alpn => Some(LayerAnswer::Alpn(
                Some(Chosen::H3),
                crate::components::Component::Http3,
            )),
            _ => None,
        }
    }
}
