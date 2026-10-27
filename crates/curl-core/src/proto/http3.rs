//! HTTP/3 over a QUIC connection (the HTTP/3 half of C's `cf-ngtcp2.c`):
//! the session a connection dialed over QUIC has from its handshake on.

use crate::conn::layer::{LayerAnswer, LayerQuery};
use crate::conn::mux::{Carrier, Routes};
use crate::conn::part::Part;
use crate::conn::quic::Quic;
use crate::http3::StreamId;
use crate::report::ResponseVersion;
use crate::tls::Chosen;

/// A connection's HTTP/3 session.
#[derive(Debug)]
pub(crate) struct H3Conn {
    pub(crate) quic: Box<Quic>,
    /// Each open stream's transfer (`streams`).
    pub(crate) routes: Routes<StreamId, ()>,
}

impl H3Conn {
    /// The session over `quic`, its handshake done.
    pub(crate) fn new(quic: Box<Quic>) -> H3Conn {
        H3Conn {
            quic,
            routes: Routes::new(),
        }
    }

    /// When its handshake completed.
    pub(crate) fn handshake_at(&self) -> Option<crate::time::Instant> {
        self.quic.handshake_at()
    }

    pub(crate) fn version(&self) -> ResponseVersion {
        ResponseVersion::Http3
    }

    /// How many transfers it takes at once, with `attached` on it
    /// (`CF_QUERY_MAX_CONCURRENT`).
    pub(crate) fn max_concurrent(&self, attached: u32, default: u32) -> u32 {
        self.quic.max_concurrent(attached, default)
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
