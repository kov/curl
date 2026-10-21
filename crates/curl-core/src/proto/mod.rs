//! The protocols a transfer can speak, each a state the transfer holds
//! while it exchanges data.
//!
//! `file:` and `http:` are built in. Tests have three more, networkless: `null:`, which
//! completes at once, `stall:`, which never does, and `script:`, which
//! delivers the pieces of its transfer's `Options::script`; and `tcp:`,
//! which connects to its URL's host and port and completes once
//! connected.

mod file;
mod http;
pub(crate) mod http1;
#[cfg(any(test, feature = "test-util"))]
mod script;

use crate::conn::io::Events;
use crate::conn::{ConnLease, Peer, Scheme};
use crate::deliver::{Directions, Pause, Pipeline};
use crate::error::ErrorKind;
use crate::error::UrlErrorKind;
use crate::multi::Host;
use crate::multi::state::{AfterRequest, StepCx};
use crate::options::Options;
use crate::url::{GetOptions, Part, Url};

/// The URL's IPv6 zone, if it has one.
fn zone(url: &Url) -> Result<Option<Vec<u8>>, ErrorKind> {
    match url.get(Part::ZoneId, GetOptions::NONE) {
        Ok(zone) => Ok(Some(zone)),
        Err(UrlErrorKind::NoZoneid) => Ok(None),
        Err(e) => Err(crate::multi::state::url_error(e)),
    }
}

/// A protocol's state for one transfer.
#[derive(Debug)]
pub(crate) enum ProtoState {
    File(file::Request),
    /// Boxed: it is moved with the transfer's state at every step.
    Http(Box<http::Request>),
    #[cfg(any(test, feature = "test-util"))]
    Null,
    #[cfg(any(test, feature = "test-util"))]
    Stall,
    #[cfg(any(test, feature = "test-util"))]
    Script(script::Player),
    #[cfg(any(test, feature = "test-util"))]
    Tcp,
}

/// What a protocol step achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtoStep {
    /// The request is complete.
    Done,
    /// Nothing more until something happens.
    Blocked,
}

impl ProtoState {
    /// The protocol for `scheme`, lowercase, if this build has one, set up
    /// for `url`: what C's protocols do in their `setup_connection`, and
    /// `file:`'s connect, which opens the file before a connection is
    /// leased.
    pub(crate) fn start<H: Host>(
        scheme: &[u8],
        url: &Url,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Option<ProtoState>, ErrorKind> {
        Ok(Some(match scheme {
            b"file" => ProtoState::File(file::Request::open(url, cx)?),
            b"http" => ProtoState::Http(
                curl_alloc::try_box(http::Request::new(url, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            #[cfg(any(test, feature = "test-util"))]
            b"null" => ProtoState::Null,
            #[cfg(any(test, feature = "test-util"))]
            b"stall" => ProtoState::Stall,
            #[cfg(any(test, feature = "test-util"))]
            b"script" => ProtoState::Script(script::Player::default()),
            #[cfg(any(test, feature = "test-util"))]
            b"tcp" => ProtoState::Tcp,
            _ => return Ok(None),
        }))
    }

    /// The peer the request connects to, or none for a protocol that
    /// does its own I/O (C's `PROTOPT_NONETWORK`).
    pub(crate) fn network(&self, url: &Url) -> Result<Option<Peer>, ErrorKind> {
        match *self {
            ProtoState::File(_) => Ok(None),
            ProtoState::Http(ref r) => {
                let (host, port) = r.origin()?;
                let scheme = Scheme {
                    name: "http",
                    reuse: true,
                };
                Ok(Some(Peer::new(scheme, host, port, zone(url)?)))
            }
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) => Ok(None),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Tcp => {
                let url_error = crate::multi::state::url_error;
                let host = url.get(Part::Host, GetOptions::NONE).map_err(url_error)?;
                let port = url.get(Part::Port, GetOptions::NONE).map_err(url_error)?;
                let port = std::str::from_utf8(&port)
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .ok_or(ErrorKind::UrlMalformat)?;
                let scheme = Scheme {
                    name: "tcp",
                    reuse: true,
                };
                Ok(Some(Peer::new(scheme, host, port, zone(url)?)))
            }
        }
    }

    /// Make the request (C's `do_it`) over the connection `lease` holds:
    /// `file:`'s is the whole transfer; the test protocols have none to
    /// make.
    pub(crate) fn do_it<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
    ) -> Result<(), ErrorKind> {
        match *self {
            ProtoState::File(ref mut f) => f.do_it(cx),
            ProtoState::Http(ref mut r) => r.do_it(cx, lease),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => {
                Ok(())
            }
        }
    }

    /// Whether the request, once made, exchanges anything more: C's
    /// transfer has a socket to receive or send on.
    pub(crate) fn exchanges(&self) -> bool {
        match *self {
            ProtoState::File(_) => false,
            ProtoState::Http(_) => true,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => true,
        }
    }

    /// Whether the request has more to send (C's `CURL_REQ_WANT_SEND`
    /// at DID): `file:` writes its upload in DO, `http:` what of its head
    /// did not go then.
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(unused_variables, reason = "only the test protocol reads the options")
    )]
    pub(crate) fn wants_send(&self, options: &Options) -> bool {
        match *self {
            ProtoState::File(_) => false,
            ProtoState::Http(ref r) => r.sending(),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(_) => script::wants_send(options),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Tcp => false,
        }
    }

    /// The ways the made request moves bytes now (C's `req.io_flags`):
    /// receiving while it exchanges, sending while it has more to send.
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(unused_variables, reason = "only the test protocol reads the options")
    )]
    pub(crate) fn directions(&self, options: &Options) -> Directions {
        let send = match *self {
            ProtoState::File(_) => false,
            ProtoState::Http(ref r) => r.sending(),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref p) => p.sending(options),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Tcp => false,
        };
        Directions {
            recv: self.exchanges(),
            send,
        }
    }

    /// Whether the request holds output for the application.
    pub(crate) fn holds_output(&self) -> bool {
        match *self {
            // A write cannot pause it: it never holds.
            ProtoState::File(_) => false,
            ProtoState::Http(ref r) => r.holds_output(),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref p) => p.holds_output(),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Tcp => false,
        }
    }

    /// The output of the request, for protocols that deliver any.
    pub(crate) fn pipeline_mut(&mut self) -> Option<&mut Pipeline> {
        match *self {
            ProtoState::File(ref mut f) => Some(f.pipeline_mut()),
            ProtoState::Http(ref mut r) => Some(r.pipeline_mut()),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref mut p) => Some(p.pipeline_mut()),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Tcp => None,
        }
    }

    /// Move the exchange on over the connection `lease` holds.
    pub(crate) fn step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        match *self {
            ProtoState::File(_) => unreachable!("a file request exchanges nothing once made"),
            ProtoState::Http(ref mut r) => r.step(cx, lease),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Tcp => Ok(ProtoStep::Done),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Stall => Ok(ProtoStep::Blocked),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref mut p) => p.step(cx),
        }
    }

    /// What the request waits for on its connection's socket, once made.
    pub(crate) fn interest(&self, pause: Pause) -> Events {
        match *self {
            ProtoState::Http(ref r) => r.interest(pause),
            ProtoState::File(_) => Events::NONE,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => {
                Events::NONE
            }
        }
    }

    /// Whether the request may be made again on a fresh connection, its
    /// reused one having died (`Curl_retry_request`): it got nothing
    /// back, and its protocol answers every request, as HTTP does.
    pub(crate) fn retryable(&self) -> bool {
        match *self {
            ProtoState::Http(ref r) => r.received_nothing(),
            ProtoState::File(_) => false,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => false,
        }
    }

    /// The request is over, with `result` so far, and `next` to follow it
    /// (C's `done`): what the protocol says of it.
    pub(crate) fn done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
        result: Result<(), ErrorKind>,
        premature: bool,
        next: AfterRequest,
    ) -> Result<(), ErrorKind> {
        match *self {
            ProtoState::Http(ref mut r) => r.done(cx, lease, result, premature, next),
            ProtoState::File(_) => result,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => {
                result
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::url::ParseOptions;

    /// The peer a URL names keeps its IPv6 zone.
    #[test]
    fn the_peer_keeps_the_url_s_zone() {
        let zone_of = |url: &[u8]| {
            let opts = ParseOptions {
                non_support_scheme: true,
                ..ParseOptions::NONE
            };
            let url = Url::parse(url, opts).unwrap();
            let peer = ProtoState::Tcp.network(&url).unwrap().unwrap();
            peer.zone().map(<[u8]>::to_vec)
        };
        assert_eq!(
            zone_of(b"tcp://[fe80::1%25eth0]:1/"),
            Some(b"eth0".to_vec())
        );
        assert_eq!(zone_of(b"tcp://[fe80::1]:1/"), None);
    }
}
