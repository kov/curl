//! The protocols a transfer can speak, each a state the transfer holds
//! while it exchanges data.
//!
//! `file:` and `http:` are built in. Tests have three more, networkless: `null:`, which
//! completes at once, `stall:`, which never does, and `script:`, which
//! delivers the pieces of its transfer's `Options::script`; and `tcp:`,
//! which connects to its URL's host and port and completes once
//! connected.

pub(crate) mod file;
pub(crate) mod http;
pub(crate) mod http1;
#[cfg(any(test, feature = "test-util"))]
mod script;

use std::num::NonZeroU32;

use curl_alloc::TryArc;

use crate::conn::io::Events;
use crate::conn::{ConnLease, Peer, Scheme};
use crate::deliver::{Directions, Pause, Pipeline};
use crate::error::ErrorKind;
use crate::error::{UrlErrorKind, url_error};
use crate::multi::Host;
use crate::multi::state::{AfterRequest, StepCx};
use crate::options::{Method, Options};
use crate::url::{GetOptions, Part, Url};

/// The peer `url` names, at `host` and `port`: in the IPv6 scope
/// `scope` if the application sets one (`CURLOPT_ADDRESS_SCOPE`), the
/// URL's zone then not read, or else in the zone's (`Curl_peer_from_url`).
pub(super) fn url_peer(
    scheme: Scheme,
    host: Vec<u8>,
    port: u16,
    url: &Url,
    scope: Option<NonZeroU32>,
) -> Result<Peer, ErrorKind> {
    if let Some(scope) = scope {
        return Ok(Peer::scoped(scheme, host, port, scope));
    }
    let zone = match url.get(Part::ZoneId, GetOptions::NONE) {
        Ok(zone) => Some(zone),
        Err(UrlErrorKind::NoZoneid) => None,
        Err(e) => return Err(url_error(e)),
    };
    Ok(Peer::new(scheme, host, port, zone))
}

/// What a transfer's request takes from the ones before it.
#[derive(Debug)]
pub(crate) struct Inherited {
    /// Where the first request went (`state.initial_origin`): what the
    /// application said for it goes nowhere else.
    pub(crate) first: Option<TryArc<Peer>>,
    /// The method, which a redirect may have turned into a GET
    /// (`state.httpreq`).
    pub(crate) method: Method,
    /// The application's custom method is no longer sent
    /// (`state.http_ignorecustom`).
    pub(crate) ignore_custom: bool,
    /// A response said HTTP/1.0: so do the requests after it
    /// (`state.http_neg.rcvd_min`).
    pub(crate) http10: bool,
    /// A 417 refused `Expect: 100-continue`: the library adds it no more
    /// (`state.disableexpect`).
    pub(crate) no_expect: bool,
    /// `Options::port` still applies: no redirect led to an absolute URL
    /// (`state.allow_port`).
    pub(crate) allow_port: bool,
}

impl Inherited {
    /// What the first request of a transfer that asks for `method` has.
    pub(crate) fn new(method: Method) -> Inherited {
        Inherited {
            first: None,
            method,
            ignore_custom: false,
            http10: false,
            no_expect: false,
            allow_port: true,
        }
    }
}

/// HTTP, as the connection layer knows it.
const HTTP: Scheme = Scheme {
    name: "http",
    reuse: true,
};

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
    /// Stopped reading at the most one step reads, with more perhaps
    /// already there: to run again at once, not when its socket is next
    /// ready (`sendrecv_dl`'s `maxloops`, `Curl_multi_mark_dirty`).
    AtReadLimit,
}

impl ProtoState {
    /// The protocol for `scheme`, lowercase, if this build has one, set up
    /// for `url`: what C's protocols do in their `setup_connection`, and
    /// `file:`'s connect, which opens the file before a connection is
    /// leased.
    pub(crate) fn start<H: Host>(
        scheme: &[u8],
        url: &Url,
        inherited: &Inherited,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Option<ProtoState>, ErrorKind> {
        Ok(Some(match scheme {
            b"file" => ProtoState::File(file::Request::open(url, cx)?),
            b"http" => ProtoState::Http(
                curl_alloc::try_box(http::Request::new(url, inherited, cx)?)
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
    pub(crate) fn network(
        &self,
        url: &Url,
        scope: Option<NonZeroU32>,
    ) -> Result<Option<Peer>, ErrorKind> {
        match *self {
            ProtoState::File(_) => Ok(None),
            ProtoState::Http(ref r) => {
                let (host, port) = r.origin()?;
                Ok(Some(url_peer(HTTP, host, port, url, scope)?))
            }
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) => Ok(None),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Tcp => {
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
                Ok(Some(url_peer(scheme, host, port, url, scope)?))
            }
        }
    }

    /// The request goes whole to a proxy that sends it on to `url`.
    pub(crate) fn forward(&mut self, url: &Url) -> Result<(), ErrorKind> {
        match *self {
            ProtoState::Http(ref mut r) => r.forward(url),
            // Only HTTP's requests are forwarded.
            _ => Ok(()),
        }
    }

    /// Make the request (C's `do_it`) over the connection `lease` holds:
    /// `file:`'s is the whole transfer; the test protocols have none to
    /// make.
    pub(crate) fn do_it<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
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

    /// When the request wants to look again whatever its socket says: an
    /// HTTP body's wait for a 100 running out.
    pub(crate) fn wake_at(&self) -> Option<crate::time::Instant> {
        match self {
            ProtoState::Http(r) => r.wake_at(),
            _ => None,
        }
    }

    /// Where the response's `Location:` points, as the server gave it.
    pub(crate) fn location(&self) -> Option<&[u8]> {
        match *self {
            ProtoState::Http(ref r) => r.location(),
            ProtoState::File(_) => None,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => None,
        }
    }

    /// What the final response's challenges offered and led to.
    pub(crate) fn auth(&mut self) -> Option<http::Challenged<'_>> {
        match *self {
            ProtoState::Http(ref mut r) => r.auth(),
            ProtoState::File(_) => None,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => None,
        }
    }

    pub(crate) fn follow(&self) -> Option<(&[u8], u16)> {
        match *self {
            ProtoState::Http(ref r) => r.follow(),
            ProtoState::File(_) => None,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => None,
        }
    }

    /// A 417 refused the request's `Expect: 100-continue`: it is to be
    /// made again without.
    pub(crate) fn expect_refused(&self) -> bool {
        match *self {
            ProtoState::Http(ref r) => r.expect_refused(),
            ProtoState::File(_) => false,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => false,
        }
    }

    /// A response to the request said HTTP/1.0.
    pub(crate) fn saw_http10(&self) -> bool {
        match *self {
            ProtoState::Http(ref r) => r.saw_http10(),
            ProtoState::File(_) => false,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => false,
        }
    }

    /// The request's body is to be read again for the next request
    /// (`Curl_creader_will_rewind`).
    pub(crate) fn rewinds_upload(&self) -> bool {
        match self {
            ProtoState::Http(r) => r.rewinds_upload(),
            _ => false,
        }
    }

    /// Start the request's body over, for the next request to send it
    /// again (`Curl_client_start`).
    pub(crate) fn rewind_upload<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
    ) -> Result<(), ErrorKind> {
        match *self {
            ProtoState::Http(ref mut r) => r.rewind_upload(cx),
            ProtoState::File(_) => Ok(()),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => {
                Ok(())
            }
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
        lease: &mut ConnLease,
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
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
        premature: bool,
        next: &AfterRequest,
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
            let peer = ProtoState::Tcp.network(&url, None).unwrap().unwrap();
            peer.zone().map(<[u8]>::to_vec)
        };
        assert_eq!(
            zone_of(b"tcp://[fe80::1%25eth0]:1/"),
            Some(b"eth0".to_vec())
        );
        assert_eq!(zone_of(b"tcp://[fe80::1]:1/"), None);
    }
}
