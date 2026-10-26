//! The protocols a transfer can speak, each a state the transfer holds
//! while it exchanges data.
//!
//! `file:`, `http:` and, with a TLS library, `https:` are built in. Tests have three more, networkless: `null:`, which
//! completes at once, `stall:`, which never does, and `script:`, which
//! delivers the pieces of its transfer's `Options::script`; and `tcp:`,
//! which connects to its URL's host and port and completes once
//! connected.

pub(crate) mod file;
pub(crate) mod http;
pub(crate) mod http1;
pub(crate) mod http2;
#[cfg(any(test, feature = "test-util"))]
mod script;

use std::num::NonZeroU32;

use crate::conn::io::Events;
use crate::conn::{ConnLease, Peer, Scheme};
use crate::deliver::{Directions, Pause, Pipeline};
use crate::error::ErrorKind;
use crate::error::{UrlErrorKind, url_error};
use crate::idn::{Idn, IdnFailure};
use crate::multi::Host;
use crate::multi::state::{AfterRequest, StepCx};
use crate::netrc::{self, NetrcError};
use crate::options::NetrcMode;
use crate::options::{Method, Options};
use crate::proto::http1::auth::{Credentials, CredentialsError, NetrcLookup};
use crate::proto::http1::follow::Inherited;
use crate::proto::http1::request::Trusted;
use crate::trace;
use crate::url::{GetOptions, Part, Url};
use curl_alloc::TryVec as _;
use std::ffi::CStr;

/// The peer `url` names, at `host` and `port`: in the IPv6 scope
/// `scope` if the application sets one (`CURLOPT_ADDRESS_SCOPE`), the
/// URL's zone then not read, or else in the zone's; a name in Unicode
/// looked up by its ASCII form, which `idn` makes (`Curl_peer_from_url`).
pub(super) fn url_peer(
    (scheme, host, port): (Scheme, Vec<u8>, u16),
    url: &Url,
    scope: Option<NonZeroU32>,
    idn: Option<&dyn Idn>,
) -> Result<Peer, ErrorKind> {
    let peer = match scope {
        Some(scope) => Peer::scoped(scheme, host, port, scope),
        None => {
            let zone = match url.get(Part::ZoneId, GetOptions::NONE) {
                Ok(zone) => Some(zone),
                Err(UrlErrorKind::NoZoneid) => None,
                Err(e) => return Err(url_error(e)),
            };
            Peer::new(scheme, host, port, zone)
        }
    };
    peer.idn(idn).map_err(IdnFailure::kind)
}

/// What a transfer's next request takes from the ones before it.
#[derive(Clone, Copy)]
pub(crate) struct Before<'r> {
    /// Where the first request went (`state.initial_origin`): what the
    /// application said for it goes nowhere else.
    pub(crate) first: Option<&'r Peer>,
    /// The method, which a redirect may have turned into a GET
    /// (`state.httpreq`).
    pub(crate) method: Method,
    /// What HTTP's requests take from the ones before them.
    pub(crate) http: &'r Inherited,
}

/// A protocol's state for one transfer.
#[derive(Debug)]
#[cfg_attr(
    any(test, feature = "test-util"),
    expect(
        clippy::large_enum_variant,
        reason = "the large one is the test protocols' player, not in the product"
    )
)]
pub(crate) enum ProtoState {
    /// Boxed, as HTTP's: it is moved with the transfer's state at every
    /// step, and a `file:` transfer's DO is a step a piece.
    File(Box<file::Request>),
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

/// What a complete exchange leads to, as its protocol decides.
#[derive(Debug)]
pub(crate) enum Ended<'r> {
    /// What follows the request.
    Then(AfterRequest),
    /// The transfer is over; where the response's `Location:`, as the
    /// server gave it, would have led is kept for the application (C's
    /// `FOLLOW_FAKE`).
    Unfollowed(&'r [u8]),
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

/// Where a step of DO left the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DoStep {
    /// Made: on to DID.
    Made,
    /// More of it to make, in the next step: what a step took is timed
    /// as the drive reads the clock before it, as C's
    /// `Curl_pgrsCheck` reads it within the one call.
    More,
}

/// `credentials` completed or replaced from a `.netrc` file, if the
/// options ask for one and leave room for it (`url_set_data_creds_netrc`).
pub(crate) fn with_netrc<H: Host>(
    credentials: Option<Credentials>,
    host: &[u8],
    cx: &mut StepCx<'_, H>,
) -> Result<Option<Credentials>, ErrorKind> {
    let copy = |bytes: &[u8]| {
        let mut v = Vec::new();
        v.try_extend_from_slice(bytes)
            .map(|()| v)
            .map_err(|_| ErrorKind::OutOfMemory)
    };
    let netrc = &cx.easy().options().netrc;
    let mode = netrc.mode;
    let user = match Credentials::netrc_lookup(credentials.as_ref(), mode) {
        NetrcLookup::No => return Ok(credentials),
        NetrcLookup::For(user) => user.map(copy).transpose()?,
    };
    let path = match &netrc.file {
        Some(file) => Some(copy(file)?),
        None => netrc::default_path().map_err(|_| ErrorKind::OutOfMemory)?,
    };
    let found = match path {
        None => Err(NetrcError::FileMissing),
        Some(mut path) => {
            path.try_push(0).map_err(|_| ErrorKind::OutOfMemory)?;
            match CStr::from_bytes_with_nul(&path) {
                Ok(path) => {
                    netrc::load(path).and_then(|text| netrc::scan(&text, host, user.as_deref()))
                }
                Err(_) => Err(NetrcError::FileMissing),
            }
        }
    };
    match found {
        Ok(found) => Ok(Some(Credentials::with_netrc(credentials, found))),
        Err(NetrcError::OutOfMemory) => Err(ErrorKind::OutOfMemory),
        Err(e) if e == NetrcError::NoMatch || mode == NetrcMode::Optional => {
            let file = match &cx.easy().options().netrc.file {
                Some(file) => copy(file)?,
                None => copy(b".netrc")?,
            };
            trace::info_with(
                cx,
                &[
                    b"Could not find host ",
                    host,
                    b" in the ",
                    &file,
                    b" file; using defaults",
                ],
            );
            Ok(credentials)
        }
        Err(e) => Err(trace::fail(
            cx,
            ErrorKind::ReadError,
            format_args!(".netrc error: {}", e.text()),
        )),
    }
}

/// C's `.netrc` step for a URL that no HTTP request is made for: one of
/// another protocol, or one the application does not let the transfer go
/// to. C reads the file before it checks the protocol
/// (`parseurlandfillconn`, before `url_set_conn_scheme`), so a required
/// file that is missing or malformed fails the transfer whatever its
/// scheme; an HTTP request reads it as it is made (`http::Request::new`).
/// The credentials are C's at that point, the application's and the
/// URL's, and are not kept: no protocol here sends any.
pub(crate) fn netrc_before_protocol<H: Host>(
    url: &Url,
    cx: &mut StepCx<'_, H>,
) -> Result<(), ErrorKind> {
    let login = &cx.easy().options().login;
    let credentials = match Credentials::for_request(login, Some(Trusted::own_url()), url) {
        Ok(credentials) => credentials,
        Err(CredentialsError::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(CredentialsError::Malformed) => {
            return Err(trace::fail(
                cx,
                ErrorKind::UrlMalformat,
                format_args!("error extracting credentials from URL"),
            ));
        }
    };
    // The host as C's origin holds it: none for `file:///`, an IPv6
    // address without its brackets.
    let host = match url.get(Part::Host, GetOptions::NONE) {
        Ok(host) => host,
        Err(UrlErrorKind::NoHost) => Vec::new(),
        Err(e) => return Err(url_error(e)),
    };
    let bare = host
        .strip_prefix(b"[")
        .and_then(|h| h.strip_suffix(b"]"))
        .unwrap_or(&host);
    with_netrc(credentials, bare, cx).map(drop)
}

/// The tests' own schemes, which `ProtoState::start` knows beside
/// libcurl's.
#[cfg(any(test, feature = "test-util"))]
const TEST_SCHEMES: [&[u8]; 4] = [b"null", b"stall", b"script", b"tcp"];

impl ProtoState {
    /// Whether `scheme`, lowercase, is one libcurl knows, whether this
    /// build has it or not (`Curl_get_scheme`): the tests' own too.
    pub(crate) fn knows(scheme: &[u8]) -> bool {
        #[cfg(any(test, feature = "test-util"))]
        if TEST_SCHEMES.contains(&scheme) {
            return true;
        }
        crate::url::is_known_scheme(scheme)
    }

    /// The protocol for `scheme`, lowercase, if this build has one, set up
    /// for `url`: what C's protocols do in their `setup_connection`, and
    /// `file:`'s connect, which opens the file before a connection is
    /// leased.
    pub(crate) fn start<H: Host>(
        scheme: &[u8],
        url: &Url,
        before: Before<'_>,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Option<ProtoState>, ErrorKind> {
        Ok(Some(match scheme {
            b"file" => ProtoState::File(
                curl_alloc::try_box(file::Request::open(url, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"http" => ProtoState::Http(
                curl_alloc::try_box(http::Request::new(url, false, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            // Over TLS, if the handle has a TLS library: without one, it
            // is a scheme the build leaves out, as in C built without.
            b"https" if cx.easy().libraries().tls.is_some() => ProtoState::Http(
                curl_alloc::try_box(http::Request::new(url, true, before, cx)?)
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
        idn: Option<&dyn Idn>,
    ) -> Result<Option<Peer>, ErrorKind> {
        match *self {
            ProtoState::File(_) => Ok(None),
            ProtoState::Http(ref r) => Ok(Some(r.network(url, scope, idn)?)),
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
                Ok(Some(url_peer((scheme, host, port), url, scope, idn)?))
            }
        }
    }

    /// The request goes over TLS (C's `PROTOPT_SSL`).
    pub(crate) fn secured(&self) -> bool {
        match self {
            ProtoState::Http(r) => r.secured(),
            _ => false,
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

    /// The connection goes to `via`, an alternative service of the
    /// origin's: the request says so (`Alt-Used:`).
    pub(crate) fn alt_used(&mut self, via: &Peer) -> Result<(), curl_alloc::OutOfMemory> {
        match *self {
            ProtoState::Http(ref mut r) => r.alt_used(via),
            // Only HTTP's requests have alternatives.
            _ => Ok(()),
        }
    }

    /// Make the request (C's `do_it`) over the connection `lease` holds,
    /// or a step of it: `file:`'s is the whole transfer, made a piece a
    /// step; the test protocols have none to make.
    pub(crate) fn do_it<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<DoStep, ErrorKind> {
        match *self {
            ProtoState::File(ref mut f) => f.do_it(cx),
            ProtoState::Http(ref mut r) => r.do_it(cx, lease).map(|()| DoStep::Made),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => {
                Ok(DoStep::Made)
            }
        }
    }

    /// Whether the size of the body to come, once known, is the request's
    /// (C's `req.size`), which a timeout's message names: `file:` gives
    /// only the progress its size (`Curl_pgrsSetDownloadSize`).
    pub(crate) fn sizes_request(&self) -> bool {
        !matches!(self, ProtoState::File(_))
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

    /// The exchange is complete: what follows it, as the protocol
    /// decides at its end (C's `req.newurl` and `req.location`). `url` is
    /// the request's, `origin` the connection's peer, and `http` what
    /// HTTP's next request takes.
    pub(crate) fn exchanged<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        url: &[u8],
        origin: Option<&Peer>,
        http: &mut Inherited,
    ) -> Result<Ended<'_>, ErrorKind> {
        match *self {
            ProtoState::Http(ref mut r) => r.exchanged(cx, url, origin, http),
            _ => Ok(Ended::Then(AfterRequest::Complete)),
        }
    }

    /// The next request is one a `code` redirect leads to, "Issue another
    /// request" said: what the protocol changes of it, `method` among it
    /// (`Curl_http_follow`). Whether it switched to GET.
    pub(crate) fn redirected<H: Host>(
        &self,
        cx: &mut StepCx<'_, H>,
        code: u16,
        method: &mut Method,
        http: &mut Inherited,
    ) -> bool {
        match *self {
            ProtoState::Http(_) => http::redirected(cx, code, method, http),
            _ => unreachable!("only HTTP's exchange ends in a redirect"),
        }
    }

    /// The transfer is done with the connection, before its request was
    /// over, outside its steps (`Curl_conn_ev_data_done`): an HTTP/2
    /// stream still open is reset, and that goes out.
    pub(crate) fn data_done<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) {
        if let ProtoState::Http(r) = self {
            r.data_done(cx, lease);
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

    /// The HTTP versions the request may speak; any, for another protocol.
    pub(crate) fn http_versions(&self, options: &Options) -> http::Versions {
        match self {
            ProtoState::Http(r) => r.versions(options.http.version),
            _ => http::Versions::ALL,
        }
    }

    /// Whether the transfer has found what its connection speaks: a
    /// protocol that is not HTTP's never multiplexes.
    pub(crate) fn settled_conn(&self) -> bool {
        match self {
            ProtoState::Http(r) => r.settled_conn(),
            _ => true,
        }
    }

    /// An HTTP/2 stream said HTTP/1.1 is required
    /// (`Curl_h2_http_1_1_error`).
    pub(crate) fn h1_required(&self) -> bool {
        match self {
            ProtoState::Http(r) => r.h1_required(),
            _ => false,
        }
    }

    /// The request went on a stream HTTP/2 refused, which is safe to make
    /// again (`state.refused_stream`): said once.
    pub(crate) fn take_refused(&mut self) -> bool {
        match self {
            ProtoState::Http(r) => r.take_refused(),
            _ => false,
        }
    }

    /// The request is over, with `result` so far, and `next` to follow it
    /// (C's `done`): what the protocol says of it, and what HTTP's next
    /// request takes from it into `http`.
    pub(crate) fn done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
        premature: bool,
        next: &AfterRequest,
        http: &mut Inherited,
    ) -> Result<(), ErrorKind> {
        match *self {
            ProtoState::Http(ref mut r) => r.done(cx, lease, result, premature, next, http),
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
            let peer = ProtoState::Tcp.network(&url, None, None).unwrap().unwrap();
            peer.zone().map(<[u8]>::to_vec)
        };
        assert_eq!(
            zone_of(b"tcp://[fe80::1%25eth0]:1/"),
            Some(b"eth0".to_vec())
        );
        assert_eq!(zone_of(b"tcp://[fe80::1]:1/"), None);
    }
}
