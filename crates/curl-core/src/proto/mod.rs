//! The protocols a transfer can speak, each a state the transfer holds
//! while it exchanges data.
//!
//! `file:`, `http:`, `imap:`, `pop3:`, `smtp:` and, with a TLS library,
//! `https:`, `imaps:`, `pop3s:` and `smtps:` are built in. Tests have three more, networkless: `null:`, which
//! completes at once, `stall:`, which never does, and `script:`, which
//! delivers the pieces of its transfer's `Options::script`; and `tcp:`,
//! which connects to its URL's host and port and completes once
//! connected.

pub(crate) mod file;
pub(crate) mod http;
pub(crate) mod http1;
pub(crate) mod http2;
pub(crate) mod http3;
pub(crate) mod imap;
pub(crate) mod pingpong;
pub(crate) mod pop3;
#[cfg(any(test, feature = "test-util"))]
mod script;
pub(crate) mod smtp;

use std::num::NonZeroU32;

use crate::auth::creds::{Credentials, CredentialsError, NetrcLookup, Takes, Trusted};
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
use crate::proto::http1::follow::Inherited;
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
    /// Boxed, as HTTP's.
    Pop3(Box<pop3::Request>),
    /// Boxed, as HTTP's.
    Imap(Box<imap::Request>),
    /// Boxed, as HTTP's.
    Smtp(Box<smtp::Request>),
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

/// `tcp:`'s connect, as its handle's script says: a goodbye in it is
/// kept on the connection, as FTP keeps its state there; and it waits
/// for good if the script has the phase, as a protocol whose server
/// never answers.
#[cfg(any(test, feature = "test-util"))]
fn tcp_connect<H: Host>(
    cx: &mut StepCx<'_, H>,
    lease: &mut ConnLease,
) -> Result<Connect, ErrorKind> {
    use crate::options::script::Piece;
    use curl_alloc::TryVec as _;
    let Some(script) = cx.easy().options().script.as_ref() else {
        return Ok(Connect::Done);
    };
    let mut pieces = (0..).map_while(|i| script.get(i));
    let goodbye = pieces.clone().find_map(|p| match p {
        Piece::Goodbye(bytes) => Some(bytes),
        _ => None,
    });
    if let Some(bytes) = goodbye
        && !lease.get().keeps_line()
    {
        let mut said = Vec::new();
        said.try_extend_from_slice(bytes)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let line = crate::conn::line::LineConn::Test(crate::conn::line::Farewell(said));
        let line = curl_alloc::try_box(line).map_err(|_| ErrorKind::OutOfMemory)?;
        lease.get().put_line(line);
    }
    Ok(if pieces.any(|p| matches!(p, Piece::ProtoConnecting)) {
        Connect::Waiting
    } else {
        Connect::Done
    })
}

/// `tcp:`'s request, as its handle's script says: made at once, or
/// for good in DOING or DOING_MORE if the script has that phase, as a
/// protocol whose server never answers.
#[cfg(any(test, feature = "test-util"))]
fn tcp_make<H: Host>(cx: &StepCx<'_, H>) -> DoStep {
    use crate::options::script::Piece;
    let Some(script) = cx.easy().options().script.as_ref() else {
        return DoStep::Did;
    };
    let mut pieces = (0..).map_while(|i| script.get(i));
    match pieces.find(|p| matches!(p, Piece::Doing | Piece::DoingMore)) {
        Some(Piece::Doing) => DoStep::Doing,
        Some(_) => DoStep::More,
        None => DoStep::Did,
    }
}

/// Where a protocol's connect over its connection stands (C's
/// `connect_it` and `connecting`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Connect {
    /// Connected: on to DO.
    Done,
    /// Not yet: waiting in PROTOCONNECTING for what its pollset says.
    Waiting,
}

/// The phase a protocol is asked to make its request in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DoPhase {
    /// DO, the request's start (`do_it`).
    Do,
    /// DOING, its rest (`doing`).
    Doing,
    /// DOING_MORE, its second half (`do_more`), FTP's once its data
    /// connection is to be made.
    More,
}

/// Where a step of making the request left it; from any phase, the
/// phase it goes on in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DoStep {
    /// Made: on to DID (`dophase_done` without `do_more`; DOMORE_DONE).
    Did,
    /// More of its first half to make, in DOING (`!dophase_done`;
    /// DOMORE_GOBACK from DOING_MORE).
    Doing,
    /// Its second half to make, in DOING_MORE (`bits.do_more`;
    /// DOMORE_INCOMPLETE there).
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(
            dead_code,
            reason = "no protocol built yet has a second half, as FTP will"
        )
    )]
    More,
    /// More of it to make within DO, in the next step: what a step took
    /// is timed as the drive reads the clock before it, as C's
    /// `Curl_pgrsCheck` reads it within the one call (`file:`'s DO, a
    /// piece a step). Only DO's step answers it.
    Piece,
}

/// A phase a request waits in before it is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Waiting {
    /// PROTOCONNECTING.
    Connecting,
    /// DOING.
    Doing,
    /// DOING_MORE.
    More,
    /// DONE, the protocol's last answer of the request awaited, which C
    /// reads blocking in its `done`.
    Done,
}

impl Waiting {
    /// What C waits for in the phase when the protocol says nothing of
    /// its own (`mstate_protocol_pollset`, `mstate_do_pollset`,
    /// `mstate_domore_pollset`): something from the server while it
    /// connects, to send while it makes the request, nothing in DONE.
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(dead_code, reason = "the protocols built say what they wait for")
    )]
    pub(crate) fn c_default(self) -> Events {
        match self {
            Waiting::Connecting => Events::IN,
            Waiting::Doing | Waiting::More => Events::OUT,
            Waiting::Done => Events::NONE,
        }
    }
}

/// Where a protocol's end of a request stands (C's `done`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Finish {
    /// Over, with this result.
    Done(Result<(), ErrorKind>),
    /// Its last answer is awaited, as the protocol's `waits(Waiting::Done)`
    /// and `due` say: C blocks on it (`imap_block_statemach`,
    /// `smtp_block_statemach`); the
    /// transfer waits in DONE instead, the others going on.
    Waiting,
}

/// What a protocol does before its request is made: its connect over
/// the connection, its request made in one step or more, and what it
/// waits for meanwhile (C's `connect_it`, `connecting`, `do_it`,
/// `doing`, `do_more` and their pollsets). Every protocol answers each,
/// none by a default.
pub(crate) trait Phases {
    /// Connect over the connection, or move the connect on.
    fn connect<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Connect, ErrorKind>;

    /// Make the request, or move it on, in the phase `asked`.
    fn make<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind>;

    /// What it waits for on its connection while in `phase`.
    fn waits(&self, phase: Waiting) -> Events;
}

/// `credentials` completed or replaced from a `.netrc` file, if the
/// options ask for one and leave room for it (`url_set_data_creds_netrc`):
/// an entry with a byte the scheme `takes` not fails the transfer.
pub(crate) fn with_netrc<H: Host>(
    credentials: Option<Credentials>,
    host: &[u8],
    takes: Takes,
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
        // Credentials a file would not change are taken as they are,
        // said only where no file is asked for.
        NetrcLookup::No => {
            let says = mode == NetrcMode::Ignored;
            return set_out_with(credentials, says, cx);
        }
        NetrcLookup::For(user) => user.map(copy).transpose()?,
    };
    // The file's name is copied out of the options only to be said.
    if trace::traces(cx, crate::components::Component::Multi) {
        let file = netrc.file.as_deref().map(copy).transpose()?;
        crate::multi::mstate::trace_with(
            cx,
            &[
                b"[NETRC] scanning '",
                file.as_deref().unwrap_or(b"(nil)"),
                b"' for host '",
                host,
                b"' user '",
                user.as_deref().unwrap_or_default(),
                b"'",
            ],
        );
    }
    let netrc = &cx.easy().options().netrc;
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
        Ok(found) if !takes.allows(&found.user) || !takes.allows(&found.password) => {
            Err(trace::fail(
                cx,
                ErrorKind::ReadError,
                format_args!("control code detected in .netrc credentials"),
            ))
        }
        Ok(found) => {
            crate::multi::mstate::trace_with(
                cx,
                &[b"netrc: using credentials for ", host, b" as ", &found.user],
            );
            set_out_with(Some(Credentials::with_netrc(credentials, found)), true, cx)
        }
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
            set_out_with(credentials, true, cx)
        }
        Err(e) => Err(trace::fail(
            cx,
            ErrorKind::ReadError,
            format_args!(".netrc error: {}", e.text()),
        )),
    }
}

/// The request sets out with `credentials`: said, if C's `.netrc` step
/// `says` so, as the handle's last request set out (`state.creds` as
/// `url_set_data_creds_netrc` traces it, before it takes these), then
/// kept for the next to say.
fn set_out_with<H: Host>(
    credentials: Option<Credentials>,
    says: bool,
    cx: &mut StepCx<'_, H>,
) -> Result<Option<Credentials>, ErrorKind> {
    // Taken out, as these replace it.
    let before = cx.easy_mut().shown_credentials.take();
    if says {
        const MSG: &[u8] = b"transfer credentials: ";
        match &before {
            None => crate::multi::mstate::trace_with(cx, &[MSG, b"-"]),
            Some(shown) => {
                let mut line = [MSG; 11];
                line[1..].copy_from_slice(&shown.parts());
                crate::multi::mstate::trace_with(cx, &line);
            }
        }
    }
    let shown = credentials
        .as_ref()
        .map(crate::auth::creds::Shown::of)
        .transpose()
        .map_err(|_| ErrorKind::OutOfMemory)?;
    cx.easy_mut().shown_credentials = shown;
    Ok(credentials)
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
    let scheme = url.get(Part::Scheme, GetOptions::NONE).map_err(url_error)?;
    let takes = Takes::of(Scheme::named(&scheme));
    let credentials = request_credentials(cx, Some(Trusted::own_url()), url, takes)?;
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
    with_netrc(credentials, bare, takes, cx).map(drop)
}

/// What a request to `url` authenticates with, as the application and
/// the URL say, the application's if `trusted` lets them go there; failed
/// as C fails it where a byte the scheme `takes` not is in them
/// (`url_set_data_creds`).
pub(crate) fn request_credentials<H: Host>(
    cx: &mut StepCx<'_, H>,
    trusted: Option<Trusted>,
    url: &Url,
    takes: Takes,
) -> Result<Option<Credentials>, ErrorKind> {
    let login = &cx.easy().options().login;
    match Credentials::for_request(login, trusted, url, takes) {
        Ok(credentials) => Ok(credentials),
        Err(CredentialsError::OutOfMemory) => Err(ErrorKind::OutOfMemory),
        Err(CredentialsError::Malformed) => Err(trace::fail(
            cx,
            ErrorKind::UrlMalformat,
            format_args!("error extracting credentials from URL"),
        )),
        Err(CredentialsError::Control) => Err(trace::fail(
            cx,
            ErrorKind::BadFunctionArgument,
            format_args!("control code detected in credentials"),
        )),
    }
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
            b"imap" => ProtoState::Imap(
                curl_alloc::try_box(imap::Request::new(url, false, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"imaps" if cx.easy().libraries().tls.is_some() => ProtoState::Imap(
                curl_alloc::try_box(imap::Request::new(url, true, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"pop3" => ProtoState::Pop3(
                curl_alloc::try_box(pop3::Request::new(url, false, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"pop3s" if cx.easy().libraries().tls.is_some() => ProtoState::Pop3(
                curl_alloc::try_box(pop3::Request::new(url, true, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"smtp" => ProtoState::Smtp(
                curl_alloc::try_box(smtp::Request::new(url, false, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"smtps" if cx.easy().libraries().tls.is_some() => ProtoState::Smtp(
                curl_alloc::try_box(smtp::Request::new(url, true, before, cx)?)
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
            ProtoState::Pop3(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Imap(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Smtp(ref r) => Ok(Some(r.network(url, scope, idn)?)),
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
                let scheme = Scheme::own(&crate::conn::TCP_SCHEME);
                Ok(Some(url_peer((scheme, host, port), url, scope, idn)?))
            }
        }
    }

    /// The scheme of libcurl's the request is of; none for the tests'
    /// own.
    pub(crate) fn scheme(&self) -> Option<Scheme> {
        match self {
            ProtoState::Http(r) => Some(r.scheme()),
            ProtoState::Pop3(r) => Some(r.scheme()),
            ProtoState::Imap(r) => Some(r.scheme()),
            ProtoState::Smtp(r) => Some(r.scheme()),
            ProtoState::File(_) => Scheme::named(b"file"),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => None,
        }
    }

    /// An idle connection is taken for the request: the one C made for
    /// it to compare with is let go, its disconnect handler run on it
    /// (`url_find_or_create_conn`, `Curl_conn_free`). Only SMTP's says
    /// anything there.
    pub(crate) fn reused<H: Host>(&self, cx: &mut StepCx<'_, H>) {
        if let ProtoState::Smtp(_) = self {
            smtp::let_go_unused(cx);
        }
    }

    /// The credentials a connection made for the request logs in with
    /// once, taken from it for the route, if its scheme logs in per
    /// connection (`url_set_conn_login`).
    pub(crate) fn take_login(&mut self) -> Option<Credentials> {
        match self {
            ProtoState::Pop3(r) => r.take_login(),
            ProtoState::Imap(r) => r.take_login(),
            ProtoState::Smtp(r) => r.take_login(),
            _ => None,
        }
    }

    /// The request goes over TLS (C's `PROTOPT_SSL`).
    pub(crate) fn secured(&self) -> bool {
        match self {
            ProtoState::Http(r) => r.secured(),
            ProtoState::Pop3(r) => r.secured(),
            ProtoState::Imap(r) => r.secured(),
            ProtoState::Smtp(r) => r.secured(),
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
    pub(crate) fn alt_used(
        &mut self,
        via: &Peer,
        speaks: Option<crate::altsvc::Alpn>,
    ) -> Result<(), curl_alloc::OutOfMemory> {
        match *self {
            ProtoState::Http(ref mut r) => r.alt_used(via, speaks),
            // Only HTTP's requests have alternatives.
            _ => Ok(()),
        }
    }

    /// Connect over the connection `lease` holds, or move the connect on
    /// (C's `connect_it`, then `connecting`); the test protocols but
    /// `script:` connect at once.
    pub(crate) fn connect<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        match *self {
            ProtoState::File(ref mut f) => f.connect(cx, lease),
            ProtoState::Http(ref mut r) => r.connect(cx, lease),
            ProtoState::Pop3(ref mut r) => r.connect(cx, lease),
            ProtoState::Imap(ref mut r) => r.connect(cx, lease),
            ProtoState::Smtp(ref mut r) => r.connect(cx, lease),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref mut p) => p.connect(cx, lease),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall => Ok(Connect::Done),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Tcp => tcp_connect(cx, lease),
        }
    }

    /// Make the request over the connection `lease` holds, or a step of
    /// it, in the phase `asked` (C's `do_it`, `doing` and `do_more`):
    /// `file:`'s is the whole transfer, made a piece a step; the test
    /// protocols but `script:` have none to make.
    pub(crate) fn make<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind> {
        match *self {
            ProtoState::File(ref mut f) => f.make(cx, lease, asked),
            ProtoState::Http(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Pop3(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Imap(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Smtp(ref mut r) => r.make(cx, lease, asked),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref mut p) => p.make(cx, lease, asked),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall => Ok(DoStep::Did),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Tcp => Ok(tcp_make(cx)),
        }
    }

    /// What the request waits for on its connection while in `phase`.
    pub(crate) fn waits(&self, phase: Waiting) -> Events {
        match *self {
            ProtoState::File(ref f) => f.waits(phase),
            ProtoState::Http(ref r) => r.waits(phase),
            ProtoState::Pop3(ref r) => r.waits(phase),
            ProtoState::Imap(ref r) => r.waits(phase),
            ProtoState::Smtp(ref r) => r.waits(phase),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref p) => p.waits(phase),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Tcp => phase.c_default(),
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
            // POP3 never says its transfer has no socket, so the
            // connection's stays its to receive on (`recv_idx`), body or
            // not.
            ProtoState::Http(_) | ProtoState::Pop3(_) => true,
            // A literal to read, a body to send, or the answer after
            // either (`imap_done`'s FETCH_FINAL and APPEND_FINAL).
            ProtoState::Imap(ref r) => r.exchanges(),
            // A mail's body to send, as the connection's `recv_idx` and
            // `send_idx` say.
            ProtoState::Smtp(ref r) => r.exchanges(),
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
            ProtoState::File(_) | ProtoState::Pop3(_) => false,
            ProtoState::Imap(ref r) => r.sending(),
            ProtoState::Smtp(ref r) => r.sending(),
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
            ProtoState::File(_) | ProtoState::Pop3(_) => false,
            ProtoState::Imap(ref r) => r.sending(),
            ProtoState::Smtp(ref r) => r.sending(),
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
    /// HTTP body's wait for a 100 running out, or IMAP's and SMTP's poll
    /// in DONE as it awaits its answer.
    pub(crate) fn due(&self) -> Option<crate::time::Instant> {
        match self {
            ProtoState::Http(r) => r.due(),
            ProtoState::Imap(r) => r.due(),
            ProtoState::Smtp(r) => r.due(),
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
            ProtoState::File(_)
            | ProtoState::Pop3(_)
            | ProtoState::Imap(_)
            | ProtoState::Smtp(_) => Ok(()),
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
            ProtoState::Pop3(ref r) => r.holds_output(),
            ProtoState::Imap(ref r) => r.holds_output(),
            ProtoState::Smtp(ref r) => r.holds_output(),
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
            ProtoState::Pop3(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Imap(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Smtp(ref mut r) => Some(r.pipeline_mut()),
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
            ProtoState::Pop3(ref mut r) => r.step(cx, lease),
            ProtoState::Imap(ref mut r) => r.step(cx, lease),
            ProtoState::Smtp(ref mut r) => r.step(cx, lease),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Tcp => Ok(ProtoStep::Done),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Stall => Ok(ProtoStep::Blocked),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref mut p) => p.step(cx),
        }
    }

    /// What of its sending an HTTP/3 connection weighs in its pollset.
    pub(crate) fn h3_sending(&self) -> Option<crate::proto::http::StreamSend> {
        match *self {
            ProtoState::Http(ref r) => r.h3_sending(),
            _ => None,
        }
    }

    /// What the request waits for on its connection's socket, once made.
    pub(crate) fn interest(&self, pause: Pause) -> Events {
        match *self {
            ProtoState::Http(ref r) => r.interest(pause),
            ProtoState::Pop3(ref r) => r.interest(pause),
            ProtoState::Imap(ref r) => r.interest(pause),
            ProtoState::Smtp(ref r) => r.interest(pause),
            ProtoState::File(_) => Events::NONE,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => {
                Events::NONE
            }
        }
    }

    /// Whether the request may be made again on a fresh connection, its
    /// reused one having died (`Curl_retry_request`): it got nothing
    /// back, and its protocol answers every request, as HTTP does, or it
    /// waits for a body it has not had.
    pub(crate) fn retryable(&self) -> bool {
        match *self {
            ProtoState::Http(ref r) => r.received_nothing(),
            ProtoState::Pop3(ref r) => r.received_nothing(),
            ProtoState::Imap(ref r) => r.received_nothing(),
            ProtoState::Smtp(ref r) => r.received_nothing(),
            ProtoState::File(_) => false,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => false,
        }
    }

    /// The credentials an HTTP request found in a `.netrc` file, which
    /// C writes into the URL a redirect is resolved against
    /// (`url_set_data_creds_netrc`, into `state.uh`).
    pub(crate) fn netrc_login(&self) -> Option<&Credentials> {
        match self {
            ProtoState::Http(r) => r.login().filter(|c| c.found_in_netrc()),
            _ => None,
        }
    }

    /// Whether the protocol follows a request with another of its own
    /// making, as HTTP does (its `follow` handler): a retry of any other
    /// is the same URL connected for again (`multi_follow`).
    pub(crate) fn follows(&self) -> bool {
        matches!(self, ProtoState::Http(_))
    }

    /// What an HTTP request may speak, as C negotiates it; none for
    /// another protocol.
    pub(crate) fn negotiation(&self) -> Option<http::Negotiation> {
        match self {
            ProtoState::Http(r) => Some(r.negotiation()),
            _ => None,
        }
    }

    /// What an HTTP request may speak, to change; none for another
    /// protocol.
    pub(crate) fn negotiation_mut(&mut self) -> Option<&mut http::Negotiation> {
        match self {
            ProtoState::Http(r) => Some(r.negotiation_mut()),
            _ => None,
        }
    }

    /// HTTP/1.1 was required: the request and those after it speak HTTP/1
    /// only.
    pub(crate) fn downgrade(&mut self) {
        if let ProtoState::Http(r) = self {
            r.downgrade();
        }
    }

    /// The HTTP versions a connection the request reuses or joins may
    /// speak (`http_neg.allowed`): with no version asked for, HTTP/3 too,
    /// though it is not wanted; any, for another protocol.
    pub(crate) fn allowed_versions(&self) -> http::Versions {
        self.negotiation()
            .map_or(http::Versions::ALL, |neg| neg.allowed_versions())
    }

    /// The HTTP versions the request wants (`http_neg.wanted`); any, for
    /// another protocol.
    pub(crate) fn http_versions(&self) -> http::Versions {
        self.negotiation()
            .map_or(http::Versions::ALL, |neg| neg.versions())
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

    /// The connection hears the transfer is done with it, once the
    /// request is (`Curl_conn_ev_data_done`).
    pub(crate) fn data_done<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) {
        if let ProtoState::Http(r) = self {
            r.data_done(cx, lease);
        }
    }

    /// The request is over, with `result` so far, and `next` to follow it
    /// (C's `done`): what the protocol says of it, and what HTTP's next
    /// request takes from it into `http`; or that it awaits its last
    /// answer, which [`ProtoState::finishing`] reads on. `exchanged` is
    /// C's `req.done`: the exchange ran to its end.
    #[expect(clippy::too_many_arguments, reason = "C's done and what it reads")]
    pub(crate) fn done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
        premature: bool,
        next: &AfterRequest,
        http: &mut Inherited,
        exchanged: bool,
    ) -> Finish {
        match *self {
            ProtoState::Http(ref mut r) => {
                Finish::Done(r.done(cx, lease, result, premature, next, http))
            }
            ProtoState::Pop3(ref mut r) => Finish::Done(r.done(cx, lease, result)),
            ProtoState::Imap(ref mut r) => r.done(cx, lease, result, premature, exchanged),
            ProtoState::Smtp(ref mut r) => r.done(cx, lease, result, premature, exchanged),
            ProtoState::File(_) => Finish::Done(result),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => {
                Finish::Done(result)
            }
        }
    }

    /// Read on the last answer its `done` awaits.
    pub(crate) fn finishing<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        exchanged: bool,
    ) -> Finish {
        match *self {
            ProtoState::Imap(ref mut r) => r.finishing(cx, lease, exchanged),
            ProtoState::Smtp(ref mut r) => r.finishing(cx, lease, exchanged),
            _ => unreachable!("only IMAP and SMTP await an answer as their request ends"),
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
