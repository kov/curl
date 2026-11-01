//! The protocols a transfer can speak, each a state the transfer holds
//! while it exchanges data.
//!
//! `dict:`, `file:`, `ftp:`, `gopher:`, `http:`, `imap:`, `mqtt:`,
//! `pop3:`, `rtsp:`, `smtp:`, `telnet:`, `tftp:` and `ws:`, with a TLS
//! library `ftps:`, `gophers:`, `https:`, `imaps:`, `mqtts:`, `pop3s:`,
//! `smtps:` and `wss:`, with an SSH library `scp:` and `sftp:`, and with
//! an LDAP library `ldap:` and, with TLS too, `ldaps:` are built in.
//! Tests have three more, networkless: `null:`, which completes at once,
//! `stall:`, which never does, and `script:`, which delivers the pieces
//! of its transfer's `Options::script`; and `tcp:`, which connects to its
//! URL's host and port and completes once connected.

pub(crate) mod dict;
pub(crate) mod file;
pub(crate) mod ftp;
pub(crate) mod gopher;
pub(crate) mod http;
pub(crate) mod http1;
pub(crate) mod http2;
pub(crate) mod http3;
pub(crate) mod imap;
pub(crate) mod ldap;
pub(crate) mod mqtt;
pub(crate) mod pingpong;
pub(crate) mod pop3;
pub(crate) mod raw;
#[cfg(any(test, feature = "test-util"))]
mod script;
pub(crate) mod smtp;
pub(crate) mod ssh;
pub(crate) mod telnet;
pub(crate) mod tftp;
pub(crate) mod ws;
pub(crate) mod xfer;

use std::num::NonZeroU32;

use crate::auth::creds::{
    CredentialGate, Credentials, CredentialsError, NetrcLookup, Takes, Trusted,
};
use crate::conn::io::Events;
use crate::conn::{ConnLease, Peer, Scheme};
use crate::deliver::{Directions, Pause, Pipeline};
use crate::error::ErrorKind;
use crate::error::{UrlErrorKind, url_error};
use crate::idn::{Idn, IdnFailure};
use crate::multi::Host;
use crate::multi::state::{AfterRequest, SetupLend, StepCx};
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
pub(crate) enum ProtoState {
    /// Boxed, as HTTP's: it is moved with the transfer's state at every
    /// step, and a `file:` transfer's DO is a step a piece.
    File(Box<file::Request>),
    /// Boxed: it is moved with the transfer's state at every step.
    Http(Box<http::Request>),
    /// Boxed, as HTTP's.
    Ftp(Box<ftp::Request>),
    /// Boxed, as HTTP's.
    Pop3(Box<pop3::Request>),
    /// Boxed, as HTTP's.
    Imap(Box<imap::Request>),
    /// Boxed, as HTTP's.
    Smtp(Box<smtp::Request>),
    /// Boxed, as HTTP's.
    Ssh(Box<ssh::Request>),
    /// Boxed, as HTTP's.
    Ldap(Box<ldap::Request>),
    /// Boxed, as HTTP's.
    Dict(Box<dict::Request>),
    /// Boxed, as HTTP's.
    Gopher(Box<gopher::Request>),
    /// Boxed, as HTTP's.
    Mqtt(Box<mqtt::Request>),
    /// Boxed, as HTTP's.
    Telnet(Box<telnet::Request>),
    /// Boxed, as HTTP's.
    Tftp(Box<tftp::Request>),
    #[cfg(any(test, feature = "test-util"))]
    Null,
    #[cfg(any(test, feature = "test-util"))]
    Stall,
    /// Boxed, as HTTP's.
    #[cfg(any(test, feature = "test-util"))]
    Script(Box<script::Player>),
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
    More,
    /// More of it to make within DO, in the next step: what a step took
    /// is timed as the drive reads the clock before it, as C's
    /// `Curl_pgrsCheck` reads it within the one call (`file:`'s DO, a
    /// piece a step). Only DO's step answers it.
    Piece,
    /// None to make: the wildcard download it is one of has no more to
    /// get, and the transfer is over (`multistate_do`, `CURLWC_DONE`).
    /// Only DO's step answers it.
    Nothing,
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

/// C's `.netrc` step for a request that keeps no credentials: one whose
/// protocol sends none, or one not made because its protocol is not built
/// or not allowed. C reads the file before it checks the protocol
/// (`parseurlandfillconn`, before `url_set_conn_scheme`), so a required
/// file that is missing or malformed fails the transfer whatever its
/// scheme. A request that keeps them reads it as it is made.
///
/// The host is the origin's name, as a request that keeps them looks it
/// up (`state.origin->hostname`), and what is wrong with the origin fails
/// first; a scheme with no network, and a test's own, have none to check.
/// The application's login counts only where `first` lets it go, as for
/// any request.
pub(crate) fn netrc_unkept<H: Host>(
    url: &Url,
    first: Option<&Peer>,
    cx: &mut StepCx<'_, H>,
) -> Result<(), ErrorKind> {
    let name = url.get(Part::Scheme, GetOptions::NONE).map_err(url_error)?;
    let scheme = Scheme::named(&name);
    let takes = Takes::of(scheme);
    if let Some(scheme) = scheme.filter(|s| !s.no_network()) {
        let peer = dict::peer_of(url, scheme.name().as_bytes(), cx)?;
        let gate = match first {
            None => CredentialGate::FIRST,
            Some(first) => {
                let other_hosts = cx.easy().options().http.unrestricted_auth;
                CredentialGate::new(first, &peer, other_hosts)
            }
        };
        let credentials = request_credentials(cx, gate.trusted(), url, takes)?;
        return with_netrc(credentials, peer.name(), takes, cx).map(drop);
    }
    let credentials = request_credentials(cx, Some(Trusted::own_url()), url, takes)?;
    let host = match url.get(Part::Host, GetOptions::NONE) {
        Ok(host) => host,
        Err(UrlErrorKind::NoHost) => Vec::new(),
        Err(e) => return Err(url_error(e)),
    };
    with_netrc(credentials, &host, takes, cx).map(drop)
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

/// Each request lends its own: HTTP's and FTP's by their own answers;
/// the others' credentials are trusted as a first request's, and they
/// speak no HTTP.
impl SetupLend for ProtoState {
    fn trusted(&self) -> Option<Trusted> {
        match self {
            ProtoState::Http(r) => SetupLend::trusted(&**r),
            ProtoState::Ftp(r) => SetupLend::trusted(&**r),
            ProtoState::File(_)
            | ProtoState::Pop3(_)
            | ProtoState::Imap(_)
            | ProtoState::Smtp(_)
            | ProtoState::Ssh(_)
            | ProtoState::Ldap(_)
            | ProtoState::Dict(_)
            | ProtoState::Gopher(_)
            | ProtoState::Mqtt(_)
            | ProtoState::Telnet(_)
            | ProtoState::Tftp(_) => CredentialGate::FIRST.trusted(),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => {
                CredentialGate::FIRST.trusted()
            }
        }
    }

    fn pipeline(&mut self) -> &mut Pipeline {
        match self {
            ProtoState::Http(r) => SetupLend::pipeline(&mut **r),
            ProtoState::Ftp(r) => SetupLend::pipeline(&mut **r),
            ProtoState::File(r) => r.pipeline_mut(),
            ProtoState::Pop3(r) => r.pipeline_mut(),
            ProtoState::Imap(r) => r.pipeline_mut(),
            ProtoState::Smtp(r) => r.pipeline_mut(),
            ProtoState::Ssh(r) => r.pipeline_mut(),
            ProtoState::Ldap(r) => r.pipeline_mut(),
            ProtoState::Dict(r) => r.pipeline_mut(),
            ProtoState::Gopher(r) => r.pipeline_mut(),
            ProtoState::Mqtt(r) => r.pipeline_mut(),
            ProtoState::Telnet(r) => r.pipeline_mut(),
            ProtoState::Tftp(r) => r.pipeline_mut(),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(p) => p.pipeline_mut(),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Tcp => {
                unreachable!("no test protocol is set up through a tunnel")
            }
        }
    }

    fn negotiation(&self) -> Option<http::Negotiation> {
        match self {
            ProtoState::Http(r) => SetupLend::negotiation(&**r),
            ProtoState::Ftp(r) => SetupLend::negotiation(&**r),
            ProtoState::File(_)
            | ProtoState::Pop3(_)
            | ProtoState::Imap(_)
            | ProtoState::Smtp(_)
            | ProtoState::Ssh(_)
            | ProtoState::Ldap(_)
            | ProtoState::Dict(_)
            | ProtoState::Gopher(_)
            | ProtoState::Mqtt(_)
            | ProtoState::Telnet(_)
            | ProtoState::Tftp(_) => None,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => None,
        }
    }

    fn negotiation_mut(&mut self) -> Option<&mut http::Negotiation> {
        match self {
            ProtoState::Http(r) => SetupLend::negotiation_mut(&mut **r),
            ProtoState::Ftp(r) => SetupLend::negotiation_mut(&mut **r),
            ProtoState::File(_)
            | ProtoState::Pop3(_)
            | ProtoState::Imap(_)
            | ProtoState::Smtp(_)
            | ProtoState::Ssh(_)
            | ProtoState::Ldap(_)
            | ProtoState::Dict(_)
            | ProtoState::Gopher(_)
            | ProtoState::Mqtt(_)
            | ProtoState::Telnet(_)
            | ProtoState::Tftp(_) => None,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => None,
        }
    }
}

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
            b"file" => {
                netrc_unkept(url, before.first, cx)?;
                ProtoState::File(
                    curl_alloc::try_box(file::Request::open(url, cx)?)
                        .map_err(|_| ErrorKind::OutOfMemory)?,
                )
            }
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
            // A WebSocket is an HTTP/1.1 request until its 101.
            b"ws" => ProtoState::Http(
                curl_alloc::try_box(http::Request::websocket(url, false, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"wss" if cx.easy().libraries().tls.is_some() => ProtoState::Http(
                curl_alloc::try_box(http::Request::websocket(url, true, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            // RTSP is spoken through HTTP's request (`lib/rtsp.c`).
            b"rtsp" => ProtoState::Http(
                curl_alloc::try_box(http::Request::rtsp(url, before, cx)?)
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
            b"ftp" => ProtoState::Ftp(
                curl_alloc::try_box(ftp::Request::new(url, false, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"ftps" if cx.easy().libraries().tls.is_some() => ProtoState::Ftp(
                curl_alloc::try_box(ftp::Request::new(url, true, before, cx)?)
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
            // With an LDAP library, as in C built with OpenLDAP.
            b"ldap" if cx.easy().libraries().ldap.is_some() => ProtoState::Ldap(
                curl_alloc::try_box(ldap::Request::new(url, false, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"ldaps"
                if cx.easy().libraries().ldap.is_some() && cx.easy().libraries().tls.is_some() =>
            {
                ProtoState::Ldap(
                    curl_alloc::try_box(ldap::Request::new(url, true, before, cx)?)
                        .map_err(|_| ErrorKind::OutOfMemory)?,
                )
            }
            // With an SSH library, as in C built with libssh.
            b"scp" if cx.easy().libraries().ssh.is_some() => ProtoState::Ssh(
                curl_alloc::try_box(ssh::Request::new(url, false, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"sftp" if cx.easy().libraries().ssh.is_some() => ProtoState::Ssh(
                curl_alloc::try_box(ssh::Request::new(url, true, before, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"dict" => {
                netrc_unkept(url, before.first, cx)?;
                ProtoState::Dict(
                    curl_alloc::try_box(dict::Request::new(url, cx)?)
                        .map_err(|_| ErrorKind::OutOfMemory)?,
                )
            }
            b"gopher" => {
                netrc_unkept(url, before.first, cx)?;
                ProtoState::Gopher(
                    curl_alloc::try_box(gopher::Request::new(url, false, cx)?)
                        .map_err(|_| ErrorKind::OutOfMemory)?,
                )
            }
            b"gophers" if cx.easy().libraries().tls.is_some() => {
                netrc_unkept(url, before.first, cx)?;
                ProtoState::Gopher(
                    curl_alloc::try_box(gopher::Request::new(url, true, cx)?)
                        .map_err(|_| ErrorKind::OutOfMemory)?,
                )
            }
            b"mqtt" => ProtoState::Mqtt(
                curl_alloc::try_box(mqtt::Request::new(url, false, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"mqtts" if cx.easy().libraries().tls.is_some() => ProtoState::Mqtt(
                curl_alloc::try_box(mqtt::Request::new(url, true, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"telnet" => ProtoState::Telnet(
                curl_alloc::try_box(telnet::Request::new(url, cx)?)
                    .map_err(|_| ErrorKind::OutOfMemory)?,
            ),
            b"tftp" => {
                netrc_unkept(url, before.first, cx)?;
                ProtoState::Tftp(
                    curl_alloc::try_box(tftp::Request::new(url, cx)?)
                        .map_err(|_| ErrorKind::OutOfMemory)?,
                )
            }
            #[cfg(any(test, feature = "test-util"))]
            b"null" => {
                netrc_unkept(url, before.first, cx)?;
                ProtoState::Null
            }
            #[cfg(any(test, feature = "test-util"))]
            b"stall" => {
                netrc_unkept(url, before.first, cx)?;
                ProtoState::Stall
            }
            #[cfg(any(test, feature = "test-util"))]
            b"script" => {
                netrc_unkept(url, before.first, cx)?;
                ProtoState::Script(
                    curl_alloc::try_box(script::Player::default())
                        .map_err(|_| ErrorKind::OutOfMemory)?,
                )
            }
            #[cfg(any(test, feature = "test-util"))]
            b"tcp" => {
                netrc_unkept(url, before.first, cx)?;
                ProtoState::Tcp
            }
            _ => return Ok(None),
        }))
    }

    /// What the protocol says of its setup for the connection, once the
    /// transfer is out of the queue (`setup_connection`, which C calls
    /// as it makes the connection to look for, after POSTQUEUE): only
    /// SMTP says anything.
    pub(crate) fn set_up_said<H: Host>(&self, cx: &mut StepCx<'_, H>) {
        match self {
            ProtoState::Smtp(_) => smtp::Request::set_up_said(cx),
            ProtoState::Ftp(_) => ftp::Request::set_up_said(cx),
            ProtoState::Ssh(r) => r.set_up_said(cx),
            ProtoState::File(_)
            | ProtoState::Http(_)
            | ProtoState::Pop3(_)
            | ProtoState::Imap(_)
            | ProtoState::Ldap(_)
            | ProtoState::Dict(_)
            | ProtoState::Gopher(_)
            | ProtoState::Mqtt(_)
            | ProtoState::Telnet(_)
            | ProtoState::Tftp(_) => {}
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => {}
        }
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
            ProtoState::Ftp(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Pop3(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Imap(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Smtp(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Ssh(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Ldap(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Dict(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Gopher(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Mqtt(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Telnet(ref r) => Ok(Some(r.network(url, scope, idn)?)),
            ProtoState::Tftp(ref r) => Ok(Some(r.network(url, scope, idn)?)),
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
            ProtoState::Ftp(r) => Some(r.scheme()),
            ProtoState::Pop3(r) => Some(r.scheme()),
            ProtoState::Imap(r) => Some(r.scheme()),
            ProtoState::Smtp(r) => Some(r.scheme()),
            ProtoState::Ssh(r) => Some(r.scheme()),
            ProtoState::Ldap(r) => Some(r.scheme()),
            ProtoState::Dict(r) => Some(r.scheme()),
            ProtoState::Gopher(r) => Some(r.scheme()),
            ProtoState::Mqtt(r) => Some(r.scheme()),
            ProtoState::Telnet(r) => Some(r.scheme()),
            ProtoState::Tftp(r) => Some(r.scheme()),
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
    /// The request is one of `wildcard`'s, if it is FTP's: the only
    /// protocol whose URL may be a pattern (C's `PROTOPT_WILDCARD`).
    /// Another is made as if the transfer were not a wildcard download,
    /// which it keeps.
    pub(crate) fn give_wildcard(&mut self, wildcard: &mut Option<Box<ftp::Wildcard>>) {
        if let ProtoState::Ftp(r) = self
            && let Some(w) = wildcard.take()
        {
            r.give_wildcard(w);
        }
    }

    /// The wildcard download the request was one of, back as it is over.
    pub(crate) fn take_wildcard(&mut self) -> Option<Box<ftp::Wildcard>> {
        match self {
            ProtoState::Ftp(r) => r.take_wildcard(),
            _ => None,
        }
    }

    /// The credentials a connection made for the request logs in with
    /// once and is matched by; RTSP's request authenticates with them
    /// too, so they are copied.
    pub(crate) fn take_login(&mut self) -> Result<Option<Credentials>, curl_alloc::OutOfMemory> {
        Ok(match self {
            ProtoState::Ftp(r) => r.take_login(),
            ProtoState::Pop3(r) => r.take_login(),
            ProtoState::Imap(r) => r.take_login(),
            ProtoState::Smtp(r) => r.take_login(),
            ProtoState::Ssh(r) => r.take_login(),
            ProtoState::Ldap(r) => r.take_login(),
            ProtoState::Http(r) => r.rtsp_login()?,
            _ => None,
        })
    }

    /// The key files an SSH connection made for the request logs in
    /// with, taken from it for the route.
    pub(crate) fn take_ssh_keys(&mut self) -> Option<ssh::Keys> {
        match self {
            ProtoState::Ssh(r) => r.take_keys(),
            _ => None,
        }
    }

    /// The request goes over TLS (C's `PROTOPT_SSL`).
    pub(crate) fn secured(&self) -> bool {
        match self {
            ProtoState::Http(r) => r.secured(),
            ProtoState::Ftp(r) => r.secured(),
            ProtoState::Pop3(r) => r.secured(),
            ProtoState::Imap(r) => r.secured(),
            ProtoState::Smtp(r) => r.secured(),
            ProtoState::Gopher(r) => r.secured(),
            ProtoState::Mqtt(r) => r.secured(),
            ProtoState::Ldap(r) => r.secured(),
            _ => false,
        }
    }

    /// The request goes whole to a proxy that sends it on to `url`, an
    /// FTP URL's type code `ftp_type` added if asked for.
    pub(crate) fn forward(&mut self, url: &Url, ftp_type: Option<u8>) -> Result<(), ErrorKind> {
        match *self {
            ProtoState::Http(ref mut r) => r.forward(url, ftp_type),
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
            ProtoState::Ftp(ref mut r) => r.connect(cx, lease),
            ProtoState::Pop3(ref mut r) => r.connect(cx, lease),
            ProtoState::Imap(ref mut r) => r.connect(cx, lease),
            ProtoState::Smtp(ref mut r) => r.connect(cx, lease),
            ProtoState::Ssh(ref mut r) => r.connect(cx, lease),
            ProtoState::Ldap(ref mut r) => r.connect(cx, lease),
            ProtoState::Dict(ref mut r) => r.connect(cx, lease),
            ProtoState::Gopher(ref mut r) => r.connect(cx, lease),
            ProtoState::Mqtt(ref mut r) => r.connect(cx, lease),
            ProtoState::Telnet(ref mut r) => r.connect(cx, lease),
            ProtoState::Tftp(ref mut r) => r.connect(cx, lease),
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
            ProtoState::Ftp(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Pop3(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Imap(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Smtp(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Ssh(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Ldap(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Dict(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Gopher(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Mqtt(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Telnet(ref mut r) => r.make(cx, lease, asked),
            ProtoState::Tftp(ref mut r) => r.make(cx, lease, asked),
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
            ProtoState::Ftp(ref r) => r.waits(phase),
            ProtoState::Pop3(ref r) => r.waits(phase),
            ProtoState::Imap(ref r) => r.waits(phase),
            ProtoState::Smtp(ref r) => r.waits(phase),
            ProtoState::Ssh(ref r) => r.waits(phase),
            ProtoState::Ldap(ref r) => r.waits(phase),
            ProtoState::Dict(ref r) => r.waits(phase),
            ProtoState::Gopher(ref r) => r.waits(phase),
            ProtoState::Mqtt(ref r) => r.waits(phase),
            ProtoState::Telnet(ref r) => r.waits(phase),
            ProtoState::Tftp(ref r) => r.waits(phase),
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
            // Data to move over the second connection.
            ProtoState::Ftp(ref r) => r.exchanges(),
            // Its body to read or send.
            ProtoState::Ssh(ref r) => r.exchanges(),
            // The search's answer.
            ProtoState::Ldap(ref r) => r.exchanges(),
            // The answer, read from DO on.
            ProtoState::Dict(_) | ProtoState::Gopher(_) => true,
            // All of it is in DOING, as C sets nothing up to exchange.
            ProtoState::Mqtt(_) | ProtoState::Telnet(_) | ProtoState::Tftp(_) => false,
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
            ProtoState::File(_)
            | ProtoState::Pop3(_)
            | ProtoState::Mqtt(_)
            | ProtoState::Telnet(_)
            | ProtoState::Tftp(_)
            // Their requests go whole in DOING.
            | ProtoState::Dict(_)
            | ProtoState::Gopher(_)
            // Its search goes whole in DO.
            | ProtoState::Ldap(_) => false,
            ProtoState::Ftp(ref r) => r.sending(),
            ProtoState::Imap(ref r) => r.sending(),
            ProtoState::Smtp(ref r) => r.sending(),
            ProtoState::Http(ref r) => r.sending(),
            ProtoState::Ssh(ref r) => r.sending(),
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
            ProtoState::File(_)
            | ProtoState::Pop3(_)
            | ProtoState::Mqtt(_)
            | ProtoState::Telnet(_)
            | ProtoState::Tftp(_)
            // Their requests go whole in DOING.
            | ProtoState::Dict(_)
            | ProtoState::Gopher(_)
            // Its search goes whole in DO.
            | ProtoState::Ldap(_) => false,
            ProtoState::Ftp(ref r) => r.sending(),
            ProtoState::Imap(ref r) => r.sending(),
            ProtoState::Smtp(ref r) => r.sending(),
            ProtoState::Http(ref r) => r.sending(),
            ProtoState::Ssh(ref r) => r.sending(),
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

    /// The timer `due` is kept in before DONE: FTP's wait for the server
    /// to connect (`EXPIRE_FTP_ACCEPT`), HTTP's for a 100 otherwise.
    pub(crate) fn due_timer(&self) -> crate::multi::timers::TimerKind {
        match self {
            ProtoState::Ftp(_) => crate::multi::timers::TimerKind::FtpAccept,
            _ => crate::multi::timers::TimerKind::Proto,
        }
    }

    /// The request sends datagrams of its own, over a UDP socket that
    /// connects to no peer: TFTP's (`TRNSPRT_UDP`).
    pub(crate) fn sends_datagrams(&self) -> bool {
        matches!(self, ProtoState::Tftp(_))
    }

    /// The request's DOING runs out of time itself, with its own reason:
    /// TELNET's loop, which C runs within DO, where the multi does not
    /// look at the time.
    pub(crate) fn times_itself(&self) -> bool {
        matches!(self, ProtoState::Telnet(_))
    }

    /// When the request wants to look again whatever its socket says: an
    /// HTTP body's wait for a 100 running out, FTP's for the server to
    /// connect, or a line protocol's poll in DONE as it awaits its answer.
    pub(crate) fn due(&self) -> Option<crate::time::Instant> {
        match self {
            ProtoState::Http(r) => r.due(),
            ProtoState::Imap(r) => r.due(),
            ProtoState::Smtp(r) => r.due(),
            ProtoState::Ftp(r) => r.due(),
            ProtoState::Telnet(r) => r.due(),
            ProtoState::Tftp(r) => r.due(),
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
            | ProtoState::Ftp(_)
            | ProtoState::Pop3(_)
            | ProtoState::Imap(_)
            | ProtoState::Smtp(_)
            | ProtoState::Ssh(_)
            | ProtoState::Ldap(_)
            | ProtoState::Dict(_)
            | ProtoState::Gopher(_)
            | ProtoState::Mqtt(_)
            | ProtoState::Telnet(_)
            | ProtoState::Tftp(_) => Ok(()),
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
            ProtoState::Ftp(ref r) => r.holds_output(),
            ProtoState::Pop3(ref r) => r.holds_output(),
            ProtoState::Imap(ref r) => r.holds_output(),
            ProtoState::Smtp(ref r) => r.holds_output(),
            ProtoState::Ssh(ref r) => r.holds_output(),
            ProtoState::Ldap(ref r) => r.holds_output(),
            ProtoState::Dict(ref r) => r.holds_output(),
            ProtoState::Gopher(ref r) => r.holds_output(),
            ProtoState::Mqtt(ref r) => r.holds_output(),
            ProtoState::Telnet(ref r) => r.holds_output(),
            ProtoState::Tftp(ref r) => r.holds_output(),
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
            ProtoState::Ftp(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Pop3(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Imap(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Smtp(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Ssh(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Ldap(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Dict(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Gopher(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Mqtt(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Telnet(ref mut r) => Some(r.pipeline_mut()),
            ProtoState::Tftp(ref mut r) => Some(r.pipeline_mut()),
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
            ProtoState::Ftp(ref mut r) => r.step(cx, lease),
            ProtoState::Pop3(ref mut r) => r.step(cx, lease),
            ProtoState::Imap(ref mut r) => r.step(cx, lease),
            ProtoState::Smtp(ref mut r) => r.step(cx, lease),
            ProtoState::Ssh(ref mut r) => r.step(cx, lease),
            ProtoState::Ldap(ref mut r) => r.step(cx, lease),
            ProtoState::Dict(ref mut r) => r.step(cx, lease),
            ProtoState::Gopher(ref mut r) => r.step(cx, lease),
            ProtoState::Mqtt(ref mut r) => Ok(r.step()),
            ProtoState::Telnet(ref mut r) => Ok(r.step()),
            ProtoState::Tftp(ref mut r) => Ok(r.step()),
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
            ProtoState::Ftp(ref r) => r.interest(pause),
            ProtoState::Pop3(ref r) => r.interest(pause),
            ProtoState::Imap(ref r) => r.interest(pause),
            ProtoState::Smtp(ref r) => r.interest(pause),
            ProtoState::Ssh(ref r) => r.interest(pause),
            ProtoState::Ldap(ref r) => r.interest(pause),
            ProtoState::Dict(ref r) => r.interest(pause),
            ProtoState::Gopher(ref r) => r.interest(pause),
            // MQTT's, TELNET's and TFTP's exchanges are over once their DO
            // is.
            ProtoState::File(_)
            | ProtoState::Mqtt(_)
            | ProtoState::Telnet(_)
            | ProtoState::Tftp(_) => Events::NONE,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => {
                Events::NONE
            }
        }
    }

    /// What the protocol traces of its pollset as it makes it, while it
    /// connects or is made or, once `made`, as its body moves: SSH's
    /// (`Curl_ssh_pollset`).
    pub(crate) fn pollset_said(&self, made: bool) -> Option<Events> {
        match self {
            ProtoState::Ssh(r) => r.pollset_said(made),
            _ => None,
        }
    }

    /// What the made request waits for on a second connection beside its
    /// own: FTP's data.
    pub(crate) fn side_interest(&self, pause: Pause) -> Events {
        match *self {
            ProtoState::Ftp(ref r) => r.data_wants(pause, true),
            _ => Events::NONE,
        }
    }

    /// The sockets of the second connection the request has open beside
    /// its own, FTP's data, and what each waits for, the request wanting
    /// `wanted` of it.
    pub(crate) fn side_pollset(
        &self,
        wanted: Events,
    ) -> impl Iterator<Item = (&dyn crate::conn::io::Socket, Events)> {
        let ftp = match self {
            ProtoState::Ftp(r) => Some(r.data_pollset(wanted)),
            _ => None,
        };
        ftp.into_iter().flatten()
    }

    /// Whether the request may be made again on a fresh connection, its
    /// reused one having died (`Curl_retry_request`): it got nothing
    /// back, and its protocol answers every request, as HTTP does, or it
    /// waits for a body it has not had and uploads nothing (`uploads`,
    /// `state.upload`). `ended` says the request ended, as a close ends
    /// it (`req.done`).
    pub(crate) fn retryable(&self, ended: bool, uploads: bool) -> bool {
        match *self {
            ProtoState::Http(ref r) => r.received_nothing(ended),
            _ if ended || uploads => false,
            ProtoState::Ftp(ref r) => r.received_nothing(),
            ProtoState::Pop3(ref r) => r.received_nothing(),
            ProtoState::Imap(ref r) => r.received_nothing(),
            ProtoState::Smtp(ref r) => r.received_nothing(),
            ProtoState::Ssh(ref r) => r.received_nothing(),
            // An answer read to the close, MQTT's, TELNET's or TFTP's,
            // leaves no connection to reuse, nor does LDAP's, whose
            // connections are not reused.
            ProtoState::File(_)
            | ProtoState::Ldap(_)
            | ProtoState::Dict(_)
            | ProtoState::Gopher(_)
            | ProtoState::Mqtt(_)
            | ProtoState::Telnet(_)
            | ProtoState::Tftp(_) => false,
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
            ProtoState::Ftp(ref mut r) => r.done(cx, lease, result, premature, exchanged),
            ProtoState::Pop3(ref mut r) => Finish::Done(r.done(cx, lease, result)),
            ProtoState::Imap(ref mut r) => r.done(cx, lease, result, premature, exchanged),
            ProtoState::Smtp(ref mut r) => r.done(cx, lease, result, premature, exchanged),
            ProtoState::Ssh(ref mut r) => r.done(cx, lease, result, premature, next, exchanged),
            ProtoState::Ldap(ref mut r) => r.done(cx, lease, result),
            ProtoState::File(_)
            | ProtoState::Dict(_)
            | ProtoState::Gopher(_)
            | ProtoState::Mqtt(_)
            | ProtoState::Telnet(_) => Finish::Done(result),
            // Its exchange's error, if it ended badly and nothing failed
            // before (`tftp_done`).
            ProtoState::Tftp(ref r) => Finish::Done(result.and(r.failed())),
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
            ProtoState::Ftp(ref mut r) => r.finishing(cx, lease, exchanged),
            ProtoState::Ssh(ref mut r) => r.finishing(cx, lease, exchanged),
            _ => unreachable!("only FTP, IMAP, SMTP and SSH wait as their request ends"),
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
