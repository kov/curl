//! `http:`, HTTP/1 over a connection: the request head sent at DO, the
//! response read, parsed and delivered, and its end judged (`lib/http.c`'s
//! `Curl_http`, `Curl_http_write_resp` and `Curl_http_done`, and
//! `lib/transfer.c`'s receive loop).

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use crate::coding::{AcceptEncoding, Coding, Decoder, Decoders, Identity, Named, Unrecognized};
use crate::components::Component;
use crate::conn::io::{Events, Recv, Sent};
use crate::conn::{ConnLease, Peer, ProxyCreds, RecvFailed, Scheme, Tcp};
use crate::date::{HttpDate, OutOfRange};
use crate::deliver::{self, Expect, Pause, Pipeline, Reach, WriteType};
use crate::error::{ErrorKind, UrlErrorKind, url_error};
use crate::handler::{DebugKind, HeaderOrigin, TrailerLines, Trailers};
use crate::idn::Idn;
use crate::libraries::Ed25519;
use crate::mime::read::MakeError;
use crate::multi::Host;
use crate::multi::TransferCx;
use crate::multi::mstate::MState;
use crate::multi::state;
use crate::multi::state::{AfterRequest, StepCx};
use crate::multi::timers::TimerKind;
use crate::options::{Follow, Http, HttpVersion, Method, Ranged, UploadSource};
use crate::progress::rate::Way;
use crate::report::{ResponseVersion, Timer};
use crate::time::Instant;
use crate::trace;
use crate::trace::OsError;
use crate::upload::chain;
use crate::upload::{self, Upload};
use crate::url::{GetOptions, Part, SetOptions, Url};

use super::http1::auth::{
    AuthAct, AuthRequest, Credentials, CredentialsError, Offered, Output, OutputError, Secret, Side,
};
use super::http1::chunked::{ChunkDecoder, ChunkError, ChunkEvent};
use super::http1::fields;
use super::http1::follow::{self, Inherited};
use super::http1::framing::{self, Asked, CodingStep, CodingTale, Framing, Left, Unsent};
use super::http1::request::{
    self, Accepted, Authorization, Conditional, CredentialGate, Forwarding, RangeLine, RequestHead,
    SentIn, Typed,
};
use super::{Before, Ended, ProtoStep};
use crate::options::AuthMethods;
use std::num::{NonZeroU32, NonZeroUsize};

pub(crate) mod alt_svc;
pub(crate) mod cookies;
mod h2;
pub(crate) mod hsts;
pub(crate) mod httpsig;
pub(crate) mod negotiate;
pub(crate) mod sigv4;
use super::http1::response::{self, Exchange, HeadError, HeadEvent, HeadParser, LineKind};

/// The most reads one step makes (`sendrecv_dl`: the first and
/// `maxloops`' ten more), so a peer that sends faster than it is read
/// cannot keep the step from returning.
const MAX_READS: usize = 11;

/// A body larger than this asks `Expect: 100-continue` on HTTP/1.1.
const EXPECT_100_THRESHOLD: u64 = 1024 * 1024;

/// What a request's body is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyKind {
    /// A POST's, a form by default (`HTTPREQ_POST`).
    Form,
    /// A POST's multipart body (`HTTPREQ_POST_MIME`).
    Mime,
    /// A PUT's.
    Put,
}

/// HTTP, as the connection layer knows it, and HTTP over TLS.
const HTTP: Scheme = Scheme {
    name: "http",
    reuse: true,
};
pub(crate) const HTTPS: Scheme = Scheme {
    name: "https",
    reuse: true,
};

/// The HTTP versions a request may speak (`CURL_HTTP_V1x`, `CURL_HTTP_V2x`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Versions {
    pub(crate) h1: bool,
    pub(crate) h2: bool,
}

impl Versions {
    pub(crate) const ALL: Versions = Versions { h1: true, h2: true };
}

/// What a final response's challenges offered and led to, its code, and
/// the origin the request authenticated with.
struct Challenged<'r> {
    offered: Offered,
    act: AuthAct,
    code: u16,
    origin: &'r Peer,
}

/// Digest's client nonce.
fn random(bytes: &mut [u8; 12]) -> Result<(), ()> {
    curl_os::random::fill(bytes).map_err(|_| ())
}

/// That `side` authenticates with `used`, as the user of `secret`, if
/// it uses a method (`output_auth_headers`).
fn auth_trace<H: Host>(
    cx: &mut StepCx<'_, H>,
    side: &str,
    used: AuthMethods,
    secret: Option<Secret<'_>>,
) {
    if !used.is_empty() {
        let user = secret.map_or(&b""[..], |s| s.user());
        let name = used.name().as_bytes();
        trace::info_with(
            cx,
            &[
                side.as_bytes(),
                b" auth using ",
                name,
                b" with user '",
                user,
                b"'",
            ],
        );
    }
}

/// `host`, and `:port` if there is one.
fn with_port(out: &mut Vec<u8>, host: &[u8], port: Option<u16>) -> Result<(), OutOfMemory> {
    out.try_extend_from_slice(host)?;
    if let Some(port) = port {
        let mut digits = [0u8; 20];
        out.try_push(b':')?;
        out.try_extend_from_slice(request::decimal(u64::from(port), &mut digits))?;
    }
    Ok(())
}

fn made(output: Result<Output, OutputError>) -> Result<Output, ErrorKind> {
    output.map_err(|e| match e {
        OutputError::OutOfMemory => ErrorKind::OutOfMemory,
        OutputError::Random => ErrorKind::FailedInit,
    })
}

/// An HTTP request and its response.
#[derive(Debug)]
pub(crate) struct Request {
    pipeline: Pipeline,
    /// The path and query the request asks for.
    target: Vec<u8>,
    /// The whole URL, the request's target when a proxy it goes to sends
    /// it on (`http_target`).
    forward_target: Option<Vec<u8>>,
    /// The alternative service the connection goes to, `host:port` with
    /// an IPv6 address bare, which `Alt-Used:` names (`altused`).
    alt_used: Option<Vec<u8>>,
    /// What the URL says to authenticate with.
    credentials: Option<Credentials>,
    /// The scheme, the host as the URL names it, and the port the
    /// request goes to.
    peer: Peer,
    /// What of the application's may go to the request's origin.
    gate: CredentialGate,
    /// The method, as the requests before it left it.
    method: Method,
    /// The application's custom method is sent in its place.
    custom: bool,
    /// The HTTP version sent, once the connection is known.
    version: SentIn,
    /// An earlier response to the transfer said HTTP/1.0
    /// (`state.http_neg.rcvd_min`).
    after_http10: bool,
    /// The library adds no `Expect: 100-continue`.
    no_expect: bool,
    /// A 417 refused the `Expect: 100-continue` sent.
    expect_refused: bool,
    /// The connection is not used again (`streamclose`).
    closing: bool,
    /// What the request sends and has not yet (`req.sendbuf`): the head,
    /// then the body as read, behind it in one buffer of
    /// `CURLOPT_UPLOAD_BUFFERSIZE` bytes. `out[sent..filled]` is still to go, the
    /// first of it the head's while `outgoing` is `Sending::Head`.
    out: Vec<u8>,
    filled: usize,
    sent: usize,
    /// The body, read at DO and as what is read goes, through its
    /// stages: chunked, framed as it is read.
    body: Option<chain::Body>,
    /// Body bytes sent (`writebytecount`).
    body_sent: u64,
    /// The body has been read from, or would have been but for a wait:
    /// the send limit started over then (`reader_started`).
    read_started: bool,
    /// Where sending the request stands.
    outgoing: Sending,
    /// Made at DO, once the connection says whether it is reused.
    head: Option<HeadParser>,
    stage: Stage,
    /// The current response is interim (1xx).
    interim: bool,
    /// The name a custom `Host:` header gives the cookies, in place of
    /// the URL's host.
    cookie_host: Option<Vec<u8>>,
    /// The request's stream, over a connection that speaks HTTP/2.
    h2: Option<h2::H2Stream>,
    /// It went on a stream HTTP/2 refused (`state.refused_stream`).
    refused: bool,
    /// It asks to go on in HTTP/2 over clear text, with these settings
    /// (`upgr101 == UPGR101_H2`), which a 101 takes up; until its answer
    /// (`bits.upgrade_in_progress`).
    upgrade: Option<Vec<u8>>,
    /// A request before it was told HTTP/1.1 is required: it speaks
    /// HTTP/1 only.
    h1_only: bool,
}

#[derive(Debug)]
enum Stage {
    Head,
    Body(Body),
    Done,
}

/// Where sending a request stands: C's `req.sendbuf_hds_len`,
/// `eos_read`, `upload_done` and `upload_aborted`, and its `cr_exp100`
/// reader's state, as one. The buffer the head and the body go from is
/// the request's, beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sending {
    /// Nothing yet: the request is not made (before DO).
    Idle,
    /// The head goes, `left` bytes of it still to, ahead of anything
    /// else in the buffer; `then` is what follows it.
    Head { left: NonZeroUsize, then: AfterHead },
    /// The head has gone, its body announced with `Expect:
    /// 100-continue`: the wait for the 100 starts as the body is next
    /// asked for (`EXP100_SENDING_REQUEST`, the request all sent).
    HeadSent,
    /// The head has gone; the body, announced with `Expect:
    /// 100-continue` and not read yet, waits for a 100 until this
    /// instant (`EXP100_AWAITING_CONTINUE`).
    AwaitingContinue(Instant),
    /// The body goes, read as what is read of it goes.
    Body(Reading),
    /// All of it went (`upload_done`), or the response ended the request
    /// with its head.
    Done,
    /// Sending stopped short of the body's end (`upload_aborted`).
    Aborted,
}

/// What follows the head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterHead {
    /// The body, announced with `Expect: 100-continue`, waits for a 100
    /// once the head has gone (`EXP100_SENDING_REQUEST`); none of it is
    /// read behind the head.
    Continue,
    /// The body, as far as it is read behind the head.
    Body(Reading),
}

/// Why a body announced with `Expect: 100-continue` is held back as its
/// readers are asked (`cr_exp100_read`'s states).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// The head has not all gone.
    Unsent,
    /// The head has gone: the wait starts.
    Starts,
    /// The wait has not run out.
    Waits,
}

/// A body being read and sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reading {
    /// All of it is in the buffer (`eos_read`): nothing more is read.
    eos_read: bool,
    /// The head said `Expect: 100-continue`, and the 100 came, the wait
    /// ran out or an error response let the body go on
    /// (`http_exp100_is_selected`).
    announced: bool,
}

impl Sending {
    /// The body as read so far, if it is read now.
    fn reading_mut(&mut self) -> Option<&mut Reading> {
        match self {
            Sending::Head {
                then: AfterHead::Body(reading),
                ..
            }
            | Sending::Body(reading) => Some(reading),
            _ => None,
        }
    }

    /// The head said `Expect: 100-continue`.
    fn announced(&self) -> bool {
        match self {
            Sending::Head {
                then: AfterHead::Continue,
                ..
            }
            | Sending::HeadSent
            | Sending::AwaitingContinue(_) => true,
            Sending::Head {
                then: AfterHead::Body(reading),
                ..
            }
            | Sending::Body(reading) => reading.announced,
            Sending::Idle | Sending::Done | Sending::Aborted => false,
        }
    }
}

/// How a step's reading ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Read {
    /// A read would block, the response is over, receiving paused or
    /// the receive limit spent: the step is not run again before its
    /// socket or its timer says.
    Waits,
    /// The step read its most, or a read would block with bytes held
    /// where a poll cannot see them: more is there, or may be already.
    Stopped,
}

/// How the body ends.
#[derive(Debug)]
enum Body {
    /// At the size the head gave.
    Length,
    /// At the last chunk.
    Chunked(ChunkDecoder),
    /// When the connection closes.
    UntilClose,
    /// When the HTTP/2 stream closes.
    Stream,
}

impl Request {
    /// The HTTP versions it may speak (`http_neg.allowed`): the
    /// application's, or HTTP/1 alone once HTTP/1.1 was required.
    pub(crate) fn versions(&self, wanted: HttpVersion) -> Versions {
        if self.h1_only {
            Versions {
                h1: true,
                h2: false,
            }
        } else {
            Versions {
                h1: wanted.h1(),
                h2: wanted.h2(),
            }
        }
    }

    /// Whether the request has found what its connection speaks, short
    /// of an upgrade not yet answered: made at DO, which finds it, and
    /// no upgrade pending (`url_match_fully_connected`).
    pub(crate) fn settled_conn(&self) -> bool {
        self.head.is_some() && self.upgrade.is_none()
    }

    /// It went on a stream HTTP/2 refused, which may be made again: said
    /// once.
    pub(crate) fn take_refused(&mut self) -> bool {
        std::mem::take(&mut self.refused)
    }

    /// Credentials may go to the request's origin.
    pub(crate) fn trusted(&self) -> Option<request::Trusted> {
        self.gate.trusted()
    }

    /// A request for `url`, whose scheme is `http`, or `https` if
    /// `secured`, after the transfer's earlier ones left it `before`.
    pub(crate) fn new<H: Host>(
        url: &Url,
        secured: bool,
        before: Before<'_>,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Request, ErrorKind> {
        let host = url.get(Part::Host, GetOptions::NONE).map_err(url_error)?;
        let port = url
            .get(
                Part::Port,
                GetOptions {
                    default_port: true,
                    ..GetOptions::NONE
                },
            )
            .map_err(url_error)?;
        let port = std::str::from_utf8(&port)
            .ok()
            .and_then(|p| p.parse().ok())
            .ok_or(ErrorKind::UrlMalformat)?;
        // The path goes out encoded, the query as it was given, as C reads
        // them for `state.up` (`CURLU_URLENCODE` on the path alone).
        let encoded = GetOptions {
            url_encode: true,
            ..GetOptions::NONE
        };
        let mut target = url.get(Part::Path, encoded).map_err(url_error)?;
        // An empty query keeps its `?`, as C asks with `CURLU_GET_EMPTY`.
        let query = GetOptions {
            get_empty: true,
            ..GetOptions::NONE
        };
        match url.get(Part::Query, query) {
            Ok(query) => {
                target.try_push(b'?').map_err(|_| ErrorKind::OutOfMemory)?;
                target
                    .try_extend_from_slice(&query)
                    .map_err(|_| ErrorKind::OutOfMemory)?;
            }
            Err(UrlErrorKind::NoQuery) => {}
            Err(e) => return Err(url_error(e)),
        }
        let scope = cx.easy().options().address_scope;
        let scheme = if secured { HTTPS } else { HTTP };
        let idn = cx.easy().libraries().idn;
        let peer = super::url_peer((scheme, host, port), url, scope, idn)?;
        let gate = match before.first {
            None => CredentialGate::FIRST,
            Some(first) => {
                let other_hosts = cx.easy().options().http.unrestricted_auth;
                CredentialGate::new(first, &peer, other_hosts)
            }
        };
        let login = &cx.easy().options().login;
        let credentials = match Credentials::for_request(login, gate.trusted(), url) {
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
        // By the host's name: an IPv6 address without its brackets, a name
        // in Unicode in its ASCII form (`Curl_netrc_scan` of `hostname`).
        let credentials = super::with_netrc(credentials, peer.name(), cx)?;
        Ok(Request {
            pipeline: Pipeline::new(Reach::Network),
            target,
            forward_target: None,
            alt_used: None,
            credentials,
            peer,
            gate,
            method: before.method,
            custom: !before.http.ignore_custom,
            no_expect: before.http.no_expect,
            expect_refused: false,
            closing: false,
            version: SentIn::Http11,
            after_http10: before.http.http10,
            out: Vec::new(),
            filled: 0,
            sent: 0,
            body: None,
            body_sent: 0,
            read_started: false,
            outgoing: Sending::Idle,
            head: None,
            stage: Stage::Head,
            interim: false,
            cookie_host: None,
            h2: None,
            refused: false,
            upgrade: None,
            h1_only: before.http.h1_only,
        })
    }

    /// Send the request whole to a proxy that sends it on: its target is
    /// `url` without its fragment and credentials, nor its scheme's port,
    /// and with a host it names in Unicode in its ASCII form
    /// (`http_target`).
    pub(crate) fn forward(&mut self, url: &Url) -> Result<(), ErrorKind> {
        let mut url = url.try_clone().map_err(url_error)?;
        for part in [Part::Fragment, Part::User, Part::Password] {
            url.set(part, None, SetOptions::NONE).map_err(url_error)?;
        }
        if self.peer.converted() {
            let host = Some(self.peer.name());
            url.set(Part::Host, host, SetOptions::NONE)
                .map_err(url_error)?;
        }
        let get = GetOptions {
            no_default_port: true,
            ..GetOptions::NONE
        };
        self.forward_target = Some(url.get(Part::Url, get).map_err(url_error)?);
        Ok(())
    }

    /// The connection goes to `via`, an alternative service of the
    /// origin's, which the request names (`H1_HD_ALT_USED`).
    pub(crate) fn alt_used(&mut self, via: &Peer) -> Result<(), OutOfMemory> {
        let mut used = Vec::new();
        let mut digits = [0u8; 20];
        for part in [
            via.name(),
            b":",
            crate::proto::http1::request::decimal(u64::from(via.port()), &mut digits),
        ] {
            used.try_extend_from_slice(part)?;
        }
        self.alt_used = Some(used);
        Ok(())
    }

    /// The peer the request connects to: its origin, in the IPv6 scope
    /// `scope` if the application sets one.
    pub(crate) fn network(
        &self,
        url: &Url,
        scope: Option<NonZeroU32>,
        idn: Option<&dyn Idn>,
    ) -> Result<Peer, ErrorKind> {
        let mut host = Vec::new();
        host.try_extend_from_slice(self.peer.shown())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let (scheme, port) = (self.peer.scheme(), self.peer.port());
        super::url_peer((scheme, host, port), url, scope, idn)
    }

    /// It goes over TLS: its scheme is `https` (C's `PROTOPT_SSL`).
    pub(crate) fn secured(&self) -> bool {
        self.peer.scheme() == HTTPS
    }

    /// The port its scheme means when a URL names none, which `Host:`
    /// and the signatures leave out.
    fn default_port(&self) -> u16 {
        if self.secured() { 443 } else { 80 }
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    /// Where the response's `Location:` points, as the server gave it.
    fn location(&self) -> Option<&[u8]> {
        self.head.as_ref()?.meta().location()
    }

    /// Where the response redirects to, if it is followed, and its code.
    fn follow(&self) -> Option<(&[u8], u16)> {
        let head = self.head.as_ref()?;
        Some((head.meta().follow()?, head.status()?.code))
    }

    /// What the final response's challenges offered and led to; the
    /// challenges are taken out, for the handle to keep.
    fn auth(&mut self) -> Option<Challenged<'_>> {
        let head = self.head.as_mut()?;
        let code = head.status()?.code;
        let act = *head.meta().auth();
        Some(Challenged {
            offered: head.meta_mut().take_challenges(),
            act,
            code,
            origin: &self.peer,
        })
    }

    /// What the complete exchange leads to, decided at its end: a 417 to
    /// an `Expect: 100-continue` or a challenge the request can answer
    /// has it made again, as a redirect to `url`, its own; a redirect
    /// followed is followed; a `Location:` not followed is left for the
    /// engine to keep (C's `req.newurl` and `req.location`, which
    /// `http_on_response` and `Curl_http_auth_act` set as the head
    /// ends). The challenges go to the handle and the report: the
    /// origin's kept for the request's origin, the proxy's for `proxy`,
    /// the connection's peer, which is the proxy's when the request goes
    /// to it whole.
    pub(crate) fn exchanged<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        url: &[u8],
        proxy: Option<&Peer>,
        inherited: &mut Inherited,
    ) -> Result<Ended<'_>, ErrorKind> {
        // A 417 has the request made again without `Expect`, as a
        // redirect to its own URL.
        if self.expect_refused {
            inherited.no_expect = true;
            let mut location = Vec::new();
            location
                .try_extend_from_slice(url)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            return Ok(Ended::Then(AfterRequest::Follow {
                location,
                code: 417,
            }));
        }
        // A 401 or 407 whose challenge the request can answer has it made
        // again.
        if let Some(Challenged {
            offered,
            act,
            code,
            origin,
        }) = self.auth()
        {
            let report = cx.report_mut();
            report.add_auth_offered(offered.host.offered);
            report.add_proxy_auth_offered(offered.proxy.offered);
            if let Some(picked) = act.picked.filter(|p| !p.is_empty()) {
                report.set_auth_used(picked);
            }
            if let Some(picked) = act.proxy_picked.filter(|p| !p.is_empty()) {
                report.set_proxy_auth_used(picked);
            }
            let proxy = proxy.expect("an HTTP request has an origin");
            cx.easy_mut()
                .auth
                .apply(&act, offered, origin, proxy)
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
            if act.again() {
                let mut location = Vec::new();
                location
                    .try_extend_from_slice(url)
                    .map_err(|_| ErrorKind::OutOfMemory)?;
                return Ok(Ended::Then(AfterRequest::Follow { location, code }));
            }
        }
        if let Some((location, code)) = self.follow() {
            let mut copy = Vec::new();
            copy.try_extend_from_slice(location)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            return Ok(Ended::Then(AfterRequest::Follow {
                location: copy,
                code,
            }));
        }
        Ok(match self.location() {
            Some(location) => Ended::Unfollowed(location),
            None => Ended::Then(AfterRequest::Complete),
        })
    }

    /// The body is to be read again for the next request
    /// (`Curl_creader_set_rewind`).
    pub(crate) fn rewinds_upload(&self) -> bool {
        self.head.as_ref().is_some_and(|h| h.meta().rewinds())
    }

    /// Start the body over, for the next request to send it again.
    pub(crate) fn rewind_upload<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
    ) -> Result<(), ErrorKind> {
        match &mut self.body {
            Some(body) => body.upload_mut().rewind(cx),
            None => Ok(()),
        }
    }

    pub(crate) fn holds_output(&self) -> bool {
        self.pipeline.holds_output()
    }

    /// Whether the response so far is nothing at all: no head line and no
    /// body byte (C's `bytecount + headerbytecount`).
    pub(crate) fn received_nothing(&self) -> bool {
        self.head.as_ref().is_none_or(|h| h.request_bytes() == 0) && self.pipeline.bytecount() == 0
    }

    /// Whether some of the request is still to send, a body waiting for
    /// a 100 included (`Curl_req_want_send`).
    pub(crate) fn sending(&self) -> bool {
        !matches!(
            self.outgoing,
            Sending::Idle | Sending::Done | Sending::Aborted
        )
    }

    /// When a body waiting for a 100 is sent anyway.
    pub(crate) fn wake_at(&self) -> Option<Instant> {
        match self.outgoing {
            Sending::AwaitingContinue(until) => Some(until),
            _ => None,
        }
    }

    /// What the request waits for on its socket.
    pub(crate) fn interest(&self, pause: Pause) -> Events {
        let mut events = Events::NONE;
        if !matches!(self.stage, Stage::Done) && !pause.recv_paused() {
            events = events | Events::IN;
        }
        // A body waiting for a 100 waits on the clock, not the socket.
        let waiting = matches!(self.outgoing, Sending::AwaitingContinue(_));
        if self.sending() && !pause.send_paused() && !waiting {
            events = events | Events::OUT;
        }
        // What HTTP/2's session holds waits for the socket.
        if self.h2.as_ref().is_some_and(h2::H2Stream::out_pending) {
            events = events | Events::OUT;
        }
        events
    }

    /// The request signed with AWS SigV4, if it has credentials to sign
    /// with.
    fn sign_sigv4(
        &self,
        options: &crate::options::Options,
        method: &[u8],
        credentials: Option<Secret<'_>>,
        now: i64,
    ) -> Option<sigv4::Signing> {
        let credentials = credentials?;
        let (path, query) = match self.target.iter().position(|&b| b == b'?') {
            Some(q) => (&self.target[..q], Some(&self.target[q + 1..])),
            None => (&self.target[..], None),
        };
        let port = self.peer.port();
        let request = sigv4::Request {
            params: options.http.signing.aws_sigv4.as_deref(),
            method,
            kind: match self.method {
                Method::Get | Method::Head => sigv4::Kind::GetOrHead,
                Method::Post => sigv4::Kind::Post,
                Method::Upload => sigv4::Kind::Put,
            },
            hostname: self.peer.name(),
            host: self.peer.request_host(),
            port: (port != self.default_port()).then_some(port),
            path,
            query,
            headers: &options.http.headers,
            post_fields: match &options.upload {
                UploadSource::Bytes(bytes) => sigv4::PostFields::Bytes(bytes),
                UploadSource::Lent(lent) => sigv4::PostFields::Lent(&**lent),
                UploadSource::None | UploadSource::Read { .. } | UploadSource::Mime(_) => {
                    sigv4::PostFields::None
                }
            },
            empty_upload: matches!(options.upload, UploadSource::Read { size: Some(0), .. }),
            user: credentials.user(),
            password: credentials.password(),
            now,
        };
        Some(sigv4::sign(&request))
    }

    /// The request signed with an HTTP message signature, unless the
    /// application signs it itself (`Curl_output_httpsig`).
    fn sign_httpsig(
        &self,
        options: &crate::options::Options,
        method: &[u8],
        now: i64,
        ed25519: Option<&'static dyn Ed25519>,
    ) -> httpsig::Signing {
        let (path, query) = match self.target.iter().position(|&b| b == b'?') {
            Some(q) => (&self.target[..q], Some(&self.target[q + 1..])),
            None => (&self.target[..], None),
        };
        // `@authority` is what `Host` says: the application's, if it
        // gives one that says anything, else the library's
        // (`httpsig_authority`).
        let port = self.peer.port();
        let port = (port != self.default_port()).then_some(port);
        let mut authority = Vec::new();
        let custom = self
            .gate
            .same_origin()
            .and_then(|same| options.http.headers.host_value(same));
        let made = match custom {
            Some(value) if !value.is_empty() => authority.try_extend_from_slice(value),
            given => {
                // An empty one leaves the host's name, without an IPv6
                // address's brackets; else what the library's `Host:`
                // says.
                let host = if given.is_some() {
                    self.peer.name()
                } else {
                    self.peer.request_host()
                };
                with_port(&mut authority, host, port)
            }
        };
        if made.is_err() {
            return httpsig::Signing {
                notes: Vec::new(),
                result: Err(httpsig::SignError::OutOfMemory),
            };
        }
        httpsig::sign(&httpsig::Request {
            signature: &options.http.signing.message,
            method,
            authority: &authority,
            path: if path.is_empty() { b"/" } else { path },
            query,
            headers: &options.http.headers,
            now,
            ed25519,
        })
    }

    /// Negotiate's header for the origin, or for the proxy that forwards
    /// the request, made by the connection's context with it
    /// (`Curl_output_negotiate`); without a GSS-API library, none, as in
    /// a build without one.
    fn negotiate<H: Host>(
        &self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        side: Side,
        get_or_head: bool,
    ) -> Result<Output, ErrorKind> {
        let Some(gss) = cx.easy().libraries().gss else {
            cx.easy_mut().auth.side(side).finish();
            return Ok(Output {
                header: None,
                used: AuthMethods::NONE,
                probe: false,
                negotiate: false,
            });
        };
        let forwarding = lease
            .conn()
            .forwarding()
            .map(|p| (p.peer.clone(), p.creds.clone()));
        let (credentials, peer) = match (side, &forwarding) {
            (Side::Host, _) => (
                self.credentials.as_ref().map(Credentials::secret),
                &self.peer,
            ),
            (Side::Proxy, Some((peer, creds))) => {
                (creds.as_deref().map(ProxyCreds::secret), &**peer)
            }
            (Side::Proxy, None) => {
                unreachable!("only a proxy that forwards is negotiated with here")
            }
        };
        let delegation = cx.easy().options().login.delegation;
        let (kept, tls) = lease.get().negotiate_over();
        let request = negotiate::Request {
            gss,
            side,
            credentials,
            peer,
            delegation,
            tls,
        };
        let (header, done) = negotiate::output(cx, kept, &request)?;
        Ok(cx
            .easy_mut()
            .auth
            .side(side)
            .negotiated(header, done, get_or_head))
    }

    /// What the request brings to the search for a connection to reuse,
    /// wanting `want` of the origin (`want_nego_http`) and `proxy_want`
    /// of the HTTP proxy on `route`, which negotiates only with
    /// credentials for it (`want_proxy_nego_http`).
    pub(crate) fn reuse_wants(
        &self,
        want: AuthMethods,
        proxy_want: AuthMethods,
        route: &Tcp,
    ) -> negotiate::Wants<'_> {
        let proxy_creds = route
            .proxy
            .as_ref()
            .is_some_and(|p| p.http() && p.creds.is_some());
        negotiate::Wants {
            negotiate: want.contains(AuthMethods::NEGOTIATE) && self.gate.trusted().is_some(),
            credentials: self.credentials.as_ref().map(Credentials::secret),
            origin: Some(&self.peer),
            proxy: proxy_creds && proxy_want.contains(AuthMethods::NEGOTIATE),
        }
    }

    /// The method the request line names: the application's own, unless
    /// a follow dropped it.
    fn method_line<'o>(&self, http: &'o Http) -> &'o [u8] {
        let custom = http.custom.method.as_deref().filter(|_| self.custom);
        custom.unwrap_or(self.method.name())
    }

    /// Render the head and send what the connection takes now (`Curl_http`).
    pub(crate) fn do_it<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        // The application's header lists as they are now, as C walks them
        // while it builds the request; the cookies' host is the one its
        // `Host:` names then (`http_set_aptr_host`).
        let options = cx.easy_mut().options_mut();
        options
            .reread_headers()
            .map_err(|_| ErrorKind::OutOfMemory)?;
        self.cookie_host = cookies::custom_host(&options.http.headers, self.gate.same_origin())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let reused = lease.conn().reused();
        // On a connection's first request, which finds what it speaks
        // (`http_check_new_conn`).
        let h2 = if reused {
            lease.conn().is_h2()
        } else {
            self.check_new_conn(cx, lease)?
        };
        let http_proxy = lease.conn().http_proxy();
        self.version = version(
            cx.easy().options().http.version,
            self.after_http10,
            lease.conn().seen_version(),
            h2,
        );
        self.h2 = h2.then(h2::H2Stream::default);
        // Over clear text, HTTP/2 is asked for by an upgrade where the
        // application wants it so (`H1_HD_UPGRADE`).
        self.upgrade = self.upgrade_settings(cx, lease, h2)?;
        let upgrade = self
            .upgrade
            .as_deref()
            .map(crate::base64::encode_url)
            .transpose()
            .map_err(|_| ErrorKind::OutOfMemory)?;
        // The proxy the request goes to whole, and what it is given.
        let forwarding = lease
            .conn()
            .forwarding()
            .map(|p| (p.peer.clone(), p.creds.clone()));
        let forwarded = forwarding.is_some();
        let get_or_head = matches!(self.method, Method::Get | Method::Head);
        let credentials = self.credentials.as_ref().map(Credentials::secret);
        // Without one, nothing goes to a proxy: its side is done at once,
        // as for its own peer.
        let (proxy_peer, proxy_secret) = match &forwarding {
            Some((peer, creds)) => (&**peer, creds.as_deref().map(ProxyCreds::secret)),
            None => (&self.peer, None),
        };
        let now = cx.unix_time();
        let ed25519 = cx.easy().libraries().ed25519;
        // The proxy's first, as C's `Curl_http_output_auth` makes them;
        // with no proxy to send the request on, nothing goes to one
        // (`authproxy->done`).
        let proxy_auth = {
            let (auth_state, options) = cx.easy_mut().auth_with_options();
            let http = &options.http;
            let request = AuthRequest {
                side: Side::Proxy,
                origin: proxy_peer,
                method: self.method_line(http),
                uri: &self.target,
                get_or_head,
                // Nothing the application set for an origin goes to a proxy.
                trusted: None,
            };
            // The proxy's own headers may replace it
            // (`Curl_checkProxyheaders`).
            let proxy_custom = options
                .proxy
                .own_headers(http)
                .replaces(b"Proxy-Authorization");
            let side = auth_state.side(Side::Proxy);
            if forwarded {
                made(side.output(proxy_secret, proxy_custom, &request, random))?
            } else {
                side.finish();
                Output {
                    header: None,
                    used: AuthMethods::NONE,
                    probe: false,
                    negotiate: false,
                }
            }
        };
        // Negotiate's token for the proxy is the connection's context's to
        // make, and is said at once, before the origin's is made.
        let proxy_traced = proxy_auth.negotiate;
        let proxy_auth = if proxy_auth.negotiate {
            let output = self.negotiate(cx, lease, Side::Proxy, get_or_head)?;
            auth_trace(cx, "Proxy", output.used, proxy_secret);
            output
        } else {
            proxy_auth
        };
        let (auth_state, options) = cx.easy_mut().auth_with_options();
        let http = &options.http;
        let request = AuthRequest {
            side: Side::Host,
            origin: &self.peer,
            method: self.method_line(http),
            uri: &self.target,
            get_or_head,
            trusted: self.gate.trusted(),
        };
        let custom = http.headers.replaces(b"Authorization");
        let auth = made(
            auth_state
                .side(Side::Host)
                .output(credentials, custom, &request, random),
        )?;
        // The origin's likewise, after the proxy's line is made and said,
        // as C makes the proxy's first.
        let proxy_traced = if auth.negotiate && !proxy_traced {
            auth_trace(cx, "Proxy", proxy_auth.used, proxy_secret);
            true
        } else {
            proxy_traced
        };
        let auth = if auth.negotiate {
            self.negotiate(cx, lease, Side::Host, get_or_head)?
        } else {
            auth
        };
        let options = cx.easy().options();
        let method = self.method_line(&options.http);
        // AWS SigV4 is signed now, with what the request will be; it
        // fails a path kept as given (`Curl_output_aws_sigv4`).
        let signing = if auth.used == AuthMethods::AWS_SIGV4 {
            if options.url_rules.path_as_is {
                return Err(trace::fail(
                    cx,
                    ErrorKind::BadFunctionArgument,
                    format_args!("Cannot use sigv4 authentication with path-as-is flag"),
                ));
            }
            (!custom)
                .then(|| self.sign_sigv4(options, method, credentials, now))
                .flatten()
        } else {
            None
        };
        let signed = if auth.used == AuthMethods::HTTPSIG {
            let signing = self.sign_httpsig(options, method, now, ed25519);
            match signing.result {
                Ok(lines) => Some((signing.notes, lines.unwrap_or_default())),
                Err(e) => {
                    // What C traces before it fails, as for SigV4.
                    auth_trace(cx, "Proxy", proxy_auth.used, proxy_secret);
                    for note in &signing.notes {
                        trace::info_with(cx, &[note]);
                    }
                    return Err(e.fail(cx));
                }
            }
        } else {
            match signing {
                None => None,
                Some(sigv4::Signing { notes, result }) => match result {
                    Ok(lines) => Some((notes, lines)),
                    Err(e) => {
                        // What C traces before it fails: the proxy's
                        // authenticating, and the signing's notes.
                        auth_trace(cx, "Proxy", proxy_auth.used, proxy_secret);
                        for note in &notes {
                            trace::info_with(cx, &[note]);
                        }
                        return Err(match e.message() {
                            Some(said) => trace::fail(cx, e.kind(), format_args!("{said}")),
                            None => e.kind(),
                        });
                    }
                },
            }
        };
        let probe = auth.probe || proxy_auth.probe;
        let auth_asked = cx.easy().auth.asked(
            (credentials, &self.peer),
            (proxy_secret, proxy_peer),
            probe,
            get_or_head,
        );
        cx.report_mut().set_auth_used(auth.used);
        if forwarded {
            cx.report_mut().set_proxy_auth_used(proxy_auth.used);
        }
        let http = &cx.easy().options().http;
        let application = http.cookies.send.is_some()
            && !http.headers.replaces(b"Cookie")
            && self.gate.trusted().is_some();
        let site = cookie_site(&self.cookie_host, &self.target, &self.peer);
        let cookie = cookies::request_value(cx, &site, application)?;
        let options = cx.easy().options();
        let http = &options.http;
        let upload_buffer = options.limits.upload_buffer.get();
        let method = self.method_line(http);
        let body = match self.method {
            Method::Get | Method::Head => None,
            Method::Post if matches!(options.upload, UploadSource::Mime(_)) => Some(BodyKind::Mime),
            Method::Post => Some(BodyKind::Form),
            Method::Upload => Some(BodyKind::Put),
        };
        if body.is_some() && options.resume.is_some() {
            return Err(trace::fail(
                cx,
                ErrorKind::BadFunctionArgument,
                format_args!("HTTP upload cannot be resumed"),
            ));
        }
        // The application's Transfer-Encoding decides whether the body is
        // chunked; otherwise one of unknown size is, which HTTP/1.0 cannot
        // send (`http_req_set_TE`).
        let asked = http.headers.asks_chunked();
        // A probe goes without its body, saying it has none
        // (`Curl_creader_set_null`). A POST asked chunked is read to its
        // end (`set_reader`).
        let mut upload = match body.filter(|_| !probe) {
            None => None,
            Some(_) => {
                let mut upload = Upload::new(&options.upload, &http.headers, options.mime_escape())
                    .map_err(MakeError::kind)?;
                if asked == Some(true) && self.method == Method::Post {
                    upload.read_to_end();
                }
                Some(upload)
            }
        };
        // The client's size, and the body's as sent: unknown if its line
        // ends are converted, as they are for any body not known to be
        // empty (`do_init_reader_stack`).
        let client_size = if probe {
            Some(0)
        } else {
            upload.as_ref().and_then(Upload::size)
        };
        let converts = options.crlf && upload.is_some() && client_size != Some(0);
        let size = client_size.filter(|_| !converts);
        let size_unknown = upload.is_some() && size.is_none();
        if asked.is_none() && size_unknown && self.version == SentIn::Http10 {
            return Err(trace::fail(
                cx,
                ErrorKind::UploadFailed,
                format_args!("Chunky upload is not supported by HTTP 1.0"),
            ));
        }
        // HTTP/2 frames the body itself, said once the head is made
        // (`http_req_set_TE`).
        let suppressed = h2 && asked == Some(true);
        let chunked = !h2 && asked.unwrap_or(size_unknown);
        // Even a request without a body sends a last chunk if chunked.
        if chunked && upload.is_none() {
            upload = Some(Upload::empty());
        }
        // A tree's head lines are kept for a probe after this request to
        // send again; a probe sends those an earlier request sent, as C
        // sends the headers it made last (`http_add_content_hds`).
        let sent = match &options.upload {
            UploadSource::Mime(source) if body == Some(BodyKind::Mime) => source.sent_head(),
            _ => None,
        };
        let probe_head = match (sent, &upload) {
            (Some(sent), Some(upload)) if !probe => {
                sent.keep(upload.head().unwrap_or(&[]))
                    .map_err(|_| ErrorKind::OutOfMemory)?;
                Vec::new()
            }
            (Some(sent), _) if probe => sent.lines().map_err(|_| ErrorKind::OutOfMemory)?,
            _ => Vec::new(),
        };
        let mut content = body.map(|kind| request::Content {
            length: size.filter(|_| !chunked),
            typed: match kind {
                BodyKind::Form => Typed::Form,
                BodyKind::Put => Typed::No,
                BodyKind::Mime if probe => Typed::Mime(&probe_head),
                BodyKind::Mime => {
                    Typed::Mime(upload.as_ref().and_then(Upload::head).unwrap_or(&[]))
                }
            },
            expect: false,
        });
        // `Expect: 100-continue`, asked for, or added on HTTP/1.1 for a
        // body large or of unknown size, holds the body back until a 100
        // comes or the wait runs out (`addexpect`).
        let expects = http.headers.expects_continue();
        let added_expect = content.is_some()
            && upgrade.is_none()
            && expects.is_none()
            && !self.no_expect
            && self.version == SentIn::Http11
            // Weighed by the client's size, converted or not
            // (`Curl_creader_client_length`).
            && client_size.is_none_or(|n| n > EXPECT_100_THRESHOLD);
        // An upgrade asks for none (`addexpect`).
        let announced = content.is_some()
            && !auth.probe
            && upgrade.is_none()
            && (expects == Some(true) || added_expect);
        if let Some(content) = &mut content {
            content.expect = added_expect;
        }
        // A download asks for its range; an upload, which cannot resume,
        // says which range of the resource its body is (`http_range`).
        let range = match (options.ranged(), body) {
            (None, _) => None,
            (Some(ranged), None) => Some(RangeLine::Get(ranged)),
            (Some(Ranged::Given(range)), Some(_)) => Some(RangeLine::Upload { range, total: size }),
            (Some(Ranged::Resume(_)), Some(_)) => unreachable!("an upload does not resume"),
        };
        // The time condition's header, if the application sends none of
        // its own; a time C's `struct tm` cannot hold fails the request
        // all the same (`Curl_add_timecondition`).
        let conditional = match options.time_condition {
            None => None,
            Some(c) => match HttpDate::of(c.time) {
                Ok(date) => (!http.headers.replaces(c.when.header())).then_some(Conditional {
                    name: c.when.header(),
                    date,
                }),
                Err(OutOfRange) => {
                    let said = format_args!("Invalid TIMEVALUE");
                    return Err(trace::fail(cx, ErrorKind::BadFunctionArgument, said));
                }
            },
        };
        let port = self.peer.port();
        let shown_port = (port != self.default_port()).then_some(port);
        let gate = self.gate;
        let authorization = match (&self.credentials, &auth.header) {
            // Digest goes beside the application's own Authorization, as
            // C's does (`H1_HD_AUTH`).
            (Some(c), Some((AuthMethods::DIGEST, value))) => {
                Some(Authorization::alongside("Digest", value, c.trusted()))
            }
            // Negotiate goes with no credentials too, made only for an
            // origin the gate trusts and without the application's own.
            (_, Some((AuthMethods::NEGOTIATE, value))) => {
                let trusted = gate.trusted().expect("Negotiate goes only where trusted");
                Authorization::new("Negotiate", value, trusted, &http.headers)
            }
            (Some(c), Some((method, value))) => {
                Authorization::new(method.name(), value, c.trusted(), &http.headers)
            }
            _ => None,
        };
        let proxy_authorization = proxy_auth
            .header
            .as_ref()
            .map(|(method, value)| Authorization::to_proxy(method.name(), value));
        let authenticated = (!auth.used.is_empty()).then_some(auth.used);
        let head = RequestHead {
            method,
            // The application's target replaces only the request line's
            // (`http_target`).
            target: match &http.custom.target {
                Some(target) => target,
                None => self
                    .forward_target
                    .as_deref()
                    .filter(|_| forwarded)
                    .unwrap_or(&self.target),
            },
            version: self.version,
            host: self.peer.request_host(),
            port: shown_port,
            user_agent: http.user_agent.as_deref(),
            referer: cx.easy().report().referer(),
            proxy_authorization,
            authorization,
            signed: signed.as_ref().map(|(_, lines)| &lines[..]),
            range,
            content,
            chunked: chunked && asked.is_none(),
            probe,
            accept_encoding: match &http.accept_encoding {
                None => None,
                Some(AcceptEncoding::All) => Some(Accepted::All(cx.easy().decoders())),
                Some(AcceptEncoding::Given(value)) => Some(Accepted::Given(value)),
            },
            // Only with gzip to undo, as C sends it only built with zlib.
            te: http.transfer_encoding
                && cx.easy().decoders().maker(Coding::Gzip).is_some()
                && !http.headers.replaces(b"TE"),
            conditional,
            cookie: cookie.as_deref(),
            alt_used: self
                .alt_used
                .as_deref()
                .filter(|_| !http.headers.replaces(b"Alt-Used")),
            upgrade: upgrade.as_deref(),
            forwarded: forwarded.then(|| Forwarding {
                own_headers: (!options.proxy.unified_headers).then_some(&options.proxy.headers),
            }),
            headers: &http.headers,
        };
        let mut out = Vec::new();
        request::render_h1(&head, &gate, &mut out)?;
        let exchange = Exchange {
            sent: match self.version {
                SentIn::Http10 => response::HttpVersion::Http10,
                SentIn::Http11 => response::HttpVersion::Http11,
                SentIn::Http2 => response::HttpVersion::Http2,
            },
            reused,
            allow_09: http.allow_09,
            asked: Asked {
                head: self.method == Method::Head,
                ignore_length: http.ignore_content_length,
                max_filesize: options.flow.max_filesize,
                decode_codings: http.transfer_encoding,
                raw_codings: http.raw,
                fail_on_error: http.fail_on_error,
                resume_from: options.resume.filter(|_| self.method == Method::Get),
                follow: http.follow != Follow::No,
                auth: auth_asked,
                http_proxy,
                time_condition: options
                    .time_condition
                    .filter(|_| options.ranged().is_none()),
                forwarded,
            },
        };
        // Named once in use, though Digest sends nothing before its
        // first challenge (`output_auth_headers`).
        if !proxy_traced {
            auth_trace(cx, "Proxy", proxy_auth.used, proxy_secret);
        }
        for note in signed.iter().flat_map(|(notes, _)| notes) {
            trace::info_with(cx, &[note]);
        }
        if let Some(method) = authenticated {
            let user = self.credentials.as_ref().map_or(&b""[..], |c| c.user());
            let name = method.name().as_bytes();
            trace::info_with(
                cx,
                &[b"Server auth using ", name, b" with user '", user, b"'"],
            );
        }
        if suppressed {
            trace::info(
                cx,
                format_args!(
                    "suppressing chunked transfer encoding on connection using HTTP version 2 \
                     or higher"
                ),
            );
        }
        let length = content.and_then(|c| c.length);
        // A tree's handlers are rewound before it is read
        // (`Curl_creader_set_mime`).
        if let Some(upload) = &mut upload {
            upload.start(cx)?;
        }
        let head_len = out.len();
        if upload.is_some() {
            // The body goes behind the head, in what is left of one
            // buffer (`Curl_req_send`).
            let room = upload_buffer.saturating_sub(head_len);
            out.try_reserve_exact(room)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            zeros(&mut out, room).map_err(|_| ErrorKind::OutOfMemory)?;
            upload::announce_size(cx, length);
        }
        // Without a body to read, all of it is in the buffer, whatever
        // was announced; with one announced, none of it is read until a
        // 100 comes or the wait runs out.
        let then = if upload.is_none() || !announced {
            AfterHead::Body(Reading {
                eos_read: upload.is_none(),
                announced,
            })
        } else {
            AfterHead::Continue
        };
        self.out = out;
        self.filled = head_len;
        self.sent = 0;
        self.body = match upload {
            Some(upload) => {
                // The request's reader (`http_req_set_reader`).
                upload.trace_set(cx);
                *cx.readers_mut() = upload.pausing().map(|client| upload::Readers {
                    chunked,
                    exp100: announced,
                    lines: converts,
                    client,
                });
                let mut body = chain::Body::new(upload);
                if converts {
                    body.convert_lines().map_err(|_| ErrorKind::OutOfMemory)?;
                }
                if chunked {
                    body.chunked().map_err(|_| ErrorKind::OutOfMemory)?;
                }
                Some(body)
            }
            None => None,
        };
        self.body_sent = 0;
        self.outgoing = Sending::Head {
            left: NonZeroUsize::new(head_len).expect("a head is never empty"),
            then,
        };
        self.head = Some(HeadParser::new(exchange));
        // A body held for a 100 is not read behind the head, but C asks
        // its readers for it, the 100's wait among them, so its send limit
        // starts now.
        let paused = cx.pause().send_paused();
        match then {
            AfterHead::Body(Reading {
                eos_read: false, ..
            }) if self.filled < self.out.len() && !paused => {
                self.fill(cx)?;
            }
            AfterHead::Continue => self.held_back(cx, Held::Unsent),
            AfterHead::Body(_) => {}
        }
        // The engine takes the request as sent at DID if it went now;
        // the buffer read behind the head is this pass's.
        self.send(cx, lease, false).map(drop)
    }

    /// Read body into the buffer behind what is there: whether anything
    /// came or the body ended (`add_from_client`).
    fn fill<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<bool, ErrorKind> {
        self.start_reading(cx);
        let pausable = self.pipeline.pausable();
        let announced = self.outgoing.announced();
        let body = self.body.as_mut().expect("a body to read");
        let dest = &mut self.out[self.filled..];
        // Under a send limit, no more than it allows, and nothing once it
        // is spent (`Curl_client_read`).
        let dest = match cx.rate_allowance(Way::Send) {
            Some(..=0) => {
                let nothing = Ok(upload::Readout { n: 0, eos: false });
                upload::client_read(cx, dest.len(), &nothing);
                return Ok(false);
            }
            Some(allowed) => {
                let room = dest
                    .len()
                    .min(usize::try_from(allowed).unwrap_or(usize::MAX));
                &mut dest[..room]
            }
            None => dest,
        };
        let len = dest.len();
        // The 100's wait over, its reader passes every read on.
        if announced {
            trace::debug_info(cx, format_args!("cr_exp100_read, pass through"));
        }
        let got = body.read(cx, dest, pausable, trailer_block);
        upload::client_read(cx, len, &got);
        let got = got?;
        self.filled += got.n;
        self.outgoing
            .reading_mut()
            .expect("a body being read")
            .eos_read = got.eos;
        Ok(got.n > 0 || got.eos)
    }

    /// The body is asked for, unless its sending is paused, and held back
    /// for a 100, `held` saying why: C's readers give nothing
    /// (`Curl_client_read`, `cr_exp100_read`).
    fn held_back<H: Host>(&mut self, cx: &mut StepCx<'_, H>, held: Held) {
        if cx.pause().send_paused() {
            return;
        }
        self.start_reading(cx);
        match held {
            Held::Unsent => trace::debug_info(
                cx,
                format_args!("cr_exp100_read, request not full sent yet"),
            ),
            Held::Starts => {
                let ms = cx.easy().options().http.continue_wait.get().as_millis();
                trace::debug_info(
                    cx,
                    format_args!("cr_exp100_read, start AWAITING_CONTINUE, timeout {ms}ms"),
                );
            }
            Held::Waits => trace::debug_info(
                cx,
                format_args!("cr_exp100_read, AWAITING_CONTINUE, not expired"),
            ),
        }
        let nothing = Ok(upload::Readout { n: 0, eos: false });
        upload::client_read(cx, self.out.len() - self.filled, &nothing);
    }

    /// The body is first read, or asked for: the send limit starts over
    /// (`Curl_client_read`'s `reader_started`).
    fn start_reading<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        if !self.read_started {
            self.read_started = true;
            cx.rate_start(Way::Send, None);
        }
    }

    /// Send what is left of the request as far as the connection takes
    /// it, reading at most one more buffer of its body if `read` and it
    /// all went: whether the request is sent (`Curl_req_send_more`,
    /// `req_set_upload_done`).
    fn send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        mut read: bool,
    ) -> Result<bool, ErrorKind> {
        while self.sending() {
            if self.sent == self.filled {
                if let Sending::Body(Reading { eos_read: true, .. }) = self.outgoing {
                    // The stream hears the body's end, which no bytes
                    // carried (`req_flush`'s `xfer_send` of none).
                    if self.h2.as_ref().is_some_and(|s| !s.body_eos()) {
                        self.h2_send(cx, lease, self.sent, true)?;
                    }
                    break;
                }
                self.sent = 0;
                self.filled = 0;
                // A body announced with `Expect: 100-continue` waits for
                // the 100, or until the wait runs out (`cr_exp100_read`).
                match self.outgoing {
                    // The body is asked for the first time since the head
                    // went: the wait starts.
                    Sending::HeadSent => {
                        if !read || cx.pause().send_paused() {
                            return Ok(false);
                        }
                        let wait = cx.easy().options().http.continue_wait.get();
                        let until = cx.now().after(wait);
                        self.outgoing = Sending::AwaitingContinue(until);
                        state::trace_set(cx, TimerKind::Proto, until);
                        self.held_back(cx, Held::Starts);
                        return Ok(false);
                    }
                    Sending::AwaitingContinue(until) if cx.now() < until => {
                        self.held_back(cx, Held::Waits);
                        return Ok(false);
                    }
                    Sending::AwaitingContinue(_) => {
                        self.release(cx);
                        trace::info(cx, format_args!("Done waiting for 100-continue"));
                    }
                    Sending::Body(_) => {}
                    Sending::Head { .. } => unreachable!("the head is in the buffer"),
                    Sending::Idle | Sending::Done | Sending::Aborted => {
                        unreachable!("sending")
                    }
                }
                if !read || cx.pause().send_paused() || !self.fill(cx)? {
                    return Ok(false);
                }
                read = false;
                continue;
            }
            // No more of the body in one send than a second's worth of the
            // send limit, the head not counted (`xfer_send`). Cut short,
            // it ends the pass's sending as a short send does.
            let head = match self.outgoing {
                Sending::Head { left, .. } => left.get(),
                _ => 0,
            };
            let body = self.filled - self.sent - head;
            let end = match cx.easy().options().flow.max_send_speed {
                Some(max) if body as u64 > max.get() => {
                    self.sent + head + usize::try_from(max.get()).expect("under a length")
                }
                _ => self.filled,
            };
            // All that is left of the request, read to its end
            // (`xfer_send`'s `eos`).
            let len = end - self.sent;
            let eos = end == self.filled
                && matches!(
                    self.outgoing,
                    Sending::Head {
                        then: AfterHead::Body(Reading { eos_read: true, .. }),
                        ..
                    } | Sending::Body(Reading { eos_read: true, .. })
                );
            if eos {
                trace::debug_info(cx, format_args!("sending last upload chunk of {len} bytes"));
            }
            let said = cx.easy().report().reasons();
            // The socket traces the send, and says why it failed, as it
            // reaches it (`cf_socket_send`); a layer may say why too. Over
            // HTTP/2 the stream takes it (`cf_h2_send`).
            let (taken, failed) = if self.h2.is_some() {
                match self.h2_send(cx, lease, end, eos) {
                    Ok(n) => (n, None),
                    Err(kind) => (0, Some(kind)),
                }
            } else {
                let sent = lease.get().send(cx, &self.out[self.sent..end]);
                match sent {
                    Ok(Sent::Bytes(n)) => (n.get(), None),
                    Ok(_) => (0, None),
                    Err(_) if cx.easy().report().reasons() > said => {
                        (0, Some(ErrorKind::SendError))
                    }
                    Err(e) => {
                        let why = OsError(&e);
                        let said = format_args!("Send failure: {why}");
                        (0, Some(trace::fail(cx, ErrorKind::SendError, said)))
                    }
                }
            };
            let code = failed.map_or(0, ErrorKind::number);
            let n = taken;
            trace::debug_info(
                cx,
                format_args!(
                    "Curl_xfer_send(len={len}, eos={}) -> {code}, {n}",
                    u8::from(eos)
                ),
            );
            if let Some(kind) = failed {
                return Err(kind);
            }
            if n == 0 {
                // Nothing went: what is left waits (`req_flush`).
                let left = self.filled - self.sent;
                trace::debug_info(cx, format_args!("Curl_req_flush(len={left}) -> EAGAIN"));
                return Ok(false);
            }
            // The head's part and the body's are traced apart
            // (`xfer_send`); both count as the request's.
            let head = match self.outgoing {
                Sending::Head { left, .. } => n.min(left.get()),
                _ => 0,
            };
            if head > 0 {
                trace::bytes(
                    cx,
                    DebugKind::HeaderOut,
                    &self.out[self.sent..self.sent + head],
                );
            }
            upload::sent(cx, &self.out[self.sent + head..self.sent + n]);
            cx.report_mut().sizes_mut().request += n as u64;
            self.body_sent += (n - head) as u64;
            self.sent += n;
            if let Sending::Head { left, then } = self.outgoing {
                self.outgoing = match (NonZeroUsize::new(left.get() - head), then) {
                    (Some(left), then) => Sending::Head { left, then },
                    (None, AfterHead::Body(reading)) => Sending::Body(reading),
                    // The head has gone: the wait for a 100 starts when
                    // the body is next asked for, not in this send
                    // (`Curl_req_send_more` reads before it flushes).
                    (None, AfterHead::Continue) => {
                        self.sent = 0;
                        self.filled = 0;
                        self.outgoing = Sending::HeadSent;
                        return Ok(false);
                    }
                };
            }
            if self.sent == end && end < self.filled {
                // Cut short by the send limit, the rest waits
                // (`req_flush`).
                let left = self.filled - self.sent;
                trace::debug_info(cx, format_args!("Curl_req_flush(len={left}) -> EAGAIN"));
                return Ok(false);
            }
        }
        self.upload_done(cx, false);
        Ok(true)
    }

    /// Nothing more of the request goes, all of it sent or, `aborted`,
    /// not (`req_set_upload_done`).
    fn upload_done<H: Host>(&mut self, cx: &mut StepCx<'_, H>, aborted: bool) {
        // Past DID the request is complete from here; before, DID marks
        // it.
        if cx.mstate() >= MState::Did {
            cx.mark(Timer::PostTransfer);
        }
        // The wait for a 100 is over, whether it came or not
        // (`cr_exp100_done`).
        if self.outgoing.announced() {
            state::trace_timer(cx, TimerKind::Proto, format_args!("cleared"));
        }
        self.outgoing = if aborted {
            Sending::Aborted
        } else {
            Sending::Done
        };
        self.sent = self.filled;
        let n = self.body_sent;
        if aborted {
            if n > 0 {
                trace::info(cx, format_args!("abort upload after having sent {n} bytes"));
            } else {
                trace::info(cx, format_args!("abort upload"));
            }
        } else if n > 0 {
            trace::info(cx, format_args!("upload completely sent off: {n} bytes"));
        } else if !matches!(self.stage, Stage::Done) {
            let sized = self
                .body
                .as_ref()
                .and_then(chain::Body::size)
                .is_some_and(|n| n != 0);
            let said = if sized {
                "We are completely uploaded and fine"
            } else {
                "Request completely sent off"
            };
            trace::info(cx, format_args!("{said}"));
        }
    }

    /// Read until the connection has nothing more now, the response is
    /// over, receiving pauses or the step has read its most, then send
    /// what is left with at most one more buffer of the body
    /// (`Curl_sendrecv`): a response that comes while the body goes is
    /// heard before more of it is sent.
    pub(crate) fn step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        self.pipeline.flush(cx)?;
        let read = match self.receive(cx, lease) {
            Ok(read) => read,
            Err(e) => {
                // A response cut short in its head is `Curl_sendrecv`'s
                // own finding, after the reads.
                if !(e == ErrorKind::PartialFile && matches!(self.stage, Stage::Head)) {
                    let code = e.number();
                    trace::debug_info(cx, format_args!("sendrecv_dl() -> {code}"));
                }
                return Err(e);
            }
        };
        // The request is over once its response is and nothing more of it
        // is to send (`KEEP_RECV` and `KEEP_SEND` both off).
        if self.sending() {
            self.send(cx, lease, true)?;
        } else if self.h2.as_ref().is_some_and(h2::H2Stream::out_pending) && lease.conn().is_h2() {
            self.h2_egress(cx, lease)?;
        }
        Ok(if matches!(self.stage, Stage::Done) && !self.sending() {
            ProtoStep::Done
        } else if read == Read::Stopped {
            ProtoStep::AtReadLimit
        } else {
            ProtoStep::Blocked
        })
    }

    /// Read what the connection has now, at most `MAX_READS` times, until
    /// the response is over or receiving pauses (`sendrecv_dl`).
    fn receive<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Read, ErrorKind> {
        let reading = !matches!(self.stage, Stage::Done);
        let read = self.read_some(cx, lease)?;
        // The response ended on a connection that closes: the server may
        // close it now, so nothing more of the request goes. A
        // multiplexed stream will stop here too.
        if reading && matches!(self.stage, Stage::Done) && self.sending() && self.closes() {
            trace::info(
                cx,
                format_args!("we are done reading and this is set to close, stop send"),
            );
            self.upload_done(cx, true);
        }
        Ok(read)
    }

    /// `receive`'s reads.
    fn read_some<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Read, ErrorKind> {
        if self.h2.is_some() {
            return self.h2_read_some(cx, lease);
        }
        let mut reads = 0;
        loop {
            if matches!(self.stage, Stage::Done) || cx.pause().recv_paused() {
                return Ok(Read::Waits);
            }
            if reads == MAX_READS {
                // Neither the end nor a read that would block: there may
                // be more to read already.
                return Ok(Read::Stopped);
            }
            let max = self.read_size(cx.easy().options().limits.buffer_size.get());
            if max == 0 {
                // The body is whole: nothing more is read for it. Like a
                // body made whole by what `input` gives it, it ends
                // without `end`, which is the connection's end of the
                // response: C stops reading at `download_done` and writes
                // no `CLIENTWRITE_EOS` for it.
                self.stage = Stage::Done;
                continue;
            }
            // Under a receive limit, no more than it allows; once spent,
            // the engine waits for it (`sendrecv_dl`'s `rate_limited`).
            let max = match cx.rate_allowance(Way::Recv) {
                Some(..=0) => return Ok(Read::Waits),
                Some(allowed) => max.min(usize::try_from(allowed).unwrap_or(usize::MAX)),
                None => max,
            };
            reads += 1;
            let said = cx.easy().report().reasons();
            // The socket traces the receive, and says why it failed, as it
            // reaches it (`cf_socket_recv`).
            let got = lease.get().recv(cx, max);
            match got {
                // Bytes a layer holds wake no poll: the step runs again
                // (`sendrecv_dl`'s `data_pending`).
                Ok(Recv::WouldBlock) if lease.get().data_pending() => return Ok(Read::Stopped),
                Ok(Recv::WouldBlock) => return Ok(Read::Waits),
                Ok(Recv::Eof) => {
                    trace::debug_info(cx, format_args!("sendrecv_dl: we are done"));
                    // The connection's end stops the sending too
                    // (`Curl_req_stop_send_recv`).
                    if self.sending() {
                        self.upload_done(cx, true);
                    }
                    let ended = self.end(cx);
                    deliver::write_resp(cx, 0, true, ended);
                    ended?;
                    self.stage = Stage::Done;
                }
                Ok(Recv::Data(_)) => {
                    let mut rx = std::mem::take(lease.get().rx_mut());
                    let fed = self.input(cx, lease, rx.filled());
                    let all = rx.filled().len();
                    rx.consume(all);
                    *lease.get().rx_mut() = rx;
                    deliver::write_resp(cx, all, false, fed);
                    fed?;
                    // Switched to HTTP/2 by a 101: read on in it.
                    if self.h2.is_some() {
                        return self.h2_read_some(cx, lease);
                    }
                }
                Err(RecvFailed::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                // A layer that said why it failed, as TLS does, is not
                // said for again (C's filters each `failf` their own).
                Err(RecvFailed::Os(_)) if cx.easy().report().reasons() > said => {
                    return Err(ErrorKind::RecvError);
                }
                Err(RecvFailed::Os(e)) => {
                    let why = OsError(&e);
                    return Err(trace::fail(
                        cx,
                        ErrorKind::RecvError,
                        format_args!("Recv failure: {why}"),
                    ));
                }
            }
        }
    }

    /// How much the next read may take: the buffer's size, and a body of
    /// a known size no further than its end (`xfer_recv_resp`,
    /// `Curl_xfer_recv`).
    fn read_size(&self, buffer: usize) -> usize {
        match self.stage {
            Stage::Body(Body::Length) => {
                let left = self
                    .head()
                    .meta()
                    .size()
                    .expect("a body by length has one")
                    .saturating_sub(self.pipeline.bytecount());
                usize::try_from(left).map_or(buffer, |left| left.min(buffer))
            }
            _ => buffer,
        }
    }

    /// What of the body is still to go, as the response's head weighs it
    /// (`http_perhapsrewind`): its size less what went, unless all went.
    /// Sent `chunked`, its framing makes its size unknown
    /// (`cr_chunked_total_length`).
    fn left_to_send(body: Option<&chain::Body>, sent_all: bool, body_sent: u64) -> Unsent {
        let rereads = body.is_some_and(|b| b.upload().needs_rewind());
        let left = match body {
            None => Left::Nothing,
            Some(_) if sent_all => Left::Nothing,
            Some(body) if body.is_chunked() => Left::Unknown,
            Some(body) => match body.size() {
                Some(size) => Left::Bytes(size.saturating_sub(body_sent)),
                None => Left::Unknown,
            },
        };
        Unsent { rereads, left }
    }

    fn head(&self) -> &HeadParser {
        self.head.as_ref().expect("made at DO")
    }

    /// Read what came, all of it (`Curl_http_write_resp`).
    fn input<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        mut input: &[u8],
    ) -> Result<(), ErrorKind> {
        while !input.is_empty() {
            match self.stage {
                Stage::Head if self.h2.is_none() => {
                    input = self.head_input(cx, lease, input, false)?;
                    // What follows a 101 that switched is HTTP/2's.
                    if self.h2.is_some() {
                        return self.upgraded_input(cx, lease, input);
                    }
                }
                Stage::Head => input = self.head_input(cx, lease, input, false)?,
                Stage::Body(Body::Length | Body::UntilClose | Body::Stream) => {
                    self.pipeline.body(cx, input)?;
                    input = &[];
                    if matches!(self.stage, Stage::Body(Body::Length)) && self.pipeline.body_done()
                    {
                        self.stage = Stage::Done;
                    }
                }
                Stage::Body(Body::Chunked(_)) => input = self.chunked_input(cx, input)?,
                // Nothing after the response is read.
                Stage::Done => return Ok(()),
            }
        }
        Ok(())
    }

    /// Feed the head parser once and deliver what it made; what is left of
    /// `input`. A `whole` input is one line, as HTTP/2 hands them on.
    fn head_input<'i, H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        input: &'i [u8],
        whole: bool,
    ) -> Result<&'i [u8], ErrorKind> {
        let Request {
            pipeline,
            head,
            interim,
            body,
            outgoing,
            body_sent,
            credentials,
            peer,
            cookie_host,
            target,
            ..
        } = self;
        let state = |side| lease.conn().negotiate().map(|n| n.state(side));
        let (host, proxy) = (state(Side::Host), state(Side::Proxy));
        let started =
            |state: Option<negotiate::State>| state.is_some_and(|s| s != negotiate::State::None);
        let conn_negotiate = framing::ConnNegotiate {
            started: started(host) || started(proxy),
            taken: host == Some(negotiate::State::Recv),
            proxy_taken: proxy == Some(negotiate::State::Recv),
        };
        let head = head.as_mut().expect("made at DO");
        // Only a status line changes it, so for a header line it is what
        // it was before.
        let bodyless = head.meta().bodyless();
        let sent_all = matches!(outgoing, Sending::Done | Sending::Aborted);
        let unsent = Self::left_to_send(body.as_ref(), sent_all, *body_sent);
        let header_bytes = &mut cx.report_mut().sizes_mut().header;
        let fed = if whole {
            head.line(input, header_bytes, unsent, conn_negotiate)
                .map(|event| (input.len(), Some(event)))
        } else {
            head.feed(input, header_bytes, unsent, conn_negotiate)
        };
        let (used, event) = match fed {
            Ok(fed) => fed,
            Err(e) => {
                // A list refused is traced as far as it was read.
                if let Some(tale) = head.failed_codings() {
                    trace_codings(cx, tale);
                }
                return Err(head_failed(cx, &e));
            }
        };
        let rest = &input[used..];
        let line = match event {
            None => return Ok(rest),
            Some(HeadEvent::Http09(bytes)) => {
                let no_body = self.method == Method::Head;
                pipeline.expect(Expect {
                    no_body,
                    no_head: true,
                    ..Expect::default()
                });
                // What was taken for a status line is the body's start,
                // unless no body is wanted (`Curl_http_write_resp_hds`).
                if !no_body {
                    pipeline.body(cx, bytes)?;
                }
                self.stage = Stage::Body(Body::UntilClose);
                return Ok(rest);
            }
            Some(HeadEvent::Line(line)) => line,
        };
        for note in line.notes.iter() {
            if note == framing::Note::NeedRewind {
                needs_rewind(cx);
            }
            trace::info(cx, format_args!("{note}"));
        }
        // The document's time, if asked for; one that cannot be read is
        // the epoch (`http_header_l`).
        if line.kind == LineKind::Header
            && cx.easy().options().filetime
            && !bodyless
            && let Some(value) = strip_name(line.bytes, b"Last-Modified:")
        {
            let t = crate::date::parse(value).unwrap_or(0);
            cx.report_mut().set_filetime(t);
        }
        // Its codings are stacked to be undone (`http_header_c`).
        if line.kind == LineKind::Header
            && !bodyless
            && cx.easy().options().http.accept_encoding.is_some()
            && let Some(value) = strip_name(line.bytes, b"Content-Encoding:")
        {
            content_codings(cx, pipeline, value)?;
        }
        // Negotiate's challenges are taken into the connection's context
        // with the origin, or with the proxy that forwards the request, and
        // the origin's persistence read, as the line is handled
        // (`auth_spnego`, `http_header_p`, `http_header_w`).
        let mut negotiated = None;
        let code = cx.report_mut().response_code();
        if line.kind == LineKind::Header
            && let Some(gss) = cx.easy().libraries().gss
        {
            let delegation = cx.easy().options().login.delegation;
            let forwarding = lease
                .conn()
                .forwarding()
                .map(|p| (p.peer.clone(), p.creds.clone()));
            let challenged = if code == Some(401)
                && cx.easy().auth.host_picks_negotiate()
                && strip_name(line.bytes, b"WWW-Authenticate:").is_some()
            {
                Some((
                    Side::Host,
                    credentials.as_ref().map(Credentials::secret),
                    &*peer,
                ))
            } else if code == Some(407)
                && cx.easy().auth.proxy_picks_negotiate()
                && strip_name(line.bytes, b"Proxy-Authenticate:").is_some()
                && let Some((proxy, creds)) = &forwarding
            {
                Some((
                    Side::Proxy,
                    creds.as_deref().map(ProxyCreds::secret),
                    &**proxy,
                ))
            } else {
                None
            };
            if let Some((side, credentials, peer)) = challenged {
                let value = fields::header_value(line.bytes).unwrap_or(&[]);
                for challenge in super::http1::auth::negotiate_challenges(value) {
                    let (kept, tls) = lease.get().negotiate_over();
                    let request = negotiate::Request {
                        gss,
                        side,
                        credentials,
                        peer,
                        delegation,
                        tls,
                    };
                    let taken = negotiate::challenged(cx, kept, &request, challenge);
                    let (any, _) = negotiated.map_or((false, true), |(_, any, last)| (any, last));
                    negotiated = Some((side, any || taken, taken));
                }
            }
            if cx.easy().auth.host_picks_negotiate()
                && strip_name(line.bytes, b"Persistent-Auth:").is_some()
            {
                let value = fields::header_value(line.bytes).unwrap_or(&[]);
                negotiate::persistence(cx, lease.get(), value)?;
            }
        }
        // A cookie is stored before its line is traced (`http_header`).
        if line.kind == LineKind::Header
            && let Some(value) = strip_name(line.bytes, b"Set-Cookie:")
        {
            let site = cookie_site(cookie_host, target, peer);
            cookies::set_by_server(cx, value, &site)?;
        }
        // As is a host's HSTS, from a response over HTTPS (`http_header_s`).
        if line.kind == LineKind::Header
            && let Some(value) = strip_name(line.bytes, b"Strict-Transport-Security:")
        {
            let value = value.strip_suffix(b"\n").unwrap_or(value);
            let value = value.strip_suffix(b"\r").unwrap_or(value);
            hsts::from_field(cx, peer.name(), value, peer.scheme() == HTTPS)?;
        }
        // And its alternative services (`http_header_a`).
        if line.kind == LineKind::Header
            && let Some(value) = strip_name(line.bytes, b"Alt-Svc:")
        {
            alt_svc::from_field(cx, peer, value, peer.scheme() == HTTPS)?;
        }
        let early = line.early.map_err(|e| head_failed(cx, &e));
        // What reading its transfer codings did, traced before the line, as
        // C reads them as it handles it (`http_header_t`).
        if let Some(tale) = line.codings {
            trace_codings(cx, tale);
        }
        trace::bytes(cx, DebugKind::HeaderIn, line.bytes);
        let origin = if *interim {
            HeaderOrigin::Interim
        } else {
            HeaderOrigin::Header
        };
        let kind = line.kind;
        let then = line.then;
        match kind {
            LineKind::Status(status) => {
                *interim = (100..200).contains(&status.code);
                cx.report_mut().set_response(status.code, status.version);
                pipeline.status(cx, line.bytes, *interim)?;
            }
            LineKind::Header => {
                if let Some(wait) = framing::retry_after(line.bytes, cx.unix_time()) {
                    cx.report_mut().set_retry_after(wait);
                }
                if let Some(media) = framing::content_type(line.bytes) {
                    cx.report_mut()
                        .set_content_type(media)
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                }
                pipeline.header(cx, line.bytes, origin)?;
            }
            LineKind::End { interim: false } if early.is_ok() && then.is_ok() => {
                // What the body comes to is known before the blank line is
                // delivered (`http_size`, then the last header), so the
                // header handler reads it there.
                // The line borrows the parser `body_start` reads, so it is
                // copied: CRLF on the stack, anything longer a server sent
                // (stray CRs before the LF, which C delivers whole) not.
                let mut short = [0u8; 2];
                let long;
                let blank: &[u8] = match short.get_mut(..line.bytes.len()) {
                    Some(short) => {
                        short.copy_from_slice(line.bytes);
                        short
                    }
                    None => {
                        long = copied(line.bytes)?;
                        &long
                    }
                };
                // A 101 to an upgrade to HTTP/2 switches the connection,
                // its head written first (`http_on_101_upgrade`).
                let switching = cx.report_mut().response_code() == Some(101);
                if switching && self.upgrade.is_some() && self.version == SentIn::Http11 {
                    self.pipeline.header(cx, blank, origin)?;
                    self.upgraded(cx, lease)?;
                    return Ok(rest);
                }
                self.body_start(cx)?;
                self.pipeline.header(cx, blank, origin)?;
            }
            LineKind::End { .. } => pipeline.header(cx, line.bytes, origin)?,
        }
        early?;
        then.map_err(|e| head_failed(cx, &e))?;
        if let Some((side, any, last)) = negotiated {
            let head = self.head.as_mut().expect("made at DO");
            head.meta_mut().negotiate_answered(side, any, last);
        }
        if let LineKind::End { interim } = kind {
            let code = cx.report_mut().response_code().unwrap_or(0);
            if !interim {
                // The upgrade was not taken: the connection speaks HTTP/1
                // on.
                self.upgrade = None;
            }
            // A 101 that ended the head is final, but C leaves it before it
            // looks at what the response says of authentication
            // (`http_on_101_upgrade`).
            if !interim && code != 101 {
                // The token that went was taken (`http_check_auth_closure`).
                negotiate::responded(lease.get(), code);
            }
            if interim && code == 100 {
                // The server is ready for the body (`http_exp100_got100`).
                self.release(cx);
            } else if !interim && code >= 300 {
                self.send_error(cx, code)?;
            }
            // A document the time condition ruled out ends the transfer
            // as a 304 would have (`http_firstwrite`). A 304 itself says
            // the condition was unmet by its code alone, as C's getinfo
            // reads it (`TransferReport::condition_unmet`).
            let unmet = !interim && self.head().meta().unmet();
            if unmet {
                cx.report_mut().set_condition_unmet();
            }
            if unmet && let Some(version) = cx.report_mut().response_version() {
                cx.report_mut().set_response(304, version);
            }
            // What is left of a body read again for the next request
            // goes, to be dropped (`http_on_response`).
            if !interim && self.head().meta().rewinds() && self.sending() {
                trace::info(cx, format_args!("Keep sending data to get tossed away"));
            }
        }
        if kind == (LineKind::End { interim: false }) {
            let abandoned = self.head().framing() == Some(Framing::Abandoned);
            if abandoned {
                // The request is over with its head: nothing more of it
                // goes (`http_firstwrite`'s `done`).
                if self.sending() {
                    self.outgoing = Sending::Done;
                }
                return Ok(&[]);
            }
            if matches!(self.stage, Stage::Done) && !rest.is_empty() {
                // Body where none is to come: the accountant judges it.
                self.pipeline.body(cx, rest)?;
                return Ok(&[]);
            }
        }
        Ok(rest)
    }

    /// A body held for a 100 goes now (`http_exp100_continue`).
    fn release<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        let open = Reading {
            eos_read: false,
            announced: true,
        };
        match &mut self.outgoing {
            Sending::Head { then, .. } if *then == AfterHead::Continue => {
                *then = AfterHead::Body(open);
            }
            Sending::HeadSent | Sending::AwaitingContinue(_) => {
                self.outgoing = Sending::Body(open);
            }
            _ => return,
        }
        state::trace_timer(cx, TimerKind::Proto, format_args!("cleared"));
    }

    /// An error response came before the body was all sent: it goes on if
    /// the application says so, and stops otherwise, the connection not
    /// used again (`http_handle_send_error`).
    fn send_error<H: Host>(&mut self, cx: &mut StepCx<'_, H>, code: u16) -> Result<(), ErrorKind> {
        let meta = self.head().meta();
        if !self.sending() || meta.close() || meta.rewinds() {
            return Ok(());
        }
        if code == 417 && self.outgoing.announced() {
            // Made again without `Expect`, its body started over if any
            // went.
            if self.body_sent == 0 && matches!(self.outgoing, Sending::AwaitingContinue(_)) {
                trace::info(
                    cx,
                    format_args!("Got HTTP failure 417 while waiting for a 100"),
                );
            } else {
                trace::info(cx, format_args!("Got HTTP failure 417 while sending data"));
                self.closing = true;
                if self
                    .body
                    .as_ref()
                    .is_some_and(|b| b.upload().needs_rewind())
                {
                    needs_rewind(cx);
                    trace::info(cx, format_args!("Need to rewind upload for next request"));
                    self.head.as_mut().expect("made at DO").meta_mut().rewind();
                }
            }
            self.expect_refused = true;
            self.upload_done(cx, true);
            return Ok(());
        }
        if cx.easy().options().http.keep_sending_on_error {
            trace::info(
                cx,
                format_args!("HTTP error before end of send, keep sending"),
            );
            self.release(cx);
        } else {
            trace::info(
                cx,
                format_args!("HTTP error before end of send, stop sending"),
            );
            self.closing = true;
            self.upload_done(cx, true);
        }
        Ok(())
    }

    /// The final head ended: what it expects of the body (`http_size`).
    fn body_start<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        let head = self.head.as_ref().expect("made at DO");
        for named in head.meta().transfer_codings() {
            self.pipeline
                .add_transfer_decoder(decoder_for(cx, named)?)?;
        }
        let framing = head.framing().expect("a final head decides its framing");
        let size = head.meta().size();
        let no_body = self.method == Method::Head;
        if size.is_some() {
            self.pipeline.announce_size(cx, size);
        }
        self.pipeline.expect(Expect {
            size,
            max: size,
            no_body,
            no_head: false,
            ignore: head.meta().ignore_body(),
        });
        self.stage = match framing {
            // Over HTTP/2, a body, if any, ends with the stream.
            Framing::Abandoned => Stage::Done,
            _ if self.h2.is_some() => Stage::Body(Body::Stream),
            Framing::None => Stage::Done,
            Framing::Length(_) => Stage::Body(Body::Length),
            Framing::Chunked => {
                let raw = cx.easy().options().http.raw;
                Stage::Body(Body::Chunked(ChunkDecoder::new(
                    raw,
                    head.lines(),
                    head.request_bytes(),
                )))
            }
            Framing::UntilClose => Stage::Body(Body::UntilClose),
        };
        Ok(())
    }

    /// Decode chunks from `input`; what is left, which is nothing unless
    /// the body ended.
    fn chunked_input<'i, H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        input: &'i [u8],
    ) -> Result<&'i [u8], ErrorKind> {
        let raw = cx.easy().options().http.raw;
        let read = self.chunks(cx, input, raw);
        // As C writes it all at once to the chain the chunked decoder is in
        // (`Curl_client_write`).
        deliver::client_write(cx, WriteType::BODY, input.len(), read);
        read.map(|()| &[][..])
    }

    /// `chunked_input`'s reading of the chunks in `input`.
    fn chunks<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        input: &[u8],
        raw: bool,
    ) -> Result<(), ErrorKind> {
        let Request {
            pipeline, stage, ..
        } = self;
        let Stage::Body(Body::Chunked(decoder)) = stage else {
            unreachable!("reading chunks");
        };
        // Traced as it came, chunk lines, trailers and what follows the
        // last chunk with it, as C traces it before decoding; raw, it is
        // passed on as it came too, and the decoder only finds the end.
        pipeline.trace_raw(cx, input);
        if raw {
            pipeline.decoded(cx, input)?;
        }
        let mut piece = input;
        while !piece.is_empty() {
            let header_size = &mut cx.report_mut().sizes_mut().header;
            let (used, event) = match decoder.feed(piece, header_size) {
                Ok(fed) => fed,
                Err(e) => {
                    if let ChunkError::BadEnd(b) = e {
                        write_trace(
                            cx,
                            format_args!("http_chunk error, expected 0x0a, seeing 0x{b}x"),
                        );
                    }
                    return Err(chunks_failed(cx, &e));
                }
            };
            match event {
                Some(ChunkEvent::Start(size)) => write_trace(
                    cx,
                    format_args!("http_chunked, chunk start of {size} bytes"),
                ),
                Some(ChunkEvent::Data { data, left }) => {
                    if !raw {
                        pipeline.decoded(cx, data)?;
                    }
                    write_trace(
                        cx,
                        format_args!(
                            "http_chunked, write {} body bytes, {left} bytes in chunk remain",
                            data.len()
                        ),
                    );
                }
                Some(ChunkEvent::Trailer { line, then }) => {
                    let written = pipeline.header(cx, line, HeaderOrigin::Trailer);
                    if trace::traces(cx, Component::Write) {
                        write_trace_with(cx, &[b"wrote trailer '", line, b"'"]);
                    }
                    if let Err(e) = written {
                        return Err(trace::fail(
                            cx,
                            e,
                            format_args!("Failed reading the chunked-encoded stream"),
                        ));
                    }
                    then.map_err(|e| chunks_failed(cx, &e))?;
                }
                Some(ChunkEvent::Done) => {
                    write_trace(cx, format_args!("http_chunk, response complete"));
                    let left = piece.len() - used;
                    if left > 0 {
                        trace::info(cx, format_args!("Leftovers after chunking: {left} bytes"));
                    }
                    *stage = Stage::Done;
                    return Ok(());
                }
                None => {}
            }
            piece = &piece[used..];
        }
        Ok(())
    }

    /// The connection closed: the response must be whole
    /// (`CLIENTWRITE_EOS`, then `Curl_sendrecv`'s check).
    fn end<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        match &self.stage {
            Stage::Head => {
                let no_body = self.method == Method::Head;
                match self.head().meta().size() {
                    Some(size) if size > 0 && !no_body => Err(trace::fail(
                        cx,
                        ErrorKind::PartialFile,
                        format_args!("transfer closed with {size} bytes remaining to read"),
                    )),
                    _ => Ok(()),
                }
            }
            Stage::Body(Body::Length | Body::UntilClose | Body::Stream) => self.pipeline.end(cx),
            Stage::Body(Body::Chunked(decoder)) => match decoder.finish() {
                Ok(()) => Ok(()),
                Err(e) => Err(chunks_failed(cx, &e)),
            },
            Stage::Done => Ok(()),
        }
    }

    /// The connection is not used again (C's `conn->bits.close`): the
    /// response's head says so (`Connection: close`, a body read until
    /// the connection closes), its body showed more than it should, or
    /// the request decided it (`streamclose`).
    fn closes(&self) -> bool {
        self.head().meta().close() || self.pipeline.body_closes() || self.closing
    }

    /// The request is over (`Curl_http_done`): a line still held is
    /// delivered, whatever came of it; a reply with nothing in it is an
    /// error, unless the request is to be made again; the connection is
    /// kept only if the response allows.
    pub(crate) fn done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
        premature: bool,
        next: &AfterRequest,
        inherited: &mut Inherited,
    ) -> Result<(), ErrorKind> {
        // A stream still open goes (`http2_data_done`).
        if self.h2.is_some() {
            self.h2_done(cx, lease);
        }
        let Some(head) = self.head.as_ref() else {
            // The request was never made.
            return result;
        };
        // Whatever comes of the request, the next says HTTP/1.0 if a
        // response to it did.
        if head.saw_http10() {
            inherited.http10 = true;
        }
        let held = head.held();
        if !held.is_empty() {
            let mut line = Vec::new();
            line.try_extend_from_slice(held)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            trace::bytes(cx, DebugKind::HeaderIn, &line);
            let origin = if self.interim {
                HeaderOrigin::Interim
            } else {
                HeaderOrigin::Header
            };
            // C ignores what comes of it.
            if self.pipeline.header(cx, &line, origin).is_ok() {
                let head = self.head.as_mut().expect("made at DO");
                let _counted =
                    head.count_held(line.len() as u64, &mut cx.report_mut().sizes_mut().header);
            }
        }
        let head = self.head.as_ref().expect("made at DO");
        if let Some(seen) = head.last_version() {
            lease.get().saw_version(seen);
        }
        if self.closes() {
            lease.get().mark_close();
        }
        result?;
        if !premature && *next != AfterRequest::Retry && head.got_nothing(self.pipeline.bytecount())
        {
            lease.get().mark_close();
            return Err(trace::fail(
                cx,
                ErrorKind::GotNothing,
                format_args!("Empty reply from server"),
            ));
        }
        Ok(())
    }
}

/// The next request is one a `code` redirect leads to, "Issue another
/// request" said (`Curl_http_follow`): a custom method asked only of the
/// first URL is dropped, and the method switches to GET where the code
/// and `CURLOPT_POSTREDIR` say (`follow_switch_get`). Whether it switched.
pub(crate) fn redirected<H: Host>(
    cx: &mut StepCx<'_, H>,
    code: u16,
    method: &mut Method,
    inherited: &mut Inherited,
) -> bool {
    let http = &cx.easy().options().http;
    let custom = http.custom.method.is_some();
    if http.follow == Follow::FirstOnly && custom && !inherited.ignore_custom {
        inherited.ignore_custom = true;
        trace::info(
            cx,
            format_args!("Drop custom request method for next request"),
        );
    }
    let http = &cx.easy().options().http;
    let switched = follow::switches_to_get(code, *method, http.post_redirect);
    if switched {
        switch_to_get(cx, code, method, inherited);
    }
    switched
}

/// The next request asks for a GET (`http_switch_to_get`): traced and the
/// custom method dropped only if the redirect's code is obeyed.
fn switch_to_get<H: Host>(
    cx: &mut StepCx<'_, H>,
    code: u16,
    method: &mut Method,
    inherited: &mut Inherited,
) {
    let http = &cx.easy().options().http;
    let custom = http.custom.method.as_deref();
    // Formatted before it is traced, as the debug handler may set the
    // custom method, and the next request uses what it sets.
    let said = if (custom.is_some() || *method != Method::Get) && http.follow == Follow::ObeyCode {
        inherited.ignore_custom = true;
        Some(trace::line(format_args!(
            "Switch to GET because of {code} response"
        )))
    } else if let Some(custom) = custom
        && http.follow != Follow::FirstOnly
    {
        let custom = trace::Bytes(custom);
        Some(trace::line(format_args!(
            "Stick to {custom} instead of GET"
        )))
    } else {
        None
    };
    if let Some(said) = said {
        trace::info_line(cx, &said);
    }
    // A HEAD stays bodyless, as `CURLOPT_NOBODY` keeps it.
    if *method != Method::Head {
        *method = Method::Get;
    }
}

/// `n` zero bytes after what `out` holds.
pub(crate) fn zeros(out: &mut Vec<u8>, mut n: usize) -> Result<(), OutOfMemory> {
    const ZEROS: [u8; 4096] = [0; 4096];
    while n > 0 {
        let k = n.min(ZEROS.len());
        out.try_extend_from_slice(&ZEROS[..k])?;
        n -= k;
    }
    Ok(())
}

/// The trailers a chunked body ends with, each line with its CRLF: the
/// trailer handler's lines that read `Name: value` (`add_last_chunk`).
fn trailer_block<H: Host>(cx: &mut StepCx<'_, H>) -> Result<Vec<u8>, ErrorKind> {
    let mut block = Vec::new();
    let Some(handler) = cx.easy().options().callbacks.trailer.clone() else {
        return Ok(block);
    };
    let mut lines = TrailerLines::default();
    if handler.trailers(&mut TransferCx::new(cx), &mut lines) == Trailers::Abort {
        return Err(trace::fail(
            cx,
            ErrorKind::AbortedByCallback,
            format_args!("operation aborted by trailing headers callback"),
        ));
    }
    for line in lines.lines().map_err(|_| ErrorKind::OutOfMemory)? {
        let colon = line.iter().position(|&b| b == b':');
        if colon.is_none_or(|at| line.get(at + 1) != Some(&b' ')) {
            trace::info(
                cx,
                format_args!("Malformatted trailing header, skipping trailer"),
            );
            continue;
        }
        block
            .try_extend_from_slice(line)
            .and_then(|()| block.try_extend_from_slice(b"\r\n"))
            .map_err(|_| ErrorKind::OutOfMemory)?;
    }
    Ok(block)
}

/// The body was read, and must be rewound for another request to send
/// it (`Curl_creader_needs_rewind`).
fn needs_rewind<H: Host>(cx: &mut StepCx<'_, H>) {
    trace::of(
        cx,
        Component::Read,
        format_args!("client reader needs rewind before next request"),
    );
}

/// A copy of `bytes`; out of memory fails the transfer.
/// Where a request goes, as its cookies see it.
fn cookie_site<'a>(
    custom_host: &'a Option<Vec<u8>>,
    target: &'a [u8],
    peer: &'a Peer,
) -> cookies::Site<'a> {
    cookies::Site {
        host: custom_host.as_deref().unwrap_or(peer.name()),
        path: target.split(|&b| b == b'?').next().unwrap_or_default(),
        secured: peer.scheme() == HTTPS,
    }
}

/// What follows `name` in a header line that starts with it, in any
/// case.
/// Stack a decoder for each of a `Content-Encoding`'s codings, in the
/// order given, to be undone last first (`Curl_build_unencoding_stack`):
/// none if they are not to be undone, and one that fails the body for a
/// coding nothing undoes.
fn content_codings<H: Host>(
    cx: &mut StepCx<'_, H>,
    pipeline: &mut Pipeline,
    list: &[u8],
) -> Result<(), ErrorKind> {
    for name in framing::coding_names(list) {
        write_trace_with(cx, &[b"looking for content decoder: ", name]);
        if cx.easy().options().http.raw_content {
            write_trace_with(cx, &[b"decoder not requested, ignored: ", name]);
            return Ok(());
        }
        if pipeline.decoders() >= MAX_CONTENT_CODINGS {
            return Err(trace::fail(
                cx,
                ErrorKind::BadContentEncoding,
                format_args!(
                    "Reject response exceeding limit of {MAX_CONTENT_CODINGS} content encodings"
                ),
            ));
        }
        let named = Named::of(name);
        let decoder = decoder_for(cx, named)?;
        let decoders = cx.easy().decoders();
        write_trace(
            cx,
            format_args!(
                "added content decoder {} -> 0",
                decoder_name(Some(named), &decoders)
            ),
        );
        pipeline.add_decoder(decoder)?;
    }
    Ok(())
}

/// What reading a `Transfer-Encoding` list did with each name
/// (`Curl_build_unencoding_stack`).
fn trace_codings<H: Host>(cx: &mut StepCx<'_, H>, tale: CodingTale<'_>) {
    if !trace::traces(cx, Component::Write) {
        return;
    }
    let decoders = cx.easy().decoders();
    tale.retell(|step| match step {
        CodingStep::Looking(name) => {
            write_trace_with(cx, &[b"looking for transfer decoder: ", name]);
        }
        CodingStep::Ignored(name) => {
            write_trace_with(cx, &[b"decoder not requested, ignored: ", name]);
        }
        CodingStep::Duplicate => {
            write_trace(cx, format_args!("ignoring duplicate 'chunked' decoder"));
        }
        CodingStep::Added(named) => write_trace(
            cx,
            format_args!(
                "added transfer decoder {} -> 0",
                decoder_name(named, &decoders)
            ),
        ),
    });
}

/// The name of the decoder C stacks for a coding, chunked for none: its
/// writer's, the error writer's for one the handle cannot undo.
fn decoder_name(named: Option<Named>, decoders: &Decoders) -> &'static str {
    match named {
        None => "chunked",
        Some(Named::Identity) => "identity",
        Some(Named::Coding(coding)) if decoders.maker(coding).is_some() => coding.name(),
        Some(Named::Coding(_) | Named::Unknown) => "ce-error",
    }
}

/// A decoder for a coding a response names: one passing the body by for
/// `identity`, one failing it for a coding the handle cannot undo.
fn decoder_for<H: Host>(cx: &StepCx<'_, H>, named: Named) -> Result<Box<dyn Decoder>, ErrorKind> {
    let oom = |_| ErrorKind::OutOfMemory;
    Ok(match named {
        Named::Identity => try_box(Identity).map_err(oom)?,
        Named::Coding(coding) => match cx.easy().decoders().maker(coding) {
            Some(make) => make()?,
            None => try_box(Unrecognized).map_err(oom)?,
        },
        Named::Unknown => try_box(Unrecognized).map_err(oom)?,
    })
}

/// The most content codings a response may stack (`MAX_ENCODE_STACK`).
const MAX_CONTENT_CODINGS: usize = 5;

fn strip_name<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    (line.len() >= name.len() && line[..name.len()].eq_ignore_ascii_case(name))
        .then(|| &line[name.len()..])
}

fn copied(bytes: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut copy = Vec::new();
    copy.try_extend_from_slice(bytes)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    Ok(copy)
}

/// Why the head is refused, said as C says it.
fn head_failed<H: Host>(cx: &mut StepCx<'_, H>, e: &HeadError) -> ErrorKind {
    if e.says() {
        trace::fail(cx, e.kind(), format_args!("{e}"))
    } else {
        e.kind()
    }
}

/// The version a request goes in, `wanted` the application's: HTTP/1.0
/// after a response in it to the transfer, or on a connection whose last
/// response was in it (`http_may_use_1_1`).
fn version(
    wanted: HttpVersion,
    after_http10: bool,
    seen: Option<ResponseVersion>,
    h2: bool,
) -> SentIn {
    if h2 {
        SentIn::Http2
    } else if after_http10 || seen == Some(ResponseVersion::Http10) || wanted == HttpVersion::Http10
    {
        SentIn::Http10
    } else {
        SentIn::Http11
    }
}

/// Why the chunks are refused: the reason, then the chunked writer's
/// summary (`cw_chunked_write`).
fn chunks_failed<H: Host>(cx: &mut StepCx<'_, H>, e: &ChunkError) -> ErrorKind {
    if *e == ChunkError::OutOfMemory {
        return e.kind();
    }
    if let Some(reason) = e.reason() {
        trace::fail(cx, e.kind(), format_args!("{reason}"));
    }
    trace::fail(cx, e.kind(), format_args!("{e}"))
}

#[cfg(test)]
mod suite;
#[cfg(test)]
mod tests;

/// A line of the write trace (`CURL_TRC_WRITE`).
fn write_trace<H: Host>(cx: &mut StepCx<'_, H>, args: std::fmt::Arguments<'_>) {
    trace::of(cx, Component::Write, args);
}

/// `write_trace` with a line made of `parts`, which need not be text.
fn write_trace_with<H: Host>(cx: &mut StepCx<'_, H>, parts: &[&[u8]]) {
    trace::of_with(cx, Component::Write, parts);
}
