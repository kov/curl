//! `http:`, HTTP/1 over a connection: the request head sent at DO, the
//! response read, parsed and delivered, and its end judged (`lib/http.c`'s
//! `Curl_http`, `Curl_http_write_resp` and `Curl_http_done`, and
//! `lib/transfer.c`'s receive loop).

use curl_alloc::TryVec as _;

use crate::conn::io::{Events, Recv, Sent};
use crate::conn::{ConnLease, Peer, RecvFailed};
use crate::deliver::{Expect, Pause, Pipeline, Reach};
use crate::error::{ErrorKind, UrlErrorKind};
use crate::handler::{DebugKind, HeaderOrigin, TrailerLines, Trailers};
use crate::multi::Host;
use crate::multi::TransferCx;
use crate::multi::state::{AfterRequest, OsError, StepCx, url_error};
use crate::options::{Follow, Http, HttpVersion, Method, Resume, UploadSource};
use crate::report::{ResponseVersion, Timer};
use crate::time::Instant;
use crate::trace;
use crate::upload::{self, Upload};
use crate::url::{GetOptions, Part, SetOptions, Url};

use super::http1::chunked::{ChunkDecoder, ChunkEncoder, ChunkError, ChunkEvent};
use super::http1::framing::{self, Asked, Framing};
use super::http1::request::{self, Authorization, CredentialGate, RequestHead};
use super::{Inherited, ProtoStep};
use crate::netrc::{self, NetrcError};
use crate::options::AuthMethods;
use crate::options::NetrcMode;
use auth::{
    AuthAct, AuthRequest, Credentials, CredentialsError, NetrcLookup, Offered, Output, OutputError,
    Secret, Side,
};
use std::ffi::CStr;

pub(crate) mod auth;
pub(crate) mod cookies;
pub(crate) mod digest;
use super::http1::response::{self, Exchange, HeadError, HeadEvent, HeadParser, LineKind};

/// The most one read takes (`CURL_MAX_WRITE_SIZE`, BUFFERSIZE's default).
const READ_SIZE: usize = 16384;

/// The send buffer the head and the body share (`UPLOADBUFFER_DEFAULT`).
const UPLOAD_BUFFER: usize = 65536;

/// A body larger than this asks `Expect: 100-continue` on HTTP/1.1.
const EXPECT_100_THRESHOLD: u64 = 1024 * 1024;

/// What a request's body is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyKind {
    /// A POST's, a form by default (`HTTPREQ_POST`).
    Form,
    /// A PUT's.
    Put,
}

/// The port a URL without one means.
const DEFAULT_PORT: u16 = 80;

/// What a final response's challenges offered and led to, its code, and
/// the origin the request authenticated with.
pub(crate) struct Challenged<'r> {
    pub(crate) offered: Offered,
    pub(crate) act: AuthAct,
    pub(crate) code: u16,
    pub(crate) origin: &'r Peer,
}

/// Digest's client nonce.
fn random(bytes: &mut [u8; 12]) -> Result<(), ()> {
    curl_os::random::fill(bytes).map_err(|_| ())
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
    version: HttpVersion,
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
    /// `UPLOAD_BUFFER` bytes. `out[sent..filled]` is still to go, the
    /// first `head_left` of it the head's.
    out: Vec<u8>,
    filled: usize,
    sent: usize,
    head_left: usize,
    /// The body, read at DO and as what is read goes.
    upload: Option<Upload>,
    /// The body is sent chunked, framed here as it is read.
    chunks: Option<ChunkEncoder>,
    /// The body is read to its end (`eos_read`).
    eos_read: bool,
    /// Body bytes sent (`writebytecount`).
    body_sent: u64,
    /// Everything is sent (`upload_done`); nothing is, before DO.
    sent_all: bool,
    /// Where the body stands behind `Expect: 100-continue`.
    expect: ExpectState,
    /// Sending stopped short of the body's end (`upload_aborted`).
    aborted: bool,
    /// Made at DO, once the connection says whether it is reused.
    head: Option<HeadParser>,
    stage: Stage,
    /// The current response is interim (1xx).
    interim: bool,
    /// The name a custom `Host:` header gives the cookies, in place of
    /// the URL's host.
    cookie_host: Option<Vec<u8>>,
    /// `Set-Cookie:` fields stored from the responses to this request.
    set_cookies: u8,
}

#[derive(Debug)]
enum Stage {
    Head,
    Body(Body),
    Done,
}

/// A body announced with `Expect: 100-continue` (C's `cr_exp100`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectState {
    /// None was announced.
    None,
    /// The head is still going; the wait starts once it has gone.
    Head,
    /// The body waits for a 100 until this instant.
    Awaiting(Instant),
    /// The 100 came, the wait ran out or an error response lets the body
    /// go on.
    Open,
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
}

/// `credentials` completed or replaced from a `.netrc` file, if the
/// options ask for one and leave room for it (`url_set_data_creds_netrc`).
fn with_netrc<H: Host>(
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

impl Request {
    /// A request for `url`, whose scheme is `http`, after the transfer's
    /// earlier ones left it `inherited`.
    pub(crate) fn new<H: Host>(
        url: &Url,
        inherited: &Inherited,
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
        let mut target = url.get(Part::Path, GetOptions::NONE).map_err(url_error)?;
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
        let peer = Peer::new(super::HTTP, host, port, super::zone(url)?);
        let gate = match inherited.first.as_deref() {
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
        let credentials = with_netrc(credentials, peer.shown(), cx)?;
        let cookie_host =
            cookies::custom_host(&cx.easy().options().http.headers, gate.same_origin())
                .map_err(|_| ErrorKind::OutOfMemory)?;
        Ok(Request {
            pipeline: Pipeline::new(Reach::Network),
            target,
            forward_target: None,
            credentials,
            peer,
            gate,
            method: inherited.method,
            custom: !inherited.ignore_custom,
            no_expect: inherited.no_expect,
            expect_refused: false,
            closing: false,
            version: cx.easy().options().http.version,
            after_http10: inherited.http10,
            out: Vec::new(),
            filled: 0,
            sent: 0,
            head_left: 0,
            upload: None,
            chunks: None,
            eos_read: false,
            body_sent: 0,
            sent_all: true,
            expect: ExpectState::None,
            aborted: false,
            head: None,
            stage: Stage::Head,
            interim: false,
            cookie_host,
            set_cookies: 0,
        })
    }

    /// Send the request whole to a proxy that sends it on: its target is
    /// `url` without its fragment and credentials, nor its scheme's port
    /// (`http_target`).
    pub(crate) fn forward(&mut self, url: &Url) -> Result<(), ErrorKind> {
        let mut url = url.try_clone().map_err(url_error)?;
        for part in [Part::Fragment, Part::User, Part::Password] {
            url.set(part, None, SetOptions::NONE).map_err(url_error)?;
        }
        let get = GetOptions {
            no_default_port: true,
            ..GetOptions::NONE
        };
        self.forward_target = Some(url.get(Part::Url, get).map_err(url_error)?);
        Ok(())
    }

    /// The host and port the request connects to.
    pub(crate) fn origin(&self) -> Result<(Vec<u8>, u16), ErrorKind> {
        let mut host = Vec::new();
        host.try_extend_from_slice(self.peer.shown())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        Ok((host, self.peer.port()))
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    /// Where the response's `Location:` points, as the server gave it.
    pub(crate) fn location(&self) -> Option<&[u8]> {
        self.head.as_ref()?.meta().location()
    }

    /// Where the response redirects to, if it is followed, and its code.
    pub(crate) fn follow(&self) -> Option<(&[u8], u16)> {
        let head = self.head.as_ref()?;
        Some((head.meta().follow()?, head.status()?.code))
    }

    /// What the final response's challenges offered and led to; the
    /// challenges are taken out, for the handle to keep.
    pub(crate) fn auth(&mut self) -> Option<Challenged<'_>> {
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

    /// A 417 refused the request's `Expect: 100-continue`.
    pub(crate) fn expect_refused(&self) -> bool {
        self.expect_refused
    }

    /// A response to the request said HTTP/1.0.
    pub(crate) fn saw_http10(&self) -> bool {
        self.head.as_ref().is_some_and(HeadParser::saw_http10)
    }

    /// Start the body over, for the next request to send it again.
    pub(crate) fn rewind_upload<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
    ) -> Result<(), ErrorKind> {
        match &mut self.upload {
            Some(upload) => upload.rewind(cx),
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
        !self.sent_all
    }

    /// When a body waiting for a 100 is sent anyway.
    pub(crate) fn wake_at(&self) -> Option<Instant> {
        match self.expect {
            ExpectState::Awaiting(until) if self.sending() => Some(until),
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
        let waiting = matches!(self.expect, ExpectState::Awaiting(_));
        if self.sending() && !pause.send_paused() && !waiting {
            events = events | Events::OUT;
        }
        events
    }

    /// The method the request line names: the application's own, unless
    /// a follow dropped it.
    fn method_line<'o>(&self, http: &'o Http) -> &'o [u8] {
        let custom = http.custom_method.as_deref().filter(|_| self.custom);
        custom.unwrap_or(self.method.name())
    }

    /// Render the head and send what the connection takes now (`Curl_http`).
    pub(crate) fn do_it<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
    ) -> Result<(), ErrorKind> {
        let reused = cx.conn(lease).reused();
        let http_proxy = cx.conn(lease).http_proxy();
        self.version = version(
            cx.easy().options().http.version,
            self.after_http10,
            cx.conn(lease).seen_version(),
        );
        // The proxy the request goes to whole, and what it is given.
        let forwarding = cx
            .conn(lease)
            .forwarding()
            .map(|p| (p.peer.clone(), p.creds.clone()));
        let forwarded = forwarding.is_some();
        let get_or_head = matches!(self.method, Method::Get | Method::Head);
        let credentials = self.credentials.as_ref().map(Credentials::secret);
        // Without one, nothing goes to a proxy: its side is done at once,
        // as for its own peer.
        let (proxy_peer, proxy_secret) = match &forwarding {
            Some((peer, creds)) => (
                &**peer,
                creds.as_deref().map(|c| Secret::new(&c.user, &c.password)),
            ),
            None => (&self.peer, None),
        };
        let (auth_state, options) = cx.easy_mut().auth_with_options();
        let http = &options.http;
        let method = self.method_line(http);
        // The proxy's first, as C's `Curl_http_output_auth` makes them.
        let request = AuthRequest {
            origin: proxy_peer,
            method,
            uri: &self.target,
            get_or_head,
        };
        // The application's proxy headers, which would replace it, are
        // none: its own headers are kept apart from them, and go beside
        // (`Curl_checkProxyheaders`, with `sep_headers`).
        let proxy_auth = made(auth_state.side(Side::Proxy).output(
            proxy_secret,
            false,
            &request,
            random,
        ))?;
        let request = AuthRequest {
            origin: &self.peer,
            ..request
        };
        let custom = http.headers.replaces(b"Authorization");
        let auth = made(
            auth_state
                .side(Side::Host)
                .output(credentials, custom, &request, random),
        )?;
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
        let method = self.method_line(http);
        let body = match self.method {
            Method::Get | Method::Head => None,
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
        // A probe goes without its body, saying it has none
        // (`Curl_creader_set_null`).
        let mut upload = body
            .filter(|_| !probe)
            .map(|_| Upload::new(&options.upload));
        let size = if probe {
            Some(0)
        } else {
            upload.as_ref().and_then(Upload::size)
        };
        // The application's Transfer-Encoding decides whether the body is
        // chunked; otherwise one of unknown size is, which HTTP/1.0 cannot
        // send (`http_req_set_TE`).
        let size_unknown = upload.is_some() && size.is_none();
        let asked = http.headers.asks_chunked();
        if asked.is_none() && size_unknown && self.version == HttpVersion::Http10 {
            return Err(trace::fail(
                cx,
                ErrorKind::UploadFailed,
                format_args!("Chunky upload is not supported by HTTP 1.0"),
            ));
        }
        let chunked = asked.unwrap_or(size_unknown);
        // Even a request without a body sends a last chunk if chunked.
        if chunked && upload.is_none() {
            upload = Some(Upload::new(&UploadSource::None));
        }
        let mut content = body.map(|kind| request::Content {
            length: size.filter(|_| !chunked),
            form: kind == BodyKind::Form,
            expect: false,
        });
        // `Expect: 100-continue`, asked for, or added on HTTP/1.1 for a
        // body large or of unknown size, holds the body back until a 100
        // comes or the wait runs out (`addexpect`).
        let expects = http.headers.expects_continue();
        let added_expect = content.is_some()
            && expects.is_none()
            && !self.no_expect
            && self.version == HttpVersion::Http11
            && size.is_none_or(|n| n > EXPECT_100_THRESHOLD);
        let expect_state =
            if content.is_some() && !auth.probe && (expects == Some(true) || added_expect) {
                ExpectState::Head
            } else {
                ExpectState::None
            };
        if let Some(content) = &mut content {
            content.expect = added_expect;
        }
        let resume_from = match options.resume {
            None => None,
            Some(Resume::At(at)) => Some(at.get()),
            // C's -1, which for a download names no range a server knows.
            Some(Resume::AtEnd) => return Err(ErrorKind::NotBuiltIn),
        };
        let port = self.peer.port();
        let shown_port = (port != DEFAULT_PORT).then_some(port);
        let gate = self.gate;
        let authorization = match (&self.credentials, &auth.header) {
            // Digest goes beside the application's own Authorization, as
            // C's does (`H1_HD_AUTH`).
            (Some(c), Some((AuthMethods::DIGEST, value))) => {
                Some(Authorization::alongside("Digest", value, c.trusted()))
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
            target: self
                .forward_target
                .as_deref()
                .filter(|_| forwarded)
                .unwrap_or(&self.target),
            version: self.version,
            host: self.peer.shown(),
            port: shown_port,
            user_agent: http.user_agent.as_deref(),
            referer: cx.easy().report().referer(),
            proxy_authorization,
            authorization,
            range_from: resume_from,
            content,
            chunked: chunked && asked.is_none(),
            probe,
            cookie: cookie.as_deref(),
            forwarded,
            headers: &http.headers,
        };
        let mut out = Vec::new();
        request::render_h1(&head, &gate, &mut out)?;
        let exchange = Exchange {
            sent: match self.version {
                HttpVersion::Http10 => response::HttpVersion::Http10,
                HttpVersion::Http11 => response::HttpVersion::Http11,
            },
            reused,
            allow_09: http.allow_09,
            asked: Asked {
                head: self.method == Method::Head,
                ignore_length: http.ignore_content_length,
                max_filesize: options.limits.max_filesize,
                decode_codings: http.transfer_encoding,
                raw_codings: http.raw,
                fail_on_error: http.fail_on_error,
                resume_from: resume_from.filter(|_| self.method == Method::Get),
                follow: http.follow != Follow::No,
                auth: auth_asked,
                http_proxy,
                forwarded,
            },
        };
        if let Some(method) = proxy_auth.header.as_ref().map(|(m, _)| m) {
            let user = proxy_secret.map_or(&b""[..], |s| s.user());
            let name = method.name().as_bytes();
            trace::info_with(
                cx,
                &[b"Proxy auth using ", name, b" with user '", user, b"'"],
            );
        }
        if let Some(method) = authenticated {
            let user = self.credentials.as_ref().map_or(&b""[..], |c| c.user());
            let name = method.name().as_bytes();
            trace::info_with(
                cx,
                &[b"Server auth using ", name, b" with user '", user, b"'"],
            );
        }
        let head_len = out.len();
        if upload.is_some() {
            // The body goes behind the head, in what is left of one
            // buffer (`Curl_req_send`).
            let room = UPLOAD_BUFFER.saturating_sub(head_len);
            out.try_reserve_exact(room)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            out.try_extend_from_slice(&[0; UPLOAD_BUFFER][..room])
                .map_err(|_| ErrorKind::OutOfMemory)?;
            upload::announce_size(cx, content.and_then(|c| c.length));
        }
        self.out = out;
        self.filled = head_len;
        self.sent = 0;
        self.head_left = head_len;
        self.eos_read = upload.is_none();
        self.upload = upload;
        self.chunks = if chunked {
            Some(ChunkEncoder::new().map_err(|_| ErrorKind::OutOfMemory)?)
        } else {
            None
        };
        self.body_sent = 0;
        self.sent_all = false;
        self.expect = expect_state;
        self.aborted = false;
        self.head = Some(HeadParser::new(exchange));
        // A body held for a 100 is not read behind the head.
        if expect_state == ExpectState::None
            && !self.eos_read
            && self.filled < self.out.len()
            && !cx.pause().send_paused()
        {
            self.fill(cx)?;
        }
        // The engine takes the request as sent at DID if it went now.
        self.send(cx, lease).map(drop)
    }

    /// Read body into the buffer behind what is there: whether anything
    /// came or the body ended (`add_from_client`).
    fn fill<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<bool, ErrorKind> {
        let pausable = self.pipeline.pausable();
        let upload = self.upload.as_mut().expect("a body to read");
        let dest = &mut self.out[self.filled..];
        let got = match &mut self.chunks {
            None => upload.read(cx, dest, pausable)?,
            Some(chunks) => {
                if let Some(room) = chunks.wants(dest.len()) {
                    let got = upload.read(cx, room, pausable)?;
                    let end = if got.eos {
                        Some(trailer_block(cx)?)
                    } else {
                        None
                    };
                    chunks
                        .got(got.n, end.as_deref())
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                }
                let (n, eos) = chunks.take(dest);
                upload::Readout { n, eos }
            }
        };
        self.filled += got.n;
        self.eos_read = got.eos;
        Ok(got.n > 0 || got.eos)
    }

    /// Send what is left of the request, reading more of its body as
    /// what was read goes, as much as the connection takes: whether it all
    /// went, the request sent (`Curl_req_send_more`,
    /// `req_set_upload_done`).
    fn send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
    ) -> Result<bool, ErrorKind> {
        while self.sending() {
            if self.sent == self.filled {
                if self.eos_read {
                    self.sent_all = true;
                    break;
                }
                self.sent = 0;
                self.filled = 0;
                // The head has gone: a body announced with `Expect:
                // 100-continue` waits for the 100, or until the wait runs
                // out (`cr_exp100_read`).
                match self.expect {
                    ExpectState::Head => {
                        let wait = cx.easy().options().http.continue_wait.0;
                        self.expect = ExpectState::Awaiting(cx.now().after(wait));
                        return Ok(false);
                    }
                    ExpectState::Awaiting(until) if cx.now() < until => return Ok(false),
                    ExpectState::Awaiting(_) => {
                        self.expect = ExpectState::Open;
                        trace::info(cx, format_args!("Done waiting for 100-continue"));
                    }
                    ExpectState::None | ExpectState::Open => {}
                }
                if cx.pause().send_paused() || !self.fill(cx)? {
                    return Ok(false);
                }
                continue;
            }
            let sent = cx.conn(lease).send(&self.out[self.sent..self.filled]);
            let n = match sent {
                Ok(Sent::Bytes(n)) => n.get(),
                Ok(Sent::WouldBlock) => return Ok(false),
                Err(e) => {
                    let why = OsError(&e);
                    return Err(trace::fail(
                        cx,
                        ErrorKind::SendError,
                        format_args!("Send failure: {why}"),
                    ));
                }
            };
            // The head's part and the body's are traced apart
            // (`xfer_send`); both count as the request's.
            let head = n.min(self.head_left);
            if head > 0 {
                trace::bytes(
                    cx,
                    DebugKind::HeaderOut,
                    &self.out[self.sent..self.sent + head],
                );
            }
            upload::sent(cx, &self.out[self.sent + head..self.sent + n]);
            cx.report_mut().sizes_mut().request += n as u64;
            self.head_left -= head;
            self.body_sent += (n - head) as u64;
            self.sent += n;
        }
        self.upload_done(cx);
        Ok(true)
    }

    /// Nothing more of the request goes, all of it sent or not
    /// (`req_set_upload_done`).
    fn upload_done<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        self.sent_all = true;
        self.sent = self.filled;
        let n = self.body_sent;
        if self.aborted {
            if n > 0 {
                trace::info(cx, format_args!("abort upload after having sent {n} bytes"));
            } else {
                trace::info(cx, format_args!("abort upload"));
            }
        } else if n > 0 {
            trace::info(cx, format_args!("upload completely sent off: {n} bytes"));
        } else if !matches!(self.stage, Stage::Done) {
            let sized = self
                .upload
                .as_ref()
                .and_then(Upload::size)
                .is_some_and(|n| n > 0);
            let said = if sized {
                "We are completely uploaded and fine"
            } else {
                "Request completely sent off"
            };
            trace::info(cx, format_args!("{said}"));
        }
    }

    /// Send what is left, then read until the connection has nothing more
    /// now, the response is over or receiving pauses (`Curl_sendrecv`).
    pub(crate) fn step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        self.pipeline.flush(cx)?;
        if self.sending() && self.send(cx, lease)? {
            // Sent after DID: the request is complete from here.
            cx.mark(Timer::PostTransfer);
        }
        loop {
            // The request is over once its response is and nothing more of
            // it is to send (`KEEP_RECV` and `KEEP_SEND` both off).
            if matches!(self.stage, Stage::Done) {
                return Ok(if self.sending() {
                    ProtoStep::Blocked
                } else {
                    ProtoStep::Done
                });
            }
            if cx.pause().recv_paused() {
                return Ok(ProtoStep::Blocked);
            }
            let max = self.read_size();
            if max == 0 {
                // The body is whole: nothing more is read for it.
                self.stage = Stage::Done;
                continue;
            }
            match cx.conn(lease).recv(max) {
                Ok(Recv::WouldBlock) => return Ok(ProtoStep::Blocked),
                Ok(Recv::Eof) => {
                    self.end(cx)?;
                    self.stage = Stage::Done;
                }
                Ok(Recv::Data(_)) => {
                    let mut rx = std::mem::take(cx.conn(lease).rx_mut());
                    let fed = self.input(cx, rx.filled());
                    let all = rx.filled().len();
                    rx.consume(all);
                    *cx.conn(lease).rx_mut() = rx;
                    fed?;
                }
                Err(RecvFailed::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
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

    /// How much the next read may take: a body of a known size is read no
    /// further than its end (`xfer_recv_resp`).
    fn read_size(&self) -> usize {
        match self.stage {
            Stage::Body(Body::Length) => {
                let left = self
                    .head()
                    .meta()
                    .size()
                    .expect("a body by length has one")
                    .saturating_sub(self.pipeline.bytecount());
                usize::try_from(left).map_or(READ_SIZE, |left| left.min(READ_SIZE))
            }
            _ => READ_SIZE,
        }
    }

    fn head(&self) -> &HeadParser {
        self.head.as_ref().expect("made at DO")
    }

    /// Read what came, all of it (`Curl_http_write_resp`).
    fn input<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        mut input: &[u8],
    ) -> Result<(), ErrorKind> {
        while !input.is_empty() {
            match self.stage {
                Stage::Head => input = self.head_input(cx, input)?,
                Stage::Body(Body::Length | Body::UntilClose) => {
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
    /// `input`.
    fn head_input<'i, H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        input: &'i [u8],
    ) -> Result<&'i [u8], ErrorKind> {
        let Request {
            pipeline,
            head,
            interim,
            upload,
            ..
        } = self;
        let head = head.as_mut().expect("made at DO");
        // Only a status line changes it, so for a header line it is what
        // it was before.
        let bodyless = head.meta().bodyless();
        let (used, event) = head
            .feed(input, &mut cx.report_mut().sizes_mut().header)
            .map_err(|e| head_failed(cx, &e))?;
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
            trace::info(cx, format_args!("{note}"));
        }
        // The body goes again with the next request (`http_perhapsrewind`).
        if line.redirects && upload.as_ref().is_some_and(Upload::needs_rewind) {
            trace::info(cx, format_args!("Need to rewind upload for next request"));
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
        // A cookie is stored before its line is traced (`http_header`).
        if line.kind == LineKind::Header
            && let Some(value) = strip_name(line.bytes, b"Set-Cookie:")
        {
            let site = cookie_site(&self.cookie_host, &self.target, &self.peer);
            cookies::set_by_server(cx, value, &site, &mut self.set_cookies)?;
        }
        let early = line.early.map_err(|e| head_failed(cx, &e));
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
                pipeline.status(cx, line.bytes)?;
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
                self.body_start(cx);
                self.pipeline.header(cx, blank, origin)?;
            }
            LineKind::End { .. } => pipeline.header(cx, line.bytes, origin)?,
        }
        early?;
        then.map_err(|e| head_failed(cx, &e))?;
        if let LineKind::End { interim } = kind {
            let code = cx.report_mut().response_code().unwrap_or(0);
            if interim && code == 100 {
                // The server is ready for the body (`http_exp100_got100`).
                self.release();
            } else if !interim && code >= 300 {
                self.send_error(cx, code)?;
            }
        }
        if kind == (LineKind::End { interim: false }) {
            let abandoned = self.head().framing() == Some(Framing::Abandoned);
            if abandoned {
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
    fn release(&mut self) {
        if matches!(self.expect, ExpectState::Head | ExpectState::Awaiting(_)) {
            self.expect = ExpectState::Open;
        }
    }

    /// An error response came before the body was all sent: it goes on if
    /// the application says so, and stops otherwise, the connection not
    /// used again (`http_handle_send_error`).
    fn send_error<H: Host>(&mut self, cx: &mut StepCx<'_, H>, code: u16) -> Result<(), ErrorKind> {
        if !self.sending() || self.head().meta().close() {
            return Ok(());
        }
        if code == 417 && self.expect != ExpectState::None {
            // Made again without `Expect`, its body started over if any
            // went.
            if self.body_sent == 0 && matches!(self.expect, ExpectState::Awaiting(_)) {
                trace::info(
                    cx,
                    format_args!("Got HTTP failure 417 while waiting for a 100"),
                );
            } else {
                trace::info(cx, format_args!("Got HTTP failure 417 while sending data"));
                self.closing = true;
                if self.upload.as_ref().is_some_and(Upload::needs_rewind) {
                    trace::info(cx, format_args!("Need to rewind upload for next request"));
                }
            }
            self.expect_refused = true;
            self.aborted = true;
            self.upload_done(cx);
            cx.mark(Timer::PostTransfer);
            return Ok(());
        }
        if cx.easy().options().http.keep_sending_on_error {
            trace::info(
                cx,
                format_args!("HTTP error before end of send, keep sending"),
            );
            self.release();
        } else {
            trace::info(
                cx,
                format_args!("HTTP error before end of send, stop sending"),
            );
            self.aborted = true;
            self.closing = true;
            self.upload_done(cx);
            cx.mark(Timer::PostTransfer);
        }
        Ok(())
    }

    /// The final head ended: what it expects of the body (`http_size`).
    fn body_start<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        let head = self.head.as_ref().expect("made at DO");
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
            Framing::None | Framing::Abandoned => Stage::Done,
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
    }

    /// Decode chunks from `input`; what is left, which is nothing unless
    /// the body ended.
    fn chunked_input<'i, H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        input: &'i [u8],
    ) -> Result<&'i [u8], ErrorKind> {
        let Request {
            pipeline, stage, ..
        } = self;
        let Stage::Body(Body::Chunked(decoder)) = stage else {
            unreachable!("reading chunks");
        };
        if cx.easy().options().http.raw {
            // Passed on as it came; the decoder only finds the end.
            pipeline.body(cx, input)?;
        } else {
            // Traced as it came, chunk lines, trailers and what follows the
            // last chunk with it, as C traces it before decoding.
            pipeline.trace_raw(cx, input);
        }
        let mut piece = input;
        while !piece.is_empty() {
            let header_size = &mut cx.report_mut().sizes_mut().header;
            let (used, event) = match decoder.feed(piece, header_size) {
                Ok(fed) => fed,
                Err(e) => return Err(chunks_failed(cx, &e)),
            };
            match event {
                Some(ChunkEvent::Data(data)) => pipeline.decoded(cx, data)?,
                Some(ChunkEvent::Trailer { line, then }) => {
                    if let Err(e) = pipeline.header(cx, line, HeaderOrigin::Trailer) {
                        return Err(trace::fail(
                            cx,
                            e,
                            format_args!("Failed reading the chunked-encoded stream"),
                        ));
                    }
                    then.map_err(|e| chunks_failed(cx, &e))?;
                }
                Some(ChunkEvent::Done) => {
                    let left = piece.len() - used;
                    if left > 0 {
                        trace::info(cx, format_args!("Leftovers after chunking: {left} bytes"));
                    }
                    *stage = Stage::Done;
                    return Ok(&[]);
                }
                None => {}
            }
            piece = &piece[used..];
        }
        Ok(&[])
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
            Stage::Body(Body::Length | Body::UntilClose) => self.pipeline.end(cx),
            Stage::Body(Body::Chunked(decoder)) => match decoder.finish() {
                Ok(()) => Ok(()),
                Err(e) => Err(chunks_failed(cx, &e)),
            },
            Stage::Done => Ok(()),
        }
    }

    /// The request is over (`Curl_http_done`): a line still held is
    /// delivered, whatever came of it; a reply with nothing in it is an
    /// error, unless the request is to be made again; the connection is
    /// kept only if the response allows.
    pub(crate) fn done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
        result: Result<(), ErrorKind>,
        premature: bool,
        next: &AfterRequest,
    ) -> Result<(), ErrorKind> {
        let Some(head) = self.head.as_ref() else {
            // The request was never made.
            return result;
        };
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
            cx.conn(lease).saw_version(seen);
        }
        if head.meta().close() || self.pipeline.body_closes() || self.closing {
            cx.conn(lease).mark_close();
        }
        result?;
        if !premature && *next != AfterRequest::Retry && head.got_nothing(self.pipeline.bytecount())
        {
            cx.conn(lease).mark_close();
            return Err(trace::fail(
                cx,
                ErrorKind::GotNothing,
                format_args!("Empty reply from server"),
            ));
        }
        Ok(())
    }
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
    }
}

/// What follows `name` in a header line that starts with it, in any
/// case.
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
fn version(wanted: HttpVersion, after_http10: bool, seen: Option<ResponseVersion>) -> HttpVersion {
    if after_http10 || seen == Some(ResponseVersion::Http10) {
        HttpVersion::Http10
    } else {
        wanted
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
