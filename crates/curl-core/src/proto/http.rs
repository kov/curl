//! `http:`, HTTP/1 over a connection: the request head sent at DO, the
//! response read, parsed and delivered, and its end judged (`lib/http.c`'s
//! `Curl_http`, `Curl_http_write_resp` and `Curl_http_done`, and
//! `lib/transfer.c`'s receive loop).

use curl_alloc::TryVec as _;

use crate::conn::io::{Events, Recv, Sent};
use crate::conn::{ConnLease, RecvFailed};
use crate::deliver::{Expect, Pause, Pipeline, Reach};
use crate::error::{ErrorKind, UrlErrorKind};
use crate::handler::{DebugKind, HeaderOrigin};
use crate::multi::Host;
use crate::multi::state::{AfterRequest, OsError, StepCx, url_error};
use crate::options::{HttpVersion, Method, Resume, UploadSource};
use crate::report::Timer;
use crate::trace;
use crate::upload::{self, Upload};
use crate::url::{GetOptions, Part, Url};

use super::ProtoStep;
use super::http1::chunked::{ChunkDecoder, ChunkEncoder, ChunkError, ChunkEvent};
use super::http1::framing::{self, Asked, Framing};
use super::http1::request::{self, Basic, CredentialGate, RequestHead};
use auth::{Credentials, CredentialsError};

mod auth;
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

/// An HTTP request and its response.
#[derive(Debug)]
pub(crate) struct Request {
    pipeline: Pipeline,
    /// The path and query the request asks for.
    target: Vec<u8>,
    /// The host as the URL names it, and its port.
    host: Vec<u8>,
    /// What the URL says to authenticate with.
    credentials: Option<Credentials>,
    port: u16,
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
    /// Made at DO, once the connection says whether it is reused.
    head: Option<HeadParser>,
    stage: Stage,
    /// The current response is interim (1xx).
    interim: bool,
}

#[derive(Debug)]
enum Stage {
    Head,
    Body(Body),
    Done,
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

impl Request {
    /// A request for `url`, whose scheme is `http`.
    pub(crate) fn new<H: Host>(url: &Url, cx: &mut StepCx<'_, H>) -> Result<Request, ErrorKind> {
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
        let credentials = match Credentials::of_url(url) {
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
        Ok(Request {
            pipeline: Pipeline::new(Reach::Network),
            target,
            host,
            credentials,
            port,
            out: Vec::new(),
            filled: 0,
            sent: 0,
            head_left: 0,
            upload: None,
            chunks: None,
            eos_read: false,
            body_sent: 0,
            sent_all: true,
            head: None,
            stage: Stage::Head,
            interim: false,
        })
    }

    /// The host and port the request connects to.
    pub(crate) fn origin(&self) -> Result<(Vec<u8>, u16), ErrorKind> {
        let mut host = Vec::new();
        host.try_extend_from_slice(&self.host)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        Ok((host, self.port))
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    pub(crate) fn holds_output(&self) -> bool {
        self.pipeline.holds_output()
    }

    /// Whether the response so far is nothing at all: no head line and no
    /// body byte (C's `bytecount + headerbytecount`).
    pub(crate) fn received_nothing(&self) -> bool {
        self.head.as_ref().is_none_or(|h| h.request_bytes() == 0) && self.pipeline.bytecount() == 0
    }

    /// Whether some of the request is still to send.
    pub(crate) fn sending(&self) -> bool {
        !self.sent_all
    }

    /// What the request waits for on its socket.
    pub(crate) fn interest(&self, pause: Pause) -> Events {
        let mut events = Events::NONE;
        if !matches!(self.stage, Stage::Done) && !pause.recv_paused() {
            events = events | Events::IN;
        }
        if self.sending() && !pause.send_paused() {
            events = events | Events::OUT;
        }
        events
    }

    /// Render the head and send what the connection takes now (`Curl_http`).
    pub(crate) fn do_it<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
    ) -> Result<(), ErrorKind> {
        let reused = cx.conn(lease).reused();
        let options = cx.easy().options();
        let http = &options.http;
        let (method, body): (&[u8], _) = match options.method {
            Method::Get => (b"GET", None),
            Method::Head => (b"HEAD", None),
            Method::Post => (b"POST", Some(BodyKind::Form)),
            Method::Upload => (b"PUT", Some(BodyKind::Put)),
        };
        let method = http.custom_method.as_deref().unwrap_or(method);
        if body.is_some() && options.resume.is_some() {
            return Err(trace::fail(
                cx,
                ErrorKind::BadFunctionArgument,
                format_args!("HTTP upload cannot be resumed"),
            ));
        }
        let mut upload = body.map(|_| Upload::new(&options.upload));
        let size = upload.as_ref().and_then(Upload::size);
        // The application's Transfer-Encoding decides whether the body is
        // chunked; otherwise one of unknown size is, which HTTP/1.0 cannot
        // send (`http_req_set_TE`).
        let size_unknown = upload.is_some() && size.is_none();
        let asked = http.headers.asks_chunked();
        if asked.is_none() && size_unknown && http.version == HttpVersion::Http10 {
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
        let content = body.map(|kind| request::Content {
            length: size.filter(|_| !chunked),
            form: kind == BodyKind::Form,
        });
        // `Expect: 100-continue`, asked for or added on HTTP/1.1 for a
        // body large or of unknown size, is not waited for yet
        // (`addexpect`).
        if content.is_some() {
            let asked = http.headers.expects_continue();
            let added = asked.is_none()
                && http.version == HttpVersion::Http11
                && size.is_none_or(|n| n > EXPECT_100_THRESHOLD);
            if asked == Some(true) || added {
                return Err(ErrorKind::NotBuiltIn);
            }
        }
        let resume_from = match options.resume {
            None => None,
            Some(Resume::At(at)) => Some(at.get()),
            // C's -1, which for a download names no range a server knows.
            Some(Resume::AtEnd) => return Err(ErrorKind::NotBuiltIn),
        };
        let shown_port = (self.port != DEFAULT_PORT).then_some(self.port);
        let peer = request::Peer {
            scheme: b"http",
            host: &self.host,
            port: self.port,
        };
        // One origin, until redirects are followed.
        let gate = CredentialGate::new(&peer, &peer, false);
        let token = match (&self.credentials, gate.trusted()) {
            (Some(c), Some(_)) => c.basic().map_err(|_| ErrorKind::OutOfMemory)?,
            _ => None,
        };
        let basic = token
            .as_deref()
            .zip(gate.trusted())
            .and_then(|(token, trusted)| Basic::new(token, trusted, &http.headers));
        let authenticates = basic.is_some();
        let head = RequestHead {
            method,
            target: &self.target,
            version: http.version,
            host: &self.host,
            port: shown_port,
            user_agent: http.user_agent.as_deref(),
            referer: http.referer.as_deref(),
            basic,
            range_from: resume_from,
            content,
            chunked: chunked && asked.is_none(),
            headers: &http.headers,
        };
        let mut out = Vec::new();
        request::render_h1(&head, &gate, &mut out)?;
        let exchange = Exchange {
            sent: match http.version {
                HttpVersion::Http10 => response::HttpVersion::Http10,
                HttpVersion::Http11 => response::HttpVersion::Http11,
            },
            reused,
            allow_09: http.allow_09,
            asked: Asked {
                head: options.method == Method::Head,
                ignore_length: http.ignore_content_length,
                max_filesize: options.limits.max_filesize,
                decode_codings: http.transfer_encoding,
                raw_codings: http.raw,
                fail_on_error: http.fail_on_error,
                resume_from: resume_from.filter(|_| options.method == Method::Get),
            },
        };
        if authenticates {
            let user = self.credentials.as_ref().map_or(&b""[..], |c| c.user());
            trace::info_with(cx, &[b"Server auth using Basic with user '", user, b"'"]);
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
        self.head = Some(HeadParser::new(exchange));
        if !self.eos_read && self.filled < self.out.len() && !cx.pause().send_paused() {
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
                    chunks.got(got.n, got.eos);
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
        if self.body_sent > 0 {
            let n = self.body_sent;
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
        Ok(true)
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
            if matches!(self.stage, Stage::Done) {
                return Ok(ProtoStep::Done);
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
            ..
        } = self;
        let head = head.as_mut().expect("made at DO");
        let (used, event) = head
            .feed(input, &mut cx.report_mut().sizes_mut().header)
            .map_err(|e| head_failed(cx, &e))?;
        let rest = &input[used..];
        let line = match event {
            None => return Ok(rest),
            Some(HeadEvent::Http09(bytes)) => {
                let no_body = cx.easy().options().method == Method::Head;
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
        if let Some(note) = line.note {
            trace::info(cx, format_args!("{note}"));
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

    /// The final head ended: what it expects of the body (`http_size`).
    fn body_start<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        let head = self.head.as_ref().expect("made at DO");
        let framing = head.framing().expect("a final head decides its framing");
        let size = head.meta().size();
        let no_body = cx.easy().options().method == Method::Head;
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
                let no_body = cx.easy().options().method == Method::Head;
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
        next: AfterRequest,
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
        if head.meta().close() || self.pipeline.body_closes() {
            cx.conn(lease).mark_close();
        }
        result?;
        if !premature && next != AfterRequest::Retry && head.got_nothing(self.pipeline.bytecount())
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

/// A copy of `bytes`; out of memory fails the transfer.
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
