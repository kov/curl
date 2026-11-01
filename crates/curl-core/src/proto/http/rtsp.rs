//! `rtsp:`, RTSP over a connection, which C speaks through HTTP's code
//! (`lib/rtsp.c`): a request of its own kind, numbered by its CSeq and
//! named by its stream, its response read by HTTP's head parser with
//! RTSP's status line, and the RTP packets the server interleaves on the
//! connection taken out of what is read, before, inside and after each
//! response, for the interleave handler (`CURLOPT_INTERLEAVEFUNCTION`).
//!
//! What lasts from one request and connection to the next is the
//! handle's (`easy::RtspState`, and the session in the options); what a
//! connection keeps between responses, a packet read in part, is the
//! connection's ([`RtspConn`]).

use std::fmt;
use std::num::NonZeroUsize;

use super::{
    AfterHead, Authorization, Body, Reading, Request, Sending, Stage, auth_trace, made, random,
};
use crate::auth::creds::Credentials;
use crate::auth::http::{AuthRequest, Side};
use crate::coding::AcceptEncoding;
use crate::conn::line::LineConn;
use crate::conn::{ConnLease, Peer};
use crate::date::{HttpDate, OutOfRange};
use crate::deliver::{Directions, Expect, Pipeline};
use crate::error::ErrorKind;
use crate::handler::Write;
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};
use crate::options::{AuthMethods, Follow, Method, RtspRequest, RtspSession, UploadSource};
use crate::proto::http1::framing::{Asked, Framing};
use crate::proto::http1::request::{Accepted, Conditional, RtspContent, RtspHead, render_rtsp};
use crate::proto::http1::response::{self, Exchange, HeadParser};
use crate::trace;
use crate::upload::{self, Upload, chain};

/// What a request of RTSP's knows of itself (`struct RTSP`, and the
/// `req.no_body` its method gives).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rtsp {
    pub(super) kind: RtspRequest,
    /// The CSeq it was sent with, and the one its response said.
    cseq_sent: u32,
    cseq_recv: u32,
    /// No body is read: its method's (`pick_method`), or a heartbeat's.
    no_body: bool,
    /// The application asked for no body (`set.opt_no_body`), which a
    /// body announced does not override.
    app_no_body: bool,
}

impl Rtsp {
    pub(super) fn new(kind: RtspRequest, app_no_body: bool) -> Rtsp {
        Rtsp {
            kind,
            cseq_sent: 0,
            cseq_recv: 0,
            no_body: false,
            app_no_body,
        }
    }

    pub(super) fn receives(&self) -> bool {
        self.kind == RtspRequest::Receive
    }

    /// Whether the request may be made again on a fresh connection, its
    /// reused one having died, as a protocol outside HTTP's may: one that
    /// waits for a body, and has not `ended` (a close ends it, a reset
    /// does not), and is not a receive (`Curl_retry_request`).
    pub(super) fn retryable(&self, ended: bool) -> bool {
        !self.receives() && !self.no_body && !ended
    }
}

/// The method a request is sent with, and whether its answer has no body
/// to read (`pick_method`).
fn pick(kind: RtspRequest) -> (&'static [u8], bool) {
    match kind {
        RtspRequest::Options => (b"OPTIONS", true),
        RtspRequest::Describe => (b"DESCRIBE", false),
        RtspRequest::Announce => (b"ANNOUNCE", true),
        RtspRequest::Setup => (b"SETUP", true),
        RtspRequest::Play => (b"PLAY", true),
        RtspRequest::Pause => (b"PAUSE", true),
        RtspRequest::Teardown => (b"TEARDOWN", true),
        RtspRequest::GetParameter => (b"GET_PARAMETER", false),
        RtspRequest::SetParameter => (b"SET_PARAMETER", true),
        RtspRequest::Record => (b"RECORD", true),
        // Interleaved RTP is read as the body.
        RtspRequest::Receive => (b"", false),
    }
}

/// Where reading an RTP message stands (`rtp_parse_st`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Parse {
    /// Between messages: what is not a `$` is the body or junk.
    #[default]
    Skip,
    /// A `$` read: its channel next.
    Channel,
    /// Its channel read: the two bytes of its length next.
    Len,
    /// Its payload.
    Data,
}

impl Parse {
    /// As C's debug build prints it.
    fn number(self) -> u8 {
        match self {
            Parse::Skip => 0,
            Parse::Channel => 1,
            Parse::Len => 2,
            Parse::Data => 3,
        }
    }
}

/// What an RTSP connection keeps between responses (`struct rtsp_conn`):
/// an RTP message read in part, and whether a head is being read.
#[derive(Debug, Default)]
pub(crate) struct RtspConn {
    /// The message so far, its four bytes of header in.
    buf: Vec<u8>,
    /// The channel of the last message, none before the first
    /// (`rtp_channel`, -1).
    channel: Option<u8>,
    /// The whole message's length, its header in.
    len: usize,
    state: Parse,
    in_header: bool,
}

/// Where the RTP filter's output goes.
pub(crate) trait RtpOut {
    /// Whether body bytes are still due: a final head came with a size
    /// the body has not reached (`in_body`, but for `in_header`).
    fn body_due(&self) -> bool;
    /// Bytes that are no RTP: as many as are due go as the body, the rest
    /// nowhere (`rtp_write_body_junk`).
    fn junk(&mut self, bytes: &[u8]) -> Result<(), ErrorKind>;
    /// A whole RTP message, on `channel` (`rtp_client_write`).
    fn packet(&mut self, channel: u8, message: &[u8]) -> Result<(), ErrorKind>;
    /// A line C's debug build says (`DEBUGF(infof())`).
    fn note(&mut self, args: fmt::Arguments<'_>);
}

impl RtspConn {
    /// Take the RTP messages out of `buf`, the body and junk between them
    /// to `out` too: how much of `buf` was taken, which is all of it
    /// unless the next response's head starts (`rtsp_filter_rtp`). The
    /// channels a message may be on are `channels`; a `receive` reads no
    /// head, so none starts one.
    pub(crate) fn filter(
        &mut self,
        buf: &[u8],
        receive: bool,
        channels: &crate::easy::RtspState,
        out: &mut dyn RtpOut,
    ) -> Result<usize, ErrorKind> {
        let mut consumed = 0;
        // The bytes before `consumed` that are body or junk, not written
        // yet.
        let mut skip = 0;
        let result = self.filter_into(buf, &mut consumed, &mut skip, receive, channels, out);
        if result.is_ok() && skip > 0 && !self.in_header {
            out.junk(&buf[consumed - skip..consumed])?;
        }
        result.map(|()| consumed)
    }

    fn filter_into(
        &mut self,
        all: &[u8],
        consumed: &mut usize,
        skip: &mut usize,
        receive: bool,
        channels: &crate::easy::RtspState,
        out: &mut dyn RtpOut,
    ) -> Result<(), ErrorKind> {
        while *consumed < all.len() {
            let in_body = !self.in_header && out.body_due();
            match self.state {
                Parse::Skip => {
                    debug_assert!(self.buf.is_empty(), "no message is read between them");
                    while *consumed < all.len() && all[*consumed] != b'$' {
                        let rest = &all[*consumed..];
                        if !in_body && rest[0] == b'R' && !receive {
                            let n = rest.len().min(5);
                            if rest[..n] == b"RTSP/"[..n] {
                                // The next response may start here: left
                                // for its head.
                                if *consumed > 0 {
                                    out.note(format_args!(
                                        "RTP rtsp_filter_rtp[SKIP] RTSP/ prefix, skipping {} \
                                         bytes of junk",
                                        *consumed
                                    ));
                                }
                                self.in_header = true;
                                return Ok(());
                            }
                        }
                        *consumed += 1;
                        *skip += 1;
                    }
                    if *consumed < all.len() {
                        // A message may start: what came before it goes.
                        if *skip > 0 {
                            let junk = &all[*consumed - *skip..*consumed];
                            *skip = 0;
                            if !self.in_header {
                                out.junk(junk)?;
                            }
                        }
                        self.push(b"$")?;
                        *consumed += 1;
                        self.state = Parse::Channel;
                    }
                }
                Parse::Channel => {
                    let channel = all[*consumed];
                    debug_assert_eq!(self.buf.len(), 1, "the `$` is read");
                    if !channels.interleaves(channel) {
                        // No channel of ours: the `$` was body or junk.
                        self.state = Parse::Skip;
                        out.note(format_args!(
                            "RTSP: invalid RTP channel {}, skipping",
                            channel / 8
                        ));
                        if *consumed == 0 {
                            // Read in an earlier call, it cannot be left
                            // unread: it goes from the buffer.
                            let dollar = [self.buf[0]];
                            self.buf.clear();
                            if !self.in_header {
                                out.junk(&dollar)?;
                            }
                        } else {
                            *skip = 1;
                            self.buf.clear();
                        }
                        continue;
                    }
                    self.channel = Some(channel);
                    self.push(&[channel])?;
                    *consumed += 1;
                    self.state = Parse::Len;
                }
                Parse::Len => {
                    let had = self.buf.len();
                    debug_assert!((2..4).contains(&had), "a length byte to read");
                    self.push(&all[*consumed..=*consumed])?;
                    *consumed += 1;
                    if had == 2 {
                        continue;
                    }
                    self.len = usize::from(u16::from_be_bytes([self.buf[2], self.buf[3]])) + 4;
                    if self.len == 4 {
                        // No payload: the header is the whole message.
                        let channel = self.channel.expect("read above");
                        out.note(format_args!(
                            "RTP write channel {channel} rtp_len {} (no payload)",
                            self.len
                        ));
                        let wrote = out.packet(channel, &self.buf);
                        self.buf.clear();
                        self.state = Parse::Skip;
                        wrote?;
                        continue;
                    }
                    self.state = Parse::Data;
                }
                Parse::Data => {
                    let had = self.buf.len();
                    debug_assert!(had < self.len, "a message not whole");
                    let needed = self.len - had;
                    let left = all.len() - *consumed;
                    if needed <= left {
                        self.push(&all[*consumed..*consumed + needed])?;
                        *consumed += needed;
                        let channel = self.channel.expect("read before its payload");
                        out.note(format_args!(
                            "RTP write channel {channel} rtp_len {}",
                            self.len
                        ));
                        let wrote = out.packet(channel, &self.buf);
                        self.buf.clear();
                        self.state = Parse::Skip;
                        wrote?;
                    } else {
                        self.push(&all[*consumed..])?;
                        *consumed = all.len();
                    }
                }
            }
        }
        Ok(())
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        use curl_alloc::TryVec as _;
        self.buf
            .try_extend_from_slice(bytes)
            .map_err(|_| ErrorKind::OutOfMemory)
    }
}

/// The filter's output, as a request's response reads it: the body
/// through its pipeline, a message to the interleave handler.
struct Delivered<'r, 'c, H: Host> {
    cx: &'r mut StepCx<'c, H>,
    pipeline: &'r mut Pipeline,
    head: &'r HeadParser,
}

impl<H: Host> Delivered<'_, '_, H> {
    /// What of the body is still due.
    fn remain(&self) -> u64 {
        if self.head.lines() == 0 {
            return 0;
        }
        let size = self.head.meta().size().unwrap_or(0);
        size.saturating_sub(self.pipeline.bytecount())
    }
}

impl<H: Host> RtpOut for Delivered<'_, '_, H> {
    fn body_due(&self) -> bool {
        self.remain() > 0
    }

    fn junk(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        let remain = self.remain();
        if remain == 0 {
            return Ok(());
        }
        let n = usize::try_from(remain).map_or(bytes.len(), |r| r.min(bytes.len()));
        self.pipeline.body(self.cx, &bytes[..n])
    }

    fn packet(&mut self, _: u8, message: &[u8]) -> Result<(), ErrorKind> {
        write_rtp(self.cx, message)
    }

    fn note(&mut self, args: fmt::Arguments<'_>) {
        trace::debug_info(self.cx, args);
    }
}

/// Give an RTP message to the interleave handler, else the write handler
/// (`rtp_client_write`).
fn write_rtp<H: Host>(cx: &mut StepCx<'_, H>, message: &[u8]) -> Result<(), ErrorKind> {
    if message.is_empty() {
        return Err(trace::fail(
            cx,
            ErrorKind::WriteError,
            format_args!("Cannot write a 0 size RTP packet."),
        ));
    }
    let options = cx.easy().options();
    let handler = options
        .small
        .interleave
        .clone()
        .or_else(|| options.callbacks.write.clone());
    let Some(handler) = handler else {
        return Ok(());
    };
    match handler.write(&mut TransferCx::new(cx), message) {
        Write::Accepted => Ok(()),
        Write::Took(n) if n == message.len() => Ok(()),
        Write::Pause => Err(trace::fail(
            cx,
            ErrorKind::WriteError,
            format_args!("Cannot pause RTP"),
        )),
        Write::Took(_) | Write::Fail => Err(trace::fail(
            cx,
            ErrorKind::WriteError,
            format_args!("Failed writing RTP data"),
        )),
    }
}

/// `n` bytes as C's `%u` of a `uint32_t` reads them: at most `u32::MAX`.
fn read_number(bytes: &[u8], max: u64) -> Option<(u64, usize)> {
    let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mut n: u64 = 0;
    for &d in &bytes[..digits] {
        n = n * 10 + u64::from(d - b'0');
        if n > max {
            return None;
        }
    }
    Some((n, digits))
}

/// `bytes` past its leading blanks (`curlx_str_passblanks`).
fn pass_blanks(bytes: &[u8]) -> &[u8] {
    let n = bytes
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\t')
        .count();
    &bytes[n..]
}

/// Whether `line` starts with `prefix`, in any case (`checkprefix`).
fn starts(line: &[u8], prefix: &[u8]) -> bool {
    line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// What a `Transport:` header's value says of the interleaved channels:
/// each named, of its first `interleaved=` parameter
/// (`rtsp_parse_transport`); a value that cannot be read is said.
pub(crate) fn parse_transport(
    value: &[u8],
    channels: &mut crate::easy::RtspState,
) -> Result<(), &'static str> {
    let mut start = c_string(value);
    while !start.is_empty() {
        start = pass_blanks(start);
        let end = start.iter().position(|&b| b == b';');
        if starts(start, b"interleaved=") {
            let p = &start[12..];
            let Some((first, used)) = read_number(p, 255) else {
                return Err("Unable to read the interleaved parameter from Transport header");
            };
            let mut last = first;
            let mut unread = false;
            if let Some(rest) = p[used..].strip_prefix(b"-") {
                match read_number(rest, 255) {
                    Some((n, _)) => last = n,
                    None => unread = true,
                }
            }
            for channel in first..=last {
                channels.add_channel(u8::try_from(channel).expect("at most 255"));
            }
            return if unread {
                Err("Unable to read the interleaved parameter from Transport header")
            } else {
                Ok(())
            };
        }
        start = match end {
            Some(at) => &start[at + 1..],
            None => &[],
        };
    }
    Ok(())
}

/// What a `Session:` header's value says, past its blanks and as C reads
/// it, to its first zero byte; and the session id it names, up to a
/// blank, a control byte, a byte above ASCII or a `;`
/// (`Curl_rtsp_parseheader`). None for a value with nothing in it, which
/// a line's end makes rare: the id is then empty.
pub(crate) fn session_id(value: &[u8]) -> Option<(&[u8], &[u8])> {
    let start = pass_blanks(c_string(value));
    if start.is_empty() {
        return None;
    }
    let len = start
        .iter()
        .position(|&b| b <= b' ' || b == b';' || b >= 0x80)
        .unwrap_or(start.len());
    Some((start, &start[..len]))
}

/// `bytes` up to its first zero byte, as C reads a string.
fn c_string(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())]
}

/// A `CSeq:` header's number (`Curl_rtsp_parseheader`).
pub(crate) fn cseq(value: &[u8]) -> Option<u32> {
    let (n, _) = read_number(pass_blanks(value), u64::from(u32::MAX))?;
    u32::try_from(n).ok()
}

impl Request {
    /// A request for `url`, whose scheme is `rtsp`, as the transfer's
    /// earlier ones left it `before`: in HTTP/1.1 alone, as C reads its
    /// responses.
    pub(crate) fn rtsp<H: Host>(
        url: &crate::url::Url,
        before: super::super::Before<'_>,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Request, ErrorKind> {
        let mut request = Request::of_scheme(url, crate::conn::Scheme::of("rtsp"), before, cx)?;
        request.neg.h1_only();
        request.neg.only_10 = false;
        let options = cx.easy().options();
        let app_no_body = options.method == Method::Head;
        request.rtsp = Some(Rtsp::new(options.small.rtsp_request, app_no_body));
        Ok(request)
    }

    /// What an RTSP connection is matched by, its scheme logging in per
    /// connection (`url_match_auth`); none for HTTP's.
    pub(crate) fn rtsp_login(&self) -> Result<Option<Credentials>, curl_alloc::OutOfMemory> {
        match (&self.rtsp, &self.base.credentials) {
            (Some(_), Some(c)) => c.try_clone().map(Some),
            _ => Ok(None),
        }
    }

    /// Connect over a new connection: the sequence numbers start at 1 if
    /// none is set, and the connection keeps what RTP reads between
    /// responses (`rtsp_connect`, `rtsp_setup_connection`).
    pub(super) fn rtsp_connect<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<super::super::Connect, ErrorKind> {
        let state = cx
            .easy_mut()
            .rtsp_mut()
            .map_err(|_| ErrorKind::OutOfMemory)?;
        if state.next_client_cseq == 0 {
            state.next_client_cseq = 1;
        }
        if state.next_server_cseq == 0 {
            state.next_server_cseq = 1;
        }
        if !lease.get().keeps_line() {
            let line = curl_alloc::try_box(LineConn::Rtsp(RtspConn::default()))
                .map_err(|_| ErrorKind::OutOfMemory)?;
            lease.get().put_line(line);
        }
        Ok(super::super::Connect::Done)
    }

    /// Make the request (`rtsp_do`).
    pub(super) fn rtsp_do<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let options = cx.easy_mut().options_mut();
        options
            .reread_headers()
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let next_cseq = cx.easy().rtsp().next_client_cseq;
        let rtsp = self.rtsp.as_mut().expect("an RTSP request");
        rtsp.cseq_sent = next_cseq;
        rtsp.cseq_recv = 0;
        let kind = rtsp.kind;
        let (method, no_body) = pick(kind);
        rtsp.no_body = no_body;
        self.wire = super::Wire::H1;
        self.version = super::SentIn::Http11;
        let reused = lease.conn().reused();
        if kind == RtspRequest::Receive {
            // Nothing goes: what the connection has is read
            // (`Curl_xfer_setup_recv`).
            self.method = Method::Get;
            self.head = Some(HeadParser::new(self.rtsp_exchange(cx, lease, reused, None)));
            self.outgoing = Sending::Done;
            crate::multi::mstate::xfer_setup(
                cx,
                Directions {
                    recv: true,
                    send: false,
                },
            );
            return Ok(());
        }
        let options = cx.easy().options();
        let headers = &options.http.headers;
        let small = &options.small;
        // The option's Transport goes only where the application gives
        // none of its own; a SETUP needs one or the other.
        let transport = match &small.rtsp_transport {
            _ if kind != RtspRequest::Setup || headers.replaces(b"Transport") => None,
            Some(t) => Some(t),
            None => {
                return Err(trace::fail(
                    cx,
                    ErrorKind::BadFunctionArgument,
                    format_args!("Refusing to issue an RTSP SETUP without a Transport: header."),
                ));
            }
        };
        let transport = match transport {
            Some(t) => Some(super::copied(t)?),
            None => None,
        };
        let stream_uri = super::copied(small.rtsp_stream_uri.as_deref().unwrap_or(b"*"))?;
        // Authenticating with the origin, the stream named as the path;
        // nothing goes to a proxy, which the request only tunnels through
        // (`Curl_http_output_auth` with `HTTPREQ_GET`).
        let credentials = self.base.credentials.as_ref().map(Credentials::secret);
        let (auth_state, options) = cx.easy_mut().auth_with_options();
        auth_state.side(Side::Proxy).finish();
        let request = AuthRequest {
            side: Side::Host,
            origin: &self.base.peer,
            method,
            uri: &stream_uri,
            get_or_head: true,
            trusted: self.gate.trusted(),
        };
        let custom = options.http.headers.replaces(b"Authorization");
        let auth = made(
            auth_state
                .side(Side::Host)
                .output(credentials, custom, &request, random),
        )?;
        let auth = if auth.negotiate {
            self.negotiate(cx, lease, Side::Host, true)?
        } else {
            auth
        };
        let probe = auth.probe;
        let auth_asked = cx.easy().auth.asked(
            (credentials, &self.base.peer),
            (None, &self.base.peer),
            probe,
            true,
        );
        cx.report_mut().set_auth_used(auth.used);
        auth_trace(cx, "Server", auth.used, credentials);
        let options = cx.easy().options();
        let headers = &options.http.headers;
        let small = &options.small;
        let range = match kind {
            RtspRequest::Play | RtspRequest::Pause | RtspRequest::Record
                if !headers.replaces(b"Range") =>
            {
                options.ranged()
            }
            _ => None,
        };
        // A session a server gave goes back only to its origin, unless
        // credentials may go anywhere.
        let session = small.rtsp_session.as_ref().filter(|s| {
            s.origin
                .as_ref()
                .is_none_or(|origin| origin == &self.base.peer)
                || options.http.unrestricted_auth
        });
        if headers.replaces(b"CSeq") {
            return Err(trace::fail(
                cx,
                ErrorKind::RtspCseqError,
                format_args!("CSeq cannot be set as a custom header."),
            ));
        }
        if headers.replaces(b"Session") {
            return Err(trace::fail(
                cx,
                ErrorKind::BadFunctionArgument,
                format_args!("Session ID cannot be set as a custom header."),
            ));
        }
        let conditional = match options.time_condition {
            Some(c) if matches!(kind, RtspRequest::Setup | RtspRequest::Describe) => {
                match HttpDate::of(c.time) {
                    Ok(date) => (!headers.replaces(c.when.header())).then_some(Conditional {
                        name: c.when.header(),
                        date,
                    }),
                    Err(OutOfRange) => {
                        let said = format_args!("Invalid TIMEVALUE");
                        return Err(trace::fail(cx, ErrorKind::BadFunctionArgument, said));
                    }
                }
            }
            _ => None,
        };
        // The body (`rtsp_setup_body`): ANNOUNCE's, SET_PARAMETER's and
        // GET_PARAMETER's, an upload's or the fields posted.
        let carries = matches!(
            kind,
            RtspRequest::Announce | RtspRequest::SetParameter | RtspRequest::GetParameter
        );
        let source = match (&options.upload, options.method) {
            _ if !carries => None,
            (UploadSource::Read { .. }, Method::Upload) => Some(&options.upload),
            (UploadSource::Bytes(_) | UploadSource::Lent(_), _) => Some(&options.upload),
            _ => None,
        };
        let mut upload = match source {
            Some(source) => {
                Some(Upload::new(source, headers, options.mime_escape()).map_err(|e| e.kind())?)
            }
            None => None,
        };
        let size = upload.as_ref().map_or(Some(0), Upload::size);
        let mut heartbeat = false;
        let content = match size {
            Some(n) if n > 0 => {
                if options.crlf {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::UploadFailed,
                        format_args!("Cannot do CRLF conversions on upload"),
                    ));
                }
                Some(RtspContent {
                    length: n,
                    typed: match kind {
                        RtspRequest::Announce => Some(&b"application/sdp"[..]),
                        _ => Some(&b"text/parameters"[..]),
                    },
                })
            }
            _ => {
                // A GET_PARAMETER with nothing said of its size is a
                // heartbeat, which reads no body.
                heartbeat = kind == RtspRequest::GetParameter;
                None
            }
        };
        if size == Some(0) {
            upload = None;
        }
        let converts = options.crlf && upload.is_some();
        let http = &options.http;
        let accept_encoding = match &http.accept_encoding {
            _ if kind != RtspRequest::Describe || headers.replaces(b"Accept-Encoding") => None,
            None => None,
            Some(AcceptEncoding::All) => Some(Accepted::All(cx.easy().decoders())),
            Some(AcceptEncoding::Given(value)) => Some(Accepted::Given(value)),
        };
        let authorization = match (&self.base.credentials, &auth.header) {
            (Some(c), Some((AuthMethods::DIGEST, value))) => {
                Some(Authorization::alongside("Digest", value, c.trusted()))
            }
            (_, Some((AuthMethods::NEGOTIATE, value))) => {
                let trusted = self
                    .gate
                    .trusted()
                    .expect("Negotiate goes only where trusted");
                Authorization::new("Negotiate", value, trusted, headers)
            }
            (Some(c), Some((m, value))) => {
                Authorization::new(m.name(), value, c.trusted(), headers)
            }
            _ => None,
        };
        let head = RtspHead {
            method,
            stream_uri: &stream_uri,
            cseq: next_cseq,
            session: session.map(RtspSession::id),
            transport: transport.as_deref(),
            accept_sdp: kind == RtspRequest::Describe && !headers.replaces(b"Accept"),
            accept_encoding,
            range,
            referer: cx.easy().report().referer(),
            user_agent: http.user_agent.as_deref(),
            proxy_authorization: None,
            authorization,
            conditional,
            content,
            probe,
            headers,
            trusted: self.gate.trusted(),
        };
        let mut out = render_rtsp(&head)?;
        let rtsp = self.rtsp.as_mut().expect("an RTSP request");
        rtsp.no_body |= heartbeat;
        let no_body = rtsp.no_body;
        self.method = if no_body { Method::Head } else { Method::Get };
        let upload_buffer = cx.easy().options().limits.upload_buffer.get();
        if let Some(upload) = &mut upload {
            upload.start(cx)?;
        }
        let head_len = out.len();
        if upload.is_some() {
            let room = upload_buffer.saturating_sub(head_len);
            out.try_reserve_exact(room)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            super::zeros(&mut out, room).map_err(|_| ErrorKind::OutOfMemory)?;
        }
        let then = AfterHead::Body(Reading {
            eos_read: upload.is_none(),
            announced: false,
        });
        self.out = out;
        self.filled = head_len;
        self.sent = 0;
        self.body = match upload {
            Some(upload) => {
                upload.trace_set(cx);
                *cx.readers_mut() = upload.pausing().map(|client| upload::Readers {
                    chunked: false,
                    exp100: false,
                    mail: false,
                    lines: converts,
                    client,
                });
                let mut body = chain::Body::new(upload);
                if converts {
                    body.convert_lines().map_err(|_| ErrorKind::OutOfMemory)?;
                }
                Some(body)
            }
            None => None,
        };
        self.body_sent = 0;
        let nothing_to_read = self.body.as_ref().is_none_or(|b| b.size() == Some(0));
        self.outgoing = Sending::Head {
            left: NonZeroUsize::new(head_len).expect("a head is never empty"),
            then,
            direct: nothing_to_read && head_len <= upload_buffer,
        };
        self.head = Some(HeadParser::new(self.rtsp_exchange(
            cx,
            lease,
            reused,
            Some(auth_asked),
        )));
        crate::multi::mstate::xfer_setup(
            cx,
            Directions {
                recv: true,
                send: true,
            },
        );
        let paused = cx.pause().send_paused();
        if self.body.is_some() && self.filled < self.out.len() && !paused {
            self.fill(cx, lease)?;
        }
        match self.send(cx, lease, false) {
            Ok(_) => {}
            Err(e) => {
                return Err(trace::fail(
                    cx,
                    e,
                    format_args!("Failed sending RTSP request"),
                ));
            }
        }
        // The next request is numbered on, once this one is on its way.
        let state = cx
            .easy_mut()
            .rtsp_mut()
            .map_err(|_| ErrorKind::OutOfMemory)?;
        state.next_client_cseq = state.next_client_cseq.wrapping_add(1);
        Ok(())
    }

    /// What the response is read as: RTSP's, in HTTP/1.1.
    fn rtsp_exchange<H: Host>(
        &self,
        cx: &StepCx<'_, H>,
        lease: &mut ConnLease,
        reused: bool,
        auth: Option<crate::auth::http::AuthAsked>,
    ) -> Exchange {
        let options = cx.easy().options();
        let http = &options.http;
        let rtsp = self.rtsp.as_ref().expect("an RTSP request");
        Exchange {
            sent: response::HttpVersion::Http11,
            reused,
            allow_09: http.allow_09,
            rtsp: true,
            asked: Asked {
                head: rtsp.app_no_body,
                ignore_length: http.ignore_content_length,
                max_filesize: options.flow.max_filesize,
                decode_codings: http.transfer_encoding,
                raw_codings: http.raw,
                fail_on_error: http.fail_on_error,
                resume_from: None,
                follow: http.follow != Follow::No,
                auth: auth.unwrap_or(crate::auth::http::AuthAsked::DEFAULT),
                http_proxy: lease.conn().http_proxy(),
                time_condition: options
                    .time_condition
                    .filter(|_| options.ranged().is_none()),
                forwarded: false,
                websocket: false,
                rtsp: true,
            },
        }
    }

    /// The final head ended: what it says of the body, which RTSP reads
    /// through its filter (`http_size`, and `rtsp_rtp_write_resp`'s size
    /// of 0 where none is given). A body announced overrides a method's
    /// lack of one, but not the application's (RFC 2326, section 12.14).
    pub(super) fn rtsp_body_start<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
    ) -> Result<(), ErrorKind> {
        let head = self.head.as_ref().expect("made at DO");
        let framing = head.framing().expect("a final head decides its framing");
        let size = head.meta().size();
        let rtsp = self.rtsp.as_mut().expect("an RTSP request");
        if rtsp.no_body && !rtsp.app_no_body && size.is_some_and(|n| n > 0) {
            rtsp.no_body = false;
        }
        let no_body = rtsp.no_body;
        if size.is_some() {
            self.base.pipeline.announce_size(cx, size);
        }
        self.base.pipeline.expect(Expect {
            size,
            max: size,
            no_body,
            no_head: false,
            ignore: head.meta().ignore_body(),
        });
        self.stage = match (framing, size) {
            (Framing::Abandoned, _) => Stage::Done,
            _ if no_body => Stage::Done,
            (_, Some(n)) if n > 0 => Stage::Body(Body::Length),
            _ => Stage::Done,
        };
        Ok(())
    }

    /// A header line of the final head or an interim one, after HTTP's own
    /// reading of it (`Curl_rtsp_parseheader`): the CSeq it numbers, the
    /// session it names, the channels it interleaves.
    pub(super) fn rtsp_header<H: Host>(
        cx: &mut StepCx<'_, H>,
        rtsp: &mut Rtsp,
        origin: &Peer,
        line: &[u8],
    ) -> Result<(), ErrorKind> {
        if starts(line, b"CSeq:") {
            let Some(n) = cseq(&line[5..]) else {
                return Err(trace::fail_with(
                    cx,
                    ErrorKind::RtspCseqError,
                    &[b"Unable to read the CSeq header: [", c_string(line), b"]"],
                ));
            };
            rtsp.cseq_recv = n;
            cx.easy_mut()
                .rtsp_mut()
                .map_err(|_| ErrorKind::OutOfMemory)?
                .cseq_recv = n;
        } else if starts(line, b"Session:") {
            let Some((start, id)) = session_id(&line[8..]) else {
                return Err(trace::fail(
                    cx,
                    ErrorKind::RtspSessionError,
                    format_args!("Got a blank Session ID"),
                ));
            };
            let small = &cx.easy().options().small;
            match &small.rtsp_session {
                Some(session) if session.id() != id => {
                    let wanted = super::copied(session.id())?;
                    return Err(trace::fail_with(
                        cx,
                        ErrorKind::RtspSessionError,
                        &[
                            b"Got RTSP Session ID Line [",
                            start,
                            b"], but wanted ID [",
                            &wanted,
                            b"]",
                        ],
                    ));
                }
                Some(_) => {}
                None => {
                    let session = RtspSession {
                        id: super::copied(id)?,
                        origin: Some(origin.try_clone().map_err(|_| ErrorKind::OutOfMemory)?),
                    };
                    cx.easy_mut()
                        .options_mut()
                        .small
                        .make_mut()
                        .map_err(|_| ErrorKind::OutOfMemory)?
                        .rtsp_session = Some(session);
                }
            }
        } else if starts(line, b"Transport:") {
            let value = &line[10..];
            let channels = cx
                .easy_mut()
                .rtsp_mut()
                .map_err(|_| ErrorKind::OutOfMemory)?;
            if let Err(said) = parse_transport(value, channels) {
                trace::info_with(cx, &[said.as_bytes(), b": [", c_string(value), b"]"]);
            }
        }
        Ok(())
    }

    /// Read what came (`rtsp_rtp_write_resp`): RTP taken out of it, the
    /// head read by HTTP's parser, the body and what follows it through
    /// the filter; what is left the body's, for the accountant to judge.
    pub(super) fn rtsp_input<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        input: &[u8],
    ) -> Result<(), ErrorKind> {
        let mut rtp = std::mem::take(lease.get().rtsp_mut().expect("an RTSP connection"));
        let result = self.rtsp_write_resp(cx, lease, &mut rtp, input);
        *lease.get().rtsp_mut().expect("an RTSP connection") = rtp;
        result
    }

    fn rtsp_write_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        rtp: &mut RtspConn,
        input: &[u8],
    ) -> Result<(), ErrorKind> {
        let receive = self.rtsp.as_ref().is_some_and(Rtsp::receives);
        let result = self.rtsp_resp(cx, lease, rtp, input, receive);
        // A receive reads what one read brings, and whatever completes a
        // message it left in part.
        if receive && rtp.state == Parse::Skip {
            self.stage = Stage::Done;
        }
        result
    }

    fn rtsp_resp<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        rtp: &mut RtspConn,
        input: &[u8],
        receive: bool,
    ) -> Result<(), ErrorKind> {
        if !matches!(self.stage, Stage::Head) {
            rtp.in_header = false;
        }
        if input.is_empty() {
            return Ok(());
        }
        trace::debug_info(
            cx,
            format_args!(
                "rtsp_rtp_write_resp(len={}, in_header={}, eos=0)",
                input.len(),
                u8::from(rtp.in_header)
            ),
        );
        let mut rest = input;
        if !rtp.in_header {
            let used = self.filter(cx, rtp, rest, receive)?;
            rest = &rest[used..];
            if !rest.is_empty() && !matches!(self.stage, Stage::Head) {
                trace::debug_info(
                    cx,
                    format_args!(
                        "RTSP: {} bytes, possibly excess in response body",
                        rest.len()
                    ),
                );
            }
        }
        if matches!(self.stage, Stage::Head) && !rest.is_empty() && !receive {
            rtp.in_header = true;
            while matches!(self.stage, Stage::Head) && !rest.is_empty() {
                rest = self.head_input(cx, lease, rest, false)?;
            }
            if !matches!(self.stage, Stage::Head) {
                rtp.in_header = false;
            }
            if !rtp.in_header {
                let used = self.filter(cx, rtp, rest, receive)?;
                rest = &rest[used..];
            }
        }
        let size = match self.stage {
            Stage::Head => -1,
            _ => self
                .head()
                .meta()
                .size()
                .and_then(|n| i64::try_from(n).ok())
                .unwrap_or(0),
        };
        trace::debug_info(
            cx,
            format_args!(
                "rtsp_rtp_write_resp(len={}, in_header={}, done=0, rtspc->state={}, req.size={size})",
                rest.len(),
                u8::from(rtp.in_header),
                rtp.state.number()
            ),
        );
        if !rest.is_empty() {
            self.base.pipeline.body(cx, rest)?;
        }
        if matches!(self.stage, Stage::Body(Body::Length)) && self.base.pipeline.body_done() {
            self.stage = Stage::Done;
        }
        Ok(())
    }

    /// Run the filter over `bytes`, the body through the pipeline.
    fn filter<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        rtp: &mut RtspConn,
        bytes: &[u8],
        receive: bool,
    ) -> Result<usize, ErrorKind> {
        // As the heads read so far left them.
        let channels = cx.easy().rtsp();
        let head = self.head.as_ref().expect("made at DO");
        let mut out = Delivered {
            cx,
            pipeline: &mut self.base.pipeline,
            head,
        };
        rtp.filter(bytes, receive, &channels, &mut out)
    }

    /// The connection closed (`rtsp_rtp_write_resp` with nothing, then
    /// `Curl_sendrecv`'s check): a body not whole is cut short.
    pub(super) fn rtsp_end<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        let no_body = self.rtsp.as_ref().is_some_and(|r| r.no_body);
        let left = match self.stage {
            Stage::Head => self.head().meta().size().unwrap_or(0),
            Stage::Body(Body::Length) if !self.head().meta().ignore_body() => self
                .head()
                .meta()
                .size()
                .unwrap_or(0)
                .saturating_sub(self.base.pipeline.bytecount()),
            _ => 0,
        };
        if left > 0 && !no_body {
            return Err(trace::fail(
                cx,
                ErrorKind::PartialFile,
                format_args!("transfer closed with {left} bytes remaining to read"),
            ));
        }
        Ok(())
    }

    /// The request is over and fine as HTTP judges it: its CSeq must be
    /// the one its response said (`rtsp_done`).
    pub(super) fn rtsp_done<H: Host>(
        &self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let Some(rtsp) = self.rtsp.as_ref() else {
            return Ok(());
        };
        if !rtsp.receives() && rtsp.cseq_sent != rtsp.cseq_recv {
            return Err(trace::fail(
                cx,
                ErrorKind::RtspCseqError,
                format_args!(
                    "The CSeq of this request {} did not match the response {}",
                    rtsp.cseq_sent, rtsp.cseq_recv
                ),
            ));
        }
        if rtsp.receives()
            && lease
                .get()
                .rtsp_mut()
                .is_some_and(|conn| conn.channel.is_none())
        {
            trace::info(
                cx,
                format_args!("Got an RTP Receive with a CSeq of {}", rtsp.cseq_recv),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
