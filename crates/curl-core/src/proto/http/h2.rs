//! A request over HTTP/2: its stream (`lib/http2.c`'s `h2_stream_ctx`).
//!
//! The request is made as for HTTP/1 and its head turned into the
//! stream's fields as it is sent, as C turns the head it rendered
//! (`h2_submit`); the body goes into the stream's send buffer, which the
//! session frames as the peer's window allows. What the session reads
//! for the stream is handed on as it is read, as C's callbacks write it
//! to the transfer: the head a line at a time, `HTTP/2 200 \r\n` first,
//! the body as it comes, and the trailers once the stream closes.

use curl_alloc::try_box;

use super::*;
use crate::components::Component;
use crate::conn::RecvFailed;
use crate::conn::layer::LayerCx;
use crate::error::AGAIN_NUMBER;
use crate::http2::{BodyRead, DEFAULT_WEIGHT, Event, Frame, FrameKind, H2Error, Heard, StreamId};
use crate::multi::PushFields;
use crate::multi::push::Full;
use crate::multi::state::{Offered, start_pushed};
use crate::proto::http2::{
    EgressFailed, GoAway, H2Conn, SEND_MAX, STREAM_WINDOW_MAX, WindowFailed, fields_of, settings,
    trace_frame, trace_settings,
};
use crate::tls::Chosen;
use crate::url::ParseOptions;

/// The most a request's fields may add up to before C warns of them
/// (`MAX_ACC`).
const MAX_FIELDS: usize = 60000;

/// The response's trailers as lines, and how many, held to C's limits
/// (`resp_trailers`, a `dynhds` of at most `MAX_HTTP_RESP_HEADER_COUNT`
/// fields and `DYN_HTTP_REQUEST` bytes of names and values).
#[derive(Debug, Default)]
struct Trailers {
    lines: Vec<u8>,
    count: usize,
}

impl Trailers {
    const MAX_COUNT: usize = 5000;
    const MAX_BYTES: usize = 1024 * 1024;
    /// What a line adds beside its name and value: `: ` and CRLF.
    const FRAMING: usize = 4;

    /// Keep a trailer, unless it is past the limits, which C's
    /// `Curl_dynhds_add` says as it says memory ran out.
    fn add(&mut self, name: &[u8], value: &[u8]) -> Result<(), OutOfMemory> {
        let held = self.lines.len() - Self::FRAMING * self.count;
        let room = Self::MAX_BYTES - held;
        if self.count >= Self::MAX_COUNT || room < name.len() || room - name.len() < value.len() {
            return Err(OutOfMemory);
        }
        let start = self.lines.len();
        let added = [name, b": ", value, b"\r\n"]
            .iter()
            .try_for_each(|part| self.lines.try_extend_from_slice(part));
        if added.is_err() {
            // Nothing of a line half kept stays.
            self.lines.truncate(start);
            return Err(OutOfMemory);
        }
        self.count += 1;
        Ok(())
    }
}

/// A request's stream, and what came of it (`h2_stream_ctx`).
#[derive(Debug, Default)]
pub(super) struct H2Stream {
    /// Its id, once its head went.
    id: Option<StreamId>,
    /// Body bytes for the session to frame (`sendbuf`): `sendbuf[taken..]`.
    sendbuf: Vec<u8>,
    taken: usize,
    /// All of the body is in the buffer (`body_eos`).
    body_eos: bool,
    /// The stream closed (`closed`), with this error code (`error`); one
    /// is a reset (`reset`), by the server if it said so
    /// (`reset_by_server`).
    closed: bool,
    error: H2Error,
    reset: bool,
    reset_by_server: bool,
    /// The response's status, while its head is read.
    status: Option<u16>,
    /// The final head ended (`resp_hds_complete`, `bodystarted`): what
    /// follows is body, and a header block after it the trailers.
    body_started: bool,
    /// The trailers, as lines (`resp_trailers`).
    trailers: Trailers,
    /// What reading for the request leaves the session to do, kept
    /// between reads for its room: emptied after each.
    after: After,
    /// Writing the response failed (`xfer_result`): nothing more is
    /// written.
    failed: Option<ErrorKind>,
    /// What the session holds to send waits for the connection.
    out_pending: bool,
    /// The fields of a PUSH_PROMISE on it, until the promise is whole
    /// (`push_headers`).
    promise: PushFields,
    /// Its transfer's output was paused when last written to
    /// (`write_paused`).
    write_paused: bool,
}

/// A line of the HTTP/2 filter's (`CURL_TRC_CF` of `cf-h2`).
const H2: Component = Component::Http2;

impl H2Stream {
    /// Whether the session's output waits for the connection.
    pub(super) fn out_pending(&self) -> bool {
        self.out_pending
    }

    /// All of the body is in its buffer.
    pub(super) fn body_eos(&self) -> bool {
        self.body_eos
    }

    /// The session takes what of the body the buffer holds, as much as
    /// `room` has (`req_body_read_callback`), traced by its transfer on
    /// `cx`: an empty buffer is C's `CURLE_AGAIN`.
    fn body_read(&mut self, cx: &mut dyn LayerCx, room: &mut [u8]) -> BodyRead {
        let len = room.len();
        let n = (self.sendbuf.len() - self.taken).min(len);
        room[..n].copy_from_slice(&self.sendbuf[self.taken..self.taken + n]);
        self.taken += n;
        let id = self.id.map_or(0, |s| s.0);
        let eos = u8::from(self.body_eos);
        let code = if n == 0 { AGAIN_NUMBER } else { 0 };
        cx.of(
            H2,
            format_args!("[{id}] req_body_read(len={len}) eos={eos} -> {n}, {code}"),
        );
        let empty = self.taken == self.sendbuf.len();
        match (n, empty && self.body_eos) {
            (_, true) => BodyRead::Last(n),
            (0, false) => BodyRead::Later,
            (n, false) => BodyRead::Bytes(n),
        }
    }

    /// The session closed the stream as it sent, with `error`.
    fn closed_with(&mut self, error: H2Error) {
        self.closed = true;
        self.error = error;
        self.reset |= error != H2Error::NO_ERROR;
    }
}

/// What the session's reading left to do on it, once it is free to:
/// C calls into the session from its callbacks.
#[derive(Debug, Default)]
struct After {
    /// Body bytes of each stream used: their windows open.
    consumed: Vec<(StreamId, usize)>,
    /// Streams to reset, with their codes.
    resets: Vec<(StreamId, H2Error)>,
    /// Streams whose bodies have more to give.
    resumes: Vec<StreamId>,
    /// Streams promised and taken, each a new transfer's from here.
    routed: Vec<(StreamId, crate::multi::TransferId)>,
    /// The receive window each stream's transfer asks for, as it took
    /// what came.
    windows: Vec<(StreamId, i32)>,
    /// The peer said GOAWAY.
    goaway: Option<GoAway>,
}

impl After {
    /// Empty, its room kept for the next read.
    fn clear(&mut self) {
        self.consumed.clear();
        self.resets.clear();
        self.resumes.clear();
        self.routed.clear();
        self.windows.clear();
        self.goaway = None;
    }
}

/// The receive window a transfer's stream asks for: none while its
/// output is failed or paused, what a rate limit allows under one, the
/// most otherwise (`cf_h2_get_desired_local_win`, `cf_h2_update_local_win`).
/// A paused way's allowance is none, as C's blocked limit's is.
fn wanted_window<H: Host>(cx: &mut StepCx<'_, H>, failed: bool) -> i32 {
    if failed {
        return 0;
    }
    match cx.rate_allowance(Way::Recv) {
        Some(..=0) => 0,
        Some(avail) => i32::try_from(avail).map_or(STREAM_WINDOW_MAX, |a| a.min(STREAM_WINDOW_MAX)),
        None => STREAM_WINDOW_MAX,
    }
}

/// A window the session could not set fails the transfer as C's does.
fn window_failed<H: Host>(
    cx: &mut StepCx<'_, H>,
    stream: StreamId,
    wanted: i32,
    failed: WindowFailed,
) -> ErrorKind {
    let id = stream.0;
    let kind = ErrorKind::Http2;
    match failed {
        WindowFailed::Set { grows: true, e } => {
            let (code, text) = (e.code, e.text);
            let why = format_args!(
                "[{id}] nghttp2 set_local_window_size({wanted}) failed: {text}({code})"
            );
            trace::fail(cx, kind, why)
        }
        WindowFailed::Set { grows: false, e } => {
            let (code, text) = (e.code, e.text);
            let why = format_args!(
                "[{id}] nghttp2_session_set_local_window_size() failed: {text}({code})"
            );
            trace::fail(cx, kind, why)
        }
        WindowFailed::Update(e) => {
            let (code, text) = (e.code, e.text);
            let why = format_args!("[{id}] nghttp2_submit_window_update() failed: {text}({code})");
            trace::fail(cx, kind, why)
        }
    }
}

/// What the session sends with, for a request's step: the stepping
/// stream's body, and a sibling's, read from its own buffer as C reads
/// the stream's (`req_body_read_callback`); the streams closed as it
/// sends, told after.
struct Egressing<'a, 'c, H: Host> {
    cx: &'a mut StepCx<'c, H>,
    stream: &'a mut H2Stream,
    closes: Vec<(StreamId, H2Error)>,
    oom: bool,
}

impl<H: Host> crate::proto::http2::Egress for Egressing<'_, '_, H> {
    fn layer_cx(&mut self) -> &mut dyn LayerCx {
        &mut *self.cx
    }

    fn body(
        &mut self,
        s: StreamId,
        to: Option<crate::multi::TransferId>,
        room: &mut [u8],
    ) -> BodyRead {
        if Some(s) == self.stream.id {
            return self.stream.body_read(&mut *self.cx, room);
        }
        let me = self.cx.me;
        match to {
            Some(to) if to != me => self
                .cx
                .with_sibling(to, |bcx, req| match req.wire.h2_mut() {
                    Some(sib) if sib.id == Some(s) => sib.body_read(bcx, room),
                    _ => BodyRead::Failed,
                })
                .unwrap_or(BodyRead::Failed),
            _ => BodyRead::Failed,
        }
    }

    /// A stream closed as the session sent is traced by its transfer
    /// (`on_stream_close`), and told after.
    fn event(&mut self, event: Event<'_>, to: Option<crate::multi::TransferId>) -> Heard {
        let Event::Closed { stream, error } = event else {
            return Heard::Fine;
        };
        let me = self.cx.me;
        if Some(stream) == self.stream.id {
            trace_closed(&mut *self.cx, stream, error);
        } else if let Some(to) = to.filter(|&to| to != me) {
            self.cx
                .with_sibling(to, |bcx, _| trace_closed(bcx, stream, error));
        } else {
            no_easy(&mut *self.cx, stream);
        }
        if self.closes.try_push((stream, error)).is_err() {
            self.oom = true;
            return Heard::Failed;
        }
        Heard::Fine
    }
}

/// A stream closed, traced by its transfer (`on_stream_close`): with its
/// error code, a reset.
fn trace_closed<H: Host>(cx: &mut StepCx<'_, H>, stream: StreamId, error: H2Error) {
    let id = stream.0;
    if error == H2Error::NO_ERROR {
        trace::of(cx, H2, format_args!("[{id}] CLOSED"));
    } else {
        let text = error_text(cx, error);
        trace::of(cx, H2, format_args!("[{id}] RESET: {text} (err {error})"));
    }
}

/// A stream closed that is no transfer's (`on_stream_close`).
fn no_easy<H: Host>(cx: &mut StepCx<'_, H>, stream: StreamId) {
    let id = stream.0;
    trace::of(
        cx,
        H2,
        format_args!("[{id}] on_stream_close, no easy set on stream"),
    );
}

/// Run `f` with the connection's session taken off it, the lease free
/// beside it, and put back after.
fn with_session<R>(lease: &mut ConnLease, f: impl FnOnce(&mut H2Conn, &mut ConnLease) -> R) -> R {
    let mut h2 = lease.get().take_h2().expect("an HTTP/2 connection");
    let r = f(&mut h2, lease);
    lease.get().put_h2(h2);
    r
}

/// A field of a stream's head or trailers, as it came (`on_header`).
fn field_line<H: Host>(
    cx: &mut StepCx<'_, H>,
    stream: StreamId,
    what: &str,
    name: &[u8],
    value: &[u8],
) {
    if !trace::traces(cx, H2) {
        return;
    }
    let mut id = [0u8; 12];
    let n = {
        use std::io::Write as _;
        let mut at = &mut id[..];
        // An i32 fits in 11 bytes.
        write!(at, "{}", stream.0).expect("room for a stream id");
        12 - at.len()
    };
    let parts: [&[u8]; 8] = [
        b"[",
        &id[..n],
        b"] ",
        what.as_bytes(),
        b": ",
        name,
        b": ",
        value,
    ];
    trace::of_with(cx, H2, &parts);
}

/// The session is made: what it starts with is framed, to go with the
/// first request, and the filter is connected (`cf_h2_ctx_open`,
/// `cf_h2_connect`).
fn h2_connect<H: Host>(
    cx: &mut StepCx<'_, H>,
    lease: &mut ConnLease,
    upgraded: bool,
) -> Result<(), ErrorKind> {
    if upgraded {
        trace::of(cx, H2, format_args!("created session via Upgrade"));
    }
    let via = if upgraded { " (via h1 upgrade)" } else { "" };
    trace::of(cx, H2, format_args!("[0] created h2 session{via}"));
    let framed = with_session(lease, |h2, _| h2.frame_first(&mut *cx));
    let made = match framed {
        Ok(()) => Ok(()),
        Err(EgressFailed::Session(e)) => {
            let (text, code) = (e.text, e.code);
            trace::of(
                cx,
                H2,
                format_args!("nghttp2_session_send error ({text}){code}"),
            );
            Err(ErrorKind::SendError)
        }
        Err(EgressFailed::Send) => Err(ErrorKind::SendError),
        Err(EgressFailed::OutOfMemory) => Err(ErrorKind::OutOfMemory),
    };
    let (code, done) = match &made {
        Ok(()) => (0, 1),
        Err(e) => (e.number(), 0),
    };
    trace::of(cx, H2, format_args!("cf_connect() -> {code}, {done}, "));
    made
}

/// The text of an HTTP/2 error code, as the library has it.
fn error_text<H: Host>(cx: &StepCx<'_, H>, code: H2Error) -> &'static str {
    cx.easy()
        .libraries()
        .h2
        .map_or("unknown", |library| library.error_text(code))
}

/// A `:status` read as C reads it (`Curl_http_decode_status`): three
/// digits, the first not 0.
pub(crate) fn decode_status(value: &[u8]) -> Option<u16> {
    match value {
        [a @ b'1'..=b'9', b @ b'0'..=b'9', c @ b'0'..=b'9'] => {
            Some(u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0'))
        }
        _ => None,
    }
}

/// What the stream had come to when asked (`stream_recv`).
enum StreamRecv {
    /// It closed and is whole: the response is over.
    Closed,
    /// Nothing yet.
    Again,
}

impl Request {
    /// What a connection's first request finds it speaks
    /// (`http_check_new_conn`): HTTP/2 if its TLS agreed on it, or if the
    /// application knows the origin speaks it and nothing is between;
    /// HTTP/1 otherwise. The session is made as the connection is found
    /// to speak HTTP/2 (`Curl_http2_switch`).
    pub(super) fn check_new_conn<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let top = lease.conn().top();
        let alpn = crate::multi::state::query_alpn(cx, lease, top);
        if alpn == Some(Chosen::H3) {
            // Its session came with its handshake.
            trace::info(cx, format_args!("using HTTP/3"));
            return Ok(());
        }
        let library = cx.easy().libraries().h2;
        let prior = self.neg.prior && self.neg.wanted.h2;
        let h2 = match library {
            None => false,
            Some(_) if alpn == Some(Chosen::H2) => true,
            Some(_) if prior && lease.conn().forwarding().is_some() => {
                trace::info(
                    cx,
                    format_args!("Ignoring HTTP/2 prior knowledge due to proxy"),
                );
                false
            }
            Some(_) => prior,
        };
        if let Some(library) = library.filter(|_| h2) {
            if alpn != Some(Chosen::H2) {
                // The filter goes on the connection now (`Curl_http2_switch`).
                trace::of(cx, H2, format_args!("added"));
                trace::of(cx, H2, format_args!("switching connection to HTTP/2"));
            }
            let (conn, _) =
                H2Conn::open(library, &settings(cx.max_streams(), cx.wants_push()), None)?;
            lease
                .get()
                .put_h2(try_box(conn).map_err(|_| ErrorKind::OutOfMemory)?);
            h2_connect(cx, lease, false)?;
            if prior {
                // No ALPN said so, but the connection speaks it now.
                lease.get().saw_version(ResponseVersion::Http2);
            }
        }
        let version = if h2 { "HTTP/2" } else { "HTTP/1.x" };
        trace::info(cx, format_args!("using {version}"));
        Ok(())
    }

    /// The settings a request asks to go on in HTTP/2 with, over a
    /// connection in clear text, where the application wants HTTP/2 by
    /// an upgrade and a library speaks it (`H1_HD_UPGRADE`,
    /// `populate_binsettings`).
    pub(super) fn upgrade_settings<H: Host>(
        &self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
        h2: bool,
    ) -> Result<Option<Vec<u8>>, ErrorKind> {
        let library = cx.easy().libraries().h2;
        let Some(library) = library.filter(|_| {
            let upgrade = cx.easy().options().http.version == HttpVersion::Http2;
            !h2 && upgrade && self.neg.wanted.h2 && !lease.conn().over_tls()
        }) else {
            return Ok(None);
        };
        let mut payload = [0u8; 80];
        match library.settings_payload(&settings(cx.max_streams(), cx.wants_push()), &mut payload) {
            Ok(n) if n > 0 => copied(&payload[..n]).map(Some),
            _ => Err(trace::fail(
                cx,
                ErrorKind::FailedInit,
                format_args!("nghttp2 unexpectedly failed on pack_settings_payload"),
            )),
        }
    }

    /// A 101 took up the request's upgrade: the connection speaks HTTP/2
    /// from here, the request's response coming on stream 1, the next
    /// head a new one (`Curl_http2_upgrade`).
    pub(super) fn upgraded<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        trace::info(cx, format_args!("Received 101, Switching to HTTP/2"));
        trace::of(cx, H2, format_args!("added"));
        trace::of(cx, H2, format_args!("upgrading connection to HTTP/2"));
        let settings = self.upgrade.take().expect("an upgrade asked for");
        let library = cx.easy().libraries().h2.expect("asked with a library");
        let head = self.method == Method::Head;
        let (mut conn, stream) = H2Conn::open(library, &[], Some((&settings, head)))?;
        if let Some(stream) = stream {
            conn.route(stream, cx.me)
                .map_err(|_| ErrorKind::OutOfMemory)?;
        }
        lease
            .get()
            .put_h2(try_box(conn).map_err(|_| ErrorKind::OutOfMemory)?);
        // The request went whole in HTTP/1.1.
        self.wire = Wire::H2(H2Stream {
            id: stream,
            body_eos: true,
            ..H2Stream::default()
        });
        self.version = SentIn::Http2;
        self.head
            .as_mut()
            .expect("made at DO")
            .restart(response::HttpVersion::Http2);
        self.stage = Stage::Head;
        self.interim = false;
        Ok(())
    }

    /// Feed the session what came behind a 101, which is HTTP/2 already,
    /// once the session sent what it starts with (`Curl_http2_upgrade`).
    pub(super) fn upgraded_input<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        rest: &[u8],
    ) -> Result<(), ErrorKind> {
        let n = rest.len();
        if n > 0 {
            trace::info(
                cx,
                format_args!(
                    "Copied HTTP/2 data in stream buffer to connection buffer after upgrade: \
                     len={n}"
                ),
            );
        }
        // Held for the session to read as the stream is next read, as C
        // holds it in its input buffer.
        with_session(lease, |h2, _| h2.hold(rest)).map_err(|_| ErrorKind::OutOfMemory)?;
        h2_connect(cx, lease, true)
    }

    /// Send what of the request is in `out[sent..end]`, the last of it if
    /// `eos` (`cf_h2_send`): the head opens the stream with its fields,
    /// the body goes into the stream's buffer as far as there is room.
    /// How much was taken.
    pub(super) fn h2_send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        end: usize,
        eos: bool,
    ) -> Result<usize, ErrorKind> {
        let len = end - self.sent;
        let mut n = 0;
        let sent = self.h2_send_on(cx, lease, end, eos, &mut n);
        // What the send came to, and the windows and buffers it left
        // (`cf_h2_send`'s last line).
        let stream = self.stream();
        let id = stream.id.map_or(-1, |s| s.0);
        let body_eos = u8::from(stream.body_eos);
        let held = stream.sendbuf.len() - stream.taken;
        let code = sent.as_ref().err().map_or(0, |e| e.number());
        let (sw, cw, out) = lease.conn().h2().map_or((-1, -1, 0), |h2| {
            let (sw, cw) = h2.send_windows(StreamId(id));
            (sw, cw, h2.out_len())
        });
        trace::of(
            cx,
            H2,
            format_args!(
                "[{id}] cf_send(len={len}) -> {code}, {n}, eos={body_eos}, h2 windows {sw}-{cw} \
                 (stream-conn), buffers {held}-{out} (stream-conn)"
            ),
        );
        sent.map(|()| n)
    }

    /// `h2_send`, short of its last line: `n` is what was taken.
    fn h2_send_on<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        end: usize,
        eos: bool,
        n: &mut usize,
    ) -> Result<(), ErrorKind> {
        let head = match self.outgoing {
            Sending::Head { left, .. } => left.get(),
            _ => 0,
        };
        let start = self.sent;
        if self.stream().id.is_none() {
            // The head goes whole, before any of the body (`h2_submit`).
            let custom = self.custom_method(cx);
            let scheme = self.peer.scheme().name.as_bytes();
            let fields = fields_of(&self.out[start..start + head], custom.as_deref(), scheme)?;
            let pairs = fields.pairs().map_err(|_| ErrorKind::OutOfMemory)?;
            let body = self.body.is_some();
            let weight = cx
                .easy()
                .options()
                .http
                .stream_weight
                .map_or(DEFAULT_WEIGHT, std::num::NonZeroU16::get);
            let me = cx.me;
            let id = with_session(lease, |h2, _| {
                let id = h2.session().submit_request(&pairs, body, weight);
                let id = match id {
                    Ok(id) => id,
                    Err(e) => return Ok(Err(e)),
                };
                h2.route(id, me).map_err(|_| ErrorKind::OutOfMemory)?;
                Ok::<_, ErrorKind>(Ok(id))
            })?;
            let id = match id {
                Ok(id) => id,
                Err(e) => {
                    let (text, code) = (e.text, e.code);
                    trace::of(
                        cx,
                        H2,
                        format_args!("send: nghttp2_submit_request error ({text}){code}"),
                    );
                    let failed = ErrorKind::SendError.number();
                    trace::of(cx, H2, format_args!("[-1] submit -> {failed}, 0"));
                    return Err(ErrorKind::SendError);
                }
            };
            self.stream().id = Some(id);
            if cx.easy().options().output.verbose {
                let url = cx.easy().report().url().map(copied).transpose()?;
                let url = url.as_deref().unwrap_or_default();
                let id = curl_alloc::try_format(format_args!("{}", id.0))
                    .map_err(|_| ErrorKind::OutOfMemory)?;
                trace::info_with(
                    cx,
                    &[b"[HTTP/2] [", id.as_bytes(), b"] OPENED stream for ", url],
                );
                let mut acc = 0;
                for (name, value) in &pairs {
                    acc += name.len() + value.len();
                    let parts: [&[u8]; 7] = [
                        b"[HTTP/2] [",
                        id.as_bytes(),
                        b"] [",
                        name,
                        b": ",
                        value,
                        b"]",
                    ];
                    trace::info_with(cx, &parts);
                }
                if acc > MAX_FIELDS {
                    trace::info(
                        cx,
                        format_args!(
                            "[HTTP/2] Warning: The cumulative length of all headers exceeds \
                             {MAX_FIELDS} bytes and that could cause the stream to be rejected."
                        ),
                    );
                }
            }
            *n = head;
            let body_len = end - start - head;
            let body = if body_len > 0 || eos {
                self.h2_body(cx, lease, start + head..end, eos)
            } else {
                Ok(0)
            };
            let code = body.as_ref().err().map_or(0, |e| e.number());
            if let Ok(k) = body {
                *n += k;
            }
            let id = id.0;
            let taken = *n;
            trace::of(cx, H2, format_args!("[{id}] submit -> {code}, {taken}"));
            body?;
        } else {
            let body_len = end - start;
            if body_len > 0 || eos {
                let body = self.h2_body(cx, lease, start..end, eos);
                let id = self.stream().id.map_or(-1, |s| s.0);
                let (code, k) = match &body {
                    Ok(k) => (0, *k),
                    Err(e) => (e.number(), 0),
                };
                let e = u8::from(eos);
                trace::of(
                    cx,
                    H2,
                    format_args!("[{id}] cf_body_send(len={body_len}) -> {code}, {k}, eos={e}"),
                );
                *n = body?;
            }
        }
        self.h2_egress(cx, lease)?;
        let stream = self.stream();
        if stream.closed && !stream.body_started {
            let id = stream.id.map_or(0, |id| id.0);
            trace::info(cx, format_args!("stream {id} closed"));
            return Err(ErrorKind::SendError);
        }
        Ok(())
    }

    /// Put `out[range]` of the body into the stream's buffer, as much as
    /// there is room for (`cf_h2_body_send`).
    fn h2_body<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        range: std::ops::Range<usize>,
        eos: bool,
    ) -> Result<usize, ErrorKind> {
        let Request { out, wire, .. } = self;
        let stream = wire.h2_mut().expect("a request over HTTP/2");
        let id = stream.id.expect("its head went");
        let len = range.len();
        if stream.closed {
            if stream.body_started {
                // The server is done with the request: what is left of its
                // body is dropped, as no transport failed.
                let id = id.0;
                trace::of(
                    cx,
                    H2,
                    format_args!("[{id}] discarding dataon closed stream with response"),
                );
                stream.body_eos |= eos;
                return Ok(len);
            }
            trace::info(cx, format_args!("stream {} closed", id.0));
            return Err(ErrorKind::SendError);
        }
        if stream.taken == stream.sendbuf.len() {
            stream.sendbuf.clear();
            stream.taken = 0;
        }
        let held = stream.sendbuf.len() - stream.taken;
        let n = len.min(SEND_MAX.saturating_sub(held));
        stream
            .sendbuf
            .try_extend_from_slice(&out[range.start..range.start + n])
            .map_err(|_| ErrorKind::OutOfMemory)?;
        if eos && n == len {
            stream.body_eos = true;
        }
        if eos || stream.taken < stream.sendbuf.len() {
            // Only a fatal failure fails the send: one not deferred is.
            match with_session(lease, |h2, _| h2.session().resume(id)) {
                Err(e) if e.fatal => return Err(ErrorKind::SendError),
                _ => {}
            }
        }
        Ok(n)
    }

    /// Have the session frame what it holds, and send what the
    /// connection takes (`h2_progress_egress`).
    pub(super) fn h2_egress<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let me = cx.me;
        let stream = self.wire.h2_mut().expect("a request over HTTP/2");
        let sent = with_session(lease, |h2, lease| {
            let mut with = Egressing {
                cx: &mut *cx,
                stream,
                closes: Vec::new(),
                oom: false,
            };
            let sent = h2.egress(&mut with, &mut lease.get().carrier());
            (sent, with.closes, with.oom)
        });
        let (sent, closes, oom) = sent;
        for (s, e) in closes {
            if Some(s) == self.stream().id {
                self.stream().closed_with(e);
            } else if let Some(to) = lease.conn().h2().and_then(|h2| h2.route_of(s))
                && to != me
            {
                cx.with_sibling(to, |_, req| {
                    if let Some(sib) = req.wire.h2_mut().filter(|sib| sib.id == Some(s)) {
                        sib.closed_with(e);
                    }
                });
            }
        }
        if oom {
            return Err(ErrorKind::OutOfMemory);
        }
        match sent {
            Ok(all) => {
                self.stream().out_pending = !all;
                Ok(())
            }
            Err(EgressFailed::Session(e)) => {
                let (text, code) = (e.text, e.code);
                trace::of(
                    cx,
                    H2,
                    format_args!("nghttp2_session_send error ({text}){code}"),
                );
                Err(trace::fail(
                    cx,
                    ErrorKind::SendError,
                    format_args!("nghttp2_session_send() failed: {text}({code})"),
                ))
            }
            Err(EgressFailed::Send) => Err(ErrorKind::SendError),
            Err(EgressFailed::OutOfMemory) => Err(ErrorKind::OutOfMemory),
        }
    }

    /// The application's method, if the request line names it.
    pub(super) fn custom_method<H: Host>(&self, cx: &StepCx<'_, H>) -> Option<Vec<u8>> {
        let custom = cx.easy().options().http.custom.method.as_deref();
        custom.filter(|_| self.custom).and_then(|m| copied(m).ok())
    }

    /// The stream was reset with HTTP/1.1 required
    /// (`Curl_h2_http_1_1_error`).
    pub(crate) fn h1_required(&self) -> bool {
        self.wire
            .h2()
            .is_some_and(|s| s.reset && s.error == H2Error::HTTP_1_1_REQUIRED)
    }

    fn stream(&mut self) -> &mut H2Stream {
        self.wire.h2_mut().expect("a request over HTTP/2")
    }

    /// `read_some` over a session's stream.
    pub(super) fn stream_read_some<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Read, ErrorKind> {
        match self.wire {
            Wire::H1 => unreachable!("a request over a session's stream"),
            Wire::H2(_) => self.h2_read_some(cx, lease),
            Wire::H3(_) => self.h3_read_some(cx, lease),
        }
    }

    /// `read_some` over HTTP/2, as one call of C's `cf_h2_recv`: what the
    /// stream has come to; if nothing yet, what the connection has, read
    /// and handed on as the session reads it until the stream is over, a
    /// read would block or the step has read its most, a buffer's worth of
    /// the connection, whichever streams it carried, so that each transfer
    /// on it reads in its own steps (`h2_progress_ingress`'s
    /// `data_max_bytes`); then what the stream came to, and what the
    /// reading left to send goes, all traced as C traces it.
    pub(super) fn h2_read_some<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Read, ErrorKind> {
        if matches!(self.stage, Stage::Done) || cx.pause().recv_paused() {
            return Ok(Read::Waits);
        }
        // Under a receive limit, no more than it allows; once spent, the
        // engine waits for it (`sendrecv_dl`'s `rate_limited`).
        let max = cx.easy().options().limits.buffer_size.get();
        let max = match cx.rate_allowance(Way::Recv) {
            Some(..=0) => return Ok(Read::Waits),
            Some(allowed) => max.min(usize::try_from(allowed).unwrap_or(usize::MAX)),
            None => max,
        };
        let mut stopped = false;
        let mut came = self.stream_recv(cx, lease, max);
        if let Ok(StreamRecv::Again) = came {
            // A connection that failed under the read fails it at once.
            stopped = self.h2_ingress(cx, lease, max)?;
            came = self.stream_recv(cx, lease, max);
        }
        // What the stream came to is read before what the reading left to
        // send goes, as C's `cf_h2_recv` asks the stream before its
        // egress: a reset the client sends then does not undo a response
        // already whole.
        let sent = self.h2_egress(cx, lease);
        let came = match (came, sent) {
            (Ok(_), Err(e)) => Err(e),
            (came, _) => came,
        };
        let code = match &came {
            Ok(StreamRecv::Closed) => 0,
            Ok(StreamRecv::Again) => AGAIN_NUMBER,
            Err(e) => e.number(),
        };
        if let Some(id) = self.stream().id
            && let Some(h2) = lease.conn().h2()
        {
            let (used, size) = h2.stream_windows(id);
            let conn = h2.local_window();
            let huge = crate::proto::http2::CONNECTION_WINDOW;
            let id = id.0;
            trace::of(
                cx,
                H2,
                format_args!(
                    "[{id}] cf_recv(len={max}) -> {code}, 0, window={used}/{size}, \
                     connection {conn}/{huge}"
                ),
            );
        }
        match came? {
            StreamRecv::Closed => {
                self.stream_ended(cx)?;
                Ok(Read::Waits)
            }
            StreamRecv::Again => Ok(if stopped || lease.get().data_pending() {
                Read::Stopped
            } else {
                Read::Waits
            }),
        }
    }

    /// Read from the connection and have the session read it, up to
    /// `max` bytes, until the stream is over, a read would block, the
    /// peer closed or the transfer paused (`h2_progress_ingress`): whether
    /// it stopped at its most.
    fn h2_ingress<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        max: usize,
    ) -> Result<bool, ErrorKind> {
        let held = with_session(lease, |h2, _| h2.take_held());
        if !held.is_empty() {
            let n = held.len();
            trace::of(
                cx,
                H2,
                format_args!("Process {n} bytes in connection buffer"),
            );
            self.h2_feed(cx, lease, &held)?;
        }
        let mut left = max;
        let mut reads = 0;
        let mut spent = false;
        loop {
            let closed = lease.conn().h2().is_none_or(H2Conn::closed);
            if closed || cx.pause().recv_paused() {
                break;
            }
            // At most so many reads too, as for HTTP/1, unlike C: a
            // connection busy with many streams' small frames would hold
            // one transfer's step for a buffer's worth of them, the
            // others waiting.
            if self.stream().closed || left == 0 || reads == MAX_READS {
                spent = left == 0 || reads == MAX_READS;
                break;
            }
            reads += 1;
            let said = cx.easy().report().reasons();
            let got = lease.get().recv(cx, left);
            match got {
                Ok(Recv::WouldBlock) => break,
                Ok(Recv::Eof) => {
                    // The peer closed the connection: the streams end
                    // with it, whole or not.
                    trace::of(cx, H2, format_args!("[0] ingress: connection closed"));
                    with_session(lease, |h2, _| h2.set_closed());
                    lease.get().mark_close();
                    self.wake_others(cx, lease);
                }
                Ok(Recv::Data(n)) => {
                    let n = n.get();
                    trace::of(cx, H2, format_args!("[0] ingress: read {n} bytes"));
                    left = left.saturating_sub(n);
                    let mut rx = std::mem::take(lease.get().rx_mut());
                    let fed = self.h2_feed(cx, lease, rx.filled());
                    let all = rx.filled().len();
                    rx.consume(all);
                    *lease.get().rx_mut() = rx;
                    fed?;
                    // The session reads all it is given.
                    trace::of(cx, H2, format_args!("[0] ingress: nw-in buffered 0"));
                }
                Err(e) => {
                    // The connection failed under every stream on it.
                    lease.get().mark_close();
                    self.wake_others(cx, lease);
                    let kind = match e {
                        RecvFailed::OutOfMemory => return Err(ErrorKind::OutOfMemory),
                        RecvFailed::Os(_) if cx.easy().report().reasons() > said => {
                            ErrorKind::RecvError
                        }
                        RecvFailed::Os(e) => {
                            let why = OsError(&e);
                            trace::fail(
                                cx,
                                ErrorKind::RecvError,
                                format_args!("Recv failure: {why}"),
                            )
                        }
                    };
                    let code = kind.number();
                    let text = kind.message();
                    return Err(trace::fail(
                        cx,
                        kind,
                        format_args!("Failed receiving HTTP2 data: {code}({text})"),
                    ));
                }
            }
        }
        if let Some(h2) = lease.conn().h2().filter(|h2| h2.closed()) {
            let how = if h2.goaway().is_some() {
                "with GOAWAY"
            } else {
                "abruptly"
            };
            trace::of(cx, H2, format_args!("server closed {how}"));
        }
        trace::of(cx, H2, format_args!("[0] ingress: done"));
        Ok(spent)
    }

    /// The stream is over and whole: the response ends as a connection's
    /// end ends HTTP/1's (`sendrecv_dl`'s "we are done").
    pub(super) fn stream_ended<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
    ) -> Result<(), ErrorKind> {
        trace::debug_info(cx, format_args!("sendrecv_dl: we are done"));
        if self.sending() {
            self.upload_done(cx, true);
        }
        let ended = self.end(cx);
        deliver::write_resp(cx, 0, true, ended);
        ended?;
        self.stage = Stage::Done;
        Ok(())
    }

    /// What the stream has come to (`stream_recv`): a failure writing the
    /// response; its close, handled; or its end with the connection's or
    /// by a reset, a failure. Asked for `len` bytes, which a failure says.
    fn stream_recv<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        len: usize,
    ) -> Result<StreamRecv, ErrorKind> {
        let came = self.stream_came(cx, lease);
        if let Err(e) = &came {
            let id = self.stream().id.map_or(-1, |id| id.0);
            let code = e.number();
            trace::of(
                cx,
                H2,
                format_args!("[{id}] stream_recv(len={len}) -> {code}, 0"),
            );
        }
        came
    }

    /// `stream_recv`, short of its line for a failure.
    fn stream_came<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<StreamRecv, ErrorKind> {
        // The window as the transfer asks now: it may have been paused or
        // unpaused since (`stream_recv`'s `cf_h2_update_local_win`).
        if self.stream().failed.is_none()
            && let Some(id) = self.stream().id
            && lease.conn().h2().is_some()
        {
            let wanted = wanted_window(cx, false);
            if let Err(e) = with_session(lease, |h2, _| h2.window_to(&mut *cx, id, wanted)) {
                let kind = window_failed(cx, id, wanted, e);
                self.stream().failed = Some(kind);
            }
        }
        let stream = self.stream();
        let id = stream.id.map_or(-1, |id| id.0);
        if let Some(e) = stream.failed {
            trace::of(cx, H2, format_args!("[{id}] xfer write failed"));
            return Err(e);
        }
        if stream.closed {
            trace::of(cx, H2, format_args!("[{id}] returning CLOSE"));
            self.stream_closed(cx, lease)?;
            return Ok(StreamRecv::Closed);
        }
        let h2 = lease.conn().h2().expect("an HTTP/2 connection");
        let gone = h2.closed() || h2.goaway().is_some_and(|g| g.last.0 < id);
        if stream.reset || gone {
            trace::of(cx, H2, format_args!("[{id}] returning ERR"));
            return Err(if self.pipeline.bytecount() > 0 {
                ErrorKind::PartialFile
            } else {
                ErrorKind::Http2
            });
        }
        Ok(StreamRecv::Again)
    }

    /// The stream closed (`http2_handle_stream_close`): a reset fails the
    /// response, but for a refused stream, which is made again on another
    /// connection, and one after a whole head of a response with no body
    /// wanted; a stream that closed before its head ended fails it too;
    /// the trailers are handed on.
    fn stream_closed<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let no_body = self.method == Method::Head;
        let bytecount = self.pipeline.bytecount();
        let stream = self.stream();
        let id = stream.id.map_or(0, |id| id.0);
        if stream.reset {
            let error = stream.error;
            if error == H2Error::REFUSED_STREAM {
                trace::info(
                    cx,
                    format_args!(
                        "HTTP/2 stream {id} refused by server, try again on a new connection"
                    ),
                );
                lease.get().mark_close();
                self.refused = true;
                return Err(ErrorKind::RecvError);
            }
            if stream.body_started && no_body {
                let text = error_text(cx, error);
                trace::of(
                    cx,
                    H2,
                    format_args!(
                        "[{id}] error after response headers, but we did not want a body \
                         anyway, ignore: {text} (err {error})"
                    ),
                );
                return Ok(());
            }
            let by = if stream.reset_by_server {
                "server"
            } else {
                "curl"
            };
            let text = error_text(cx, error);
            let kind = if error != H2Error::NO_ERROR {
                ErrorKind::Http2Stream
            } else if bytecount > 0 {
                ErrorKind::PartialFile
            } else {
                ErrorKind::Http2
            };
            return Err(trace::fail(
                cx,
                kind,
                format_args!("HTTP/2 stream {id} reset by {by} (error 0x{error:x} {text})"),
            ));
        }
        if !stream.body_started {
            return Err(trace::fail(
                cx,
                ErrorKind::Http2Stream,
                format_args!(
                    "HTTP/2 stream {id} was closed cleanly, but before getting all response \
                     header fields, treated as error"
                ),
            ));
        }
        let trailers = std::mem::take(&mut stream.trailers);
        let mut handed = Ok(());
        for line in trailers.lines.split_inclusive(|&b| b == b'\n') {
            trace::bytes(cx, DebugKind::HeaderIn, line);
            handed = self.pipeline.header(cx, line, HeaderOrigin::Trailer);
            if handed.is_err() {
                break;
            }
            let head = self.head.as_mut().expect("made at DO");
            let mut request_bytes = head.request_bytes();
            response::count_head(
                line.len() as u64,
                &mut request_bytes,
                &mut cx.report_mut().sizes_mut().header,
            )
            .map_err(|e| head_failed(cx, &e))?;
        }
        let code = handed.as_ref().err().map_or(0, |e| e.number());
        trace::of(cx, H2, format_args!("handle_stream_close -> {code}, 0"));
        handed
    }

    /// Feed the session what the connection read; what it reads for the
    /// stream is handed on as it reads it, and what that leaves to do on
    /// the session done after.
    fn h2_feed<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        bytes: &[u8],
    ) -> Result<(), ErrorKind> {
        // Taken out while the read runs, which allocates nothing, and put
        // back emptied after, its room kept.
        let mut after = std::mem::take(&mut self.stream().after);
        let prior = lease.conn().h2().and_then(H2Conn::goaway);
        let me = cx.me;
        let own = self.stream().id;
        let fed = with_session(lease, |h2, lease| {
            let read = h2.recv(bytes, &mut |event, routed, said| {
                // A frame is traced by the transfer reading, whichever
                // stream it is on (`on_frame_recv`).
                trace_frame(&mut *cx, &event);
                if let Event::Settings {
                    max_concurrent,
                    enable_push,
                } = event
                {
                    trace_settings(&mut *cx, said, max_concurrent, enable_push);
                }
                let stream = crate::proto::http2::stream_of(&event);
                let to = stream.and_then(|s| {
                    routed.or_else(|| after.routed.iter().find(|r| r.0 == s).map(|&(_, to)| to))
                });
                if let Event::Received(f) = event
                    && let Some(s) = stream
                    && Some(s) != own
                    && to.is_none()
                {
                    let id = f.stream.0;
                    trace::of(cx, H2, format_args!("[{id}] No Curl_easy associated"));
                    return Heard::Fine;
                }
                // What is read for a sibling's stream is handed to it at
                // once, as C's callbacks write to that stream's transfer;
                // a stream promised in this read is routed by `after`.
                if let Some(s) = stream
                    && Some(s) != own
                    && let Some(to) = to
                    && to != me
                {
                    let consumed = match event {
                        Event::Data { stream, bytes } => Some((stream, bytes.len())),
                        _ => None,
                    };
                    let after = &mut after;
                    return match cx
                        .with_sibling(to, |bcx, req| req.h2_event(bcx, lease, event, prior, after))
                    {
                        Some(heard) => heard,
                        None => match consumed {
                            Some(c) => {
                                let id = c.0.0;
                                trace::of(cx, H2, format_args!("[{id}] Data for unknown"));
                                match after.consumed.try_push(c) {
                                    Ok(()) => Heard::Fine,
                                    Err(_) => Heard::Failed,
                                }
                            }
                            None => Heard::Fine,
                        },
                    };
                }
                self.h2_event(cx, lease, event, prior, &mut after)
            });
            // The streams promised and taken are their transfers' from
            // here, as C sets their user data in `push_promise`. Unlike
            // nghttp2's, the table can be refused memory.
            for &(stream, to) in &after.routed {
                h2.route(stream, to)?;
            }
            Ok(read)
        });
        let goaway = after.goaway;
        let unset = with_session(lease, |h2, _| {
            if let Some(goaway) = goaway {
                h2.set_goaway(goaway);
            }
            // Each window as its transfer asks, before what it took is
            // consumed, as C's write does before `on_data_chunk_recv`
            // consumes.
            let mut unset = None;
            for &(stream, wanted) in &after.windows {
                if let Err(e) = h2.window_to(&mut *cx, stream, wanted) {
                    unset = Some((stream, wanted, e));
                    break;
                }
            }
            for &(stream, n) in &after.consumed {
                // Only a fatal failure matters, and consuming has none.
                let _consumed = h2.session().consume(stream, n);
            }
            for &(stream, code) in &after.resets {
                let _reset = h2.session().reset(stream, code);
            }
            for &stream in &after.resumes {
                let _resumed = h2.session().resume(stream);
            }
            // A sibling's window the session could not set ends its stream,
            // which its transfer finds failed when it next reads.
            if let Some((stream, _, _)) = unset.as_ref().filter(|u| Some(u.0) != own) {
                let _reset = h2.session().reset(*stream, H2Error::C_CALLBACK_FAILURE);
            }
            unset
        });
        after.clear();
        self.stream().after = after;
        if let Some((stream, wanted, e)) = unset.filter(|u| Some(u.0) == own) {
            let kind = window_failed(cx, stream, wanted, e);
            self.stream().failed = Some(kind);
        }
        if goaway.is_some() {
            // Each stream on it learns so (`Curl_multi_connchanged`); no
            // new request goes on it, as it takes no more transfers than
            // it has (`cf_h2_query`).
            self.wake_others(cx, lease);
        }
        let fed = fed.map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        if let Err(e) = fed {
            let n = e.code;
            let text = e.text;
            return Err(trace::fail(
                cx,
                ErrorKind::RecvError,
                format_args!("nghttp2 recv error {n}: {text}"),
            ));
        }
        Ok(())
    }

    /// What the session read, handed on (`on_header`, `on_frame_recv`,
    /// `on_data_chunk_recv`, `on_stream_close`).
    fn h2_event<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        event: Event<'_>,
        goaway: Option<GoAway>,
        after: &mut After,
    ) -> Heard {
        let id = self.stream().id;
        let ours = |s: StreamId| Some(s) == id;
        let pushed = |r: Result<(), curl_alloc::OutOfMemory>| match r {
            Ok(()) => Heard::Fine,
            Err(_) => Heard::Failed,
        };
        match event {
            Event::Header {
                stream,
                name,
                value,
            } if ours(stream) => {
                let s = self.stream();
                if s.body_started {
                    field_line(cx, stream, "trailer", name, value);
                    let s = self.stream();
                    // A trailer, kept until the stream closes; one past
                    // C's limits fails the stream as memory would.
                    return match s.trailers.add(name, value) {
                        Ok(()) => Heard::Fine,
                        Err(OutOfMemory) => self.header_error(cx, ErrorKind::OutOfMemory, after),
                    };
                }
                let mut line = Vec::new();
                let made = if name == b":status" {
                    let Some(code) = decode_status(value) else {
                        return self.header_error(cx, ErrorKind::UnsupportedProtocol, after);
                    };
                    self.stream().status = Some(code);
                    line.try_extend_from_slice(b"HTTP/2 ")
                        .and_then(|()| line.try_extend_from_slice(value))
                        .and_then(|()| line.try_extend_from_slice(b" \r\n"))
                } else {
                    line.try_extend_from_slice(name)
                        .and_then(|()| line.try_extend_from_slice(b": "))
                        .and_then(|()| line.try_extend_from_slice(value))
                        .and_then(|()| line.try_extend_from_slice(b"\r\n"))
                };
                if made.is_err() {
                    return self.header_error(cx, ErrorKind::OutOfMemory, after);
                }
                self.h2_head_line(cx, lease, &line);
                // Traced once written (`on_header`).
                match self.stream().status.filter(|_| name == b":status") {
                    Some(code) => {
                        let id = stream.0;
                        trace::of(cx, H2, format_args!("[{id}] status: HTTP/2 {code:03}"));
                    }
                    None => field_line(cx, stream, "header", name, value),
                }
                Heard::Fine
            }
            Event::HeadersDone { stream, end_stream } if ours(stream) => {
                let s = self.stream();
                if !s.body_started {
                    let Some(status) = s.status else {
                        return Heard::Failed;
                    };
                    if status / 100 != 1 {
                        s.body_started = true;
                    } else {
                        s.status = None;
                    }
                    self.h2_head_line(cx, lease, b"\r\n");
                }
                if end_stream {
                    self.stream_end(cx, stream, after);
                    return Heard::Fine;
                }
                let wanted = wanted_window(cx, self.stream().failed.is_some());
                pushed(after.windows.try_push((stream, wanted)))
            }
            Event::Data { stream, bytes } if ours(stream) => {
                if !self.stream().body_started {
                    after
                        .resets
                        .try_push((stream, H2Error::PROTOCOL_ERROR))
                        .ok();
                }
                if self.stream().failed.is_none() {
                    let written = self.input(cx, lease, bytes);
                    deliver::write_resp(cx, bytes.len(), false, written);
                    if let Err(e) = written {
                        self.stream().failed = Some(e);
                        // `NGHTTP2_ERR_CALLBACK_FAILURE`, as C resets it.
                        after
                            .resets
                            .try_push((stream, H2Error::C_CALLBACK_FAILURE))
                            .ok();
                    }
                }
                // What the write came to (`h2_xfer_write_resp`).
                let id = stream.0;
                let paused = cx.pause().recv_paused();
                let s = self.stream();
                if let Some(e) = s.failed {
                    let (code, len) = (e.number(), bytes.len());
                    trace::of(
                        cx,
                        H2,
                        format_args!(
                            "[{id}] error {code} writing {len} bytes of data, RST-ing stream"
                        ),
                    );
                } else if paused != s.write_paused {
                    s.write_paused = paused;
                    let un = if paused { "" } else { "un" };
                    trace::of(cx, H2, format_args!("[{id}] stream output {un}paused"));
                }
                let wanted = wanted_window(cx, self.stream().failed.is_some());
                pushed(
                    after
                        .windows
                        .try_push((stream, wanted))
                        .and_then(|()| after.consumed.try_push((stream, bytes.len()))),
                )
            }
            // Nobody reads it: consumed as it comes.
            Event::Data { stream, bytes } => {
                let id = stream.0;
                trace::of(cx, H2, format_args!("[{id}] Data for unknown"));
                pushed(after.consumed.try_push((stream, bytes.len())))
            }
            // The frame whole, for the stream's transfer (`on_stream_frame`).
            Event::Received(Frame {
                stream,
                kind:
                    FrameKind::Data {
                        window: (used, size),
                        ..
                    },
                ..
            }) if ours(stream) => {
                let id = stream.0;
                trace::of(cx, H2, format_args!("[{id}] DATA, window={used}/{size}"));
                Heard::Fine
            }
            Event::DataEnd { stream } if ours(stream) => {
                self.stream_end(cx, stream, after);
                Heard::Fine
            }
            Event::WindowUpdate {
                stream: Some(stream),
            } if ours(stream) => {
                let s = self.stream();
                if s.taken < s.sendbuf.len() {
                    return pushed(after.resumes.try_push(stream));
                }
                Heard::Fine
            }
            Event::PushField {
                stream,
                name,
                value,
            } if ours(stream) => self.push_field(cx, stream, name, value, after),
            Event::Promised { stream, promised } if ours(stream) => {
                self.h2_promised(cx, lease, promised, after)
            }
            Event::Reset { stream, error } if ours(stream) => {
                if error != H2Error::NO_ERROR {
                    self.stream().reset_by_server = true;
                }
                Heard::Fine
            }
            Event::Closed { stream, error } if ours(stream) => {
                let s = self.stream();
                s.closed = true;
                s.error = error;
                if error != H2Error::NO_ERROR {
                    s.reset = true;
                    // A stream a GOAWAY refused fails with the GOAWAY's
                    // error, if it had one.
                    let goaway = after.goaway.or(goaway);
                    if error == H2Error::REFUSED_STREAM
                        && let Some(g) = goaway.filter(|g| g.error != H2Error::NO_ERROR)
                    {
                        s.error = g.error;
                    }
                }
                trace_closed(cx, stream, error);
                Heard::Fine
            }
            Event::Closed { stream, .. } => {
                no_easy(cx, stream);
                Heard::Fine
            }
            Event::GoAway { last_stream, error } => {
                after.goaway = Some(GoAway {
                    last: last_stream,
                    error,
                });
                let last = last_stream.0;
                trace::info(
                    cx,
                    format_args!("received GOAWAY, error={error}, last_stream={last}"),
                );
                Heard::Fine
            }
            _ => Heard::Fine,
        }
    }

    /// Step every other transfer with a stream on the connection: what
    /// they share changed, a GOAWAY or the connection's end.
    fn wake_others<H: Host>(&self, cx: &mut StepCx<'_, H>, lease: &ConnLease) {
        let me = cx.me;
        if let Some(h2) = lease.conn().h2() {
            for to in h2.others(me) {
                cx.wake(to);
            }
        }
    }

    /// A field of a PUSH_PROMISE on the stream, kept for the promise
    /// (`on_header`): one naming an authority other than the request's
    /// resets the stream and fails the read, as RFC 9113 makes it a
    /// stream error; past the most there may be, the read fails too.
    fn push_field<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        stream: StreamId,
        name: &[u8],
        value: &[u8],
        after: &mut After,
    ) -> Heard {
        if name == b":authority" {
            match self.serves_authority(value) {
                Ok(true) => {}
                Ok(false) => {
                    after
                        .resets
                        .try_push((stream, H2Error::PROTOCOL_ERROR))
                        .ok();
                    return Heard::Failed;
                }
                Err(OutOfMemory) => return Heard::Failed,
            }
        }
        match self.stream().promise.push(name, value) {
            Ok(()) => Heard::Fine,
            Err(full) => {
                if full == Full::TooMany {
                    trace::fail(
                        cx,
                        ErrorKind::RecvError,
                        format_args!("Too many PUSH_PROMISE headers"),
                    );
                }
                self.stream().promise = PushFields::default();
                Heard::Failed
            }
        }
    }

    /// Whether a promise's `:authority` is the request's origin's: its
    /// host and port, or its host alone at its scheme's port.
    fn serves_authority(&self, value: &[u8]) -> Result<bool, OutOfMemory> {
        let peer = &self.peer;
        let name = peer.name();
        let check = curl_alloc::try_format(format_args!(
            "{}:{}",
            String::from_utf8_lossy(name),
            peer.port()
        ))?;
        let default = if peer.scheme() == HTTPS { 443 } else { 80 };
        Ok(check.as_bytes().eq_ignore_ascii_case(value)
            || (peer.port() == default && name.eq_ignore_ascii_case(value)))
    }

    /// The server promised a response on `promised` (`push_promise`):
    /// offered to the application, it is a new transfer's once taken;
    /// refused, the stream is cancelled, and the application may fail the
    /// request with it.
    fn h2_promised<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        promised: StreamId,
        after: &mut After,
    ) -> Heard {
        let fields = std::mem::take(&mut self.stream().promise);
        let p = promised.0;
        trace::of(cx, H2, format_args!("[{p}] PUSH_PROMISE received"));
        let offered = if cx.wants_push() {
            self.offer(cx, lease, promised, &fields)
        } else {
            if !cx.wants_push() {
                trace::of(cx, H2, format_args!("Got PUSH_PROMISE, ignore it"));
            }
            Offered::Denied
        };
        let pushed = match offered {
            Offered::Added(to) => after.routed.try_push((promised, to)),
            Offered::Denied => after.resets.try_push((promised, H2Error::CANCEL)),
            Offered::Failed => {
                if let Some(id) = self.stream().id {
                    let id = id.0;
                    trace::of(cx, H2, format_args!("[{id}] fail in PUSH_PROMISE received"));
                }
                let s = self.stream();
                s.failed = s.failed.or(Some(ErrorKind::RecvError));
                after.resets.try_push((promised, H2Error::CANCEL))
            }
        };
        match pushed {
            Ok(()) => Heard::Fine,
            Err(OutOfMemory) => Heard::Failed,
        }
    }

    /// Make the pushed transfer's handle and offer it: one whose URL is
    /// not the request's origin's is refused unasked (`set_transfer_url`).
    fn offer<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        promised: StreamId,
        fields: &PushFields,
    ) -> Offered {
        let Ok(Some(url)) = self.pushed_url(fields) else {
            return Offered::Denied;
        };
        let Ok(mut easy) = try_box(cx.easy().pushed()) else {
            return Offered::Denied;
        };
        if easy.report_mut().set_url(&url).is_err() {
            return Offered::Denied;
        }
        cx.offer_push(fields, easy, |pcx, run| {
            let request = Request::pushed(&url, pcx, promised)?;
            let request = try_box(request).map_err(|_| ErrorKind::OutOfMemory)?;
            let origin = lease.conn().origin().cloned();
            let key = pcx
                .pushed_lease(lease)
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
            let proto = crate::proto::ProtoState::Http(request);
            start_pushed(run, pcx, &url, (key, origin), proto)
        })
    }

    /// The URL a promise names by its scheme, authority and path, if it is
    /// one and of the request's origin (`set_transfer_url`,
    /// `Curl_url_same_origin`).
    fn pushed_url(&self, fields: &PushFields) -> Result<Option<Url>, OutOfMemory> {
        let (Some(scheme), Some(authority)) =
            (fields.by_name(b":scheme"), fields.by_name(b":authority"))
        else {
            return Ok(None);
        };
        let path = fields.by_name(b":path").unwrap_or(b"/");
        let mut text = Vec::new();
        text.try_extend_from_slice(scheme)?;
        text.try_extend_from_slice(b"://")?;
        text.try_extend_from_slice(authority)?;
        text.try_extend_from_slice(path)?;
        let opts = ParseOptions {
            disallow_user: true,
            path_as_is: true,
            ..ParseOptions::NONE
        };
        let Ok(url) = Url::parse(&text, opts) else {
            return Ok(None);
        };
        let port = GetOptions {
            default_port: true,
            ..GetOptions::NONE
        };
        let same = url
            .get(Part::Scheme, GetOptions::NONE)
            .is_ok_and(|s| s.eq_ignore_ascii_case(self.peer.scheme().name.as_bytes()))
            && url
                .get(Part::Host, GetOptions::NONE)
                .is_ok_and(|h| h.eq_ignore_ascii_case(self.peer.shown()))
            && url.get(Part::Port, port).is_ok_and(|p| {
                std::str::from_utf8(&p).ok().and_then(|p| p.parse().ok()) == Some(self.peer.port())
            });
        Ok(same.then_some(url))
    }

    /// The request a server imagines for a response it pushes on
    /// `promised`, as the pushed transfer's own: a GET of `url` gone in
    /// HTTP/2, the response's head to come (`http2_data_setup`, with the
    /// size to come unknown).
    pub(crate) fn pushed<H: Host>(
        url: &Url,
        cx: &mut StepCx<'_, H>,
        promised: StreamId,
    ) -> Result<Request, ErrorKind> {
        let scheme = url.get(Part::Scheme, GetOptions::NONE).map_err(url_error)?;
        let secured = scheme.eq_ignore_ascii_case(b"https");
        let inherited = Inherited::new(cx.easy().options().http.version);
        let before = Before {
            first: None,
            method: Method::Get,
            http: &inherited,
        };
        let mut request = Request::new(url, secured, before, cx)?;
        let options = cx.easy().options();
        let (want, proxy_want) = (options.http.auth.0, options.proxy.auth.0);
        cx.easy_mut().auth.start(want, proxy_want);
        let peer = &request.peer;
        let auth = cx
            .easy()
            .auth
            .asked((None, peer), (None, peer), false, true);
        let options = cx.easy().options();
        let http = &options.http;
        let exchange = Exchange {
            sent: response::HttpVersion::Http2,
            reused: true,
            allow_09: http.allow_09,
            asked: Asked {
                head: false,
                ignore_length: http.ignore_content_length,
                max_filesize: options.flow.max_filesize,
                decode_codings: http.transfer_encoding,
                raw_codings: http.raw,
                fail_on_error: http.fail_on_error,
                resume_from: None,
                follow: http.follow != Follow::No,
                auth,
                http_proxy: false,
                time_condition: None,
                forwarded: false,
            },
        };
        request.head = Some(HeadParser::new(exchange));
        request.version = SentIn::Http2;
        request.wire = Wire::H2(H2Stream {
            id: Some(promised),
            body_eos: true,
            ..H2Stream::default()
        });
        request.stage = Stage::Head;
        Ok(request)
    }

    /// A frame ended the stream (`on_stream_frame`'s END_STREAM): one
    /// that ends a response that was no success while the request's body
    /// still goes stops the body by a reset.
    fn stream_end<H: Host>(&mut self, cx: &mut StepCx<'_, H>, stream: StreamId, after: &mut After) {
        let s = self.stream();
        let status = s.status.unwrap_or(0);
        if !s.closed && !s.body_eos && !(200..400).contains(&status) {
            after.resets.try_push((stream, H2Error::STREAM_CLOSED)).ok();
            s.closed = true;
            let id = stream.0;
            let status = s.status.map_or(-1, i32::from);
            trace::of(
                cx,
                H2,
                format_args!(
                    "[{id}] EOS frame with unfinished upload and HTTP status {status}, abort \
                     upload by RST"
                ),
            );
        }
    }

    /// A field could not be read (`cf_h2_header_error`): the stream is
    /// reset, and the read fails.
    fn header_error<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        kind: ErrorKind,
        after: &mut After,
    ) -> Heard {
        let code = kind.number();
        let text = kind.message();
        trace::fail(
            cx,
            kind,
            format_args!("Error receiving HTTP2 header: {code}({text})"),
        );
        let s = self.stream();
        if let Some(id) = s.id {
            after.resets.try_push((id, H2Error::STREAM_CLOSED)).ok();
        }
        s.closed = true;
        s.reset = true;
        Heard::Failed
    }

    /// Hand on a line of the head (`h2_xfer_write_resp_hd`): once writing
    /// failed, nothing more is.
    fn h2_head_line<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        line: &[u8],
    ) {
        if self.stream().failed.is_some() {
            return;
        }
        if let Err(e) = self.head_input(cx, lease, line, true) {
            self.stream().failed = Some(e);
        }
    }

    /// The request is over (`http2_data_done`): a stream still open is
    /// reset, and that goes out.
    pub(super) fn h2_done<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) {
        let stream = self.stream();
        let id = stream.id;
        let open = !stream.closed;
        stream.closed = true;
        if lease.conn().h2().is_none() {
            return;
        }
        let Some(id) = id else {
            return;
        };
        // The stream is no transfer's from here.
        with_session(lease, |h2, _| h2.unroute(id));
        if !open {
            return;
        }
        let _reset = with_session(lease, |h2, _| {
            h2.session().reset(id, H2Error::STREAM_CLOSED)
        });
        // What goes is what can now; a failure is the connection's.
        if self.h2_egress(cx, lease).is_err() {
            lease.get().mark_close();
        }
    }
}

#[cfg(test)]
mod tests;
