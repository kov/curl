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
use crate::conn::RecvFailed;
use crate::http2::{BodyRead, Event, Heard, StreamId, code};
use crate::options::HttpVersion as Wanted;
use crate::proto::http2::{EgressFailed, GoAway, H2Conn, SEND_MAX, fields_of, settings};
use crate::tls::Chosen;

/// The most a request's fields may add up to before C warns of them
/// (`MAX_ACC`).
const MAX_FIELDS: usize = 60000;

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
    error: u32,
    reset: bool,
    reset_by_server: bool,
    /// The response's status, while its head is read.
    status: Option<u16>,
    /// The final head ended (`resp_hds_complete`, `bodystarted`): what
    /// follows is body, and a header block after it the trailers.
    body_started: bool,
    /// The trailers, as lines (`resp_trailers`).
    trailers: Vec<u8>,
    /// Writing the response failed (`xfer_result`): nothing more is
    /// written.
    failed: Option<ErrorKind>,
    /// What the session holds to send waits for the connection.
    out_pending: bool,
}

impl H2Stream {
    /// Whether the session's output waits for the connection.
    pub(super) fn out_pending(&self) -> bool {
        self.out_pending
    }

    /// All of the body is in its buffer.
    pub(super) fn body_eos(&self) -> bool {
        self.body_eos
    }
}

/// What the session's reading left to do on it, once it is free to:
/// C calls into the session from its callbacks.
#[derive(Default)]
struct After {
    /// Body bytes of each stream used: their windows open.
    consumed: Vec<(StreamId, usize)>,
    /// Streams to reset, with their codes.
    resets: Vec<(StreamId, u32)>,
    /// The stream's body has more to give.
    resume: bool,
    /// The peer said GOAWAY.
    goaway: Option<GoAway>,
}

/// Run `f` with the connection's session taken off it, the lease free
/// beside it, and put back after.
fn with_session<R>(lease: &mut ConnLease, f: impl FnOnce(&mut H2Conn, &mut ConnLease) -> R) -> R {
    let mut h2 = lease.get().take_h2().expect("an HTTP/2 connection");
    let r = f(&mut h2, lease);
    lease.get().put_h2(h2);
    r
}

/// The text of an HTTP/2 error code, as the library has it.
fn error_text<H: Host>(cx: &StepCx<'_, H>, code: u32) -> &'static str {
    cx.easy()
        .libraries()
        .h2
        .map_or("unknown", |library| library.error_text(code))
}

/// A `:status` read as C reads it (`Curl_http_decode_status`): three
/// digits, the first not 0.
fn decode_status(value: &[u8]) -> Option<u16> {
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
    ) -> Result<bool, ErrorKind> {
        let top = lease.conn().top();
        let alpn = crate::multi::state::query_alpn(cx, lease, top);
        let library = cx.easy().libraries().h2;
        let prior = cx.easy().options().http.version == Wanted::Http2Prior;
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
            let (conn, _) = H2Conn::open(library, &settings(), None)?;
            lease
                .get()
                .put_h2(try_box(conn).map_err(|_| ErrorKind::OutOfMemory)?);
            if prior {
                // No ALPN said so, but the connection speaks it now.
                lease.get().saw_version(ResponseVersion::Http2);
            }
        }
        let version = if h2 { "HTTP/2" } else { "HTTP/1.x" };
        trace::info(cx, format_args!("using {version}"));
        Ok(h2)
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
        let wanted = cx.easy().options().http.version;
        let library = cx.easy().libraries().h2;
        let Some(library) =
            library.filter(|_| !h2 && wanted == Wanted::Http2 && !lease.conn().over_tls())
        else {
            return Ok(None);
        };
        let mut payload = [0u8; 80];
        match library.settings_payload(&settings(), &mut payload) {
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
        let settings = self.upgrade.take().expect("an upgrade asked for");
        let library = cx.easy().libraries().h2.expect("asked with a library");
        let head = self.method == Method::Head;
        let (conn, stream) = H2Conn::open(library, &[], Some((&settings, head)))?;
        lease
            .get()
            .put_h2(try_box(conn).map_err(|_| ErrorKind::OutOfMemory)?);
        // The request went whole in HTTP/1.1.
        self.h2 = Some(H2Stream {
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

    /// Feed the session what came behind a 101, which is HTTP/2 already.
    pub(super) fn upgraded_input<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        rest: &[u8],
    ) -> Result<(), ErrorKind> {
        if rest.is_empty() {
            return Ok(());
        }
        let n = rest.len();
        trace::info(
            cx,
            format_args!(
                "Copied HTTP/2 data in stream buffer to connection buffer after upgrade: len={n}"
            ),
        );
        self.h2_feed(cx, lease, rest)
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
        let head = match self.outgoing {
            Sending::Head { left, .. } => left.get(),
            _ => 0,
        };
        let start = self.sent;
        let mut n = 0;
        if self.stream().id.is_none() {
            // The head goes whole, before any of the body (`h2_submit`).
            let custom = self.custom_method(cx);
            let scheme = self.peer.scheme().name.as_bytes();
            let fields = fields_of(&self.out[start..start + head], custom.as_deref(), scheme)?;
            let pairs = fields.pairs().map_err(|_| ErrorKind::OutOfMemory)?;
            let body = self.body.is_some();
            let id = with_session(lease, |h2, _| h2.session().submit_request(&pairs, body))
                .map_err(|_| ErrorKind::SendError)?;
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
            n = head;
        }
        let body_len = end - start - n;
        if body_len > 0 || eos {
            n += self.h2_body(cx, lease, start + n..end, eos)?;
        }
        self.h2_egress(cx, lease)?;
        let stream = self.stream();
        if stream.closed && !stream.body_started {
            let id = stream.id.map_or(0, |id| id.0);
            trace::info(cx, format_args!("stream {id} closed"));
            return Err(ErrorKind::SendError);
        }
        Ok(n)
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
        let Request { out, h2, .. } = self;
        let stream = h2.as_mut().expect("a request over HTTP/2");
        let id = stream.id.expect("its head went");
        let len = range.len();
        if stream.closed {
            if stream.body_started {
                // The server is done with the request: what is left of its
                // body is dropped, as no transport failed.
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
        let stream = self.h2.as_mut().expect("a request over HTTP/2");
        let H2Stream {
            id,
            sendbuf,
            taken,
            body_eos,
            closed,
            error,
            reset,
            ..
        } = stream;
        let id = *id;
        let sent = with_session(lease, |h2, lease| {
            h2.egress(
                cx,
                lease.get(),
                &mut |s, room| {
                    if Some(s) != id {
                        return BodyRead::Failed;
                    }
                    let n = (sendbuf.len() - *taken).min(room.len());
                    room[..n].copy_from_slice(&sendbuf[*taken..*taken + n]);
                    *taken += n;
                    let empty = *taken == sendbuf.len();
                    match (n, empty && *body_eos) {
                        (_, true) => BodyRead::Last(n),
                        (0, false) => BodyRead::Later,
                        (n, false) => BodyRead::Bytes(n),
                    }
                },
                &mut |event| {
                    if let Event::Closed {
                        stream: s,
                        error: e,
                    } = event
                        && Some(s) == id
                    {
                        *closed = true;
                        *error = e;
                        *reset |= e != 0;
                    }
                    Heard::Fine
                },
            )
        });
        match sent {
            Ok(all) => {
                self.stream().out_pending = !all;
                Ok(())
            }
            Err(EgressFailed::Session(e)) => Err(trace::fail(
                cx,
                ErrorKind::SendError,
                format_args!("nghttp2_session_send() failed: {}({})", e.text, e.code),
            )),
            Err(EgressFailed::Send) => Err(ErrorKind::SendError),
            Err(EgressFailed::OutOfMemory) => Err(ErrorKind::OutOfMemory),
        }
    }

    /// The application's method, if the request line names it.
    fn custom_method<H: Host>(&self, cx: &StepCx<'_, H>) -> Option<Vec<u8>> {
        let custom = cx.easy().options().http.custom.method.as_deref();
        custom.filter(|_| self.custom).and_then(|m| copied(m).ok())
    }

    fn stream(&mut self) -> &mut H2Stream {
        self.h2.as_mut().expect("a request over HTTP/2")
    }

    /// `read_some` over HTTP/2: what the stream has, then what the
    /// connection has, read and handed on as the session reads it, until
    /// the stream is over, a read would block or the step has read its
    /// most (`cf_h2_recv`).
    pub(super) fn h2_read_some<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Read, ErrorKind> {
        let mut reads = 0;
        loop {
            if matches!(self.stage, Stage::Done) || cx.pause().recv_paused() {
                return Ok(Read::Waits);
            }
            if let StreamRecv::Closed = self.stream_recv(cx, lease)? {
                self.h2_ended(cx)?;
                continue;
            }
            if reads == MAX_READS {
                return Ok(Read::Stopped);
            }
            // Under a receive limit, no more than it allows; once spent,
            // the engine waits for it (`sendrecv_dl`'s `rate_limited`).
            let max = cx.easy().options().limits.buffer_size.get();
            let max = match cx.rate_allowance(Way::Recv) {
                Some(..=0) => return Ok(Read::Waits),
                Some(allowed) => max.min(usize::try_from(allowed).unwrap_or(usize::MAX)),
                None => max,
            };
            reads += 1;
            let said = cx.easy().report().reasons();
            let got = lease.get().recv(cx, max);
            match got {
                Ok(Recv::WouldBlock) => {
                    self.h2_egress(cx, lease)?;
                    if let StreamRecv::Closed = self.stream_recv(cx, lease)? {
                        self.h2_ended(cx)?;
                        continue;
                    }
                    return Ok(if lease.get().data_pending() {
                        Read::Stopped
                    } else {
                        Read::Waits
                    });
                }
                Ok(Recv::Eof) => {
                    // The peer closed the connection: the stream ends
                    // with it, whole or not (`h2_progress_ingress`).
                    with_session(lease, |h2, _| h2.set_closed());
                    lease.get().mark_close();
                }
                Ok(Recv::Data(_)) => {
                    let mut rx = std::mem::take(lease.get().rx_mut());
                    let fed = self.h2_feed(cx, lease, rx.filled());
                    let all = rx.filled().len();
                    rx.consume(all);
                    *lease.get().rx_mut() = rx;
                    fed?;
                    self.h2_egress(cx, lease)?;
                }
                Err(e) => {
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
    }

    /// The stream is over and whole: the response ends as a connection's
    /// end ends HTTP/1's (`sendrecv_dl`'s "we are done").
    fn h2_ended<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
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
    /// by a reset, a failure.
    fn stream_recv<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<StreamRecv, ErrorKind> {
        let stream = self.stream();
        if let Some(e) = stream.failed {
            return Err(e);
        }
        if stream.closed {
            self.stream_closed(cx, lease)?;
            return Ok(StreamRecv::Closed);
        }
        let id = stream.id.map_or(0, |id| id.0);
        let h2 = lease.conn().h2().expect("an HTTP/2 connection");
        let gone = h2.closed() || h2.goaway().is_some_and(|g| g.last.0 < id);
        if stream.reset || gone {
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
            if error == code::REFUSED_STREAM {
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
                return Ok(());
            }
            let by = if stream.reset_by_server {
                "server"
            } else {
                "curl"
            };
            let text = error_text(cx, error);
            let kind = if error != 0 {
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
        for line in trailers.split_inclusive(|&b| b == b'\n') {
            trace::bytes(cx, DebugKind::HeaderIn, line);
            self.pipeline.header(cx, line, HeaderOrigin::Trailer)?;
            let head = self.head.as_mut().expect("made at DO");
            let mut request_bytes = head.request_bytes();
            response::count_head(
                line.len() as u64,
                &mut request_bytes,
                &mut cx.report_mut().sizes_mut().header,
            )
            .map_err(|e| head_failed(cx, &e))?;
        }
        Ok(())
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
        let mut after = After::default();
        let prior = lease.conn().h2().and_then(H2Conn::goaway);
        let fed = with_session(lease, |h2, lease| {
            h2.session().recv(bytes, &mut |event| {
                self.h2_event(cx, lease, event, prior, &mut after)
            })
        });
        let id = self.stream().id;
        let resume = after.resume && id.is_some();
        let goaway = after.goaway;
        with_session(lease, |h2, _| {
            if let Some(goaway) = goaway {
                h2.set_goaway(goaway);
            }
            for &(stream, n) in &after.consumed {
                // Only a fatal failure matters, and consuming has none.
                let _consumed = h2.session().consume(stream, n);
            }
            for &(stream, code) in &after.resets {
                let _reset = h2.session().reset(stream, code);
            }
            if resume && let Some(id) = id {
                let _resumed = h2.session().resume(id);
            }
        });
        if goaway.is_some() {
            // No new request goes on it (`Curl_multi_connchanged`).
            lease.get().mark_close();
        }
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
                    // A trailer, kept until the stream closes.
                    let t = &mut s.trailers;
                    return pushed(
                        t.try_extend_from_slice(name)
                            .and_then(|()| t.try_extend_from_slice(b": "))
                            .and_then(|()| t.try_extend_from_slice(value))
                            .and_then(|()| t.try_extend_from_slice(b"\r\n")),
                    );
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
                    self.stream_end(stream, after);
                }
                Heard::Fine
            }
            Event::Data { stream, bytes } if ours(stream) => {
                if !self.stream().body_started {
                    after.resets.try_push((stream, code::PROTOCOL_ERROR)).ok();
                }
                if self.stream().failed.is_none() {
                    let written = self.input(cx, lease, bytes);
                    deliver::write_resp(cx, bytes.len(), false, written);
                    if let Err(e) = written {
                        self.stream().failed = Some(e);
                        // `NGHTTP2_ERR_CALLBACK_FAILURE`, as C resets it.
                        after.resets.try_push((stream, 0xffff_fc7a)).ok();
                    }
                }
                pushed(after.consumed.try_push((stream, bytes.len())))
            }
            // Nobody reads it: consumed as it comes.
            Event::Data { stream, bytes } => pushed(after.consumed.try_push((stream, bytes.len()))),
            Event::DataEnd { stream } if ours(stream) => {
                self.stream_end(stream, after);
                Heard::Fine
            }
            Event::WindowUpdate { stream } if ours(stream) => {
                let s = self.stream();
                if s.taken < s.sendbuf.len() {
                    after.resume = true;
                }
                Heard::Fine
            }
            Event::Reset { stream, error } if ours(stream) => {
                if error != 0 {
                    self.stream().reset_by_server = true;
                }
                Heard::Fine
            }
            Event::Closed { stream, error } if ours(stream) => {
                let s = self.stream();
                s.closed = true;
                s.error = error;
                if error != 0 {
                    s.reset = true;
                    // A stream a GOAWAY refused fails with the GOAWAY's
                    // error, if it had one.
                    let goaway = after.goaway.or(goaway);
                    if error == code::REFUSED_STREAM
                        && let Some(g) = goaway.filter(|g| g.error != 0)
                    {
                        s.error = g.error;
                    }
                }
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

    /// A frame ended the stream (`on_stream_frame`'s END_STREAM): one
    /// that ends a response that was no success while the request's body
    /// still goes stops the body by a reset.
    fn stream_end(&mut self, stream: StreamId, after: &mut After) {
        let s = self.stream();
        let status = s.status.unwrap_or(0);
        if !s.closed && !s.body_eos && !(200..400).contains(&status) {
            after.resets.try_push((stream, code::STREAM_CLOSED)).ok();
            s.closed = true;
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
            after.resets.try_push((id, code::STREAM_CLOSED)).ok();
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
        let Some(id) = stream.id.filter(|_| !stream.closed) else {
            return;
        };
        stream.closed = true;
        if !lease.conn().is_h2() {
            return;
        }
        let _reset = with_session(lease, |h2, _| h2.session().reset(id, code::STREAM_CLOSED));
        // What goes is what can now; a failure is the connection's.
        if self.h2_egress(cx, lease).is_err() {
            lease.get().mark_close();
        }
    }
}

#[cfg(test)]
mod tests;
