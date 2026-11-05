//! A tunnel through an HTTPS proxy that speaks HTTP/2 (`cf-h2-proxy.c`):
//! a session with the proxy, whose one stream is the `CONNECT`, and once
//! the proxy answers it, the stream's DATA are the tunnel's bytes both
//! ways. The setup drives the `CONNECT` over the layers below; the
//! session, as it stands then, becomes the layer the tunnel's bytes pass
//! through.

use std::io;
use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::buf::HeldBytes;
use super::io::{Events, Recv, Sent};
use super::layer::{Alive, Below, Handshake, Layer, LayerAnswer, LayerCx, LayerQuery, Part};
use crate::bufq::{ChunkQueue, Passed};
use crate::components::Component;
use crate::conn::layer::LayerCalls as _;
use crate::error::{AGAIN_NUMBER, ErrorKind};
use crate::http2::{
    BodyRead, DEFAULT_WEIGHT, Event, FrameError, H2Error, Heard, Http2, Session, Setting, StreamId,
    Took,
};

/// What the session reads and writes at a time (`PROXY_H2_CHUNK_SIZE`).
const CHUNK: usize = 16 * 1024;

/// The tunnel stream's receive window (`H2_TUNNEL_WINDOW_SIZE`), which
/// is also as much of its DATA as is held for the layer above.
const TUNNEL_WINDOW: u32 = 10 * 1024 * 1024;

/// The connection's receive window (`PROXY_HTTP2_HUGE_WINDOW_SIZE`).
const CONNECTION_WINDOW: i32 = 100 * 1024 * 1024;

/// The layer above's bytes are held for the session to frame in chunks
/// of `CHUNK`, 128 KiB of them (`H2_TUNNEL_SEND_CHUNKS`).
const SEND_CHUNKS: usize = 128 * 1024 / CHUNK;

/// The session's output is one chunk, sent on whole as the next frame
/// needs its room (`PROXY_H2_NW_SEND_CHUNKS`).
const OUT_CHUNKS: usize = 1;

/// Where the tunnel's `CONNECT` stands (`h2_tunnel_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TunnelState {
    /// No `CONNECT` is open.
    Init,
    /// The `CONNECT` is sent, its answer not whole yet.
    Connect,
    /// The proxy's final answer is whole, and being looked at.
    Response,
    /// The proxy agreed: the stream carries the tunnel.
    Established,
    Failed,
}

/// A line of the layer's (`CURL_TRC_CF` of `cf-h2-proxy`).
const H2P: Component = Component::H2Proxy;

/// A field of the tunnel stream's answer, or of another stream's, as C's
/// `proxy_h2_on_header` traces it: `[<id>] <what>: <name>: <value>`.
fn field_line(cx: &mut dyn LayerCx, stream: StreamId, what: &str, name: &[u8], value: &[u8]) {
    if !cx.traces(H2P) {
        return;
    }
    let id = crate::text::Text::<64>::clipped(format_args!("[{}] {what}: ", stream.0)).0;
    cx.of_with(H2P, &[id.bytes(), name, b": ", value]);
}

/// What the tunnel makes of an event of the session, traced as C's
/// callbacks trace it (`proxy_h2_on_frame_recv`, `proxy_h2_on_header`,
/// `proxy_h2_on_stream_close`): each frame read, the answer's status and
/// fields, its end, the tunnel's close, and what is not the tunnel's.
fn heard_traced(
    tunnel: &mut Tunnel,
    cx: &mut dyn LayerCx,
    library: &dyn Http2,
    event: &Event<'_>,
) -> Result<Heard, OutOfMemory> {
    let ours = |s: StreamId| Some(s) == tunnel.stream;
    match *event {
        Event::Received(f) => {
            let id = f.stream.0;
            cx.of(H2P, format_args!("[{id}] <- {f}"));
            if id == 0 {
                return Ok(Heard::Fine);
            }
            if !ours(f.stream) {
                cx.of(H2P, format_args!("[{id}] rcvd FRAME not for tunnel"));
                return Ok(Heard::Failed);
            }
            if let crate::http2::FrameKind::Headers = f.kind {
                // Only a status makes an answer (`tunnel.resp`).
                let Some(answer) = &tunnel.answer else {
                    return Ok(Heard::Failed);
                };
                let status = answer.status;
                cx.of(H2P, format_args!("[{id}] got http status: {status}"));
            }
            Ok(Heard::Fine)
        }
        Event::Header {
            stream,
            name,
            value,
        } => {
            if !ours(stream) {
                field_line(cx, stream, "header for non-tunnel stream", name, value);
                return Ok(Heard::Failed);
            }
            let trailer = tunnel.final_answer;
            let heard = tunnel.heard(event)?;
            if heard == Heard::Fine && !trailer {
                if name == b":status" {
                    let status = tunnel.answer.as_ref().map_or(0, |a| a.status);
                    let id = stream.0;
                    cx.of(H2P, format_args!("[{id}] status: HTTP/2 {status:03}"));
                } else {
                    field_line(cx, stream, "header", name, value);
                }
            }
            Ok(heard)
        }
        Event::Closed { stream, error } if ours(stream) => {
            let (id, text) = (stream.0, library.error_text(error));
            cx.of(
                H2P,
                format_args!("[{id}] proxy_h2_on_stream_close, {text} (err {error})"),
            );
            tunnel.heard(event)
        }
        Event::GoAway { last_stream, error } => {
            let last = last_stream.0;
            cx.info(format_args!(
                "received GOAWAY, error={error}, last_stream={last}"
            ));
            tunnel.heard(event)
        }
        _ => tunnel.heard(event),
    }
}

/// The proxy's final answer to the `CONNECT`: its status, and its fields
/// but the pseudo-headers, held to C's limit (`Curl_http_resp_make`'s
/// `dynhds` of `DYN_HTTP_REQUEST` bytes of names and values).
#[derive(Debug, Default)]
pub(crate) struct Answer {
    pub(crate) status: u16,
    pub(crate) fields: Vec<(Vec<u8>, Vec<u8>)>,
    /// The bytes of the fields' names and values.
    held: usize,
}

impl Answer {
    const MAX_BYTES: usize = 1024 * 1024;

    pub(crate) fn new(status: u16) -> Answer {
        Answer {
            status,
            fields: Vec::new(),
            held: 0,
        }
    }

    /// The first field named `name`, any case (`Curl_dynhds_cget`).
    pub(crate) fn field(&self, name: &[u8]) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| &v[..])
    }

    /// Keep a field, unless it is past the limit, which C's
    /// `Curl_dynhds_add` says as it says memory ran out.
    pub(crate) fn add(&mut self, name: &[u8], value: &[u8]) -> Result<(), OutOfMemory> {
        let room = Self::MAX_BYTES - self.held;
        if room < name.len() || room - name.len() < value.len() {
            return Err(OutOfMemory);
        }
        let mut n = Vec::new();
        n.try_extend_from_slice(name)?;
        let mut v = Vec::new();
        v.try_extend_from_slice(value)?;
        self.fields.try_push((n, v))?;
        self.held += name.len() + value.len();
        Ok(())
    }
}

/// The `CONNECT`'s stream (`tunnel_stream`).
#[derive(Debug)]
struct Tunnel {
    stream: Option<StreamId>,
    state: TunnelState,
    /// The answer being read: an interim one's replaced by the next.
    answer: Option<Answer>,
    /// The answer read is final, not an interim 1xx.
    final_answer: bool,
    /// Its DATA, not read by the layer above yet.
    recv: HeldBytes,
    /// The layer above's bytes, not framed yet (`sendbuf`), as many as
    /// its chunks have room for.
    send: ChunkQueue,
    closed: bool,
    /// The code it closed with, and whether the proxy reset it.
    error: H2Error,
    reset: bool,
}

impl Tunnel {
    fn new() -> Tunnel {
        Tunnel {
            stream: None,
            state: TunnelState::Init,
            answer: None,
            final_answer: false,
            recv: HeldBytes::default(),
            send: ChunkQueue::new(CHUNK, SEND_CHUNKS),
            closed: false,
            error: H2Error::NO_ERROR,
            reset: false,
        }
    }

    fn held(&self) -> &[u8] {
        self.recv.held()
    }

    /// Take as much of what is held as `buf` has room for into it.
    fn take(&mut self, buf: &mut [u8]) -> usize {
        self.recv.take(buf)
    }

    /// The bytes stored to hold what is held.
    #[cfg(test)]
    fn stored(&self) -> usize {
        self.recv.stored()
    }

    /// What it makes of an event of the session (`proxy_h2_on_header`,
    /// `proxy_h2_on_frame_recv`, `tunnel_recv_callback`,
    /// `proxy_h2_on_stream_close`): anything of another stream, or a
    /// field before the status, fails the read.
    fn heard(&mut self, event: &Event<'_>) -> Result<Heard, OutOfMemory> {
        let ours = |s: &StreamId| Some(*s) == self.stream;
        Ok(match *event {
            Event::Header {
                ref stream,
                name,
                value,
            } => {
                if !ours(stream) {
                    return Ok(Heard::Failed);
                }
                // Trailers the tunnel has no use for.
                if self.final_answer {
                    return Ok(Heard::Fine);
                }
                if name == b":status" {
                    let Some(status) = crate::proto::http::decode_status(value) else {
                        return Ok(Heard::Failed);
                    };
                    self.answer = Some(Answer::new(status));
                    return Ok(Heard::Fine);
                }
                let Some(answer) = &mut self.answer else {
                    return Ok(Heard::Failed);
                };
                // A field past the limit fails the read, as C's callback
                // fails it.
                match answer.add(name, value) {
                    Ok(()) => Heard::Fine,
                    Err(OutOfMemory) => Heard::Failed,
                }
            }
            Event::HeadersDone { ref stream, .. } => {
                if !ours(stream) {
                    return Ok(Heard::Failed);
                }
                let Some(answer) = &self.answer else {
                    return Ok(Heard::Failed);
                };
                if answer.status / 100 != 1 {
                    self.final_answer = true;
                }
                Heard::Fine
            }
            Event::Data { ref stream, bytes } => {
                if !ours(stream) {
                    return Ok(Heard::Failed);
                }
                self.recv.push(bytes)?;
                Heard::Fine
            }
            Event::Reset { ref stream, error } => {
                if !ours(stream) {
                    return Ok(Heard::Failed);
                }
                if error != H2Error::NO_ERROR {
                    self.reset = true;
                }
                Heard::Fine
            }
            Event::Closed { ref stream, error } => {
                if ours(stream) {
                    self.closed = true;
                    self.error = error;
                    if error != H2Error::NO_ERROR {
                        self.reset = true;
                    }
                }
                Heard::Fine
            }
            Event::WindowUpdate { stream: None } => Heard::Fine,
            Event::DataEnd { ref stream }
            | Event::WindowUpdate {
                stream: Some(ref stream),
            } => {
                if ours(stream) {
                    Heard::Fine
                } else {
                    Heard::Failed
                }
            }
            Event::PushField { .. } | Event::Promised { .. } => Heard::Failed,
            Event::Settings { .. } | Event::GoAway { .. } | Event::Received(_) | Event::Sent(_) => {
                Heard::Fine
            }
        })
    }
}

/// Why moving the session on failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Progress {
    /// A receive below failed, or what came could not be read.
    Recv,
    /// The session or a send below failed.
    Send,
    OutOfMemory,
}

impl From<OutOfMemory> for Progress {
    fn from(_: OutOfMemory) -> Progress {
        Progress::OutOfMemory
    }
}

/// Send `bytes` of the session's output to the layers below, traced
/// (`proxy_h2_nw_out_writer`).
fn nw_out_writer(cx: &mut dyn LayerCx, below: Below<'_>, bytes: &[u8]) -> Passed<Progress> {
    let len = bytes.len();
    let (passed, code, n) = match below.send(cx, bytes) {
        Ok(Sent::Bytes(n)) => (Passed::Bytes(n), 0, n.get()),
        Ok(Sent::WouldBlock) => (Passed::Blocked, AGAIN_NUMBER, 0),
        Err(_) => (
            Passed::Failed(Progress::Send),
            ErrorKind::SendError.number(),
            0,
        ),
    };
    cx.of(
        Component::H2Proxy,
        format_args!("[0] nw_out_writer(len={len}) -> {code}, {n}"),
    );
    passed
}

impl Progress {
    pub(crate) fn kind(self) -> ErrorKind {
        match self {
            Progress::Recv => ErrorKind::RecvError,
            Progress::Send => ErrorKind::SendError,
            Progress::OutOfMemory => ErrorKind::OutOfMemory,
        }
    }
}

/// The session with the proxy, and the tunnel's stream on it
/// (`cf_h2_proxy_ctx`).
pub(crate) struct H2Proxy {
    library: &'static dyn Http2,
    session: Box<dyn Session>,
    /// What was read from below and not fed to the session (`inbufq`).
    input: Vec<u8>,
    /// What the session gave to send and the layers below did not take
    /// yet (`outbufq`), a chunk sent whole once it is full.
    out: ChunkQueue,
    tunnel: Tunnel,
    /// The proxy closed the connection.
    conn_closed: bool,
    /// The proxy said GOAWAY: no stream past this one is served.
    goaway: Option<StreamId>,
    sent_goaway: bool,
    /// The layers below took no more of the output (`nw_out_blocked`).
    blocked: bool,
    /// What a receive or send of the layer failed with, for the
    /// transfer's error.
    failure: Option<ErrorKind>,
}

impl std::fmt::Debug for H2Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Proxy")
            .field("stream", &self.tunnel.stream)
            .field("state", &self.tunnel.state)
            .field("held", &self.tunnel.held().len())
            .field("pending", &self.out.len())
            .finish_non_exhaustive()
    }
}

impl H2Proxy {
    /// A session with the proxy: its SETTINGS queued, its receive window
    /// opened, nothing sent yet (`cf_h2_proxy_ctx_init`). The proxy may
    /// open `max_streams` at once, and push nothing.
    pub(crate) fn open(
        library: &'static dyn Http2,
        max_streams: u32,
    ) -> Result<H2Proxy, ErrorKind> {
        let mut session = library
            .client()
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        let settings = [
            Setting::MaxConcurrentStreams(max_streams),
            Setting::InitialWindowSize(TUNNEL_WINDOW),
            Setting::EnablePush(false),
        ];
        session
            .submit_settings(&settings)
            .map_err(|_| ErrorKind::Http2)?;
        session
            .set_local_window(CONNECTION_WINDOW)
            .map_err(|_| ErrorKind::Http2)?;
        Ok(H2Proxy {
            library,
            session,
            input: Vec::new(),
            out: ChunkQueue::new(CHUNK, OUT_CHUNKS),
            tunnel: Tunnel::new(),
            conn_closed: false,
            goaway: None,
            sent_goaway: false,
            blocked: false,
            failure: None,
        })
    }

    /// Take `bytes` the connection received before the session, which it
    /// reads first.
    pub(crate) fn received(&mut self, bytes: Vec<u8>) {
        debug_assert!(self.input.is_empty(), "the session read nothing yet");
        self.input = bytes;
    }

    /// Open the tunnel's stream with the `CONNECT`'s `fields`, a body to
    /// follow: the tunnel's bytes (`proxy_h2_submit`). Any answer to a
    /// `CONNECT` before is forgotten (`tunnel_stream_reset`).
    pub(crate) fn submit(&mut self, fields: &[(&[u8], &[u8])]) -> Result<StreamId, FrameError> {
        self.tunnel = Tunnel::new();
        let stream = self.session.submit_request(fields, true, DEFAULT_WEIGHT)?;
        self.tunnel.stream = Some(stream);
        Ok(stream)
    }

    /// Move the tunnel to `state`, traced (`h2_tunnel_go_state`); `udp`
    /// for a `CONNECT-UDP`'s.
    pub(crate) fn go_state(&mut self, cx: &mut dyn LayerCx, state: TunnelState, udp: bool) {
        if self.tunnel.state == state {
            return;
        }
        let id = self.tunnel.stream.map_or(-1, |s| s.0);
        let name = match state {
            TunnelState::Init => "init",
            TunnelState::Connect => "connect",
            TunnelState::Response => "response",
            TunnelState::Established => "established",
            TunnelState::Failed => "failed",
        };
        cx.of(H2P, format_args!("[{id}] new tunnel state '{name}'"));
        self.tunnel.state = state;
        if state == TunnelState::Established {
            let udp = if udp { "-UDP" } else { "" };
            cx.info(format_args!(
                "CONNECT{udp} phase completed for HTTP/2 proxy"
            ));
        }
    }

    /// The proxy's final answer to the `CONNECT`, once it is whole.
    pub(crate) fn answer(&self) -> Option<&Answer> {
        self.tunnel
            .answer
            .as_ref()
            .filter(|_| self.tunnel.final_answer)
    }

    /// The tunnel's stream closed.
    pub(crate) fn tunnel_closed(&self) -> bool {
        self.tunnel.closed
    }

    /// The proxy closed the connection.
    pub(crate) fn conn_closed(&self) -> bool {
        self.conn_closed
    }

    /// What the session waits for on the socket as the `CONNECT` goes
    /// (`cf_h2_proxy_adjust_pollset`, not connected).
    pub(crate) fn connect_interest(&self) -> Events {
        let wants = self.session.wants();
        let mut events = Events::NONE;
        if wants.read {
            events = events | Events::IN;
        }
        if wants.write || !self.out.is_empty() || !self.tunnel.send.is_empty() {
            events = events | Events::OUT;
        }
        events
    }

    /// Feed the session what was read and not fed, then read from below
    /// until it would block, the connection or the stream closes, or the
    /// stream holds as much as it may (`proxy_h2_progress_ingress`).
    pub(crate) fn ingress(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
    ) -> Result<(), Progress> {
        if !self.input.is_empty() {
            let n = self.input.len();
            cx.of(
                H2P,
                format_args!("[0] process {n} bytes in connection buffer"),
            );
            self.feed(cx)?;
        }
        while !self.conn_closed
            && !self.tunnel.closed
            && self.input.is_empty()
            && self.tunnel.held().len() < TUNNEL_WINDOW as usize
        {
            let mut buf = [0u8; CHUNK];
            let got = below.reborrow().recv(cx, &mut buf);
            // What the read came to, the input as it left it
            // (`Curl_cf_recv_bufq`).
            let (code, n) = match &got {
                Ok(Recv::Data(n)) => (0, n.get()),
                Ok(Recv::WouldBlock) => (AGAIN_NUMBER, 0),
                Ok(Recv::Eof) => (0, 0),
                Err(_) => (ErrorKind::RecvError.number(), 0),
            };
            cx.of(
                H2P,
                format_args!("[0] read {n} bytes nw data -> {code}, {n}"),
            );
            match got {
                Ok(Recv::Data(n)) => {
                    self.input
                        .try_extend_from_slice(&buf[..n.get()])
                        .map_err(|OutOfMemory| Progress::OutOfMemory)?;
                }
                Ok(Recv::WouldBlock) => break,
                Ok(Recv::Eof) => {
                    cx.of(H2P, format_args!("server closed connection"));
                    self.conn_closed = true;
                    break;
                }
                Err(_) => {
                    cx.fails(
                        ErrorKind::RecvError,
                        format_args!("Failed receiving HTTP2 proxy data"),
                    );
                    return Err(Progress::Recv);
                }
            }
            self.feed(cx)?;
        }
        Ok(())
    }

    /// Hand the session what was read, until it has read all of it or
    /// takes no more (`proxy_h2_process_pending_input`), traced as C
    /// traces it.
    fn feed(&mut self, cx: &mut dyn LayerCx) -> Result<(), Progress> {
        let H2Proxy {
            library,
            session,
            input,
            tunnel,
            goaway,
            ..
        } = self;
        while !input.is_empty() {
            let blen = input.len();
            let mut oom = false;
            let read = session.recv(input, &mut |event| {
                if let Event::GoAway { last_stream, .. } = event {
                    *goaway = Some(last_stream);
                }
                match heard_traced(tunnel, &mut *cx, *library, &event) {
                    Ok(heard) => heard,
                    Err(OutOfMemory) => {
                        oom = true;
                        Heard::Failed
                    }
                }
            });
            match &read {
                Ok(n) => cx.of(H2P, format_args!("[0] {blen} bytes to nghttp2 -> {n}")),
                Err(e) => {
                    let code = e.code;
                    cx.of(H2P, format_args!("[0] {blen} bytes to nghttp2 -> {code}"));
                }
            }
            if oom {
                return Err(Progress::OutOfMemory);
            }
            match read {
                Err(e) => {
                    cx.fails(
                        ErrorKind::RecvError,
                        format_args!(
                            "process_pending_input: nghttp2_session_mem_recv() returned {}:{}",
                            e.code, e.text
                        ),
                    );
                    return Err(Progress::Recv);
                }
                // Nothing taken, and no failure: what is left waits.
                Ok(0) => break,
                Ok(n) => {
                    input.drain(..n.min(blen));
                    if input.is_empty() {
                        cx.of(
                            H2P,
                            format_args!("[0] all data in connection buffer processed"),
                        );
                    } else {
                        let left = input.len();
                        cx.of(
                            H2P,
                            format_args!(
                                "[0] process_pending_input: {left} bytes left in connection buffer"
                            ),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Have the session frame what it wants sent, the tunnel's bytes as
    /// its stream's DATA, while it wants to and the layers below do not
    /// block, then send what its output holds (`proxy_h2_progress_egress`):
    /// whether all of it went. The frames go into the output, which is sent
    /// on a chunk at a time as it fills (`proxy_h2_on_session_send`), so
    /// the layers below are sent chunks cut across frames, as C sends them.
    pub(crate) fn egress(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
    ) -> Result<bool, Progress> {
        self.blocked = false;
        while !self.blocked && self.session.wants().write {
            let H2Proxy {
                library,
                session,
                out,
                tunnel,
                blocked,
                ..
            } = self;
            let mut failed = None;
            let closed = tunnel.closed;
            let id = tunnel.stream.map_or(0, |s| s.0);
            let send = &mut tunnel.send;
            let tunnel_events = std::cell::RefCell::new(Vec::new());
            let cx = std::cell::RefCell::new(&mut *cx);
            let sent = session.send(
                &mut |bytes| {
                    let mut cx = cx.borrow_mut();
                    let put = out.write_pass(
                        bytes,
                        Some(&mut |b| nw_out_writer(&mut **cx, below.reborrow(), b)),
                    );
                    match put {
                        Ok(n) => NonZeroUsize::new(n).map_or_else(
                            || {
                                *blocked = true;
                                Took::Blocked
                            },
                            Took::Bytes,
                        ),
                        Err(e) => {
                            if e == Progress::Send {
                                cx.fails(
                                    ErrorKind::SendError,
                                    format_args!("Failed sending HTTP2 data"),
                                );
                            }
                            failed = Some(e);
                            Took::Failed
                        }
                    }
                },
                &mut |_, room| {
                    // `tunnel_send_callback`: what is held, the end once
                    // the stream closed and nothing is.
                    let n = send.read(room);
                    if n == 0 {
                        return BodyRead::Later;
                    }
                    cx.borrow_mut().of(
                        Component::H2Proxy,
                        format_args!("[{id}] tunnel_send_callback -> {n}"),
                    );
                    if closed && send.is_empty() {
                        BodyRead::Last(n)
                    } else {
                        BodyRead::Bytes(n)
                    }
                },
                &mut |event| match event {
                    Event::Sent(frame) => {
                        // `proxy_h2_on_frame_send`.
                        let stream = frame.stream.0;
                        cx.borrow_mut()
                            .of(Component::H2Proxy, format_args!("[{stream}] -> {frame}"));
                        Heard::Fine
                    }
                    Event::Closed { stream, error } => {
                        if tunnel_events
                            .borrow_mut()
                            .try_push((stream, error))
                            .is_err()
                        {
                            return Heard::Failed;
                        }
                        Heard::Fine
                    }
                    _ => Heard::Fine,
                },
            );
            for (stream, error) in tunnel_events.into_inner() {
                let closed = Event::Closed { stream, error };
                heard_traced(tunnel, &mut **cx.borrow_mut(), *library, &closed)
                    .map_err(|OutOfMemory| Progress::OutOfMemory)?;
            }
            if let Some(failed) = failed {
                if failed == Progress::Send
                    && let Err(e) = &sent
                {
                    cx.borrow_mut().of(
                        Component::H2Proxy,
                        format_args!("[0] nghttp2_session_send error ({}){}", e.text, e.code),
                    );
                }
                return Err(failed);
            }
            if let Err(e) = sent {
                if e.fatal {
                    cx.borrow_mut().of(
                        Component::H2Proxy,
                        format_args!("[0] nghttp2_session_send error ({}){}", e.text, e.code),
                    );
                    return Err(Progress::Send);
                }
                break;
            }
        }
        self.flush(cx, below)
    }

    /// Send what the output holds, as far as the layers below take it
    /// (`proxy_h2_nw_out_flush`): whether all of it went.
    fn flush(&mut self, cx: &mut dyn LayerCx, mut below: Below<'_>) -> Result<bool, Progress> {
        if self.out.is_empty() {
            return Ok(true);
        }
        let went = self
            .out
            .pass(&mut |b| nw_out_writer(&mut *cx, below.reborrow(), b))?;
        if went == 0 {
            let held = self.out.len();
            cx.of(
                Component::H2Proxy,
                format_args!("[0] flush nw send buffer({held}) -> EAGAIN"),
            );
            self.blocked = true;
            return Ok(false);
        }
        cx.of(
            Component::H2Proxy,
            format_args!("[0] nw send buffer flushed"),
        );
        Ok(self.out.is_empty())
    }

    /// The session wants neither to read nor to write: it is over
    /// (`proxy_h2_should_close_session`).
    fn over(&self) -> bool {
        let wants = self.session.wants();
        !wants.read && !wants.write
    }

    /// What the tunnel's stream gives the layer above when it holds
    /// nothing (`tunnel_recv`, `h2_handle_tunnel_close`).
    fn nothing_held(&mut self, cx: &mut dyn LayerCx) -> io::Result<Recv> {
        let stream = self.tunnel.stream.map_or(-1, |s| s.0);
        if self.tunnel.closed {
            if self.tunnel.error != H2Error::NO_ERROR {
                let by = if self.tunnel.reset { "server" } else { "curl" };
                let error = self.tunnel.error;
                cx.fails(
                    ErrorKind::RecvError,
                    format_args!(
                        "HTTP/2 stream {stream} reset by {by} (error 0x{error:x} {})",
                        self.library.error_text(error)
                    ),
                );
                return Err(self.failed(ErrorKind::RecvError));
            }
            cx.of(H2P, format_args!("[{stream}] handle_tunnel_close -> 0"));
            return Ok(Recv::Eof);
        }
        let gone = self.goaway.is_some_and(|last| last.0 < stream);
        if self.tunnel.reset || (self.conn_closed && self.input.is_empty()) || gone {
            return Err(self.failed(ErrorKind::RecvError));
        }
        Ok(Recv::WouldBlock)
    }

    /// The layer's receive or send fails with `kind`.
    fn failed(&mut self, kind: ErrorKind) -> io::Error {
        self.failure.get_or_insert(kind);
        // A bare kind, which allocates nothing: the failure is `kind`.
        io::Error::from(io::ErrorKind::Other)
    }
}

impl Part<Below<'_>> for H2Proxy {
    /// What the transfer waits for, as the windows the proxy left say: to
    /// read for a window that is shut, to write while there is room and
    /// something to send (`cf_h2_proxy_adjust_pollset`).
    fn adjust_pollset(&self, wanted: Events) -> Events {
        let (want_recv, want_send) = (wanted.contains(Events::IN), wanted.contains(Events::OUT));
        let held_out = !self.out.is_empty() || !self.tunnel.send.is_empty();
        if self.sent_goaway {
            let wants = self.session.wants();
            return events(wants.read, wants.write || held_out);
        }
        if !want_recv && !want_send {
            return wanted;
        }
        let c_exhaust = self.session.remote_window() == 0;
        let s_exhaust = self
            .tunnel
            .stream
            .is_some_and(|s| self.session.stream_remote_window(s) == 0);
        let recv = want_recv || c_exhaust || s_exhaust;
        let send =
            (!s_exhaust && want_send) || (!c_exhaust && self.session.wants().write) || held_out;
        events(recv, send)
    }

    fn data_pending(&self, below: Below<'_>) -> bool {
        !self.input.is_empty()
            || (self.tunnel.state == TunnelState::Established && !self.tunnel.held().is_empty())
            || below.data_pending()
    }

    /// Alive while the layers below are and the session is not over: what
    /// an idle connection was sent, the proxy's frames, is read
    /// (`proxy_h2_connisalive`).
    fn is_alive(&mut self, cx: &mut dyn LayerCx, mut below: Below<'_>) -> Alive {
        match below.reborrow().alive(cx) {
            Alive::Dead => Alive::Dead,
            Alive::Alive {
                input_pending: false,
            } => Alive::Alive {
                input_pending: false,
            },
            Alive::Alive {
                input_pending: true,
            } => {
                let mut buf = [0u8; CHUNK];
                let alive = match below.recv(cx, &mut buf) {
                    Ok(Recv::Data(n)) => {
                        self.input.try_extend_from_slice(&buf[..n.get()]).is_ok()
                            && self.feed(cx).is_ok()
                            && !self.over()
                    }
                    Ok(Recv::Eof) => {
                        self.conn_closed = true;
                        !self.over()
                    }
                    Ok(Recv::WouldBlock) => true,
                    Err(_) => false,
                };
                if alive {
                    Alive::Alive {
                        input_pending: false,
                    }
                } else {
                    Alive::Dead
                }
            }
        }
    }

    fn filter(&self) -> Option<Component> {
        Some(Component::H2Proxy)
    }

    /// Say GOAWAY, once, and move the session on until it is done
    /// (`cf_h2_proxy_shutdown`).
    fn shutdown(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
    ) -> Result<Handshake, ErrorKind> {
        if self.tunnel.state != TunnelState::Established || self.conn_closed {
            return Ok(Handshake::Done);
        }
        if !self.sent_goaway {
            if let Err(e) = self.session.goaway(H2Error::NO_ERROR, b"shutdown\0") {
                return Err(cx.fails(
                    ErrorKind::SendError,
                    format_args!("nghttp2_submit_goaway() failed: {}({})", e.text, e.code),
                ));
            }
            self.sent_goaway = true;
        }
        let mut result = Ok(());
        if self.session.wants().write {
            result = self.egress(cx, below.reborrow()).map(|_| ());
        }
        if result.is_ok() && self.session.wants().read {
            result = self.ingress(cx, below);
        }
        match result {
            Err(e) => Err(e.kind()),
            Ok(()) if self.conn_closed || self.over() => Ok(Handshake::Done),
            Ok(()) => Ok(Handshake::Waiting),
        }
    }

    fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        match q {
            LayerQuery::Failure => self.failure.map(LayerAnswer::Failure),
            LayerQuery::Tunnel => Some(LayerAnswer::Tunnel(Component::H2Proxy)),
            _ => None,
        }
    }
}

impl Layer for H2Proxy {
    /// The tunnel's DATA as they come, the stream's window opened by as
    /// much as is read (`cf_h2_proxy_recv`).
    fn recv(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        let len = buf.len();
        let got = self.recv_on(cx, below, buf);
        let (code, n) = self.code_of(&got);
        let id = self.tunnel.stream.map_or(-1, |s| s.0);
        cx.of(
            H2P,
            format_args!("[{id}] cf_recv(len={len}) -> {code}, {n}"),
        );
        got
    }

    /// The layer above's bytes held for the stream's DATA, as much as is
    /// room for, and as much of them sent as the session and the layers
    /// below take (`cf_h2_proxy_send`), traced with the windows and the
    /// buffers it left.
    fn send(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, bytes: &[u8]) -> io::Result<Sent> {
        let sent = self.send_on(cx, below, bytes);
        let (code, n) = match &sent {
            Ok(Sent::Bytes(n)) => (0, n.get()),
            Ok(Sent::WouldBlock) => (AGAIN_NUMBER, 0),
            Err(_) => (self.failure.unwrap_or(ErrorKind::SendError).number(), 0),
        };
        let (len, id) = (bytes.len(), self.tunnel.stream.map_or(0, |s| s.0));
        let (sw, cw) = (
            self.session.stream_remote_window(StreamId(id)),
            self.session.remote_window(),
        );
        let (held, out) = (self.tunnel.send.len(), self.out.len());
        cx.of(
            Component::H2Proxy,
            format_args!(
                "[{id}] cf_send(len={len}) -> {code}, {n}, h2 windows {sw}-{cw} (stream-conn), \
                 buffers {held}-{out} (stream-conn)"
            ),
        );
        sent
    }
}

impl H2Proxy {
    /// The code and length C's lines give what a receive came to.
    fn code_of(&self, got: &io::Result<Recv>) -> (u16, usize) {
        match got {
            Ok(Recv::Data(n)) => (0, n.get()),
            Ok(Recv::WouldBlock) => (AGAIN_NUMBER, 0),
            Ok(Recv::Eof) => (0, 0),
            Err(_) => (self.failure.unwrap_or(ErrorKind::RecvError).number(), 0),
        }
    }

    /// `recv`, short of its last line: what the stream holds, read from
    /// below first if it holds nothing; the stream's window opened by as
    /// much as is taken; then what the session has to send.
    fn recv_on(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
        buf: &mut [u8],
    ) -> io::Result<Recv> {
        if self.tunnel.state != TunnelState::Established {
            return Err(self.failed(ErrorKind::RecvError));
        }
        if self.tunnel.held().is_empty()
            && let Err(e) = self.ingress(cx, below.reborrow())
        {
            return Err(self.failed(e.kind()));
        }
        let got = self.tunnel_recv(cx, buf);
        if let Ok(r) = &got
            && !matches!(r, Recv::WouldBlock)
        {
            let n = self.code_of(&got).1;
            let stream = self
                .tunnel
                .stream
                .expect("an established tunnel has its stream");
            cx.of(H2P, format_args!("[{}] increase window by {n}", stream.0));
            if self.session.consume(stream, n).is_err() {
                return Err(self.failed(ErrorKind::RecvError));
            }
        }
        // A failure to send is the receive's only if it had none of its
        // own (`Curl_1st_fatal`).
        if let Err(e) = self.egress(cx, below)
            && got.is_ok()
        {
            return Err(self.failed(e.kind()));
        }
        got
    }

    /// What the stream holds, as much as `buf` has room for, or what its
    /// holding nothing means (`tunnel_recv`), traced.
    fn tunnel_recv(&mut self, cx: &mut dyn LayerCx, buf: &mut [u8]) -> io::Result<Recv> {
        let len = buf.len();
        let got = match NonZeroUsize::new(self.tunnel.take(buf)) {
            Some(n) => Ok(Recv::Data(n)),
            None => self.nothing_held(cx),
        };
        let (code, n) = self.code_of(&got);
        let id = self.tunnel.stream.map_or(-1, |s| s.0);
        cx.of(
            H2P,
            format_args!("[{id}] tunnel_recv(len={len}) -> {code}, {n}"),
        );
        got
    }

    /// `send`, short of its last line.
    fn send_on(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
        bytes: &[u8],
    ) -> io::Result<Sent> {
        if self.tunnel.state != TunnelState::Established || self.tunnel.closed {
            return Err(self.failed(ErrorKind::SendError));
        }
        let n = match self.tunnel.send.fill(bytes) {
            Ok(n) => n,
            Err(OutOfMemory) => return Err(self.failed(ErrorKind::OutOfMemory)),
        };
        // A buffer with no room for any of it is C's `CURLE_AGAIN`.
        let code = if n == 0 && !bytes.is_empty() {
            AGAIN_NUMBER
        } else {
            0
        };
        cx.of(
            Component::H2Proxy,
            format_args!("cf_send(), bufq_write {code}, {n}"),
        );
        let stream = self
            .tunnel
            .stream
            .expect("an established tunnel has its stream");
        if !self.tunnel.send.is_empty()
            && let Err(e) = self.session.resume(stream)
            && e.fatal
        {
            return Err(self.failed(ErrorKind::SendError));
        }
        if let Err(e) = self.ingress(cx, below.reborrow()) {
            return Err(self.failed(e.kind()));
        }
        if let Err(e) = self.egress(cx, below) {
            return Err(self.failed(e.kind()));
        }
        if self.over() {
            if self.tunnel.closed {
                return Err(self.failed(ErrorKind::SendError));
            }
            cx.of(
                Component::H2Proxy,
                format_args!("[0] send: nothing to do in this session"),
            );
            return Err(self.failed(ErrorKind::Http2));
        }
        Ok(NonZeroUsize::new(n).map_or(Sent::WouldBlock, Sent::Bytes))
    }
}

fn events(recv: bool, send: bool) -> Events {
    let mut events = Events::NONE;
    if recv {
        events = events | Events::IN;
    }
    if send {
        events = events | Events::OUT;
    }
    events
}

#[cfg(test)]
mod tests;
