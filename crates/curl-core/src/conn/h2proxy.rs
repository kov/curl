//! A tunnel through an HTTPS proxy that speaks HTTP/2 (`cf-h2-proxy.c`):
//! a session with the proxy, whose one stream is the `CONNECT`, and once
//! the proxy answers it, the stream's DATA are the tunnel's bytes both
//! ways. The setup drives the `CONNECT` over the layers below; the
//! session, as it stands then, becomes the layer the tunnel's bytes pass
//! through.

use std::io;
use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::io::{Events, Recv, Sent};
use super::layer::{Alive, Below, Handshake, Layer, LayerAnswer, LayerCx, LayerQuery};
use crate::components::Component;
use crate::error::ErrorKind;
use crate::http2::{
    BodyRead, DEFAULT_WEIGHT, Event, FrameError, H2Error, Heard, Http2, Session, Setting, StreamId,
};

/// What the session reads and writes at a time (`PROXY_H2_CHUNK_SIZE`).
const CHUNK: usize = 16 * 1024;

/// The tunnel stream's receive window (`H2_TUNNEL_WINDOW_SIZE`), which
/// is also as much of its DATA as is held for the layer above.
const TUNNEL_WINDOW: u32 = 10 * 1024 * 1024;

/// The connection's receive window (`PROXY_HTTP2_HUGE_WINDOW_SIZE`).
const CONNECTION_WINDOW: i32 = 100 * 1024 * 1024;

/// The most of the layer above's bytes held for the session to frame
/// (`H2_TUNNEL_SEND_CHUNKS`).
const SEND_MAX: usize = 128 * 1024;

/// The most the session's output holds before it is sent on
/// (`PROXY_H2_NW_SEND_CHUNKS`).
const OUT_MAX: usize = CHUNK;

/// Where the tunnel's `CONNECT` stands (`h2_tunnel_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TunnelState {
    /// No `CONNECT` is open.
    Init,
    /// The `CONNECT` is sent, its answer not whole yet.
    Connect,
    /// The proxy agreed: the stream carries the tunnel.
    Established,
    Failed,
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

    fn new(status: u16) -> Answer {
        Answer {
            status,
            fields: Vec::new(),
            held: 0,
        }
    }

    /// Keep a field, unless it is past the limit, which C's
    /// `Curl_dynhds_add` says as it says memory ran out.
    fn add(&mut self, name: &[u8], value: &[u8]) -> Result<(), OutOfMemory> {
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
    /// Its DATA, not read by the layer above yet: `recv[read..]`.
    recv: Vec<u8>,
    read: usize,
    /// The layer above's bytes, not framed yet.
    send: Vec<u8>,
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
            recv: Vec::new(),
            read: 0,
            send: Vec::new(),
            closed: false,
            error: H2Error::NO_ERROR,
            reset: false,
        }
    }

    fn held(&self) -> &[u8] {
        &self.recv[self.read..]
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
                if self.read == self.recv.len() {
                    self.recv.clear();
                    self.read = 0;
                }
                self.recv.try_extend_from_slice(bytes)?;
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
            Event::Settings | Event::GoAway { .. } => Heard::Fine,
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
    /// yet (`outbufq`): `out[sent..]`.
    out: Vec<u8>,
    sent: usize,
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
            .field("pending", &(self.out.len() - self.sent))
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
            out: Vec::new(),
            sent: 0,
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
        self.tunnel.state = TunnelState::Connect;
        Ok(stream)
    }

    pub(crate) fn stream(&self) -> Option<StreamId> {
        self.tunnel.stream
    }

    pub(crate) fn set_state(&mut self, state: TunnelState) {
        self.tunnel.state = state;
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
        if wants.write || self.sent < self.out.len() || !self.tunnel.send.is_empty() {
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
            self.feed(cx)?;
        }
        while !self.conn_closed
            && !self.tunnel.closed
            && self.input.is_empty()
            && self.tunnel.held().len() < TUNNEL_WINDOW as usize
        {
            let mut buf = [0u8; CHUNK];
            match below.reborrow().recv(cx, &mut buf) {
                Ok(Recv::Data(n)) => {
                    self.input
                        .try_extend_from_slice(&buf[..n.get()])
                        .map_err(|OutOfMemory| Progress::OutOfMemory)?;
                }
                Ok(Recv::WouldBlock) => break,
                Ok(Recv::Eof) => {
                    cx.of(Component::H2Proxy, format_args!("server closed connection"));
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

    /// Hand the session what was read (`proxy_h2_process_pending_input`).
    fn feed(&mut self, cx: &mut dyn LayerCx) -> Result<(), Progress> {
        let H2Proxy {
            session,
            input,
            tunnel,
            goaway,
            ..
        } = self;
        let mut oom = false;
        let mut said = None;
        let read = session.recv(input, &mut |event| {
            if let Event::GoAway { last_stream, error } = event {
                *goaway = Some(last_stream);
                said = Some((error, last_stream));
            }
            match tunnel.heard(&event) {
                Ok(heard) => heard,
                Err(OutOfMemory) => {
                    oom = true;
                    Heard::Failed
                }
            }
        });
        if oom {
            return Err(Progress::OutOfMemory);
        }
        if let Some((error, last)) = said {
            cx.info(format_args!(
                "received GOAWAY, error={error}, last_stream={}",
                last.0
            ));
        }
        match read {
            Ok(n) => {
                input.drain(..n.min(input.len()));
                Ok(())
            }
            Err(e) => {
                cx.fails(
                    ErrorKind::RecvError,
                    format_args!(
                        "process_pending_input: nghttp2_session_mem_recv() returned {}:{}",
                        e.code, e.text
                    ),
                );
                Err(Progress::Recv)
            }
        }
    }

    /// Ask the session for what it wants sent, the tunnel's bytes framed
    /// as its stream's DATA, and send what the layers below take
    /// (`proxy_h2_progress_egress`): whether all of it went.
    pub(crate) fn egress(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
    ) -> Result<bool, Progress> {
        self.blocked = false;
        loop {
            if !self.flush(cx, below.reborrow())? {
                self.blocked = true;
                return Ok(false);
            }
            if !self.session.wants().write {
                return Ok(true);
            }
            let H2Proxy {
                session,
                out,
                tunnel,
                ..
            } = self;
            let mut oom = false;
            let closed = tunnel.closed;
            let send = &mut tunnel.send;
            let tunnel_events = std::cell::RefCell::new(Vec::new());
            let sent = session.send(
                &mut |bytes| {
                    if out.try_extend_from_slice(bytes).is_err() {
                        oom = true;
                        return false;
                    }
                    out.len() < OUT_MAX
                },
                &mut |_, room| {
                    // `tunnel_send_callback`: what is held, the end once
                    // the stream closed and nothing is.
                    if send.is_empty() {
                        return BodyRead::Later;
                    }
                    let n = room.len().min(send.len());
                    room[..n].copy_from_slice(&send[..n]);
                    send.drain(..n);
                    if closed && send.is_empty() {
                        BodyRead::Last(n)
                    } else {
                        BodyRead::Bytes(n)
                    }
                },
                &mut |event| match event {
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
                tunnel
                    .heard(&closed)
                    .map_err(|OutOfMemory| Progress::OutOfMemory)?;
            }
            if oom {
                return Err(Progress::OutOfMemory);
            }
            if let Err(e) = sent
                && e.fatal
            {
                cx.of(
                    Component::H2Proxy,
                    format_args!("[0] nghttp2_session_send error ({}){}", e.text, e.code),
                );
                return Err(Progress::Send);
            }
            if self.out.is_empty() {
                return Ok(true);
            }
        }
    }

    /// Send what the output holds, as far as the layers below take it
    /// (`proxy_h2_nw_out_flush`): whether all of it went.
    fn flush(&mut self, cx: &mut dyn LayerCx, mut below: Below<'_>) -> Result<bool, Progress> {
        while self.sent < self.out.len() {
            match below.reborrow().send(cx, &self.out[self.sent..]) {
                Ok(Sent::Bytes(n)) => self.sent += n.get(),
                Ok(Sent::WouldBlock) => return Ok(false),
                Err(_) => return Err(Progress::Send),
            }
        }
        self.out.clear();
        self.sent = 0;
        Ok(true)
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
        io::Error::other("the HTTP/2 tunnel failed")
    }
}

impl Layer for H2Proxy {
    /// The tunnel's DATA as they come, the stream's window opened by as
    /// much as is read (`cf_h2_proxy_recv`).
    fn recv(
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
        let got = match NonZeroUsize::new(buf.len().min(self.tunnel.held().len())) {
            Some(n) => {
                let held = &self.tunnel.recv[self.tunnel.read..];
                buf[..n.get()].copy_from_slice(&held[..n.get()]);
                self.tunnel.read += n.get();
                let stream = self
                    .tunnel
                    .stream
                    .expect("an established tunnel has its stream");
                if self.session.consume(stream, n.get()).is_err() {
                    return Err(self.failed(ErrorKind::RecvError));
                }
                Ok(Recv::Data(n))
            }
            None => self.nothing_held(cx),
        };
        if let Err(e) = self.egress(cx, below) {
            return Err(self.failed(e.kind()));
        }
        got
    }

    /// The layer above's bytes held for the stream's DATA, as much as is
    /// room for, and as much of them sent as the session and the layers
    /// below take (`cf_h2_proxy_send`).
    fn send(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Below<'_>,
        bytes: &[u8],
    ) -> io::Result<Sent> {
        if self.tunnel.state != TunnelState::Established || self.tunnel.closed {
            return Err(self.failed(ErrorKind::SendError));
        }
        let n = bytes
            .len()
            .min(SEND_MAX - self.tunnel.send.len().min(SEND_MAX));
        if self.tunnel.send.try_extend_from_slice(&bytes[..n]).is_err() {
            return Err(self.failed(ErrorKind::OutOfMemory));
        }
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

    /// What the transfer waits for, as the windows the proxy left say: to
    /// read for a window that is shut, to write while there is room and
    /// something to send (`cf_h2_proxy_adjust_pollset`).
    fn adjust_pollset(&self, wanted: Events) -> Events {
        let (want_recv, want_send) = (wanted.contains(Events::IN), wanted.contains(Events::OUT));
        let held_out = self.sent < self.out.len() || !self.tunnel.send.is_empty();
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
