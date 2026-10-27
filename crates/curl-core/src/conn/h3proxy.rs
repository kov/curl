//! A tunnel through an HTTPS proxy that speaks HTTP/3 (`cf-ngtcp2-proxy.c`):
//! a QUIC connection to the proxy, whose one request stream is the
//! `CONNECT`, and once the proxy answers it, the stream's DATA are the
//! tunnel's bytes both ways. The connection's handshake is a QUIC attempt
//! of the setup's; the setup then drives the `CONNECT` over it, and the
//! connection, as it stands then, becomes the bottom layer, over the UDP
//! socket, that the tunnel's bytes pass through.

use std::io;
use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::h2proxy::Answer;
use super::io::{Events, Recv, Sent, Socket};
use super::layer::{Alive, Below, Handshake, Layer, LayerAnswer, LayerCx, LayerQuery, Part};
use super::quic::{Quic, QuicCx, QuicIo, RECV_ROOM};
use crate::components::Component;
use crate::error::{AGAIN_NUMBER, ErrorKind};
use crate::http3::{Event, H3Error, Heard, StreamId};
use crate::time::Instant;

/// How much of the tunnel's DATA is held for the layer above, which its
/// receive window is kept open to (`PROXY_H3_TUNNEL_RX_WIN`).
const TUNNEL_WINDOW: u64 = 512 * 1024;

/// The stream's receive window as it opens
/// (`H3_STREAM_WINDOW_SIZE_INITIAL`).
const STREAM_WINDOW_INITIAL: u64 = super::quic::STREAM_WINDOW_INITIAL;

/// The traces' component.
const H3P: Component = Component::H3Proxy;

/// Where the tunnel's `CONNECT` stands (`h3_tunnel_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TunnelState {
    /// No `CONNECT` is open.
    Init,
    /// The `CONNECT` is sent, its answer not whole yet.
    Connect,
    /// The proxy's final answer is whole.
    Response,
    /// The proxy agreed: the stream carries the tunnel.
    Established,
    Failed,
}

/// The `CONNECT`'s stream (`h3_tunnel_stream`).
#[derive(Debug)]
struct Tunnel {
    /// None before the `CONNECT`, and once the stream closed
    /// (`ts->stream`, cleared by the close).
    stream: Option<StreamId>,
    /// The stream it was, for the traces after.
    last: i64,
    state: TunnelState,
    /// The answer being read: an interim one's replaced by the next.
    answer: Option<Answer>,
    /// The status of the answer being read (`status_code`).
    status: u16,
    /// The answer read is final, not an interim 1xx.
    final_answer: bool,
    /// Its DATA, not read by the layer above yet: `recv[read..]`.
    recv: Vec<u8>,
    read: usize,
    /// The DATA received in all (`rx_total`), and the receive window's
    /// offsets (`rx_offset`, `rx_offset_max`).
    rx_total: u64,
    rx_offset: u64,
    rx_offset_max: u64,
    /// The window to open by, once the library's call is over.
    extend: u64,
    closed: bool,
    /// The code it closed with, and whether the proxy reset it.
    error: H3Error,
    reset: bool,
    /// The library may send none of the stream's data for its flow
    /// control (`quic_flow_blocked`).
    flow_blocked: bool,
}

impl Tunnel {
    fn new() -> Tunnel {
        Tunnel {
            stream: None,
            last: -1,
            state: TunnelState::Init,
            answer: None,
            status: 0,
            final_answer: false,
            recv: Vec::new(),
            read: 0,
            rx_total: 0,
            rx_offset: 0,
            rx_offset_max: STREAM_WINDOW_INITIAL,
            extend: 0,
            closed: false,
            error: H3Error::NO_ERROR,
            reset: false,
            flow_blocked: false,
        }
    }

    fn held(&self) -> &[u8] {
        &self.recv[self.read..]
    }

    /// The stream's id as traced: -1 once it is gone.
    fn id(&self) -> i64 {
        self.stream.map_or(-1, |s| s.0)
    }

    /// Open the receive window back to what is held for the layer above
    /// allowing for as much again (`cf_h3_proxy_upd_rx_win`): by how much,
    /// once the library's call is over.
    fn update_window(&mut self, cx: &mut dyn LayerCx) {
        let Some(stream) = self.stream else { return };
        let buffered = self.held().len() as u64;
        let wanted = TUNNEL_WINDOW.saturating_sub(buffered);
        let current = self.rx_offset_max - self.rx_offset;
        if wanted > current {
            let delta = (wanted - current).min(u64::MAX - self.rx_offset_max);
            if delta > 0 {
                let id = stream.0;
                cx.of(
                    H3P,
                    format_args!(
                        "[{id}] rx window, extend {current} (buffered {buffered}) by {delta} bytes"
                    ),
                );
                self.rx_offset_max += delta;
                self.extend += delta;
            }
        }
    }

    /// What it makes of an event of the connection's streams
    /// (`ngh3_proxy_callbacks`): one of another stream is let be, as C's
    /// callbacks find no tunnel for it.
    fn heard(&mut self, cx: &mut dyn LayerCx, event: Event<'_>) -> Heard {
        let ours = |s: StreamId, me: Option<StreamId>| Some(s) == me;
        match event {
            Event::Header {
                stream,
                name,
                value,
                status,
            } => {
                if !ours(stream, self.stream) || self.final_answer {
                    return Heard::Fine;
                }
                if status {
                    let Some(code) = crate::proto::http::decode_status(value) else {
                        return Heard::Failed;
                    };
                    self.status = code;
                    self.answer = Some(Answer::new(code));
                    return Heard::Fine;
                }
                let Some(answer) = &mut self.answer else {
                    return Heard::Failed;
                };
                let (id, n, v) = (
                    stream.0,
                    String::from_utf8_lossy(name),
                    String::from_utf8_lossy(value),
                );
                cx.of(H3P, format_args!("[{id}] header: {n}: {v}"));
                match answer.add(name, value) {
                    Ok(()) => Heard::Fine,
                    Err(OutOfMemory) => Heard::Failed,
                }
            }
            Event::HeadersDone { stream } => {
                if !ours(stream, self.stream) {
                    return Heard::Fine;
                }
                let (id, status) = (stream.0, self.status);
                cx.of(H3P, format_args!("[{id}] end_headers, status={status}"));
                if status / 100 != 1 {
                    self.final_answer = true;
                }
                Heard::Fine
            }
            Event::Data { stream, bytes } => {
                if !ours(stream, self.stream) {
                    return Heard::Failed;
                }
                let (id, len) = (stream.0, bytes.len());
                self.rx_total += len as u64;
                let total = self.rx_total;
                cx.of(
                    H3P,
                    format_args!("[cb_h3_proxy_recv_data] [{id}] DATA len={len}, total={total}"),
                );
                if self.read == self.recv.len() {
                    self.recv.clear();
                    self.read = 0;
                }
                if self.recv.try_extend_from_slice(bytes).is_err() {
                    return Heard::Failed;
                }
                self.rx_offset += len as u64;
                self.rx_offset_max = self.rx_offset_max.max(self.rx_offset);
                let win = self.rx_offset_max - self.rx_offset;
                cx.of(H3P, format_args!("[{id}] DATA len={len}, rx win={win}"));
                self.update_window(cx);
                Heard::Fine
            }
            Event::Closed { stream, error } => {
                if !ours(stream, self.stream) {
                    return Heard::Fine;
                }
                let id = stream.0;
                self.error = error;
                if error == H3Error::NO_ERROR {
                    cx.of(H3P, format_args!("[{id}] CLOSED"));
                } else {
                    self.reset = true;
                    let code = error.0;
                    cx.of(H3P, format_args!("[{id}] RESET: error {code}"));
                }
                self.stream = None;
                self.closed = true;
                Heard::Fine
            }
            Event::QuicClosed { stream, error, rv } => {
                let (id, error) = (stream.0, error.0);
                cx.of(
                    H3P,
                    format_args!("[{id}] quic close(app_error={error}) -> {rv}"),
                );
                Heard::Fine
            }
            Event::H3Reset { stream, rv } => {
                if ours(stream, self.stream) {
                    let id = stream.0;
                    cx.of(H3P, format_args!("[{id}] reset -> {rv}"));
                    self.stream = None;
                    self.closed = true;
                }
                Heard::Fine
            }
            Event::BodyRead {
                stream,
                vecs,
                n,
                eof,
                buffered,
            } => {
                let id = stream.0;
                if n == 0 {
                    cx.of(H3P, format_args!("[{id}] read req body -> AGAIN"));
                } else {
                    let eof = if eof { " EOF" } else { "" };
                    cx.of(
                        H3P,
                        format_args!(
                            "[{id}] read req body -> {vecs} vecs{eof} with {n} (buffered={buffered})"
                        ),
                    );
                }
                Heard::Fine
            }
            Event::Blocked { stream } => {
                if ours(stream, self.stream) {
                    self.flow_blocked = true;
                }
                Heard::Fine
            }
            Event::Unblocked { stream } => {
                if ours(stream, self.stream) {
                    self.flow_blocked = false;
                }
                Heard::Fine
            }
            Event::QuicReset { .. } | Event::Consumed { .. } => Heard::Fine,
            Event::HandshakeDone { .. } | Event::H3Failed { .. } | Event::MaxBidiStreams(_) => {
                unreachable!("the connection's own events are its own")
            }
        }
    }
}

/// The QUIC connection to the proxy, and the tunnel's stream on it
/// (`cf_h3_proxy_ctx`).
pub(crate) struct H3Proxy {
    quic: Box<Quic>,
    tunnel: Tunnel,
    /// The room the connection receives in, kept between calls.
    room: Vec<u8>,
    /// What a receive or send of the layer failed with, for the
    /// transfer's error.
    failure: Option<ErrorKind>,
}

impl std::fmt::Debug for H3Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Proxy")
            .field("stream", &self.tunnel.stream)
            .field("state", &self.tunnel.state)
            .field("held", &self.tunnel.held().len())
            .finish_non_exhaustive()
    }
}

/// A call into the connection: the transfer's context, the socket, and
/// the tunnel each stream event goes to.
struct Tunnelled<'a> {
    cx: &'a mut dyn LayerCx,
    socket: &'a dyn Socket,
    tunnel: &'a mut Tunnel,
    room: &'a mut Vec<u8>,
}

impl LayerCx for Tunnelled<'_> {
    fn now(&self) -> Instant {
        self.cx.now()
    }

    fn of(&mut self, component: Component, line: std::fmt::Arguments<'_>) {
        self.cx.of(component, line);
    }

    fn info(&mut self, line: std::fmt::Arguments<'_>) {
        self.cx.info(line);
    }

    fn socket_failed(&mut self, e: &io::Error) {
        self.cx.socket_failed(e);
    }

    fn fails(&mut self, kind: ErrorKind, why: std::fmt::Arguments<'_>) -> ErrorKind {
        self.cx.fails(kind, why)
    }

    fn bytes(&mut self, kind: crate::handler::DebugKind, bytes: &[u8]) {
        self.cx.bytes(kind, bytes);
    }

    fn debugs(&self) -> bool {
        self.cx.debugs()
    }

    fn verbose(&self) -> bool {
        self.cx.verbose()
    }

    fn certinfo_report(&mut self) -> Option<&mut crate::report::TransferReport> {
        self.cx.certinfo_report()
    }

    fn tls_verified(&mut self, filter: Component, result: i64) {
        self.cx.tls_verified(filter, result);
    }

    fn configures_tls(&self) -> bool {
        self.cx.configures_tls()
    }

    fn configure_tls(&mut self, native: crate::tls::TlsNative) -> Result<(), ErrorKind> {
        self.cx.configure_tls(native)
    }

    fn pause_recv(&mut self) {
        self.cx.pause_recv();
    }

    fn unix_time(&self) -> i64 {
        self.cx.unix_time()
    }

    fn has_tls_sessions(&self) -> bool {
        self.cx.has_tls_sessions()
    }

    fn tls_sessions(&mut self, f: &mut dyn FnMut(&mut crate::tls::SessionCache, &mut dyn LayerCx)) {
        self.cx.tls_sessions(f);
    }

    fn h3_event(&mut self, event: Event<'_>) -> Heard {
        self.tunnel.heard(&mut *self.cx, event)
    }

    fn quic_due(&mut self, wait: std::time::Duration) {
        self.cx.quic_due(wait);
    }
}

impl QuicCx for Tunnelled<'_> {
    fn take_room(&mut self) -> Result<Vec<u8>, OutOfMemory> {
        let mut room = std::mem::take(self.room);
        if room.len() < RECV_ROOM {
            room.try_resize(RECV_ROOM, 0)?;
        }
        Ok(room)
    }

    fn give_room(&mut self, room: Vec<u8>) {
        *self.room = room;
    }
}

impl QuicIo for Tunnelled<'_> {
    fn socket(&self) -> &dyn Socket {
        self.socket
    }
}

impl H3Proxy {
    /// The tunnel over `quic`, a connection to the proxy whose handshake
    /// is done; nothing asked of it yet.
    pub(crate) fn new(quic: Box<Quic>) -> H3Proxy {
        H3Proxy {
            quic,
            tunnel: Tunnel::new(),
            room: Vec::new(),
            failure: None,
        }
    }

    /// Run `f` on the connection, its streams' events the tunnel's, then
    /// open the tunnel's window by what they asked.
    fn call<R>(
        &mut self,
        cx: &mut dyn LayerCx,
        socket: &dyn Socket,
        f: impl FnOnce(&mut Quic, &mut dyn QuicIo) -> R,
    ) -> R {
        let H3Proxy {
            quic, tunnel, room, ..
        } = self;
        let mut over = Tunnelled {
            cx,
            socket,
            tunnel,
            room,
        };
        let r = f(quic, &mut over);
        let extend = std::mem::take(&mut self.tunnel.extend);
        if extend > 0
            && let Some(stream) = self.tunnel.stream
        {
            self.quic.extend_stream_window(stream, extend);
        }
        r
    }

    /// Open the tunnel's stream with the `CONNECT`'s `fields` for the
    /// transfer of `url`, its body to follow: the tunnel's bytes
    /// (`cf_h3_proxy_submit`). The answer to a `CONNECT` before is
    /// forgotten (`h3_tunnel_stream_reset`).
    pub(crate) fn submit(
        &mut self,
        cx: &mut dyn LayerCx,
        socket: &dyn Socket,
        fields: &[(&[u8], &[u8])],
        url: &[u8],
    ) -> Result<(), ErrorKind> {
        self.tunnel = Tunnel::new();
        let verbose = cx.verbose();
        let stream = self.call(cx, socket, |quic, over| {
            // The connection's first stream keeps it alive
            // (`Curl_cf_ngtcp2_h3_stream_setup`).
            quic.keep_alive(over, 1);
            quic.submit(over, fields, true)
        });
        let stream = stream?;
        self.tunnel.stream = Some(stream);
        self.tunnel.last = stream.0;
        let id = stream.0;
        cx.of(H3P, format_args!("[{id}] opened bidi stream"));
        if verbose {
            let url = String::from_utf8_lossy(url);
            cx.of(
                H3P,
                format_args!("[H3-PROXY] [{id}] OPENED stream for {url}"),
            );
        }
        Ok(())
    }

    /// Move the tunnel to `state`, traced (`h3_tunnel_go_state`).
    pub(crate) fn go_state(&mut self, cx: &mut dyn LayerCx, state: TunnelState) {
        if self.tunnel.state == state {
            return;
        }
        let id = self.tunnel.last;
        let name = match state {
            TunnelState::Init => "init",
            TunnelState::Connect => "connect",
            TunnelState::Response => "response",
            TunnelState::Established => "established",
            TunnelState::Failed => "failed",
        };
        cx.of(H3P, format_args!("[{id}] -> [{name}]"));
        self.tunnel.state = state;
        if state == TunnelState::Established {
            cx.info(format_args!("CONNECT phase completed for HTTP/3 proxy"));
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

    /// Read what came, then send what waits, the timer set as the
    /// library asks (`cf_h3_proxy_tunnel`'s `H3_TUNNEL_CONNECT`).
    pub(crate) fn progress(
        &mut self,
        cx: &mut dyn LayerCx,
        socket: &dyn Socket,
    ) -> Result<(), ErrorKind> {
        self.call(cx, socket, |quic, over| {
            let r = quic.ingress(over).and_then(|()| quic.egress(over));
            first_fatal(r, quic.set_expiry(over))
        })
    }

    /// Send what waits, the timer set as the library asks.
    pub(crate) fn egress(
        &mut self,
        cx: &mut dyn LayerCx,
        socket: &dyn Socket,
    ) -> Result<(), ErrorKind> {
        self.call(cx, socket, |quic, over| {
            let r = quic.egress(over);
            first_fatal(r, quic.set_expiry(over))
        })
    }

    /// What the connection waits for on the socket as the `CONNECT` goes.
    pub(crate) fn connect_interest(&self) -> Events {
        self.quic.wants()
    }

    /// What a read that found nothing held gets: to wait, or, once the
    /// stream closed, its end, or a failure for a reset or a close before
    /// the answer's head (`cf_h3_proxy_recv_closed_stream`).
    fn nothing_held(&mut self, cx: &mut dyn LayerCx) -> Result<Recv, ErrorKind> {
        if !self.tunnel.closed {
            return Ok(Recv::WouldBlock);
        }
        let id = self.tunnel.last;
        if self.tunnel.reset {
            let error = self.tunnel.error;
            if error == H3Error::REQUEST_REJECTED {
                cx.info(format_args!(
                    "HTTP/3 stream {id} refused by server, try again on a new connection"
                ));
                return Err(ErrorKind::RecvError);
            }
            let (code, name) = (error.0, error.name());
            return Err(cx.fails(
                ErrorKind::Http3,
                format_args!("HTTP/3 stream {id} reset by server (error 0x{code:x} {name})"),
            ));
        }
        if !self.tunnel.final_answer {
            return Err(cx.fails(
                ErrorKind::Http3,
                format_args!(
                    "HTTP/3 stream {id} was closed cleanly, but before getting all response \
                     header fields, treated as error"
                ),
            ));
        }
        Ok(Recv::Eof)
    }

    /// The layer's receive or send fails with `kind`.
    fn failed(&mut self, kind: ErrorKind) -> io::Error {
        self.failure.get_or_insert(kind);
        io::Error::other("the HTTP/3 tunnel failed")
    }

    /// Take what is held for the layer above into `buf`, its window
    /// opened again.
    fn take_held(&mut self, cx: &mut dyn LayerCx, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.tunnel.held().len());
        if n > 0 {
            buf[..n].copy_from_slice(&self.tunnel.held()[..n]);
            self.tunnel.read += n;
            self.tunnel.update_window(cx);
            let extend = std::mem::take(&mut self.tunnel.extend);
            if extend > 0
                && let Some(stream) = self.tunnel.stream
            {
                self.quic.extend_stream_window(stream, extend);
            }
        }
        n
    }

    fn recv_inner(
        &mut self,
        cx: &mut dyn LayerCx,
        socket: &dyn Socket,
        buf: &mut [u8],
    ) -> (Result<Recv, ErrorKind>, usize) {
        // A stream gone before the read fails it (`!stream`).
        if self.tunnel.stream.is_none() || self.quic.shutdown_started() {
            return (Err(ErrorKind::RecvError), 0);
        }
        let mut n = self.take_held(cx, buf);
        let read = self.call(cx, socket, |quic, over| quic.ingress(over));
        let r = match read {
            Err(kind) => Err(kind),
            Ok(()) => {
                if n == 0 {
                    n = self.take_held(cx, buf);
                }
                match NonZeroUsize::new(n) {
                    Some(n) => Ok(Recv::Data(n)),
                    None => self.nothing_held(cx),
                }
            }
        };
        let after = self.call(cx, socket, |quic, over| {
            let sent = quic.egress(over);
            first_fatal(sent, quic.set_expiry(over))
        });
        (first_fatal(r, after), n)
    }

    fn send_inner(
        &mut self,
        cx: &mut dyn LayerCx,
        socket: &dyn Socket,
        bytes: &[u8],
    ) -> (Result<(), ErrorKind>, usize) {
        let read = self.call(cx, socket, |quic, over| quic.ingress(over));
        if let Err(kind) = read {
            return (self.send_ended(cx, socket, Err(kind)), 0);
        }
        let Some(stream) = self.tunnel.stream.filter(|_| !self.tunnel.closed) else {
            return (Err(ErrorKind::SendError), 0);
        };
        let took = match self.quic.write_body(stream, bytes) {
            Ok(took) => took,
            Err(kind) => return (self.send_ended(cx, socket, Err(kind)), 0),
        };
        let (id, len) = (stream.0, bytes.len());
        let code = if took == 0 && len > 0 {
            AGAIN_NUMBER
        } else {
            0
        };
        cx.of(
            H3P,
            format_args!("[{id}] cf_send, add to sendbuf(len={len}) -> {code}, {took}"),
        );
        self.quic.resume(stream);
        let r = self.call(cx, socket, |quic, over| quic.egress(over));
        (self.send_ended(cx, socket, r), took)
    }

    /// A send's end: the timer set as the library asks.
    fn send_ended(
        &mut self,
        cx: &mut dyn LayerCx,
        socket: &dyn Socket,
        r: Result<(), ErrorKind>,
    ) -> Result<(), ErrorKind> {
        let expiry = self.call(cx, socket, |quic, over| quic.set_expiry(over));
        first_fatal(r, expiry)
    }
}

/// The first of two results that failed (`Curl_1st_fatal`).
fn first_fatal<T>(r: Result<T, ErrorKind>, then: Result<(), ErrorKind>) -> Result<T, ErrorKind> {
    match (r, then) {
        (Err(kind), _) | (Ok(_), Err(kind)) => Err(kind),
        (r, Ok(())) => r,
    }
}

impl Part<Below<'_>> for H3Proxy {
    /// What the transfer waits for, as the windows the proxy left say: to
    /// read for a window that is shut, to write while the stream may and
    /// the connection has something to send (`cf_h3_proxy_adjust_pollset`).
    fn adjust_pollset(&self, wanted: Events) -> Events {
        let (want_recv, want_send) = (wanted.contains(Events::IN), wanted.contains(Events::OUT));
        let held_out = self.quic.wants().contains(Events::OUT);
        if !want_recv && !want_send && !held_out {
            return wanted;
        }
        let c_exhaust = want_send && !self.quic.send_room();
        let s_exhaust = want_send && self.tunnel.stream.is_some() && self.tunnel.flow_blocked;
        let recv = want_recv || c_exhaust || s_exhaust;
        let send = (!s_exhaust && want_send) || held_out;
        let mut events = Events::NONE;
        if recv {
            events = events | Events::IN;
        }
        if send {
            events = events | Events::OUT;
        }
        events
    }

    fn data_pending(&self, below: Below<'_>) -> bool {
        !self.tunnel.held().is_empty() || below.data_pending()
    }

    /// Alive while the connection may be used, its socket is, and what
    /// waits on it reads (`Curl_cf_ngtcp2_cmn_conn_is_alive`).
    fn is_alive(&mut self, cx: &mut dyn LayerCx, mut below: Below<'_>) -> Alive {
        if !self.quic.usable() {
            return Alive::Dead;
        }
        match below.reborrow().alive(cx) {
            Alive::Alive {
                input_pending: true,
            } => {
                let socket = below.socket();
                if self.call(cx, socket, |quic, over| quic.read_pending(over)) {
                    Alive::Alive {
                        input_pending: false,
                    }
                } else {
                    Alive::Dead
                }
            }
            alive => alive,
        }
    }

    fn filter(&self) -> Option<Component> {
        Some(H3P)
    }

    /// Close the connection, as far as the socket takes the packets now
    /// (`cf_h3_proxy_shutdown`, `Curl_cf_ngtcp2_cmn_shutdown`).
    fn shutdown(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        let socket = below.socket();
        Ok(match self.call(cx, socket, |quic, over| quic.close(over)) {
            true => Handshake::Done,
            false => Handshake::Waiting,
        })
    }

    fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        match q {
            LayerQuery::Failure => self.failure.map(LayerAnswer::Failure),
            LayerQuery::Tunnel => Some(LayerAnswer::Tunnel(H3P)),
            _ => None,
        }
    }
}

impl Layer for H3Proxy {
    /// The tunnel's DATA as they come, the stream's window opened by as
    /// much as is read (`cf_h3_proxy_recv`).
    fn recv(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        if let Err(kind) = self.quic.verified() {
            return Err(self.failed(kind));
        }
        let socket = below.socket();
        let (r, n) = self.recv_inner(cx, socket, buf);
        let (id, len) = (self.tunnel.id(), buf.len());
        let code = match r {
            Ok(Recv::WouldBlock) => AGAIN_NUMBER,
            Ok(_) => 0,
            Err(kind) => kind.number(),
        };
        cx.of(
            H3P,
            format_args!("[{id}] cf_recv(len={len}) -> {code}, {n}"),
        );
        r.map_err(|kind| self.failed(kind))
    }

    /// The layer above's bytes held for the stream's DATA, as much as is
    /// room for, and as much of them sent as the connection takes
    /// (`cf_h3_proxy_send`).
    fn send(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, bytes: &[u8]) -> io::Result<Sent> {
        if let Err(kind) = self.quic.verified() {
            return Err(self.failed(kind));
        }
        let socket = below.socket();
        let (r, n) = self.send_inner(cx, socket, bytes);
        let (id, len) = (self.tunnel.id(), bytes.len());
        let code = crate::trace::Code(r);
        cx.of(
            H3P,
            format_args!("[{id}] cf_send(len={len}) -> {code}, {n}"),
        );
        match r {
            Ok(()) => Ok(NonZeroUsize::new(n).map_or(Sent::WouldBlock, Sent::Bytes)),
            Err(kind) => Err(self.failed(kind)),
        }
    }
}
