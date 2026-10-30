//! A tunnel through an HTTPS proxy that speaks HTTP/3 (`cf-ngtcp2-proxy.c`):
//! a QUIC connection to the proxy, whose one request stream is the
//! `CONNECT`, and once the proxy answers it, the stream's DATA are the
//! tunnel's bytes both ways. The connection's handshake is a QUIC attempt
//! of the setup's; the setup then drives the `CONNECT` over it, and the
//! connection, as it stands then, becomes the bottom layer, over the UDP
//! socket, that the tunnel's bytes pass through.

use std::io;
use std::num::NonZeroUsize;

use curl_alloc::OutOfMemory;

use super::buf::HeldBytes;
use super::h2proxy::Answer;
use super::io::{Events, Recv, Sent, Socket};
use super::layer::{Alive, Below, Handshake, Layer, LayerAnswer, LayerCx, LayerQuery, Part};
use super::quic::{Quic, QuicIo, RecvRoom, SocketIo, Via};
use crate::components::Component;
use crate::conn::layer::LayerCalls as _;
use crate::error::{AGAIN_NUMBER, ErrorKind};
use crate::http3::{H3Error, Heard, StreamEvent, StreamId};
use crate::text::Text;
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
    life: Life,
    state: TunnelState,
    answer: Answering,
    /// Its DATA, not read by the layer above yet.
    recv: HeldBytes,
    /// The DATA received in all, the receive window's offset
    /// (`rx_total`, `rx_offset`), and how far the proxy may send
    /// (`rx_offset_max`).
    rx_offset: u64,
    rx_offset_max: u64,
    /// The window to open by, once the library's call is over.
    extend: u64,
}

/// Where the tunnel's stream is in its life (`ts->stream`, cleared by
/// the close; `closed`, `reset`, `error3`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Life {
    /// No `CONNECT` went yet.
    Unopened,
    /// The `CONNECT`'s stream is open; the library may send none of its
    /// data for the proxy's flow control if `flow_blocked`
    /// (`quic_flow_blocked`).
    Open {
        stream: StreamId,
        flow_blocked: bool,
    },
    /// The stream closed, the proxy resetting it with an error if
    /// `reset`.
    Closed {
        stream: StreamId,
        reset: Option<H3Error>,
    },
}

/// The proxy's answer, as it is read (`status_code`, `resp`).
#[derive(Debug)]
enum Answering {
    /// No head yet.
    Waiting,
    /// A head being read: an interim one's replaced by the next.
    Reading(Answer),
    /// The final answer's head is whole: none if it had no status.
    Final(Option<Answer>),
}

impl Answering {
    /// The status of the answer read, 0 if it had none (`status_code`).
    fn status(&self) -> u16 {
        match self {
            Answering::Reading(answer) | Answering::Final(Some(answer)) => answer.status,
            Answering::Waiting | Answering::Final(None) => 0,
        }
    }
}

impl Tunnel {
    fn new() -> Tunnel {
        Tunnel {
            life: Life::Unopened,
            state: TunnelState::Init,
            answer: Answering::Waiting,
            recv: HeldBytes::default(),
            rx_offset: 0,
            rx_offset_max: STREAM_WINDOW_INITIAL,
            extend: 0,
        }
    }

    /// Its stream, while it is open.
    fn open(&self) -> Option<StreamId> {
        match self.life {
            Life::Open { stream, .. } => Some(stream),
            Life::Unopened | Life::Closed { .. } => None,
        }
    }

    /// The stream it is or was, for the traces: -1 before the `CONNECT`.
    fn last(&self) -> i64 {
        match self.life {
            Life::Unopened => -1,
            Life::Open { stream, .. } | Life::Closed { stream, .. } => stream.0,
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

    /// The stream's id as traced: -1 once it is gone.
    fn id(&self) -> i64 {
        self.open().map_or(-1, |s| s.0)
    }

    /// Open the receive window back to what is held for the layer above
    /// allowing for as much again (`cf_h3_proxy_upd_rx_win`): by how much,
    /// once the library's call is over.
    fn update_window(&mut self, cx: &mut dyn LayerCx) {
        let Some(stream) = self.open() else { return };
        let buffered = self.held().len() as u64;
        let wanted = TUNNEL_WINDOW.saturating_sub(buffered);
        let current = self.rx_offset_max - self.rx_offset;
        // Opened by what is wanted past what is open, if anything, short of
        // the largest offset.
        let delta = wanted
            .saturating_sub(current)
            .min(u64::MAX - self.rx_offset_max);
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

    /// What it makes of an event of the connection's streams
    /// (`ngh3_proxy_callbacks`): one of another stream is let be, as C's
    /// callbacks find no tunnel for it.
    fn heard(&mut self, cx: &mut dyn LayerCx, stream: StreamId, event: StreamEvent<'_>) -> Heard {
        let ours = self.open() == Some(stream);
        match event {
            StreamEvent::Header {
                name,
                value,
                status,
            } => {
                if !ours || matches!(self.answer, Answering::Final(_)) {
                    return Heard::Fine;
                }
                if status {
                    let Some(code) = crate::proto::http::decode_status(value) else {
                        return Heard::Failed;
                    };
                    self.answer = Answering::Reading(Answer::new(code));
                    return Heard::Fine;
                }
                let Answering::Reading(answer) = &mut self.answer else {
                    return Heard::Failed;
                };
                let id = Text::<24>::clipped(format_args!("[{}] ", stream.0)).0;
                cx.of_with(H3P, &[id.bytes(), b"header: ", name, b": ", value]);
                match answer.add(name, value) {
                    Ok(()) => Heard::Fine,
                    Err(OutOfMemory) => Heard::Failed,
                }
            }
            StreamEvent::HeadersDone => {
                if !ours {
                    return Heard::Fine;
                }
                let (id, status) = (stream.0, self.answer.status());
                cx.of(H3P, format_args!("[{id}] end_headers, status={status}"));
                if status / 100 != 1 {
                    self.answer = match std::mem::replace(&mut self.answer, Answering::Waiting) {
                        Answering::Waiting => Answering::Final(None),
                        Answering::Reading(answer) => Answering::Final(Some(answer)),
                        done @ Answering::Final(_) => done,
                    };
                }
                Heard::Fine
            }
            StreamEvent::Data(bytes) => {
                if !ours {
                    return Heard::Failed;
                }
                let (id, len) = (stream.0, bytes.len());
                let total = self.rx_offset + len as u64;
                cx.of(
                    H3P,
                    format_args!("[cb_h3_proxy_recv_data] [{id}] DATA len={len}, total={total}"),
                );
                if self.recv.push(bytes).is_err() {
                    return Heard::Failed;
                }
                self.rx_offset += len as u64;
                self.rx_offset_max = self.rx_offset_max.max(self.rx_offset);
                let win = self.rx_offset_max - self.rx_offset;
                cx.of(H3P, format_args!("[{id}] DATA len={len}, rx win={win}"));
                self.update_window(cx);
                Heard::Fine
            }
            StreamEvent::Closed(error) => {
                if !ours {
                    return Heard::Fine;
                }
                let id = stream.0;
                let reset = if error == H3Error::NO_ERROR {
                    cx.of(H3P, format_args!("[{id}] CLOSED"));
                    None
                } else {
                    let code = error.0;
                    cx.of(H3P, format_args!("[{id}] RESET: error {code}"));
                    Some(error)
                };
                self.life = Life::Closed { stream, reset };
                Heard::Fine
            }
            StreamEvent::QuicClosed { error, answer } => {
                let rv = crate::http3::returned(answer);
                let (id, error) = (stream.0, error.0);
                cx.of(
                    H3P,
                    format_args!("[{id}] quic close(app_error={error}) -> {rv}"),
                );
                Heard::Fine
            }
            StreamEvent::H3Reset { answer } => {
                if ours {
                    let rv = crate::http3::returned(answer);
                    let id = stream.0;
                    cx.of(H3P, format_args!("[{id}] reset -> {rv}"));
                    self.life = Life::Closed {
                        stream,
                        reset: None,
                    };
                }
                Heard::Fine
            }
            StreamEvent::BodyRead {
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
            StreamEvent::Blocked | StreamEvent::Unblocked => {
                if let Life::Open { flow_blocked, .. } = &mut self.life
                    && ours
                {
                    *flow_blocked = event == StreamEvent::Blocked;
                }
                Heard::Fine
            }
            StreamEvent::QuicReset { .. } | StreamEvent::Consumed(_) => Heard::Fine,
        }
    }
}

/// The QUIC connection to the proxy, and the tunnel's stream on it
/// (`cf_h3_proxy_ctx`).
pub(crate) struct H3Proxy {
    quic: Box<Quic>,
    tunnel: Tunnel,
    /// The tunnel is CONNECT-UDP's, QUIC's datagrams going through it
    /// as capsules (`h3_tunnel_stream.udp`).
    udp: bool,
    /// What a receive or send of the layer failed with, for the
    /// transfer's error.
    failure: Option<ErrorKind>,
}

impl std::fmt::Debug for H3Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Proxy")
            .field("stream", &self.tunnel.life)
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
}

impl LayerCx for Tunnelled<'_> {
    fn now(&self) -> Instant {
        self.cx.now()
    }

    fn trace(&mut self) -> Option<&mut dyn super::layer::Trace> {
        self.cx.trace()
    }

    fn failures(&mut self) -> Option<&mut dyn super::layer::Failures> {
        self.cx.failures()
    }

    fn transfer(&mut self) -> Option<&mut dyn super::layer::ForTransfer> {
        self.cx.transfer()
    }

    fn tls_sessions(&mut self) -> Option<&mut dyn super::layer::TlsSessions> {
        self.cx.tls_sessions()
    }

    fn early_data(&mut self) -> Option<&mut dyn super::layer::EarlyData> {
        self.cx.early_data()
    }

    fn quic_timer(&mut self) -> Option<&mut dyn super::layer::QuicTimer> {
        self.cx.quic_timer()
    }

    /// The tunnel's: its stream is the one stream on the connection.
    fn h3_streams(&mut self) -> Option<&mut dyn super::layer::H3Streams> {
        Some(self)
    }

    /// The transfer's: the connection to the proxy is on a socket, and
    /// receives in the multi's room as the origin's would
    /// (`Curl_multi_xfer_sockbuf_borrow`).
    fn recv_room(&mut self) -> Option<&mut RecvRoom> {
        self.cx.recv_room()
    }
}

impl super::layer::H3Streams for Tunnelled<'_> {
    fn heard(&mut self, stream: StreamId, event: StreamEvent<'_>) -> Heard {
        self.tunnel.heard(&mut *self.cx, stream, event)
    }
}

/// The connection to the proxy is on its own socket.
impl QuicIo for Tunnelled<'_> {
    fn via(&mut self) -> Via<'_> {
        Via::Socket(self)
    }
}

impl SocketIo for Tunnelled<'_> {
    fn socket(&self) -> &dyn Socket {
        self.socket
    }
}

impl H3Proxy {
    /// The QUIC connection to the proxy.
    pub(crate) fn quic(&self) -> &Quic {
        &self.quic
    }

    /// The tunnel over `quic`, a connection to the proxy whose handshake
    /// is done; nothing asked of it yet.
    pub(crate) fn new(quic: Box<Quic>, udp: bool) -> H3Proxy {
        H3Proxy {
            quic,
            tunnel: Tunnel::new(),
            udp,
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
        let H3Proxy { quic, tunnel, .. } = self;
        let mut over = Tunnelled { cx, socket, tunnel };
        let r = f(quic, &mut over);
        let extend = std::mem::take(&mut self.tunnel.extend);
        if extend > 0
            && let Some(stream) = self.tunnel.open()
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
        self.tunnel.life = Life::Open {
            stream,
            flow_blocked: false,
        };
        let id = stream.0;
        cx.of(H3P, format_args!("[{id}] opened bidi stream"));
        if verbose {
            let id = Text::<24>::clipped(format_args!("[H3-PROXY] [{id}] ")).0;
            cx.of_with(H3P, &[id.bytes(), b"OPENED stream for ", url]);
        }
        Ok(())
    }

    /// No `CONNECT` is open on it yet.
    pub(crate) fn unasked(&self) -> bool {
        self.tunnel.state == TunnelState::Init
    }

    /// The proxy agreed: the tunnel is up.
    pub(crate) fn established(&self) -> bool {
        self.tunnel.state == TunnelState::Established
    }

    /// Move the tunnel to `state`, traced (`h3_tunnel_go_state`).
    pub(crate) fn go_state(&mut self, cx: &mut dyn LayerCx, state: TunnelState) {
        if self.tunnel.state == state {
            return;
        }
        let id = self.tunnel.last();
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
            let udp = if self.udp { "-UDP" } else { "" };
            cx.info(format_args!(
                "CONNECT{udp} phase completed for HTTP/3 proxy"
            ));
        }
    }

    /// The proxy's final answer to the `CONNECT`, once it is whole.
    pub(crate) fn answer(&self) -> Option<&Answer> {
        match &self.tunnel.answer {
            Answering::Final(answer) => answer.as_ref(),
            Answering::Waiting | Answering::Reading(_) => None,
        }
    }

    /// The tunnel's stream closed.
    pub(crate) fn tunnel_closed(&self) -> bool {
        matches!(self.tunnel.life, Life::Closed { .. })
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

    /// What a read that found nothing held gets: to wait, or, once the
    /// stream closed, its end, or a failure for a reset or a close before
    /// the answer's head (`cf_h3_proxy_recv_closed_stream`).
    fn nothing_held(&mut self, cx: &mut dyn LayerCx) -> Result<Recv, ErrorKind> {
        let Life::Closed { stream, reset } = self.tunnel.life else {
            return Ok(Recv::WouldBlock);
        };
        let id = stream.0;
        if let Some(error) = reset {
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
        if !matches!(self.tunnel.answer, Answering::Final(_)) {
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
        // A bare kind, which allocates nothing: the failure is `kind`.
        io::Error::from(io::ErrorKind::Other)
    }

    /// Take what is held for the layer above into `buf`, its window
    /// opened again.
    fn take_held(&mut self, cx: &mut dyn LayerCx, buf: &mut [u8]) -> usize {
        let n = self.tunnel.take(buf);
        if n > 0 {
            self.tunnel.update_window(cx);
            let extend = std::mem::take(&mut self.tunnel.extend);
            if extend > 0
                && let Some(stream) = self.tunnel.open()
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
        if self.tunnel.open().is_none() || self.quic.shutdown_started() {
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
        let Some(stream) = self.tunnel.open() else {
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
        // None taken is to wait: nothing is sent, the timer set.
        if code != 0 {
            return (self.send_ended(cx, socket, Ok(())), 0);
        }
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
    /// With no stream, before the `CONNECT` or once it closed, the poll is
    /// left as it is.
    fn adjust_pollset(&self, wanted: Events) -> Events {
        let Life::Open { flow_blocked, .. } = self.tunnel.life else {
            return wanted;
        };
        let (want_recv, want_send) = (wanted.contains(Events::IN), wanted.contains(Events::OUT));
        let held_out = self.quic.wants().contains(Events::OUT);
        if !(want_recv || want_send || held_out) {
            return wanted;
        }
        let c_exhaust = want_send && !self.quic.send_room();
        let s_exhaust = want_send && flow_blocked;
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
        let code = match r {
            Ok(()) if n == 0 => AGAIN_NUMBER,
            Ok(()) => 0,
            Err(kind) => kind.number(),
        };
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

#[cfg(test)]
mod tests;
