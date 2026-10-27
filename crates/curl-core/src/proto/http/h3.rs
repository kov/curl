//! A request over HTTP/3: its stream (`cf-ngtcp2.c`'s `h3_stream_ctx`).
//!
//! The request is made as for HTTP/1 and its head turned into the
//! stream's fields as it is sent, as for HTTP/2. Each call the request
//! makes on the connection reads what came first or last, sends what the
//! library has to send, and sets the library's timer (`cf_ngtcp2_send`,
//! `cf_ngtcp2_recv`); what the library reads for a stream reaches the
//! stream's transfer as it reads it, as C's callbacks write it: the head
//! a line at a time, `HTTP/3 200 \r\n` first, and the body as it comes.

use super::*;
use crate::conn::layer::LayerCx;
use crate::conn::mux::Routes;
use crate::conn::quic::{Quic, QuicCx, QuicIo, STREAM_WINDOW_INITIAL};
use crate::error::AGAIN_NUMBER;
use crate::http3::{Event, H3Error, Heard, StreamId};
use crate::proto::http2::fields_of;
use crate::proto::http3::H3Conn;
use crate::tls::TlsNative;

/// The most a stream's receive window opens to
/// (`H3_STREAM_WINDOW_SIZE_MAX`).
const STREAM_WINDOW_MAX: u64 = 10 * 1024 * 1024;

/// What of the body the library is first given to hold in flight
/// (`H3_STREAM_SEND_BUF_INITIAL`), and the step it is adjusted by as
/// the library keeps more or less (`cf_ngtcp2_send`'s `delta`).
const SEND_IDEAL_INITIAL: usize = 32 * 1024;
const SEND_IDEAL_STEP: usize = 2 * 1024;

/// A request's stream, and what came of it (`h3_stream_ctx`).
#[derive(Debug)]
pub(super) struct H3Stream {
    /// Set up on the connection, as the request first went
    /// (`Curl_cf_ngtcp2_h3_stream_setup`).
    set_up: bool,
    /// Its id, once its head went.
    id: Option<StreamId>,
    /// The body bytes received, and how far the peer may send
    /// (`rx_offset`, `rx_offset_max`).
    rx_offset: u64,
    rx_offset_max: u64,
    /// How much of the body the library should hold in flight
    /// (`tx_in_flight_ideal`).
    send_ideal: usize,
    /// The response's status (`status_code`).
    status: u16,
    /// Writing the response failed (`xfer_result`): nothing more is
    /// written.
    failed: Option<ErrorKind>,
    /// The final head is whole (`resp_hds_complete`).
    head_done: bool,
    /// The stream closed (`closed`), with this code (`error3`); one with
    /// an error is a reset (`reset`).
    closed: bool,
    reset: bool,
    error: H3Error,
    /// Nothing more of the request goes (`send_closed`).
    send_closed: bool,
    /// The body's size, none if unknown until it is all sent; and how
    /// much of it the library was handed. What is left of it is
    /// `upload_left`.
    body_size: Option<u64>,
    handed: u64,
    /// The peer's flow control holds its sending back
    /// (`quic_flow_blocked`).
    flow_blocked: bool,
}

/// What of a request's sending its connection weighs as the transfer's
/// pollset is made (`cf_ngtcp2_adjust_pollset`): its stream, how much of
/// its body is to be in flight, and whether the peer holds it back.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamSend {
    pub(crate) stream: StreamId,
    pub(crate) ideal: usize,
    pub(crate) flow_blocked: bool,
}

impl Default for H3Stream {
    fn default() -> Self {
        H3Stream {
            set_up: false,
            id: None,
            rx_offset: 0,
            rx_offset_max: STREAM_WINDOW_INITIAL,
            send_ideal: SEND_IDEAL_INITIAL,
            status: 0,
            failed: None,
            head_done: false,
            closed: false,
            reset: false,
            error: H3Error::default(),
            send_closed: false,
            body_size: Some(0),
            handed: 0,
            flow_blocked: false,
        }
    }
}

impl H3Stream {
    /// What its connection weighs of its sending, once it is open.
    pub(super) fn sending(&self) -> Option<StreamSend> {
        self.id.map(|stream| StreamSend {
            stream,
            ideal: self.send_ideal,
            flow_blocked: self.flow_blocked,
        })
    }

    /// The id C traces it by: -1 before it opened.
    fn shown_id(&self) -> i64 {
        self.id.map_or(-1, |id| id.0)
    }
}

/// What a request's call on the connection came to, short of a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Called {
    /// What it did is done: the stream ended, or the bytes went.
    Done,
    /// Nothing more for now (`CURLE_AGAIN`).
    Again,
}

/// The number C traces for a call's result.
fn code(r: Result<Called, ErrorKind>) -> u16 {
    match r {
        Ok(Called::Done) => 0,
        Ok(Called::Again) => AGAIN_NUMBER,
        Err(kind) => kind.number(),
    }
}

/// The first of two results that failed for good (`Curl_1st_fatal`).
fn first_fatal(
    a: Result<Called, ErrorKind>,
    b: Result<(), ErrorKind>,
) -> Result<Called, ErrorKind> {
    match (a, b) {
        (Err(_), _) => a,
        (_, Err(kind)) => Err(kind),
        _ => a,
    }
}

/// What a request's calls on its connection reach: the step, the request
/// with its stream, the connection with its session taken out, and who
/// each of the session's streams is for. Its socket is the connection's;
/// what the library tells of a stream goes to the stream's transfer.
struct H3Step<'a, 'c, H: Host> {
    cx: &'a mut StepCx<'c, H>,
    req: &'a mut Request,
    lease: &'a mut ConnLease,
    routes: &'a mut Routes<StreamId, ()>,
    /// The receive windows the library's reading opened, each by as much,
    /// for the step to open on the connection once the call returns.
    extends: Vec<(StreamId, u64)>,
    /// A window could not be kept for want of memory.
    oom: bool,
}

impl<H: Host> LayerCx for H3Step<'_, '_, H> {
    fn quic_due(&mut self, wait: std::time::Duration) {
        LayerCx::quic_due(&mut *self.cx, wait);
    }

    fn now(&self) -> crate::time::Instant {
        self.cx.now()
    }

    fn of(&mut self, component: Component, line: std::fmt::Arguments<'_>) {
        LayerCx::of(&mut *self.cx, component, line);
    }

    fn info(&mut self, line: std::fmt::Arguments<'_>) {
        LayerCx::info(&mut *self.cx, line);
    }

    fn socket_failed(&mut self, e: &std::io::Error) {
        LayerCx::socket_failed(&mut *self.cx, e);
    }

    fn early_done(&mut self, sent: i64) {
        LayerCx::early_done(&mut *self.cx, sent);
    }

    fn fails(&mut self, kind: ErrorKind, why: std::fmt::Arguments<'_>) -> ErrorKind {
        LayerCx::fails(&mut *self.cx, kind, why)
    }

    fn bytes(&mut self, kind: DebugKind, bytes: &[u8]) {
        LayerCx::bytes(&mut *self.cx, kind, bytes);
    }

    fn debugs(&self) -> bool {
        LayerCx::debugs(&*self.cx)
    }

    fn verbose(&self) -> bool {
        LayerCx::verbose(&*self.cx)
    }

    fn certinfo_report(&mut self) -> Option<&mut crate::report::TransferReport> {
        LayerCx::certinfo_report(&mut *self.cx)
    }

    fn tls_verified(&mut self, filter: Component, result: i64) {
        LayerCx::tls_verified(&mut *self.cx, filter, result);
    }

    fn configures_tls(&self) -> bool {
        LayerCx::configures_tls(&*self.cx)
    }

    fn configure_tls(&mut self, native: TlsNative) -> Result<(), ErrorKind> {
        LayerCx::configure_tls(&mut *self.cx, native)
    }

    fn pause_recv(&mut self) {
        LayerCx::pause_recv(&mut *self.cx);
    }

    fn unix_time(&self) -> i64 {
        LayerCx::unix_time(&*self.cx)
    }

    fn has_tls_sessions(&self) -> bool {
        LayerCx::has_tls_sessions(&*self.cx)
    }

    fn tls_sessions(&mut self, f: &mut dyn FnMut(&mut crate::tls::SessionCache, &mut dyn LayerCx)) {
        LayerCx::tls_sessions(&mut *self.cx, f);
    }

    /// What the library told of a stream, handed to its transfer: the
    /// stepping one's own, a sibling's, or none, as C's callbacks find
    /// the stream's transfer by its user data.
    fn h3_event(&mut self, event: Event<'_>) -> Heard {
        let Some(stream) = stream_of(&event) else {
            return Heard::Fine;
        };
        // The packet's writer says so, whichever transfer the stream is
        // (`read_pkt_to_send`).
        if let Event::Blocked { .. } = event {
            let id = stream.0;
            trace::of(
                &mut *self.cx,
                Component::Http3,
                format_args!("[{id}] block quic flow"),
            );
        }
        let me = self.cx.me;
        let own = self.req.wire.h3().and_then(|s| s.id);
        let mut extend = None;
        let heard = if own == Some(stream) {
            self.req
                .h3_event(&mut *self.cx, &mut *self.lease, event, &mut extend)
        } else {
            let to = self.routes.route_of(stream).filter(|&to| to != me);
            let lease = &mut *self.lease;
            let told = to.and_then(|to| {
                self.cx.with_sibling(to, |scx, sib| {
                    sib.h3_event(scx, lease, event.clone(), &mut extend)
                })
            });
            told.unwrap_or_else(|| crate::conn::quic::unrouted(&mut *self.cx, &event))
        };
        if let Some(n) = extend
            && self.extends.try_push((stream, n)).is_err()
        {
            self.oom = true;
            return Heard::Failed;
        }
        heard
    }
}

impl<H: Host> QuicCx for H3Step<'_, '_, H> {
    fn take_room(&mut self) -> Result<Vec<u8>, OutOfMemory> {
        QuicCx::take_room(&mut *self.cx)
    }

    fn give_room(&mut self, room: Vec<u8>) {
        QuicCx::give_room(&mut *self.cx, room);
    }
}

impl<H: Host> QuicIo for H3Step<'_, '_, H> {
    fn socket(&self) -> &dyn crate::conn::io::Socket {
        self.lease
            .conn()
            .stream_socket()
            .expect("a QUIC connection over its socket")
    }
}

impl<H: Host> H3Step<'_, '_, H> {
    /// The receive windows the library's reading opened, opened on the
    /// connection now that its call returned (`cf_ngtcp2_upd_rx_win`'s
    /// `ngtcp2_conn_extend_max_stream_offset`).
    fn open_windows(&mut self, quic: &mut Quic) -> Result<(), ErrorKind> {
        for (stream, n) in self.extends.drain(..) {
            quic.extend_stream_window(stream, n);
        }
        if std::mem::take(&mut self.oom) {
            return Err(ErrorKind::OutOfMemory);
        }
        Ok(())
    }

    fn stream(&mut self) -> &mut H3Stream {
        self.req.h3_stream()
    }
}

/// The stream an event of the library's is of, if any.
fn stream_of(event: &Event<'_>) -> Option<StreamId> {
    match *event {
        Event::Consumed { stream, .. }
        | Event::QuicClosed { stream, .. }
        | Event::QuicReset { stream, .. }
        | Event::Unblocked { stream }
        | Event::Blocked { stream }
        | Event::Header { stream, .. }
        | Event::HeadersDone { stream }
        | Event::Data { stream, .. }
        | Event::Closed { stream, .. }
        | Event::H3Reset { stream, .. }
        | Event::BodyRead { stream, .. } => Some(stream),
        Event::HandshakeDone { .. } | Event::H3Failed { .. } | Event::MaxBidiStreams(_) => None,
    }
}

impl Request {
    fn h3_stream(&mut self) -> &mut H3Stream {
        match &mut self.wire {
            Wire::H3(s) => s,
            _ => unreachable!("a request over HTTP/3"),
        }
    }

    /// Run `f` with the connection's session taken off it and a step over
    /// the rest, and put the session back after.
    fn with_h3<H: Host, R>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        f: impl FnOnce(&mut H3Step<'_, '_, H>, &mut Quic) -> R,
    ) -> R {
        let mut h3 = lease.get().take_h3().expect("an HTTP/3 connection");
        let H3Conn { quic, routes } = &mut *h3;
        let mut step = H3Step {
            cx,
            req: self,
            lease: &mut *lease,
            routes,
            extends: Vec::new(),
            oom: false,
        };
        if matches!(step.req.outgoing, Sending::Done | Sending::Aborted) {
            done_sending(&mut step, quic);
        }
        let r = f(&mut step, quic);
        lease.get().put_h3(h3);
        r
    }

    /// Send what of the request is in `out[sent..end]`, the last of it if
    /// `eos` (`cf_ngtcp2_send`): what came is read first; the head opens
    /// the stream with its fields. How much was taken.
    pub(super) fn h3_send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        end: usize,
        _eos: bool,
    ) -> Result<usize, ErrorKind> {
        let start = self.sent;
        let len = end - start;
        let (r, n) = self.with_h3(cx, lease, |step, quic| {
            let mut n = 0;
            if let Err(kind) = quic.verified() {
                let id = step.stream().shown_id();
                let code = kind.number();
                trace::of(
                    &mut *step.cx,
                    Component::Http3,
                    format_args!("[{id}] cf_send(len={len}) -> {code}, {n}"),
                );
                return (Err(kind), n);
            }
            let r = 'out: {
                if let Err(kind) = quic.ingress(step).and_then(|()| step.open_windows(quic)) {
                    break 'out Err(kind);
                }
                let s = step.stream();
                let id = s.shown_id();
                if s.id.is_none() {
                    if quic.shutdown_started() {
                        trace::of(
                            &mut *step.cx,
                            Component::Http3,
                            format_args!("cannot open stream on closed connection"),
                        );
                        break 'out Err(ErrorKind::SendError);
                    }
                    match open(step, quic, start..end) {
                        Ok(taken) => n = taken,
                        Err(kind) => {
                            let code = kind.number();
                            trace::of(
                                &mut *step.cx,
                                Component::Http3,
                                format_args!("failed to open stream -> {code}"),
                            );
                            break 'out Err(kind);
                        }
                    }
                } else if let Some(kind) = s.failed {
                    trace::of(
                        &mut *step.cx,
                        Component::Http3,
                        format_args!("[{id}] xfer write failed"),
                    );
                    close(step, quic);
                    break 'out Err(kind);
                } else if s.closed {
                    if s.head_done {
                        // The server is done with the request: what is left
                        // of its body is dropped, as no transport failed.
                        trace::of(
                            &mut *step.cx,
                            Component::Http3,
                            format_args!("[{id}] discarding dataon closed stream with response"),
                        );
                        n = len;
                        break 'out Ok(Called::Done);
                    }
                    trace::of(
                        &mut *step.cx,
                        Component::Http3,
                        format_args!("[{id}] send_body(len={len}) -> stream closed"),
                    );
                    break 'out Err(ErrorKind::Http3);
                } else if quic.shutdown_started() {
                    trace::of(
                        &mut *step.cx,
                        Component::Http3,
                        format_args!("cannot send on closed connection"),
                    );
                    break 'out Err(ErrorKind::SendError);
                } else {
                    let Some(stream) = s.id else {
                        unreachable!("the stream opened above")
                    };
                    if quic.body_in_flight(stream) >= s.send_ideal {
                        // As much is in flight as is meant to be: no
                        // more until some is acknowledged.
                        break 'out Ok(Called::Again);
                    }
                    let took = match quic.write_body(stream, &step.req.out[start..end]) {
                        Ok(took) => took,
                        Err(kind) => break 'out Err(kind),
                    };
                    let code = if took == 0 { AGAIN_NUMBER } else { 0 };
                    trace::of(
                        &mut *step.cx,
                        Component::Http3,
                        format_args!("[{id}] cf_send, add to sendbuf(len={len}) -> {code}, {took}"),
                    );
                    if took == 0 {
                        break 'out Ok(Called::Again);
                    }
                    n = took;
                    // All of a body of known size held: it ends after it.
                    let written = written(step.stream(), quic, stream);
                    if step.stream().body_size == Some(written) {
                        quic.end_body(stream);
                    }
                    quic.resume(stream);
                }
                // What went before the handshake is early data.
                quic.sent(n);
                let sent = quic.egress(step).map(|()| Called::Done);
                if n > 0 {
                    adjust_ideal(step, quic, len, n);
                }
                sent
            };
            let r = first_fatal(r, quic.set_expiry(step));
            let r = match quic.verified() {
                Err(kind) => Err(kind),
                Ok(()) => r,
            };
            let id = step.stream().shown_id();
            let code = code(r);
            trace::of(
                &mut *step.cx,
                Component::Http3,
                format_args!("[{id}] cf_send(len={len}) -> {code}, {n}"),
            );
            (r, n)
        });
        r.map(|_| n)
    }

    /// `read_some` over HTTP/3: one look at the connection, which hands
    /// on what it reads for each stream as it reads it, as C's
    /// `sendrecv_dl` reads until the filter says to wait (`cf_ngtcp2_recv`
    /// returns no bytes but at the stream's end).
    pub(super) fn h3_read_some<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Read, ErrorKind> {
        loop {
            if matches!(self.stage, Stage::Done) || cx.pause().recv_paused() {
                return Ok(Read::Waits);
            }
            // Under a receive limit spent, the engine waits for it
            // (`sendrecv_dl`'s `rate_limited`).
            if matches!(cx.rate_allowance(Way::Recv), Some(..=0)) {
                return Ok(Read::Waits);
            }
            let max = cx.easy().options().limits.buffer_size.get();
            let max = match cx.rate_allowance(Way::Recv) {
                Some(allowed) => max.min(usize::try_from(allowed).unwrap_or(usize::MAX)),
                None => max,
            };
            match self.h3_recv(cx, lease, max)? {
                Called::Done => self.stream_ended(cx)?,
                Called::Again => return Ok(Read::Waits),
            }
        }
    }

    /// One call to receive (`cf_ngtcp2_recv`): what is known of the
    /// stream first, without touching the connection; then what came,
    /// handed on as it is read; then the stream again. `Done` once the
    /// stream ended whole.
    fn h3_recv<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        buflen: usize,
    ) -> Result<Called, ErrorKind> {
        self.with_h3(cx, lease, |step, quic| {
            if let Err(kind) = quic.verified() {
                let id = step.stream().shown_id();
                let code = kind.number();
                trace::of(
                    &mut *step.cx,
                    Component::Http3,
                    format_args!("[{id}] cf_recv(buflen={buflen}) -> {code}, 0"),
                );
                return Err(kind);
            }
            let r = 'out: {
                if quic.shutdown_started() {
                    break 'out Err(ErrorKind::RecvError);
                }
                rx_window(step, quic);
                for first in [true, false] {
                    let s = step.stream();
                    let id = s.shown_id();
                    if let Some(kind) = s.failed {
                        trace::of(
                            &mut *step.cx,
                            Component::Http3,
                            format_args!("[{id}] xfer write failed"),
                        );
                        close(step, quic);
                        break 'out Err(kind);
                    }
                    if s.closed {
                        break 'out step.req.recv_closed_stream(step.cx, step.lease);
                    }
                    if first
                        && quic
                            .ingress(step)
                            .and_then(|()| step.open_windows(quic))
                            .is_err()
                    {
                        break 'out Err(ErrorKind::RecvError);
                    }
                }
                Ok(Called::Again)
            };
            let r = first_fatal(r, quic.egress(step));
            let r = first_fatal(r, quic.set_expiry(step));
            let r = match quic.verified() {
                Err(kind) => Err(kind),
                Ok(()) => r,
            };
            let id = step.stream().shown_id();
            let code = code(r);
            trace::of(
                &mut *step.cx,
                Component::Http3,
                format_args!("[{id}] cf_recv(buflen={buflen}) -> {code}, 0"),
            );
            r
        })
    }

    /// The stream closed (`recv_closed_stream`): a reset fails the
    /// response, but for a rejected request, which is made again on
    /// another connection, and one after a whole head of a response with
    /// no body wanted; a stream that closed before its head ended fails
    /// it too.
    fn recv_closed_stream<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Called, ErrorKind> {
        let no_body = self.method == Method::Head;
        let bytecount = self.pipeline.bytecount();
        let s = self.h3_stream();
        let id = s.shown_id();
        if s.reset {
            let error = s.error;
            let (code, name) = (error.0, error.name());
            if error == H3Error::REQUEST_REJECTED {
                trace::info(
                    cx,
                    format_args!(
                        "HTTP/3 stream {id} refused by server, try again on a new connection"
                    ),
                );
                lease.get().mark_close();
                self.refused = true;
                return Err(ErrorKind::RecvError);
            }
            if s.head_done && no_body {
                trace::of(
                    cx,
                    Component::Http3,
                    format_args!(
                        "[{id}] error after response headers, but we did not want a body \
                         anyway, ignore error 0x{code:x} {name}"
                    ),
                );
                return Ok(Called::Done);
            }
            let kind = if bytecount > 0 {
                ErrorKind::PartialFile
            } else {
                ErrorKind::Http3
            };
            return Err(trace::fail(
                cx,
                kind,
                format_args!("HTTP/3 stream {id} reset by server (error 0x{code:x} {name})"),
            ));
        }
        if !s.head_done {
            return Err(trace::fail(
                cx,
                ErrorKind::Http3,
                format_args!(
                    "HTTP/3 stream {id} was closed cleanly, but before getting all response \
                     header fields, treated as error"
                ),
            ));
        }
        Ok(Called::Done)
    }

    /// What the library told of the request's stream, handed on as C's
    /// callbacks write it to the transfer (`cb_h3_recv_header`,
    /// `cb_h3_end_headers`, `cb_h3_recv_data`, `cb_h3_stream_close`):
    /// a receive window its reading opened is left in `extend` for the
    /// step to open.
    fn h3_event<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        event: Event<'_>,
        extend: &mut Option<u64>,
    ) -> Heard {
        let s = self.h3_stream();
        let id = s.shown_id();
        let h3 = Component::Http3;
        match event {
            Event::Header {
                value,
                status: true,
                ..
            } => {
                let Some(code) = decode_status(value) else {
                    return Heard::Failed;
                };
                s.status = code;
                let mut line = Vec::new();
                let made = line
                    .try_extend_from_slice(b"HTTP/3 ")
                    .and_then(|()| line.try_extend_from_slice(value))
                    .and_then(|()| line.try_extend_from_slice(b" \r\n"));
                if made.is_ok() {
                    self.h3_head_line(cx, lease, &line);
                }
                let shown = String::from_utf8_lossy(&line);
                trace::of(cx, h3, format_args!("[{id}] status: {shown}"));
                match made {
                    Ok(()) => Heard::Fine,
                    Err(OutOfMemory) => Heard::Failed,
                }
            }
            Event::Header { name, value, .. } => {
                let (n, v) = (
                    String::from_utf8_lossy(name),
                    String::from_utf8_lossy(value),
                );
                trace::of(cx, h3, format_args!("[{id}] header: {n}: {v}"));
                let mut line = Vec::new();
                let made = line
                    .try_extend_from_slice(name)
                    .and_then(|()| line.try_extend_from_slice(b": "))
                    .and_then(|()| line.try_extend_from_slice(value))
                    .and_then(|()| line.try_extend_from_slice(b"\r\n"));
                match made {
                    Ok(()) => {
                        self.h3_head_line(cx, lease, &line);
                        Heard::Fine
                    }
                    Err(OutOfMemory) => Heard::Failed,
                }
            }
            Event::HeadersDone { .. } => {
                self.h3_head_line(cx, lease, b"\r\n");
                let s = self.h3_stream();
                let status = s.status;
                trace::of(cx, h3, format_args!("[{id}] end_headers, status={status}"));
                if status / 100 != 1 {
                    s.head_done = true;
                }
                Heard::Fine
            }
            Event::Data { bytes, .. } => {
                if self.h3_stream().failed.is_none() {
                    let written = self.input(cx, lease, bytes);
                    deliver::write_resp(cx, bytes.len(), false, written);
                    if let Err(kind) = written {
                        self.h3_stream().failed = Some(kind);
                        let (code, len) = (kind.number(), bytes.len());
                        trace::of(
                            cx,
                            h3,
                            format_args!("[{id}] error {code} writing {len} bytes of data"),
                        );
                    }
                }
                let s = self.h3_stream();
                s.rx_offset += bytes.len() as u64;
                s.rx_offset_max = s.rx_offset_max.max(s.rx_offset);
                let (len, win) = (bytes.len(), s.rx_offset_max - s.rx_offset);
                trace::of(cx, h3, format_args!("[{id}] DATA len={len}, rx win={win}"));
                *extend = self.rx_extend(cx);
                Heard::Fine
            }
            Event::Consumed { n, .. } => {
                s.rx_offset += n;
                s.rx_offset_max += n;
                Heard::Fine
            }
            Event::Closed { error, .. } => {
                s.closed = true;
                s.error = error;
                if error == H3Error::NO_ERROR {
                    trace::of(cx, h3, format_args!("[{id}] CLOSED"));
                } else {
                    s.reset = true;
                    s.send_closed = true;
                    let code = error.0;
                    trace::of(cx, h3, format_args!("[{id}] RESET: error {code}"));
                }
                Heard::Fine
            }
            Event::QuicClosed { error, rv, .. } => {
                let error = error.0;
                trace::of(
                    cx,
                    h3,
                    format_args!("[{id}] quic close(app_error={error}) -> {rv}"),
                );
                Heard::Fine
            }
            Event::QuicReset { rv, .. } | Event::H3Reset { rv, .. } => {
                trace::of(cx, h3, format_args!("[{id}] reset -> {rv}"));
                Heard::Fine
            }
            Event::Blocked { .. } => {
                s.flow_blocked = true;
                Heard::Fine
            }
            Event::Unblocked { .. } => {
                if s.flow_blocked {
                    trace::of(cx, h3, format_args!("[{id}] unblock quic flow"));
                    s.flow_blocked = false;
                }
                Heard::Fine
            }
            Event::BodyRead {
                vecs,
                n,
                eof,
                buffered,
                ..
            } => {
                // As C's `cb_h3_read_req_body` says it, what is left of a
                // body of unknown size `-1`.
                s.handed += n as u64;
                if eof {
                    s.send_closed = true;
                }
                if n == 0 && !eof {
                    trace::of(cx, h3, format_args!("[{id}] read req body -> AGAIN"));
                } else {
                    let left = s.body_size.map_or(-1, |size| {
                        i64::try_from(size - s.handed).expect("a body's size fits")
                    });
                    let end = if eof { " EOF" } else { "" };
                    trace::of(
                        cx,
                        h3,
                        format_args!(
                            "[{id}] read req body -> {vecs} vecs{end} with {n} \
                             (buffered={buffered}, left={left})"
                        ),
                    );
                }
                Heard::Fine
            }
            _ => Heard::Fine,
        }
    }

    /// Hand on a line of the head (`h3_xfer_write_resp_hd`): once writing
    /// failed, nothing more is.
    fn h3_head_line<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        line: &[u8],
    ) {
        if self.h3_stream().failed.is_some() {
            return;
        }
        if let Err(kind) = self.head_input(cx, lease, line, true) {
            let s = self.h3_stream();
            s.failed = Some(kind);
            let (id, code, len) = (s.shown_id(), kind.number(), line.len());
            trace::of(
                cx,
                Component::Http3,
                format_args!("[{id}] error {code} writing {len} bytes of headers"),
            );
        }
    }

    /// How much more of the body the peer may send, as the transfer can
    /// take it, said as it is decided: by as much as the receive window
    /// falls short of the most, or of what a receive limit allows, which
    /// starts once bytes came (`cf_ngtcp2_upd_rx_win`).
    fn rx_extend<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Option<u64> {
        let allowed = cx.rate_allowance(Way::Recv);
        let s = self.h3_stream();
        let id = s.shown_id();
        let wanted = match allowed {
            None => STREAM_WINDOW_MAX,
            Some(_) if s.rx_offset == 0 => return None,
            Some(avail @ ..=0) => {
                trace::of(
                    cx,
                    Component::Http3,
                    format_args!("[{id}] dl rate limit exhausted ({avail} tokens)"),
                );
                return None;
            }
            Some(avail) => (avail as u64).min(STREAM_WINDOW_MAX),
        };
        let window = s.rx_offset_max - s.rx_offset;
        if wanted <= window {
            return None;
        }
        let delta = (wanted - window).min(u64::MAX - s.rx_offset_max);
        if delta == 0 {
            return None;
        }
        s.rx_offset_max += delta;
        trace::of(
            cx,
            Component::Http3,
            format_args!("[{id}] rx window, extend by {delta} bytes"),
        );
        Some(delta)
    }

    /// The request is over (`Curl_cf_ngtcp2_h3_stream_done`): a stream
    /// still open is cancelled, and with none left open the connection is
    /// no longer kept alive.
    pub(super) fn h3_done<H: Host>(&mut self, cx: &mut StepCx<'_, H>, lease: &mut ConnLease) {
        if !self.h3_stream().set_up || lease.conn().h3().is_none() {
            return;
        }
        self.with_h3(cx, lease, |step, quic| {
            let s = step.stream();
            let id = s.shown_id();
            trace::of(
                &mut *step.cx,
                Component::Http3,
                format_args!("[{id}] easy handle is done"),
            );
            close(step, quic);
            if let Some(stream) = step.stream().id {
                step.routes.unroute(stream);
            }
            if step.routes.len() == 0 {
                quic.keep_alive(&mut *step.cx, 0);
            }
        });
    }
}

/// The stream's receive window opened as the transfer can take more, on
/// the connection at once: no call of the library's is under way.
fn rx_window<H: Host>(step: &mut H3Step<'_, '_, H>, quic: &mut Quic) {
    if let Some(n) = step.req.rx_extend(step.cx)
        && let Some(stream) = step.stream().id
    {
        quic.extend_stream_window(stream, n);
    }
}

/// How much of `stream`'s body was written to the library: what it was
/// handed, and what it holds that it was not.
fn written(s: &H3Stream, quic: &Quic, stream: StreamId) -> u64 {
    let unhanded = quic.body_buffered(stream) - quic.body_in_flight(stream);
    s.handed + unhanded as u64
}

/// The request is all sent, or will not be (`CF_CTRL_DATA_DONE_SEND`):
/// its body ends after what the library holds, its size now known. What
/// is left goes as the connection next sends.
fn done_sending<H: Host>(step: &mut H3Step<'_, '_, H>, quic: &mut Quic) {
    let s = step.stream();
    let Some(stream) = s.id.filter(|_| !s.send_closed && !s.closed) else {
        return;
    };
    s.send_closed = true;
    let written = written(s, quic, stream);
    step.stream().body_size = Some(written);
    quic.end_body(stream);
    quic.resume(stream);
}

/// Stop the stream, if it is open, both ways, nothing more heard of it
/// (`Curl_cf_ngtcp2_h3_stream_close`).
fn close<H: Host>(step: &mut H3Step<'_, '_, H>, quic: &mut Quic) {
    let s = step.stream();
    if s.closed {
        return;
    }
    s.closed = true;
    if let Some(stream) = s.id {
        quic.cancel(step, stream);
    }
}

/// Open the request's stream with the head in `out[range]`, its fields
/// as HTTP/2's are (`h3_stream_open`): the first stream open on the
/// connection keeps it alive; the stream's receive window opens to its
/// most. How much of the request it took: its head.
fn open<H: Host>(
    step: &mut H3Step<'_, '_, H>,
    quic: &mut Quic,
    range: std::ops::Range<usize>,
) -> Result<usize, ErrorKind> {
    let head = match step.req.outgoing {
        Sending::Head { left, .. } => left.get(),
        _ => 0,
    };
    let start = range.start;
    // Set up on the connection (`Curl_cf_ngtcp2_h3_stream_setup`): the
    // first of its streams has it kept alive.
    step.stream().set_up = true;
    if step.routes.len() == 0 {
        quic.keep_alive(&mut *step.cx, 1);
    }
    let custom = step.req.custom_method(step.cx);
    let scheme = step.req.peer.scheme().name.as_bytes();
    let fields = fields_of(
        &step.req.out[start..start + head],
        custom.as_deref(),
        scheme,
    )?;
    let pairs = fields.pairs().map_err(|_| ErrorKind::OutOfMemory)?;
    // A body of no bytes is none: the head ends the stream.
    let size = match &step.req.body {
        None => Some(0),
        Some(body) => {
            assert!(!body.is_chunked(), "HTTP/3 frames the body itself");
            body.size()
        }
    };
    let body = size != Some(0);
    let stream = quic.submit(step, &pairs, body)?;
    let me = step.cx.me;
    step.routes
        .route(stream, me, ())
        .map_err(|_| ErrorKind::OutOfMemory)?;
    let s = step.stream();
    s.id = Some(stream);
    s.send_closed = !body;
    s.body_size = size;
    rx_window(step, quic);
    if step.cx.easy().options().output.verbose {
        let url = step.cx.easy().report().url().map(copied).transpose()?;
        let url = url.as_deref().unwrap_or_default();
        let id = curl_alloc::try_format(format_args!("{}", stream.0))
            .map_err(|_| ErrorKind::OutOfMemory)?;
        trace::info_with(
            step.cx,
            &[b"[HTTP/3] [", id.as_bytes(), b"] OPENED stream for ", url],
        );
        for (name, value) in &pairs {
            let parts: [&[u8]; 7] = [
                b"[HTTP/3] [",
                id.as_bytes(),
                b"] [",
                name,
                b": ",
                value,
                b"]",
            ];
            trace::info_with(step.cx, &parts);
        }
    }
    Ok(head)
}

/// The library keeps more or less of the body in flight than it is given
/// room for: the room follows it (`cf_ngtcp2_send`'s `tx_in_flight_ideal`).
fn adjust_ideal<H: Host>(step: &mut H3Step<'_, '_, H>, quic: &Quic, len: usize, added: usize) {
    let Some(stream) = step.stream().id else {
        return;
    };
    let in_flight = quic.body_in_flight(stream);
    let s = step.stream();
    let (id, ideal) = (stream.0, s.send_ideal);
    let said = if in_flight > ideal + SEND_IDEAL_STEP {
        s.send_ideal += SEND_IDEAL_STEP;
        "increase"
    } else if in_flight + SEND_IDEAL_STEP < ideal {
        s.send_ideal -= SEND_IDEAL_STEP;
        "reduce"
    } else {
        return;
    };
    let ideal = s.send_ideal;
    trace::of(
        &mut *step.cx,
        Component::Http3,
        format_args!(
            "[{id}] cf_send({len}), added {added}, inflight={in_flight}, {said} tx_win={ideal}"
        ),
    );
}
