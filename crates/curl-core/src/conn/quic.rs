//! QUIC over a connection's UDP socket (C's `vquic.c` and the part of
//! `cf-ngtcp2-cmn.c` that is the transport's): the packets the QUIC
//! library writes, collected and sent in runs the kernel cuts; the
//! datagrams received, read in batches and handed to the library; its
//! timer; and the close it sends once a failure is past saving. What the
//! library tells of the connection as it reads is heard here, and what it
//! tells of a stream is handed on to the transfer the call is made for.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use curl_alloc::TryVec;

use super::io::{BATCH, Datagram, Events, IO_FAILED, SLOT, Socket, TOO_LARGE};
use super::layer::LayerCx;
use crate::components::Component;
use crate::error::{AGAIN_NUMBER, ErrorKind};
use crate::http3::{
    CloseError, Connection, Event, Expiry, H3Error, Heard, QuicError, StreamId, SubmitFailed,
};
use crate::time::{Instant, SharedClock};
use crate::tls::{SessionPeer, TlsCx};
use crate::trace::{Code, Ip, OsError};

/// The room the packets to send are collected in (`NW_CHUNK_SIZE`, one
/// chunk).
const SEND_ROOM: usize = 64 * 1024;

/// The room the datagrams received are read into, lent by the multi
/// (`Curl_multi_xfer_sockbuf_borrow`).
pub(crate) const RECV_ROOM: usize = BATCH * SLOT;

/// A request stream's first receive window, which its request opens
/// further (`H3_STREAM_WINDOW_SIZE_INITIAL`).
pub(crate) const STREAM_WINDOW_INITIAL: u64 = 32 * 1024;

/// The most packets one look at the socket reads (`progress_ingress`).
const MAX_PACKETS: usize = 1000;

/// The most a packet that closes the connection is
/// (`NGTCP2_MAX_UDP_PAYLOAD_SIZE`).
const CLOSE_ROOM: usize = 1200;

/// What closes are kinds of (`ngtcp2_ccerr_type`): a version
/// negotiation's.
const CLOSE_VERSION_NEGOTIATION: i32 = 2;
/// The transport's codes from which a close is TLS's alert
/// (`NGTCP2_CRYPTO_ERROR`).
const CRYPTO_ERROR: u64 = 0x100;
/// The server refused the connection (`NGTCP2_CONNECTION_REFUSED`).
const CONNECTION_REFUSED: u64 = 0x2;

/// What QUIC reaches beyond the transfer's trace: the multi's room for
/// the datagrams it receives, and the transfer's timer for the QUIC
/// library's (`EXPIRE_QUIC`). What the library tells of a stream reaches
/// the transfer through `LayerCx::h3_event`.
pub(crate) trait QuicCx: LayerCx {
    /// The room to receive in, of at least `RECV_ROOM` bytes, lent until
    /// it is given back.
    fn take_room(&mut self) -> Result<Vec<u8>, curl_alloc::OutOfMemory>;

    /// The room lent, given back.
    fn give_room(&mut self, room: Vec<u8>);

    /// The QUIC library wants to be called again after `wait` from now,
    /// in whole milliseconds (`Curl_expire_set(EXPIRE_QUIC)`).
    fn quic_due(&mut self, wait: Duration);
}

/// A `QuicCx` with the UDP socket the connection goes over, asked for at
/// each call on it, so that nothing holds it while the library tells the
/// transfer what it read.
pub(crate) trait QuicIo: QuicCx {
    fn socket(&self) -> &dyn Socket;
}

/// An event of a stream no transfer has, as C's callbacks hear one whose
/// stream has no user data: the QUIC stream's close is traced for the
/// transfer of the call (`cb_stream_close`), and body bytes for nobody
/// fail the read (`cb_h3_recv_data`).
pub(crate) fn unrouted(cx: &mut dyn LayerCx, event: &Event<'_>) -> Heard {
    match *event {
        Event::QuicClosed { stream, error, rv } => {
            let (id, error) = (stream.0, error.0);
            cx.of(
                Component::Http3,
                format_args!("[{id}] quic close(app_error={error}) -> {rv}"),
            );
            Heard::Fine
        }
        Event::Data { .. } => Heard::Failed,
        _ => Heard::Fine,
    }
}

/// The context of a call on a connection no transfer is stepping, as its
/// health is checked or it says goodbye: every stream is one no transfer
/// has, the room to read into is made for the call, and the library's
/// timer is set by no one, as C's calls give it no packet context.
pub(crate) struct Lone<'a> {
    pub(crate) cx: &'a mut dyn LayerCx,
}

impl LayerCx for Lone<'_> {
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

    fn early_done(&mut self, sent: i64) {
        self.cx.early_done(sent);
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
        unrouted(&mut *self.cx, &event)
    }
}

impl QuicCx for Lone<'_> {
    fn take_room(&mut self) -> Result<Vec<u8>, curl_alloc::OutOfMemory> {
        let mut room = Vec::new();
        room.try_resize(RECV_ROOM, 0)?;
        Ok(room)
    }

    fn give_room(&mut self, _room: Vec<u8>) {}

    fn quic_due(&mut self, _wait: Duration) {}
}

/// An attempt's context, with the socket it dialed.
pub(crate) struct Over<'a> {
    pub(crate) cx: &'a mut dyn QuicCx,
    pub(crate) socket: &'a dyn Socket,
}

impl LayerCx for Over<'_> {
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

    fn early_done(&mut self, sent: i64) {
        self.cx.early_done(sent);
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
        self.cx.h3_event(event)
    }
}

impl QuicCx for Over<'_> {
    fn take_room(&mut self) -> Result<Vec<u8>, curl_alloc::OutOfMemory> {
        self.cx.take_room()
    }

    fn give_room(&mut self, room: Vec<u8>) {
        self.cx.give_room(room);
    }

    fn quic_due(&mut self, wait: Duration) {
        self.cx.quic_due(wait);
    }
}

impl QuicIo for Over<'_> {
    fn socket(&self) -> &dyn Socket {
        self.socket
    }
}

/// What an I/O call came to, short of success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    /// The socket would block (`CURLE_AGAIN`).
    Again,
    Failed(ErrorKind),
}

impl Stop {
    fn number(self) -> u16 {
        match self {
            Stop::Again => AGAIN_NUMBER,
            Stop::Failed(kind) => kind.number(),
        }
    }
}

/// The number C traces for a result.
fn number(r: Result<(), Stop>) -> u16 {
    r.err().map_or(0, Stop::number)
}

/// The packets collected to send (`sendbuf`): the bytes at `sent..`,
/// sent as datagrams of `gso` bytes each, the first `split` of them, if
/// set, as datagrams of their own size.
struct Out {
    bytes: Vec<u8>,
    sent: usize,
    gso: usize,
    split: Option<(usize, usize)>,
    /// The kernel failed to cut a run once: each datagram goes on its own
    /// from then on.
    no_gso: bool,
}

impl Out {
    fn unsent(&self) -> &[u8] {
        &self.bytes[self.sent..]
    }

    fn is_empty(&self) -> bool {
        self.sent == self.bytes.len()
    }

    /// `n` of the unsent went.
    fn skip(&mut self, n: usize) {
        self.sent += n;
        if let Some((len, gso)) = self.split {
            self.split = (len > n).then(|| (len - n, gso));
        }
        if self.is_empty() {
            self.bytes.clear();
            self.sent = 0;
        }
    }
}

/// What the connection keeps of itself as it reads, apart from the QUIC
/// library's, which is lent out while it reads.
#[derive(Debug)]
struct State {
    /// The first connect call (`started_at`).
    started: Instant,
    /// The handshake completed (`handshake_at`).
    handshake_at: Option<Instant>,
    /// What the check of the peer said (`tls_vrfy_result`).
    verified: Result<(), ErrorKind>,
    /// The peer's limit on the streams opened (`max_bidi_streams`).
    max_bidi: u64,
    /// The streams opened (`used_bidi_streams`).
    used_bidi: u64,
    /// The packet that closes it was made (`shutdown_started`).
    shutdown_started: bool,
    /// It is in the middle of closing, which a failure sending its last
    /// packets does not start again.
    closing: bool,
    /// The connect is done (`cf->connected`).
    connected: bool,
    /// When the library was last called, which what it tells is timed by.
    now: Instant,
    /// When the first datagram came (`first_byte_at`), the connect's time.
    first_byte_at: Option<Instant>,
    /// When a datagram last went or came (`last_io`).
    last_io: Instant,
}

/// A QUIC connection over its UDP socket.
pub(crate) struct Quic {
    conn: Box<dyn Connection>,
    /// Who its TLS sessions are kept for, the context of its TLS's.
    peer: SessionPeer,
    remote: SocketAddr,
    out: Out,
    state: State,
    /// The clock it was made under, read again before each call into
    /// its library as C's filter reads the time
    /// (`Curl_cf_ngtcp2_io_ctx_update_time`), whichever transfer, multi or
    /// share uses it.
    clock: SharedClock,
}

impl std::fmt::Debug for Quic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Quic")
            .field("remote", &self.remote)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Quic {
    /// The connection `conn`, to `remote`, whose TLS's sessions are kept
    /// for `peer`, its connect started now on `clock`.
    pub(crate) fn new(
        conn: Box<dyn Connection>,
        peer: SessionPeer,
        remote: SocketAddr,
        clock: SharedClock,
    ) -> Result<Quic, curl_alloc::OutOfMemory> {
        let now = clock.now();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(SEND_ROOM)
            .map_err(|_| curl_alloc::OutOfMemory)?;
        Ok(Quic {
            conn,
            peer,
            remote,
            out: Out {
                bytes,
                sent: 0,
                gso: 0,
                split: None,
                no_gso: false,
            },
            state: State {
                started: now,
                handshake_at: None,
                verified: Ok(()),
                max_bidi: 0,
                used_bidi: 0,
                shutdown_started: false,
                closing: false,
                connected: false,
                now,
                first_byte_at: None,
                last_io: now,
            },
            clock,
        })
    }

    /// When the first datagram came, the time a QUIC connection is
    /// connected at (`cf_socket_cntrl`'s for QUIC).
    pub(crate) fn first_byte_at(&self) -> Option<Instant> {
        self.state.first_byte_at
    }

    /// When the handshake completed.
    pub(crate) fn handshake_at(&self) -> Option<Instant> {
        self.state.handshake_at
    }

    /// How many transfers it takes at once, with `attached` on it
    /// (`cf_ngtcp2_query`'s `CF_QUERY_MAX_CONCURRENT`): QUIC counts the
    /// streams opened over the connection's life, so those open and the
    /// streams the peer still allows; before its limit arrives, the
    /// multi's own, `default`; none once it is shutting down. At most
    /// C's `INT_MAX`.
    pub(crate) fn max_concurrent(&self, attached: u32, default: u32) -> u32 {
        const MOST: u64 = i32::MAX as u64;
        if self.state.shutdown_started {
            return 0;
        }
        let max = match self.state.max_bidi {
            0 => u64::from(default),
            limit => u64::from(attached) + limit.saturating_sub(self.state.used_bidi),
        };
        u32::try_from(max.min(MOST)).expect("at most INT_MAX")
    }

    /// What the socket is watched for (`cf_ngtcp2_adjust_pollset`): to
    /// read always, and to write while packets wait to go.
    pub(crate) fn wants(&self) -> Events {
        if self.out.is_empty() {
            Events::IN
        } else {
            Events::IN | Events::OUT
        }
    }

    /// The first connect call: the client's first flight sent, and the
    /// timer set (`Curl_cf_ngtcp2_cmn_connect` with no connection yet).
    pub(crate) fn start(&mut self, cx: &mut dyn QuicIo) -> Result<bool, ErrorKind> {
        let sent = self.egress(cx);
        self.connect_ended(cx, sent.map(|()| false))
    }

    /// A later connect call: what came read, what is due sent, and done
    /// once the handshake is and the peer checked
    /// (`Curl_cf_ngtcp2_cmn_connect`).
    pub(crate) fn connect(&mut self, cx: &mut dyn QuicIo) -> Result<bool, ErrorKind> {
        let step = (|| {
            self.ingress(cx)?;
            self.egress(cx)?;
            if self.conn.handshake_done() {
                self.state.verified?;
                cx.of(Component::Http3, format_args!("peer verified"));
                self.state.connected = true;
                return Ok(true);
            }
            Ok(false)
        })();
        self.connect_ended(cx, step)
    }

    /// A connect call ended with `step`: a failed check of the peer wins
    /// over what else failed, a peer that closed it says why, and the
    /// timer is set if it goes on.
    fn connect_ended(
        &mut self,
        cx: &mut dyn QuicIo,
        step: Result<bool, ErrorKind>,
    ) -> Result<bool, ErrorKind> {
        let mut step = step;
        if let Err(kind) = self.state.verified {
            step = Err(kind);
        }
        if matches!(step, Err(ErrorKind::RecvError | ErrorKind::SendError)) && self.conn.draining()
        {
            step = Err(ErrorKind::CouldntConnect);
            if let Some(CloseError { kind, code }) = self.conn.closed_with() {
                let h3 = Component::Http3;
                cx.of(h3, format_args!("connect error, type={kind}, code={code}"));
                if kind == CLOSE_VERSION_NEGOTIATION {
                    cx.of(h3, format_args!("error in version negotiation"));
                } else if code >= CRYPTO_ERROR {
                    let alert = code & 0xff;
                    cx.of(h3, format_args!("crypto error, tls alert={alert}"));
                } else if code == CONNECTION_REFUSED {
                    cx.of(h3, format_args!("connection refused by server"));
                    // A server shutting down may say so at once: the next
                    // address is tried.
                    step = Err(ErrorKind::WeirdServerReply);
                }
            }
        }
        if let Err(kind) = step {
            let (ip, port) = (self.remote.ip(), self.remote.port());
            let why = kind.message();
            cx.info(format_args!(
                "QUIC connect to {ip} port {port} failed: {why}"
            ));
        }
        if step.is_ok()
            && let Err(kind) = self.set_expiry(cx)
        {
            step = Err(kind);
        }
        let done = matches!(step, Ok(true));
        if step.is_err() || done {
            let code = Code(step.map(|_| ()));
            let done = u8::from(done);
            cx.of(
                Component::Http3,
                format_args!("connect -> {code}, done={done}"),
            );
        }
        step
    }

    /// The library's timer: run if it is due, and set for when it next is
    /// (`Curl_cf_ngtcp2_cmn_set_expiry`).
    pub(crate) fn set_expiry(&mut self, cx: &mut dyn QuicIo) -> Result<(), ErrorKind> {
        let mut expiry = self.conn.expiry(self.clock.now());
        if expiry == Expiry::Due {
            let now = self.clock.now();
            self.state.now = now;
            let ran = {
                let Quic {
                    conn, peer, state, ..
                } = self;
                let mut tcx = TlsCx::new(cx, Component::Http3, peer);
                conn.handle_expiry(&mut tcx, now, &mut |tcx, e| state.heard(tcx, e))
            };
            if let Err(error) = ran {
                let why = error.text;
                cx.fails(
                    ErrorKind::SendError,
                    format_args!("ngtcp2_conn_handle_expiry returned error: {why}"),
                );
                self.failed(cx, error);
                return Err(ErrorKind::SendError);
            }
            let moved = self.ingress(cx).and_then(|()| self.egress(cx));
            if let Err(kind) = moved {
                // A failed check of the peer wins over what else failed.
                return Err(self.state.verified.err().unwrap_or(kind));
            }
            expiry = self.conn.expiry(self.clock.now());
        }
        if let Expiry::In(wait) = expiry {
            // In whole milliseconds, rounded up.
            let ms = wait.as_nanos().div_ceil(1_000_000);
            cx.quic_due(Duration::from_millis(u64::try_from(ms).unwrap_or(u64::MAX)));
        }
        Ok(())
    }

    /// Its TLS session's library objects.
    pub(crate) fn tls_native(&self) -> crate::tls::TlsNative {
        self.conn.tls_native()
    }

    /// Whether it may still be used, as far as it knows itself
    /// (`Curl_cf_ngtcp2_cmn_conn_is_alive`): not if it shuts down, nor once
    /// idle past the time the peer said it closes an idle connection by,
    /// in whole milliseconds.
    pub(crate) fn usable(&self) -> bool {
        if self.state.shutdown_started {
            return false;
        }
        match self.conn.peer_idle_timeout() {
            Some(max) if max > Duration::ZERO => {
                let idle = self.clock.now().since(self.state.last_io).as_millis();
                idle == 0 || idle <= max.as_millis()
            }
            _ => true,
        }
    }

    /// What waits on the socket of a connection no transfer uses, read: it
    /// is alive if that went (`Curl_cf_ngtcp2_cmn_conn_is_alive`).
    pub(crate) fn read_pending(&mut self, cx: &mut dyn QuicIo) -> bool {
        let read = self.ingress(cx);
        let code = Code(read);
        cx.of(
            Component::Http3,
            format_args!("is_alive, progress ingress -> {code}"),
        );
        read.is_ok()
    }

    /// What the check of the peer said (`tls_vrfy_result`): a failure
    /// denies every send and receive after.
    pub(crate) fn verified(&self) -> Result<(), ErrorKind> {
        self.state.verified
    }

    /// The packet that closes it was made: no stream opens on it, and
    /// none sends (`shutdown_started`).
    pub(crate) fn shutdown_started(&self) -> bool {
        self.state.shutdown_started
    }

    /// Open a stream for a request of `fields`, with a body if `body`,
    /// counted among those the peer allows (`h3_stream_open`). A request
    /// the library refused cancels its stream.
    pub(crate) fn submit(
        &mut self,
        cx: &mut dyn QuicIo,
        fields: &[(&[u8], &[u8])],
        body: bool,
    ) -> Result<StreamId, ErrorKind> {
        match self.conn.submit_request(fields, body) {
            Ok(stream) => {
                self.state.used_bidi += 1;
                Ok(stream)
            }
            Err(SubmitFailed::OutOfMemory) => Err(ErrorKind::OutOfMemory),
            Err(SubmitFailed::NoStream) => Err(cx.fails(
                ErrorKind::SendError,
                format_args!("cannot open bidi streams"),
            )),
            Err(SubmitFailed::Refused {
                stream,
                error,
                closing,
            }) => {
                self.state.used_bidi += 1;
                let id = stream.0;
                if closing {
                    cx.of(
                        Component::Http3,
                        format_args!("h3sid[{id}] failed to send, connection is closing"),
                    );
                } else {
                    let (code, text) = (error.code, error.text);
                    cx.of(
                        Component::Http3,
                        format_args!("h3sid[{id}] failed to send -> {code} ({text})"),
                    );
                }
                self.cancel(cx, stream);
                Err(ErrorKind::SendError)
            }
        }
    }

    /// Stop `stream` both ways as cancelled, nothing more heard of it,
    /// and send what that says (`Curl_cf_ngtcp2_h3_stream_close`).
    pub(crate) fn cancel(&mut self, cx: &mut dyn QuicIo, stream: StreamId) {
        self.conn.cancel(stream, H3Error::REQUEST_CANCELLED);
        if let Err(kind) = self.egress(cx) {
            let (id, code) = (stream.0, kind.number());
            cx.of(
                Component::Http3,
                format_args!("[{id}] cancel stream -> {code}"),
            );
        }
    }

    /// Open `stream`'s receive window by `n`.
    pub(crate) fn extend_stream_window(&mut self, stream: StreamId, n: u64) {
        self.conn.extend_stream_window(stream, n);
    }

    /// The bytes of `stream`'s body handed to the library and not yet
    /// acknowledged (`tx_in_flight_size`).
    pub(crate) fn body_in_flight(&self, stream: StreamId) -> usize {
        self.conn.body_in_flight(stream)
    }

    /// Whether the connection may send more now: its congestion window and
    /// the peer's limit on its data leave room (`ngtcp2_conn_get_cwnd_left`,
    /// `ngtcp2_conn_get_max_data_left`).
    pub(crate) fn send_room(&self) -> bool {
        self.conn.send_room()
    }

    /// The bytes of `stream`'s body held and not yet acknowledged, handed
    /// to the library or not (`sendbuf`'s length).
    pub(crate) fn body_buffered(&self, stream: StreamId) -> usize {
        self.conn.body_buffered(stream)
    }

    /// Take what of `bytes` it holds room for of `stream`'s body: how
    /// many.
    pub(crate) fn write_body(
        &mut self,
        stream: StreamId,
        bytes: &[u8],
    ) -> Result<usize, ErrorKind> {
        self.conn
            .write_body(stream, bytes)
            .map_err(|_| ErrorKind::OutOfMemory)
    }

    /// `stream`'s body ends after what it holds.
    pub(crate) fn end_body(&mut self, stream: StreamId) {
        self.conn.end_body(stream);
    }

    /// `stream` has more of its body to send (`nghttp3_conn_resume_stream`).
    pub(crate) fn resume(&mut self, stream: StreamId) {
        self.conn.resume(stream);
    }

    /// Keep the connection alive while `streams` are open, as often as
    /// half the peer's idle timeout, lest it close one waiting for a
    /// response (`cf_ngtcp2_setup_keep_alive`).
    pub(crate) fn keep_alive(&mut self, cx: &mut dyn LayerCx, streams: usize) {
        let h3 = Component::Http3;
        match self.conn.peer_idle_timeout() {
            None => {
                self.conn.set_keep_alive(None);
                cx.of(h3, format_args!("no peer idle timeout, unset keep-alive"));
            }
            Some(_) if streams == 0 => {
                self.conn.set_keep_alive(None);
                cx.of(h3, format_args!("no active streams, unset keep-alive"));
            }
            Some(idle) => {
                let keep = if idle > Duration::from_nanos(1) {
                    idle / 2
                } else {
                    Duration::from_nanos(1)
                };
                self.conn.set_keep_alive(Some(keep));
                let (idle, keep) = (idle.as_millis(), keep.as_millis());
                cx.of(
                    h3,
                    format_args!("peer idle timeout is {idle}ms, set keep-alive to {keep} ms."),
                );
            }
        }
    }

    /// The library's call failed with `error`: kept as what it closes
    /// with, if nothing was before, and closed now if past saving
    /// (`Curl_cf_ngtcp2_cmn_err_set`).
    fn failed(&mut self, cx: &mut dyn QuicIo, error: QuicError) {
        if self.conn.failed(error) {
            self.close(cx);
        }
    }

    /// Close it: what waits to go sent, then the packet that closes it,
    /// as far as the socket takes them now (`Curl_cf_ngtcp2_cmn_shutdown`).
    /// Whether all went.
    pub(crate) fn close(&mut self, cx: &mut dyn QuicIo) -> bool {
        if self.state.closing {
            return false;
        }
        self.state.closing = true;
        let done = self.close_step(cx);
        self.state.closing = false;
        done
    }

    fn close_step(&mut self, cx: &mut dyn QuicIo) -> bool {
        let h3 = Component::Http3;
        if !self.state.shutdown_started {
            if !self.out.is_empty() {
                cx.of(h3, format_args!("shutdown, flushing sendbuf"));
                let sent = self.egress(cx);
                if !self.out.is_empty() {
                    cx.of(h3, format_args!("sending shutdown packets blocked"));
                    return false;
                }
                if let Err(kind) = sent {
                    let code = kind.number();
                    cx.of(h3, format_args!("shutdown, error {code} flushing sendbuf"));
                    return true;
                }
            }
            self.state.shutdown_started = true;
            let mut packet = [0u8; CLOSE_ROOM];
            let closing = self.conn.close_error();
            let written = self.conn.write_close(self.clock.now(), &mut packet);
            let (kind, code) = (closing.kind, closing.code);
            match written {
                Ok(n) => cx.of(
                    h3,
                    format_args!("start shutdown(err_type={kind}, err_code={code}) -> {n}"),
                ),
                Err(e) => {
                    let rv = e.code;
                    cx.of(
                        h3,
                        format_args!("start shutdown(err_type={kind}, err_code={code}) -> {rv}"),
                    );
                }
            }
            // Its failure is passed over: the close is as graceful as it
            // can be.
            if let Ok(n) = written
                && n > 0
            {
                if self.out.bytes.try_extend_from_slice(&packet[..n]).is_err() {
                    let oom = ErrorKind::OutOfMemory.number();
                    cx.of(
                        h3,
                        format_args!(
                            "error {oom} adding shutdown packets to sendbuf, aborting shutdown"
                        ),
                    );
                    return false;
                }
                self.out.no_gso = true;
                self.out.gso = n;
                self.out.split = None;
            }
        }
        if !self.out.is_empty() {
            cx.of(h3, format_args!("shutdown, flushing egress"));
            match self.flush(cx) {
                Ok(()) => {}
                Err(Stop::Again) => {
                    cx.of(h3, format_args!("sending shutdown packets blocked"));
                    return false;
                }
                Err(Stop::Failed(kind)) => {
                    let code = kind.number();
                    cx.of(h3, format_args!("shutdown, error {code} flushing sendbuf"));
                    return true;
                }
            }
        }
        if self.out.is_empty() {
            cx.of(h3, format_args!("shutdown completely sent off, done"));
            return true;
        }
        false
    }

    /// Send what waits, then collect what the library has to send and
    /// send it, in runs of packets of one size (`progress_egress`).
    pub(crate) fn egress(&mut self, cx: &mut dyn QuicIo) -> Result<(), ErrorKind> {
        match self.flush(cx) {
            Ok(()) => {}
            Err(Stop::Again) => {
                cx.quic_due(Duration::from_millis(1));
                return Ok(());
            }
            Err(Stop::Failed(kind)) => return Err(kind),
        }
        // A packet larger than those before may be the library finding
        // the path's MTU, which the network may refuse: what is collected
        // before it goes first, so that what follows is not refused with
        // it.
        let max = self.conn.max_payload();
        let path_max = self.conn.path_max_payload();
        let quantum = self.conn.send_quantum();
        cx.of(
            Component::Http3,
            format_args!("egress, collect and send packets, quantum={quantum}"),
        );
        let (mut packets, mut gso) = (0usize, 0usize);
        while let Some(n) = self.collect(cx, max)? {
            let len = self.out.unsent().len();
            if len >= quantum || len + gso >= SEND_ROOM {
                break;
            }
            packets += 1;
            if packets == 1 {
                // The first: of a size known to work, or a probe.
                gso = n;
            } else if n > gso || (gso > path_max && n != gso) {
                // This one is a probe, or those before were and this one
                // is smaller: those before go first.
                match self.send_tail_split(cx, gso, n, n) {
                    Ok(()) => {}
                    Err(Stop::Again) => {
                        cx.quic_due(Duration::from_millis(1));
                        return Ok(());
                    }
                    Err(Stop::Failed(kind)) => return Err(kind),
                }
                packets = 0;
            } else if n < gso {
                // The last of a run.
                break;
            }
        }
        if !self.out.is_empty() {
            let len = self.out.unsent().len();
            cx.of(
                Component::Http3,
                format_args!("egress, send collected {packets} packets in {len} bytes"),
            );
            self.out.gso = gso;
            match self.flush(cx) {
                Ok(()) => {}
                Err(Stop::Again) => {
                    cx.quic_due(Duration::from_millis(1));
                    return Ok(());
                }
                Err(Stop::Failed(kind)) => return Err(kind),
            }
            self.conn.sent_at(self.clock.now());
        }
        Ok(())
    }

    /// The library's next packet, of at most `max` bytes, added to those
    /// collected: its length, or none if it has none
    /// (`read_pkt_to_send`).
    fn collect(&mut self, cx: &mut dyn QuicIo, max: usize) -> Result<Option<usize>, ErrorKind> {
        let at = self.out.bytes.len();
        if self.out.bytes.try_resize(at + max, 0).is_err() {
            return Err(ErrorKind::OutOfMemory);
        }
        let now = self.clock.now();
        self.state.now = now;
        let wrote = {
            let Quic {
                conn,
                peer,
                state,
                out,
                ..
            } = self;
            let mut tcx = TlsCx::new(cx, Component::Http3, peer);
            conn.write_packet(&mut tcx, now, &mut out.bytes[at..], &mut |tcx, e| {
                state.heard(tcx, e)
            })
        };
        match wrote {
            Ok(Some(n)) => {
                self.out.bytes.truncate(at + n);
                Ok(Some(n))
            }
            Ok(None) => {
                self.out.bytes.truncate(at);
                Ok(None)
            }
            Err(error) => {
                self.out.bytes.truncate(at);
                let (call, why) = (error.call, error.text);
                cx.fails(
                    ErrorKind::SendError,
                    format_args!("{call} returned error: {why}"),
                );
                self.failed(cx, error);
                Err(ErrorKind::SendError)
            }
        }
    }

    /// The packets collected but the last `tail` bytes sent, as datagrams
    /// of `gso` bytes, and the tail as datagrams of `tail_gso`
    /// (`Curl_vquic_send_tail_split`).
    fn send_tail_split(
        &mut self,
        cx: &mut dyn QuicIo,
        gso: usize,
        tail: usize,
        tail_gso: usize,
    ) -> Result<(), Stop> {
        let len = self.out.unsent().len();
        assert!(len > tail, "a tail is split from packets before it");
        let head = len - tail;
        self.out.split = Some((head, gso));
        self.out.gso = tail_gso;
        cx.of(
            Component::Http3,
            format_args!("vquic_send_tail_split: [{head} gso={gso}][{tail} gso={tail_gso}]"),
        );
        self.flush(cx)
    }

    /// Send what is collected (`Curl_vquic_flush`).
    fn flush(&mut self, cx: &mut dyn QuicIo) -> Result<(), Stop> {
        while !self.out.is_empty() {
            let unsent = self.out.unsent().len();
            let (len, gso) = match self.out.split {
                Some((len, gso)) => (unsent.min(len), gso),
                None => (unsent, self.out.gso),
            };
            let (sent, r) = self.send_packets(cx, len, gso);
            self.out.skip(sent);
            r?;
            self.state.last_io = self.clock.now();
        }
        Ok(())
    }

    /// The first `len` bytes of what waits sent, as datagrams of `gso`
    /// bytes: how many went (`vquic_send_packets`).
    fn send_packets(
        &mut self,
        cx: &mut dyn QuicIo,
        len: usize,
        gso: usize,
    ) -> (usize, Result<(), Stop>) {
        if self.out.no_gso && len > gso {
            self.send_apart(cx, len, gso)
        } else {
            self.send_run(cx, len, gso)
        }
    }

    /// One send of `len` bytes, cut by the kernel into datagrams of `gso`
    /// bytes (`do_sendmsg`).
    fn send_run(
        &mut self,
        cx: &mut dyn QuicIo,
        len: usize,
        gso: usize,
    ) -> (usize, Result<(), Stop>) {
        let at = self.out.sent;
        let bytes = &self.out.bytes[at..at + len];
        // No size known yet is no cutting: one datagram, as the kernel
        // takes a segment size of 0.
        let segment = if gso == 0 { len } else { gso };
        let (sent, r) = match cx.socket().send_segments(bytes, segment) {
            Ok(n) if n == len => (n, Ok(())),
            Ok(n) => {
                cx.fails(
                    ErrorKind::SendError,
                    format_args!("sendmsg() sent only {n}/{len} bytes"),
                );
                (n, Err(Stop::Failed(ErrorKind::SendError)))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, Err(Stop::Again)),
            // Too large for the path, a probe of its MTU: lost.
            Err(e) if e.raw_os_error() == Some(TOO_LARGE) => (len, Ok(())),
            Err(e) if e.raw_os_error() == Some(IO_FAILED) && len > gso => {
                // The kernel cannot cut it: each datagram goes on its own
                // from now on.
                let errno = IO_FAILED;
                cx.info(format_args!(
                    "sendmsg() returned -1 (errno {errno}); disable GSO"
                ));
                self.out.no_gso = true;
                return self.send_apart(cx, len, gso);
            }
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(0);
                cx.fails(
                    ErrorKind::SendError,
                    format_args!("sendmsg() returned -1 (errno {errno})"),
                );
                (0, Err(Stop::Failed(ErrorKind::SendError)))
            }
        };
        let code = number(r);
        cx.of(
            Component::Http3,
            format_args!("vquic_sendmsg(len={len}, gso={gso}, calls=1) -> {code}, sent={sent}"),
        );
        (sent, r)
    }

    /// `len` bytes sent a datagram of `gso` bytes at a time
    /// (`send_packet_no_gso`).
    fn send_apart(
        &mut self,
        cx: &mut dyn QuicIo,
        len: usize,
        gso: usize,
    ) -> (usize, Result<(), Stop>) {
        let (mut sent, mut calls) = (0, 0);
        let mut r = Ok(());
        let start = self.out.sent;
        while sent < len {
            let one = gso.min(len - sent);
            // Each is sent from where the last left off, which the
            // collected bytes are not yet skipped past.
            self.out.sent = start + sent;
            let (n, got) = self.send_run(cx, one, one);
            self.out.sent = start;
            if let Err(stop) = got {
                r = Err(stop);
                break;
            }
            sent += n;
            calls += 1;
        }
        let code = number(r);
        cx.of(
            Component::Http3,
            format_args!(
                "vquic_sendmsg(len={len}, gso={gso}, calls={calls}) -> {code}, sent={sent}"
            ),
        );
        (sent, r)
    }

    /// Read what the socket has, in batches, and hand each packet to the
    /// library (`Curl_cf_ngtcp2_progress_ingress`).
    pub(crate) fn ingress(&mut self, cx: &mut dyn QuicIo) -> Result<(), ErrorKind> {
        {
            let Quic { conn, peer, .. } = self;
            conn.before_recv(&mut TlsCx::new(cx, Component::Http3, peer))?;
        }
        cx.of(Component::Http3, format_args!("progress_ingress(socket)"));
        let Ok(mut room) = cx.take_room() else {
            return Err(ErrorKind::OutOfMemory);
        };
        let r = self.recv_packets(cx, &mut room);
        cx.give_room(room);
        r
    }

    /// What the socket has, at most `MAX_PACKETS` packets of it, read
    /// into `room` and handed to the library (`recvmmsg_packets`).
    fn recv_packets(&mut self, cx: &mut dyn QuicIo, room: &mut [u8]) -> Result<(), ErrorKind> {
        let mut got = [Datagram::default(); BATCH];
        let (mut total, mut packets, mut calls) = (0usize, 0usize, 0usize);
        let mut first = None;
        let r = loop {
            if packets >= MAX_PACKETS {
                break Ok(());
            }
            let n = BATCH.min(MAX_PACKETS - packets);
            let count = match cx.socket().recv_batch(room, SLOT, &mut got[..n]) {
                Ok(count) => count,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    cx.of(
                        Component::Http3,
                        format_args!("ingress, recvmmsg -> EAGAIN"),
                    );
                    break Ok(());
                }
                Err(e) if !self.state.connected && e.kind() == io::ErrorKind::ConnectionRefused => {
                    let (ip, port) = (Ip(Some(self.remote.ip())), self.remote.port());
                    let kind = ErrorKind::CouldntConnect;
                    let why = format_args!("QUIC: connection to {ip} port {port} refused");
                    break Err(cx.fails(kind, why));
                }
                Err(e) => {
                    let errno = e.raw_os_error().unwrap_or(0);
                    let why = OsError(&e);
                    break Err(cx.fails(
                        ErrorKind::RecvError,
                        format_args!(
                            "QUIC: recvmmsg() unexpectedly returned -1 (errno={errno}; {why})"
                        ),
                    ));
                }
            };
            calls += 1;
            let mut failed = None;
            for (i, d) in got[..count].iter().enumerate() {
                // An empty datagram is no QUIC packet.
                if d.len == 0 {
                    packets += 1;
                    continue;
                }
                total += d.len;
                first.get_or_insert_with(|| self.clock.now());
                let bytes = &room[i * SLOT..i * SLOT + d.len];
                if let Err(kind) = self.read_datagram(cx, d, bytes) {
                    failed = Some(kind);
                    break;
                }
                packets += d.len.div_ceil(d.segment);
            }
            if let Some(kind) = failed {
                break Err(kind);
            }
        };
        // Time of the first datagram ever read: the connect's
        // (`Curl_vquic_recv_packets`).
        if r.is_ok() && total > 0 && self.state.first_byte_at.is_none() {
            self.state.first_byte_at = first;
        }
        if r.is_ok() && total > 0 {
            self.state.last_io = self.clock.now();
        }
        if total > 0 || r.is_err() {
            let code = Code(r);
            cx.of(
                Component::Http3,
                format_args!(
                    "vquic_recvmmsg(len={total}, packets={packets}, calls={calls}) -> {code}"
                ),
            );
        }
        r
    }

    /// The packets of datagram `d`, `bytes`, handed to the library one by
    /// one (`cf_ngtcp2_recv_pkts`).
    fn read_datagram(
        &mut self,
        cx: &mut dyn QuicIo,
        d: &Datagram,
        bytes: &[u8],
    ) -> Result<(), ErrorKind> {
        if d.ecn != 0 {
            let (len, gso, ecn) = (d.len, d.segment, d.ecn);
            cx.of(
                Component::Http3,
                format_args!("vquic_recv(len={len}, gso={gso}, ecn={ecn:x})"),
            );
        }
        let from = d.from.unwrap_or(self.remote);
        let now = self.clock.now();
        self.state.now = now;
        for packet in bytes.chunks(d.segment) {
            let read = {
                let Quic {
                    conn, peer, state, ..
                } = self;
                let mut tcx = TlsCx::new(cx, Component::Http3, peer);
                conn.read_packet(&mut tcx, now, from, d.ecn, packet, &mut |tcx, e| {
                    state.heard(tcx, e)
                })
            };
            if let Err(error) = read {
                let (text, code) = (error.text, error.code);
                cx.of(
                    Component::Http3,
                    format_args!("ingress, read_pkt -> {text} ({code})"),
                );
                self.failed(cx, error);
                // A failed TLS, which an unverified peer often is.
                return Err(if error.crypto {
                    ErrorKind::PeerFailedVerification
                } else {
                    ErrorKind::RecvError
                });
            }
        }
        Ok(())
    }
}

impl State {
    /// The library told `event`: the connection's own heard here, a
    /// stream's handed to the transfer the call is made for.
    fn heard(&mut self, cx: &mut TlsCx<'_>, event: Event<'_>) -> Heard {
        match event {
            Event::HandshakeDone {
                checked,
                max_udp_payload,
                initial_max_data,
                ..
            } => {
                let now = self.now;
                self.handshake_at = Some(now);
                self.verified = checked;
                if checked.is_ok() {
                    let ms = now.since(self.started).as_millis();
                    cx.trace(format_args!(
                        "handshake complete after {ms}ms, remote transport[max_udp_payload={max_udp_payload}, initial_max_data={initial_max_data}]"
                    ));
                }
                Heard::Fine
            }
            // The call fails for it; C says why as it fails it
            // (`init_ngh3_conn`).
            Event::H3Failed {
                why,
                detail,
                out_of_memory,
            } => {
                let kind = if out_of_memory {
                    ErrorKind::OutOfMemory
                } else {
                    ErrorKind::QuicConnectError
                };
                match detail {
                    Some(detail) => cx.fail(kind, format_args!("{why}: {detail}")),
                    None => cx.fail(kind, format_args!("{why}")),
                };
                Heard::Failed
            }
            Event::MaxBidiStreams(n) => {
                self.max_bidi = n;
                let used = self.used_bidi;
                cx.trace(format_args!("max bidi streams now {n}, used {used}"));
                Heard::Fine
            }
            other => cx.h3_event(other),
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::disallowed_macros)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::conn::io::{Connect, Readiness, Recv, Remote, Sent, SocketKey, SocketOption};
    use crate::http3::fake::{FakeHttp3, Script, Told};
    use crate::http3::{ClientSetup, Http3};
    use crate::time::{Clock, ManualClock};

    /// What a scripted socket does with a call.
    #[derive(Debug)]
    enum Act {
        Take,
        Short(usize),
        Fail(i32),
        Block,
    }

    /// A UDP socket whose sends do as scripted, taking all once the
    /// script is used, and whose receives give what is queued.
    #[derive(Debug, Default)]
    struct Scripted {
        sends: Mutex<VecDeque<Act>>,
        sent: Mutex<Vec<(usize, usize)>>,
        datagrams: Mutex<VecDeque<Result<Vec<u8>, i32>>>,
    }

    impl Socket for Scripted {
        fn key(&self) -> SocketKey {
            SocketKey::new(7)
        }
        fn readiness(&self) -> Readiness<'_> {
            unreachable!("not polled")
        }
        fn take_error(&self) -> io::Result<Option<io::Error>> {
            Ok(None)
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 40000)))
        }
        fn set(&self, _: SocketOption) -> io::Result<()> {
            Ok(())
        }
        fn set_nonblocking(&self) -> io::Result<()> {
            Ok(())
        }
        fn bind(&self, _: SocketAddr) -> io::Result<()> {
            Ok(())
        }
        fn bind_to_device(&self, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn connect(&self, _: &Remote) -> io::Result<Connect> {
            Ok(Connect::Done)
        }
        fn recv(&self, _: &mut [u8]) -> io::Result<Recv> {
            unreachable!("QUIC receives in batches")
        }
        fn send(&self, _: &[u8]) -> io::Result<Sent> {
            unreachable!("QUIC sends in runs")
        }
        fn send_segments(&self, buf: &[u8], segment: usize) -> io::Result<usize> {
            let act = self.sends.lock().unwrap().pop_front().unwrap_or(Act::Take);
            match act {
                Act::Take => {
                    self.sent.lock().unwrap().push((buf.len(), segment));
                    Ok(buf.len())
                }
                Act::Short(n) => Ok(n),
                Act::Fail(errno) => Err(io::Error::from_raw_os_error(errno)),
                Act::Block => Err(io::ErrorKind::WouldBlock.into()),
            }
        }
        fn recv_batch(
            &self,
            buf: &mut [u8],
            slot: usize,
            out: &mut [Datagram],
        ) -> io::Result<usize> {
            let mut queued = self.datagrams.lock().unwrap();
            match queued.pop_front() {
                None => Err(io::ErrorKind::WouldBlock.into()),
                Some(Err(errno)) => Err(io::Error::from_raw_os_error(errno)),
                Some(Ok(d)) => {
                    buf[..d.len()].copy_from_slice(&d);
                    assert!(d.len() <= slot);
                    out[0] = Datagram {
                        len: d.len(),
                        segment: d.len(),
                        ecn: 0,
                        from: None,
                    };
                    Ok(1)
                }
            }
        }
        fn release(self: Box<Self>) -> SocketKey {
            self.key()
        }
    }

    /// A context that notes what is traced and failed, and the waits the
    /// library asks for.
    struct Cx {
        clock: ManualClock,
        lines: Vec<String>,
        due: Vec<Duration>,
        socket: Scripted,
    }

    impl LayerCx for Cx {
        fn now(&self) -> Instant {
            self.clock.now()
        }
        fn of(&mut self, _: Component, line: std::fmt::Arguments<'_>) {
            self.lines.push(line.to_string());
        }
        fn info(&mut self, line: std::fmt::Arguments<'_>) {
            self.lines.push(format!("* {line}"));
        }
        fn fails(&mut self, kind: ErrorKind, why: std::fmt::Arguments<'_>) -> ErrorKind {
            self.lines.push(format!("! {why}"));
            kind
        }
    }

    impl QuicCx for Cx {
        fn take_room(&mut self) -> Result<Vec<u8>, curl_alloc::OutOfMemory> {
            Ok(vec![0; RECV_ROOM])
        }
        fn give_room(&mut self, _: Vec<u8>) {}
        fn quic_due(&mut self, wait: Duration) {
            self.due.push(wait);
        }
    }

    impl QuicIo for Cx {
        fn socket(&self) -> &dyn Socket {
            &self.socket
        }
    }

    /// A QUIC connection over the fake library running `script`, and a
    /// context for it, with its socket.
    fn quic(script: &Arc<Mutex<Script>>) -> (Quic, Cx) {
        let clock = ManualClock::new().unwrap();
        let remote = SocketAddr::from(([127, 0, 0, 1], 443));
        let setup = ClientSetup {
            local: SocketAddr::from(([127, 0, 0, 1], 40000)),
            remote,
            now: clock.now(),
            handshake_timeout: Duration::from_secs(10),
            max_window: 1 << 20,
            stream_window: 1 << 15,
            max_streams: 100,
        };
        let h3 = FakeHttp3::new(script.clone());
        let conn = h3
            .client(&setup, crate::tls::fake::quic_session().unwrap())
            .unwrap();
        let identity =
            crate::tls::TlsIdentity::of(&Default::default(), Default::default()).unwrap();
        let origin =
            crate::conn::Peer::new(crate::proto::http::HTTPS, b"q.test".to_vec(), 443, None);
        let peer =
            SessionPeer::new(&identity, &origin, None, &"test", crate::conn::Dial::Quic).unwrap();
        let cx = Cx {
            clock: clock.clone(),
            lines: Vec::new(),
            due: Vec::new(),
            socket: Scripted::default(),
        };
        let shared = SharedClock::new(Box::new(clock)).unwrap();
        (Quic::new(conn, peer, remote, shared).unwrap(), cx)
    }

    fn packets(script: &Arc<Mutex<Script>>, sizes: &[usize]) {
        let mut s = script.lock().unwrap();
        for &n in sizes {
            s.out.push_back(vec![0x51; n]);
        }
    }

    /// A packet larger than those before it, which may be a probe of the
    /// path's MTU, sends those before as their run first, then itself
    /// on its own size (`Curl_vquic_send_tail_split`).
    #[test]
    fn a_larger_packet_splits_the_run_before_it() {
        let script = Script::new();
        // A probe may be as large as the path's largest found.
        script.lock().unwrap().max_payload = 1452;
        packets(&script, &[1200, 1200, 1406]);
        let (mut q, mut cx) = quic(&script);
        q.egress(&mut cx).unwrap();
        assert_eq!(
            *cx.socket.sent.lock().unwrap(),
            [(2400, 1200), (1406, 1406)]
        );
        assert_eq!(
            cx.lines,
            [
                "egress, collect and send packets, quantum=12000",
                "vquic_send_tail_split: [2400 gso=1200][1406 gso=1406]",
                "vquic_sendmsg(len=2400, gso=1200, calls=1) -> 0, sent=2400",
                "vquic_sendmsg(len=1406, gso=1406, calls=1) -> 0, sent=1406",
            ]
        );
        assert_eq!(q.wants(), Events::IN);
    }

    /// A run of one size goes in one send, the kernel cutting it; one
    /// smaller packet ends the run, counted, and goes with it.
    #[test]
    fn a_smaller_packet_ends_the_run() {
        let script = Script::new();
        packets(&script, &[1200, 1200, 900, 1200]);
        let (mut q, mut cx) = quic(&script);
        q.egress(&mut cx).unwrap();
        assert_eq!(*cx.socket.sent.lock().unwrap(), [(3300, 1200)]);
        assert_eq!(
            cx.lines[1],
            "egress, send collected 3 packets in 3300 bytes"
        );
        assert_eq!(script.lock().unwrap().sent_at.len(), 1);
        assert_eq!(script.lock().unwrap().out.len(), 1, "the next is for later");
    }

    /// A datagram too large for the path is lost, and counted as sent; a
    /// run the kernel cannot cut goes a datagram at a time, from then on.
    #[test]
    fn too_large_is_lost_and_a_failed_cut_sends_apart() {
        let script = Script::new();
        packets(&script, &[1200, 1200]);
        let (mut q, mut cx) = quic(&script);
        cx.socket
            .sends
            .lock()
            .unwrap()
            .push_back(Act::Fail(TOO_LARGE));
        q.egress(&mut cx).unwrap();
        assert_eq!(
            cx.lines.last().unwrap(),
            "vquic_sendmsg(len=2400, gso=1200, calls=1) -> 0, sent=2400"
        );
        assert!(cx.socket.sent.lock().unwrap().is_empty());

        cx.lines.clear();
        packets(&script, &[1200, 1200]);
        cx.socket
            .sends
            .lock()
            .unwrap()
            .push_back(Act::Fail(IO_FAILED));
        q.egress(&mut cx).unwrap();
        assert_eq!(
            *cx.socket.sent.lock().unwrap(),
            [(1200, 1200), (1200, 1200)]
        );
        assert_eq!(
            cx.lines[2..],
            [
                "* sendmsg() returned -1 (errno 5); disable GSO",
                "vquic_sendmsg(len=1200, gso=1200, calls=1) -> 0, sent=1200",
                "vquic_sendmsg(len=1200, gso=1200, calls=1) -> 0, sent=1200",
                "vquic_sendmsg(len=2400, gso=1200, calls=2) -> 0, sent=2400",
            ]
        );
        // From then on each goes on its own.
        cx.socket.sent.lock().unwrap().clear();
        packets(&script, &[1200, 1200]);
        q.egress(&mut cx).unwrap();
        assert_eq!(
            *cx.socket.sent.lock().unwrap(),
            [(1200, 1200), (1200, 1200)]
        );
    }

    /// A socket that would block keeps the packets, the socket watched
    /// to write and the library called again in a millisecond; they go
    /// first at the next egress. A short send fails it.
    #[test]
    fn a_blocked_send_waits_and_a_short_one_fails() {
        let script = Script::new();
        packets(&script, &[1200, 1200]);
        let (mut q, mut cx) = quic(&script);
        cx.socket.sends.lock().unwrap().push_back(Act::Block);
        q.egress(&mut cx).unwrap();
        assert_eq!(
            cx.lines.last().unwrap(),
            "vquic_sendmsg(len=2400, gso=1200, calls=1) -> 81, sent=0"
        );
        assert_eq!(cx.due, [Duration::from_millis(1)]);
        assert_eq!(q.wants(), Events::IN | Events::OUT);
        q.egress(&mut cx).unwrap();
        assert_eq!(*cx.socket.sent.lock().unwrap(), [(2400, 1200)]);
        assert_eq!(q.wants(), Events::IN);

        packets(&script, &[1200, 1200]);
        cx.socket.sends.lock().unwrap().push_back(Act::Short(1000));
        let r = q.egress(&mut cx);
        assert_eq!(r, Err(ErrorKind::SendError));
        assert!(
            cx.lines
                .contains(&"! sendmsg() sent only 1000/2400 bytes".to_owned())
        );
    }

    /// A refused datagram before the connect is done fails it as a
    /// refused connect; any other error is a receive's.
    #[test]
    fn a_refused_receive_fails_the_connect() {
        let script = Script::new();
        let (mut q, mut cx) = quic(&script);
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused)
            .raw_os_error()
            .unwrap_or(111);
        cx.socket.datagrams.lock().unwrap().push_back(Err(refused));
        let r = q.connect(&mut cx);
        assert_eq!(r, Err(ErrorKind::CouldntConnect));
        assert!(
            cx.lines
                .contains(&"! QUIC: connection to 127.0.0.1 port 443 refused".to_owned()),
            "{:?}",
            cx.lines
        );
        assert!(
            cx.lines
                .contains(&"vquic_recvmmsg(len=0, packets=0, calls=0) -> 7".to_owned())
        );
        assert!(cx.lines.contains(&"connect -> 7, done=0".to_owned()));
    }

    /// A packet the library fails as TLS's fails the connect as the
    /// peer's verification; the failure past saving closes it, its close
    /// sent.
    #[test]
    fn a_crypto_failure_is_the_peers_verification() {
        let script = Script::new();
        script.lock().unwrap().read_fails = Some(-213);
        let (mut q, mut cx) = quic(&script);
        cx.socket
            .datagrams
            .lock()
            .unwrap()
            .push_back(Ok(b"flight".to_vec()));
        let r = q.connect(&mut cx);
        assert_eq!(r, Err(ErrorKind::PeerFailedVerification));
        assert!(
            cx.lines
                .contains(&"ingress, read_pkt -> ERR_FAKE (-213)".to_owned())
        );
        assert_eq!(
            *cx.socket.sent.lock().unwrap(),
            [] as [(usize, usize); 0],
            "not past saving"
        );
        script.lock().unwrap().read_fails = Some(-502);
        cx.socket
            .datagrams
            .lock()
            .unwrap()
            .push_back(Ok(b"flight".to_vec()));
        assert_eq!(q.connect(&mut cx), Err(ErrorKind::RecvError));
        assert_eq!(*cx.socket.sent.lock().unwrap(), [(5, 5)], "its close");
    }

    /// The library's timer is set in whole milliseconds, rounded up; one
    /// due runs, then is set again for when it is next.
    #[test]
    fn the_timer_rounds_up_and_runs_when_due() {
        let script = Script::new();
        script.lock().unwrap().expiry = Some(Duration::from_micros(4500));
        let (mut q, mut cx) = quic(&script);
        assert_eq!(q.start(&mut cx), Ok(false));
        assert_eq!(cx.due, [Duration::from_millis(5)]);
        script.lock().unwrap().expiry = Some(Duration::ZERO);
        assert_eq!(q.connect(&mut cx), Ok(false));
        assert_eq!(script.lock().unwrap().expired, 1);
        // Run, it is never due again.
        assert_eq!(cx.due.len(), 1);
    }

    /// HTTP/3 that could not be set up as the keys came fails the
    /// connect, saying why (`init_ngh3_conn`'s `failf`).
    #[test]
    fn http3_not_set_up_fails_the_connect_saying_why() {
        let script = Script::new();
        script
            .lock()
            .unwrap()
            .on_read
            .push_back(vec![Told::H3Failed(
                "QUIC connection lacks 3 uni streams to run HTTP/3",
            )]);
        let (mut q, mut cx) = quic(&script);
        cx.socket
            .datagrams
            .lock()
            .unwrap()
            .push_back(Ok(b"flight".to_vec()));
        assert_eq!(q.connect(&mut cx), Err(ErrorKind::RecvError));
        assert!(
            cx.lines
                .contains(&"! QUIC connection lacks 3 uni streams to run HTTP/3".to_owned()),
            "{:?}",
            cx.lines
        );
    }

    /// The handshake done and the peer checked, the connect is done; the
    /// limit on transfers comes as the library tells the streams allowed,
    /// each opened counted.
    #[test]
    fn the_handshake_done_and_checked_connects() {
        let script = Script::new();
        script
            .lock()
            .unwrap()
            .on_read
            .push_back(vec![Told::HandshakeDone, Told::MaxBidiStreams(3)]);
        let (mut q, mut cx) = quic(&script);
        assert_eq!(
            q.max_concurrent(0, 7),
            7,
            "the multi's own before the peer's"
        );
        cx.socket
            .datagrams
            .lock()
            .unwrap()
            .push_back(Ok(b"flight".to_vec()));
        assert_eq!(q.connect(&mut cx), Ok(true));
        assert_eq!(
            q.max_concurrent(2, 7),
            5,
            "those on it and the 3 the peer allows"
        );
        // A stream opened is one of the peer's used.
        q.submit(
            &mut cx,
            &[(b":method".as_slice(), b"GET".as_slice())],
            false,
        )
        .unwrap();
        assert_eq!(q.max_concurrent(1, 7), 3);
        assert_eq!(q.first_byte_at(), Some(cx.clock.now()));
        assert_eq!(q.handshake_at(), Some(cx.clock.now()));
        assert!(cx.lines.contains(&"peer verified".to_owned()));
    }

    /// A connection is usable until it is idle past the time the peer
    /// said it closes an idle one by, counted from its last datagram,
    /// and not once it shuts down.
    #[test]
    fn idle_past_the_peer_s_timeout_or_shut_down_is_unusable() {
        let script = Script::new();
        script.lock().unwrap().idle = Some(Duration::from_secs(30));
        let (mut q, mut cx) = quic(&script);
        assert!(q.usable());
        cx.clock.advance(Duration::from_millis(30_000));
        assert!(q.usable(), "at the timeout, not past it");
        cx.clock.advance(Duration::from_millis(1));
        assert!(!q.usable());
        // A datagram read starts the wait again.
        cx.socket
            .datagrams
            .lock()
            .unwrap()
            .push_back(Ok(b"ping".to_vec()));
        assert!(q.read_pending(&mut cx));
        assert!(q.usable());
        q.close(&mut cx);
        assert!(!q.usable(), "shutting down");
    }

    /// What waits on an idle connection is read as its health is checked;
    /// one the library cannot take makes it dead, said as C says it.
    #[test]
    fn input_pending_is_read_as_the_connection_is_checked() {
        let script = Script::new();
        let (mut q, mut cx) = quic(&script);
        cx.socket
            .datagrams
            .lock()
            .unwrap()
            .push_back(Ok(b"frames".to_vec()));
        assert!(q.read_pending(&mut cx));
        assert_eq!(script.lock().unwrap().read.len(), 1);
        assert_eq!(
            cx.lines.last().map(String::as_str),
            Some("is_alive, progress ingress -> 0")
        );
        script.lock().unwrap().read_fails = Some(-502);
        cx.socket
            .datagrams
            .lock()
            .unwrap()
            .push_back(Ok(b"bad".to_vec()));
        assert!(!q.read_pending(&mut cx));
        assert!(
            cx.lines
                .last()
                .is_some_and(|l| l.starts_with("is_alive, progress ingress -> ")
                    && l != "is_alive, progress ingress -> 0"),
            "{:?}",
            cx.lines
        );
    }
}
