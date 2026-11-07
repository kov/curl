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

#[cfg(unix)]
use super::io::IO_FAILED;
use super::io::{BATCH, Datagram, Events, Recv, SLOT, Sent, Socket, TOO_LARGE};

/// The call a run of datagrams goes out with, as C's traces name it
/// (`VQUIC_SEND_METHOD`): `sendmsg` where the system has it, `send` on
/// Windows.
#[cfg(unix)]
const SEND_METHOD: &str = "sendmsg";
#[cfg(windows)]
const SEND_METHOD: &str = "send";

/// The call datagrams come in with, as C's traces name it: a batch with
/// `recvmmsg` where the system has it (Linux), one at a time with
/// `recvmsg` on macOS (`recvmsg_packets`), with `recvfrom` on Windows
/// (`recvfrom_packets`).
#[cfg(target_os = "linux")]
const RECV_METHOD: &str = "recvmmsg";
#[cfg(target_vendor = "apple")]
const RECV_METHOD: &str = "recvmsg";
#[cfg(windows)]
const RECV_METHOD: &str = "recvfrom";

/// Whether an empty receive is traced, as C's `recvmmsg_packets` and
/// `recvfrom_packets` trace it and its `recvmsg_packets` does not.
const TRACES_EAGAIN: bool = !cfg!(target_vendor = "apple");

/// The room one `recvfrom` receives into, C's buffer on the stack.
#[cfg(windows)]
const RECVFROM_ROOM: usize = 64 * 1024;

/// Send `bytes` as datagrams of `segment` bytes in one call: how many
/// bytes went.
#[cfg(unix)]
fn send_datagrams(socket: &dyn Socket, bytes: &[u8], segment: usize) -> io::Result<usize> {
    socket.send_segments(bytes, segment)
}

/// Send `bytes` as one datagram (`swrite`), as C does on Windows, which
/// has no `sendmsg` to cut a run with: how many bytes went.
#[cfg(windows)]
fn send_datagrams(socket: &dyn Socket, bytes: &[u8], _segment: usize) -> io::Result<usize> {
    match socket.send(bytes)? {
        Sent::Bytes(n) => Ok(n.get()),
        Sent::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
    }
}

/// Receive datagrams into slots of `room`, `SLOT` bytes each, at most as
/// many as `out` holds: how many came (on macOS one a call).
#[cfg(unix)]
fn recv_datagrams(socket: &dyn Socket, room: &mut [u8], out: &mut [Datagram]) -> io::Result<usize> {
    socket.recv_batch(room, SLOT, out)
}

/// Receive one datagram into the start of `room` (`recvfrom`), as C does
/// on Windows: 1, or `WouldBlock` if none waits.
#[cfg(windows)]
fn recv_datagrams(socket: &dyn Socket, room: &mut [u8], out: &mut [Datagram]) -> io::Result<usize> {
    let fits = room.len().min(RECVFROM_ROOM);
    match socket.recv_from(&mut room[..fits])? {
        None => Err(io::ErrorKind::WouldBlock.into()),
        Some((len, from)) => {
            out[0] = Datagram {
                len,
                segment: len,
                ecn: 0,
                from: Some(from),
            };
            Ok(1)
        }
    }
}
use super::layer::{
    Below, EarlyData, Failures, ForTransfer, H3Streams, LayerCalls as _, LayerCx, QuicTimer,
    TlsSessions, Trace,
};
use crate::components::Component;
use crate::error::{AGAIN_NUMBER, ErrorKind};
use crate::http3::{
    CloseKind, ConnEvent, Connection, Event, Expiry, Flavour, H3Error, Heard, Layer, QuicError,
    StreamEvent, StreamId, SubmitFailed,
};
use crate::time::{Instant, SharedClock};
use crate::tls::{SessionPeer, TlsCx};
use crate::trace::{Code, Ip};

/// The room the packets to send are collected in (`NW_CHUNK_SIZE`, one
/// chunk).
const SEND_ROOM: usize = 64 * 1024;

/// The most packets quiche's filter sends in one go (`MAX_PKT_BURST`).
const BURST: usize = 10;

/// The room the datagrams a connection on a socket receives are read
/// into, lent by the multi (`Curl_multi_xfer_sockbuf_borrow`).
pub(crate) const RECV_ROOM: usize = BATCH * SLOT;

/// A room of `len` bytes to receive in, zeroed by the allocator, where
/// C's is left unwritten: never filled byte by byte, which in an
/// unoptimised build costs milliseconds at a connection's first look at
/// what it received.
fn new_room(len: usize) -> Result<Vec<u8>, ErrorKind> {
    curl_alloc::try_zeroed(len).map_err(|_| ErrorKind::OutOfMemory)
}

/// The multi's room that connections on a socket receive in
/// (`xfer_sockbuf`): made at the first receive, then lent to one receive
/// at a time and given back. One per multi, whatever its connections:
/// the origin's, a proxy's, or a proxy's under a tunnelled origin's,
/// which receives while the origin's own receive runs, into a room of
/// its own (`Quic::ingress`).
#[derive(Debug, Default)]
pub(crate) enum RecvRoom {
    /// No receive has asked yet.
    #[default]
    Unmade,
    Kept(Vec<u8>),
    /// A receive has it.
    Lent,
}

impl RecvRoom {
    /// The room, lent until [`RecvRoom::give`]. Lending it twice is a
    /// receive inside a receive on the same room, which nothing does: C
    /// refuses it (`attempt to borrow xfer_sockbuf when already
    /// borrowed`), and no input can make one.
    fn take(&mut self) -> Result<Vec<u8>, ErrorKind> {
        match std::mem::replace(self, RecvRoom::Lent) {
            RecvRoom::Kept(room) => Ok(room),
            RecvRoom::Unmade => new_room(RECV_ROOM).inspect_err(|_| *self = RecvRoom::Unmade),
            RecvRoom::Lent => panic!("the multi's receive room is lent to one receive at a time"),
        }
    }

    /// The room lent, given back.
    fn give(&mut self, room: Vec<u8>) {
        assert!(
            matches!(self, RecvRoom::Lent),
            "only a room lent is given back"
        );
        *self = RecvRoom::Kept(room);
    }
}

/// A request stream's first receive window, which its request opens
/// further (`H3_STREAM_WINDOW_SIZE_INITIAL`).
pub(crate) const STREAM_WINDOW_INITIAL: u64 = 32 * 1024;

/// The most packets one look at the socket reads (`progress_ingress`).
const MAX_PACKETS: usize = 1000;

/// The most a datagram through a tunnel is read into
/// (`QUIC_TUNNEL_INBUF_SIZE`): more than any datagram's payload.
const TUNNEL_ROOM: usize = 64 * 1024;

/// The most a packet that closes the connection is
/// (`NGTCP2_MAX_UDP_PAYLOAD_SIZE`).
const CLOSE_ROOM: usize = 1200;

/// The `LayerCx` of a call on a QUIC connection, which says where the
/// connection's datagrams go: the context knows, from the connection's
/// transport or the attempt's kind, and the connection asks it at each
/// send and receive, so that nothing holds the way while the library
/// tells the transfer what it read.
pub(crate) trait QuicIo: LayerCx {
    /// The context, as one over a socket or over layers.
    fn via(&mut self) -> Via<'_>;
}

/// Where a call's datagrams go: the context itself, as the context of a
/// connection on a UDP socket of its own, or of one layered over a
/// tunnel's stream (`qctx->sockfd == CURL_SOCKET_BAD`).
pub(crate) enum Via<'a> {
    Socket(&'a mut dyn SocketIo),
    Layers(&'a mut dyn LayersIo),
}

/// The context of a call on a connection over its own UDP socket.
pub(crate) trait SocketIo: QuicIo {
    /// The socket.
    fn socket(&self) -> &dyn Socket;
}

/// The context of a call on a connection layered over a tunnel, whose
/// datagrams go through the layers below it.
pub(crate) trait LayersIo: QuicIo {
    /// Send `datagram` through the layers below
    /// (`Curl_conn_cf_send(cf->next)`).
    fn send_below(&mut self, datagram: &[u8]) -> Result<Sent, ErrorKind>;

    /// Receive a datagram into `buf` from the layers below
    /// (`Curl_conn_cf_recv(cf->next)`).
    fn recv_below(&mut self, buf: &mut [u8]) -> Result<Recv, ErrorKind>;

    /// Send on what the layers below hold from datagrams before
    /// (`Curl_conn_flush`).
    fn flush_below(&mut self) -> Result<(), ErrorKind>;
}

/// An event of a stream no transfer has, as C's callbacks hear one whose
/// stream has no user data: the QUIC stream's close is traced for the
/// transfer of the call (`cb_stream_close`), and body bytes for nobody
/// fail the read (`cb_h3_recv_data`).
pub(crate) fn unrouted(cx: &mut dyn LayerCx, stream: StreamId, event: &StreamEvent<'_>) -> Heard {
    match *event {
        StreamEvent::QuicClosed { error, answer } => {
            let rv = crate::http3::returned(answer);
            let (id, error) = (stream.0, error.0);
            cx.of(
                Component::Http3,
                format_args!("[{id}] quic close(app_error={error}) -> {rv}"),
            );
            Heard::Fine
        }
        StreamEvent::Data(_) => Heard::Failed,
        _ => Heard::Fine,
    }
}

/// The context of a call on a connection no transfer is stepping, as its
/// health is checked or it says goodbye: every stream is one no transfer
/// has, the room to read into is the one the call lends, and the
/// library's timer is set by no one, as C's calls give it no packet
/// context.
pub(crate) struct Lone<'a> {
    pub(crate) cx: &'a mut dyn LayerCx,
}

impl LayerCx for Lone<'_> {
    fn now(&self) -> Instant {
        self.cx.now()
    }

    fn trace(&mut self) -> Option<&mut dyn Trace> {
        self.cx.trace()
    }

    fn failures(&mut self) -> Option<&mut dyn Failures> {
        self.cx.failures()
    }

    fn transfer(&mut self) -> Option<&mut dyn ForTransfer> {
        self.cx.transfer()
    }

    fn tls_sessions(&mut self) -> Option<&mut dyn TlsSessions> {
        self.cx.tls_sessions()
    }

    fn early_data(&mut self) -> Option<&mut dyn EarlyData> {
        self.cx.early_data()
    }

    /// The library's timer is set by no one: C's calls give it no packet
    /// context.
    fn quic_timer(&mut self) -> Option<&mut dyn QuicTimer> {
        None
    }

    /// Every stream is one no transfer has.
    fn h3_streams(&mut self) -> Option<&mut dyn H3Streams> {
        Some(self)
    }

    fn recv_room(&mut self) -> Option<&mut RecvRoom> {
        self.cx.recv_room()
    }
}

impl H3Streams for Lone<'_> {
    fn heard(&mut self, stream: StreamId, event: StreamEvent<'_>) -> Heard {
        unrouted(&mut *self.cx, stream, &event)
    }
}

/// A call's context on what its datagrams go `on`: the socket an
/// attempt dialed, or a connection's own (`&dyn Socket`); or the layers
/// of a connection's stream, for one layered over a tunnel (`Below`). An
/// attempt's, or a connection's that no transfer is stepping.
pub(crate) struct Over<'a, W> {
    pub(crate) cx: &'a mut dyn LayerCx,
    pub(crate) on: W,
}

impl<W> LayerCx for Over<'_, W> {
    fn now(&self) -> Instant {
        self.cx.now()
    }

    fn trace(&mut self) -> Option<&mut dyn Trace> {
        self.cx.trace()
    }

    fn failures(&mut self) -> Option<&mut dyn Failures> {
        self.cx.failures()
    }

    fn transfer(&mut self) -> Option<&mut dyn ForTransfer> {
        self.cx.transfer()
    }

    fn tls_sessions(&mut self) -> Option<&mut dyn TlsSessions> {
        self.cx.tls_sessions()
    }

    fn early_data(&mut self) -> Option<&mut dyn EarlyData> {
        self.cx.early_data()
    }

    fn quic_timer(&mut self) -> Option<&mut dyn QuicTimer> {
        self.cx.quic_timer()
    }

    fn h3_streams(&mut self) -> Option<&mut dyn H3Streams> {
        self.cx.h3_streams()
    }

    fn recv_room(&mut self) -> Option<&mut RecvRoom> {
        self.cx.recv_room()
    }
}

impl QuicIo for Over<'_, &dyn Socket> {
    fn via(&mut self) -> Via<'_> {
        Via::Socket(self)
    }
}

impl SocketIo for Over<'_, &dyn Socket> {
    fn socket(&self) -> &dyn Socket {
        self.on
    }
}

impl QuicIo for Over<'_, Below<'_>> {
    fn via(&mut self) -> Via<'_> {
        Via::Layers(self)
    }
}

impl LayersIo for Over<'_, Below<'_>> {
    fn send_below(&mut self, datagram: &[u8]) -> Result<Sent, ErrorKind> {
        let sent = self.on.reborrow().send(&mut *self.cx, datagram);
        sent.map_err(|_| self.on.failure().unwrap_or(ErrorKind::SendError))
    }

    fn recv_below(&mut self, buf: &mut [u8]) -> Result<Recv, ErrorKind> {
        let got = self.on.reborrow().recv(&mut *self.cx, buf);
        got.map_err(|_| self.on.failure().unwrap_or(ErrorKind::RecvError))
    }

    fn flush_below(&mut self) -> Result<(), ErrorKind> {
        let flushed = self.on.reborrow().flush(&mut *self.cx);
        flushed
            .map(|_| ())
            .map_err(|_| self.on.failure().unwrap_or(ErrorKind::SendError))
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
    /// The kernel failed to cut a run once, or cannot (Windows): each
    /// datagram goes on its own from then on.
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
    /// The filter C's chain traces it as: `HTTP/3`, or `H3-PROXY` for a
    /// connection to an HTTP/3 proxy.
    component: Component,
    /// Early data is sent: this much of the request went before the
    /// handshake was done (`use_earlydata`, `earlydata_skip`).
    early: Option<usize>,
    /// The failures of the connection's own so far: a read that failed,
    /// or the library's call failing. Each is every stream's on it, not
    /// the stepping transfer's alone: the call that saw it has the other
    /// transfers on the connection run at once (`failures`).
    failures: u32,
}

/// What a session resumed says of the early data a connection may send
/// under it: how much it allows, the protocol it was made for and the
/// transport parameters its connection had, encoded.
#[derive(Debug)]
pub(crate) struct EarlyTicket {
    pub(crate) most: usize,
    pub(crate) alpn: Option<crate::tls::Chosen>,
    pub(crate) params: Vec<u8>,
}

/// A QUIC connection over its UDP socket.
pub(crate) struct Quic {
    conn: Box<dyn Connection>,
    /// Which of C's filters it is spoken as, its library's.
    flavour: Flavour,
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
    /// The room a connection through a tunnel receives each datagram in
    /// (`tunnel_inbuf`): its own, as the multi's may be lent to the
    /// proxy's connection below it; made at its first receive, empty
    /// until then and for a connection on a socket.
    tunnel_room: Vec<u8>,
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
    /// for `peer`, its connect started now on `clock`, traced as
    /// `component`'s and as `flavour`, its library's, says. Where its
    /// datagrams go each call's context says.
    pub(crate) fn new(
        conn: Box<dyn Connection>,
        peer: SessionPeer,
        remote: SocketAddr,
        clock: SharedClock,
        component: Component,
        flavour: Flavour,
    ) -> Result<Quic, curl_alloc::OutOfMemory> {
        let now = clock.now();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(SEND_ROOM)
            .map_err(|_| curl_alloc::OutOfMemory)?;
        Ok(Quic {
            conn,
            flavour,
            peer,
            remote,
            out: Out {
                bytes,
                sent: 0,
                gso: 0,
                split: None,
                // Only Linux cuts a run into datagrams (`UDP_SEGMENT`).
                no_gso: cfg!(not(target_os = "linux")),
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
                component,
                early: None,
                failures: 0,
            },
            clock,
            tunnel_room: Vec::new(),
        })
    }

    /// When the first datagram came, the time a QUIC connection is
    /// connected at (`cf_socket_cntrl`'s for QUIC).
    /// Which of C's filters it is spoken as.
    pub(crate) fn flavour(&self) -> Flavour {
        self.flavour
    }

    /// The filter C's chain traces it as.
    pub(crate) fn component(&self) -> Component {
        self.state.component
    }

    pub(crate) fn first_byte_at(&self) -> Option<Instant> {
        self.state.first_byte_at
    }

    /// How long after its connect started the first datagram came, once
    /// one has (`CF_QUERY_CONNECT_REPLY_MS`).
    pub(crate) fn reply_ms(&self) -> Option<i64> {
        let at = self.state.first_byte_at?;
        Some(at.ms_since(self.state.started))
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
        // Sending early data, it counts as connected, and its first
        // packets go with the request's (`cf->connected` set by
        // `cf_ngtcp2_on_session_reuse`).
        if self.state.early.is_some() {
            self.state.connected = true;
            return self.connect_ended(cx, Ok(true));
        }
        let sent = self.egress(cx);
        if self.flavour == Flavour::Quiche && sent.is_ok() {
            cx.of(
                self.state.component,
                format_args!("Sent QUIC client Initial, ALPN: h3"),
            );
        }
        self.connect_ended(cx, sent.map(|()| false))
    }

    /// The session resumed allows early data under `ticket`, which is
    /// sent if it was made for HTTP/3 and kept with transport parameters
    /// the connection takes (`cf_ngtcp2_on_session_reuse`): said as C
    /// says it, and the session told whether it goes, once that is
    /// known, as C's TLS backends are by `do_early_data`. A failure to
    /// set up HTTP/3 for it fails the connect.
    pub(crate) fn early_data(
        &mut self,
        cx: &mut dyn LayerCx,
        ticket: &EarlyTicket,
    ) -> Result<(), ErrorKind> {
        let early = self.decide_early(cx, ticket)?;
        let component = self.state.component;
        let Quic { conn, peer, .. } = self;
        conn.early_data_decided(&mut TlsCx::new(cx, component, peer), early)
    }

    /// Whether early data goes under `ticket`: the connection set up for
    /// it if so. It goes too where the TLS library then refuses to send
    /// it, which C's session is told after `do_early_data`.
    fn decide_early(
        &mut self,
        cx: &mut dyn LayerCx,
        ticket: &EarlyTicket,
    ) -> Result<bool, ErrorKind> {
        let h3 = self.state.component;
        if ticket.most == 0 {
            cx.of(h3, format_args!("SSL session does not allow earlydata"));
            return Ok(false);
        }
        if ticket.alpn != Some(crate::tls::Chosen::H3) {
            cx.of(
                h3,
                format_args!("SSL session from different ALPN, no early data"),
            );
            return Ok(false);
        }
        if ticket.params.is_empty() {
            cx.of(
                h3,
                format_args!("no 0RTT transport parameters, no early data"),
            );
            return Ok(false);
        }
        if let Err(why) = self.conn.set_early_params(&ticket.params) {
            cx.of(
                h3,
                format_args!("no early data, failed to set 0RTT transport parameters: {why}"),
            );
            return Ok(false);
        }
        let most = ticket.most;
        cx.info(format_args!(
            "SSL session allows {most} bytes of early data, reusing ALPN 'h3'"
        ));
        match self.conn.start_early() {
            Ok(crate::http3::EarlyStart::Started) => {
                self.state.early = Some(0);
                Ok(true)
            }
            Ok(crate::http3::EarlyStart::Refused) => {
                cx.of(h3, format_args!("OpenSSL refused to use early data"));
                Ok(true)
            }
            Err(failed) => Err(cx.fails(failed.kind(), format_args!("{failed}"))),
        }
    }

    /// `n` bytes of the request were taken: early data if the handshake
    /// is not yet done (`earlydata_skip`).
    pub(crate) fn sent(&mut self, n: usize) {
        if let Some(early) = self.state.early.as_mut()
            && !self.conn.handshake_done()
        {
            *early += n;
        }
    }

    /// A later connect call: what came read, what is due sent, and done
    /// once the handshake is and the peer checked
    /// (`Curl_cf_ngtcp2_cmn_connect`).
    pub(crate) fn connect(&mut self, cx: &mut dyn QuicIo) -> Result<bool, ErrorKind> {
        // Connected already, for early data (`cf->connected`).
        if self.state.connected {
            return Ok(true);
        }
        let step = (|| {
            self.ingress(cx)?;
            self.egress(cx)?;
            if self.conn.handshake_done() {
                self.state.verified?;
                cx.of(self.state.component, format_args!("peer verified"));
                self.state.connected = true;
                return Ok(true);
            }
            // A server shutting down may close at once: quiche's filter
            // says so as a weird reply, the next address tried
            // (`cf_quiche_connect`).
            if self.flavour == Flavour::Quiche && self.conn.draining() {
                return Err(ErrorKind::WeirdServerReply);
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
        if self.flavour == Flavour::Ngtcp2
            && matches!(step, Err(ErrorKind::RecvError | ErrorKind::SendError))
            && self.conn.draining()
        {
            step = Err(ErrorKind::CouldntConnect);
            if let Some(closed) = self.conn.closed_with() {
                let h3 = self.state.component;
                let (kind, code) = (closed.kind, closed.code);
                cx.of(h3, format_args!("connect error, type={kind}, code={code}"));
                if kind == CloseKind::VersionNegotiation {
                    cx.of(h3, format_args!("error in version negotiation"));
                } else if let Some(alert) = closed.tls_alert() {
                    cx.of(h3, format_args!("crypto error, tls alert={alert}"));
                } else if closed.refused() {
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
            let quic = match self.flavour {
                Flavour::Ngtcp2 => "QUIC ",
                Flavour::Quiche => "",
            };
            cx.info(format_args!(
                "{quic}connect to {ip} port {port} failed: {why}"
            ));
        }
        if step.is_ok()
            && let Err(kind) = self.set_expiry(cx)
        {
            step = Err(kind);
        }
        let done = matches!(step, Ok(true));
        if self.flavour == Flavour::Ngtcp2 && (step.is_err() || done) {
            let code = Code(step.map(|_| ()));
            let done = u8::from(done);
            cx.of(
                self.state.component,
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
                let flavour = self.flavour;
                let Quic {
                    conn, peer, state, ..
                } = self;
                let mut tcx = TlsCx::new(cx, state.component, peer);
                conn.handle_expiry(&mut tcx, now, &mut |tcx, e| state.heard(tcx, flavour, e))
            };
            if let Err(error) = ran {
                let why = error.text;
                match self.flavour {
                    Flavour::Ngtcp2 => cx.fails(
                        ErrorKind::SendError,
                        format_args!("ngtcp2_conn_handle_expiry returned error: {why}"),
                    ),
                    // Closed by its timer: by the idle timeout or the
                    // server (`cf_flush_egress`).
                    Flavour::Quiche => cx.fails(ErrorKind::SendError, format_args!("{why}")),
                };
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
        // Closed, by its idle timeout or otherwise (`cf_quiche_conn_is_alive`).
        if self.flavour == Flavour::Quiche {
            return self.conn.closed_with().is_none();
        }
        match self.conn.peer_idle_timeout() {
            Some(max) if max > Duration::ZERO => {
                // In milliseconds, as C counts them.
                let idle = self.clock.now().ms_since(self.state.last_io);
                idle <= 0 || idle <= crate::time::millis(max)
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
            self.state.component,
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

    /// The peer closed it (`quiche_conn_is_draining`).
    pub(crate) fn draining(&self) -> bool {
        self.conn.draining()
    }

    /// Open a stream for a request of `fields` for `url`, with a body if
    /// `body`, counted among those the peer allows (`h3_stream_open`):
    /// its id, or none if the peer's flow control holds it back for now.
    /// A request the library refused cancels its stream; quiche's opens
    /// none, and its filter names the request by its URL.
    pub(crate) fn submit(
        &mut self,
        cx: &mut dyn QuicIo,
        fields: &[(&[u8], &[u8])],
        body: bool,
        url: &[u8],
    ) -> Result<Option<StreamId>, ErrorKind> {
        let submitted = self.conn.submit_request(fields, body);
        if self.flavour == Flavour::Quiche {
            let rv = match &submitted {
                Ok(stream) => stream.0,
                Err(SubmitFailed::Blocked { error } | SubmitFailed::Refused { error, .. }) => {
                    i64::from(error.code)
                }
                Err(_) => -1,
            };
            cx.of(
                self.state.component,
                format_args!("quiche_send_request() -> {rv}"),
            );
        }
        match submitted {
            Ok(stream) => {
                self.state.used_bidi += 1;
                Ok(Some(stream))
            }
            // quiche says this as the connection's window runs out, which
            // happens often and passes (`h3_open_stream`).
            Err(SubmitFailed::Blocked { .. }) => Ok(None),
            // quiche opens no stream for a request it refuses.
            Err(SubmitFailed::Refused { error, .. }) if self.flavour == Flavour::Quiche => {
                let (url, rv) = (curl_alloc::Lossy(url), error.code);
                cx.of(
                    self.state.component,
                    format_args!("send_request({url}) -> {rv}"),
                );
                Err(ErrorKind::SendError)
            }
            Err(SubmitFailed::OutOfMemory) => Err(ErrorKind::OutOfMemory),
            Err(SubmitFailed::NoStream) => Err(cx.fails(
                ErrorKind::SendError,
                format_args!("cannot open bidi streams"),
            )),
            Err(SubmitFailed::Closing { stream }) => {
                let id = stream.0;
                cx.of(
                    self.state.component,
                    format_args!("h3sid[{id}] failed to send, connection is closing"),
                );
                self.refused(cx, stream);
                Err(ErrorKind::SendError)
            }
            Err(SubmitFailed::Refused { stream, error }) => {
                let (id, code, text) = (stream.0, error.code, error.text);
                cx.of(
                    self.state.component,
                    format_args!("h3sid[{id}] failed to send -> {code} ({text})"),
                );
                self.refused(cx, stream);
                Err(ErrorKind::SendError)
            }
        }
    }

    /// The library refused a request on `stream`: the stream, counted
    /// among those the peer allows, is cancelled.
    fn refused(&mut self, cx: &mut dyn QuicIo, stream: StreamId) {
        self.state.used_bidi += 1;
        self.cancel(cx, stream);
    }

    /// Stop `stream` both ways as cancelled, nothing more heard of it,
    /// and send what that says (`Curl_cf_ngtcp2_h3_stream_close`).
    pub(crate) fn cancel(&mut self, cx: &mut dyn QuicIo, stream: StreamId) {
        // quiche's filter shuts a stream with no error
        // (`cf_quiche_stream_close`).
        let (error, said) = match self.flavour {
            Flavour::Ngtcp2 => (H3Error::REQUEST_CANCELLED, "cancel stream"),
            Flavour::Quiche => (H3Error::NO_ERROR, "stream close, flush egress"),
        };
        self.conn.cancel(stream, error);
        if let Err(kind) = self.egress(cx) {
            let (id, code) = (stream.0, kind.number());
            cx.of(
                self.state.component,
                format_args!("[{id}] {said} -> {code}"),
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
        // quiche's filter keeps none alive.
        if self.flavour == Flavour::Quiche {
            return;
        }
        let h3 = self.state.component;
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
        self.state.failures = self.state.failures.wrapping_add(1);
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
        if self.flavour == Flavour::Quiche {
            return self.close_quiche(cx);
        }
        let h3 = self.state.component;
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

    /// quiche's close (`cf_quiche_shutdown`): the library told to close,
    /// the packets that wait sent, and done once none does. What it sends
    /// for the close goes as its connection next sends, which nothing
    /// asks of a connection already sent off: C's filter frees it so.
    fn close_quiche(&mut self, cx: &mut dyn QuicIo) -> bool {
        let h3 = self.state.component;
        if !self.state.shutdown_started {
            self.state.shutdown_started = true;
            if let Err(e) = self.conn.write_close(self.clock.now(), &mut []) {
                let rv = e.code;
                cx.of(
                    h3,
                    format_args!("error {rv} adding shutdown packet, aborting shutdown"),
                );
                return true;
            }
        }
        if !self.out.is_empty() {
            cx.of(h3, format_args!("shutdown, flushing sendbuf"));
            if self.egress(cx).is_err() {
                return true;
            }
        }
        if self.out.is_empty() {
            cx.of(h3, format_args!("shutdown completely sent off, done"));
            return true;
        }
        cx.of(h3, format_args!("shutdown sending blocked"));
        false
    }

    /// Send what waits, then collect what the library has to send and
    /// send it, in runs of packets of one size (`progress_egress`).
    pub(crate) fn egress(&mut self, cx: &mut dyn QuicIo) -> Result<(), ErrorKind> {
        // What the tunnel's layers hold goes first, as C flushes the
        // filters before it drives them (`Curl_conn_needs_flush`).
        if let Via::Layers(below) = cx.via() {
            below.flush_below()?;
        }
        match self.flush(cx) {
            Ok(()) => {}
            Err(Stop::Again) => {
                cx.quic_due(Duration::from_millis(1));
                return Ok(());
            }
            Err(Stop::Failed(kind)) => return Err(kind),
        }
        match self.flavour {
            Flavour::Ngtcp2 => self.egress_run(cx)?,
            Flavour::Quiche => self.egress_bursts(cx)?,
        }
        let now = self.clock.now();
        self.state.now = now;
        let done = {
            let flavour = self.flavour;
            let Quic {
                conn, peer, state, ..
            } = self;
            let mut tcx = TlsCx::new(cx, state.component, peer);
            conn.egress_done(&mut tcx, now, &mut |tcx, e| state.heard(tcx, flavour, e))
        };
        done.map_err(|error| {
            self.failed(cx, error);
            ErrorKind::SendError
        })
    }

    /// Collect a run of packets and send it, a quantum's worth at most
    /// (`cf_progress_egress`).
    ///
    /// A packet larger than those before may be the library finding the
    /// path's MTU, which the network may refuse: what is collected before
    /// it goes first, so that what follows is not refused with it.
    fn egress_run(&mut self, cx: &mut dyn QuicIo) -> Result<(), ErrorKind> {
        let ngtcp2 = self.flavour == Flavour::Ngtcp2;
        let max = self.conn.max_payload();
        let path_max = self.conn.path_max_payload();
        let quantum = self.conn.send_quantum();
        if ngtcp2 {
            cx.of(
                self.state.component,
                format_args!("egress, collect and send packets, quantum={quantum}"),
            );
        }
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
            if ngtcp2 {
                cx.of(
                    self.state.component,
                    format_args!("egress, send collected {packets} packets in {len} bytes"),
                );
            }
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

    /// Send what the library has, until it has no more: in bursts of up
    /// to ten packets, each burst ended early by a packet shorter than
    /// the largest the library sends, which is every burst's segment size
    /// (quiche's `cf_flush_egress`).
    fn egress_bursts(&mut self, cx: &mut dyn QuicIo) -> Result<(), ErrorKind> {
        let max = self.conn.max_payload();
        let mut packets = 0;
        loop {
            let collected = self.collect(cx, max)?;
            if let Some(n) = collected {
                packets += 1;
                if n == max && packets < BURST {
                    continue;
                }
            }
            if !self.out.is_empty() {
                self.out.gso = max;
                match self.flush(cx) {
                    Ok(()) => {}
                    Err(Stop::Again) => {
                        cx.quic_due(Duration::from_millis(1));
                        return Ok(());
                    }
                    Err(Stop::Failed(kind)) => return Err(kind),
                }
            }
            if collected.is_none() {
                return Ok(());
            }
            packets = 0;
        }
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
            let flavour = self.flavour;
            let Quic {
                conn,
                peer,
                state,
                out,
                ..
            } = self;
            let mut tcx = TlsCx::new(cx, state.component, peer);
            conn.write_packet(&mut tcx, now, &mut out.bytes[at..], &mut |tcx, e| {
                state.heard(tcx, flavour, e)
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
                let (call, why, code) = (error.call, error.text, error.code);
                match self.flavour {
                    Flavour::Ngtcp2 => cx.fails(
                        ErrorKind::SendError,
                        format_args!("{call} returned error: {why}"),
                    ),
                    Flavour::Quiche => {
                        cx.fails(ErrorKind::SendError, format_args!("{call} returned {code}"))
                    }
                };
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
            self.state.component,
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
        match cx.via() {
            Via::Layers(below) => self.send_through(below, len, gso),
            Via::Socket(on) if self.out.no_gso && len > gso => self.send_apart(on, len, gso),
            Via::Socket(on) => self.send_run(on, len, gso),
        }
    }

    /// The first `len` bytes of what waits sent through the layers below,
    /// a datagram of `gso` bytes at a time if they hold more than one,
    /// each whole or not at all (`Curl_vquic_flush`'s tunnelled branch,
    /// `send_packet_no_gso_cf`).
    fn send_through(
        &mut self,
        cx: &mut dyn LayersIo,
        len: usize,
        gso: usize,
    ) -> (usize, Result<(), Stop>) {
        let at = self.out.sent;
        if gso == 0 || len <= gso {
            return match cx.send_below(&self.out.bytes[at..at + len]) {
                Ok(Sent::Bytes(n)) => (n.get(), Ok(())),
                Ok(Sent::WouldBlock) => (0, Err(Stop::Again)),
                Err(kind) => (0, Err(Stop::Failed(kind))),
            };
        }
        let (mut sent, mut calls) = (0, 0);
        let r = loop {
            if sent == len {
                break Ok(());
            }
            let one = gso.min(len - sent);
            let datagram = &self.out.bytes[at + sent..at + sent + one];
            let r = cx.send_below(datagram);
            calls += 1;
            match r {
                Ok(Sent::Bytes(n)) if n.get() == one => sent += one,
                // Only a whole datagram is sent.
                Ok(Sent::Bytes(_)) => break Err(Stop::Failed(ErrorKind::SendError)),
                Ok(Sent::WouldBlock) => break Err(Stop::Again),
                Err(kind) => break Err(Stop::Failed(kind)),
            }
        };
        let code = number(r);
        cx.of(
            self.state.component,
            format_args!(
                "vquic_cf_send(len={len}, gso={gso}, calls={calls}) -> {code}, sent={sent}"
            ),
        );
        (sent, r)
    }

    /// One send of `len` bytes, cut by the kernel into datagrams of `gso`
    /// bytes (`do_sendmsg`); where it cannot cut (not Linux), one
    /// datagram.
    fn send_run(
        &mut self,
        cx: &mut dyn SocketIo,
        len: usize,
        gso: usize,
    ) -> (usize, Result<(), Stop>) {
        let at = self.out.sent;
        let bytes = &self.out.bytes[at..at + len];
        // No size known yet is no cutting: one datagram, as the kernel
        // takes a segment size of 0.
        let segment = if gso == 0 { len } else { gso };
        let (sent, r) = match send_datagrams(cx.socket(), bytes, segment) {
            Ok(n) if n == len => (n, Ok(())),
            // C checks a short send only of `sendmsg`'s.
            #[cfg(windows)]
            Ok(n) => (n, Ok(())),
            #[cfg(unix)]
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
            #[cfg(unix)]
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
                    format_args!("{SEND_METHOD}() returned -1 (errno {errno})"),
                );
                (0, Err(Stop::Failed(ErrorKind::SendError)))
            }
        };
        let code = number(r);
        cx.of(
            self.state.component,
            format_args!(
                "vquic_{SEND_METHOD}(len={len}, gso={gso}, calls=1) -> {code}, sent={sent}"
            ),
        );
        (sent, r)
    }

    /// `len` bytes sent a datagram of `gso` bytes at a time
    /// (`send_packet_no_gso`).
    fn send_apart(
        &mut self,
        cx: &mut dyn SocketIo,
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
            self.state.component,
            format_args!(
                "vquic_{SEND_METHOD}(len={len}, gso={gso}, calls={calls}) -> {code}, sent={sent}"
            ),
        );
        (sent, r)
    }

    /// Read what the socket has, in batches, and hand each packet to the
    /// library (`Curl_cf_ngtcp2_progress_ingress`).
    pub(crate) fn ingress(&mut self, cx: &mut dyn QuicIo) -> Result<(), ErrorKind> {
        {
            let component = self.state.component;
            let Quic { conn, peer, .. } = self;
            conn.before_recv(&mut TlsCx::new(cx, component, peer))?;
        }
        let mut read = match cx.via() {
            Via::Layers(below) => self.ingress_through(below),
            Via::Socket(on) => self.ingress_socket(on),
        };
        if read.is_ok() {
            read = self.ingress_done(cx);
        }
        if read.is_err() {
            self.state.failures = self.state.failures.wrapping_add(1);
        }
        read
    }

    /// What the library read told, once the call's datagrams were all
    /// read; its failure the connection's, as a packet's would be.
    fn ingress_done(&mut self, cx: &mut dyn QuicIo) -> Result<(), ErrorKind> {
        let done = {
            let flavour = self.flavour;
            let Quic {
                conn, peer, state, ..
            } = self;
            let mut tcx = TlsCx::new(cx, state.component, peer);
            conn.ingress_done(&mut tcx, &mut |tcx, e| state.heard(tcx, flavour, e))
        };
        done.map_err(|error| {
            self.failed(cx, error);
            match error.layer {
                Layer::Http3 => ErrorKind::Http3,
                _ => ErrorKind::RecvError,
            }
        })
    }

    /// The count of its failures so far, which a call compares before and
    /// after to know whether one came under it.
    pub(crate) fn failures(&self) -> u32 {
        self.state.failures
    }

    /// What the layers below have, read into the connection's own room
    /// (`Curl_cf_ngtcp2_progress_ingress`'s tunnelled branch).
    fn ingress_through(&mut self, cx: &mut dyn LayersIo) -> Result<(), ErrorKind> {
        if self.flavour == Flavour::Ngtcp2 {
            cx.of(
                self.state.component,
                format_args!("progress_ingress(sub-filters)"),
            );
        }
        // At least C's 64 KiB, and as large as the path's largest
        // datagram, grown as that is (`QUIC_TUNNEL_INBUF_SIZE`).
        let want = TUNNEL_ROOM.max(self.conn.path_max_payload());
        if self.tunnel_room.len() < want {
            self.tunnel_room = Vec::new();
            self.tunnel_room = new_room(want)?;
        }
        let mut room = std::mem::take(&mut self.tunnel_room);
        let r = self.recv_through(cx, &mut room);
        self.tunnel_room = room;
        r
    }

    /// What the socket has, read into the room the call lends or one
    /// made for it.
    fn ingress_socket(&mut self, cx: &mut dyn SocketIo) -> Result<(), ErrorKind> {
        if self.flavour == Flavour::Ngtcp2 {
            cx.of(
                self.state.component,
                format_args!("progress_ingress(socket)"),
            );
        }
        // The multi's room if the call has one to lend, else one made for
        // the call, as C's `Curl_multi_xfer_sockbuf_borrow` mallocs one
        // for a call with no multi.
        let lent = match cx.recv_room() {
            Some(lender) => Some(lender.take()?),
            None => None,
        };
        let borrowed = lent.is_some();
        let mut room = match lent {
            Some(room) => room,
            None => new_room(RECV_ROOM)?,
        };
        let r = self.recv_packets(cx, &mut room);
        if borrowed {
            cx.recv_room()
                .expect("the context that lent the room takes it back")
                .give(room);
        }
        r
    }

    /// What the layers below have, a datagram at a time, at most
    /// `MAX_PACKETS` of them, read into `buf` and handed to the library
    /// (`Curl_cf_ngtcp2_progress_ingress`'s tunnelled branch).
    fn recv_through(&mut self, cx: &mut dyn LayersIo, buf: &mut [u8]) -> Result<(), ErrorKind> {
        for _ in 0..MAX_PACKETS {
            let n = match cx.recv_below(buf) {
                Ok(Recv::Data(n)) => n.get(),
                // Nothing more now, or the tunnel closed.
                Ok(Recv::WouldBlock | Recv::Eof) => return Ok(()),
                Err(kind) => {
                    let code = kind.number();
                    cx.of(
                        self.state.component,
                        format_args!("ingress, recv from tunnel failed: {code}"),
                    );
                    return Err(kind);
                }
            };
            let d = Datagram {
                len: n,
                segment: n,
                ecn: 0,
                from: None,
            };
            self.read_datagram(cx, &d, &buf[..n])?;
            let now = self.clock.now();
            self.state.first_byte_at.get_or_insert(now);
            self.state.last_io = now;
        }
        Ok(())
    }

    /// What the socket has, at most `MAX_PACKETS` packets of it, read
    /// into `room` and handed to the library (`recvmmsg_packets`).
    fn recv_packets(&mut self, cx: &mut dyn SocketIo, room: &mut [u8]) -> Result<(), ErrorKind> {
        let mut got = [Datagram::default(); BATCH];
        let (mut total, mut packets, mut calls) = (0usize, 0usize, 0usize);
        let mut first = None;
        let r = loop {
            if packets >= MAX_PACKETS {
                break Ok(());
            }
            let n = BATCH.min(MAX_PACKETS - packets);
            let count = match recv_datagrams(cx.socket(), room, &mut got[..n]) {
                Ok(count) => count,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if TRACES_EAGAIN {
                        cx.of(
                            self.state.component,
                            format_args!("ingress, {RECV_METHOD} -> EAGAIN"),
                        );
                    }
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
                    let errno = crate::text::Text::<80>::clipped(format_args!(
                        "QUIC: {RECV_METHOD}() unexpectedly returned -1 (errno={errno}; "
                    ))
                    .0;
                    let why = curl_os::error::ErrorText::of(&e);
                    break Err(
                        cx.fails_with(ErrorKind::RecvError, &[errno.bytes(), why.as_bytes(), b")"])
                    );
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
                self.state.component,
                format_args!(
                    "vquic_{RECV_METHOD}(len={total}, packets={packets}, calls={calls}) -> {code}"
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
        if d.ecn != 0 && self.flavour == Flavour::Ngtcp2 {
            let (len, gso, ecn) = (d.len, d.segment, d.ecn);
            cx.of(
                self.state.component,
                format_args!("vquic_recv(len={len}, gso={gso}, ecn={ecn:x})"),
            );
        }
        let from = d.from.unwrap_or(self.remote);
        let now = self.clock.now();
        self.state.now = now;
        // Its packets in one call: what the libraries' callbacks reach is
        // set up once for them all.
        let read = {
            let flavour = self.flavour;
            let Quic {
                conn, peer, state, ..
            } = self;
            let mut tcx = TlsCx::new(cx, state.component, peer);
            let packets = bytes.chunks(d.segment);
            conn.read_packets(&mut tcx, now, from, d.ecn, packets, &mut |tcx, e| {
                state.heard(tcx, flavour, e)
            })
        };
        if let Err(error) = read {
            let (text, code) = (error.text, error.code);
            if self.flavour == Flavour::Ngtcp2 {
                cx.of(
                    self.state.component,
                    format_args!("ingress, read_pkt -> {text} ({code})"),
                );
            }
            self.failed(cx, error);
            // A failed TLS, which an unverified peer often is.
            return Err(if error.layer == Layer::Crypto {
                ErrorKind::PeerFailedVerification
            } else {
                ErrorKind::RecvError
            });
        }
        Ok(())
    }
}

impl State {
    /// The library told `event`: the connection's own heard here, a
    /// stream's handed to the transfer the call is made for.
    fn heard(&mut self, cx: &mut TlsCx<'_>, flavour: Flavour, event: Event<'_>) -> Heard {
        let event = match event {
            Event::Connection(event) => event,
            Event::Stream(stream, event) => return cx.h3_event(stream, event),
        };
        match event {
            ConnEvent::HandshakeDone {
                checked,
                max_udp_payload,
                initial_max_data,
                early_data,
            } => {
                let now = self.now;
                self.handshake_at = Some(now);
                self.verified = checked;
                let ms = now.ms_since(self.started);
                match flavour {
                    Flavour::Ngtcp2 if checked.is_ok() => cx.trace(format_args!(
                        "handshake complete after {ms}ms, remote transport[max_udp_payload={max_udp_payload}, initial_max_data={initial_max_data}]"
                    )),
                    // quiche's says it before the peer is checked
                    // (`cf_quiche_connect`).
                    Flavour::Ngtcp2 | Flavour::Quiche => {}
                }
                // What of the early data the peer took is reported, the
                // handshake's time the connection's as it truly connected;
                // a proxy's is not the transfer's (`CF_TYPE_PROXY`).
                if let (Some(sent), Some(accepted)) = (self.early, early_data) {
                    let did = if accepted { "" } else { " not" };
                    cx.trace(format_args!(
                        "server did{did} accept {sent} bytes of early data"
                    ));
                    let sent = i64::try_from(sent).unwrap_or(i64::MAX);
                    let sent = if accepted { sent } else { -sent };
                    if self.component == Component::H3Proxy {
                        cx.proxy_early_done(sent);
                    } else {
                        cx.early_done(sent);
                    }
                }
                Heard::Fine
            }
            // The call fails for it; C says why as it fails it
            // (`init_ngh3_conn`).
            ConnEvent::H3Failed(failed) => {
                cx.fail(failed.kind(), format_args!("{failed}"));
                Heard::Failed
            }
            ConnEvent::MaxBidiStreams(n) => {
                self.max_bidi = n;
                let used = self.used_bidi;
                if flavour == Flavour::Ngtcp2 {
                    cx.trace(format_args!("max bidi streams now {n}, used {used}"));
                }
                Heard::Fine
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::disallowed_macros)]
pub(crate) mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::conn::io::{Connect, Readiness, Recv, Remote, Sent, SocketKey, SocketOption};
    use crate::http3::fake::{FakeHttp3, Script, Told};
    use crate::http3::{ClientSetup, Http3};
    use crate::time::{Clock, ManualClock};

    /// What a scripted socket does with a call.
    #[derive(Debug)]
    pub(crate) enum Act {
        Take,
        /// Only `sendmsg`'s short send is checked.
        #[cfg(unix)]
        Short(usize),
        Fail(i32),
        Block,
    }

    /// A UDP socket whose sends do as scripted, taking all once the
    /// script is used, and whose receives give what is queued.
    #[derive(Debug, Default)]
    pub(crate) struct Scripted {
        pub(crate) sends: Mutex<VecDeque<Act>>,
        pub(crate) sent: Mutex<Vec<(usize, usize)>>,
        pub(crate) datagrams: Mutex<VecDeque<Result<Vec<u8>, i32>>>,
        /// The size of the packets the kernel joined each datagram of
        /// (GRO), if it did.
        #[cfg(unix)]
        pub(crate) segment: Mutex<Option<usize>>,
    }

    impl Scripted {
        /// A send of `buf` as datagrams of `segment` bytes, as scripted.
        fn take_send(&self, buf: &[u8], segment: usize) -> io::Result<usize> {
            let act = self.sends.lock().unwrap().pop_front().unwrap_or(Act::Take);
            match act {
                Act::Take => {
                    self.sent.lock().unwrap().push((buf.len(), segment));
                    Ok(buf.len())
                }
                #[cfg(unix)]
                Act::Short(n) => Ok(n),
                Act::Fail(errno) => Err(io::Error::from_raw_os_error(errno)),
                Act::Block => Err(io::ErrorKind::WouldBlock.into()),
            }
        }

        /// The next datagram queued, into `buf`: its length.
        fn take_datagram(&self, buf: &mut [u8]) -> io::Result<usize> {
            match self.datagrams.lock().unwrap().pop_front() {
                None => Err(io::ErrorKind::WouldBlock.into()),
                Some(Err(errno)) => Err(io::Error::from_raw_os_error(errno)),
                Some(Ok(d)) => {
                    buf[..d.len()].copy_from_slice(&d);
                    Ok(d.len())
                }
            }
        }
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
        #[cfg(target_os = "linux")]
        fn bind_to_device(&self, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn connect(&self, _: &Remote) -> io::Result<Connect> {
            Ok(Connect::Done)
        }
        fn recv(&self, _: &mut [u8]) -> io::Result<Recv> {
            unreachable!("QUIC receives in batches, or with its sender")
        }
        #[cfg(unix)]
        fn send(&self, _: &[u8]) -> io::Result<Sent> {
            unreachable!("QUIC sends in runs")
        }
        /// On Windows each datagram is a send of its own.
        #[cfg(windows)]
        fn send(&self, buf: &[u8]) -> io::Result<Sent> {
            match self.take_send(buf, buf.len()) {
                Ok(n) => Ok(Sent::Bytes(std::num::NonZeroUsize::new(n).unwrap())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Sent::WouldBlock),
                Err(e) => Err(e),
            }
        }
        /// On Windows each datagram is received on its own, with its
        /// sender.
        #[cfg(windows)]
        fn recv_from(&self, buf: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
            match self.take_datagram(buf) {
                Ok(n) => Ok(Some((n, SocketAddr::from(([127, 0, 0, 1], 443))))),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(e),
            }
        }
        #[cfg(unix)]
        fn send_segments(&self, buf: &[u8], segment: usize) -> io::Result<usize> {
            self.take_send(buf, segment)
        }
        #[cfg(unix)]
        fn recv_batch(
            &self,
            buf: &mut [u8],
            slot: usize,
            out: &mut [Datagram],
        ) -> io::Result<usize> {
            let len = self.take_datagram(buf)?;
            assert!(len <= slot);
            out[0] = Datagram {
                len,
                segment: self.segment.lock().unwrap().unwrap_or(len),
                ecn: 0,
                from: None,
            };
            Ok(1)
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
        /// The layers below, in place of the socket, if set.
        below: Option<Layers>,
        /// The multi's room it lends.
        room: RecvRoom,
    }

    /// Layers below a connection with no socket, a tunnel's: its sends
    /// do as scripted, taking all once the script is used, and its
    /// receives give what is queued.
    #[derive(Default)]
    struct Layers {
        sends: VecDeque<Result<Sent, ErrorKind>>,
        sent: Vec<Vec<u8>>,
        datagrams: VecDeque<Result<Vec<u8>, ErrorKind>>,
        /// The room each receive was given.
        rooms: Vec<usize>,
        /// The egresses that flushed the layers first.
        flushes: usize,
    }

    impl LayerCx for Cx {
        fn now(&self) -> Instant {
            self.clock.now()
        }

        fn trace(&mut self) -> Option<&mut dyn Trace> {
            Some(self)
        }

        fn failures(&mut self) -> Option<&mut dyn Failures> {
            Some(self)
        }

        fn transfer(&mut self) -> Option<&mut dyn ForTransfer> {
            None
        }

        fn tls_sessions(&mut self) -> Option<&mut dyn TlsSessions> {
            None
        }

        fn early_data(&mut self) -> Option<&mut dyn EarlyData> {
            None
        }

        fn quic_timer(&mut self) -> Option<&mut dyn QuicTimer> {
            Some(self)
        }

        fn h3_streams(&mut self) -> Option<&mut dyn H3Streams> {
            None
        }

        fn recv_room(&mut self) -> Option<&mut RecvRoom> {
            Some(&mut self.room)
        }
    }

    impl Trace for Cx {
        fn line(&mut self, _: Component, line: std::fmt::Arguments<'_>) {
            self.lines.push(line.to_string());
        }
        fn line_with(&mut self, _: Component, parts: &[&[u8]]) {
            self.lines
                .push(String::from_utf8(parts.concat()).expect("a test's line is text"));
        }
        fn info_line(&mut self, line: std::fmt::Arguments<'_>) {
            self.lines.push(format!("* {line}"));
        }
        fn info_line_with(&mut self, parts: &[&[u8]]) {
            let line = String::from_utf8(parts.concat()).expect("a test's line is text");
            self.lines.push(format!("* {line}"));
        }
        fn says_info(&self) -> bool {
            false
        }
    }

    impl Failures for Cx {
        fn keep(&mut self, kind: ErrorKind, why: std::fmt::Arguments<'_>) -> ErrorKind {
            self.lines.push(format!("! {why}"));
            kind
        }
        fn keep_with(&mut self, kind: ErrorKind, parts: &[&[u8]]) -> ErrorKind {
            let why = String::from_utf8(parts.concat()).expect("a test's reason is text");
            self.lines.push(format!("! {why}"));
            kind
        }
        fn keep_errno(&mut self, e: &std::io::Error) {
            self.lines.push(format!("errno {e}"));
        }
    }

    impl QuicTimer for Cx {
        fn due_in(&mut self, wait: Duration) {
            self.due.push(wait);
        }
    }

    /// Its datagrams go through the layers it has, else on its socket.
    impl QuicIo for Cx {
        fn via(&mut self) -> Via<'_> {
            if self.below.is_some() {
                Via::Layers(self)
            } else {
                Via::Socket(self)
            }
        }
    }

    impl SocketIo for Cx {
        fn socket(&self) -> &dyn Socket {
            &self.socket
        }
    }

    impl LayersIo for Cx {
        fn send_below(&mut self, datagram: &[u8]) -> Result<Sent, ErrorKind> {
            let below = self.below.as_mut().unwrap();
            let all = Sent::Bytes(std::num::NonZeroUsize::new(datagram.len()).unwrap());
            let r = below.sends.pop_front().unwrap_or(Ok(all));
            if r == Ok(all) {
                below.sent.push(datagram.to_vec());
            }
            r
        }

        fn recv_below(&mut self, buf: &mut [u8]) -> Result<Recv, ErrorKind> {
            let below = self.below.as_mut().unwrap();
            below.rooms.push(buf.len());
            match below.datagrams.pop_front() {
                None => Ok(Recv::WouldBlock),
                Some(Err(kind)) => Err(kind),
                Some(Ok(d)) => {
                    buf[..d.len()].copy_from_slice(&d);
                    Ok(Recv::Data(std::num::NonZeroUsize::new(d.len()).unwrap()))
                }
            }
        }

        fn flush_below(&mut self) -> Result<(), ErrorKind> {
            self.below.as_mut().unwrap().flushes += 1;
            Ok(())
        }
    }

    /// A QUIC connection over the fake library running `script`, and a
    /// context for it, with its socket.
    fn quic(script: &Arc<Mutex<Script>>) -> (Quic, Cx) {
        quic_over(script, false)
    }

    /// `quic`, its context with layers its datagrams go through if
    /// `layered`.
    fn quic_over(script: &Arc<Mutex<Script>>, layered: bool) -> (Quic, Cx) {
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
            crate::tls::TlsIdentity::of(&Default::default(), crate::tls::CaDefaults::NONE).unwrap();
        let origin =
            crate::conn::Peer::new(crate::proto::http::HTTPS, b"q.test".to_vec(), 443, None);
        let peer =
            SessionPeer::new(&identity, &origin, None, &"test", crate::conn::Dial::Quic).unwrap();
        let cx = Cx {
            clock: clock.clone(),
            lines: Vec::new(),
            due: Vec::new(),
            socket: Scripted::default(),
            below: layered.then(Layers::default),
            room: RecvRoom::Unmade,
        };
        let shared = SharedClock::new(Box::new(clock)).unwrap();
        (
            Quic::new(
                conn,
                peer,
                remote,
                shared,
                Component::Http3,
                Flavour::Ngtcp2,
            )
            .unwrap(),
            cx,
        )
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
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
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

    /// On Windows and macOS, which cannot cut a run, each packet is a
    /// send of its own, from the first: a run of one size goes a
    /// datagram at a time, traced as C's `send` or `sendmsg` calls are
    /// (`send_packet_no_gso`).
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_run_goes_a_datagram_at_a_time() {
        let script = Script::new();
        packets(&script, &[1200, 1200, 900]);
        let (mut q, mut cx) = quic(&script);
        q.egress(&mut cx).unwrap();
        assert_eq!(
            *cx.socket.sent.lock().unwrap(),
            [(1200, 1200), (1200, 1200), (900, 900)]
        );
        assert_eq!(
            cx.lines[1..],
            [
                "egress, send collected 3 packets in 3300 bytes".to_owned(),
                format!("vquic_{SEND_METHOD}(len=1200, gso=1200, calls=1) -> 0, sent=1200"),
                format!("vquic_{SEND_METHOD}(len=1200, gso=1200, calls=1) -> 0, sent=1200"),
                format!("vquic_{SEND_METHOD}(len=900, gso=900, calls=1) -> 0, sent=900"),
                format!("vquic_{SEND_METHOD}(len=3300, gso=1200, calls=3) -> 0, sent=3300"),
            ]
        );
    }

    /// On Windows and macOS a datagram too large for the path is lost
    /// and counted as sent; a send that would block keeps the packets
    /// for the next egress; any other failure fails it, said as C's
    /// `send()`'s or `sendmsg()`'s.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_datagram_too_large_is_lost_and_a_blocked_one_waits() {
        let script = Script::new();
        packets(&script, &[1200]);
        let (mut q, mut cx) = quic(&script);
        let sends = |cx: &Cx, act| cx.socket.sends.lock().unwrap().push_back(act);
        sends(&cx, Act::Fail(TOO_LARGE));
        q.egress(&mut cx).unwrap();
        assert_eq!(
            *cx.lines.last().unwrap(),
            format!("vquic_{SEND_METHOD}(len=1200, gso=1200, calls=1) -> 0, sent=1200")
        );
        assert!(cx.socket.sent.lock().unwrap().is_empty());
        packets(&script, &[1200]);
        sends(&cx, Act::Block);
        q.egress(&mut cx).unwrap();
        assert_eq!(
            *cx.lines.last().unwrap(),
            format!("vquic_{SEND_METHOD}(len=1200, gso=1200, calls=1) -> 81, sent=0")
        );
        assert_eq!(q.wants(), Events::IN | Events::OUT);
        q.egress(&mut cx).unwrap();
        assert_eq!(*cx.socket.sent.lock().unwrap(), [(1200, 1200)]);
        packets(&script, &[1200]);
        // A reset connection: `WSAECONNRESET`, macOS's `ECONNRESET`.
        let reset = if cfg!(windows) { 10054 } else { 54 };
        sends(&cx, Act::Fail(reset));
        assert_eq!(q.egress(&mut cx), Err(ErrorKind::SendError));
        let failed = format!("! {SEND_METHOD}() returned -1 (errno {reset})");
        assert!(cx.lines.contains(&failed), "{:?}", cx.lines);
    }

    /// On macOS a datagram sent short fails the send, as C's `sendmsg`
    /// path says it (`do_sendmsg`).
    #[cfg(target_vendor = "apple")]
    #[test]
    fn a_short_send_fails() {
        let script = Script::new();
        packets(&script, &[1200, 1200]);
        let (mut q, mut cx) = quic(&script);
        cx.socket.sends.lock().unwrap().push_back(Act::Short(1000));
        assert_eq!(q.egress(&mut cx), Err(ErrorKind::SendError));
        assert!(
            cx.lines
                .contains(&"! sendmsg() sent only 1000/1200 bytes".to_owned()),
            "{:?}",
            cx.lines
        );
        let said = "vquic_sendmsg(len=2400, gso=1200, calls=0) -> 55, sent=0".to_owned();
        assert!(cx.lines.contains(&said), "{:?}", cx.lines);
    }

    /// On Windows and macOS datagrams come one at a time, each with its
    /// sender, traced as C's `recvfrom` or `recvmsg` calls are; C's
    /// `recvmsg_packets` does not say the empty receive that ends them.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn datagrams_come_one_at_a_time() {
        let script = Script::new();
        let (mut q, mut cx) = quic(&script);
        let mut queued = cx.socket.datagrams.lock().unwrap();
        queued.push_back(Ok(vec![0x51; 30]));
        queued.push_back(Ok(Vec::new()));
        queued.push_back(Ok(vec![0x51; 20]));
        drop(queued);
        q.ingress(&mut cx).unwrap();
        assert_eq!(
            cx.lines
                .contains(&format!("ingress, {RECV_METHOD} -> EAGAIN")),
            TRACES_EAGAIN,
            "{:?}",
            cx.lines
        );
        let said = format!("vquic_{RECV_METHOD}(len=50, packets=3, calls=3) -> 0");
        assert!(cx.lines.contains(&said), "{:?}", cx.lines);
    }

    /// The packets of a datagram the kernel joined (GRO) are each read, in
    /// order, and the first the library fails to read is the last; its
    /// failure is said and is the receive's.
    #[cfg(unix)]
    #[test]
    fn a_joined_datagram_s_packets_are_read_in_order_until_one_fails() {
        let script = Script::new();
        let (mut q, mut cx) = quic(&script);
        *cx.socket.segment.lock().unwrap() = Some(10);
        let joined = [vec![1; 10], vec![2; 10], vec![3; 5]];
        let datagram = || Ok(joined.concat());
        cx.socket.datagrams.lock().unwrap().push_back(datagram());
        q.ingress(&mut cx).unwrap();
        let read: Vec<Vec<u8>> = script.lock().unwrap().read.drain(..).map(|r| r.0).collect();
        assert_eq!(read, joined);
        let said = format!("vquic_{RECV_METHOD}(len=25, packets=3, ");
        assert!(
            cx.lines.iter().any(|l| l.starts_with(&said)),
            "{:?}",
            cx.lines
        );

        script.lock().unwrap().read_fails = Some(-215);
        cx.socket.datagrams.lock().unwrap().push_back(datagram());
        assert_eq!(q.ingress(&mut cx), Err(ErrorKind::RecvError));
        assert_eq!(script.lock().unwrap().read.len(), 1, "the first, failed");
        let said = "ingress, read_pkt -> ERR_FAKE (-215)";
        assert!(cx.lines.iter().any(|l| l == said), "{:?}", cx.lines);
    }

    /// A refused datagram before the connect is done fails it as a
    /// refused connect; any other error is a receive's.
    #[test]
    fn a_refused_receive_fails_the_connect() {
        let script = Script::new();
        let (mut q, mut cx) = quic(&script);
        // `ECONNREFUSED`: Linux's, macOS's, Winsock's `WSAECONNREFUSED`.
        let refused = if cfg!(windows) {
            10061
        } else if cfg!(target_vendor = "apple") {
            61
        } else {
            111
        };
        cx.socket.datagrams.lock().unwrap().push_back(Err(refused));
        let r = q.connect(&mut cx);
        assert_eq!(r, Err(ErrorKind::CouldntConnect));
        assert!(
            cx.lines
                .contains(&"! QUIC: connection to 127.0.0.1 port 443 refused".to_owned()),
            "{:?}",
            cx.lines
        );
        let said = format!("vquic_{RECV_METHOD}(len=0, packets=0, calls=0) -> 7");
        assert!(cx.lines.contains(&said), "{:?}", cx.lines);
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
            b"https://localhost/",
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

    /// Through a tunnel, with no socket, a run of datagrams goes to the
    /// layers below one at a time, each whole, and one alone in one send
    /// (`send_packet_no_gso_cf`).
    #[test]
    fn a_tunnel_takes_a_datagram_at_a_time() {
        let script = Script::new();
        packets(&script, &[1200, 1200, 900]);
        let (mut q, mut cx) = quic_over(&script, true);
        cx.below = Some(Layers::default());
        q.egress(&mut cx).unwrap();
        let sent: Vec<usize> = cx
            .below
            .as_ref()
            .unwrap()
            .sent
            .iter()
            .map(Vec::len)
            .collect();
        assert_eq!(sent, [1200, 1200, 900]);
        assert_eq!(
            cx.lines.last().unwrap(),
            "vquic_cf_send(len=3300, gso=1200, calls=3) -> 0, sent=3300"
        );
        // What the layers held from before goes first.
        assert_eq!(cx.below.as_ref().unwrap().flushes, 1);

        cx.lines.clear();
        packets(&script, &[700]);
        q.egress(&mut cx).unwrap();
        assert_eq!(cx.below.as_ref().unwrap().sent.last().unwrap().len(), 700);
        assert!(
            !cx.lines.iter().any(|l| l.starts_with("vquic_")),
            "the layer below traces a single send: {:?}",
            cx.lines
        );
    }

    /// A tunnel that takes part of a datagram fails the send; one that
    /// blocks keeps what it did not take for later.
    #[test]
    fn a_tunnel_s_short_send_fails_and_a_blocked_one_waits() {
        let script = Script::new();
        packets(&script, &[1200, 1200]);
        let (mut q, mut cx) = quic_over(&script, true);
        let mut below = Layers::default();
        below
            .sends
            .push_back(Ok(Sent::Bytes(std::num::NonZeroUsize::new(1200).unwrap())));
        below.sends.push_back(Ok(Sent::WouldBlock));
        cx.below = Some(below);
        q.egress(&mut cx).unwrap();
        assert_eq!(
            cx.lines.last().unwrap(),
            &format!("vquic_cf_send(len=2400, gso=1200, calls=2) -> {AGAIN_NUMBER}, sent=1200")
        );
        assert!(q.wants().contains(Events::OUT), "the rest waits");

        let (mut q, mut cx) = quic_over(&script, true);
        packets(&script, &[1200, 1200]);
        let mut below = Layers::default();
        below
            .sends
            .push_back(Ok(Sent::Bytes(std::num::NonZeroUsize::new(100).unwrap())));
        cx.below = Some(below);
        assert_eq!(q.egress(&mut cx), Err(ErrorKind::SendError));
        assert_eq!(
            cx.lines.last().unwrap(),
            "vquic_cf_send(len=2400, gso=1200, calls=1) -> 55, sent=0"
        );
    }

    /// Through a tunnel each receive is one datagram, handed to the
    /// library whole, until the layers below have no more; a failure
    /// below fails the read, said as C says it.
    #[test]
    fn a_tunnel_gives_a_datagram_at_a_time() {
        let script = Script::new();
        let (mut q, mut cx) = quic_over(&script, true);
        let mut below = Layers::default();
        below.datagrams.push_back(Ok(b"one".to_vec()));
        below.datagrams.push_back(Ok(b"two".to_vec()));
        cx.below = Some(below);
        q.ingress(&mut cx).unwrap();
        assert_eq!(
            script.lock().unwrap().read,
            [(b"one".to_vec(), 0), (b"two".to_vec(), 0)]
        );
        // Each into C's room for a tunnel's datagram, 64 KiB
        // (`QUIC_TUNNEL_INBUF_SIZE`).
        assert_eq!(cx.below.as_ref().unwrap().rooms, [64 * 1024; 3]);
        assert!(
            cx.lines
                .contains(&"progress_ingress(sub-filters)".to_owned())
        );
        assert_eq!(q.first_byte_at(), Some(cx.clock.now()));

        cx.below
            .as_mut()
            .unwrap()
            .datagrams
            .push_back(Err(ErrorKind::RecvError));
        assert_eq!(q.ingress(&mut cx), Err(ErrorKind::RecvError));
        assert_eq!(
            cx.lines.last().unwrap(),
            "ingress, recv from tunnel failed: 56"
        );
    }

    /// The packets a connection receives are handed to its library at the
    /// time of the clock it was made under, read as they are, not at the
    /// time of whatever context calls it.
    #[test]
    fn received_packets_are_handed_over_at_the_connection_s_time() {
        let script = Script::new();
        let (mut q, mut cx) = quic_over(&script, true);
        let own = std::mem::replace(&mut cx.clock, ManualClock::new().unwrap());
        own.advance(Duration::from_secs(5));
        cx.clock.advance(Duration::from_secs(2));
        let mut below = Layers::default();
        below.datagrams.push_back(Ok(b"one".to_vec()));
        cx.below = Some(below);
        q.ingress(&mut cx).unwrap();
        assert_eq!(script.lock().unwrap().last_ts, Some(own.now()));
    }

    /// A connection through a tunnel receives in a room of its own, C's
    /// 64 KiB grown to the path's largest datagram (`tunnel_inbuf`), and
    /// never asks for the multi's, which the proxy's connection below it
    /// may have lent; one on a socket borrows the multi's and gives it
    /// back.
    #[test]
    fn a_tunnel_receives_in_its_own_room_and_a_socket_in_the_multis() {
        let script = Script::new();
        let (mut q, mut cx) = quic_over(&script, true);
        cx.below = Some(Layers::default());
        // The proxy's connection has the multi's room.
        cx.room = RecvRoom::Lent;
        q.ingress(&mut cx).unwrap();
        script.lock().unwrap().path_max_payload = 70_000;
        q.ingress(&mut cx).unwrap();
        assert_eq!(cx.below.as_ref().unwrap().rooms, [64 * 1024, 70_000]);
        assert!(matches!(cx.room, RecvRoom::Lent));

        let script = Script::new();
        let (mut q, mut cx) = quic(&script);
        q.ingress(&mut cx).unwrap();
        assert!(matches!(&cx.room, RecvRoom::Kept(room) if room.len() == RECV_ROOM));
    }

    /// The multi's room goes to one receive at a time: a second is a
    /// receive inside a receive on it, which nothing makes.
    #[test]
    #[should_panic(expected = "lent to one receive at a time")]
    fn the_multis_room_is_lent_once() {
        let mut room = RecvRoom::Unmade;
        let first = room.take().unwrap();
        drop(room.take());
        drop(first);
    }

    /// The layer under a connection over a tunnel: nothing to read or
    /// send, and a flush that counts itself and fails.
    #[derive(Debug)]
    struct Stuck(Arc<Mutex<usize>>);

    impl crate::conn::part::Part<Below<'_>> for Stuck {}

    impl crate::conn::layer::Layer for Stuck {
        fn recv(&mut self, _: &mut dyn LayerCx, _: Below<'_>, _: &mut [u8]) -> io::Result<Recv> {
            Ok(Recv::WouldBlock)
        }

        fn send(&mut self, _: &mut dyn LayerCx, _: Below<'_>, _: &[u8]) -> io::Result<Sent> {
            Ok(Sent::WouldBlock)
        }

        fn flush(&mut self, _: &mut dyn LayerCx, _: Below<'_>) -> io::Result<bool> {
            *self.0.lock().unwrap() += 1;
            Err(io::Error::other("stuck"))
        }
    }

    /// A call over a tunnel flushes the tunnel's layers, a failure there
    /// failing the send (`Curl_conn_flush`).
    #[test]
    fn a_call_over_a_tunnel_flushes_its_layers() {
        let script = Script::new();
        let (_q, mut cx) = quic(&script);
        let flushes = Arc::new(Mutex::new(0));
        let mut layers: [Box<dyn crate::conn::layer::Layer>; 1] =
            [Box::new(Stuck(flushes.clone()))];
        let socket = Scripted::default();
        let mut over = Over {
            cx: &mut cx,
            on: Below::new(&mut layers, &socket),
        };
        assert_eq!(over.flush_below(), Err(ErrorKind::SendError));
        assert_eq!(*flushes.lock().unwrap(), 1);
    }

    /// A stream cancelled is stopped both ways with
    /// `H3_REQUEST_CANCELLED`, and what that says is sent at once
    /// (`Curl_cf_ngtcp2_h3_stream_close`).
    #[test]
    fn a_stream_cancelled_is_stopped_and_said_at_once() {
        let script = Script::new();
        packets(&script, &[40]);
        let (mut q, mut cx) = quic(&script);
        q.cancel(&mut cx, StreamId(4));
        assert_eq!(script.lock().unwrap().cancelled, [(4, 0x10c)]);
        assert_eq!(*cx.socket.sent.lock().unwrap(), [(40, 40)]);
    }
}
