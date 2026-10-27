//! HTTP/3 over QUIC, as a library speaks it: a client connection fed the
//! datagrams its socket received and asked for the packets it wants
//! sent, which tells what it read stream by stream (`lib/vquic`'s use of
//! ngtcp2 and nghttp3). The core links none; a handle's `Libraries` name
//! the one its build has, and without one HTTP/3 is not built in, as in
//! a C build without ngtcp2.
//!
//! The library owns the connection's TLS session, which it is handed
//! made, and wraps each of its own calls that may move the handshake on
//! in the session's `drive`: those calls take the transfer's `TlsCx`,
//! and hand it back to the caller's `events` with each event, as the
//! callbacks that tell them run inside the drive. What passes between
//! the QUIC library and the HTTP/3 one (stream data read, acknowledged,
//! closed, reset, unblocked) is the library's; what C's filter decides
//! or traces of it is told as an `Event`.
//!
//! C's callbacks act on the connection as they are told (opening a
//! stream's window as its data is read, resuming a body the peer
//! acknowledged). Here the connection is borrowed while it tells: a body
//! is the library's to resume, as it holds the body, and a window the
//! caller opens once the call returns, which changes nothing on the wire
//! before the connection next writes.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use curl_alloc::OutOfMemory;

use crate::error::ErrorKind;
use crate::time::Instant;
use crate::tls::{QuicTls, TlsCx};

/// A QUIC stream, by its id: a request's is a client-opened
/// bidirectional one (`int64_t stream_id`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub i64);

/// An HTTP/3 error code, as a stream's reset or a connection's close
/// carries it (RFC 9114, section 8.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct H3Error(pub u64);

impl H3Error {
    pub const NO_ERROR: H3Error = H3Error(0x100);
    pub const REQUEST_REJECTED: H3Error = H3Error(0x10b);
    pub const REQUEST_CANCELLED: H3Error = H3Error(0x10c);
}

/// A library's failure: which library, the call that failed, its code
/// and its text for it (`ngtcp2_strerror`, `nghttp3_strerror`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuicError {
    pub layer: Layer,
    pub call: &'static str,
    pub code: i32,
    pub text: &'static str,
    /// It is the QUIC library's failure of the handshake's TLS, commonly
    /// the peer's certificate (`NGTCP2_ERR_CRYPTO`).
    pub crypto: bool,
}

/// Which of the two libraries a failure is the code of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Quic,
    Http3,
}

/// What a connection closes with, or the peer closed it with
/// (`ngtcp2_ccerr`): its kind, as the library numbers it (a transport
/// error is 0, an application's 1), and its code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseError {
    pub kind: i32,
    pub code: u64,
}

/// What the connection read, as it read it. The library acts on what
/// passes between its two halves; these are what C's filter traces or
/// decides on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// The handshake is done and the peer checked
    /// (`cb_ngtcp2_handshake_completed`): `checked` is the check's
    /// verdict, a failure of which fails the call under way. The peer's
    /// transport parameters said `max_udp_payload` and `initial_max_data`.
    /// `early_data` says, if early data was sent, whether the peer took
    /// it.
    HandshakeDone {
        checked: Result<(), ErrorKind>,
        max_udp_payload: u64,
        initial_max_data: u64,
        early_data: Option<bool>,
    },
    /// The HTTP/3 library could not be set up as the 1-RTT keys arrived
    /// (`init_ngh3_conn`): why, as C says it, and the library's word for
    /// it if C adds it; for want of memory if `out_of_memory`.
    H3Failed {
        why: &'static str,
        detail: Option<&'static str>,
        out_of_memory: bool,
    },
    /// The peer allows this many bidirectional streams of ours
    /// (`cb_extend_max_local_streams_bidi`).
    MaxBidiStreams(u64),
    /// The HTTP/3 library took `n` bytes of `stream`'s framing, its
    /// window opened by as much (`cb_recv_stream_data`,
    /// `cb_h3_deferred_consume`).
    Consumed { stream: StreamId, n: u64 },
    /// The QUIC stream closed, with the peer's error code if it gave one;
    /// the HTTP/3 library's answer to closing it (`cb_stream_close`).
    QuicClosed {
        stream: StreamId,
        error: H3Error,
        rv: i32,
    },
    /// The peer reset `stream`; the HTTP/3 library's answer to it
    /// (`cb_stream_reset`).
    QuicReset { stream: StreamId, rv: i32 },
    /// The peer let `stream` send more (`cb_extend_max_stream_data`).
    Unblocked { stream: StreamId },
    /// `stream` could not send for the peer's flow control
    /// (`NGTCP2_ERR_STREAM_DATA_BLOCKED`).
    Blocked { stream: StreamId },
    /// A field of a header block of `stream`: the response's head, an
    /// interim response's, or the trailers. `:status` is `status`.
    Header {
        stream: StreamId,
        name: &'a [u8],
        value: &'a [u8],
        status: bool,
    },
    /// A header block of `stream` is over (`cb_h3_end_headers`).
    HeadersDone { stream: StreamId },
    /// Body bytes of `stream` (`cb_h3_recv_data`); the connection's
    /// window opened by as many.
    Data { stream: StreamId, bytes: &'a [u8] },
    /// The HTTP/3 stream closed, with this error code
    /// (`cb_h3_stream_close`).
    Closed { stream: StreamId, error: H3Error },
    /// The peer asked `stream` to stop sending; the QUIC library's answer
    /// to shutting it (`cb_h3_reset_stream`).
    H3Reset { stream: StreamId, rv: i32 },
    /// The HTTP/3 library took `n` bytes of `stream`'s request body in
    /// `vecs` pieces to send, the last if `eof`, `buffered` held in all;
    /// or, with none and not the last, found none to take
    /// (`cb_h3_read_req_body`).
    BodyRead {
        stream: StreamId,
        vecs: usize,
        n: usize,
        eof: bool,
        buffered: usize,
    },
}

/// What the caller is told the events of a call with: the transfer the
/// call reaches, and each event.
pub type Events<'e> = &'e mut dyn FnMut(&mut TlsCx<'_>, Event<'_>) -> Heard;

/// What the caller made of an event: a failure stops the connection's
/// reading, and the read fails (`*_ERR_CALLBACK_FAILURE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Heard {
    Fine,
    Failed,
}

/// How a client connection is set up (`quic_settings`, `cf_connect_start`).
#[derive(Clone, Copy, Debug)]
pub struct ClientSetup {
    /// The socket's two ends.
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub now: Instant,
    /// How long the handshake may take.
    pub handshake_timeout: Duration,
    /// The connection's receive window at its largest, and its first.
    pub max_window: u64,
    /// A request stream's first receive window.
    pub stream_window: u64,
    /// The streams the peer may open of each kind.
    pub max_streams: u64,
}

/// When a connection wants to be called again (`ngtcp2_conn_get_expiry`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// Not until something happens.
    Never,
    /// Now, or already.
    Due,
    /// In this long.
    In(Duration),
}

/// An HTTP/3 library, as ngtcp2 and nghttp3 serve C.
pub trait Http3: fmt::Debug + Send + Sync {
    /// A client connection with C's settings, over `tls`, which it keeps
    /// and drives (`cf_connect_start`). Its first packets are not yet
    /// written.
    fn client(
        &self,
        setup: &ClientSetup,
        tls: Box<dyn QuicTls>,
    ) -> Result<Box<dyn Connection>, ConnectFailed>;

    /// The libraries' names and versions, as curl's version says them:
    /// `ngtcp2/1.25.0 nghttp3/1.18.0`.
    fn version(&self) -> &dyn fmt::Display;
}

/// Why a client connection could not be made: memory, the QUIC
/// library's refusal (`CURLE_QUIC_CONNECT_ERROR`, which C does not
/// explain), or its crypto's, said as C says it (`CURLE_FAILED_INIT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectFailed {
    OutOfMemory,
    Refused,
    Crypto { why: &'static str },
}

impl From<OutOfMemory> for ConnectFailed {
    fn from(_: OutOfMemory) -> ConnectFailed {
        ConnectFailed::OutOfMemory
    }
}

/// A client connection, QUIC's and HTTP/3's together.
pub trait Connection: fmt::Debug + Send {
    /// Feed it one packet `from` the peer, received at `now` with ECN
    /// bits `ecn` (`ngtcp2_conn_read_pkt`): what it read is told to
    /// `events`, in order.
    fn read_packet(
        &mut self,
        cx: &mut TlsCx<'_>,
        now: Instant,
        from: SocketAddr,
        ecn: u8,
        packet: &[u8],
        events: Events<'_>,
    ) -> Result<(), QuicError>;

    /// Write the next packet it wants sent into `buf`, as many frames of
    /// as many streams as fit (`read_pkt_to_send`): its length, or none
    /// if it has nothing to send.
    fn write_packet(
        &mut self,
        cx: &mut TlsCx<'_>,
        now: Instant,
        buf: &mut [u8],
        events: Events<'_>,
    ) -> Result<Option<usize>, QuicError>;

    /// Get its TLS ready for the peer's bytes: the trust store set up,
    /// if it is not (`Curl_vquic_tls_before_recv`).
    fn before_recv(&mut self, cx: &mut TlsCx<'_>) -> Result<(), ErrorKind>;

    /// Packets went at `now` (`ngtcp2_conn_update_pkt_tx_time`).
    fn sent_at(&mut self, now: Instant);

    /// The largest packet it sends now, and on its path at most
    /// (`ngtcp2_conn_get_max_tx_udp_payload_size`,
    /// `ngtcp2_conn_get_path_max_tx_udp_payload_size`).
    fn max_payload(&self) -> usize;
    fn path_max_payload(&self) -> usize;

    /// How much it may send in one go (`ngtcp2_conn_get_send_quantum`).
    fn send_quantum(&self) -> usize;

    /// When it wants to be called again.
    fn expiry(&self, now: Instant) -> Expiry;

    /// Its timers, due at `now` (`ngtcp2_conn_handle_expiry`).
    fn handle_expiry(
        &mut self,
        cx: &mut TlsCx<'_>,
        now: Instant,
        events: Events<'_>,
    ) -> Result<(), QuicError>;

    /// The handshake is done (`ngtcp2_conn_get_handshake_completed`).
    fn handshake_done(&self) -> bool;

    /// It is draining: the peer closed it (`ngtcp2_conn_in_draining_period`).
    fn draining(&self) -> bool;

    /// The peer's idle timeout, if it set one.
    fn peer_idle_timeout(&self) -> Option<Duration>;

    /// Keep it alive by pinging this often, or never.
    fn set_keep_alive(&mut self, every: Option<Duration>);

    /// It may send now, the congestion window and the connection's flow
    /// control allowing (`ngtcp2_conn_get_cwnd_left`,
    /// `ngtcp2_conn_get_max_data_left`).
    fn send_room(&self) -> bool;

    /// A call failed with `error`: what the connection closes with, if
    /// nothing failed before, and whether it is past saving and must
    /// close now (`Curl_cf_ngtcp2_cmn_err_set`, `Curl_cf_ngtcp2_h3_err_set`).
    fn failed(&mut self, error: QuicError) -> bool;

    /// What it closes with (`last_error`).
    fn close_error(&self) -> CloseError;

    /// What it was closed with, by the peer or by itself
    /// (`ngtcp2_conn_get_ccerr`), if it says.
    fn closed_with(&self) -> Option<CloseError>;

    /// Write the packet that closes it into `buf`, with what it closes
    /// with (`ngtcp2_conn_write_connection_close`): its length.
    fn write_close(&mut self, now: Instant, buf: &mut [u8]) -> Result<usize, QuicError>;

    /// Open a stream and submit a request of `fields`, its pseudo-headers
    /// first, with a body if `body` (`h3_stream_open`).
    fn submit_request(
        &mut self,
        fields: &[(&[u8], &[u8])],
        body: bool,
    ) -> Result<StreamId, SubmitFailed>;

    /// Take what of `bytes` it can hold of `stream`'s request body, to
    /// send as the peer allows: how many. The bytes are kept until the
    /// peer acknowledges them, as the HTTP/3 library points at them
    /// until then; it holds at most `BODY_HELD` of a stream's, as C's
    /// buffer does (`H3_STREAM_SEND_BUFFER_MAX`).
    fn write_body(&mut self, stream: StreamId, bytes: &[u8]) -> Result<usize, OutOfMemory>;

    /// The body of `stream` ends after what it holds.
    fn end_body(&mut self, stream: StreamId);

    /// The bytes of `stream`'s body it holds: handed to the HTTP/3
    /// library and not yet acknowledged, and not yet handed.
    fn body_in_flight(&self, stream: StreamId) -> usize;
    fn body_buffered(&self, stream: StreamId) -> usize;

    /// `stream` has more to send (`nghttp3_conn_resume_stream`).
    fn resume(&mut self, stream: StreamId);

    /// Stop `stream` both ways with `error`, nothing more told of it
    /// (`h3_stream_close`).
    fn cancel(&mut self, stream: StreamId, error: H3Error);

    /// Open `stream`'s receive window by `n`
    /// (`ngtcp2_conn_extend_max_stream_offset`).
    fn extend_stream_window(&mut self, stream: StreamId, n: u64);
}

/// Why a request could not be submitted (`h3_stream_open`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitFailed {
    /// No stream could be opened.
    NoStream,
    /// The HTTP/3 library refused it on `stream`, the connection closing
    /// if `closing`.
    Refused {
        stream: StreamId,
        error: QuicError,
        closing: bool,
    },
    OutOfMemory,
}

/// The most of a stream's request body a connection holds
/// (`H3_STREAM_SEND_BUFFER_MAX`, ten chunks of 64 KiB).
pub const BODY_HELD: usize = 10 * 64 * 1024;

#[cfg(any(test, feature = "test-util"))]
pub mod fake;
