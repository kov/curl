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
//! or traces of it is told as an `Event`: of the connection itself, or
//! of one of its streams.
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

    /// Its name, as C says it (`Curl_vquic_h3_err_str`): the reserved
    /// codes past those named are no error.
    pub fn name(self) -> &'static str {
        const NAMES: [&str; 17] = [
            "NO_ERROR",
            "GENERAL_PROTOCOL_ERROR",
            "INTERNAL_ERROR",
            "STREAM_CREATION_ERROR",
            "CLOSED_CRITICAL_STREAM",
            "FRAME_UNEXPECTED",
            "FRAME_ERROR",
            "EXCESSIVE_LOAD",
            "ID_ERROR",
            "SETTINGS_ERROR",
            "MISSING_SETTINGS",
            "REQUEST_REJECTED",
            "REQUEST_CANCELLED",
            "REQUEST_INCOMPLETE",
            "MESSAGE_ERROR",
            "CONNECT_ERROR",
            "VERSION_FALLBACK",
        ];
        match self
            .0
            .checked_sub(0x100)
            .and_then(|i| NAMES.get(usize::try_from(i).ok()?))
        {
            Some(name) => name,
            None if self.0 >= 0x21 && (self.0 - 0x21).is_multiple_of(0x1f) => "NO_ERROR",
            None => "unknown",
        }
    }
}

/// A library's failure: which library, the call that failed, its code
/// and its text for it (`ngtcp2_strerror`, `nghttp3_strerror`). The code
/// is the library's number, kept for C's messages, which print it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuicError {
    pub layer: Layer,
    pub call: &'static str,
    pub code: i32,
    pub text: &'static str,
}

/// Which of the two libraries a failure is the code of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Quic,
    /// The QUIC library's failure of the handshake's TLS, commonly the
    /// peer's certificate (`NGTCP2_ERR_CRYPTO`).
    Crypto,
    Http3,
}

/// What a library call the caller is told of came to, as C traces it:
/// 0, or the failure's code.
pub fn returned(answer: Result<(), QuicError>) -> i32 {
    answer.map_or_else(|error| error.code, |()| 0)
}

/// What a connection closes with, or the peer closed it with
/// (`ngtcp2_ccerr`): its kind, and its code, a QUIC transport error's or
/// the application's as the kind says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseError {
    pub kind: CloseKind,
    pub code: u64,
}

/// The transport error from which a code is TLS's alert, in its low byte
/// (RFC 9001, section 4.8; `NGTCP2_CRYPTO_ERROR`).
const CRYPTO_ERROR: u64 = 0x100;
/// The server refused the connection (RFC 9000, section 20.1;
/// `NGTCP2_CONNECTION_REFUSED`).
const CONNECTION_REFUSED: u64 = 0x2;

impl CloseError {
    /// The TLS alert its code is, if it is one: as C reads it, whatever
    /// the kind (`cf_ngtcp2_connect`).
    pub fn tls_alert(&self) -> Option<u64> {
        (self.code >= CRYPTO_ERROR).then_some(self.code & 0xff)
    }

    /// Its code says the server refused the connection, whatever the
    /// kind, as C reads it.
    pub fn refused(&self) -> bool {
        self.code == CONNECTION_REFUSED
    }
}

/// What kind of close a `CloseError` is (`ngtcp2_ccerr_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseKind {
    /// A QUIC transport error.
    Transport,
    /// The application's error, HTTP/3's.
    Application,
    /// The peer answered with a Version Negotiation packet.
    VersionNegotiation,
    /// The idle timeout passed.
    IdleClose,
    /// The connection is dropped with no CONNECTION_CLOSE sent.
    DropConn,
    /// A Retry packet is sent (a server's).
    Retry,
}

/// The kind's number, as C's traces print it (`ngtcp2_ccerr_type`).
impl fmt::Display for CloseKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = match self {
            CloseKind::Transport => 0,
            CloseKind::Application => 1,
            CloseKind::VersionNegotiation => 2,
            CloseKind::IdleClose => 3,
            CloseKind::DropConn => 4,
            CloseKind::Retry => 5,
        };
        write!(f, "{n}")
    }
}

/// What the connection read, as it read it. The library acts on what
/// passes between its two halves; these are what C's filter traces or
/// decides on: the connection's own, heard by the connection, and a
/// stream's, handed to the stream's transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    Connection(ConnEvent),
    Stream(StreamId, StreamEvent<'a>),
}

/// What the connection read of itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnEvent {
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
    /// The HTTP/3 library could not be set up as the 1-RTT keys arrived.
    H3Failed(H3Failed),
    /// The peer allows this many bidirectional streams of ours
    /// (`cb_extend_max_local_streams_bidi`).
    MaxBidiStreams(u64),
}

/// Why the HTTP/3 library could not be set up (`init_ngh3_conn`): why, as
/// C says it, and the library's word for it if C adds it; for want of
/// memory if `out_of_memory`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H3Failed {
    pub why: &'static str,
    pub detail: Option<&'static str>,
    pub out_of_memory: bool,
}

impl H3Failed {
    /// What the call under way fails with.
    pub fn kind(&self) -> ErrorKind {
        if self.out_of_memory {
            ErrorKind::OutOfMemory
        } else {
            ErrorKind::QuicConnectError
        }
    }
}

/// Its words, as C fails the call with them.
impl fmt::Display for H3Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.detail {
            Some(detail) => write!(f, "{}: {detail}", self.why),
            None => f.write_str(self.why),
        }
    }
}

/// What the connection read of one of its streams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamEvent<'a> {
    /// The HTTP/3 library took `n` bytes of the stream's framing, its
    /// window opened by as much (`cb_recv_stream_data`,
    /// `cb_h3_deferred_consume`).
    Consumed(u64),
    /// The HTTP/3 library refused the stream's bytes: the connection's
    /// read fails after (`cb_recv_stream_data`).
    ReadFailed,
    /// The QUIC stream closed, with the peer's error code if it gave one;
    /// the HTTP/3 library's answer to closing it (`cb_stream_close`).
    QuicClosed {
        error: H3Error,
        answer: Result<(), QuicError>,
    },
    /// The peer reset the stream; the HTTP/3 library's answer to it
    /// (`cb_stream_reset`).
    QuicReset { answer: Result<(), QuicError> },
    /// The peer let the stream send more (`cb_extend_max_stream_data`).
    Unblocked,
    /// The stream could not send for the peer's flow control
    /// (`NGTCP2_ERR_STREAM_DATA_BLOCKED`).
    Blocked,
    /// A field of a header block: the response's head, an interim
    /// response's, or the trailers. `:status` is `status`.
    Header {
        name: &'a [u8],
        value: &'a [u8],
        status: bool,
    },
    /// A header block is over (`cb_h3_end_headers`).
    HeadersDone,
    /// Body bytes (`cb_h3_recv_data`); the connection's window opened by
    /// as many.
    Data(&'a [u8]),
    /// The HTTP/3 stream closed, with this error code
    /// (`cb_h3_stream_close`).
    Closed(H3Error),
    /// The peer asked the stream to stop sending; the QUIC library's
    /// answer to shutting it (`cb_h3_reset_stream`).
    H3Reset { answer: Result<(), QuicError> },
    /// The HTTP/3 library took `n` bytes of the stream's request body in
    /// `vecs` pieces to send, the last if `eof`, `buffered` held in all;
    /// or, with none and not the last, found none to take
    /// (`cb_h3_read_req_body`).
    BodyRead {
        vecs: usize,
        n: usize,
        eof: bool,
        buffered: usize,
    },
}
/// What the caller is told the events of a call with: the transfer the
/// call reaches, and each event.
pub type Events<'e> = &'e mut dyn FnMut(&mut TlsCx<'_>, &Event<'_>) -> Heard;

/// What the caller made of an event: a failure stops the connection's
/// reading, and the read fails (`*_ERR_CALLBACK_FAILURE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Heard {
    Fine,
    Failed,
}

/// What `Connection::start_early` came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EarlyStart {
    /// The request goes as early data.
    Started,
    /// The TLS library would not send early data: none goes.
    Refused,
}

/// How a client connection is set up (`quic_settings`, `cf_connect_start`).
#[derive(Debug)]
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
    /// Where the connection writes its qlog, if anywhere.
    pub qlog: Option<QlogDir>,
}

/// The longest name of a qlog file, its zero byte included
/// (`DYN_QLOG_NAME`).
const QLOG_NAME_MAX: usize = 1024;

/// The directory each connection writes a qlog to, as `QLOGDIR` names
/// it, and the permissions a file is created with
/// (`CURLOPT_NEW_FILE_PERMS`): the file a connection's library writes
/// is named after the connection's source id (`Curl_qlogdir`).
pub struct QlogDir {
    /// The directory and a `/` after it, in its first `len` bytes.
    name: [u8; QLOG_NAME_MAX],
    len: usize,
    mode: crate::options::FileMode,
}

impl fmt::Debug for QlogDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QlogDir({})", self.name[..self.len].escape_ascii())
    }
}

impl QlogDir {
    /// The directory `QLOGDIR` names: none if it is unset or empty, as
    /// `curl_getenv` gives neither, or if no file in it has a name short
    /// enough.
    pub fn from_env(mode: crate::options::FileMode) -> Option<QlogDir> {
        let mut buf = [0u8; QLOG_NAME_MAX];
        QlogDir::from_value(curl_os::env::var_into(b"QLOGDIR", &mut buf), mode)
    }

    /// The directory `QLOGDIR`'s value `value` names, as `from_env`.
    fn from_value(value: Option<&[u8]>, mode: crate::options::FileMode) -> Option<QlogDir> {
        match value {
            None | Some([]) => None,
            Some(dir) => QlogDir::new(dir, mode),
        }
    }

    /// The directory `dir`, not checked: none if no file in it has a
    /// name short enough. A directory that is not there is only found
    /// as a file in it is opened.
    pub fn new(dir: &[u8], mode: crate::options::FileMode) -> Option<QlogDir> {
        let mut name = [0u8; QLOG_NAME_MAX];
        let len = dir.len() + 1;
        // Room for at least the extension and the zero byte.
        if len + b".sqlog".len() >= QLOG_NAME_MAX {
            return None;
        }
        name[..dir.len()].copy_from_slice(dir);
        name[dir.len()] = b'/';
        Some(QlogDir { name, len, mode })
    }

    /// Create the qlog of the connection of source id `scid`, to write
    /// it from its start: `<dir>/<scid in hex>.sqlog`. None if the name
    /// is too long or the file will not open, which leaves the
    /// connection without one and says nothing.
    ///
    /// C opens the file to write without cutting it (`O_WRONLY |
    /// O_CREAT`); it is opened here to write anew, which differs only for
    /// a file there already, which a source id of random bytes does not
    /// name.
    pub fn open(&self, scid: &[u8]) -> Option<std::fs::File> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        const EXT: &[u8] = b".sqlog";
        let mut name = self.name;
        let mut at = self.len;
        // The name and its zero byte must fit, as C's buffer's limit says.
        if at + 2 * scid.len() + EXT.len() >= QLOG_NAME_MAX {
            return None;
        }
        for &b in scid {
            name[at] = HEX[usize::from(b >> 4)];
            name[at + 1] = HEX[usize::from(b & 0xf)];
            at += 2;
        }
        name[at..at + EXT.len()].copy_from_slice(EXT);
        at += EXT.len();
        let mode = u32::from(self.mode.bits());
        curl_os::fs::with_c_name(&name[..at], |c| {
            curl_os::fs::open_write(c, curl_os::fs::Keep::Nothing, mode)
        })
        .ok()
    }
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

/// Which of C's two QUIC filters a library is spoken through: ngtcp2's
/// (`cf-ngtcp2.c`) or quiche's (`cf-quiche.c`), which differ in what they
/// trace and in some of what they do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Flavour {
    #[default]
    Ngtcp2,
    Quiche,
}

impl Flavour {
    /// The sessions the peer gives are kept, and early data sent under
    /// one resumed: not by quiche's filter, which passes its TLS neither
    /// a new-session callback nor a session-reuse one
    /// (`Curl_vquic_tls_init`); a session already kept, which it never
    /// keeps itself, still resumes.
    pub fn keeps_sessions(self) -> bool {
        self == Flavour::Ngtcp2
    }
}

/// An HTTP/3 library, as ngtcp2 and nghttp3, or quiche, serve C.
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

    /// Set up a QUIC session's TLS objects as the library's crypto needs
    /// them (`cf_ngtcp2_tls_ctx_setup`): the context, before the session
    /// is made from it, or for a library whose crypto sets the session up
    /// (GnuTLS), the session, as soon as it is made; why it could not, as
    /// C says it.
    fn setup_tls_context(&self, ctx: crate::tls::TlsNative) -> Result<(), &'static str> {
        let _ = ctx;
        Ok(())
    }

    /// The filter of C's it is spoken through.
    fn flavour(&self) -> Flavour {
        Flavour::Ngtcp2
    }
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
    /// Feed it `packets`, those of one datagram `from` the peer, received
    /// at `now` with ECN bits `ecn`, one after the other
    /// (`ngtcp2_conn_read_pkt` on each): what it read is told to `events`,
    /// in order. The first packet it fails to read is the last read, and
    /// its failure the call's.
    fn read_packets(
        &mut self,
        cx: &mut TlsCx<'_>,
        now: Instant,
        from: SocketAddr,
        ecn: u8,
        packets: std::slice::Chunks<'_, u8>,
        events: Events<'_>,
    ) -> Result<(), QuicError>;

    /// What came in was all read, every datagram the socket had for this
    /// call: what the library holds of it is told to `events` now, for a
    /// library that has no callbacks to tell it as it reads (quiche's
    /// `cf_poll_events`, after `Curl_vquic_recv_packets`).
    fn ingress_done(&mut self, _cx: &mut TlsCx<'_>, _events: Events<'_>) -> Result<(), QuicError> {
        Ok(())
    }

    /// What it had to send went, at `now`: what that came to is told to
    /// `events`, for a library that has no callbacks to tell it (quiche's
    /// connection found established after a connect call's flush,
    /// `cf_quiche_connect`).
    fn egress_done(
        &mut self,
        _cx: &mut TlsCx<'_>,
        _now: Instant,
        _events: Events<'_>,
    ) -> Result<(), QuicError> {
        Ok(())
    }

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

    /// Its TLS session's library objects.
    fn tls_native(&self) -> crate::tls::TlsNative;

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

    /// Take the transport parameters `params`, encoded, which the
    /// session resumed was kept with, as the peer's until it says its own
    /// (`ngtcp2_conn_decode_and_set_0rtt_transport_params`): the
    /// library's words for why not.
    fn set_early_params(&mut self, params: &[u8]) -> Result<(), &'static str>;

    /// Send early data: HTTP/3 set up before the handshake, and the TLS
    /// library told to send it (`init_h3_conn_cb`,
    /// `SSL_set_quic_tls_early_data_enabled`). Whether the TLS library
    /// would; or why HTTP/3 could not be set up.
    fn start_early(&mut self) -> Result<EarlyStart, H3Failed>;

    /// Tell its TLS session whether early data goes under the ticket it
    /// resumed (`QuicTls::early_data_decided`).
    fn early_data_decided(&mut self, cx: &mut TlsCx<'_>, early: bool) -> Result<(), ErrorKind>;

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
    /// The peer's flow control holds the request back for now: it is
    /// submitted again later (quiche's `QUICHE_H3_ERR_STREAM_BLOCKED`,
    /// `error`).
    Blocked {
        error: QuicError,
    },
    /// The HTTP/3 library refused it on `stream`, as the connection is
    /// closing (`NGHTTP3_ERR_CONN_CLOSING`).
    Closing {
        stream: StreamId,
    },
    /// The HTTP/3 library refused it on `stream` for another reason.
    Refused {
        stream: StreamId,
        error: QuicError,
    },
    OutOfMemory,
}

/// The most of a stream's request body a connection holds
/// (`H3_STREAM_SEND_BUFFER_MAX`, ten chunks of 64 KiB).
pub const BODY_HELD: usize = 10 * 64 * 1024;

#[cfg(any(test, feature = "test-util"))]
pub mod fake;

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_macros, clippy::disallowed_methods)]

    use super::QlogDir;
    use crate::options::FileMode;

    /// A directory of the test's own, removed as it goes.
    struct Dir(std::path::PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Named with no link in it: the system counts a name's length with
    /// its links resolved, and macOS's temporary directory is under
    /// `/var`, a link to `/private/var`.
    fn dir(name: &str) -> Dir {
        let d = std::env::temp_dir().join(format!("curl-core-qlog-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        Dir(std::fs::canonicalize(&d).unwrap())
    }

    /// `QLOGDIR` unset or empty names no directory, as `curl_getenv`
    /// gives neither; any other value names one.
    #[test]
    fn qlogdir_unset_or_empty_names_none() {
        let mode = FileMode::default();
        assert!(QlogDir::from_value(None, mode).is_none());
        assert!(QlogDir::from_value(Some(b""), mode).is_none());
        let dir = QlogDir::from_value(Some(b"/q"), mode).unwrap();
        assert_eq!(&dir.name[..dir.len], b"/q/");
        assert_eq!(format!("{dir:?}"), "QlogDir(/q/)");
    }

    /// The file is `<dir>/<source id in lower-case hex>.sqlog`, as
    /// `Curl_qlogdir` names it.
    #[test]
    fn a_qlog_is_named_after_the_source_id_in_hex() {
        let d = dir("name");
        let qlog = QlogDir::new(d.0.as_os_str().as_encoded_bytes(), FileMode::default()).unwrap();
        assert!(qlog.open(&[0x00, 0x0a, 0xb1, 0xff]).is_some());
        let names: Vec<_> = std::fs::read_dir(&d.0)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["000ab1ff.sqlog"]);
    }

    /// A file is created with the handle's permissions, before the umask.
    #[cfg(unix)]
    #[test]
    fn a_qlog_is_created_with_the_permissions_given() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = dir("mode");
        let mode = FileMode::new(0o600).unwrap();
        let qlog = QlogDir::new(d.0.as_os_str().as_encoded_bytes(), mode).unwrap();
        let file = qlog.open(&[0x42]).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// A name longer than C's buffer for it holds opens no file
    /// (`DYN_QLOG_NAME`): the longest is 1023 bytes.
    #[test]
    fn a_qlog_name_too_long_opens_none() {
        let d = dir("long");
        let base = d.0.as_os_str().as_encoded_bytes();
        // `<base>/x...x` with a 1-byte source id: `/`, 2 digits, `.sqlog`.
        let fill = |total: usize| {
            let mut dir = base.to_vec();
            dir.push(b'/');
            dir.resize(total - (1 + 2 + 6), b'x');
            dir
        };
        // Made as a chain of directories no longer than the system's
        // longest component.
        let made: Vec<u8> = fill(1023)
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if i > base.len() && i % 200 == 0 {
                    b'/'
                } else {
                    b
                }
            })
            .collect();
        std::fs::create_dir_all(String::from_utf8(made.clone()).unwrap()).unwrap();
        let fits = QlogDir::new(&made, FileMode::default()).unwrap();
        assert!(fits.open(&[0x01]).is_some());
        assert!(fits.open(&[0x01, 0x02]).is_none());
        // One byte more, in a directory that is there.
        let mut over = made.clone();
        over.push(b'x');
        std::fs::create_dir_all(String::from_utf8(over.clone()).unwrap()).unwrap();
        let over = QlogDir::new(&over, FileMode::default()).unwrap();
        assert!(over.open(&[0x01]).is_none());
    }
}
