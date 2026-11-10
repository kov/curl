//! HTTP/3 over QUIC from quiche, as C's `lib/vquic/cf-quiche.c` uses it:
//! a client connection with C's settings, over the TLS session the
//! OpenSSL backend made for it, which quiche takes and frees (C's
//! `quiche_conn_new_with_tls`), its HTTP/3 set up once the connection is
//! established and the peer checked.
//!
//! quiche runs over BoringSSL alone (C's CMake: "quiche requires
//! BoringSSL"): the one the OpenSSL backend links, the program's only
//! copy, quiche built without its own. Over another the crate is empty.
//!
//! quiche has no callbacks: what it read is polled once a call has fed
//! it, stream by stream, and told to the caller as C's filter hands it
//! to the stream's transfer (`cf_poll_events`). Each call that may move
//! the handshake on runs inside the session's `QuicTls::drive`, as the
//! session's own callbacks (the key log, its trust store) reach the
//! transfer through it.

#![cfg(boringssl)]

mod tls;

// The BoringSSL quiche calls, linked as curl-openssl links it.
extern crate openssl_sys;

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _, try_box};
use curl_core::error::ErrorKind;
use curl_core::http3::{
    ClientSetup, CloseError, CloseKind, ConnEvent, ConnectFailed, EarlyStart, Event, Events,
    Expiry, Flavour, H3Error, H3Failed, Heard, Http3, Layer, QuicError, StreamEvent, StreamId,
    SubmitFailed,
};
use curl_core::time::Instant;
use curl_core::tls::{DriveCall, QuicTls, TlsCx, TlsKind, TlsNative};
use quiche::h3::NameValue as _;

/// Run `f`, a call into quiche, its allocations kept from the debug
/// build's tracker: they are the library's, as C's quiche makes them in
/// its own library, unseen by curl's memory debugging. What the TLS
/// library calls back into the session while quiche runs goes untracked
/// with it.
fn quiet<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(feature = "debug-hooks")]
    return curl_alloc::track::untracked(f);
    #[cfg(not(feature = "debug-hooks"))]
    f()
}

/// The library, as the handles are given it.
pub static QUICHE: Quiche = Quiche;

/// quiche, as a library the core speaks HTTP/3 through.
#[derive(Debug)]
pub struct Quiche;

/// Why a session of a library quiche does not run over is refused.
const OTHER_LIBRARY: &str = "quiche runs over OpenSSL's TLS alone";

impl Http3 for Quiche {
    fn client(
        &self,
        setup: &ClientSetup,
        tls: Box<dyn QuicTls>,
    ) -> Result<Box<dyn curl_core::http3::Connection>, ConnectFailed> {
        let conn = Connection::client(setup, tls)?;
        Ok(try_box(conn)?)
    }

    fn version(&self) -> &dyn fmt::Display {
        &Version
    }

    fn flavour(&self) -> Flavour {
        Flavour::Quiche
    }
}

/// The library's name and version, as curl's version says it:
/// `quiche/0.30.0`.
pub fn version() -> impl fmt::Display {
    Version
}

struct Version;

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "quiche/{}", quiche_version())
    }
}

/// The library's version, as it says it (`quiche_version`).
pub fn quiche_version() -> &'static str {
    tls::version()
}

/// The streams the peer may open of each kind (`QUIC_MAX_STREAMS`).
const MAX_STREAMS: u64 = 100;
/// A stream's receive window (`H3_STREAM_WINDOW_SIZE`).
const STREAM_WINDOW: u64 = 128 * 1024;
/// The connection's first receive window.
const MAX_DATA: u64 = 1024 * 1024;
/// The packets sent in one go (`MAX_PKT_BURST`).
const BURST: usize = 10;
/// The most a response's head may be, as curl takes it
/// (`MAX_HTTP_RESP_HEADER_SIZE`): quiche's own limit is smaller.
const MAX_HEAD: u64 = 300 * 1024;
/// What a body is written to the transfer in, the most at a time
/// (`H3_STREAM_CHUNK_SIZE`), and how much is read before it is
/// (`H3_STREAM_RECV_CHUNKS` of them).
const CHUNK: usize = 16 * 1024;
const BODY_ROOM: usize = 128 * 1024;
const _: () = assert!(BODY_ROOM == 8 * CHUNK);
/// A packet's room: the largest UDP payload.
const PACKET: usize = 65527;

/// The id quiche gave a stream it opened.
fn quiche_id(stream: StreamId) -> u64 {
    u64::try_from(stream.0).expect("a stream quiche opened")
}

/// quiche's number for a failure of its QUIC half, as C's traces print
/// it (`quiche_error`).
fn quic_code(e: quiche::Error) -> i32 {
    use quiche::Error as E;
    match e {
        E::Done => -1,
        E::BufferTooShort => -2,
        E::UnknownVersion => -3,
        E::InvalidFrame => -4,
        E::InvalidPacket => -5,
        E::InvalidState => -6,
        E::InvalidStreamState { .. } => -7,
        E::InvalidTransportParam => -8,
        E::CryptoFail => -9,
        E::TlsFail => -10,
        E::FlowControl => -11,
        E::StreamLimit => -12,
        E::FinalSize => -13,
        E::CongestionControl => -14,
        E::StreamStopped { .. } => -15,
        E::StreamReset { .. } => -16,
        E::IdLimit => -17,
        E::OutOfIdentifiers => -18,
        E::KeyUpdate => -19,
        E::CryptoBufferExceeded => -20,
        E::InvalidAckRange => -21,
        E::OptimisticAckDetected => -22,
        E::InvalidDcidInitialization => -23,
    }
}

/// quiche's number for a failure of its HTTP/3 half (`quiche_h3_error`).
fn h3_code(e: quiche::h3::Error) -> i32 {
    use quiche::h3::Error as E;
    match e {
        E::Done => -1,
        E::BufferTooShort => -2,
        E::InternalError => -3,
        E::ExcessiveLoad => -4,
        E::IdError => -5,
        E::StreamCreationError => -6,
        E::ClosedCriticalStream => -7,
        E::MissingSettings => -8,
        E::FrameUnexpected => -9,
        E::FrameError => -10,
        E::QpackDecompressionFailed => -11,
        E::StreamBlocked => -13,
        E::SettingsError => -14,
        E::RequestRejected => -15,
        E::RequestCancelled => -16,
        E::RequestIncomplete => -17,
        E::MessageError => -18,
        E::ConnectError => -19,
        E::VersionFallback => -20,
        E::TransportError(e) => quic_code(e) - 1000,
    }
}

fn quic_error(layer: Layer, call: &'static str, e: quiche::Error) -> QuicError {
    QuicError {
        layer,
        call,
        code: quic_code(e),
        text: "",
    }
}

fn h3_error(call: &'static str, e: quiche::h3::Error) -> QuicError {
    QuicError {
        layer: Layer::Http3,
        call,
        code: h3_code(e),
        text: "",
    }
}

/// A connection's failure said in C's words, which the caller says.
fn said(call: &'static str, text: &'static str) -> QuicError {
    QuicError {
        layer: Layer::Quic,
        call,
        code: 0,
        text,
    }
}

/// Tell the caller `event`, with the transfer the call reaches.
fn tell(call: &mut dyn DriveCall, events: Events<'_>, event: Event<'_>) -> Heard {
    let mut heard = Heard::Fine;
    call.with_cx(&mut |cx| heard = events(cx, &event));
    heard
}

/// Trace `line` on the transfer the call reaches.
fn trace(call: &mut dyn DriveCall, line: fmt::Arguments<'_>) {
    call.with_cx(&mut |cx| cx.trace(line));
}

/// A header field is one C hands on: no CR, LF or NUL in it
/// (`is_valid_h3_header`).
fn valid(field: &[u8]) -> bool {
    !field.iter().any(|&b| matches!(b, b'\n' | b'\r' | 0))
}

/// One client connection: quiche's, its HTTP/3 once connected, and the
/// TLS session whose SSL quiche holds.
pub struct Connection {
    // Dropped in this order: HTTP/3, then the QUIC connection, which frees
    // the session's SSL and the BIO it owns, then the session, whose
    // context, callbacks and BIO method the SSL used until then.
    h3: Option<quiche::h3::Connection>,
    quic: Box<quiche::Connection>,
    tls: Box<dyn QuicTls>,
    h3_config: quiche::h3::Config,
    /// The socket's own end, which each datagram came to.
    local: SocketAddr,
    /// When the connect started, the handshake's time measured from.
    started: Instant,
    /// The connection is established, and the caller was told.
    established: bool,
    /// The streams opened, and the peer's room for more as the caller
    /// was last told it.
    opened: u64,
    left: Option<u64>,
    /// The peer said GOAWAY: no stream opens after.
    goaway: bool,
    /// The streams open, and those of them waiting on quiche.
    streams: Streams,
    /// Where a packet is read: quiche decrypts it in place.
    packet: Vec<u8>,
    /// Where a body is read.
    body: Vec<u8>,
    /// quiche read packets since HTTP/3 was last polled.
    read_any: bool,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("established", &self.established)
            .field("opened", &self.opened)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// The session, the room a packet is read into, and the rest a call
    /// into quiche reaches.
    fn parts(&mut self) -> (&mut Box<dyn QuicTls>, &mut Vec<u8>, Parts<'_>) {
        let Connection {
            h3,
            quic,
            tls,
            h3_config,
            started,
            established,
            opened,
            left,
            goaway,
            streams,
            packet,
            body,
            read_any,
            ..
        } = self;
        let parts = Parts {
            h3,
            quic,
            h3_config,
            started: *started,
            established,
            opened: *opened,
            left,
            goaway,
            streams,
            body,
            read_any,
        };
        (tls, packet, parts)
    }

    /// A client connection over `tls`, with C's settings
    /// (`cf_quiche_ctx_open`): quiche takes the session's SSL, whatever
    /// comes of its making.
    fn client(setup: &ClientSetup, mut tls: Box<dyn QuicTls>) -> Result<Connection, ConnectFailed> {
        let crypto = |why| ConnectFailed::Crypto { why };
        // quiche runs over OpenSSL's family alone: a session of another
        // library is refused before any of it is read.
        if tls.native().kind() != TlsKind::OpenSsl || tls.quiche().is_none() {
            return Err(crypto(OTHER_LIBRARY));
        }
        let mut config = quiet(|| quiche::Config::new(quiche::PROTOCOL_VERSION))
            .map_err(|_| crypto("cannot create quiche config"))?;
        config.enable_pacing(false);
        config.set_initial_max_data(MAX_DATA);
        config.set_initial_max_streams_bidi(MAX_STREAMS);
        config.set_initial_max_streams_uni(MAX_STREAMS);
        config.set_initial_max_stream_data_bidi_local(STREAM_WINDOW);
        config.set_initial_max_stream_data_bidi_remote(STREAM_WINDOW);
        config.set_initial_max_stream_data_uni(STREAM_WINDOW);
        config.set_disable_active_migration(true);
        config.set_max_connection_window(10 * MAX_STREAMS * STREAM_WINDOW);
        config.set_max_stream_window(10 * STREAM_WINDOW);
        quiet(|| config.set_application_protos(&[b"h3"]))
            .map_err(|_| crypto("cannot create quiche config"))?;
        let mut h3_config =
            quiet(quiche::h3::Config::new).map_err(|_| ConnectFailed::OutOfMemory)?;
        // quiche rejects a head over 32 KiB of its own: as much as curl
        // takes (`quiche_h3_config_set_max_field_section_size`).
        h3_config.set_max_field_section_size(MAX_HEAD);
        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        curl_os::random::fill(&mut scid).map_err(|_| ConnectFailed::Refused)?;
        let mut packet = Vec::new();
        packet.try_resize(PACKET, 0)?;
        let ssl = tls
            .quiche()
            .expect("checked as it was handed")
            .give_up_session();
        let mut quic = quiet(|| tls::connect(&scid, setup.local, setup.remote, &config, ssl))
            .ok_or(ConnectFailed::OutOfMemory)?;
        // The qlog, named after the source id (`Curl_qlogdir`), handed to
        // quiche if the file opened, as `quiche_conn_set_qlog_fd` hands
        // it; not on Windows, where C's says it does not work.
        #[cfg(not(windows))]
        if let Some(file) = setup.qlog.as_ref().and_then(|dir| dir.open(&scid)) {
            set_qlog(&mut quic, file);
        }
        Ok(Connection {
            h3: None,
            quic,
            tls,
            h3_config,
            local: setup.local,
            started: setup.now,
            established: false,
            opened: 0,
            left: None,
            goaway: false,
            streams: Streams::default(),
            packet,
            body: Vec::new(),
            read_any: false,
        })
    }
}

/// Have quiche write the qlog of `quic` to `file`, buffered, under the
/// title and description C's filter gives it (`quiche_conn_set_qlog_fd`,
/// which adds the connection's trace id). Memory short for the two
/// leaves it without one, as C's `Curl_qlogdir` does for its name.
#[cfg(not(windows))]
fn set_qlog(quic: &mut quiche::Connection, file: std::fs::File) {
    let title = curl_alloc::try_format(format_args!("qlog title"));
    let description = curl_alloc::try_format(format_args!("curl qlog id={}", quic.trace_id()));
    let (Ok(title), Ok(description)) = (title, description) else {
        return;
    };
    // The writer and what quiche makes of it are quiche's, as when its
    // own C call makes them.
    quiet(|| {
        let writer = std::io::BufWriter::new(file);
        if let Ok(writer) = try_box(writer) {
            quic.set_qlog(writer, title, description);
        }
    });
}

/// The streams the connection opened and quiche has not ended, and those
/// of them waiting on quiche: room for each open stream in each list is
/// made as it opens, so that joining one never fails.
#[derive(Default)]
struct Streams {
    live: Vec<StreamId>,
    /// Those quiche held a body back on, told when packets next came
    /// (`cf_quiche_do_resume`).
    blocked: Vec<StreamId>,
    /// Those whose body ends once quiche takes the end.
    ends: Vec<StreamId>,
}

impl Streams {
    /// Room for one more stream in each list, made before it opens.
    fn make_room(&mut self) -> Result<(), OutOfMemory> {
        let want = self.live.len() + 1;
        for list in [&mut self.live, &mut self.blocked, &mut self.ends] {
            list.try_reserve(want - list.len())
                .map_err(|_| OutOfMemory)?;
        }
        Ok(())
    }

    fn opened(&mut self, stream: StreamId) {
        self.live.try_push(stream).expect("room made as it opened");
    }

    /// `stream` in `list`, once, if it is open.
    fn join(live: &[StreamId], list: &mut Vec<StreamId>, stream: StreamId) {
        if live.contains(&stream) && !list.contains(&stream) {
            list.try_push(stream).expect("room made as it opened");
        }
    }

    fn block(&mut self, stream: StreamId) {
        Self::join(&self.live, &mut self.blocked, stream);
    }

    fn end(&mut self, stream: StreamId) {
        Self::join(&self.live, &mut self.ends, stream);
    }

    /// quiche is done with `stream`, or the request with it.
    fn ended(&mut self, stream: StreamId) {
        for list in [&mut self.live, &mut self.blocked, &mut self.ends] {
            list.retain(|&s| s != stream);
        }
    }
}

/// What a call came to as quiche read a datagram's packets.
enum Read {
    /// All read, or what was left dropped as quiche had done.
    Fine,
    /// The connection failed: closed or draining, or quiche refused.
    Failed(QuicError),
    /// The handshake's TLS failed: the peer's chain may be why.
    Tls,
}

/// The parts of a connection a call into quiche reaches, apart from the
/// session that drives it.
struct Parts<'c> {
    h3: &'c mut Option<quiche::h3::Connection>,
    quic: &'c mut quiche::Connection,
    h3_config: &'c quiche::h3::Config,
    started: Instant,
    established: &'c mut bool,
    opened: u64,
    left: &'c mut Option<u64>,
    goaway: &'c mut bool,
    streams: &'c mut Streams,
    body: &'c mut Vec<u8>,
    read_any: &'c mut bool,
}

impl Parts<'_> {
    /// Once established, the peer checked, said as quiche's filter says
    /// it, then HTTP/3 set up over it (`cf_quiche_connect`).
    fn connected(&mut self, call: &mut dyn DriveCall, now: Instant, events: Events<'_>) -> Heard {
        if *self.established || !self.quic.is_established() {
            return Heard::Fine;
        }
        *self.established = true;
        let ms = now.ms_since(self.started);
        trace(call, format_args!("handshake complete after {ms}ms"));
        let checked = call.handshake_done();
        let event = ConnEvent::HandshakeDone {
            checked,
            max_udp_payload: 0,
            initial_max_data: 0,
            early_data: None,
        };
        // A peer that failed its check fails the connect, as the event
        // says: no HTTP/3 is set up over it.
        if tell(call, events, Event::Connection(event)) == Heard::Failed {
            return Heard::Failed;
        }
        if checked.is_err() {
            return Heard::Fine;
        }
        match quiet(|| quiche::h3::Connection::with_transport(self.quic, self.h3_config)) {
            Ok(h3) => {
                *self.h3 = Some(h3);
                Heard::Fine
            }
            Err(_) => {
                let failed = H3Failed {
                    why: "quiche_h3_conn_new_with_transport failed",
                    detail: None,
                    out_of_memory: true,
                };
                tell(call, events, Event::Connection(ConnEvent::H3Failed(failed)));
                Heard::Failed
            }
        }
    }

    /// Packets came: the streams quiche held back may send again
    /// (`cf_quiche_do_resume`).
    fn resume(&mut self, call: &mut dyn DriveCall, events: Events<'_>) {
        // Each told once; the list keeps its room.
        while let Some(stream) = self.streams.blocked.pop() {
            tell(call, events, Event::Stream(stream, StreamEvent::Unblocked));
        }
    }

    /// The peer's room for streams, told when it changed.
    fn streams_left(&mut self, call: &mut dyn DriveCall, events: Events<'_>) {
        if self.h3.is_none() {
            return;
        }
        let left = if *self.goaway {
            0
        } else {
            self.quic.peer_streams_left_bidi()
        };
        if *self.left != Some(left) {
            *self.left = Some(left);
            let n = self.opened + left;
            tell(
                call,
                events,
                Event::Connection(ConnEvent::MaxBidiStreams(n)),
            );
        }
    }

    /// What HTTP/3 read, polled and told stream by stream
    /// (`cf_poll_events`).
    fn poll(&mut self, call: &mut dyn DriveCall, events: Events<'_>) -> Result<(), QuicError> {
        loop {
            let Some(h3) = self.h3.as_mut() else {
                return Ok(());
            };
            let (id, event) = match quiet(|| h3.poll(self.quic)) {
                Ok(polled) => polled,
                Err(quiche::h3::Error::Done) => return Ok(()),
                Err(e) => {
                    let rv = h3_code(e);
                    trace(call, format_args!("error poll: {rv}"));
                    return Err(h3_error("quiche_h3_conn_poll", e));
                }
            };
            let stream = StreamId(i64::try_from(id).unwrap_or(i64::MAX));
            // A transfer that failed writing has its call fail with its
            // own failure; the rest waits for the next poll
            // (`stream->xfer_result`).
            if self.event(call, events, stream, event) == Heard::Failed {
                return Ok(());
            }
        }
    }

    /// One event of `stream`'s, told (`cf_quiche_process_ev`).
    fn event(
        &mut self,
        call: &mut dyn DriveCall,
        events: Events<'_>,
        stream: StreamId,
        event: quiche::h3::Event,
    ) -> Heard {
        let id = stream.0;
        match event {
            quiche::h3::Event::Headers { list, .. } => {
                for field in &list {
                    let (name, value) = (field.name(), field.value());
                    let status = name == b":status";
                    if !valid(value) || (!status && !valid(name)) {
                        let n = name.len() + value.len();
                        trace(call, format_args!("[{id}] ignore {n} bytes bad header"));
                        continue;
                    }
                    let header = StreamEvent::Header {
                        name,
                        value,
                        status,
                    };
                    if tell(call, events, Event::Stream(stream, header)) == Heard::Failed {
                        return Heard::Failed;
                    }
                }
                tell(
                    call,
                    events,
                    Event::Stream(stream, StreamEvent::HeadersDone),
                )
            }
            quiche::h3::Event::Data => self.data(call, events, stream),
            quiche::h3::Event::Finished => {
                self.streams.ended(stream);
                let closed = StreamEvent::Closed(H3Error::NO_ERROR);
                tell(call, events, Event::Stream(stream, closed))
            }
            quiche::h3::Event::Reset(code) => {
                self.streams.ended(stream);
                let closed = StreamEvent::Closed(H3Error(code));
                tell(call, events, Event::Stream(stream, closed))
            }
            quiche::h3::Event::GoAway => {
                *self.goaway = true;
                trace(call, format_args!("[{id}] <- [GOAWAY]"));
                Heard::Fine
            }
            quiche::h3::Event::PriorityUpdate => {
                // C's number for the event (`QUICHE_H3_EVENT_PRIORITY_UPDATE`).
                trace(call, format_args!("[{id}] recv, unhandled event 5"));
                Heard::Fine
            }
        }
    }

    /// `stream`'s body, read until quiche has no more, C's buffer of
    /// eight chunks at a time, each buffer told a chunk at a time; read
    /// whatever the transfer makes of it, as quiche otherwise raises the
    /// event over and over (`cf_quiche_recv_body`, `cf_quiche_flush_body`).
    /// Any failure of quiche's to read is the end of what there is now,
    /// as C reads it; memory for the buffer failing is the stream's.
    fn data(&mut self, call: &mut dyn DriveCall, events: Events<'_>, stream: StreamId) -> Heard {
        let h3 = self.h3.as_mut().expect("polled over HTTP/3");
        let mut heard = Heard::Fine;
        loop {
            self.body.clear();
            let (mut more, mut oom) = (true, false);
            while more && self.body.len() < BODY_ROOM {
                let at = self.body.len();
                let room = CHUNK - at % CHUNK;
                if self.body.try_resize(at + room, 0).is_err() {
                    self.body.truncate(at);
                    oom = true;
                    break;
                }
                let into = &mut self.body[at..];
                let read = quiet(|| h3.recv_body(self.quic, quiche_id(stream), into));
                let n = read.unwrap_or(0);
                self.body.truncate(at + n);
                more = n > 0;
            }
            for piece in self.body.chunks(CHUNK) {
                if heard == Heard::Fine {
                    let piece = StreamEvent::Data(piece);
                    heard = tell(call, events, Event::Stream(stream, piece));
                }
            }
            if oom {
                let (id, rv) = (stream.0, ErrorKind::OutOfMemory.number());
                trace(call, format_args!("[{id}] recv_body error {rv}"));
                call.with_cx(&mut |cx| {
                    cx.fail(
                        ErrorKind::OutOfMemory,
                        format_args!("[{id}] Error {rv} in HTTP/3 response body for stream"),
                    );
                });
                // Its end said as a reset, H3_INTERNAL_ERROR (`stream->reset`).
                let ended = StreamEvent::Closed(H3Error(0x102));
                tell(call, events, Event::Stream(stream, ended));
                return Heard::Failed;
            }
            if !more {
                return heard;
            }
        }
    }
}

impl curl_core::http3::Connection for Connection {
    /// Each packet to quiche, its failure said as C's filter says it
    /// (`cf_quiche_recv_pkts`): what it read is told once all came in.
    fn read_packets(
        &mut self,
        cx: &mut TlsCx<'_>,
        _now: Instant,
        from: SocketAddr,
        _ecn: u8,
        packets: std::slice::Chunks<'_, u8>,
        _events: Events<'_>,
    ) -> Result<(), QuicError> {
        let local = self.local;
        let (tls, packet, parts) = self.parts();
        let mut read = Read::Fine;
        tls.drive(cx, &mut || None, &mut |call| {
            let mut pkts = 0usize;
            for bytes in packets.clone() {
                let room = &mut packet[..bytes.len()];
                room.copy_from_slice(bytes);
                let info = quiche::RecvInfo { from, to: local };
                match quiet(|| parts.quic.recv(room, info)) {
                    Ok(n) => {
                        if n < bytes.len() {
                            let len = bytes.len();
                            trace(
                                call,
                                format_args!("ingress, quiche only read {n}/{len} bytes"),
                            );
                        }
                        pkts += 1;
                    }
                    Err(quiche::Error::Done) => {
                        if parts.quic.is_draining() {
                            trace(call, format_args!("ingress, connection is draining"));
                            read = Read::Failed(said("quiche_conn_recv", "draining"));
                        } else if parts.quic.is_closed() {
                            trace(call, format_args!("ingress, connection is closed"));
                            read = Read::Failed(said("quiche_conn_recv", "closed"));
                        } else {
                            trace(call, format_args!("ingress, quiche is DONE"));
                        }
                        break;
                    }
                    Err(quiche::Error::TlsFail) => {
                        read = Read::Tls;
                        break;
                    }
                    Err(e) => {
                        let rv = quic_code(e);
                        call.with_cx(&mut |cx| {
                            cx.fail(
                                ErrorKind::RecvError,
                                format_args!("quiche reports error {rv} on receive"),
                            );
                        });
                        read = Read::Failed(quic_error(Layer::Quic, "quiche_conn_recv", e));
                        break;
                    }
                }
            }
            *parts.read_any |= pkts > 0;
        });
        match read {
            Read::Fine => Ok(()),
            Read::Failed(error) => Err(error),
            // A peer the TLS library's own check failed, said so; else
            // the handshake failed otherwise (`cf_quiche_recv_pkts`).
            Read::Tls => match tls.quiche().expect("checked at connect").unverified(cx) {
                Some(_) => Err(quic_error(
                    Layer::Crypto,
                    "quiche_conn_recv",
                    quiche::Error::TlsFail,
                )),
                None => {
                    cx.fail(
                        ErrorKind::RecvError,
                        format_args!("ingress, quiche reports TLS fail"),
                    );
                    Err(quic_error(
                        Layer::Quic,
                        "quiche_conn_recv",
                        quiche::Error::TlsFail,
                    ))
                }
            },
        }
    }

    /// Streams quiche held back may send again once it read packets, and
    /// what HTTP/3 read is polled (`cf_process_ingress`).
    fn ingress_done(&mut self, cx: &mut TlsCx<'_>, events: Events<'_>) -> Result<(), QuicError> {
        let (tls, _, mut parts) = self.parts();
        let mut polled = Ok(());
        tls.drive(cx, &mut || None, &mut |call| {
            if std::mem::take(parts.read_any) {
                parts.resume(call, events);
            }
            polled = parts.poll(call, events);
            parts.streams_left(call, events);
        });
        polled
    }

    /// What was read and sent may have established the connection,
    /// checked as C's filter checks it after each flush while it connects
    /// (`cf_quiche_connect`).
    fn egress_done(
        &mut self,
        cx: &mut TlsCx<'_>,
        now: Instant,
        events: Events<'_>,
    ) -> Result<(), QuicError> {
        let (tls, _, mut parts) = self.parts();
        let mut done = Ok(());
        tls.drive(cx, &mut || None, &mut |call| {
            if parts.connected(call, now, events) == Heard::Failed {
                done = Err(said("quiche_conn_is_established", "callback failure"));
            }
        });
        done
    }

    /// The next packet quiche has to send, the ends of bodies it held
    /// back offered again first (`read_pkt_to_send`).
    fn write_packet(
        &mut self,
        cx: &mut TlsCx<'_>,
        _now: Instant,
        buf: &mut [u8],
        _events: Events<'_>,
    ) -> Result<Option<usize>, QuicError> {
        let (tls, _, parts) = self.parts();
        let mut wrote = Ok(None);
        tls.drive(cx, &mut || None, &mut |_| {
            if let Some(h3) = parts.h3.as_mut() {
                parts.streams.ends.retain(|&stream| {
                    matches!(
                        quiet(|| h3.send_body(parts.quic, quiche_id(stream), &[], true)),
                        Err(quiche::h3::Error::Done)
                    )
                });
            }
            wrote = match quiet(|| parts.quic.send(buf)) {
                Ok((n, _)) => Ok(Some(n)),
                Err(quiche::Error::Done) => Ok(None),
                Err(e) => Err(quic_error(Layer::Quic, "quiche_conn_send", e)),
            };
        });
        wrote
    }

    fn before_recv(&mut self, cx: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        self.tls.before_recv(cx)
    }

    fn tls_native(&self) -> TlsNative {
        self.tls.native()
    }

    fn sent_at(&mut self, _now: Instant) {}

    fn max_payload(&self) -> usize {
        self.quic.max_send_udp_payload_size()
    }

    fn path_max_payload(&self) -> usize {
        self.quic.max_send_udp_payload_size()
    }

    /// C's burst of packets (`MAX_PKT_BURST`), each as large as quiche
    /// sends.
    fn send_quantum(&self) -> usize {
        BURST * self.quic.max_send_udp_payload_size()
    }

    fn expiry(&self, _now: Instant) -> Expiry {
        match self.quic.timeout() {
            None => Expiry::Never,
            Some(wait) if wait.is_zero() => Expiry::Due,
            Some(wait) => Expiry::In(wait),
        }
    }

    /// quiche's timers run; a connection they closed fails the call, and
    /// every transfer on it (`cf_flush_egress`).
    fn handle_expiry(
        &mut self,
        cx: &mut TlsCx<'_>,
        _now: Instant,
        _events: Events<'_>,
    ) -> Result<(), QuicError> {
        let Connection { quic, tls, .. } = self;
        let mut closed = None;
        tls.drive(cx, &mut || None, &mut |call| {
            quiet(|| quic.on_timeout());
            if quic.is_closed() {
                closed = Some(if quic.is_timed_out() {
                    "connection closed by idle timeout"
                } else {
                    "connection closed by server"
                });
                trace(call, format_args!("conn closed, expire all transfers"));
            }
        });
        match closed {
            Some(why) => Err(said("quiche_conn_on_timeout", why)),
            None => Ok(()),
        }
    }

    /// Established, the peer checked and HTTP/3 set up over it.
    fn handshake_done(&self) -> bool {
        self.h3.is_some()
    }

    /// quiche's filter sends no early data: no session it resumes asks.
    fn set_early_params(&mut self, _params: &[u8]) -> Result<(), &'static str> {
        Err("quiche sends no early data")
    }

    fn start_early(&mut self) -> Result<EarlyStart, H3Failed> {
        unreachable!("quiche's filter sends no early data")
    }

    fn early_data_decided(&mut self, cx: &mut TlsCx<'_>, early: bool) -> Result<(), ErrorKind> {
        self.tls.early_data_decided(cx, early)
    }

    fn draining(&self) -> bool {
        self.quic.is_draining()
    }

    /// None the filter weighs: quiche closes an idle connection itself.
    fn peer_idle_timeout(&self) -> Option<Duration> {
        None
    }

    fn set_keep_alive(&mut self, _every: Option<Duration>) {}

    /// The connection itself never holds sending back as C's filter weighs
    /// it (`cf_quiche_adjust_pollset`'s `c_exhaust`).
    fn send_room(&self) -> bool {
        true
    }

    /// quiche's filter closes no connection for a call that failed.
    fn failed(&mut self, _error: QuicError) -> bool {
        false
    }

    /// The application's, no error (`quiche_conn_close(qconn, TRUE, 0)`).
    fn close_error(&self) -> CloseError {
        CloseError {
            kind: CloseKind::Application,
            code: 0,
        }
    }

    /// Once quiche closed it: what the peer or it closed it with, or its
    /// idle timeout.
    fn closed_with(&self) -> Option<CloseError> {
        if !self.quic.is_closed() {
            return None;
        }
        if self.quic.is_timed_out() {
            return Some(CloseError {
                kind: CloseKind::IdleClose,
                code: 0,
            });
        }
        let error = self.quic.peer_error().or(self.quic.local_error());
        Some(error.map_or(
            CloseError {
                kind: CloseKind::DropConn,
                code: 0,
            },
            |e| CloseError {
                kind: if e.is_app {
                    CloseKind::Application
                } else {
                    CloseKind::Transport
                },
                code: e.error_code,
            },
        ))
    }

    /// quiche told to close, as the application with no error; the packet
    /// that says so written into `buf` if it has room
    /// (`cf_quiche_shutdown`).
    fn write_close(&mut self, _now: Instant, buf: &mut [u8]) -> Result<usize, QuicError> {
        match quiet(|| self.quic.close(true, 0, b"")) {
            Ok(()) | Err(quiche::Error::Done) => {}
            Err(e) => return Err(quic_error(Layer::Quic, "quiche_conn_close", e)),
        }
        if buf.is_empty() {
            return Ok(0);
        }
        match quiet(|| self.quic.send(buf)) {
            Ok((n, _)) => Ok(n),
            Err(quiche::Error::Done) => Ok(0),
            Err(e) => Err(quic_error(Layer::Quic, "quiche_conn_send", e)),
        }
    }

    /// The request's fields sent at once, the stream ended with them
    /// unless a body follows (`quiche_h3_send_request`).
    fn submit_request(
        &mut self,
        fields: &[(&[u8], &[u8])],
        body: bool,
    ) -> Result<StreamId, SubmitFailed> {
        let oom = |_| SubmitFailed::OutOfMemory;
        self.streams
            .make_room()
            .map_err(|OutOfMemory| SubmitFailed::OutOfMemory)?;
        let mut headers = Vec::new();
        headers.try_reserve_exact(fields.len()).map_err(oom)?;
        for &(name, value) in fields {
            headers
                .try_push(quiche::h3::HeaderRef::new(name, value))
                .map_err(|_| SubmitFailed::OutOfMemory)?;
        }
        let quic = &mut *self.quic;
        let h3 = self.h3.as_mut().expect("requests go once HTTP/3 is set up");
        let sent = quiet(|| h3.send_request(quic, &headers, !body));
        match sent {
            Ok(id) => {
                self.opened += 1;
                let stream = StreamId(i64::try_from(id).unwrap_or(i64::MAX));
                self.streams.opened(stream);
                Ok(stream)
            }
            Err(e @ quiche::h3::Error::StreamBlocked) => Err(SubmitFailed::Blocked {
                error: h3_error("quiche_h3_send_request", e),
            }),
            Err(e) => Err(SubmitFailed::Refused {
                stream: StreamId(-1),
                error: h3_error("quiche_h3_send_request", e),
            }),
        }
    }

    /// What of `bytes` quiche takes of the body now: it holds them, none
    /// if its flow control holds the stream back (`cf_quiche_send_body`).
    fn write_body(&mut self, stream: StreamId, bytes: &[u8]) -> Result<usize, OutOfMemory> {
        let quic = &mut *self.quic;
        let h3 = self.h3.as_mut().expect("bodies go once HTTP/3 is set up");
        // A stream the peer stopped or reset takes nothing either: the
        // peer's word for it comes as the connection next reads.
        let n = quiet(|| h3.send_body(quic, quiche_id(stream), bytes, false)).unwrap_or_default();
        if n == 0 && !bytes.is_empty() {
            self.streams.block(stream);
        }
        Ok(n)
    }

    /// The body's end, offered now and again as packets are written
    /// until quiche takes it (`CF_CTRL_DATA_DONE_SEND`).
    fn end_body(&mut self, stream: StreamId) {
        let quic = &mut *self.quic;
        let h3 = self.h3.as_mut().expect("bodies go once HTTP/3 is set up");
        if let Err(quiche::h3::Error::Done) =
            quiet(|| h3.send_body(quic, quiche_id(stream), &[], true))
        {
            self.streams.end(stream);
        }
    }

    /// quiche holds what it took: none in flight but it.
    fn body_in_flight(&self, _stream: StreamId) -> usize {
        0
    }

    fn body_buffered(&self, _stream: StreamId) -> usize {
        0
    }

    fn resume(&mut self, _stream: StreamId) {}

    /// Shut both ways (`cf_quiche_stream_close`): quiche says nothing of
    /// it after.
    fn cancel(&mut self, stream: StreamId, error: H3Error) {
        let Ok(id) = u64::try_from(stream.0) else {
            return;
        };
        self.streams.ended(stream);
        for how in [quiche::Shutdown::Read, quiche::Shutdown::Write] {
            match quiet(|| self.quic.stream_shutdown(id, how, error.0)) {
                // A side already shut, or a stream quiche is done with,
                // is shut: C's filter heeds neither.
                Ok(()) | Err(quiche::Error::Done | quiche::Error::InvalidStreamState(_)) => {}
                // quiche 0.30.0's `stream_shutdown` says no other.
                Err(e) => unreachable!("quiche shuts a client's stream or says why not: {e}"),
            }
        }
    }

    /// quiche opens a stream's window itself.
    fn extend_stream_window(&mut self, _stream: StreamId, _n: u64) {}
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]

    use super::*;

    /// curl's version names the library as C's does.
    #[test]
    fn the_version_is_said_as_c_says_it() {
        assert_eq!(quiche_version(), "0.30.0");
        assert_eq!(version().to_string(), "quiche/0.30.0");
        assert_eq!(QUICHE.flavour(), Flavour::Quiche);
    }

    /// A failure is numbered as quiche's C API numbers it, which C's
    /// traces print (`include/quiche.h`).
    #[test]
    fn failures_are_numbered_as_quiche_h_numbers_them() {
        use quiche::Error as E;
        use quiche::h3::Error as H;
        // Each of quiche.h's `quiche_error` and `quiche_h3_error`.
        let quic = [
            (E::Done, -1),
            (E::BufferTooShort, -2),
            (E::UnknownVersion, -3),
            (E::InvalidFrame, -4),
            (E::InvalidPacket, -5),
            (E::InvalidState, -6),
            (E::InvalidStreamState(4), -7),
            (E::InvalidTransportParam, -8),
            (E::CryptoFail, -9),
            (E::TlsFail, -10),
            (E::FlowControl, -11),
            (E::StreamLimit, -12),
            (E::FinalSize, -13),
            (E::CongestionControl, -14),
            (E::StreamStopped(1), -15),
            (E::StreamReset(1), -16),
            (E::IdLimit, -17),
            (E::OutOfIdentifiers, -18),
            (E::KeyUpdate, -19),
            (E::CryptoBufferExceeded, -20),
            (E::InvalidAckRange, -21),
            (E::OptimisticAckDetected, -22),
            (E::InvalidDcidInitialization, -23),
        ];
        for (e, n) in quic {
            assert_eq!(quic_code(e), n, "{e:?}");
        }
        let h3 = [
            (H::Done, -1),
            (H::BufferTooShort, -2),
            (H::InternalError, -3),
            (H::ExcessiveLoad, -4),
            (H::IdError, -5),
            (H::StreamCreationError, -6),
            (H::ClosedCriticalStream, -7),
            (H::MissingSettings, -8),
            (H::FrameUnexpected, -9),
            (H::FrameError, -10),
            (H::QpackDecompressionFailed, -11),
            (H::StreamBlocked, -13),
            (H::SettingsError, -14),
            (H::RequestRejected, -15),
            (H::RequestCancelled, -16),
            (H::RequestIncomplete, -17),
            (H::MessageError, -18),
            (H::ConnectError, -19),
            (H::VersionFallback, -20),
            (H::TransportError(E::TlsFail), -1010),
        ];
        for (e, n) in h3 {
            assert_eq!(h3_code(e), n, "{e:?}");
        }
    }

    /// Every stream open joins each list without the list growing: the
    /// room was made as it opened. One quiche ended leaves them all, and
    /// one not open joins none.
    #[test]
    fn open_streams_join_their_lists_in_the_room_made() {
        let mut s = Streams::default();
        for id in 0..5 {
            s.make_room().unwrap();
            s.opened(StreamId(id * 4));
        }
        let room = (s.blocked.capacity(), s.ends.capacity());
        for id in 0..5 {
            s.end(StreamId(id * 4));
            s.block(StreamId(id * 4));
            s.end(StreamId(id * 4));
        }
        assert_eq!((s.blocked.capacity(), s.ends.capacity()), room);
        assert_eq!(s.ends.len(), 5, "each once");
        s.ended(StreamId(8));
        assert!(
            ![&s.live, &s.blocked, &s.ends]
                .iter()
                .any(|l| l.contains(&StreamId(8)))
        );
        s.end(StreamId(8));
        s.block(StreamId(99));
        assert_eq!((s.blocked.len(), s.ends.len()), (4, 4));
    }

    /// A field with CR, LF or NUL in it is not handed on; its status's
    /// name is the pseudo-header's, never checked.
    #[test]
    fn a_field_with_a_line_break_or_nul_is_not_valid() {
        assert!(valid(b"text/html; charset=utf-8"));
        for bad in [&b"a\rb"[..], b"a\nb", b"a\0b"] {
            assert!(!valid(bad));
        }
    }
}
