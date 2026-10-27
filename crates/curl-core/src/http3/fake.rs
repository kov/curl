//! A fake HTTP/3 library for the core's tests: a connection whose packets
//! out are scripted, whose packets in are kept, and whose events for each
//! packet read are scripted, all through a handle the test keeps.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use curl_alloc::OutOfMemory;

use super::{
    ClientSetup, CloseError, ConnectFailed, Connection, Event, Events, Expiry, H3Error, Heard,
    Http3, Layer, QuicError, StreamId, SubmitFailed,
};
use crate::error::ErrorKind;
use crate::time::Instant;
use crate::tls::{QuicTls, TlsCx};

/// What a fake connection tells as it reads a packet, or writes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Told {
    /// The handshake is done; the session checks the peer.
    HandshakeDone,
    MaxBidiStreams(u64),
    Header {
        stream: i64,
        name: Vec<u8>,
        value: Vec<u8>,
    },
    HeadersDone(i64),
    Data(i64, Vec<u8>),
    Closed(i64, u64),
    QuicClosed(i64, u64),
    Blocked(i64),
    Unblocked(i64),
    /// The HTTP/3 library took this much of a stream's framing.
    Consumed(i64, u64),
    /// HTTP/3 could not be set up, for this reason; the call fails, as
    /// the binding's callback does.
    H3Failed(&'static str),
}

/// The script and the record of one connection, shared with the test.
#[derive(Debug, Default)]
pub struct Script {
    /// The packets it writes, in order; none once they are out. An empty
    /// one ends a flight: none is written for it, and the next write
    /// takes up the next flight.
    pub out: VecDeque<Vec<u8>>,
    /// What it tells as it reads each packet, in order; nothing once
    /// they are used.
    pub on_read: VecDeque<Vec<Told>>,
    /// The packets it read, as they came.
    pub read: Vec<(Vec<u8>, u8)>,
    /// A read fails with this code, the QUIC library's.
    pub read_fails: Option<i32>,
    /// Its timer is due in this long, or never.
    pub expiry: Option<Duration>,
    /// A timer that starts as it is first asked about once a request was
    /// submitted and comes due this long after, on the clock, then never
    /// again; and when it is due.
    pub timer: Option<Duration>,
    pub timer_at: Option<Instant>,
    /// What it has to send once its timer ran, as its retransmission.
    pub on_expiry: Vec<Vec<u8>>,
    /// Its timer ran this many times.
    pub expired: usize,
    pub handshake_done: bool,
    pub draining: bool,
    pub max_payload: usize,
    pub path_max_payload: usize,
    pub send_quantum: usize,
    /// The peer's idle timeout.
    pub idle: Option<Duration>,
    pub keep_alive: Option<Option<Duration>>,
    /// The times the packets it wrote went.
    pub sent_at: Vec<Instant>,
    /// The failures it was told, and the close it then says.
    pub failed: Vec<QuicError>,
    pub close: Option<CloseError>,
    /// What the peer closed it with, once it drains.
    pub peer_close: Option<CloseError>,
    /// The requests submitted, their fields as `name: value`.
    pub requests: Vec<Vec<String>>,
    pub windows: Vec<(i64, u64)>,
    pub cancelled: Vec<(i64, u64)>,
    /// What the session's checks said.
    pub checked: Vec<Result<(), ErrorKind>>,
}

impl Script {
    pub fn new() -> Arc<Mutex<Script>> {
        Arc::new(Mutex::new(Script {
            max_payload: 1200,
            path_max_payload: 1452,
            send_quantum: 12000,
            ..Script::default()
        }))
    }
}

/// The fake library: each connection it makes runs `script`.
#[derive(Debug)]
pub struct FakeHttp3 {
    pub script: Arc<Mutex<Script>>,
    /// What each `client` was given.
    pub setups: Mutex<Vec<ClientSetup>>,
}

impl FakeHttp3 {
    pub fn new(script: Arc<Mutex<Script>>) -> FakeHttp3 {
        FakeHttp3 {
            script,
            setups: Mutex::new(Vec::new()),
        }
    }
}

impl Http3 for FakeHttp3 {
    fn client(
        &self,
        setup: &ClientSetup,
        tls: Box<dyn QuicTls>,
    ) -> Result<Box<dyn Connection>, ConnectFailed> {
        self.setups.lock().unwrap().push(*setup);
        Ok(Box::new(FakeConnection {
            script: self.script.clone(),
            tls,
            next_stream: 0,
        }))
    }

    fn version(&self) -> &dyn fmt::Display {
        &"fake-http3/1.0"
    }
}

/// A connection the script drives.
struct FakeConnection {
    script: Arc<Mutex<Script>>,
    tls: Box<dyn QuicTls>,
    next_stream: i64,
}

impl fmt::Debug for FakeConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FakeConnection")
    }
}

impl FakeConnection {
    /// Tell `told`, inside the session's drive as the libraries do.
    fn tell(&mut self, cx: &mut TlsCx<'_>, told: Vec<Told>, events: Events<'_>) -> Heard {
        let script = self.script.clone();
        let mut heard = Heard::Fine;
        self.tls.drive(cx, &mut || None, &mut |call| {
            for t in &told {
                let event_heard = match t {
                    Told::HandshakeDone => {
                        let checked = call.handshake_done();
                        let mut s = script.lock().unwrap();
                        s.checked.push(checked);
                        s.handshake_done = checked.is_ok();
                        drop(s);
                        let event = Event::HandshakeDone {
                            checked,
                            max_udp_payload: 1452,
                            initial_max_data: 786432,
                            early_data: None,
                        };
                        let mut h = Heard::Fine;
                        call.with_cx(&mut |cx| h = events(cx, event.clone()));
                        if checked.is_err() {
                            h = Heard::Failed;
                        }
                        h
                    }
                    Told::H3Failed(why) => {
                        let event = Event::H3Failed {
                            why,
                            detail: None,
                            out_of_memory: false,
                        };
                        call.with_cx(&mut |cx| {
                            events(cx, event.clone());
                        });
                        Heard::Failed
                    }
                    other => {
                        let mut h = Heard::Fine;
                        call.with_cx(&mut |cx| h = events(cx, event_of(other)));
                        h
                    }
                };
                if event_heard == Heard::Failed {
                    heard = Heard::Failed;
                    break;
                }
            }
        });
        heard
    }
}

/// The event `told` is.
fn event_of(told: &Told) -> Event<'_> {
    match told {
        Told::HandshakeDone | Told::H3Failed(_) => unreachable!("told with what follows it"),
        Told::Consumed(s, n) => Event::Consumed {
            stream: StreamId(*s),
            n: *n,
        },
        Told::MaxBidiStreams(n) => Event::MaxBidiStreams(*n),
        Told::Header {
            stream,
            name,
            value,
        } => Event::Header {
            stream: StreamId(*stream),
            name,
            value,
            status: name == b":status",
        },
        Told::HeadersDone(s) => Event::HeadersDone {
            stream: StreamId(*s),
        },
        Told::Data(s, bytes) => Event::Data {
            stream: StreamId(*s),
            bytes,
        },
        Told::Closed(s, e) => Event::Closed {
            stream: StreamId(*s),
            error: H3Error(*e),
        },
        Told::QuicClosed(s, e) => Event::QuicClosed {
            stream: StreamId(*s),
            error: H3Error(*e),
            rv: 0,
        },
        Told::Blocked(s) => Event::Blocked {
            stream: StreamId(*s),
        },
        Told::Unblocked(s) => Event::Unblocked {
            stream: StreamId(*s),
        },
    }
}

/// The QUIC library's failure `code` in `call`.
pub fn quic_error(call: &'static str, code: i32) -> QuicError {
    QuicError {
        layer: Layer::Quic,
        call,
        code,
        text: "ERR_FAKE",
        crypto: code == -213,
    }
}

impl Connection for FakeConnection {
    fn read_packet(
        &mut self,
        cx: &mut TlsCx<'_>,
        _now: Instant,
        _from: SocketAddr,
        ecn: u8,
        packet: &[u8],
        events: Events<'_>,
    ) -> Result<(), QuicError> {
        let told = {
            let mut s = self.script.lock().unwrap();
            s.read.push((packet.to_vec(), ecn));
            if let Some(code) = s.read_fails {
                return Err(quic_error("ngtcp2_conn_read_pkt", code));
            }
            s.on_read.pop_front().unwrap_or_default()
        };
        match self.tell(cx, told, events) {
            Heard::Fine => Ok(()),
            Heard::Failed => Err(quic_error("ngtcp2_conn_read_pkt", -502)),
        }
    }

    fn write_packet(
        &mut self,
        _cx: &mut TlsCx<'_>,
        _now: Instant,
        buf: &mut [u8],
        _events: Events<'_>,
    ) -> Result<Option<usize>, QuicError> {
        let mut s = self.script.lock().unwrap();
        let Some(packet) = s.out.pop_front().filter(|p| !p.is_empty()) else {
            return Ok(None);
        };
        assert!(packet.len() <= buf.len(), "a scripted packet fits");
        buf[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
    }

    fn before_recv(&mut self, cx: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        self.tls.before_recv(cx)
    }

    fn sent_at(&mut self, now: Instant) {
        self.script.lock().unwrap().sent_at.push(now);
    }

    fn max_payload(&self) -> usize {
        self.script.lock().unwrap().max_payload
    }

    fn path_max_payload(&self) -> usize {
        self.script.lock().unwrap().path_max_payload
    }

    fn send_quantum(&self) -> usize {
        self.script.lock().unwrap().send_quantum
    }

    fn expiry(&self, now: Instant) -> Expiry {
        let mut s = self.script.lock().unwrap();
        if let Some(d) = s.timer.filter(|_| !s.requests.is_empty()) {
            let at = *s.timer_at.get_or_insert(now.after(d));
            return match at.since(now) {
                Duration::ZERO => Expiry::Due,
                left => Expiry::In(left),
            };
        }
        match s.expiry {
            None => Expiry::Never,
            Some(Duration::ZERO) => Expiry::Due,
            Some(d) => Expiry::In(d),
        }
    }

    fn handle_expiry(
        &mut self,
        _cx: &mut TlsCx<'_>,
        _now: Instant,
        _events: Events<'_>,
    ) -> Result<(), QuicError> {
        let mut s = self.script.lock().unwrap();
        s.expired += 1;
        s.expiry = None;
        s.timer = None;
        let resent = std::mem::take(&mut s.on_expiry);
        s.out.extend(resent);
        Ok(())
    }

    fn handshake_done(&self) -> bool {
        self.script.lock().unwrap().handshake_done
    }

    fn draining(&self) -> bool {
        self.script.lock().unwrap().draining
    }

    fn peer_idle_timeout(&self) -> Option<Duration> {
        self.script.lock().unwrap().idle
    }

    fn set_keep_alive(&mut self, every: Option<Duration>) {
        self.script.lock().unwrap().keep_alive = Some(every);
    }

    fn send_room(&self) -> bool {
        true
    }

    fn failed(&mut self, error: QuicError) -> bool {
        let mut s = self.script.lock().unwrap();
        s.failed.push(error);
        if s.close.is_none() {
            s.close = Some(CloseError {
                kind: 0,
                code: u64::from(error.code.unsigned_abs()),
            });
        }
        error.code <= -500
    }

    fn close_error(&self) -> CloseError {
        self.script
            .lock()
            .unwrap()
            .close
            .unwrap_or(CloseError { kind: 0, code: 0 })
    }

    fn closed_with(&self) -> Option<CloseError> {
        let s = self.script.lock().unwrap();
        s.draining.then_some(s.peer_close).flatten()
    }

    fn write_close(&mut self, _now: Instant, buf: &mut [u8]) -> Result<usize, QuicError> {
        buf[..5].copy_from_slice(b"CLOSE");
        Ok(5)
    }

    fn submit_request(
        &mut self,
        fields: &[(&[u8], &[u8])],
        _body: bool,
    ) -> Result<StreamId, SubmitFailed> {
        let lines = fields
            .iter()
            .map(|(n, v)| {
                format!(
                    "{}: {}",
                    String::from_utf8_lossy(n),
                    String::from_utf8_lossy(v)
                )
            })
            .collect();
        self.script.lock().unwrap().requests.push(lines);
        let id = self.next_stream;
        self.next_stream += 4;
        Ok(StreamId(id))
    }

    fn write_body(&mut self, _stream: StreamId, bytes: &[u8]) -> Result<usize, OutOfMemory> {
        Ok(bytes.len())
    }

    fn end_body(&mut self, _stream: StreamId) {}

    fn body_in_flight(&self, _stream: StreamId) -> usize {
        0
    }

    fn body_buffered(&self, _stream: StreamId) -> usize {
        0
    }

    fn resume(&mut self, _stream: StreamId) {}

    fn cancel(&mut self, stream: StreamId, error: H3Error) {
        self.script
            .lock()
            .unwrap()
            .cancelled
            .push((stream.0, error.0));
    }

    fn extend_stream_window(&mut self, stream: StreamId, n: u64) {
        self.script.lock().unwrap().windows.push((stream.0, n));
    }
}
