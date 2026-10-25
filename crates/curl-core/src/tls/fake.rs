//! A TLS library for tests, whose wire form a `Conversation` can script
//! and read: a handshake of text lines, then records of ROT13'd bytes.
//!
//! - The client sends `FAKETLS HELLO`, then a blank line: a request's
//!   head, which the peer answers.
//! - The server's flight is `FAKETLS WELCOME` and a blank line, read as
//!   one record of its length.
//! - The client then sends `FAKETLS FINISHED` and a line end, no head,
//!   and the handshake is done.
//! - Each record is `[` four hex digits `]`, then that many bytes with
//!   their letters ROT13'd, so a request's blank line shows through.
//! - Either side says goodbye with `FAKETLS CLOSE` and a blank line.
//!
//! A session allocates nothing past its own box, so what a test counts
//! is the library's. A library made `ticketing` resumes a session the
//! transfer's cache holds, and gives one to keep as its handshake ends,
//! each a ticket of TLS 1.3 good for two hours. A session says its
//! verification of the peer gave its number, counting from 1. A record a send cannot put on the wire whole is
//! kept and sent before anything else: a read that must send first
//! waits to write.

use std::fmt;
use std::io;
use std::num::NonZeroUsize;
use std::ptr::NonNull;
use std::sync::Mutex;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};

use super::{
    Alpn, CaDefaults, Chosen, Handshake, TLS1_3, TlsBackend, TlsIdentity, TlsIo, TlsNative,
    TlsPeer, TlsPeerKind, TlsSession, TlsShared, TlsTicket, TlsWait,
};
use crate::conn::io::{Recv, Sent};
use crate::error::ErrorKind;

/// The client's first flight.
pub const HELLO: &[u8] = b"FAKETLS HELLO\r\n\r\n";
/// The server's answer to it.
pub const WELCOME: &[u8] = b"FAKETLS WELCOME\r\n\r\n";
/// The client's last flight, which the handshake ends with.
pub const FINISHED: &[u8] = b"FAKETLS FINISHED\n";
/// Either side's goodbye (close_notify).
pub const CLOSE: &[u8] = b"FAKETLS CLOSE\r\n\r\n";

/// The file of certificates the fake trusts when a transfer names none.
pub const CA_FILE: &str = "/fake/ca-bundle.crt";

/// The most bytes a record carries.
pub const RECORD: usize = 4096;
/// A record's header: `[`, four hex digits, `]`.
const HEADER: usize = 6;
/// The names a log keeps whole, the rest cut.
const NAME: usize = 64;
/// The receives a log keeps the sizes of.
const ASKED: usize = 32;

/// The fake library: each session it makes notes what it was asked in
/// the log the library shares with the test.
#[derive(Debug)]
pub struct FakeTls {
    log: TryArc<Mutex<FakeLog>>,
    /// Each session stops the transfer receiving once, as the peer's
    /// flight is read, as a verification the application finishes later
    /// does (`SSL_ERROR_WANT_RETRY_VERIFY`).
    pause: bool,
    /// Each session's peer agrees by ALPN to the first protocol offered.
    agree: bool,
    /// Each session resumes a ticket kept and gives one to keep.
    tickets: bool,
    /// What each session binds a channel with.
    binding: FakeBinding,
}

/// What a fake session binds a channel with, once its handshake is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeBinding {
    /// Nothing, as a library that cannot bind (C's `get_channel_binding`
    /// unset) or a peer with no certificate.
    None,
    /// `tls-server-end-point:` and the session's number, a byte.
    Bound,
    /// The peer's certificate names no digest: nothing, said so.
    NoDigest,
    /// The peer's certificate's signature is not known: the transfer
    /// fails.
    Fails,
}

/// The prefix of a channel binding (RFC 5929's `tls-server-end-point`).
pub const BINDING: &[u8] = b"tls-server-end-point:";

/// The ticket a ticketing fake's handshake gives.
pub const TICKET: &[u8] = b"FAKETLS TICKET";

/// What a fake library's sessions were asked.
#[derive(Clone, Copy, Debug)]
pub struct FakeLog {
    /// Sessions made.
    pub sessions: usize,
    /// The last session's peer: its name (cut at 64 bytes), port and
    /// kind.
    name: [u8; NAME],
    name_len: usize,
    pub port: u16,
    pub kind: Option<TlsPeerKind>,
    /// Whether the last session was to verify its peer.
    pub verify_peer: bool,
    /// The room each receive was given, the first 32.
    asked: [usize; ASKED],
    asked_len: usize,
    /// Handshakes done.
    pub handshakes: usize,
    /// Goodbyes sent, and those that heard the peer's.
    pub closes_sent: usize,
    pub closes_heard: usize,
    /// The multis' states it made, and those dropped since.
    pub states_made: usize,
    pub states_dropped: usize,
    /// The number of the state the last session was handed, counting
    /// from 1 in the order they were made.
    pub state: usize,
    /// Sessions that resumed a ticket the transfer's cache held.
    pub resumed: usize,
    /// What the last session offered by ALPN.
    pub alpn: Option<Alpn>,
}

/// What the fake keeps for a multi: its number, and the log it notes
/// its drop in.
struct FakeState {
    number: usize,
    log: TryArc<Mutex<FakeLog>>,
}

impl FakeState {
    fn new(log: &TryArc<Mutex<FakeLog>>) -> FakeState {
        let mut l = log.lock().expect("no test panics holding the log");
        l.states_made += 1;
        FakeState {
            number: l.states_made,
            log: log.clone(),
        }
    }
}

impl Drop for FakeState {
    fn drop(&mut self) {
        self.log
            .lock()
            .expect("no test panics holding the log")
            .states_dropped += 1;
    }
}

impl FakeLog {
    /// The last session's peer's name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// The room each receive was given, in order, the first 32.
    pub fn asked(&self) -> &[usize] {
        &self.asked[..self.asked_len]
    }
}

impl FakeTls {
    pub fn new() -> Result<FakeTls, OutOfMemory> {
        let log = FakeLog {
            sessions: 0,
            name: [0; NAME],
            name_len: 0,
            port: 0,
            kind: None,
            verify_peer: false,
            asked: [0; ASKED],
            asked_len: 0,
            handshakes: 0,
            closes_sent: 0,
            closes_heard: 0,
            states_made: 0,
            states_dropped: 0,
            state: 0,
            resumed: 0,
            alpn: None,
        };
        Ok(FakeTls {
            log: TryArc::try_new(Mutex::new(log))?,
            pause: false,
            agree: false,
            tickets: false,
            binding: FakeBinding::None,
        })
    }

    /// The same, each session binding a channel as `binding` says.
    pub fn binding(binding: FakeBinding) -> Result<FakeTls, OutOfMemory> {
        Ok(FakeTls {
            binding,
            ..FakeTls::new()?
        })
    }

    /// The same, each session resuming a ticket the transfer's cache
    /// holds for its peer and giving one to keep as its handshake ends.
    pub fn ticketing() -> Result<FakeTls, OutOfMemory> {
        Ok(FakeTls {
            tickets: true,
            ..FakeTls::new()?
        })
    }

    /// The same, each session's peer agreeing by ALPN to the first
    /// protocol offered, where the plain fake's peers agree to none.
    pub fn agreeing() -> Result<FakeTls, OutOfMemory> {
        Ok(FakeTls {
            agree: true,
            ..FakeTls::new()?
        })
    }

    /// The same, each session pausing the transfer's receiving once, as
    /// the peer's flight is read: the handshake goes on only once the
    /// application unpauses it.
    pub fn pausing() -> Result<FakeTls, OutOfMemory> {
        Ok(FakeTls {
            pause: true,
            ..FakeTls::new()?
        })
    }

    /// What its sessions were asked so far.
    pub fn log(&self) -> FakeLog {
        *self.log.lock().expect("no test panics holding the log")
    }
}

impl TlsBackend for FakeTls {
    fn id(&self) -> &dyn fmt::Display {
        &"FakeTLS/1.0"
    }

    fn ca_defaults(&self) -> CaDefaults {
        CaDefaults {
            file: Some(CA_FILE),
            path: None,
        }
    }

    fn session(
        &self,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
        shared: &TlsShared,
    ) -> Result<Box<dyn TlsSession>, ErrorKind> {
        let state = shared
            .with(|| FakeState::new(&self.log), |s| s.number)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?
            .expect("one library per multi in the tests");
        let number = {
            let mut log = self.log.lock().expect("no test panics holding the log");
            log.state = state;
            log.sessions += 1;
            let n = peer.name.len().min(NAME);
            log.name[..n].copy_from_slice(&peer.name[..n]);
            log.name_len = n;
            log.port = peer.port;
            log.kind = Some(peer.kind);
            log.verify_peer = identity.verify_peer;
            log.alpn = Some(alpn);
            log.sessions
        };
        let session = FakeSession {
            log: self.log.clone(),
            number,
            made: false,
            pause: self.pause,
            tickets: self.tickets,
            binding: self.binding,
            agreed: match alpn {
                Alpn::None => None,
                Alpn::Http11 => Some(Chosen::Http11),
                Alpn::Http10 => Some(Chosen::Http10),
                Alpn::H2Http11 | Alpn::H2 => Some(Chosen::H2),
            }
            .filter(|_| self.agree),
            stage: Stage::Hello(0),
            waits: TlsWait::Nothing,
            header: [0; HEADER],
            header_len: 0,
            body: [0; RECORD],
            body_len: 0,
            body_read: 0,
            plain: 0..0,
            peer_closed: false,
            out: [0; HEADER + RECORD],
            out_len: 0,
            out_sent: 0,
        };
        Ok(try_box(session).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?)
    }
}

/// How far a session got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Sending its hello, this much sent.
    Hello(usize),
    /// Reading the server's welcome, this much read.
    Welcome(usize),
    /// Sending its finished line, this much sent.
    Finished(usize),
    Open,
    /// Sending its goodbye, this much sent.
    Closing(usize),
    /// Its goodbye sent, waiting for the peer's.
    Closed,
}

struct FakeSession {
    log: TryArc<Mutex<FakeLog>>,
    /// Its number, counting from 1 in the order the library made them:
    /// what it says its verification of the peer gave.
    number: usize,
    /// Its own object is made, at the first step, after the application
    /// set its context up: its `body`, which `native` points at, as its
    /// context is its `out`.
    made: bool,
    /// It is to pause the transfer's receiving as the welcome is read.
    pause: bool,
    /// It resumes a ticket kept and gives one to keep.
    tickets: bool,
    /// What it binds a channel with.
    binding: FakeBinding,
    /// What its peer agrees to by ALPN, once the handshake is over.
    agreed: Option<Chosen>,
    stage: Stage,
    waits: TlsWait,
    /// The header of the record being read, as far as read.
    header: [u8; HEADER],
    header_len: usize,
    /// The record being read: its length once its header is read, and
    /// how much of it is read; once whole, its bytes not given out yet.
    body: [u8; RECORD],
    body_len: usize,
    body_read: usize,
    plain: std::ops::Range<usize>,
    /// The peer said goodbye.
    peer_closed: bool,
    /// The record being sent, and how much of it went.
    out: [u8; HEADER + RECORD],
    out_len: usize,
    out_sent: usize,
}

impl fmt::Debug for FakeSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeSession")
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

/// What sending a flight came to.
enum Flushed {
    Done,
    Blocked,
}

impl FakeSession {
    fn log(&self) -> std::sync::MutexGuard<'_, FakeLog> {
        self.log.lock().expect("no test panics holding the log")
    }

    /// Send what is left of `bytes` from `*sent`, once: a send that takes
    /// less is tried again at the next call.
    fn flight(io: &mut TlsIo<'_>, bytes: &[u8], sent: &mut usize) -> io::Result<Flushed> {
        if *sent < bytes.len() {
            match io.send(&bytes[*sent..])? {
                Sent::Bytes(n) => *sent += n.get(),
                Sent::WouldBlock => return Ok(Flushed::Blocked),
            }
        }
        Ok(if *sent == bytes.len() {
            Flushed::Done
        } else {
            Flushed::Blocked
        })
    }

    /// Send the record kept, if one is.
    fn flush(&mut self, io: &mut TlsIo<'_>) -> io::Result<Flushed> {
        let (out, len) = (&self.out, self.out_len);
        let flushed = Self::flight(io, &out[..len], &mut self.out_sent)?;
        if let Flushed::Done = flushed {
            self.out_len = 0;
            self.out_sent = 0;
        }
        Ok(flushed)
    }

    /// Read the next record whole, or the peer's goodbye.
    fn read_record(&mut self, io: &mut TlsIo<'_>) -> io::Result<Option<Recv>> {
        while self.header_len < HEADER {
            match io.recv(&mut self.header[self.header_len..])? {
                Recv::Data(n) => self.header_len += n.get(),
                Recv::WouldBlock => return Ok(Some(Recv::WouldBlock)),
                // An end without a goodbye, between records.
                Recv::Eof if self.header_len == 0 => return Ok(Some(Recv::Eof)),
                Recv::Eof => return Err(io::ErrorKind::UnexpectedEof.into()),
            }
        }
        let goodbye = self.header == CLOSE[..HEADER];
        let len = if goodbye {
            CLOSE.len() - HEADER
        } else {
            record_len(&self.header).ok_or(io::ErrorKind::InvalidData)?
        };
        self.body_len = len;
        while self.body_read < len {
            match io.recv(&mut self.body[self.body_read..len])? {
                Recv::Data(n) => self.body_read += n.get(),
                Recv::WouldBlock => return Ok(Some(Recv::WouldBlock)),
                Recv::Eof => return Err(io::ErrorKind::UnexpectedEof.into()),
            }
        }
        self.header_len = 0;
        self.body_read = 0;
        if goodbye {
            if self.body[..len] != CLOSE[HEADER..] {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.peer_closed = true;
            self.log().closes_heard += 1;
            return Ok(Some(Recv::Eof));
        }
        rot13(&mut self.body[..len]);
        self.plain = 0..len;
        Ok(None)
    }
}

/// The length a record's header says, if it is one.
fn record_len(header: &[u8; HEADER]) -> Option<usize> {
    if header[0] != b'[' || header[HEADER - 1] != b']' {
        return None;
    }
    let digits = std::str::from_utf8(&header[1..HEADER - 1]).ok()?;
    let len = usize::from_str_radix(digits, 16).ok()?;
    (1..=RECORD).contains(&len).then_some(len)
}

/// Each letter turned 13 places, both ways.
fn rot13(bytes: &mut [u8]) {
    for b in bytes {
        let base = match *b {
            b'a'..=b'z' => b'a',
            b'A'..=b'Z' => b'A',
            _ => continue,
        };
        *b = (*b - base + 13) % 26 + base;
    }
}

impl TlsSession for FakeSession {
    fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        let failed = |_: io::Error| ErrorKind::SslConnectError;
        if !self.made {
            if io.configures_context() {
                io.configure_context(TlsNative::new(NonNull::from(&self.out).cast(), None))?;
            }
            if self.tickets && io.caches_sessions() {
                let taken = io.take_session();
                if taken.as_ref().is_some_and(|t| t.data == TICKET) {
                    self.log().resumed += 1;
                }
                io.return_session(taken);
            }
            self.made = true;
        }
        loop {
            match self.stage {
                Stage::Hello(mut sent) => {
                    let flushed = Self::flight(io, HELLO, &mut sent).map_err(failed)?;
                    self.stage = Stage::Hello(sent);
                    if let Flushed::Blocked = flushed {
                        self.waits = TlsWait::Send;
                        return Ok(Handshake::Waiting);
                    }
                    self.stage = Stage::Welcome(0);
                }
                Stage::Welcome(read) => {
                    // The flight is read as one record of its length.
                    let mut buf = [0u8; WELCOME.len()];
                    let got = io.recv(&mut buf[read..]).map_err(failed)?;
                    match got {
                        Recv::Data(n) => {
                            let to = read + n.get();
                            if buf[read..to] != WELCOME[read..to] {
                                return Err(ErrorKind::SslConnectError);
                            }
                            if to == WELCOME.len() {
                                io.verified(self.number as i64);
                            }
                            self.stage = if to == WELCOME.len() {
                                Stage::Finished(0)
                            } else {
                                Stage::Welcome(to)
                            };
                            if to == WELCOME.len() && std::mem::take(&mut self.pause) {
                                self.waits = TlsWait::Nothing;
                                io.pause_recv();
                                return Ok(Handshake::Waiting);
                            }
                        }
                        Recv::WouldBlock => {
                            self.waits = TlsWait::Recv;
                            return Ok(Handshake::Waiting);
                        }
                        Recv::Eof => return Err(ErrorKind::SslConnectError),
                    }
                }
                Stage::Finished(mut sent) => {
                    let flushed = Self::flight(io, FINISHED, &mut sent).map_err(failed)?;
                    self.stage = Stage::Finished(sent);
                    if let Flushed::Blocked = flushed {
                        self.waits = TlsWait::Send;
                        return Ok(Handshake::Waiting);
                    }
                    self.stage = Stage::Open;
                    self.waits = TlsWait::Nothing;
                    self.log().handshakes += 1;
                    if self.tickets && io.caches_sessions() {
                        let mut ticket = Vec::new();
                        ticket
                            .try_extend_from_slice(TICKET)
                            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
                        let until = io.unix_time() + 7200;
                        io.keep_session(TlsTicket::new(ticket, TLS1_3, self.agreed, 0, until));
                    }
                    return Ok(Handshake::Done);
                }
                Stage::Open | Stage::Closing(_) | Stage::Closed => return Ok(Handshake::Done),
            }
        }
    }

    fn recv(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        {
            let mut log = self.log();
            if log.asked_len < ASKED {
                let i = log.asked_len;
                log.asked[i] = buf.len();
                log.asked_len += 1;
            }
        }
        assert_eq!(self.stage, Stage::Open, "read once the handshake is done");
        loop {
            // What it holds goes first; a record kept to send goes before
            // it reads the peer again.
            if let Some(n) = NonZeroUsize::new(self.plain.len().min(buf.len())) {
                let from = self.plain.start;
                buf[..n.get()].copy_from_slice(&self.body[from..from + n.get()]);
                self.plain.start += n.get();
                self.waits = TlsWait::Nothing;
                return Ok(Recv::Data(n));
            }
            if self.peer_closed {
                return Ok(Recv::Eof);
            }
            if let Flushed::Blocked = self.flush(io)? {
                self.waits = TlsWait::Send;
                return Ok(Recv::WouldBlock);
            }
            if let Some(got) = self.read_record(io)? {
                self.waits = match got {
                    Recv::WouldBlock => TlsWait::Recv,
                    Recv::Data(_) | Recv::Eof => TlsWait::Nothing,
                };
                return Ok(got);
            }
        }
    }

    fn send(&mut self, io: &mut TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent> {
        assert_eq!(self.stage, Stage::Open, "sent once the handshake is done");
        if let Flushed::Blocked = self.flush(io)? {
            self.waits = TlsWait::Send;
            return Ok(Sent::WouldBlock);
        }
        let n = NonZeroUsize::new(bytes.len().min(RECORD)).expect("a send needs bytes");
        let header = format_header(n.get());
        self.out[..HEADER].copy_from_slice(&header);
        self.out[HEADER..HEADER + n.get()].copy_from_slice(&bytes[..n.get()]);
        rot13(&mut self.out[HEADER..HEADER + n.get()]);
        self.out_len = HEADER + n.get();
        self.out_sent = 0;
        // Taken whole: what the wire does not take now goes first next.
        self.waits = match self.flush(io)? {
            Flushed::Done => TlsWait::Nothing,
            Flushed::Blocked => TlsWait::Send,
        };
        Ok(Sent::Bytes(n))
    }

    fn shutdown(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        loop {
            match self.stage {
                // No goodbye before the handshake is done.
                Stage::Hello(_) | Stage::Welcome(_) | Stage::Finished(_) => {
                    return Ok(Handshake::Done);
                }
                // A goodbye is said back to the peer's too.
                Stage::Open => self.stage = Stage::Closing(0),
                Stage::Closing(mut sent) => {
                    let flushed =
                        Self::flight(io, CLOSE, &mut sent).map_err(|_| ErrorKind::SendError)?;
                    self.stage = Stage::Closing(sent);
                    if let Flushed::Blocked = flushed {
                        self.waits = TlsWait::Send;
                        return Ok(Handshake::Waiting);
                    }
                    self.log().closes_sent += 1;
                    self.stage = Stage::Closed;
                }
                Stage::Closed => {
                    if self.peer_closed {
                        self.waits = TlsWait::Nothing;
                        return Ok(Handshake::Done);
                    }
                    // Records still coming are read past, as a
                    // goodbye's read for the peer's does.
                    match self.read_record(io) {
                        Ok(None) => self.plain = 0..0,
                        Ok(Some(Recv::WouldBlock)) => {
                            self.waits = TlsWait::Recv;
                            return Ok(Handshake::Waiting);
                        }
                        Ok(Some(Recv::Eof | Recv::Data(_))) | Err(_) => {
                            self.waits = TlsWait::Nothing;
                            return Ok(Handshake::Done);
                        }
                    }
                }
            }
        }
    }

    fn chosen(&self) -> Option<Chosen> {
        self.agreed
            .filter(|_| !matches!(self.stage, Stage::Hello(_) | Stage::Welcome(_)))
    }

    /// Only once the handshake is over, as before it the peer showed no
    /// certificate.
    fn channel_binding(
        &self,
        notes: &mut dyn crate::tls::BindingNotes,
    ) -> Result<Option<Vec<u8>>, ErrorKind> {
        if matches!(self.stage, Stage::Hello(_) | Stage::Welcome(_)) {
            return Ok(None);
        }
        match self.binding {
            FakeBinding::None => Ok(None),
            FakeBinding::Bound => {
                let mut bytes = Vec::new();
                bytes
                    .try_extend_from_slice(BINDING)
                    .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
                let number = u8::try_from(self.number).expect("a test makes few sessions");
                bytes
                    .try_extend_from_slice(&[number])
                    .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
                Ok(Some(bytes))
            }
            FakeBinding::NoDigest => {
                notes.info(format_args!(
                    "certificate exposes no signing digest algorithm, nothing to add to channel binding"
                ));
                Ok(None)
            }
            FakeBinding::Fails => Err(notes.fail(
                ErrorKind::SslInvalidcertstatus,
                format_args!("certificate signature algorithm not recognized"),
            )),
        }
    }

    fn waits(&self) -> TlsWait {
        self.waits
    }

    fn pending(&self) -> bool {
        !self.plain.is_empty()
    }

    fn native(&self) -> Option<TlsNative> {
        let session = self.made.then(|| NonNull::from(&self.body).cast());
        Some(TlsNative::new(NonNull::from(&self.out).cast(), session))
    }
}

/// A record's header for `len` bytes.
fn format_header(len: usize) -> [u8; HEADER] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut h = [b'[', 0, 0, 0, 0, b']'];
    for (i, shift) in [12, 8, 4, 0].into_iter().enumerate() {
        h[1 + i] = HEX[(len >> shift) & 0xf];
    }
    h
}

/// `plain` as the records a peer sends, each as long as it can be.
pub fn records(plain: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut out = Vec::new();
    for chunk in plain.chunks(RECORD) {
        out.try_extend_from_slice(&format_header(chunk.len()))?;
        let at = out.len();
        out.try_extend_from_slice(chunk)?;
        rot13(&mut out[at..]);
    }
    Ok(out)
}

/// What a client sent, as the peer's side reads it: its handshake lines
/// and goodbye as they are, its records' bytes unscrambled.
pub fn read_client(wire: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut out = Vec::new();
    let mut rest = wire;
    while !rest.is_empty() {
        let line = [HELLO, FINISHED, CLOSE]
            .into_iter()
            .find(|line| rest.starts_with(line));
        if let Some(line) = line {
            out.try_extend_from_slice(line)?;
            rest = &rest[line.len()..];
            continue;
        }
        let header: Option<&[u8; HEADER]> = rest.get(..HEADER).and_then(|h| h.try_into().ok());
        let len = header.and_then(record_len);
        match len {
            Some(len) if rest.len() >= HEADER + len => {
                let at = out.len();
                out.try_extend_from_slice(&rest[HEADER..HEADER + len])?;
                rot13(&mut out[at..]);
                rest = &rest[HEADER + len..];
            }
            // Cut short, or not a record: as it is.
            _ => {
                out.try_extend_from_slice(rest)?;
                break;
            }
        }
    }
    Ok(out)
}
