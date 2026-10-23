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
//! is the library's. A record a send cannot put on the wire whole is
//! kept and sent before anything else: a read that must send first
//! waits to write.

use std::fmt;
use std::io;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};

use super::{Handshake, TlsBackend, TlsIdentity, TlsIo, TlsPeer, TlsPeerKind, TlsSession, TlsWait};
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
}

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
        };
        Ok(FakeTls {
            log: TryArc::try_new(Mutex::new(log))?,
        })
    }

    /// What its sessions were asked so far.
    pub fn log(&self) -> FakeLog {
        *self.log.lock().expect("no test panics holding the log")
    }
}

impl TlsBackend for FakeTls {
    fn session(
        &self,
        identity: &TlsIdentity,
        peer: &TlsPeer<'_>,
    ) -> Result<Box<dyn TlsSession>, ErrorKind> {
        {
            let mut log = self.log.lock().expect("no test panics holding the log");
            log.sessions += 1;
            let n = peer.name.len().min(NAME);
            log.name[..n].copy_from_slice(&peer.name[..n]);
            log.name_len = n;
            log.port = peer.port;
            log.kind = Some(peer.kind);
            log.verify_peer = identity.verify_peer;
        }
        let session = FakeSession {
            log: self.log.clone(),
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
        *b = match *b {
            b'a'..=b'z' => (*b - b'a' + 13) % 26 + b'a',
            b'A'..=b'Z' => (*b - b'A' + 13) % 26 + b'A',
            other => other,
        };
    }
}

impl TlsSession for FakeSession {
    fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        let failed = |_: io::Error| ErrorKind::SslConnectError;
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
                            self.stage = if to == WELCOME.len() {
                                Stage::Finished(0)
                            } else {
                                Stage::Welcome(to)
                            };
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

    fn waits(&self) -> TlsWait {
        self.waits
    }

    fn pending(&self) -> bool {
        !self.plain.is_empty()
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
