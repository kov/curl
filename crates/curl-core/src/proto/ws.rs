//! WebSocket over HTTP/1.1 (`lib/ws.c`): what a connection that switched
//! to it keeps (`struct websocket`), its frames encoded and sent, and
//! received and decoded, for a transfer that delivers them to its write
//! handler or for the application to send and receive itself once its
//! transfer only connected (`CURLOPT_CONNECT_ONLY` 2).
//!
//! It does no I/O of its own: what it sends goes through a [`Wire`],
//! what it receives comes in through its buffers, and what it says
//! through a [`Said`].

pub(crate) mod frame;
pub(crate) mod queue;
#[cfg(test)]
mod tests;

use std::fmt;

use curl_alloc::OutOfMemory;

use crate::error::ErrorKind;
use crate::ws::{Frame, FrameKind, FrameLen, FrameType, SendFlags, Sent};
use frame::{Decoder, Encoder, MAX_CONTROL, Passed, Take};
use queue::ChunkQueue;

/// The size of a WebSocket buffer's chunks (`WS_CHUNK_SIZE`), and how
/// many make one full (`WS_CHUNK_COUNT`).
pub(crate) const CHUNK_SIZE: usize = 65535;
const CHUNK_COUNT: usize = 2;

/// What a WebSocket says as it works: its own trace's lines
/// (`CURL_TRC_WS`), a verbose transfer's (`infof`), and why it failed
/// (`failf`).
pub(crate) trait Said {
    fn ws(&mut self, args: fmt::Arguments<'_>);
    fn info(&mut self, args: fmt::Arguments<'_>);
    /// `kind`, its reason kept and traced.
    fn fail(&mut self, kind: ErrorKind, args: fmt::Arguments<'_>) -> ErrorKind;
}

/// Why a WebSocket step stopped short: nothing more for now
/// (`CURLE_AGAIN`), or a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    Again,
    Failed(ErrorKind),
}

impl From<ErrorKind> for Stop {
    fn from(kind: ErrorKind) -> Stop {
        Stop::Failed(kind)
    }
}

/// What a WebSocket's frames go out on, and what masks them.
pub(crate) trait Wire: Said {
    /// Random bytes into `out` (`Curl_rand`).
    fn random(&mut self, out: &mut [u8]) -> Result<(), ErrorKind>;

    /// Send what the connection takes of `bytes` now: how much, none
    /// for now (`Curl_xfer_send`, or `Curl_senddata` once the transfer
    /// only connected).
    fn send(&mut self, bytes: &[u8]) -> Result<usize, ErrorKind>;

    /// Send all of `bytes`, waiting for the connection to take it, as a
    /// callback that sends is not expected to cope with a part sent
    /// (`ws_send_raw_blocking`).
    fn send_all(&mut self, bytes: &[u8]) -> Result<(), ErrorKind>;

    /// Receive into `buf` what the connection has now (`Curl_easy_recv`):
    /// how much, none at its end; `None` if nothing came yet.
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ErrorKind>;
}

/// The control frame waiting to go, a pong of the payload it answers
/// (`ws_cntrl_frame`): C keeps only the last.
#[derive(Clone, Copy, Debug)]
struct Pong {
    payload: [u8; MAX_CONTROL],
    len: u8,
}

/// What the debug test build changes of a WebSocket, from its
/// environment as the connection switches: the size of its buffers'
/// chunks (`CURL_WS_CHUNK_SIZE`), the frames left unmasked
/// (`CURL_WS_FORCE_ZERO_MASK`), and a send that blocks after this many
/// bytes (`CURL_WS_CHUNK_EAGAIN`).
#[derive(Clone, Copy, Debug)]
struct Debugging {
    chunk: usize,
    zero_mask: bool,
    chunk_eagain: usize,
}

impl Debugging {
    fn from_env() -> Debugging {
        let mut d = Debugging {
            chunk: CHUNK_SIZE,
            zero_mask: false,
            chunk_eagain: 0,
        };
        if cfg!(feature = "debug-hooks") {
            let number = |name: &[u8]| {
                let mut buf = [0u8; 32];
                let given = curl_os::env::var_into(name, &mut buf)?;
                curl_number(given, DEBUG_MAX)
            };
            if let Some(n) = number(b"CURL_WS_CHUNK_SIZE") {
                d.chunk = n;
            }
            if let Some(n) = number(b"CURL_WS_CHUNK_EAGAIN") {
                d.chunk_eagain = n;
            }
            d.zero_mask = curl_os::env::is_set(b"CURL_WS_FORCE_ZERO_MASK");
        }
        d
    }
}

/// The most the debug test build's sizes may be, a MiB (C's
/// `curlx_str_number` limit for them).
const DEBUG_MAX: usize = 1024 * 1024;

/// The decimal number `text` starts with, if it does and is no more than
/// `max` (`curlx_str_number`).
fn curl_number(text: &[u8], max: usize) -> Option<usize> {
    let digits = text.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mut n: usize = 0;
    for &d in &text[..digits] {
        n = n.checked_mul(10)?.checked_add(usize::from(d - b'0'))?;
        if n > max {
            return None;
        }
    }
    Some(n)
}

/// A WebSocket on its connection (`struct websocket`).
#[derive(Debug)]
pub(crate) struct WsConn {
    pub(crate) dec: Decoder,
    pub(crate) enc: Encoder,
    /// What came from the server and is not decoded yet, for the
    /// application's receives (`recvbuf`).
    pub(crate) recvbuf: ChunkQueue,
    /// What is encoded and not yet sent (`sendbuf`).
    sendbuf: ChunkQueue,
    /// Of what is in `sendbuf`, the application's payload, not yet said
    /// to have gone (`sendbuf_payload`).
    sendbuf_payload: usize,
    /// The frame the bytes last received are of (`recvframe`).
    meta: Option<Frame>,
    pending: Option<Pong>,
    /// The transfer's upload is sent as frames through its reader
    /// (`using_reader`), which sends what is encoded.
    pub(crate) using_reader: bool,
    debugging: Debugging,
}

impl WsConn {
    /// A WebSocket, as a connection switches to it (`Curl_ws_accept`).
    pub(crate) fn new(said: &mut dyn Said) -> Result<Box<WsConn>, OutOfMemory> {
        let debugging = Debugging::from_env();
        let chunk = debugging.chunk;
        said.ws(format_args!("WS, using chunk size {chunk}"));
        curl_alloc::try_box(WsConn {
            dec: Decoder::default(),
            enc: Encoder::default(),
            recvbuf: ChunkQueue::new(chunk, CHUNK_COUNT),
            sendbuf: ChunkQueue::new(chunk, CHUNK_COUNT),
            sendbuf_payload: 0,
            meta: None,
            pending: None,
            using_reader: false,
            debugging,
        })
    }

    /// The frame the bytes last received are of, if any came.
    pub(crate) fn meta(&self) -> crate::ws::Meta {
        match self.meta {
            Some(frame) => crate::ws::Meta::Frame(frame),
            None => crate::ws::Meta::Nothing,
        }
    }

    /// The bytes last received are `len` of `frame`, from `offset` of
    /// its `total` (`update_meta`).
    pub(crate) fn set_meta(&mut self, frame: FrameType, offset: u64, total: u64, len: usize) {
        self.meta = Some(Frame {
            kind: frame,
            offset,
            bytes_left: total - offset - len as u64,
            len,
        });
    }

    /// Whether a control frame waits to go.
    #[cfg(test)]
    pub(crate) fn pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Answer a ping with a pong of `payload`, in place of any waiting
    /// (`ws_enc_add_cntrl`).
    pub(crate) fn add_pong(&mut self, payload: &[u8]) {
        self.pending = Some(Pong::of(payload));
    }

    /// Start a frame, `len` bytes long, its head into the send buffer:
    /// after the control frame waiting, if one is (`ws_enc_write_head`).
    pub(crate) fn write_head(
        &mut self,
        wire: &mut dyn Wire,
        flags: SendFlags,
        len: u64,
    ) -> Result<(), ErrorKind> {
        if self.pending.is_some() {
            match self.add_pending(wire) {
                Ok(()) | Err(Stop::Again) => {}
                Err(Stop::Failed(kind)) => return Err(kind),
            }
        }
        self.add_frame(wire, flags, len)
    }

    fn add_frame(
        &mut self,
        wire: &mut dyn Wire,
        flags: SendFlags,
        len: u64,
    ) -> Result<(), ErrorKind> {
        let zero_mask = self.debugging.zero_mask;
        self.enc
            .add_frame(wire, flags, len, &mut self.sendbuf, zero_mask)
    }

    /// The control frame waiting, encoded into the send buffer unless a
    /// frame's payload is under way there (`ws_enc_add_pending`).
    fn add_pending(&mut self, wire: &mut dyn Wire) -> Result<(), Stop> {
        let Some(pong) = self.pending else {
            return Ok(());
        };
        if self.enc.remain > 0 {
            return Err(Stop::Again);
        }
        let pong_flags = SendFlags {
            kind: Some(FrameKind::Pong),
            more: false,
        };
        let payload = &pong.payload[..usize::from(pong.len)];
        if let Err(kind) = self.add_frame(wire, pong_flags, payload.len() as u64) {
            let code = kind.number();
            wire.ws(format_args!("ws_enc_cntrl(), error adding head: {code}"));
            return Err(Stop::Failed(kind));
        }
        match self.enc.write_payload(wire, payload, &mut self.sendbuf) {
            Ok(n) => assert_eq!(n, payload.len(), "a control frame always fits"),
            Err(stop) => {
                let code = match stop {
                    Stop::Again => crate::error::AGAIN_NUMBER,
                    Stop::Failed(kind) => kind.number(),
                };
                wire.ws(format_args!("ws_enc_cntrl(), error adding payload: {code}"));
                return Err(stop);
            }
        }
        self.pending = None;
        Ok(())
    }

    /// Send what is encoded, as far as the connection takes it, the
    /// control frame waiting added first if there is room; waiting for
    /// the connection if `blocking` (`ws_flush`).
    pub(crate) fn flush(&mut self, wire: &mut dyn Wire, blocking: bool) -> Result<(), Stop> {
        if self.sendbuf.len() < self.sendbuf.chunk_size() {
            match self.add_pending(wire) {
                Ok(()) | Err(Stop::Again) => {}
                Err(stop) => return Err(stop),
            }
        }
        // The debug test build blocks a send after so many bytes.
        let chunk_eagain = self.debugging.chunk_eagain;
        let mut eagain_next = false;
        while !self.sendbuf.is_empty() {
            if eagain_next {
                return Err(Stop::Again);
            }
            let mut out = self.sendbuf.peek();
            if chunk_eagain > 0 && out.len() > chunk_eagain {
                out = &out[..chunk_eagain];
                eagain_next = true;
            }
            let sent = if blocking {
                wire.send_all(out).map(|()| out.len())
            } else {
                wire.send(out)
            };
            match sent {
                Ok(0) => {
                    let left = self.sendbuf.len();
                    wire.ws(format_args!("flush EAGAIN, {left} bytes remain in buffer"));
                    return Err(Stop::Again);
                }
                Ok(n) => {
                    wire.ws(format_args!("flushed {n} bytes"));
                    self.sendbuf.skip(n);
                }
                Err(kind) => {
                    let code = kind.number();
                    let why = format_args!("[WS] flush, write error {code}");
                    return Err(Stop::Failed(wire.fail(kind, why)));
                }
            }
        }
        Ok(())
    }

    /// Encode and send the application's `buffer` as a frame `len` long,
    /// or as more of the frame under way, as `flags` say
    /// (`ws_enc_send`): how much of it went, the rest to be given again;
    /// waiting for the connection inside a callback.
    pub(crate) fn send(
        &mut self,
        wire: &mut dyn Wire,
        mut buffer: &[u8],
        len: FrameLen,
        flags: SendFlags,
        in_callback: bool,
    ) -> Result<usize, Stop> {
        let mut sent = 0;
        if self.enc.remain > 0 || !self.sendbuf.is_empty() {
            // A frame is under way, its payload in the buffer or to come.
            let buffered = self.sendbuf_payload;
            if buffer.len() < buffered {
                let why = format_args!(
                    "[WS] curl_ws_send() called with smaller 'buflen' than bytes already \
                     buffered in previous call, {} vs {buffered}",
                    buffer.len()
                );
                return Err(Stop::Failed(wire.fail(ErrorKind::BadFunctionArgument, why)));
            }
            let room = self.enc.remain.saturating_add(buffered as u64);
            if buffer.len() as u64 > room {
                let why = format_args!(
                    "[WS] unaligned frame size (sending {} instead of {room})",
                    buffer.len()
                );
                return Err(Stop::Failed(wire.fail(ErrorKind::BadFunctionArgument, why)));
            }
        } else {
            self.flush(wire, in_callback)?;
            let total = match len {
                FrameLen::These => buffer.len() as u64,
                FrameLen::Total(total) => total,
            };
            if let Err(kind) = self.write_head(wire, flags, total) {
                let code = kind.number();
                wire.ws(format_args!(
                    "curl_ws_send(), error writing frame head {code}"
                ));
                return Err(Stop::Failed(kind));
            }
        }
        while !self.sendbuf.is_empty() || buffer.len() > self.sendbuf_payload {
            if buffer.len() > self.sendbuf_payload {
                let before = self.sendbuf.len();
                let more = &buffer[self.sendbuf_payload..];
                match self.enc.write_payload(wire, more, &mut self.sendbuf) {
                    Ok(_) | Err(Stop::Again) => {}
                    Err(stop) => return Err(stop),
                }
                self.sendbuf_payload += self.sendbuf.len() - before;
                if self.sendbuf_payload == 0 {
                    return Err(Stop::Again);
                }
            }
            match self.flush(wire, in_callback) {
                Ok(()) if self.sendbuf_payload > 0 => {
                    sent += self.sendbuf_payload;
                    buffer = &buffer[self.sendbuf_payload..];
                    self.sendbuf_payload = 0;
                }
                Ok(()) => return Ok(sent),
                Err(Stop::Again) if self.sendbuf_payload > self.sendbuf.len() => {
                    // Blocked with some of the payload gone: that much
                    // went.
                    let flushed = self.sendbuf_payload - self.sendbuf.len();
                    sent += flushed;
                    self.sendbuf_payload -= flushed;
                    return Ok(sent);
                }
                Err(Stop::Again) => {
                    // Blocked before any of the payload went: a send of
                    // none is no answer, so it is to be given again.
                    let encoded = self.sendbuf_payload;
                    let all = buffer.len();
                    wire.ws(format_args!(
                        "EAGAIN flushing sendbuf, payload_encoded: {encoded}/{all}"
                    ));
                    return Err(Stop::Again);
                }
                Err(stop) => return Err(stop),
            }
        }
        Ok(sent)
    }

    /// Send the application's `buffer` as it is, what is encoded first
    /// (`ws_send_raw`): all of it inside a callback, which waits for the
    /// connection, else what goes now.
    pub(crate) fn send_raw(
        &mut self,
        wire: &mut dyn Wire,
        buffer: &[u8],
        in_callback: bool,
    ) -> Result<usize, Stop> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.flush(wire, in_callback)?;
        let sent = if in_callback {
            wire.send_all(buffer).map(|()| Some(buffer.len()))
        } else {
            wire.send(buffer).map(|n| (n > 0).then_some(n))
        };
        let (code, n) = match sent {
            Ok(Some(n)) => (0, n),
            Ok(None) => (crate::error::AGAIN_NUMBER, 0),
            Err(kind) => (kind.number(), 0),
        };
        let len = buffer.len();
        wire.ws(format_args!("ws_send_raw(len={len}) -> {code}, {n}"));
        match sent {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Err(Stop::Again),
            Err(kind) => Err(Stop::Failed(kind)),
        }
    }

    /// Start a frame `len` long whose payload the application gives
    /// after (`curl_ws_start_frame`): refused while one is under way.
    pub(crate) fn start_frame(
        &mut self,
        wire: &mut dyn Wire,
        flags: SendFlags,
        len: u64,
    ) -> Result<(), ErrorKind> {
        if self.enc.remain > 0 {
            let why = format_args!("[WS] previous frame not finished");
            return Err(wire.fail(ErrorKind::SendError, why));
        }
        let headed = self.write_head(wire, flags, len);
        if let Err(kind) = headed {
            let code = kind.number();
            wire.ws(format_args!(
                "curl_start_frame(), error adding frame head {code}"
            ));
        }
        headed
    }

    /// What is encoded and not sent, for the upload's reader to take.
    pub(crate) fn sendbuf_mut(&mut self) -> &mut ChunkQueue {
        &mut self.sendbuf
    }

    /// Encode what it takes of `payload` as more of the frame under way,
    /// into the send buffer (`ws_enc_write_payload`): how much.
    pub(crate) fn encode_payload(
        &mut self,
        said: &mut dyn Said,
        payload: &[u8],
    ) -> Result<usize, Stop> {
        self.enc.write_payload(said, payload, &mut self.sendbuf)
    }

    /// The pong waiting is sent now, if it can be, after a receive
    /// (`curl_ws_recv`): a failure is no receive's.
    pub(crate) fn send_pending(&mut self, wire: &mut dyn Wire, in_callback: bool) {
        if self.pending.is_some() && self.add_pending(wire).is_ok() {
            // As C's, whatever the flush comes to.
            let _flushed = self.flush(wire, in_callback);
        }
    }

    /// Receive into `buf` what payload has come of the next frame, more
    /// read from the wire while none is held (`curl_ws_recv`): the frame
    /// they are of, and how many.
    pub(crate) fn recv(
        &mut self,
        wire: &mut dyn Wire,
        buf: &mut [u8],
        auto_pong: bool,
    ) -> Result<Frame, Stop> {
        let WsConn {
            dec,
            recvbuf,
            pending,
            ..
        } = self;
        let mut collect = Collect {
            said: wire,
            buf,
            at: 0,
            first: None,
            written: false,
            auto_pong,
            pending,
        };
        loop {
            if recvbuf.is_empty() {
                let n = slurp(recvbuf, &mut *collect.said)?;
                if n == 0 {
                    collect
                        .said
                        .info(format_args!("[WS] connection expectedly closed?"));
                    return Err(Stop::Failed(ErrorKind::GotNothing));
                }
                let held = recvbuf.len();
                collect.said.ws(format_args!(
                    "curl_ws_recv, added {held} bytes from network"
                ));
            }
            match dec.pass(recvbuf, &mut collect) {
                Ok(Passed::Again) | Err(Stop::Again) if !collect.written => {
                    dec.info(collect.said, "need more input");
                }
                Ok(Passed::Again) | Err(Stop::Again) => break,
                Err(stop) => return Err(stop),
                Ok(Passed::Frame) if collect.written => break,
                Ok(Passed::Frame) => {}
            }
        }
        let (frame, offset, total) = collect.first.expect("a frame was written");
        let n = collect.at;
        self.set_meta(frame, offset, total, n);
        Ok(self.meta.expect("set just above"))
    }
}

/// Receive from `wire` into `q`, while each read fills the room its last
/// chunk has (`Curl_bufq_slurp`): how much, none at the stream's end; a
/// first read that has nothing for now is waited on.
fn slurp(q: &mut ChunkQueue, wire: &mut dyn Wire) -> Result<usize, Stop> {
    let mut total = 0;
    let mut buf = Vec::new();
    loop {
        let room = q.tail_room();
        buf.clear();
        buf.try_reserve_exact(room)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        #[expect(clippy::disallowed_methods, reason = "reserved just above")]
        buf.resize(room, 0);
        match wire.recv(&mut buf) {
            Ok(Some(0)) => return Ok(total),
            Ok(Some(n)) => {
                q.write(&buf[..n]).map_err(|_| ErrorKind::OutOfMemory)?;
                total += n;
                if n < room {
                    return Ok(total);
                }
            }
            Ok(None) if total == 0 => return Err(Stop::Again),
            Ok(None) => return Ok(total),
            Err(kind) => return Err(Stop::Failed(kind)),
        }
    }
}

/// The bits C's `flags` has for `flags`, and the `fragsize` for `len`,
/// as its traces print them (`CURLWS_*`).
fn c_args(len: FrameLen, flags: SendFlags) -> (u64, u32) {
    let kind = match flags.kind {
        None => 0,
        Some(FrameKind::Text) => 1,
        Some(FrameKind::Binary) => 2,
        Some(FrameKind::Close) => 8,
        Some(FrameKind::Ping) => 0x10,
        Some(FrameKind::Pong) => 0x40,
    };
    let more = if flags.more { 4 } else { 0 };
    match len {
        FrameLen::These => (0, kind | more),
        FrameLen::Total(total) => (total, kind | more | 0x20),
    }
}

/// What a send's result comes to for the application: how much went, or
/// none for now.
fn sent_of(sent: Result<usize, Stop>) -> Result<Sent, ErrorKind> {
    match sent {
        Ok(n) => Ok(Sent::Bytes(n)),
        Err(Stop::Again) => Ok(Sent::WouldBlock),
        Err(Stop::Failed(kind)) => Err(kind),
    }
}

/// The application sends `bytes` (`curl_ws_send`): as a frame `len`
/// long, or as more of the frame under way, as `flags` say; as they are,
/// if frames are `raw`. Inside a callback, the sends wait for the
/// connection.
pub(crate) fn api_send(
    ws: &mut WsConn,
    wire: &mut dyn Wire,
    raw: bool,
    bytes: &[u8],
    len: FrameLen,
    flags: SendFlags,
    in_callback: bool,
) -> Result<Sent, ErrorKind> {
    let (fragsize, bits) = c_args(len, flags);
    let (n, raw_n) = (bytes.len(), u8::from(raw));
    wire.ws(format_args!(
        "curl_ws_send(len={n}, fragsize={fragsize}, flags={bits:x}), raw={raw_n}"
    ));
    if raw {
        // What waits to go goes first.
        match ws.flush(wire, false) {
            Ok(()) => {}
            Err(Stop::Again) => return Ok(Sent::WouldBlock),
            Err(Stop::Failed(kind)) => return Err(kind),
        }
        if fragsize != 0 || bits != 0 {
            let why = format_args!("[WS] fragsize and flags must be zero in raw mode");
            return Err(wire.fail(ErrorKind::BadFunctionArgument, why));
        }
        return sent_of(ws.send_raw(wire, bytes, in_callback));
    }
    let sent = ws.send(wire, bytes, len, flags, in_callback);
    let (code, went) = match sent {
        Ok(went) => (0, went),
        Err(Stop::Again) => (crate::error::AGAIN_NUMBER, 0),
        Err(Stop::Failed(kind)) => (kind.number(), 0),
    };
    wire.ws(format_args!(
        "curl_ws_send(len={n}, fragsize={fragsize}, flags={bits:x}, raw={raw_n}) -> {code}, {went}"
    ));
    sent_of(sent)
}

/// The application starts a frame `len` long, its payload to follow in
/// its sends (`curl_ws_start_frame`): refused for `raw` frames.
pub(crate) fn api_start_frame(
    ws: &mut WsConn,
    wire: &mut dyn Wire,
    raw: bool,
    flags: SendFlags,
    len: u64,
) -> Result<(), ErrorKind> {
    if raw {
        let why = format_args!("cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled");
        return Err(wire.fail(ErrorKind::FailedInit, why));
    }
    let (_, bits) = c_args(FrameLen::These, flags);
    // C's line has no closing parenthesis.
    wire.ws(format_args!(
        "curl_ws_start_frame(flags={bits:x}, frame_len={len}"
    ));
    ws.start_frame(wire, flags, len)
}

/// The application receives into `buf` what has come of the next frame
/// (`curl_ws_recv`), answering pings unless frames are `raw` or it
/// answers them itself; the pong waiting is sent after, unless the
/// upload sends it.
pub(crate) fn api_recv(
    ws: &mut WsConn,
    wire: &mut dyn Wire,
    buf: &mut [u8],
    raw: bool,
    auto_pong: bool,
    in_callback: bool,
) -> Result<crate::ws::Received, ErrorKind> {
    let len = buf.len();
    let frame = match ws.recv(wire, buf, auto_pong) {
        Ok(frame) => frame,
        Err(Stop::Again) => return Ok(crate::ws::Received::WouldBlock),
        Err(Stop::Failed(kind)) => return Err(kind),
    };
    let (n, at, left) = (frame.len, frame.offset, frame.bytes_left);
    wire.ws(format_args!(
        "curl_ws_recv(len={len}) -> {n} bytes (frame at {at}, {left} left)"
    ));
    if !raw && !ws.using_reader {
        ws.send_pending(wire, in_callback);
    }
    Ok(crate::ws::Received::Frame(frame))
}

/// What takes the payload a receive gets into the application's buffer
/// (`ws_collect`, `ws_client_collect`).
struct Collect<'a> {
    said: &'a mut dyn Wire,
    buf: &'a mut [u8],
    at: usize,
    /// The frame the bytes are of, where they start and its length.
    first: Option<(FrameType, u64, u64)>,
    /// Bytes of a frame were taken, or a frame of none: the receive is
    /// over.
    written: bool,
    auto_pong: bool,
    pending: &'a mut Option<Pong>,
}

impl Said for Collect<'_> {
    fn ws(&mut self, args: fmt::Arguments<'_>) {
        self.said.ws(args);
    }

    fn info(&mut self, args: fmt::Arguments<'_>) {
        self.said.info(args);
    }

    fn fail(&mut self, kind: ErrorKind, args: fmt::Arguments<'_>) -> ErrorKind {
        self.said.fail(kind, args)
    }
}

impl Take for Collect<'_> {
    fn take(
        &mut self,
        bytes: &[u8],
        frame: FrameType,
        offset: u64,
        len: u64,
    ) -> Result<usize, Stop> {
        let remain = len - offset - bytes.len() as u64;
        if self.at == 0 {
            self.first = Some((frame, offset, len));
        }
        if self.auto_pong && frame.kind == FrameKind::Ping && remain == 0 {
            // Only a ping's last bytes are its pong's (`ws_client_collect`).
            self.said
                .ws(format_args!("auto PONG to [PING payload={offset}/{len}]"));
            *self.pending = Some(Pong::of(bytes));
            return Ok(bytes.len());
        }
        self.written = true;
        let n = bytes.len().min(self.buf.len() - self.at);
        if n == 0 {
            return if bytes.is_empty() {
                Ok(0)
            } else {
                Err(Stop::Again)
            };
        }
        self.buf[self.at..self.at + n].copy_from_slice(&bytes[..n]);
        self.at += n;
        Ok(n)
    }

    fn paused(&self) -> bool {
        false
    }
}

impl Pong {
    /// A pong of `payload`, a ping's, which is short.
    fn of(payload: &[u8]) -> Pong {
        assert!(payload.len() <= MAX_CONTROL, "a ping's payload is short");
        let mut pong = Pong {
            payload: [0; MAX_CONTROL],
            len: payload.len() as u8,
        };
        pong.payload[..payload.len()].copy_from_slice(payload);
        pong
    }
}
