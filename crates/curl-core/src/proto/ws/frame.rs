//! WebSocket frames as libcurl's client reads and writes them (RFC 6455
//! 5.2, `lib/ws.c`'s decoder and encoder). The decoder is at the trust
//! boundary: whatever a server sends is a frame read, a frame refused
//! with C's reason, or bytes waited for, never a panic.

use std::fmt;

use super::queue::ChunkQueue;
use super::{Said, Stop, Wire};
use crate::error::ErrorKind;
use crate::ws::{FrameKind, FrameType, SendFlags};

const FIN: u8 = 0x80;
const RSV: u8 = 0x70;
const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BIN: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xa;
const MASK: u8 = 0x80;

/// The longest payload of a control frame (RFC 6455 5.5).
pub(crate) const MAX_CONTROL: usize = 125;

/// The name a trace gives a frame's opcode (`ws_frame_name_of_op`).
fn op_name(first: u8) -> &'static str {
    match first & 0xf {
        OP_CONT => "CONT",
        OP_TEXT => "TEXT",
        OP_BIN => "BIN",
        OP_CLOSE => "CLOSE",
        OP_PING => "PING",
        OP_PONG => "PONG",
        _ => "???",
    }
}

/// " NON-FINAL" or nothing, as a trace says it of a frame's first byte.
fn non_final(first: u8, word: &'static str) -> &'static str {
    if first & FIN != 0 { "" } else { word }
}

/// What a frame's first byte says, given the data message under way,
/// if one is (`ws_frame_firstbyte2flags`): a frame refused with C's
/// reason otherwise.
fn first_byte(
    said: &mut dyn Said,
    first: u8,
    ongoing: Option<FrameKind>,
) -> Result<FrameType, ErrorKind> {
    let frame = |kind, more| Ok(FrameType { kind, more });
    let refused =
        |said: &mut dyn Said, why: fmt::Arguments<'_>| Err(said.fail(ErrorKind::RecvError, why));
    let interrupted = |said: &mut dyn Said, kind| {
        let name = if kind == FrameKind::Text {
            "TEXT"
        } else {
            "BINARY"
        };
        refused(
            said,
            format_args!("[WS] fragmented message interrupted by new {name} msg"),
        )
    };
    match first {
        OP_CONT => match ongoing {
            Some(kind) => frame(kind, true),
            None => refused(
                said,
                format_args!("[WS] no ongoing fragmented message to resume"),
            ),
        },
        b if b == OP_CONT | FIN => match ongoing {
            Some(kind) => frame(kind, false),
            None => refused(
                said,
                format_args!("[WS] no ongoing fragmented message to resume"),
            ),
        },
        OP_TEXT | OP_BIN if ongoing.is_some() => interrupted(said, kind_of(first)),
        b if (b == OP_TEXT | FIN || b == OP_BIN | FIN) && ongoing.is_some() => {
            interrupted(said, kind_of(first & 0xf))
        }
        OP_TEXT | OP_BIN => frame(kind_of(first), true),
        b if b == OP_TEXT | FIN || b == OP_BIN | FIN => frame(kind_of(first & 0xf), false),
        OP_CLOSE => refused(said, format_args!("[WS] invalid fragmented CLOSE frame")),
        OP_PING => refused(said, format_args!("[WS] invalid fragmented PING frame")),
        OP_PONG => refused(said, format_args!("[WS] invalid fragmented PONG frame")),
        b if b == OP_CLOSE | FIN => frame(FrameKind::Close, false),
        b if b == OP_PING | FIN => frame(FrameKind::Ping, false),
        b if b == OP_PONG | FIN => frame(FrameKind::Pong, false),
        b if b & RSV != 0 => refused(said, format_args!("[WS] invalid reserved bits: {b:02x}")),
        b => refused(said, format_args!("[WS] invalid opcode: {b:02x}")),
    }
}

/// The kind of a data frame's opcode, text or binary.
fn kind_of(op: u8) -> FrameKind {
    if op == OP_TEXT {
        FrameKind::Text
    } else {
        FrameKind::Binary
    }
}

/// The first byte of a frame the application sends as `flags`, a
/// fragmented message of its being under way if `cont`
/// (`ws_frame_flags2firstbyte`).
pub(crate) fn send_byte(
    said: &mut dyn Said,
    flags: SendFlags,
    cont: bool,
) -> Result<u8, ErrorKind> {
    let bad = |said: &mut dyn Said, why: fmt::Arguments<'_>| {
        Err(said.fail(ErrorKind::BadFunctionArgument, why))
    };
    let data = |op, more| match (cont, more) {
        (true, false) => OP_CONT | FIN,
        (true, true) => OP_CONT,
        (false, false) => op | FIN,
        (false, true) => op,
    };
    match (flags.kind, flags.more) {
        (None, false) if cont => {
            said.ws(format_args!(
                "no flags given; interpreting as continuation fragment for compatibility"
            ));
            Ok(OP_CONT | FIN)
        }
        (None, false) => bad(said, format_args!("[WS] no flags given")),
        (None, true) if cont => {
            said.info(format_args!(
                "[WS] setting CURLWS_CONT flag without message type is supported for \
                 compatibility but highly discouraged"
            ));
            Ok(OP_CONT)
        }
        (None, true) => bad(
            said,
            format_args!("[WS] No ongoing fragmented message to continue"),
        ),
        (Some(FrameKind::Text), more) => Ok(data(OP_TEXT, more)),
        (Some(FrameKind::Binary), more) => Ok(data(OP_BIN, more)),
        (Some(FrameKind::Close), false) => Ok(OP_CLOSE | FIN),
        (Some(FrameKind::Close), true) => bad(
            said,
            format_args!("[WS] CLOSE frame must not be fragmented"),
        ),
        (Some(FrameKind::Ping), false) => Ok(OP_PING | FIN),
        (Some(FrameKind::Ping), true) => {
            bad(said, format_args!("[WS] PING frame must not be fragmented"))
        }
        (Some(FrameKind::Pong), false) => Ok(OP_PONG | FIN),
        (Some(FrameKind::Pong), true) => {
            bad(said, format_args!("[WS] PONG frame must not be fragmented"))
        }
    }
}

/// Where the decoder is in a frame (`ws_dec_state`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum DecState {
    /// Before a frame.
    #[default]
    Init,
    /// In its head.
    Head,
    /// In its payload.
    Payload,
}

/// What reading a frame got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Passed {
    /// A frame's head and all its payload were handed on.
    Frame,
    /// More bytes are needed, or the taker took no more.
    Again,
}

/// What takes a frame's payload as the decoder reads it (C's
/// `ws_write_payload` callback and its context).
pub(crate) trait Take: Said {
    /// Take what it will of `bytes`, the payload of `frame` from
    /// `offset` of its `len` bytes: how many it took. A frame with no
    /// payload is given once, with none.
    fn take(
        &mut self,
        bytes: &[u8],
        frame: FrameType,
        offset: u64,
        len: u64,
    ) -> Result<usize, Stop>;

    /// Whether the application paused its writes, so no more is handed
    /// on now (`Curl_cwriter_is_paused`).
    fn paused(&self) -> bool;
}

/// Frames read from a server (`ws_decoder`).
#[derive(Clone, Debug, Default)]
pub(crate) struct Decoder {
    pub(crate) state: DecState,
    /// The head read so far, of `head_total` bytes once its length is
    /// known.
    head: [u8; 10],
    head_len: u8,
    head_total: u8,
    /// What the frame's first byte said.
    frame: Option<FrameType>,
    /// Where in the payload the reading is.
    offset: u64,
    len: u64,
    /// The data message under way, fragmented (`cont_flags` with
    /// `CURLWS_CONT`): carried from frame to frame.
    ongoing: Option<FrameKind>,
}

impl Decoder {
    /// Ready for the next frame, the message under way kept
    /// (`ws_dec_next_frame`).
    fn next_frame(&mut self) {
        *self = Decoder {
            ongoing: self.ongoing,
            ..Decoder::default()
        };
    }

    /// As new (`ws_dec_reset`).
    pub(crate) fn reset(&mut self) {
        *self = Decoder::default();
    }

    /// The frame being read, and where: its type, offset and length.
    fn current(&self) -> FrameType {
        self.frame.expect("a frame's first byte was read")
    }

    /// What it has read of the frame, as a trace says it (`ws_dec_info`).
    pub(crate) fn info(&self, said: &mut dyn Said, msg: &str) {
        let first = self.head[0];
        let (name, nf) = (op_name(first), non_final(first, " NON-FINAL"));
        match self.head_len {
            0 => {}
            1 => said.ws(format_args!("decoded {msg} [{name}{nf}]")),
            n if n < self.head_total => {
                let total = self.head_total;
                said.ws(format_args!("decoded {msg} [{name}{nf}]({n}/{total})"));
            }
            _ => {
                let (at, len) = (self.offset, self.len);
                said.ws(format_args!(
                    "decoded {msg} [{name}{nf} payload={at}/{len}]"
                ));
            }
        }
    }

    /// Read a frame's head from `input` (`ws_dec_read_head`): done, more
    /// needed (all of `input` taken), or refused.
    fn read_head(
        &mut self,
        said: &mut dyn Said,
        input: &mut ChunkQueue,
    ) -> Result<bool, ErrorKind> {
        loop {
            let Some(&byte) = input.peek().first() else {
                return Ok(false);
            };
            if self.head_len == 0 {
                self.head[0] = byte;
                input.skip(1);
                match first_byte(said, byte, self.ongoing) {
                    Ok(frame) => {
                        // Only data frames are fragments of a message.
                        if matches!(frame.kind, FrameKind::Text | FrameKind::Binary) {
                            self.ongoing = frame.more.then_some(frame.kind);
                        }
                        self.frame = Some(frame);
                    }
                    Err(kind) => {
                        self.reset();
                        return Err(kind);
                    }
                }
                self.head_len = 1;
                continue;
            } else if self.head_len == 1 {
                self.head[1] = byte;
                input.skip(1);
                self.head_len = 2;
                if byte & MASK != 0 {
                    // A client fails on a masked frame (RFC 6455 5.1).
                    let kind = said.fail(
                        ErrorKind::RecvError,
                        format_args!("[WS] masked input frame"),
                    );
                    self.reset();
                    return Err(kind);
                }
                // A control frame's payload is short: a long ping would
                // be answered by a pong as long.
                let control = match self.current().kind {
                    FrameKind::Ping => Some("PING"),
                    FrameKind::Pong => Some("PONG"),
                    FrameKind::Close => Some("CLOSE"),
                    FrameKind::Text | FrameKind::Binary => None,
                };
                if let Some(name) = control
                    && usize::from(byte) > MAX_CONTROL
                {
                    let why = format_args!("[WS] received {name} frame is too big");
                    let kind = said.fail(ErrorKind::RecvError, why);
                    self.reset();
                    return Err(kind);
                }
                match byte {
                    126 => {
                        self.head_total = 4;
                        continue;
                    }
                    127 => {
                        self.head_total = 10;
                        continue;
                    }
                    _ => self.head_total = 2,
                }
            }
            if self.head_len < self.head_total {
                self.head[usize::from(self.head_len)] = byte;
                input.skip(1);
                self.head_len += 1;
                if self.head_len < self.head_total {
                    continue;
                }
            }
            break;
        }
        // The whole head.
        self.len = match self.head_total {
            2 => u64::from(self.head[1]),
            4 => u64::from(u16::from_be_bytes([self.head[2], self.head[3]])),
            10 => {
                if self.head[2] > 127 {
                    // Left as it is: asked again, it says so again.
                    let why = format_args!("[WS] frame length longer than 63 bits not supported");
                    return Err(said.fail(ErrorKind::RecvError, why));
                }
                let mut be = [0u8; 8];
                be.copy_from_slice(&self.head[2..10]);
                u64::from_be_bytes(be)
            }
            _ => unreachable!("a head is 2, 4 or 10 bytes"),
        };
        self.offset = 0;
        self.info(said, "head");
        Ok(true)
    }

    /// Hand on the payload in `input` to `taker` (`ws_dec_pass_payload`):
    /// all of it, or more is needed.
    fn pass_payload(
        &mut self,
        input: &mut ChunkQueue,
        taker: &mut dyn Take,
    ) -> Result<Passed, Stop> {
        let frame = self.current();
        let mut remain = self.len - self.offset;
        while remain > 0 && !input.is_empty() && !taker.paused() {
            let piece = input.peek();
            let n = usize::try_from(remain).map_or(piece.len(), |r| r.min(piece.len()));
            let took = taker.take(&piece[..n], frame, self.offset, self.len)?;
            input.skip(took);
            self.offset += took as u64;
            remain = self.len - self.offset;
            taker.ws(format_args!("passed {took} bytes payload, {remain} remain"));
        }
        Ok(if remain > 0 {
            Passed::Again
        } else {
            Passed::Frame
        })
    }

    /// Read on in `input`, handing payload to `taker` (`ws_dec_pass`):
    /// a frame read whole, more needed, or a frame refused. A frame of
    /// no payload the taker would not take is over as it is next read.
    pub(crate) fn pass(
        &mut self,
        input: &mut ChunkQueue,
        taker: &mut dyn Take,
    ) -> Result<Passed, Stop> {
        if input.is_empty() {
            return Ok(Passed::Again);
        }
        if self.state == DecState::Init {
            self.next_frame();
            self.state = DecState::Head;
        }
        if self.state == DecState::Head {
            match self.read_head(taker, input) {
                Ok(true) => {}
                Ok(false) => return Ok(Passed::Again),
                Err(kind) => {
                    let code = kind.number();
                    let why = format_args!("[WS] decode frame error {code}");
                    return Err(Stop::Failed(taker.fail(kind, why)));
                }
            }
            self.state = DecState::Payload;
            if self.len == 0 {
                // A frame with no payload is handed on once.
                taker.take(&[], self.current(), 0, 0)?;
                self.state = DecState::Init;
                return Ok(Passed::Frame);
            }
        }
        let passed = self.pass_payload(input, taker);
        self.info(taker, "passing");
        match passed {
            Ok(Passed::Frame) => {}
            Ok(Passed::Again) | Err(Stop::Again) => return Ok(Passed::Again),
            Err(stop) => return Err(stop),
        }
        self.state = DecState::Init;
        Ok(Passed::Frame)
    }
}

/// Frames written to a server (`ws_encoder`).
#[derive(Clone, Debug, Default)]
pub(crate) struct Encoder {
    /// The payload of the frame being written, and how much of it is
    /// still to come.
    pub(crate) len: u64,
    pub(crate) remain: u64,
    /// The frame's mask, and where in it the next byte is.
    mask: [u8; 4],
    xori: usize,
    /// The frame's first byte.
    first: u8,
    /// The last data frame sent was not its message's last
    /// (`contfragment`).
    pub(crate) cont: bool,
}

impl Encoder {
    /// How far the frame is, as a trace says it (`ws_enc_info`).
    fn info(&self, said: &mut dyn Said, msg: &str) {
        let (name, nf) = (op_name(self.first), non_final(self.first, " NON-FIN"));
        let (at, len) = (self.len - self.remain, self.len);
        said.ws(format_args!(
            "WS-ENC: {msg} [{name}{nf} payload={at}/{len}]"
        ));
    }

    /// Start a frame of `flags` with `len` bytes of payload, its head
    /// into `out` (`ws_enc_add_frame`), masked with what `wire` draws,
    /// or nothing if `zero_mask`.
    pub(crate) fn add_frame(
        &mut self,
        wire: &mut dyn Wire,
        flags: SendFlags,
        len: u64,
        out: &mut ChunkQueue,
        zero_mask: bool,
    ) -> Result<(), ErrorKind> {
        if self.remain > 0 {
            let remain = self.remain;
            let why = format_args!(
                "[WS] starting new frame with {remain} bytes from last one remaining to be sent"
            );
            return Err(wire.fail(ErrorKind::SendError, why));
        }
        let first = send_byte(wire, flags, self.cont)?;
        // Only data frames are fragments of a message.
        if matches!(flags.kind, Some(FrameKind::Text | FrameKind::Binary)) {
            self.cont = flags.more;
        }
        let control = match flags.kind {
            Some(FrameKind::Ping) => Some("PING"),
            Some(FrameKind::Pong) => Some("PONG"),
            Some(FrameKind::Close) => Some("CLOSE"),
            _ => None,
        };
        if let Some(name) = control
            && len > MAX_CONTROL as u64
        {
            let why = format_args!("[WS] given {name} frame is too big");
            return Err(wire.fail(ErrorKind::TooLarge, why));
        }
        let mut head = [0u8; 14];
        self.first = first;
        head[0] = first;
        let mut hlen = if len > 65535 {
            head[1] = 127 | MASK;
            head[2..10].copy_from_slice(&len.to_be_bytes());
            10
        } else if len >= 126 {
            head[1] = 126 | MASK;
            head[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            4
        } else {
            head[1] = len as u8 | MASK;
            2
        };
        self.len = len;
        self.remain = len;
        self.info(wire, "sending");
        wire.random(&mut self.mask)?;
        if zero_mask {
            self.mask = [0; 4];
        }
        head[hlen..hlen + 4].copy_from_slice(&self.mask);
        hlen += 4;
        self.xori = 0;
        out.write(&head[..hlen]).map_err(|_| ErrorKind::OutOfMemory)
    }

    /// Mask as much of `buf` as the frame has left into `out`, unless it
    /// is full (`ws_enc_write_payload`): how much.
    pub(crate) fn write_payload(
        &mut self,
        said: &mut dyn Said,
        buf: &[u8],
        out: &mut ChunkQueue,
    ) -> Result<usize, Stop> {
        if out.is_full() {
            return Err(Stop::Again);
        }
        let n = usize::try_from(self.remain).map_or(buf.len(), |r| r.min(buf.len()));
        for &b in &buf[..n] {
            out.push(b ^ self.mask[self.xori])
                .map_err(|_| Stop::Failed(ErrorKind::OutOfMemory))?;
            self.xori = (self.xori + 1) & 3;
        }
        self.remain -= n as u64;
        self.info(said, "buffered");
        Ok(n)
    }
}
