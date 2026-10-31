//! A WebSocket's frames, decoded out of the body of the 101 that switched
//! to them and handed to the write handler a frame's piece at a time,
//! what the handler is told of each kept on the connection
//! (`ws_cw_decode`). A ping is answered by a pong, unless the
//! application answers them itself, sent once what came is decoded.

use std::fmt;

use super::{Client, ClientOut, handler_paused, write_trace};
use crate::coding::Decoder;
use crate::components::Component;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::proto::http::ws::{lent, ws_of};
use crate::proto::ws::frame::{Passed, Take};
use crate::proto::ws::queue::ChunkQueue;
use crate::proto::ws::{CHUNK_SIZE, Said, Stop};
use crate::trace;
use crate::ws::{FrameKind, FrameType};

/// The body not yet decoded into frames, and whether frames are handed on
/// as they came, undecoded (`ws_cw_ctx`, `CURLWS_RAW_MODE`).
#[derive(Debug)]
pub(crate) struct WsStage {
    buf: ChunkQueue,
    raw: bool,
}

impl WsStage {
    pub(crate) fn new(raw: bool) -> WsStage {
        WsStage {
            buf: ChunkQueue::new(CHUNK_SIZE, 1),
            raw,
        }
    }
}

/// What follows the stage: the content decoders, then the handlers.
pub(super) struct After<'p, H: Host> {
    pub(super) decoders: &'p mut [Box<dyn Decoder>],
    pub(super) out: &'p mut ClientOut,
    pub(super) pausable: bool,
    _host: std::marker::PhantomData<H>,
}

impl<'p, H: Host> After<'p, H> {
    pub(super) fn new(
        decoders: &'p mut [Box<dyn Decoder>],
        out: &'p mut ClientOut,
        pausable: bool,
    ) -> After<'p, H> {
        After {
            decoders,
            out,
            pausable,
            _host: std::marker::PhantomData,
        }
    }

    fn write(&mut self, cx: &mut StepCx<'_, H>, bytes: &[u8]) -> Result<(), ErrorKind> {
        let (out, pausable) = (&mut *self.out, self.pausable);
        super::decode::run(self.decoders, bytes, &mut Client { cx, out, pausable })
    }
}

impl WsStage {
    /// Decode body `bytes`, the last of the body if `eos`, and hand on the
    /// frames' payload (`ws_cw_write`).
    pub(super) fn write<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        after: &mut After<'_, H>,
        bytes: &[u8],
        eos: bool,
    ) -> Result<(), ErrorKind> {
        let kind = if eos { 0x81 } else { 1 };
        write_trace(
            cx,
            format_args!("[WS] write(len={}, type={kind})", bytes.len()),
        );
        if self.raw {
            return if bytes.is_empty() {
                Ok(())
            } else {
                after.write(cx, bytes)
            };
        }
        if self.buf.write(bytes).is_err() {
            let code = ErrorKind::OutOfMemory.number();
            trace::info(cx, format_args!("[WS] error adding data to buffer {code}"));
            return Err(ErrorKind::OutOfMemory);
        }
        let mut result = after
            .out
            .flush(cx, after.pausable)
            .and_then(|()| self.decode(cx, after));
        if result.is_ok() {
            result = send_pending(cx);
        }
        if result.is_ok() && eos && (!self.buf.is_empty() || decoding(cx)) {
            result = Err(trace::fail(
                cx,
                ErrorKind::RecvError,
                format_args!("[WS] decode ended with incomplete frame"),
            ));
        }
        result
    }

    /// Hand on what was held back while the handler paused, once it lets
    /// output go again (`ws_cw_flush`).
    pub(super) fn flush<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        after: &mut After<'_, H>,
    ) -> Result<(), ErrorKind> {
        write_trace(cx, format_args!("[ws] flush"));
        if !self.raw {
            after.out.flush(cx, after.pausable)?;
            self.decode(cx, after)?;
        }
        after.out.flush(cx, after.pausable)
    }

    /// Decode what is held, while the handler takes it (`ws_dec_pass`
    /// in `ws_cw_write`'s loop); a frame cut short waits for more.
    fn decode<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        after: &mut After<'_, H>,
    ) -> Result<(), ErrorKind> {
        while !self.buf.is_empty() && !handler_paused(cx) {
            // Out of the connection while it decodes, for the handler to
            // reach the rest of it.
            let mut dec = std::mem::take(&mut ws_of(cx).dec);
            let auto_pong = cx.easy().options().ws.auto_pong();
            let passed = dec.pass(
                &mut self.buf,
                &mut Pass {
                    cx,
                    after,
                    auto_pong,
                },
            );
            ws_of(cx).dec = dec;
            match passed {
                Ok(Passed::Frame) => {}
                // More is needed, kept for later.
                Ok(Passed::Again) | Err(Stop::Again) => return Ok(()),
                Err(Stop::Failed(kind)) => {
                    let code = kind.number();
                    let e = trace::fail(cx, kind, format_args!("[WS] decode payload error {code}"));
                    self.buf.reset();
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

/// Whether a frame is under way, read in part.
fn decoding<H: Host>(cx: &mut StepCx<'_, H>) -> bool {
    ws_of(cx).dec.state != crate::proto::ws::frame::DecState::Init
}

/// Send what waits to go, a pong among it, as the connection takes it
/// now, unless the upload sends it (`ws_flush` after `ws_cw_write`).
fn send_pending<H: Host>(cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    if ws_of(cx).using_reader {
        return Ok(());
    }
    let flushed = cx
        .with_ws_conn(|cx, conn| {
            let (ws, mut wire) = lent(cx, conn);
            ws.flush(&mut wire, false)
        })
        .expect("lent");
    match flushed {
        Ok(()) | Err(Stop::Again) => Ok(()),
        Err(Stop::Failed(kind)) => Err(kind),
    }
}

/// What takes the frames' payload: the handlers, told of each frame on
/// the connection first (`ws_cw_dec_next`).
struct Pass<'p, 'c, 'a, H: Host> {
    cx: &'p mut StepCx<'c, H>,
    after: &'p mut After<'a, H>,
    auto_pong: bool,
}

impl<H: Host> Said for Pass<'_, '_, '_, H> {
    fn ws(&mut self, args: fmt::Arguments<'_>) {
        trace::of(self.cx, Component::Ws, args);
    }

    fn info(&mut self, args: fmt::Arguments<'_>) {
        trace::info(self.cx, args);
    }

    fn fail(&mut self, kind: ErrorKind, args: fmt::Arguments<'_>) -> ErrorKind {
        trace::fail(self.cx, kind, args)
    }
}

impl<H: Host> Take for Pass<'_, '_, '_, H> {
    fn take(
        &mut self,
        bytes: &[u8],
        frame: FrameType,
        offset: u64,
        len: u64,
    ) -> Result<usize, Stop> {
        let remain = len - offset - bytes.len() as u64;
        if self.auto_pong && frame.kind == FrameKind::Ping && remain == 0 {
            // Only a ping's last bytes are its pong's.
            self.ws(format_args!("auto PONG to [PING payload={offset}/{len}]"));
            ws_of(self.cx).add_pong(bytes);
        } else if !bytes.is_empty() || remain == 0 {
            ws_of(self.cx).set_meta(frame, offset, len, bytes.len());
            let n = bytes.len();
            write_trace(self.cx, format_args!("[WS] pass {n} decoded bytes"));
            let written = if bytes.is_empty() {
                let (out, pausable) = (&mut *self.after.out, self.after.pausable);
                out.empty_body(self.cx, pausable)
            } else {
                self.after.write(self.cx, bytes)
            };
            written?;
        }
        Ok(bytes.len())
    }

    fn paused(&self) -> bool {
        handler_paused(self.cx)
    }
}
