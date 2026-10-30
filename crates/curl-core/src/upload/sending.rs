//! A body a line protocol sends after its command (IMAP's `APPEND`,
//! SMTP's `DATA`): read through its chain as the send limit allows, and
//! sent over the connection as C's request buffer sends it (`xfer_send`,
//! `Curl_req_flush`), what the connection does not take kept for the
//! next send.

use super::chain::Body;
use super::{Readout, client_read, sent};
use crate::conn::ConnLease;
use crate::conn::io::Sent;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::mstate::MState;
use crate::multi::state::StepCx;
use crate::progress::rate::Way;
use crate::proto::ProtoStep;
use crate::report::Timer;
use crate::trace;

/// A body as it goes out: what was read of it and not sent.
#[derive(Debug)]
pub(crate) struct Sending {
    body: Body,
    buf: Vec<u8>,
    /// The bytes of `buf` read and not sent, from `at` to `len`.
    at: usize,
    len: usize,
    /// The source said its end (`eos_read`).
    eos: bool,
    /// The send that ends the body has gone (`eos_sent`).
    eos_sent: bool,
    /// The body's bytes sent (`writebytecount`).
    sent: u64,
    /// The body was first read: the send limit runs from then
    /// (`reader_started`).
    read_started: bool,
}

impl Sending {
    /// `body`, to be read `room` bytes at a time (the upload buffer).
    pub(crate) fn new(body: Body, room: usize) -> Result<Box<Sending>, ErrorKind> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(room)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        crate::proto::http::zeros(&mut buf, room).map_err(|_| ErrorKind::OutOfMemory)?;
        curl_alloc::try_box(Sending {
            body,
            buf,
            at: 0,
            len: 0,
            eos: false,
            eos_sent: false,
            sent: 0,
            read_started: false,
        })
        .map_err(|_| ErrorKind::OutOfMemory)
    }

    /// The body.
    pub(crate) fn body(&self) -> &Body {
        &self.body
    }

    /// Send the body on, as the connection takes it: `Done` once it is
    /// all sent, the end said ("upload completely sent off").
    pub(crate) fn send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        loop {
            if self.at < self.len || (self.eos && !self.eos_sent) {
                // The read took no more than the send limit allows: a send
                // of it is never cut by the limit (`xfer_send`).
                let piece = &self.buf[self.at..self.len];
                let len = piece.len();
                let eos = self.eos;
                if eos {
                    trace::debug_info(cx, format_args!("sending last upload chunk of {len} bytes"));
                }
                // The end said with nothing left to send sends nothing
                // (`xfer_send` of no bytes).
                let (n, failed) = if len == 0 {
                    (0, None)
                } else {
                    match lease.get().send(cx, piece) {
                        Ok(Sent::Bytes(n)) => (n.get(), None),
                        Ok(_) => (0, None),
                        Err(_) => (0, Some(ErrorKind::SendError)),
                    }
                };
                let code = failed.map_or(0, ErrorKind::number);
                trace::debug_info(
                    cx,
                    format_args!(
                        "Curl_xfer_send(len={len}, eos={}) -> {code}, {n}",
                        u8::from(eos)
                    ),
                );
                if let Some(kind) = failed {
                    return Err(kind);
                }
                if eos && n == len {
                    self.eos_sent = true;
                }
                sent(cx, &piece[..n]);
                self.at += n;
                self.sent += n as u64;
                if n < len {
                    let left = len - n;
                    trace::debug_info(cx, format_args!("Curl_req_flush(len={left}) -> EAGAIN"));
                    return Ok(ProtoStep::Blocked);
                }
                continue;
            }
            if self.eos {
                // All of it sent (`req_set_upload_done`).
                if cx.mstate() >= MState::Did {
                    cx.mark(Timer::PostTransfer);
                }
                let n = self.sent;
                if n > 0 {
                    trace::info(cx, format_args!("upload completely sent off: {n} bytes"));
                } else {
                    trace::info(cx, format_args!("Request completely sent off"));
                }
                return Ok(ProtoStep::Done);
            }
            if cx.pause().send_paused() {
                return Ok(ProtoStep::Blocked);
            }
            if !self.read_started {
                self.read_started = true;
                cx.rate_start(Way::Send, None);
            }
            // Under a send limit, no more than it allows, and nothing once
            // it is spent (`Curl_client_read`).
            let room = match cx.rate_allowance(Way::Send) {
                Some(..=0) => {
                    let nothing = Ok(Readout { n: 0, eos: false });
                    client_read(cx, self.buf.len(), &nothing);
                    return Ok(ProtoStep::Blocked);
                }
                Some(allowed) => self
                    .buf
                    .len()
                    .min(usize::try_from(allowed).unwrap_or(usize::MAX)),
                None => self.buf.len(),
            };
            let got = self
                .body
                .read(cx, &mut self.buf[..room], true, |_| Ok(Vec::new()));
            client_read(cx, room, &got);
            let got = got?;
            self.at = 0;
            self.len = got.n;
            self.eos = got.eos;
            if got.n == 0 && !got.eos {
                // Paused by its handler.
                return Ok(ProtoStep::Blocked);
            }
        }
    }
}
