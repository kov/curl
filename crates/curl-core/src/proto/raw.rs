//! What DICT and Gopher share: a request sent whole as the transfer's
//! DO, and its answer, the transfer's body, read until the server closes
//! the connection (C's `Curl_xfer_send` loop and `Curl_xfer_setup_recv`
//! with no size, read by `sendrecv_dl`).

use curl_alloc::TryVec as _;

use super::ProtoStep;
use crate::conn::io::Recv;
use crate::conn::{ConnLease, RecvFailed};
use crate::deliver::{self, Pipeline};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::progress::rate::Way;
use crate::trace;
use curl_os::net::Sent;

/// What is told of each piece of a request that goes: where it starts in
/// the request, and its bytes.
pub(crate) type Each<'a, 'c, H> =
    dyn FnMut(&mut StepCx<'c, H>, usize, &[u8]) -> Result<(), ErrorKind> + 'a;

/// A request on its way out: its bytes, and how many have gone.
#[derive(Debug, Default)]
pub(crate) struct Outgoing {
    bytes: Vec<u8>,
    sent: usize,
}

impl Outgoing {
    /// The request `parts` make, none of it sent yet.
    pub(crate) fn of(parts: &[&[u8]]) -> Result<Outgoing, ErrorKind> {
        let mut bytes = Vec::new();
        for part in parts {
            bytes
                .try_extend_from_slice(part)
                .map_err(|_| ErrorKind::OutOfMemory)?;
        }
        Ok(Outgoing { bytes, sent: 0 })
    }

    /// Whether all of it has gone.
    pub(crate) fn is_sent(&self) -> bool {
        self.sent == self.bytes.len()
    }

    /// Send what the connection takes of the rest now, `each` told of
    /// every piece that goes, where it starts in the request and its
    /// bytes. Whether all of it has gone. A failing send fails it.
    pub(crate) fn send<'c, H: Host>(
        &mut self,
        cx: &mut StepCx<'c, H>,
        lease: &mut ConnLease,
        each: &mut Each<'_, 'c, H>,
    ) -> Result<bool, ErrorKind> {
        while !self.is_sent() {
            let at = self.sent;
            match lease.get().send(cx, &self.bytes[at..]) {
                Ok(Sent::Bytes(n)) => {
                    let n = n.get();
                    self.sent += n;
                    each(cx, at, &self.bytes[at..at + n])?;
                }
                Ok(Sent::WouldBlock) => return Ok(false),
                Err(_) => return Err(ErrorKind::SendError),
            }
        }
        Ok(true)
    }
}

/// An answer read until the connection closes.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ToClose {
    /// It is being read (`KEEP_RECV`).
    receiving: bool,
    /// It was read to its end (`req.done`).
    received: bool,
}

impl ToClose {
    /// Start reading it (`Curl_xfer_setup_recv`, its size unknown).
    pub(crate) fn start<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        crate::multi::mstate::xfer_setup(
            cx,
            deliver::Directions {
                recv: true,
                send: false,
            },
        );
        self.receiving = true;
    }

    /// It is being read.
    pub(crate) fn receiving(&self) -> bool {
        self.receiving
    }

    /// It was read to its end.
    pub(crate) fn received(&self) -> bool {
        self.received
    }

    /// Read what the connection has into `pipeline` as body, as many
    /// reads as a pass of C's makes (`sendrecv_dl`), what ended the pass
    /// traced as C traces it.
    pub(crate) fn read<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        pipeline: &mut Pipeline,
    ) -> Result<ProtoStep, ErrorKind> {
        pipeline.flush(cx)?;
        let read = self.pass(cx, lease, pipeline);
        match read {
            Ok(ProtoStep::AtReadLimit) => crate::multi::mstate::trace(
                cx,
                format_args!("sendrecv_dl() no EAGAIN/pending data, mark as dirty"),
            ),
            Err(e) => {
                let code = e.number();
                trace::debug_info(cx, format_args!("sendrecv_dl() -> {code}"));
            }
            Ok(_) => {}
        }
        read
    }

    fn pass<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        pipeline: &mut Pipeline,
    ) -> Result<ProtoStep, ErrorKind> {
        let mut reads = 0;
        loop {
            if !self.receiving {
                self.received = true;
                return Ok(ProtoStep::Done);
            }
            if cx.pause().recv_paused() {
                return Ok(ProtoStep::Blocked);
            }
            if reads == super::http::MAX_READS {
                return Ok(ProtoStep::AtReadLimit);
            }
            let max = cx.easy().options().limits.buffer_size.get();
            let max = match cx.rate_allowance(Way::Recv) {
                Some(..=0) => return Ok(ProtoStep::Blocked),
                Some(allowed) => max.min(usize::try_from(allowed).unwrap_or(usize::MAX)),
                None => max,
            };
            reads += 1;
            let said = cx.easy().report().reasons();
            match lease.get().recv(cx, max) {
                Ok(Recv::WouldBlock) if lease.get().data_pending() => {
                    return Ok(ProtoStep::AtReadLimit);
                }
                Ok(Recv::WouldBlock) => return Ok(ProtoStep::Blocked),
                Ok(Recv::Eof) => {
                    trace::debug_info(cx, format_args!("sendrecv_dl: we are done"));
                    deliver::write_resp(cx, 0, true, Ok(()));
                    self.receiving = false;
                }
                Ok(Recv::Data(_)) => {
                    let mut rx = std::mem::take(lease.get().rx_mut());
                    let fed = pipeline.body(cx, rx.filled());
                    let all = rx.filled().len();
                    rx.consume(all);
                    *lease.get().rx_mut() = rx;
                    deliver::write_resp(cx, all, false, fed);
                    fed?;
                }
                Err(RecvFailed::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                Err(RecvFailed::Os(_)) if cx.easy().report().reasons() > said => {
                    return Err(ErrorKind::RecvError);
                }
                Err(RecvFailed::Os(e)) => {
                    let why = curl_os::error::ErrorText::of(&e);
                    return Err(trace::fail_with(
                        cx,
                        ErrorKind::RecvError,
                        &[b"Recv failure: ", why.as_bytes()],
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod wire;
