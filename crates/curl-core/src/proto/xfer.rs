//! The receive side of a transfer whose protocol reads its body over a
//! stream, as FTP, IMAP, POP3, DICT and Gopher do (C's
//! `Curl_xfer_setup_recv` and `sendrecv_dl`): what is left to read, one
//! pass of reads, and what ended it, traced as C traces it. Where the bytes
//! come from is a `Source`, where they go and what the end does a `Sink`.

use super::ProtoStep;
use crate::conn::io::Recv;
use crate::conn::{ConnLease, RecvBuf, RecvFailed};
use crate::deliver::{self, Pipeline};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::progress::rate::Way;
use crate::trace;

/// What a pass reads from.
pub(crate) trait Source<H: Host> {
    /// Read once, up to `max` bytes, into its buffer.
    fn recv(&mut self, cx: &mut StepCx<'_, H>, max: usize) -> Result<Recv, RecvFailed>;
    /// Whether its layers hold bytes the socket will not wake for.
    fn data_pending(&mut self) -> bool;
    /// Its buffer, out of it for as long as a body is written.
    fn take_rx(&mut self) -> RecvBuf;
    /// The buffer back.
    fn put_rx(&mut self, rx: RecvBuf);
}

impl<H: Host> Source<H> for ConnLease {
    fn recv(&mut self, cx: &mut StepCx<'_, H>, max: usize) -> Result<Recv, RecvFailed> {
        self.get().recv(cx, max)
    }

    fn data_pending(&mut self) -> bool {
        self.get().data_pending()
    }

    fn take_rx(&mut self) -> RecvBuf {
        std::mem::take(self.get().rx_mut())
    }

    fn put_rx(&mut self, rx: RecvBuf) {
        *self.get().rx_mut() = rx;
    }
}

/// Where a pass's bytes go, and what ends it.
pub(crate) trait Sink<H: Host, S> {
    /// Body bytes: whether they ended the body.
    fn body(&mut self, cx: &mut StepCx<'_, H>, bytes: &[u8]) -> Result<bool, ErrorKind>;
    /// The body's bytes so far, against the size said.
    fn bytecount(&self) -> u64;
    /// The source ended, or the `size` said is all here. A step to return
    /// if the end has to wait, none once it is over; a failure ends it too.
    fn end(
        &mut self,
        cx: &mut StepCx<'_, H>,
        source: &mut S,
        size: Option<u64>,
    ) -> Result<Option<ProtoStep>, ErrorKind>;
}

/// The end of the body writes through the writers (`CLIENTWRITE_EOS`).
impl<H: Host, S> Sink<H, S> for Pipeline {
    fn body(&mut self, cx: &mut StepCx<'_, H>, bytes: &[u8]) -> Result<bool, ErrorKind> {
        Pipeline::body(self, cx, bytes)?;
        Ok(self.body_done())
    }

    fn bytecount(&self) -> u64 {
        Pipeline::bytecount(self)
    }

    fn end(
        &mut self,
        cx: &mut StepCx<'_, H>,
        _: &mut S,
        _: Option<u64>,
    ) -> Result<Option<ProtoStep>, ErrorKind> {
        write_end(cx, self)?;
        Ok(None)
    }
}

/// The body's end said and written through `pipeline`'s writers
/// (`Curl_xfer_write_resp`).
pub(crate) fn write_end<H: Host>(
    cx: &mut StepCx<'_, H>,
    pipeline: &mut Pipeline,
) -> Result<(), ErrorKind> {
    trace::debug_info(cx, format_args!("sendrecv_dl: we are done"));
    let ended = pipeline.end(cx);
    deliver::write_resp(cx, 0, true, ended);
    ended
}

/// What a transfer has left to read.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Receive {
    /// The size said of the body, all that is read of it (`req.size`).
    size: Option<u64>,
    /// It is being read (`KEEP_RECV`).
    receiving: bool,
    /// The source's end was met and its end is under way, waiting:
    /// nothing more is read from it, only the end moved on
    /// (`xfer_recv_shutdown_started`).
    ending: bool,
}

impl Receive {
    /// The size the body is said to be, before it is read.
    pub(crate) fn size(&self) -> Option<u64> {
        self.size
    }

    pub(crate) fn set_size(&mut self, size: Option<u64>) {
        self.size = size;
    }

    /// Whether it is being read (`KEEP_RECV`).
    pub(crate) fn is_receiving(&self) -> bool {
        self.receiving
    }

    /// Start reading it.
    pub(crate) fn start(&mut self) {
        self.receiving = true;
        self.ending = false;
    }

    /// Start reading a body of `size` (`Curl_xfer_setup_recv`).
    pub(crate) fn start_sized(&mut self, size: u64) {
        self.size = Some(size);
        self.receiving = true;
        self.ending = false;
    }

    /// Start reading a body of no size said, to its end, said as C says it
    /// (`Curl_xfer_setup_recv`).
    pub(crate) fn start_to_end<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        crate::multi::mstate::xfer_setup(
            cx,
            deliver::Directions {
                recv: true,
                send: false,
            },
        );
        self.receiving = true;
        self.ending = false;
    }

    /// Read no more.
    pub(crate) fn stop(&mut self) {
        self.receiving = false;
    }

    /// As many reads as a pass of C's makes (`sendrecv_dl`), from `source`
    /// into `sink`, what ended the pass traced as C traces it.
    pub(crate) fn read<H: Host, S: Source<H>>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        source: &mut S,
        sink: &mut impl Sink<H, S>,
    ) -> Result<ProtoStep, ErrorKind> {
        let read = self.pass(cx, source, sink);
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

    fn pass<H: Host, S: Source<H>>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        source: &mut S,
        sink: &mut impl Sink<H, S>,
    ) -> Result<ProtoStep, ErrorKind> {
        let mut reads = 0;
        loop {
            if !self.receiving {
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
            // A size said is all that is read: what follows it is not
            // asked for (`xfer_recv_resp`).
            let max = match self.size {
                Some(size) => {
                    let left = size.saturating_sub(sink.bytecount());
                    max.min(usize::try_from(left).unwrap_or(usize::MAX))
                }
                None => max,
            };
            // All is here, or the end is under way: the end is moved on,
            // and nothing more read (`xfer_recv_resp`).
            if max == 0 || self.ending {
                if let Some(step) = self.end(cx, source, sink)? {
                    return Ok(step);
                }
                continue;
            }
            reads += 1;
            let said = cx.easy().report().reasons();
            match source.recv(cx, max) {
                Ok(Recv::WouldBlock) if source.data_pending() => {
                    return Ok(ProtoStep::AtReadLimit);
                }
                Ok(Recv::WouldBlock) => return Ok(ProtoStep::Blocked),
                Ok(Recv::Eof) => {
                    self.ending = true;
                    if let Some(step) = self.end(cx, source, sink)? {
                        return Ok(step);
                    }
                }
                Ok(Recv::Data(_)) => {
                    let mut rx = source.take_rx();
                    let fed = sink.body(cx, rx.filled());
                    let all = rx.filled().len();
                    rx.consume(all);
                    source.put_rx(rx);
                    deliver::write_resp(cx, all, false, fed.map(|_| ()));
                    if fed? {
                        self.receiving = false;
                    }
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

    /// The end, the source's or the size's: over unless it asks to wait.
    fn end<H: Host, S: Source<H>>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        source: &mut S,
        sink: &mut impl Sink<H, S>,
    ) -> Result<Option<ProtoStep>, ErrorKind> {
        let ended = sink.end(cx, source, self.size);
        if !matches!(ended, Ok(Some(_))) {
            self.receiving = false;
        }
        ended
    }
}
