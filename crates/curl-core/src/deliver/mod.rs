//! Delivering a transfer's output to the application's handlers: C's
//! client writer chain (`lib/sendf.c`, `lib/cw-out.c`) as one struct, in
//! the order of its fields.

mod held;
mod pause;

pub use pause::PauseRequest;
pub(crate) use pause::{Directions, Pause, RecvPause, SendPause};

use crate::error::ErrorKind;
use crate::handler::{DebugKind, HeaderOrigin, Write};
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};
use crate::report::Timer;
use crate::trace;
use held::{HeldOutput, OutKind};

/// The most body a write handler is given at once (`CURL_MAX_WRITE_SIZE`).
pub(crate) const MAX_WRITE: usize = 16384;

/// Where a protocol's output comes from (C's `PROTOPT_NONETWORK`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reach {
    /// A connection: its input can stop while output is held, so a write
    /// may pause, and its header lines are kept for the headers API.
    Network,
    /// The local machine: a pausing write fails, and header lines are not
    /// kept.
    Local,
}

/// One request's output, from the protocol to the handlers.
#[derive(Debug)]
pub(crate) struct Pipeline {
    accountant: BodyAccountant,
    out: ClientOut,
    reach: Reach,
}

impl Pipeline {
    pub(crate) fn new(reach: Reach) -> Pipeline {
        Pipeline {
            accountant: BodyAccountant::default(),
            out: ClientOut::default(),
            reach,
        }
    }

    /// Whether the protocol can pause, its input and its output.
    pub(crate) fn pausable(&self) -> bool {
        self.reach == Reach::Network
    }

    /// Replay held output, unless a handler holds it still.
    pub(crate) fn flush<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        self.out.flush(cx, self.pausable())
    }

    /// Whether output is held: the request cannot be over until it is
    /// delivered.
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(dead_code, reason = "only the test protocol holds output before HTTP")
    )]
    pub(crate) fn holds_output(&self) -> bool {
        self.out.holds_output()
    }

    /// The body's size, as the response announces it, or not
    /// (`Curl_pgrsSetDownloadSize`).
    pub(crate) fn announce_size<H: Host>(&mut self, cx: &mut StepCx<'_, H>, size: Option<u64>) {
        cx.report_mut().sizes_mut().download_expected = size;
    }

    /// What the response's head says the body comes to.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no protocol reads a head before HTTP")
    )]
    pub(crate) fn expect(&mut self, expect: Expect) {
        self.accountant.expect = expect;
    }

    /// The body is complete: what more comes is no part of it (C's
    /// `download_done`).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no protocol reads a head before HTTP")
    )]
    pub(crate) fn body_done(&self) -> bool {
        self.accountant.done
    }

    /// The body showed the connection cannot be reused: more came than was
    /// expected, or any where none was.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no protocol reads a head before HTTP")
    )]
    pub(crate) fn body_closes(&self) -> bool {
        self.accountant.close
    }

    /// Body bytes delivered (C's `req.bytecount`).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no protocol reads a head before HTTP")
    )]
    pub(crate) fn bytecount(&self) -> u64 {
        self.accountant.bytecount
    }

    /// Deliver body bytes, as the protocol decoded them (`cw_download`):
    /// none when none was wanted, and no more than the expected size, what
    /// is past it noted and the connection given up.
    pub(crate) fn body<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        bytes: &[u8],
    ) -> Result<(), ErrorKind> {
        raw_trace(cx, bytes);
        self.accountant.response_started(cx);
        let expect = self.accountant.expect;
        if expect.no_body && !bytes.is_empty() {
            // A head was read, so the response is fine; the body goes.
            self.accountant.close = true;
            self.accountant.done = true;
            return Ok(());
        }
        let (wanted, excess) = self.accountant.cut(bytes.len());
        let max_filesize = cx.easy().options().limits.max_filesize;
        let allowed = self.accountant.allowed(wanted, max_filesize);
        self.out.body(cx, &bytes[..allowed], self.pausable())?;
        // Counted once the handlers are done with it: inside them, the
        // download size leaves out the write in progress.
        self.accountant.bytecount += allowed as u64;
        cx.report_mut().sizes_mut().download += allowed as u64;
        if excess > 0 {
            let bytecount = self.accountant.bytecount;
            trace::info(
                cx,
                format_args!(
                    "Excess found writing body: excess = {excess}, size = {}, maxdownload = {}, bytecount = {bytecount}",
                    CSize(expect.size),
                    CSize(expect.max)
                ),
            );
            self.accountant.close = true;
        } else if allowed < wanted {
            let max = max_filesize.expect("only a limit cuts the body short");
            let bytecount = self.accountant.bytecount;
            return Err(trace::fail(
                cx,
                ErrorKind::FilesizeExceeded,
                format_args!(
                    "Exceeded the maximum allowed file size ({max}) with {bytecount} bytes"
                ),
            ));
        }
        Ok(())
    }

    /// The response ended (`CLIENTWRITE_EOS`): a body of a known size must
    /// be whole.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no protocol reads a head before HTTP")
    )]
    pub(crate) fn end<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        let expect = self.accountant.expect;
        let bytecount = self.accountant.bytecount;
        match expect.size {
            Some(size) if expect.max.is_some() && !expect.no_body && size > bytecount => {
                Err(trace::fail(
                    cx,
                    ErrorKind::PartialFile,
                    format_args!("end of response with {} bytes missing", size - bytecount),
                ))
            }
            _ => Ok(()),
        }
    }

    /// Deliver one header line, whole: into the report's header store
    /// from a network, then to the write handler if the headers are
    /// included in the output, then to the header handler.
    pub(crate) fn header<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
        origin: HeaderOrigin,
    ) -> Result<(), ErrorKind> {
        if self.reach == Reach::Network {
            cx.report_mut().headers_mut().push(line, origin)?;
        }
        self.head_line(cx, line, origin)
    }

    /// Deliver a response's status line, as a header line the store does
    /// not keep (`CLIENTWRITE_STATUS`).
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(
            dead_code,
            reason = "only the test protocol writes a status line before HTTP"
        )
    )]
    pub(crate) fn status<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
    ) -> Result<(), ErrorKind> {
        self.head_line(cx, line, HeaderOrigin::Header)
    }

    fn head_line<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
        origin: HeaderOrigin,
    ) -> Result<(), ErrorKind> {
        if origin != HeaderOrigin::Connect {
            self.accountant.response_started(cx);
        }
        // An included line is body, to be held and replayed with it.
        if cx.easy().options().output.include_header {
            self.out.body(cx, line, self.pausable())?;
        }
        self.out.header(cx, line, origin, self.pausable())
    }
}

/// The body as received, before any decoding, to the debug handler of a
/// verbose transfer (`cw_raw_write`).
fn raw_trace<H: Host>(cx: &mut StepCx<'_, H>, bytes: &[u8]) {
    let options = cx.easy().options();
    if !options.output.verbose {
        return;
    }
    if let Some(handler) = options.callbacks.debug.clone() {
        handler.debug(&mut TransferCx::new(cx), DebugKind::DataIn, bytes);
    }
}

/// What a response's head says its body comes to (C's `req.size`,
/// `req.maxdownload` and `req.no_body`); nothing, before a head or
/// without one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Expect {
    /// The size the head gives.
    pub(crate) size: Option<u64>,
    /// The most body to deliver, past which the rest is excess.
    pub(crate) max: Option<u64>,
    /// No body is wanted.
    pub(crate) no_body: bool,
}

/// A size as C prints one: -1 for none.
struct CSize(Option<u64>);

impl std::fmt::Display for CSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(n) => n.fmt(f),
            None => f.write_str("-1"),
        }
    }
}

/// What a request's body came to, and the limits on it (`cw_download`).
#[derive(Debug, Default)]
struct BodyAccountant {
    /// Body bytes past the accountant (C's `req.bytecount`).
    bytecount: u64,
    /// Something of the response, not of a proxy's CONNECT, has come.
    started: bool,
    expect: Expect,
    /// The body is complete.
    done: bool,
    /// The connection is not to be reused.
    close: bool,
}

impl BodyAccountant {
    /// The response's first output: STARTTRANSFER.
    fn response_started<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        if !self.started {
            self.started = true;
            cx.mark(Timer::StartTransfer);
        }
    }

    /// How much of `len` more bytes the expected size wants, and how many
    /// are past it; the body is complete once it has them all.
    fn cut(&mut self, len: usize) -> (usize, usize) {
        let Some(max) = self.expect.max else {
            return (len, 0);
        };
        let left = usize::try_from(max.saturating_sub(self.bytecount)).unwrap_or(usize::MAX);
        let wanted = len.min(left);
        if wanted == left {
            self.done = true;
        }
        (wanted, len - wanted)
    }

    /// How much of `len` more bytes the size limit lets through.
    fn allowed(&self, len: usize, max_filesize: Option<std::num::NonZeroU64>) -> usize {
        let Some(max) = max_filesize else {
            return len;
        };
        let left = max.get().saturating_sub(self.bytecount);
        usize::try_from(left).map_or(len, |left| len.min(left))
    }
}

/// The last stage: the handlers (`cw-out`).
#[derive(Debug, Default)]
enum ClientOut {
    /// Writing straight to the handlers.
    #[default]
    Direct,
    /// Output a write handler paused on, held until it is replayed, with
    /// what came after it.
    Held(HeldOutput),
    /// A write failed: no handler is called again (#13337).
    Failed,
}

impl ClientOut {
    /// Write `bytes` to the write handler in pieces of at most
    /// `MAX_WRITE`, reading the handler again before each; held, if output
    /// is held already.
    fn body<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        bytes: &[u8],
        pausable: bool,
    ) -> Result<(), ErrorKind> {
        let result = self.write(cx, OutKind::Body, bytes, pausable);
        self.fail_on(result)
    }

    fn header<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
        origin: HeaderOrigin,
        pausable: bool,
    ) -> Result<(), ErrorKind> {
        let result = self.write(cx, OutKind::Header(origin), line, pausable);
        self.fail_on(result)
    }

    /// Replay held output until it is all delivered or a handler pauses
    /// again (`cw_out_flush_chain`).
    fn flush<H: Host>(&mut self, cx: &mut StepCx<'_, H>, pausable: bool) -> Result<(), ErrorKind> {
        let result = self.replay(cx, pausable);
        self.fail_on(result)
    }

    fn write<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        kind: OutKind,
        bytes: &[u8],
        pausable: bool,
    ) -> Result<(), ErrorKind> {
        match self {
            ClientOut::Failed => Err(ErrorKind::WriteError),
            ClientOut::Held(held) => {
                held.append(kind, bytes)?;
                self.replay(cx, pausable)
            }
            ClientOut::Direct => {
                let delivered = deliver(cx, kind, bytes, pausable)?;
                if delivered < bytes.len() {
                    let mut held = HeldOutput::default();
                    held.append(kind, &bytes[delivered..])?;
                    *self = ClientOut::Held(held);
                }
                Ok(())
            }
        }
    }

    fn replay<H: Host>(&mut self, cx: &mut StepCx<'_, H>, pausable: bool) -> Result<(), ErrorKind> {
        let held = match self {
            ClientOut::Failed => return Err(ErrorKind::WriteError),
            ClientOut::Direct => return Ok(()),
            ClientOut::Held(held) => held,
        };
        // Only a handler's own pause stops the replay, and it is the only
        // thing that leaves an entry part delivered; one the application
        // asked for from inside it does not.
        while cx.pause().recv != RecvPause::Held {
            let Some((kind, bytes)) = held.front() else {
                break;
            };
            let delivered = deliver(cx, kind, bytes, pausable)?;
            held.consume(delivered);
        }
        if held.is_empty() {
            *self = ClientOut::Direct;
        }
        Ok(())
    }

    /// Any error ends the output for good.
    fn fail_on(&mut self, result: Result<(), ErrorKind>) -> Result<(), ErrorKind> {
        if result.is_err() {
            *self = ClientOut::Failed;
        }
        result
    }

    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(dead_code, reason = "only the test protocol holds output before HTTP")
    )]
    fn holds_output(&self) -> bool {
        matches!(self, ClientOut::Held(_))
    }
}

/// Give `bytes` to the handler for `kind`, body in pieces, until a handler
/// pauses; how much it took. A paused piece is not taken: it is given
/// again, whole, when the transfer goes on (`cw_out_ptr_flush`).
fn deliver<H: Host>(
    cx: &mut StepCx<'_, H>,
    kind: OutKind,
    bytes: &[u8],
    pausable: bool,
) -> Result<usize, ErrorKind> {
    match kind {
        OutKind::Body => deliver_body(cx, bytes, pausable),
        OutKind::Header(origin) => {
            let Some(handler) = cx.easy().options().callbacks.header.clone() else {
                return Ok(bytes.len());
            };
            let reasons = cx.easy().report().reasons();
            let w = handler.header(&mut TransferCx::new(cx), bytes, origin);
            Ok(if verdict(cx, w, bytes.len(), reasons, pausable)? {
                bytes.len()
            } else {
                0
            })
        }
    }
}

fn deliver_body<H: Host>(
    cx: &mut StepCx<'_, H>,
    bytes: &[u8],
    pausable: bool,
) -> Result<usize, ErrorKind> {
    let mut delivered = 0;
    for piece in bytes.chunks(MAX_WRITE) {
        let easy = cx.easy();
        let Some(handler) = easy.options().callbacks.write.clone() else {
            return Ok(bytes.len());
        };
        // Body bytes delivered, included header lines among them (C's
        // `progress.deliver`).
        let so_far = easy.report().sizes().delivered();
        if let Some(max) = easy.options().limits.max_filesize
            && piece.len() as u64 > max.get().saturating_sub(so_far)
        {
            let kind = ErrorKind::FilesizeExceeded;
            return Err(trace::fail(
                cx,
                kind,
                format_args!("Would have exceeded max file size"),
            ));
        }
        let reasons = cx.easy().report().reasons();
        let w = handler.write(&mut TransferCx::new(cx), piece);
        if !verdict(cx, w, piece.len(), reasons, pausable)? {
            break;
        }
        cx.report_mut().sizes_mut().delivered += piece.len() as u64;
        delivered += piece.len();
    }
    Ok(delivered)
}

/// Whether the handler took what it was given; a pause holds the output
/// from here on. A handler that failed with a reason of its own, given
/// since the transfer had `reasons`, is not given another.
fn verdict<H: Host>(
    cx: &mut StepCx<'_, H>,
    w: Write,
    len: usize,
    reasons: u32,
    pausable: bool,
) -> Result<bool, ErrorKind> {
    match w {
        Write::Accepted => Ok(true),
        Write::Pause if !pausable => Err(trace::fail(
            cx,
            ErrorKind::WriteError,
            format_args!("Write callback asked for PAUSE when not supported"),
        )),
        Write::Pause => {
            cx.pause_mut().recv = RecvPause::Held;
            Ok(false)
        }
        Write::Fail if cx.easy().report().reasons() != reasons => Err(ErrorKind::WriteError),
        Write::Fail => Err(trace::fail(
            cx,
            ErrorKind::WriteError,
            format_args!("client returned ERROR on write of {len} bytes"),
        )),
    }
}

#[cfg(test)]
mod tests;
