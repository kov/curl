//! Delivering a transfer's output to the application's handlers: C's
//! client writer chain (`lib/sendf.c`, `lib/cw-out.c`) as one struct, in
//! the order of its fields.

#![cfg_attr(
    not(any(test, feature = "test-util")),
    expect(dead_code, reason = "no protocol is built in before step 8")
)]

use crate::error::ErrorKind;
use crate::handler::{DebugKind, HeaderOrigin, Write};
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};
use crate::report::Timer;

/// The most body a write handler is given at once (`CURL_MAX_WRITE_SIZE`).
pub(crate) const MAX_WRITE: usize = 16384;

/// One request's output, from the protocol to the handlers.
#[derive(Debug, Default)]
pub(crate) struct Pipeline {
    accountant: BodyAccountant,
    out: ClientOut,
}

impl Pipeline {
    /// Deliver body bytes, as the protocol decoded them.
    pub(crate) fn body<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        bytes: &[u8],
    ) -> Result<(), ErrorKind> {
        raw_trace(cx, bytes);
        self.accountant.response_started(cx);
        let max_filesize = cx.easy().options().limits.max_filesize;
        let allowed = self.accountant.allowed(bytes.len(), max_filesize);
        self.out.body(cx, &bytes[..allowed])?;
        // Counted once the handlers are done with it: inside them, the
        // download size leaves out the write in progress.
        self.accountant.bytecount += allowed as u64;
        cx.report_mut().sizes_mut().download += allowed as u64;
        if allowed < bytes.len() {
            // "Exceeded the maximum allowed file size"
            return Err(ErrorKind::FilesizeExceeded);
        }
        Ok(())
    }

    /// Deliver one header line, whole: to the write handler first if the
    /// headers are included in the output, then to the header handler.
    pub(crate) fn header<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
        origin: HeaderOrigin,
    ) -> Result<(), ErrorKind> {
        if origin != HeaderOrigin::Connect {
            self.accountant.response_started(cx);
        }
        if cx.easy().options().output.include_header {
            self.out.body(cx, line)?;
        }
        self.out.header(cx, line, origin)
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

/// What a request's body came to, and the limits on it (`cw_download`).
#[derive(Debug, Default)]
struct BodyAccountant {
    /// Body bytes past the accountant (C's `req.bytecount`).
    bytecount: u64,
    /// Something of the response, not of a proxy's CONNECT, has come.
    started: bool,
}

impl BodyAccountant {
    /// The response's first output: STARTTRANSFER.
    fn response_started<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        if !self.started {
            self.started = true;
            cx.mark(Timer::StartTransfer);
        }
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
    /// A write failed: no handler is called again (#13337).
    Failed,
}

impl ClientOut {
    /// Write `bytes` to the write handler in pieces of at most
    /// `MAX_WRITE`, reading the handler again before each.
    fn body<H: Host>(&mut self, cx: &mut StepCx<'_, H>, bytes: &[u8]) -> Result<(), ErrorKind> {
        let result = self.try_body(cx, bytes);
        self.fail_on(result)
    }

    fn try_body<H: Host>(&mut self, cx: &mut StepCx<'_, H>, bytes: &[u8]) -> Result<(), ErrorKind> {
        if let ClientOut::Failed = self {
            return Err(ErrorKind::WriteError);
        }
        for piece in bytes.chunks(MAX_WRITE) {
            let easy = cx.easy();
            let Some(handler) = easy.options().callbacks.write.clone() else {
                return Ok(());
            };
            // Body bytes delivered, included header lines among them (C's
            // `progress.deliver`).
            let delivered = easy.report().sizes().delivered();
            if let Some(max) = easy.options().limits.max_filesize
                && piece.len() as u64 > max.get().saturating_sub(delivered)
            {
                // "Would have exceeded max file size"
                return Err(ErrorKind::FilesizeExceeded);
            }
            verdict(handler.write(&mut TransferCx::new(cx), piece))?;
            cx.report_mut().sizes_mut().delivered += piece.len() as u64;
        }
        Ok(())
    }

    fn header<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
        origin: HeaderOrigin,
    ) -> Result<(), ErrorKind> {
        let result = match self {
            ClientOut::Failed => Err(ErrorKind::WriteError),
            ClientOut::Direct => match cx.easy().options().callbacks.header.clone() {
                None => Ok(()),
                Some(handler) => verdict(handler.header(&mut TransferCx::new(cx), line, origin)),
            },
        };
        self.fail_on(result)
    }

    /// Any error ends the output for good.
    fn fail_on(&mut self, result: Result<(), ErrorKind>) -> Result<(), ErrorKind> {
        if result.is_err() {
            *self = ClientOut::Failed;
        }
        result
    }
}

fn verdict(w: Write) -> Result<(), ErrorKind> {
    match w {
        Write::Accepted => Ok(()),
        // No protocol can pause yet ("Write callback asked for PAUSE when
        // not supported").
        Write::Pause | Write::Fail => Err(ErrorKind::WriteError),
    }
}

#[cfg(test)]
mod tests;
