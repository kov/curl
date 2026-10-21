//! What a transfer sends: C's client readers (`lib/sendf.c`'s `cr_in`,
//! `cr_buf` and `cr_null`) as one struct, read by the protocol.

#[cfg(test)]
mod tests;

use curl_alloc::TryRc;

use crate::deliver::SendPause;
use crate::error::ErrorKind;
use crate::handler::{DebugKind, Handler, Read, ReadHandler, Rewind};
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};
use crate::options::UploadSource;
use crate::trace;

/// One request's body to send, read from its source.
#[derive(Debug)]
pub(crate) struct Upload {
    source: Source,
    /// Bytes read since the start or the last rewind (`read_len`, `index`).
    read: u64,
    latch: Latch,
    /// The handler has been called since the start or the last rewind,
    /// whatever it answered (`has_used_cb`).
    called: bool,
}

#[derive(Debug)]
enum Source {
    None,
    Bytes(TryRc<Vec<u8>>),
    Read {
        handler: Handler<dyn ReadHandler>,
        #[cfg_attr(
            not(any(test, feature = "test-util")),
            expect(
                dead_code,
                reason = "only the test protocol sends a body again before HTTP"
            )
        )]
        rewind: Option<Handler<dyn Rewind>>,
        size: Option<u64>,
    },
}

/// Whether a read handler is called again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Latch {
    Open,
    /// It said it was done, or gave the whole size: never again until a
    /// rewind.
    Eof,
    /// It failed: the same failure, without calling it, from now on.
    Errored(ErrorKind),
}

/// What a read gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Readout {
    /// Bytes at the start of the buffer.
    pub(crate) n: usize,
    /// The body is complete with them.
    pub(crate) eos: bool,
}

impl Upload {
    /// The body `source` gives, from its start.
    pub(crate) fn new(source: &UploadSource) -> Upload {
        let source = match source {
            UploadSource::None => Source::None,
            UploadSource::Bytes(bytes) => Source::Bytes(bytes.clone()),
            UploadSource::Read {
                handler,
                rewind,
                size,
            } => Source::Read {
                handler: handler.clone(),
                rewind: rewind.clone(),
                size: *size,
            },
        };
        Upload {
            source,
            read: 0,
            latch: Latch::Open,
            called: false,
        }
    }

    /// The body's size, where known (`Curl_creader_total_length`).
    pub(crate) fn size(&self) -> Option<u64> {
        match &self.source {
            Source::None => Some(0),
            Source::Bytes(bytes) => Some(bytes.len() as u64),
            Source::Read { size, .. } => *size,
        }
    }

    /// Read into `buf`, which is not empty, at most what is left of a known
    /// size. A handler pausing (where the protocol `pausable` can) pauses
    /// the transfer's sending and gives nothing.
    pub(crate) fn read<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        buf: &mut [u8],
        pausable: bool,
    ) -> Result<Readout, ErrorKind> {
        assert!(!buf.is_empty(), "a read has room");
        let (handler, size) = match &self.source {
            Source::None => return Ok(Readout { n: 0, eos: true }),
            Source::Bytes(bytes) => {
                let at = usize::try_from(self.read).expect("an index into the bytes");
                let n = (bytes.len() - at).min(buf.len());
                buf[..n].copy_from_slice(&bytes[at..at + n]);
                self.read += n as u64;
                let eos = at + n == bytes.len();
                return Ok(Readout { n, eos });
            }
            Source::Read { handler, size, .. } => (handler.clone(), *size),
        };
        match self.latch {
            Latch::Errored(e) => return Err(e),
            Latch::Eof => return Ok(Readout { n: 0, eos: true }),
            Latch::Open => {}
        }
        let room = match size {
            Some(size) => buf
                .len()
                .min(usize::try_from(size - self.read).unwrap_or(usize::MAX)),
            None => buf.len(),
        };
        // With the whole size read, the handler is not asked again.
        let answer = if room > 0 {
            self.called = true;
            handler.read(&mut TransferCx::new(cx), &mut buf[..room])
        } else {
            Read::Eof
        };
        match answer {
            Read::Eof => {
                if let Some(size) = size
                    && self.read < size
                {
                    let read = self.read;
                    return Err(trace::fail(
                        cx,
                        ErrorKind::ReadError,
                        format_args!(
                            "client read function EOF fail, only {read}/{size} of needed bytes read"
                        ),
                    ));
                }
                self.latch = Latch::Eof;
                Ok(Readout { n: 0, eos: true })
            }
            Read::Abort => {
                let why = format_args!("operation aborted by callback");
                Err(self.fail(trace::fail(cx, ErrorKind::AbortedByCallback, why)))
            }
            Read::Fail => {
                let why = format_args!("client read function failed");
                Err(self.fail(trace::fail(cx, ErrorKind::ReadError, why)))
            }
            Read::Pause if !pausable => {
                let why = format_args!("Read callback asked for PAUSE when not supported");
                Err(trace::fail(cx, ErrorKind::ReadError, why))
            }
            Read::Pause => {
                cx.pause_mut().send = SendPause::Paused;
                Ok(Readout { n: 0, eos: false })
            }
            Read::Data(n) if n.get() > room => {
                let why = format_args!("read function returned funny value");
                Err(self.fail(trace::fail(cx, ErrorKind::ReadError, why)))
            }
            Read::Data(n) => {
                self.read += n.get() as u64;
                let eos = size.is_some_and(|size| self.read >= size);
                if eos {
                    self.latch = Latch::Eof;
                }
                Ok(Readout { n: n.get(), eos })
            }
        }
    }

    fn fail(&mut self, e: ErrorKind) -> ErrorKind {
        self.latch = Latch::Errored(e);
        e
    }

    /// Start the body over (`cr_in_rewind`, `cr_buf_cntrl`). A handler that
    /// was called, whatever it answered, needs its rewind: without one, or
    /// if it fails, SendFailRewind ("necessary data rewind was not
    /// possible").
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(
            dead_code,
            reason = "only the test protocol sends a body again before HTTP"
        )
    )]
    pub(crate) fn rewind<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        if let Source::Read { rewind, .. } = &self.source {
            if !self.called {
                return Ok(());
            }
            let reasons = cx.easy().report().reasons();
            let rewound = match rewind.clone() {
                Some(rewind) => rewind.rewind(&mut TransferCx::new(cx)).is_ok(),
                None => false,
            };
            if !rewound && cx.easy().report().reasons() != reasons {
                return Err(ErrorKind::SendFailRewind);
            }
            if !rewound {
                let why = format_args!("necessary data rewind was not possible");
                return Err(trace::fail(cx, ErrorKind::SendFailRewind, why));
            }
        }
        self.read = 0;
        self.latch = Latch::Open;
        self.called = false;
        Ok(())
    }
}

/// Body bytes went out: counted, and traced for a verbose transfer
/// (`xfer_send`'s DATA_OUT). `file:` writes its body itself, untraced.
pub(crate) fn sent<H: Host>(cx: &mut StepCx<'_, H>, body: &[u8]) {
    if body.is_empty() {
        return;
    }
    let options = cx.easy().options();
    if options.output.verbose
        && let Some(handler) = options.callbacks.debug.clone()
    {
        handler.debug(&mut TransferCx::new(cx), DebugKind::DataOut, body);
    }
    // The request's size counts them where the protocol sends them, with
    // the head and any framing (`Curl_xfer_send`).
    cx.report_mut().sizes_mut().upload += body.len() as u64;
}

/// The size of the body to send, as the request announces it, or not
/// (`Curl_pgrsSetUploadSize`).
pub(crate) fn announce_size<H: Host>(cx: &mut StepCx<'_, H>, size: Option<u64>) {
    cx.report_mut().sizes_mut().upload_expected = size;
}
