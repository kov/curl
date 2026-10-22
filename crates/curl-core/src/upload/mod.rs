//! What a transfer sends: C's client readers (`lib/sendf.c`'s `cr_in`,
//! `cr_buf` and `cr_null`) as one struct, read by the protocol.

#[cfg(test)]
mod tests;

use curl_alloc::TryArc;

use crate::deliver::SendPause;
use crate::error::ErrorKind;
use crate::handler::{DebugKind, Handler, LentBytes, Read, ReadHandler, Rewind};
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
    Bytes(TryArc<Vec<u8>>),
    Lent(Handler<dyn LentBytes>),
    Read {
        handler: Handler<dyn ReadHandler>,
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
            UploadSource::Lent(bytes) => Source::Lent(bytes.clone()),
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

    /// The handler was called, and must be rewound for the body to be
    /// sent again (`Curl_creader_needs_rewind`).
    pub(crate) fn needs_rewind(&self) -> bool {
        match self.source {
            Source::Read { .. } => self.called,
            // Read where they are, as C's `cr_buf` reads its buffer.
            Source::Lent(_) => self.read > 0,
            Source::None | Source::Bytes(_) => false,
        }
    }

    /// Read to its end, whatever size the handler was given: a POST the
    /// application asks chunked (`set_reader`, C's issue 13229). Bytes,
    /// lent or not, keep their length.
    pub(crate) fn read_to_end(&mut self) {
        if let Source::Read { size, .. } = &mut self.source {
            *size = None;
        }
    }

    /// The body's size, where known (`Curl_creader_total_length`).
    pub(crate) fn size(&self) -> Option<u64> {
        match &self.source {
            Source::None => Some(0),
            Source::Bytes(bytes) => Some(bytes.len() as u64),
            Source::Lent(bytes) => Some(bytes.size()),
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
            Source::Lent(bytes) => {
                let len = bytes.size();
                let left = usize::try_from(len - self.read).unwrap_or(usize::MAX);
                let n = if left == 0 {
                    0
                } else {
                    let room = buf.len().min(left);
                    let n = bytes.copy_at(self.read, &mut buf[..room]);
                    assert!(n <= room, "lent bytes copy no more than fit");
                    n
                };
                self.read += n as u64;
                return Ok(Readout {
                    n,
                    eos: self.read == len,
                });
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
    /// possible", unless the handler gave its own reason), followed by
    /// the reader's failure (`Curl_client_start`).
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
            if !rewound {
                if cx.easy().report().reasons() == reasons {
                    let why = format_args!("necessary data rewind was not possible");
                    trace::fail(cx, ErrorKind::SendFailRewind, why);
                }
                // C's reader is `cr-in`, and 65 its `CURLE_SEND_FAIL_REWIND`.
                let why = format_args!("rewind of client reader 'cr-in' failed: 65");
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
