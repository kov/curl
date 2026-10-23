//! What a transfer sends: C's client readers (`lib/sendf.c`'s `cr_in`,
//! `cr_buf` and `cr_null`, `lib/mime.c`'s `cr_mime`) as one struct, read
//! by the protocol.

pub(crate) mod chain;
#[cfg(test)]
mod tests;

use curl_alloc::{TryArc, try_box};

use crate::components::Component;
use crate::error::ErrorKind;
use crate::handler::{DebugKind, Handler, LentBytes, Read, ReadHandler, Rewind};
use crate::mime::MimeError;
use crate::mime::read::{Escape, MakeError, MimeReader};
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};
use crate::options::UploadSource;
use crate::progress::rate::Way;
use crate::proto::http1::request::UserHeaders;
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
    Mime(Box<MimeReader>),
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
    /// The body `source` gives, from its start; a tree's headers made for
    /// a request whose own lines are `request`, its names quoted as
    /// `escaping` says. A tree's handlers are rewound by `start`.
    pub(crate) fn new(
        source: &UploadSource,
        request: &UserHeaders,
        escaping: Escape,
    ) -> Result<Upload, MakeError> {
        let source = match source {
            UploadSource::Mime(tree) => match tree.mime() {
                Ok(Some(mime)) => Source::Mime(try_box(MimeReader::new(mime, request, escaping)?)?),
                // Nothing to send: an empty body (C's unbound part).
                Ok(None) => Source::None,
                Err(MimeError::OutOfMemory) => return Err(MakeError::OutOfMemory),
                Err(MimeError::TooDeep) => return Err(MakeError::TooLarge),
                Err(MimeError::Unreadable) => return Err(MakeError::Unreadable),
            },
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
        Ok(Upload {
            source,
            read: 0,
            latch: Latch::Open,
            called: false,
        })
    }

    /// The body of a source that is no tree.
    #[cfg(test)]
    pub(crate) fn plain(source: &UploadSource) -> Upload {
        assert!(!matches!(source, UploadSource::Mime(_)), "no tree");
        Upload::new(source, &UserHeaders::NONE, Escape::Form).expect("no tree to make")
    }

    /// Nothing to send.
    pub(crate) fn empty() -> Upload {
        Upload {
            source: Source::None,
            read: 0,
            latch: Latch::Open,
            called: false,
        }
    }

    /// The reader set for a request, as C traces it
    /// (`Curl_creader_set_buf`, `Curl_creader_set_fread`): a tree's and
    /// nothing's are set untraced.
    pub(crate) fn trace_set<H: Host>(&self, cx: &mut StepCx<'_, H>) {
        match &self.source {
            Source::Bytes(_) | Source::Lent(_) => {
                let len = self.size().expect("bytes have a length");
                trace::of(
                    cx,
                    Component::Read,
                    format_args!("add buf reader, len={len} -> 0"),
                );
            }
            Source::Read { size, .. } => {
                let len = Total(*size);
                trace::of(
                    cx,
                    Component::Read,
                    format_args!("add fread reader, len={len} -> 0"),
                );
            }
            Source::None | Source::Mime(_) => {}
        }
    }

    /// Ready to be read: a tree's handlers rewound, as it may have been
    /// read before (`Curl_creader_set_mime`); failing, SendFailRewind.
    pub(crate) fn start<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        match &mut self.source {
            Source::Mime(reader) => reader.start(cx),
            _ => Ok(()),
        }
    }

    /// The body of the transfer's options, ready to be read: a tree with
    /// no request headers of its own to type it.
    pub(crate) fn open<H: Host>(cx: &mut StepCx<'_, H>) -> Result<Upload, ErrorKind> {
        let source = cx.easy().options().upload.clone();
        let escaping = cx.easy().options().mime_escape();
        let mut upload =
            Upload::new(&source, &UserHeaders::NONE, escaping).map_err(MakeError::kind)?;
        upload.start(cx)?;
        Ok(upload)
    }

    /// Whether the source can pause the body, and as which of C's readers.
    pub(crate) fn pausing(&self) -> Option<Pausing> {
        match &self.source {
            Source::Read { .. } => Some(Pausing::Handler),
            Source::Mime(_) => Some(Pausing::Mime),
            Source::None | Source::Bytes(_) | Source::Lent(_) => None,
        }
    }

    /// The header lines the request sends to type the body: a tree's.
    pub(crate) fn head(&self) -> Option<&[Vec<u8>]> {
        match &self.source {
            Source::Mime(reader) => Some(reader.head()),
            _ => None,
        }
    }

    /// The handler was called, and must be rewound for the body to be
    /// sent again (`Curl_creader_needs_rewind`).
    pub(crate) fn needs_rewind(&self) -> bool {
        match &self.source {
            Source::Read { .. } => self.called,
            // Read from at all, as C's `cr_buf` says of its buffer,
            // copied or not.
            Source::Bytes(_) | Source::Lent(_) => self.read > 0,
            Source::Mime(reader) => reader.needs_rewind(),
            Source::None => false,
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
            Source::Mime(reader) => reader.size(),
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
        let (handler, size) = match &mut self.source {
            Source::None => return Ok(Readout { n: 0, eos: true }),
            Source::Mime(reader) => return reader.read(cx, buf, pausable),
            Source::Bytes(bytes) => {
                let at = usize::try_from(self.read).expect("an index into the bytes");
                let n = (bytes.len() - at).min(buf.len());
                buf[..n].copy_from_slice(&bytes[at..at + n]);
                self.read += n as u64;
                let eos = at + n == bytes.len();
                return Ok(buf_read(cx, buf.len(), Readout { n, eos }));
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
                let eos = self.read == len;
                return Ok(buf_read(cx, buf.len(), Readout { n, eos }));
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
        let got = self.answered(cx, answer, size, room, pausable);
        let (code, n, eos) = match got {
            Ok(Readout { n, eos }) => (trace::Code(Ok(())), n, eos),
            Err(e) => (trace::Code(Err(e)), 0, false),
        };
        let (total, read) = (Total(size), self.read);
        trace::of(
            cx,
            Component::Read,
            format_args!(
                "cr_in_read(len={room}, total={total}, read={read}) -> {code}, nread={n}, eos={}",
                u8::from(eos)
            ),
        );
        got
    }

    /// What the read handler's `answer` to a read of `room` comes to.
    fn answered<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        answer: Read,
        size: Option<u64>,
        room: usize,
        pausable: bool,
    ) -> Result<Readout, ErrorKind> {
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
                trace::of(
                    cx,
                    Component::Read,
                    format_args!("cr_in_read, callback returned CURL_READFUNC_PAUSE"),
                );
                cx.pause_mut().ask_send();
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
        if let Source::Mime(reader) = &mut self.source {
            return reader.rewind(cx);
        }
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

/// The readers C stacks for a request's body (`data->req.reader.stack`)
/// whose source can pause it, from the network's side: the chunk stage,
/// the 100's wait, then the source. Set as the request's body is, and let
/// go with C's stack (`Curl_client_reset`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Readers {
    pub(crate) chunked: bool,
    /// The head said `Expect: 100-continue`: C's reader for it stays for
    /// the request, the 100 come or not.
    pub(crate) exp100: bool,
    pub(crate) client: Pausing,
}

/// A source that can pause the body, by C's name for its reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pausing {
    /// The application's read handler (`cr-in`).
    Handler,
    /// A tree's (`cr-mime`).
    Mime,
}

impl Readers {
    /// The pause a reader asked for is lifted: each reader is told, its
    /// name traced as it is (`Curl_creader_unpause`). None of them fails.
    pub(crate) fn trace_unpause<H: Host>(self, cx: &mut StepCx<'_, H>) {
        let client = match self.client {
            Pausing::Handler => "cr-in",
            Pausing::Mime => "cr-mime",
        };
        let stack = [
            self.chunked.then_some("chunked"),
            self.exp100.then_some("cr-exp100"),
            Some(client),
        ];
        for name in stack.into_iter().flatten() {
            trace::of(cx, Component::Read, format_args!("unpausing {name} -> 0"));
        }
    }
}

/// A body's size as C's readers trace it: -1 for one not known.
pub(crate) struct Total(pub(crate) Option<u64>);

impl std::fmt::Display for Total {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(size) => size.fmt(f),
            None => f.write_str("-1"),
        }
    }
}

/// A read of bytes the transfer holds, into room for `len` (`cr_buf_read`).
fn buf_read<H: Host>(cx: &mut StepCx<'_, H>, len: usize, got: Readout) -> Readout {
    let (n, eos) = (got.n, u8::from(got.eos));
    trace::of(
        cx,
        Component::Read,
        format_args!("cr_buf_read(len={len}) -> 0, nread={n}, eos={eos}"),
    );
    got
}

/// A read of the request's body through its readers, for room of `len`
/// (`Curl_client_read`).
pub(crate) fn client_read<H: Host>(
    cx: &mut StepCx<'_, H>,
    len: usize,
    got: &Result<Readout, ErrorKind>,
) {
    let (code, n, eos) = match *got {
        Ok(Readout { n, eos }) => (trace::Code(Ok(())), n, eos),
        Err(e) => (trace::Code(Err(e)), 0, false),
    };
    trace::of(
        cx,
        Component::Read,
        format_args!(
            "client_read(len={len}) -> {code}, nread={n}, eos={}",
            u8::from(eos)
        ),
    );
}

/// The readers are let go as a request starts or ends, unless the next
/// request is to send the body again, when they are kept to be rewound
/// (`Curl_client_reset`).
pub(crate) fn trace_reset<H: Host>(cx: &mut StepCx<'_, H>, rewinding: bool) {
    let what = if rewinding {
        "will rewind reader"
    } else {
        "clear readers"
    };
    trace::of(cx, Component::Read, format_args!("client_reset, {what}"));
    if !rewinding {
        *cx.readers_mut() = None;
    }
}

/// Body bytes went out: counted, and traced for a verbose transfer
/// (`xfer_send`'s DATA_OUT). `file:` writes its body itself, untraced.
pub(crate) fn sent<H: Host>(cx: &mut StepCx<'_, H>, body: &[u8]) {
    if body.is_empty() {
        return;
    }
    crate::trace::bytes(cx, DebugKind::DataOut, body);
    // The request's size counts them where the protocol sends them, with
    // the head and any framing (`Curl_xfer_send`).
    cx.report_mut().sizes_mut().upload += body.len() as u64;
    // The send limit takes them (`Curl_pgrs_upload_inc`).
    cx.rate_drain(Way::Send, body.len());
}

/// The size of the body to send, as the request announces it, or not
/// (`Curl_pgrsSetUploadSize`).
pub(crate) fn announce_size<H: Host>(cx: &mut StepCx<'_, H>, size: Option<u64>) {
    cx.report_mut().sizes_mut().upload_expected = size;
}
