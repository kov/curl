//! What an application gives a transfer to call: where its output goes.
//!
//! Each handler is shared, as C's callback and its userdata pointer are: a
//! copy of the `Easy` (`curl_easy_duphandle`) calls the same one. So a
//! handler is called through `&self` and keeps its state in cells.

use std::fmt;
use std::num::NonZeroUsize;
use std::ops::Deref;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};

use crate::multi::TransferCx;

/// What a write or header handler did with what it was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Write {
    Accepted,
    /// Stop delivering; what was given is delivered again once unpaused
    /// (`CURL_WRITEFUNC_PAUSE`).
    Pause,
    /// The transfer fails with a write error.
    Fail,
    /// This many of the bytes given were taken: any other count than all
    /// of them fails the transfer with a write error, as a destination
    /// that could not take them.
    Took(usize),
}

/// What a read handler gave (`CURLOPT_READFUNCTION`'s return).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// This many bytes at the start of the buffer; more than it holds is
    /// a read error.
    Data(NonZeroUsize),
    /// Nothing more to send.
    Eof,
    /// Nothing now; the transfer's sending is paused until unpaused
    /// (`CURL_READFUNC_PAUSE`).
    Pause,
    /// The transfer fails with AbortedByCallback (`CURL_READFUNC_ABORT`).
    Abort,
    /// What there is to send could not be read: the transfer fails with
    /// ReadError.
    Fail,
}

/// Gives what a transfer sends (`CURLOPT_READFUNCTION`).
pub trait ReadHandler: Send + Sync {
    fn read(&self, cx: &mut TransferCx<'_>, buf: &mut [u8]) -> Read;
}

/// Gives the trailers a chunked request body ends with
/// (`CURLOPT_TRAILERFUNCTION`): each line, `Name: value`, added to
/// `lines`; a line without a colon and a space after it is skipped.
pub trait TrailerHandler: Send + Sync {
    fn trailers(&self, cx: &mut TransferCx<'_>, lines: &mut TrailerLines) -> Trailers;
}

/// Whether a trailer handler lets the body end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trailers {
    Done,
    /// The transfer fails with AbortedByCallback.
    Abort,
}

/// The trailer lines a handler gives, each without its line end. A line
/// that could not be kept fails the transfer with OutOfMemory.
#[derive(Debug, Default)]
pub struct TrailerLines {
    lines: Vec<Vec<u8>>,
    lost: bool,
}

impl TrailerLines {
    pub fn add(&mut self, line: &[u8]) -> Result<(), OutOfMemory> {
        let mut copy = Vec::new();
        let kept = copy
            .try_extend_from_slice(line)
            .and_then(|()| self.lines.try_push(copy));
        self.lost |= kept.is_err();
        kept
    }

    /// The lines, or none if one was lost.
    pub(crate) fn lines(&self) -> Result<impl Iterator<Item = &[u8]>, OutOfMemory> {
        if self.lost {
            return Err(OutOfMemory);
        }
        Ok(self.lines.iter().map(Vec::as_slice))
    }
}

/// A rewind that could not be done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewindFailed;

/// Starts what a read handler gives over from the beginning, for a request
/// sent again (`CURLOPT_SEEKFUNCTION` to 0, `CURLOPT_IOCTLFUNCTION`).
pub trait Rewind: Send + Sync {
    fn rewind(&self, cx: &mut TransferCx<'_>) -> Result<(), RewindFailed>;
}

/// Where a header line came from (`CURLH_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderOrigin {
    /// The response's head.
    Header,
    /// After the body (`CURLH_TRAILER`).
    Trailer,
    /// A proxy's answer to CONNECT (`CURLH_CONNECT`).
    Connect,
    /// An informational response, 1xx (`CURLH_1XX`).
    Interim,
}

/// Bytes the application holds and lends as a body, of a known length:
/// read where they are as they are sent, not copied when given
/// (`CURLOPT_POSTFIELDS`). The body's position is the transfer's.
pub trait LentBytes: Send + Sync {
    /// How many there are.
    fn size(&self) -> u64;
    /// Copy into `buf` those from `at`, which is below `size`, as many as
    /// fit; how many.
    fn copy_at(&self, at: u64, buf: &mut [u8]) -> usize;
}

/// A list of lines the application keeps, and may change after giving
/// it: read again each time a transfer would read the option it is given
/// for, so that a line added since is seen (`CURLOPT_HTTPHEADER` and the
/// other `curl_slist` options, which C walks where it uses them).
pub trait LineSource: Send + Sync {
    /// Give each line, in order, to `line`; stop at its first error.
    fn lines(
        &self,
        line: &mut dyn FnMut(&[u8]) -> Result<(), OutOfMemory>,
    ) -> Result<(), OutOfMemory>;
}

/// What a trace entry is (`curl_infotype`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugKind {
    Text,
    HeaderIn,
    HeaderOut,
    DataIn,
    DataOut,
    SslDataIn,
    SslDataOut,
}

/// How far a transfer has come, for its progress handler. A size not
/// known is `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProgressNow {
    pub download_total: Option<u64>,
    pub downloaded: u64,
    pub upload_total: Option<u64>,
    pub uploaded: u64,
}

/// What a progress handler wants done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressVerdict {
    Continue,
    /// Go on, and draw the meter as if there were no handler
    /// (`CURL_PROGRESSFUNC_CONTINUE`).
    ContinueWithMeter,
    /// The transfer fails with AbortedByCallback.
    Abort,
}

/// Told of a transfer's progress, about once a second and whenever it
/// moves (`CURLOPT_XFERINFOFUNCTION`).
pub trait ProgressHandler: Send + Sync {
    fn progress(&self, cx: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict;
}

/// Takes text meant for the user: the progress meter, and messages with
/// no debug handler to go to (`CURLOPT_STDERR`).
pub trait TextSink: Send + Sync {
    fn write(&self, text: &[u8]);
}

/// Takes the trace of a verbose transfer (`CURLOPT_DEBUGFUNCTION`).
pub trait DebugHandler: Send + Sync {
    fn debug(&self, cx: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]);
}

/// Takes the body (`CURLOPT_WRITEFUNCTION`), in pieces of at most 16384
/// bytes (`CURL_MAX_WRITE_SIZE`).
pub trait WriteHandler: Send + Sync {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write;
}

/// Takes each header line whole, with its line ending
/// (`CURLOPT_HEADERFUNCTION`).
pub trait HeaderHandler: Send + Sync {
    fn header(&self, cx: &mut TransferCx<'_>, line: &[u8], origin: HeaderOrigin) -> Write;
}

/// A handler as a transfer holds it: shared by every copy of the `Easy`.
pub struct Handler<T: ?Sized>(TryArc<Box<T>>);

impl<T: ?Sized> Handler<T> {
    /// A handler already boxed; `Handler::write` and the like box one.
    pub fn new(handler: Box<T>) -> Result<Handler<T>, OutOfMemory> {
        Ok(Handler(TryArc::try_new(handler)?))
    }

    /// Whether `a` and `b` are the same handler.
    pub fn ptr_eq(a: &Handler<T>, b: &Handler<T>) -> bool {
        TryArc::ptr_eq(&a.0, &b.0)
    }
}

impl Handler<dyn WriteHandler> {
    pub fn write(handler: impl WriteHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn HeaderHandler> {
    pub fn header(handler: impl HeaderHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn LentBytes> {
    pub fn lent(bytes: impl LentBytes + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(bytes)?)
    }
}

impl Handler<dyn ReadHandler> {
    pub fn read(handler: impl ReadHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn TrailerHandler> {
    pub fn trailer(handler: impl TrailerHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn Rewind> {
    pub fn rewind(handler: impl Rewind + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn ProgressHandler> {
    pub fn progress(handler: impl ProgressHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn TextSink> {
    pub fn text(handler: impl TextSink + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn DebugHandler> {
    pub fn debug(handler: impl DebugHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn LineSource> {
    pub fn lines(source: impl LineSource + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(source)?)
    }
}

impl<T: ?Sized> Clone for Handler<T> {
    fn clone(&self) -> Handler<T> {
        Handler(self.0.clone())
    }
}

impl<T: ?Sized> Deref for Handler<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> fmt::Debug for Handler<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Handler")
    }
}
