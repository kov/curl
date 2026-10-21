//! A transfer's options, in typed groups: what `curl_easy_setopt` sets.
//!
//! Only the options the multi reads exist yet; the rest arrive with the
//! code that reads them.

#[cfg(any(test, feature = "test-util"))]
pub mod script;

use curl_alloc::{OutOfMemory, TryRc, TryVec};

use std::num::{NonZeroU16, NonZeroU64};

use crate::handler::{
    DebugHandler, Handler, HeaderHandler, ProgressHandler, ReadHandler, Rewind, TextSink,
    WriteHandler,
};
use crate::time::TimeLimit;

/// Every option of a transfer. The default sets nothing and allocates
/// nothing.
#[derive(Debug, Default)]
pub struct Options {
    url: Option<Vec<u8>>,
    pub limits: Limits,
    pub output: Output,
    pub callbacks: Callbacks,
    pub progress: Progress,
    /// What a transfer sends, if its request has a body.
    pub upload: UploadSource,
    /// What the test protocol `script:` plays.
    #[cfg(any(test, feature = "test-util"))]
    pub script: Option<script::Script>,
}

impl Options {
    /// The URL to transfer (`CURLOPT_URL`), as given: it is parsed when
    /// the transfer starts.
    pub fn url(&self) -> Option<&[u8]> {
        self.url.as_deref()
    }

    pub fn set_url(&mut self, url: Option<&[u8]>) -> Result<(), OutOfMemory> {
        self.url = url.map(copy).transpose()?;
        Ok(())
    }

    /// A copy (`curl_easy_duphandle`).
    pub fn try_clone(&self) -> Result<Options, OutOfMemory> {
        Ok(Options {
            url: self.url.as_deref().map(copy).transpose()?,
            limits: self.limits,
            output: self.output,
            callbacks: self.callbacks.clone(),
            progress: self.progress.clone(),
            upload: self.upload.clone(),
            #[cfg(any(test, feature = "test-util"))]
            script: self.script.clone(),
        })
    }
}

fn copy(s: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(s)?;
    Ok(v)
}

/// How long a transfer may take.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// The whole transfer (`CURLOPT_TIMEOUT_MS`).
    pub total: Option<TimeLimit>,
    /// Each connection (`CURLOPT_CONNECTTIMEOUT_MS`); five minutes if none.
    pub connect: Option<TimeLimit>,
    /// The most body bytes a transfer may deliver
    /// (`CURLOPT_MAXFILESIZE_LARGE`).
    pub max_filesize: Option<NonZeroU64>,
    /// Fail a transfer slower than this for this long
    /// (`CURLOPT_LOW_SPEED_LIMIT`, `CURLOPT_LOW_SPEED_TIME`).
    pub low_speed: Option<LowSpeed>,
}

/// A speed a transfer must keep up, at least once in every `time`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowSpeed {
    /// Bytes a second, up and down together.
    pub limit: NonZeroU64,
    /// Seconds.
    pub time: NonZeroU16,
}

/// What a transfer tells the application besides the body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Output {
    /// Header lines go to the write handler too, before the header
    /// handler (`CURLOPT_HEADER`).
    pub include_header: bool,
    /// Trace the transfer (`CURLOPT_VERBOSE`).
    pub verbose: bool,
}

/// Where a transfer's output goes. A copy of the options shares each
/// handler, as C's copies share a callback and its userdata.
#[derive(Clone, Debug, Default)]
pub struct Callbacks {
    /// The body; without one, it is dropped.
    pub write: Option<Handler<dyn WriteHandler>>,
    /// Header lines; without one, they go nowhere.
    pub header: Option<Handler<dyn HeaderHandler>>,
    /// The trace of a verbose transfer.
    pub debug: Option<Handler<dyn DebugHandler>>,
    /// Text for the user; without one, the process's standard error.
    pub stderr: Option<Handler<dyn TextSink>>,
}

/// Where the body a transfer sends comes from.
#[derive(Clone, Debug, Default)]
pub enum UploadSource {
    /// Nothing: an empty body.
    #[default]
    None,
    /// These bytes, shared by every copy of the options
    /// (`CURLOPT_COPYPOSTFIELDS`).
    Bytes(TryRc<Vec<u8>>),
    /// What a handler reads, `size` bytes if known (`CURLOPT_READFUNCTION`,
    /// `CURLOPT_INFILESIZE_LARGE`). Without a rewind, a request that must be
    /// sent again after reading fails with SendFailRewind.
    Read {
        handler: Handler<dyn ReadHandler>,
        rewind: Option<Handler<dyn Rewind>>,
        size: Option<u64>,
    },
}

/// How a transfer shows its progress.
#[derive(Clone, Debug, Default)]
pub enum Progress {
    /// Not at all (`CURLOPT_NOPROGRESS`, on by default).
    #[default]
    Off,
    /// The meter, drawn on the standard error sink.
    Meter,
    /// A handler, which may ask for the meter too.
    Handler(Handler<dyn ProgressHandler>),
}
