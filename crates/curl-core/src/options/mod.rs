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
    default_protocol: Option<Vec<u8>>,
    /// How the URL is read.
    pub url_rules: UrlRules,
    /// What the request asks for.
    pub method: Method,
    /// Where in the resource the transfer starts.
    pub resume: Option<Resume>,
    /// What a file an upload creates may be opened for.
    pub new_file_mode: FileMode,
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

    /// The scheme a URL without one is given (`CURLOPT_DEFAULT_PROTOCOL`),
    /// as given: an unknown one fails the transfer when it starts.
    pub fn default_protocol(&self) -> Option<&[u8]> {
        self.default_protocol.as_deref()
    }

    pub fn set_default_protocol(&mut self, scheme: Option<&[u8]>) -> Result<(), OutOfMemory> {
        self.default_protocol = scheme.map(copy).transpose()?;
        Ok(())
    }

    /// A copy (`curl_easy_duphandle`).
    pub fn try_clone(&self) -> Result<Options, OutOfMemory> {
        Ok(Options {
            url: self.url.as_deref().map(copy).transpose()?,
            default_protocol: self.default_protocol.as_deref().map(copy).transpose()?,
            url_rules: self.url_rules,
            method: self.method,
            resume: self.resume,
            new_file_mode: self.new_file_mode,
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

/// What a URL may hold, beyond what parsing it always allows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UrlRules {
    /// A user name or password in it is an error
    /// (`CURLOPT_DISALLOW_USERNAME_IN_URL`).
    pub disallow_user: bool,
    /// `.` and `..` in its path are kept, not resolved
    /// (`CURLOPT_PATH_AS_IS`).
    pub path_as_is: bool,
}

/// What a request asks for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Method {
    /// The resource.
    #[default]
    Get,
    /// What is known of the resource, without its body
    /// (`CURLOPT_NOBODY`).
    Head,
    /// To store the body the transfer sends, from `Options::upload`
    /// (`CURLOPT_UPLOAD`).
    Upload,
}

/// Where in the resource a transfer starts (`CURLOPT_RESUME_FROM_LARGE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// This many bytes in: a download skips them; an upload skips them of
    /// its body and appends the rest to what is stored.
    At(NonZeroU64),
    /// At the end (C's -1): a download gets the last byte; an upload skips
    /// as much of its body as is stored already and appends the rest.
    AtEnd,
}

/// The permission bits of a file a transfer creates, before the umask
/// (`CURLOPT_NEW_FILE_PERMS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMode(u16);

impl FileMode {
    /// `bits`, if they are permission bits alone.
    pub fn new(bits: u16) -> Option<FileMode> {
        (bits <= 0o777).then_some(FileMode(bits))
    }

    pub fn bits(self) -> u16 {
        self.0
    }
}

impl Default for FileMode {
    /// Read and write for the owner, read for the rest.
    fn default() -> FileMode {
        FileMode(0o644)
    }
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
    /// Which idle connections the transfer may reuse.
    pub reuse: ReuseLimits,
}

/// How long a connection may have been idle, and have lived, for a
/// transfer to reuse it; none for no limit, as C's 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReuseLimits {
    /// `CURLOPT_MAXAGE_CONN`: 118 seconds unless set.
    pub max_idle: Option<TimeLimit>,
    /// `CURLOPT_MAXLIFETIME_CONN`: a day unless set.
    pub max_age: Option<TimeLimit>,
}

impl Default for ReuseLimits {
    fn default() -> Self {
        ReuseLimits {
            max_idle: TimeLimit::from_millis(118 * 1000),
            max_age: TimeLimit::from_millis(24 * 3600 * 1000),
        }
    }
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
    /// Told a transfer's first reason for failing as it is given, as C
    /// copies it into `CURLOPT_ERRORBUFFER`; the report keeps it too.
    pub failure: Option<Handler<dyn TextSink>>,
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
