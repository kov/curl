//! A transfer's options, in typed groups: what `curl_easy_setopt` sets.
//!
//! Only the options the multi reads exist yet; the rest arrive with the
//! code that reads them.

#[cfg(any(test, feature = "test-util"))]
pub mod script;

use curl_alloc::{OutOfMemory, TryRc, TryVec};

use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::time::Duration;

use crate::handler::{
    DebugHandler, Handler, HeaderHandler, ProgressHandler, ReadHandler, Rewind, TextSink,
    WriteHandler,
};
use crate::time::TimeLimit;

pub use crate::proto::http1::request::{UserHeaders, Version as HttpVersion};

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
    /// Which of a name's addresses a connection may use
    /// (`CURLOPT_IPRESOLVE`).
    pub ip_version: IpVersion,
    /// Addresses given for names ahead of resolving them
    /// (`CURLOPT_RESOLVE`).
    pub resolve: ResolveList,
    /// Peers to connect to in place of the URL's
    /// (`CURLOPT_CONNECT_TO`): `HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT`,
    /// the first that matches the URL's host and port taken, an empty
    /// field matching any and keeping the URL's.
    pub connect_to: Lines,
    pub output: Output,
    pub callbacks: Callbacks,
    pub progress: Progress,
    /// What a transfer sends, if its request has a body.
    pub upload: UploadSource,
    pub http: Http,
    pub tls: Tls,
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
            ip_version: self.ip_version,
            resolve: self.resolve.try_clone()?,
            connect_to: self.connect_to.try_clone()?,
            output: self.output,
            callbacks: self.callbacks.clone(),
            progress: self.progress.clone(),
            upload: self.upload.clone(),
            http: self.http.try_clone()?,
            tls: self.tls,
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

/// Entries giving names their addresses (`CURLOPT_RESOLVE`), each as the
/// application gave it, read into the multi's cache when the next
/// transfer starts: `HOST:PORT:ADDRESS[,ADDRESS]...`, kept for good, or
/// for the cache's timeout with a `+` before; `-HOST:PORT` to forget.
#[derive(Debug, Default)]
pub struct ResolveList {
    entries: Lines,
    /// Which setting of the list this is: a transfer reads each once.
    stamp: u64,
}

impl ResolveList {
    pub fn entries(&self) -> impl Iterator<Item = &[u8]> {
        self.entries.iter()
    }

    /// The list as the application sets it again, replacing what it was:
    /// read again by the next transfer, even if it is the same.
    pub fn set<'a>(
        &mut self,
        entries: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<(), OutOfMemory> {
        self.entries.set(entries)?;
        self.stamp += 1;
        Ok(())
    }

    pub(crate) fn stamp(&self) -> u64 {
        self.stamp
    }

    fn try_clone(&self) -> Result<ResolveList, OutOfMemory> {
        Ok(ResolveList {
            entries: self.entries.try_clone()?,
            stamp: self.stamp,
        })
    }
}

/// A list of lines, each as the application gave it.
#[derive(Debug, Default)]
pub struct Lines(Vec<Vec<u8>>);

impl Lines {
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.0.iter().map(|e| &e[..])
    }

    /// The lines given, in place of those before.
    pub fn set<'a>(
        &mut self,
        lines: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<(), OutOfMemory> {
        let mut owned = Vec::new();
        for line in lines {
            owned.try_push(copy(line)?)?;
        }
        self.0 = owned;
        Ok(())
    }

    fn try_clone(&self) -> Result<Lines, OutOfMemory> {
        let mut owned = Vec::new();
        for line in self.iter() {
            owned.try_push(copy(line)?)?;
        }
        Ok(Lines(owned))
    }
}

/// Which addresses of a name a connection may use; an address the URL
/// names is used whatever this says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IpVersion {
    #[default]
    Any,
    V4,
    V6,
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
    pub eyeballs: EyeballsDelay,
}

/// How long a connect attempt runs before the next starts beside it
/// (`CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`): 200 milliseconds unless set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EyeballsDelay(pub Duration);

impl Default for EyeballsDelay {
    fn default() -> Self {
        EyeballsDelay(Duration::from_millis(200))
    }
}

/// How long a connection may have been idle, and have lived, for a
/// transfer to reuse it, none for no limit as C's 0; and how many an
/// easy handle's own pool keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReuseLimits {
    /// `CURLOPT_MAXAGE_CONN`: 118 seconds unless set.
    pub max_idle: Option<TimeLimit>,
    /// `CURLOPT_MAXLIFETIME_CONN`: a day unless set.
    pub max_age: Option<TimeLimit>,
    /// `CURLOPT_MAXCONNECTS`: 5 unless set. A multi's own limit is the
    /// multi's.
    pub max_connects: NonZeroU32,
    /// `CURLOPT_FORBID_REUSE`: the connection is closed once the
    /// transfer is done with it.
    pub forbid: bool,
    /// `CURLOPT_FRESH_CONNECT`: a new connection, not an idle one.
    pub fresh: bool,
}

impl Default for ReuseLimits {
    fn default() -> Self {
        ReuseLimits {
            max_idle: TimeLimit::from_millis(118 * 1000),
            max_age: TimeLimit::from_millis(24 * 3600 * 1000),
            max_connects: NonZeroU32::new(5).expect("not zero"),
            forbid: false,
            fresh: false,
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

/// What an HTTP request says, and how its response is read.
#[derive(Debug, Default)]
pub struct Http {
    /// `CURLOPT_USERAGENT`.
    pub user_agent: Option<Vec<u8>>,
    /// The application's header lines (`CURLOPT_HTTPHEADER`).
    pub headers: UserHeaders,
    pub version: HttpVersion,
    /// A response that is no HTTP is read as HTTP/0.9
    /// (`CURLOPT_HTTP09_ALLOWED`).
    pub allow_09: bool,
    /// `Content-Length` is not read (`CURLOPT_IGNORE_CONTENT_LENGTH`).
    pub ignore_content_length: bool,
    /// Transfer codings are passed on as they came, not decoded
    /// (`CURLOPT_HTTP_TRANSFER_DECODING` off).
    pub raw: bool,
    /// Codings other than chunked are asked for and decoded
    /// (`CURLOPT_TRANSFER_ENCODING`).
    pub transfer_encoding: bool,
    /// `CURLOPT_REFERER`.
    pub referer: Option<Vec<u8>>,
    /// A response code of 400 or more fails the transfer at the end of
    /// its head (`CURLOPT_FAILONERROR`).
    pub fail_on_error: bool,
}

impl Http {
    fn try_clone(&self) -> Result<Http, OutOfMemory> {
        Ok(Http {
            user_agent: self.user_agent.as_deref().map(copy).transpose()?,
            headers: self.headers.try_clone()?,
            version: self.version,
            allow_09: self.allow_09,
            ignore_content_length: self.ignore_content_length,
            raw: self.raw,
            transfer_encoding: self.transfer_encoding,
            referer: self.referer.as_deref().map(copy).transpose()?,
            fail_on_error: self.fail_on_error,
        })
    }
}

/// How a TLS peer is checked. No TLS layer reads these yet; they are kept
/// as an application sets them, for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tls {
    /// The peer's certificate must verify (`CURLOPT_SSL_VERIFYPEER`).
    pub verify_peer: bool,
    /// The certificate must name the host (`CURLOPT_SSL_VERIFYHOST`).
    pub verify_host: bool,
}

impl Default for Tls {
    fn default() -> Self {
        Tls {
            verify_peer: true,
            verify_host: true,
        }
    }
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
