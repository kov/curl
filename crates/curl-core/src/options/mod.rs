//! A transfer's options, in typed groups: what `curl_easy_setopt` sets.
//!
//! Only the options the multi reads exist yet; the rest arrive with the
//! code that reads them.

#[cfg(any(test, feature = "test-util"))]
pub mod script;

use curl_alloc::{OutOfMemory, TryArc, TryVec};

use std::fmt;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::time::Duration;

use crate::handler::{
    DebugHandler, Handler, HeaderHandler, ProgressHandler, ReadHandler, Rewind, TextSink,
    TrailerHandler, WriteHandler,
};
use crate::time::TimeLimit;
use crate::url::SharedUrl;

pub use crate::proto::http1::request::{UserHeaders, Version as HttpVersion};

/// Every option of a transfer. The default sets nothing and allocates
/// nothing.
#[derive(Debug, Default)]
pub struct Options {
    url: Option<Vec<u8>>,
    shared_url: Option<SharedUrl>,
    default_protocol: Option<Vec<u8>>,
    /// How the URL is read.
    pub url_rules: UrlRules,
    /// What the request asks for.
    pub method: Method,
    /// Where in the resource the transfer starts.
    pub resume: Option<Resume>,
    /// What a file an upload creates may be opened for.
    pub new_file_mode: FileMode,
    /// The remote file's time is read, where the protocol has to ask for
    /// it (`CURLOPT_FILETIME`): HTTP's `Last-Modified`.
    pub filetime: bool,
    /// The remote file is transferred only if its time meets this.
    pub time_condition: Option<TimeCondition>,
    pub limits: Limits,
    /// Which of a name's addresses a connection may use
    /// (`CURLOPT_IPRESOLVE`).
    pub ip_version: IpVersion,
    /// The port the first URL is reached on, whatever it says, and any a
    /// relative redirect leads to (`CURLOPT_PORT`).
    pub port: Option<NonZeroU16>,
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
    /// Who the transfer authenticates as.
    pub login: Login,
    pub netrc: Netrc,
    pub proxy: Proxy,
    pub http: Http,
    pub tls: Tls,
    /// What the test protocol `script:` plays.
    #[cfg(any(test, feature = "test-util"))]
    pub script: Option<script::Script>,
}

/// The user, password and token the application gives
/// (`CURLOPT_USERNAME`, `CURLOPT_PASSWORD`, `CURLOPT_USERPWD`,
/// `CURLOPT_XOAUTH2_BEARER`), each as given; none is not the same as
/// empty. They go only to the origin the transfer starts at,
/// unless `Http::unrestricted_auth` says otherwise.
#[derive(Debug, Default)]
pub struct Login {
    pub user: Option<Vec<u8>>,
    pub password: Option<Vec<u8>>,
    /// An OAuth 2.0 token, for Bearer (`CURLOPT_XOAUTH2_BEARER`).
    pub bearer: Option<Vec<u8>>,
}

/// The proxy transfers go through, and which go direct.
#[derive(Debug, Default)]
pub struct Proxy {
    /// The proxy, as a URL whose scheme may name its type
    /// (`CURLOPT_PROXY`): none to look for one in the environment, an
    /// empty one for none at all.
    pub url: Option<Vec<u8>>,
    /// Its type where the URL names none (`CURLOPT_PROXYTYPE`).
    pub kind: ProxyType,
    /// The SOCKS proxy it is reached through, as a URL whose scheme may
    /// name its type, SOCKS4 if none (`CURLOPT_PRE_PROXY`): alone, the
    /// proxy; an empty one for none, which also leaves the environment
    /// unread.
    pub pre_proxy: Option<Vec<u8>>,
    /// Its port where the URL names none (`CURLOPT_PROXYPORT`); none for
    /// its scheme's.
    pub port: Option<NonZeroU16>,
    /// The hosts reached without it, a comma-separated list
    /// (`CURLOPT_NOPROXY`): none to look in the environment.
    pub no_proxy: Option<Vec<u8>>,
    /// Every transfer tunnels through an HTTP proxy, with `CONNECT`
    /// (`CURLOPT_HTTPPROXYTUNNEL`).
    pub tunnel: bool,
    /// The user an HTTP proxy is given where its URL names none
    /// (`CURLOPT_PROXYUSERNAME`).
    pub user: Option<Vec<u8>>,
    /// Its password, likewise (`CURLOPT_PROXYPASSWORD`).
    pub password: Option<Vec<u8>>,
    /// The methods it may be authenticated with (`CURLOPT_PROXYAUTH`).
    pub auth: HttpAuth,
    /// The answer to `CONNECT` is not delivered, though its headers are
    /// kept (`CURLOPT_SUPPRESS_CONNECT_HEADERS`).
    pub suppress_connect_headers: bool,
    /// How a SOCKS5 proxy may authenticate the user
    /// (`CURLOPT_SOCKS5_AUTH`).
    pub socks5_auth: Socks5Auth,
    /// The header lines an HTTP proxy is sent of its own
    /// (`CURLOPT_PROXYHEADER`).
    pub headers: UserHeaders,
    /// The proxy is sent the application's headers for the origin in
    /// their place (`CURLHEADER_UNIFIED` in `CURLOPT_HEADEROPT`).
    pub unified_headers: bool,
    /// A new connection says first where it comes from, in the PROXY
    /// protocol's line (`CURLOPT_HAPROXYPROTOCOL`).
    pub haproxy: bool,
    /// The address it says, as source and destination both, in place of
    /// the connection's (`CURLOPT_HAPROXY_CLIENT_IP`).
    pub haproxy_client_ip: Option<Vec<u8>>,
}

/// The methods a SOCKS5 proxy may authenticate with
/// (`CURLOPT_SOCKS5_AUTH`): a user and password, GSS-API, and whether
/// one of them must be, never none. Both, and none allowed, unless set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Socks5Auth {
    pub basic: bool,
    pub gssapi: bool,
    /// The proxy must authenticate the user (`CURLAUTH_ONLY`).
    pub only: bool,
}

impl Default for Socks5Auth {
    fn default() -> Self {
        Socks5Auth {
            basic: true,
            gssapi: true,
            only: false,
        }
    }
}

/// Why `user:password` for a proxy is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyUserError {
    OutOfMemory,
    /// A part decodes to a zero byte.
    Malformed,
}

impl Proxy {
    fn try_clone(&self) -> Result<Proxy, OutOfMemory> {
        Ok(Proxy {
            url: self.url.as_deref().map(copy).transpose()?,
            kind: self.kind,
            pre_proxy: self.pre_proxy.as_deref().map(copy).transpose()?,
            port: self.port,
            no_proxy: self.no_proxy.as_deref().map(copy).transpose()?,
            tunnel: self.tunnel,
            user: self.user.as_deref().map(copy).transpose()?,
            password: self.password.as_deref().map(copy).transpose()?,
            auth: self.auth,
            suppress_connect_headers: self.suppress_connect_headers,
            socks5_auth: self.socks5_auth,
            headers: self.headers.try_clone()?,
            unified_headers: self.unified_headers,
            haproxy: self.haproxy,
            haproxy_client_ip: self.haproxy_client_ip.as_deref().map(copy).transpose()?,
        })
    }

    /// The header lines an HTTP proxy is sent of its own, which replace
    /// the library's to it (`Curl_checkProxyheaders`): the origin's where
    /// the two are unified.
    pub(crate) fn own_headers<'a>(&'a self, http: &'a Http) -> &'a UserHeaders {
        if self.unified_headers {
            &http.headers
        } else {
            &self.headers
        }
    }

    /// The user and password from `user:password`, split at the first
    /// colon and each URL-decoded (`CURLOPT_PROXYUSERPWD`); none clears
    /// both.
    pub fn set_user_password(&mut self, pair: Option<&[u8]>) -> Result<(), ProxyUserError> {
        let decoded = |part: &[u8]| match crate::url::decode_but_zero(part) {
            Ok(Some(decoded)) => Ok(decoded),
            Ok(None) => Err(ProxyUserError::Malformed),
            Err(_) => Err(ProxyUserError::OutOfMemory),
        };
        let (user, password) = match pair {
            None => (None, None),
            Some(pair) => {
                let login =
                    Login::from_pair(pair).map_err(|OutOfMemory| ProxyUserError::OutOfMemory)?;
                (
                    login.user.as_deref().map(decoded).transpose()?,
                    login.password.as_deref().map(decoded).transpose()?,
                )
            }
        };
        self.user = user;
        self.password = password;
        Ok(())
    }
}

/// What a proxy speaks (`curl_proxytype`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProxyType {
    #[default]
    Http,
    /// HTTP/1.0 for `CONNECT`.
    Http10,
    /// HTTP over TLS.
    Https,
    /// HTTP/2 over TLS.
    Https2,
    /// HTTP/3.
    Https3,
    Socks4,
    /// SOCKS4 with the name resolved by the proxy.
    Socks4a,
    Socks5,
    /// SOCKS5 with the name resolved by the proxy.
    Socks5Hostname,
}

/// Whether a `.netrc` file gives credentials, and which
/// (`CURLOPT_NETRC`, `CURLOPT_NETRC_FILE`).
#[derive(Debug, Default)]
pub struct Netrc {
    pub mode: NetrcMode,
    /// The file; none for `$NETRC`, or `.netrc` in the home directory.
    pub file: Option<Vec<u8>>,
}

/// How a `.netrc` file is used (`CURL_NETRC_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NetrcMode {
    /// Not read.
    #[default]
    Ignored,
    /// Read where the options and the URL leave a user or password out;
    /// a file missing or malformed is passed over.
    Optional,
    /// Read even where the URL has both, its user kept; a file missing
    /// or malformed fails the transfer.
    Required,
}

impl Login {
    /// `user:password`, split at the first colon; with none, a user alone
    /// (`Curl_parse_login_details`).
    pub fn from_pair(pair: &[u8]) -> Result<Login, OutOfMemory> {
        let (user, password) = match pair.iter().position(|&b| b == b':') {
            Some(at) => (&pair[..at], Some(&pair[at + 1..])),
            None => (pair, None),
        };
        Ok(Login {
            user: Some(copy(user)?),
            password: password.map(copy).transpose()?,
            bearer: None,
        })
    }

    fn try_clone(&self) -> Result<Login, OutOfMemory> {
        Ok(Login {
            user: self.user.as_deref().map(copy).transpose()?,
            password: self.password.as_deref().map(copy).transpose()?,
            bearer: self.bearer.as_deref().map(copy).transpose()?,
        })
    }
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

    /// The URL to transfer as the application keeps it, read as each
    /// transfer starts (`CURLOPT_CURLU`): it goes before `url`, which
    /// setting it, even to none, clears.
    pub fn shared_url(&self) -> Option<&SharedUrl> {
        self.shared_url.as_ref()
    }

    pub fn set_shared_url(&mut self, url: Option<SharedUrl>) {
        self.url = None;
        self.shared_url = url;
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
            shared_url: self.shared_url.clone(),
            default_protocol: self.default_protocol.as_deref().map(copy).transpose()?,
            url_rules: self.url_rules,
            method: self.method,
            resume: self.resume,
            new_file_mode: self.new_file_mode,
            filetime: self.filetime,
            time_condition: self.time_condition,
            limits: self.limits,
            ip_version: self.ip_version,
            port: self.port,
            resolve: self.resolve.try_clone()?,
            connect_to: self.connect_to.try_clone()?,
            output: self.output,
            callbacks: self.callbacks.clone(),
            progress: self.progress.clone(),
            upload: self.upload.clone(),
            login: self.login.try_clone()?,
            netrc: Netrc {
                mode: self.netrc.mode,
                file: self.netrc.file.as_deref().map(copy).transpose()?,
            },
            proxy: self.proxy.try_clone()?,
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
    /// To send the body from `Options::upload` for the resource to take
    /// (`CURLOPT_POST`, `CURLOPT_POSTFIELDS`); `file:` reads the file.
    Post,
}

impl Method {
    /// The method as a request line names it.
    pub fn name(self) -> &'static [u8] {
        match self {
            Method::Get => b"GET",
            Method::Head => b"HEAD",
            Method::Post => b"POST",
            Method::Upload => b"PUT",
        }
    }
}

/// A condition on the remote file's time (`CURLOPT_TIMECONDITION`,
/// `CURLOPT_TIMEVALUE_LARGE`). A range asked for sets it aside, as does a
/// file whose time is not known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeCondition {
    pub when: Condition,
    /// Seconds since 1970-01-01 00:00:00 UTC; at 0, any file meets it.
    pub time: i64,
}

/// What a time condition asks of the file, and the HTTP header it sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    /// Modified after the time (`If-Modified-Since`).
    ModifiedSince,
    /// Not modified after it (`If-Unmodified-Since`).
    UnmodifiedSince,
    /// Sent as `Last-Modified`; checked as `ModifiedSince`, as C does.
    LastModified,
}

impl Condition {
    /// The header a request sends it as.
    pub(crate) fn header(self) -> &'static [u8] {
        match self {
            Condition::ModifiedSince => b"If-Modified-Since",
            Condition::UnmodifiedSince => b"If-Unmodified-Since",
            Condition::LastModified => b"Last-Modified",
        }
    }
}

/// Why a file fails a time condition, as C says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unmet {
    NotNewEnough,
    NotOldEnough,
}

impl fmt::Display for Unmet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Unmet::NotNewEnough => "The requested document is not new enough",
            Unmet::NotOldEnough => "The requested document is not old enough",
        })
    }
}

impl TimeCondition {
    /// Whether a file modified at `doc`, 0 for not known, meets it
    /// (`Curl_meets_timecondition`).
    pub(crate) fn met_by(self, doc: i64) -> Result<(), Unmet> {
        if doc == 0 || self.time == 0 {
            return Ok(());
        }
        match self.when {
            Condition::ModifiedSince | Condition::LastModified if doc <= self.time => {
                Err(Unmet::NotNewEnough)
            }
            Condition::UnmodifiedSince if doc >= self.time => Err(Unmet::NotOldEnough),
            _ => Ok(()),
        }
    }
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

    /// `line` after those given before.
    pub fn push(&mut self, line: &[u8]) -> Result<(), OutOfMemory> {
        self.0.try_push(copy(line)?)
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

/// How long a body announced with `Expect: 100-continue` waits for the
/// 100 before it is sent anyway (`CURLOPT_EXPECT_100_TIMEOUT_MS`): a
/// second unless set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContinueWait(pub Duration);

impl Default for ContinueWait {
    fn default() -> Self {
        ContinueWait(Duration::from_secs(1))
    }
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
    /// `CURLOPT_DNS_CACHE_TIMEOUT`: how long a name's answer is kept, 60
    /// seconds unless set; none for ever.
    pub dns_max_age: Option<Duration>,
}

impl Default for ReuseLimits {
    fn default() -> Self {
        ReuseLimits {
            max_idle: TimeLimit::from_millis(118 * 1000),
            max_age: TimeLimit::from_millis(24 * 3600 * 1000),
            max_connects: NonZeroU32::new(5).expect("not zero"),
            forbid: false,
            fresh: false,
            dns_max_age: Some(Duration::from_secs(60)),
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
    /// The content codings asked for, and a response's undone; without,
    /// a coded body is delivered as it came (`CURLOPT_ACCEPT_ENCODING`).
    pub accept_encoding: Option<crate::coding::AcceptEncoding>,
    /// Content codings are passed on as they came, not decoded
    /// (`CURLOPT_HTTP_CONTENT_DECODING` off).
    pub raw_content: bool,
    /// `CURLOPT_REFERER`.
    pub referer: Option<Vec<u8>>,
    /// The request's method as sent, in place of the one `method` implies,
    /// which still decides the body (`CURLOPT_CUSTOMREQUEST`).
    pub custom_method: Option<Vec<u8>>,
    /// A response code of 400 or more fails the transfer at the end of
    /// its head (`CURLOPT_FAILONERROR`).
    pub fail_on_error: bool,
    /// How long a body announced with `Expect: 100-continue` waits for
    /// the 100.
    pub continue_wait: ContinueWait,
    /// An error response before the body is all sent lets it go on
    /// rather than stop (`CURLOPT_KEEP_SENDING_ON_ERROR`).
    pub keep_sending_on_error: bool,
    /// Which redirects are followed (`CURLOPT_FOLLOWLOCATION`).
    pub follow: Follow,
    pub max_redirects: MaxRedirects,
    /// Which redirects keep a POST a POST (`CURLOPT_POSTREDIR`).
    pub post_redirect: PostRedir,
    /// A followed redirect sends the URL it came from as its referer
    /// (`CURLOPT_AUTOREFERER`).
    pub auto_referer: bool,
    /// What the application said for the first origin goes to any a
    /// redirect leads to (`CURLOPT_UNRESTRICTED_AUTH`).
    pub unrestricted_auth: bool,
    pub auth: HttpAuth,
    pub cookies: Cookies,
}

/// Where a transfer's cookies come from and go.
#[derive(Debug, Default)]
pub struct Cookies {
    /// Sent as given, after the jar's, to the first origin only unless
    /// `Http::unrestricted_auth` says otherwise, and not beside the
    /// application's own `Cookie:` header (`CURLOPT_COOKIE`).
    pub send: Option<Vec<u8>>,
    /// Files read into the jar as each transfer starts, in the Netscape
    /// format or as `Set-Cookie:` lines; `-` is standard input
    /// (`CURLOPT_COOKIEFILE`). Any, even an empty name, turns the jar on.
    pub files: Lines,
    /// Where `Easy::save_cookies` writes the jar, `-` for standard
    /// output; set, it turns the jar on (`CURLOPT_COOKIEJAR`).
    pub save_to: Option<Vec<u8>>,
    /// The files' cookies that last the session are passed over
    /// (`CURLOPT_COOKIESESSION`).
    pub new_session: bool,
}

impl Cookies {
    /// Whether the options turn the jar on.
    pub(crate) fn wanted(&self) -> bool {
        self.files.iter().next().is_some() || self.save_to.is_some()
    }

    fn try_clone(&self) -> Result<Cookies, OutOfMemory> {
        Ok(Cookies {
            send: self.send.as_deref().map(copy).transpose()?,
            files: self.files.try_clone()?,
            save_to: self.save_to.as_deref().map(copy).transpose()?,
            new_session: self.new_session,
        })
    }
}

/// The methods a request may authenticate with (`CURLOPT_HTTPAUTH`): one
/// is used at once, more are chosen from as a server asks. Basic unless
/// set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpAuth(pub AuthMethods);

impl Default for HttpAuth {
    fn default() -> Self {
        HttpAuth(AuthMethods::BASIC)
    }
}

/// HTTP authentication methods, as a set (`CURLAUTH_*`); empty unless
/// set.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthMethods(u8);

impl AuthMethods {
    pub const NONE: AuthMethods = AuthMethods(0);
    pub const BASIC: AuthMethods = AuthMethods(1);
    pub const DIGEST: AuthMethods = AuthMethods(2);
    pub const BEARER: AuthMethods = AuthMethods(4);
    /// Methods this library does not implement, asked for all the same:
    /// never used, but with one of the others, that one is used only once
    /// a server asks for it, as with `ONLY`.
    pub const OTHER: AuthMethods = AuthMethods(0x40);
    /// Not a method: with one, that one is used only once a server asks
    /// for it (`CURLAUTH_ONLY`).
    pub const ONLY: AuthMethods = AuthMethods(0x80);
    /// Every method there is, chosen from as a server asks
    /// (`CURLAUTH_ANY`).
    pub const ANY: AuthMethods = AuthMethods(1 | 2 | 4 | 0x40 | 0x80);

    pub fn contains(self, other: AuthMethods) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The one method this is, if it is exactly one this library
    /// implements; with `ONLY` or `OTHER`, none.
    pub(crate) fn single(self) -> Option<AuthMethods> {
        let known = Self::BASIC.0 | Self::DIGEST.0 | Self::BEARER.0;
        (self.0.count_ones() == 1 && self.0 & !known == 0).then_some(self)
    }

    /// The method's name, as an `Authorization` line starts.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::BASIC => "Basic",
            Self::DIGEST => "Digest",
            Self::BEARER => "Bearer",
            _ => unreachable!("one method: {self:?}"),
        }
    }
}

impl std::ops::BitOr for AuthMethods {
    type Output = AuthMethods;
    fn bitor(self, other: AuthMethods) -> AuthMethods {
        AuthMethods(self.0 | other.0)
    }
}

impl std::ops::BitAnd for AuthMethods {
    type Output = AuthMethods;
    fn bitand(self, other: AuthMethods) -> AuthMethods {
        AuthMethods(self.0 & other.0)
    }
}

impl std::ops::Not for AuthMethods {
    type Output = AuthMethods;
    fn not(self) -> AuthMethods {
        AuthMethods(!self.0 & Self::ANY.0)
    }
}

impl fmt::Debug for AuthMethods {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [
            (Self::BASIC, "BASIC"),
            (Self::DIGEST, "DIGEST"),
            (Self::BEARER, "BEARER"),
            (Self::OTHER, "OTHER"),
            (Self::ONLY, "ONLY"),
        ];
        let mut set = f.debug_set();
        for (bit, name) in names {
            if self.contains(bit) {
                set.entry(&format_args!("{name}"));
            }
        }
        set.finish()
    }
}

/// Which redirects keep a POST a POST (`CURLOPT_POSTREDIR`): unless set,
/// a 301, 302 or 303 turns it into a GET.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PostRedir {
    pub post301: bool,
    pub post302: bool,
    pub post303: bool,
}

/// How many redirects a transfer follows (`CURLOPT_MAXREDIRS`): 30 unless
/// set; `None` for no limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxRedirects(pub Option<u16>);

impl Default for MaxRedirects {
    fn default() -> Self {
        MaxRedirects(Some(30))
    }
}

/// Which redirects a transfer follows, and how its method changes along
/// them (`CURLFOLLOW_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Follow {
    /// None: where a redirect leads is only reported.
    #[default]
    No,
    /// Every redirect.
    All,
    /// Every redirect, the method changing as its code says, a custom
    /// one included.
    ObeyCode,
    /// Every redirect, a custom method sent only to the first URL.
    FirstOnly,
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
            accept_encoding: match &self.accept_encoding {
                None => None,
                Some(crate::coding::AcceptEncoding::All) => {
                    Some(crate::coding::AcceptEncoding::All)
                }
                Some(crate::coding::AcceptEncoding::Given(v)) => {
                    Some(crate::coding::AcceptEncoding::Given(copy(v)?))
                }
            },
            raw_content: self.raw_content,
            referer: self.referer.as_deref().map(copy).transpose()?,
            custom_method: self.custom_method.as_deref().map(copy).transpose()?,
            fail_on_error: self.fail_on_error,
            continue_wait: self.continue_wait,
            keep_sending_on_error: self.keep_sending_on_error,
            follow: self.follow,
            max_redirects: self.max_redirects,
            post_redirect: self.post_redirect,
            auto_referer: self.auto_referer,
            unrestricted_auth: self.unrestricted_auth,
            auth: self.auth,
            cookies: self.cookies.try_clone()?,
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
    /// The trailers a chunked request body ends with; without one, none.
    pub trailer: Option<Handler<dyn TrailerHandler>>,
}

/// Where the body a transfer sends comes from.
#[derive(Clone, Debug, Default)]
pub enum UploadSource {
    /// Nothing: an empty body.
    #[default]
    None,
    /// These bytes, shared by every copy of the options
    /// (`CURLOPT_COPYPOSTFIELDS`).
    Bytes(TryArc<Vec<u8>>),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A copy keeps the lists of addresses and peers given for names.
    #[test]
    fn a_copy_keeps_the_lists_for_names() {
        let mut o = Options::default();
        o.resolve.set([&b"a:1:127.0.0.1"[..]]).unwrap();
        o.connect_to.set([&b"::b:2"[..]]).unwrap();
        let copy = o.try_clone().unwrap();
        assert!(copy.resolve.entries().eq([&b"a:1:127.0.0.1"[..]]));
        assert_eq!(copy.resolve.stamp(), o.resolve.stamp());
        assert!(copy.connect_to.iter().eq([&b"::b:2"[..]]));
    }

    /// A copy keeps the proxy, the login and the cookies' options.
    #[test]
    fn a_copy_keeps_the_proxy_login_and_cookies() {
        let mut o = Options::default();
        o.proxy.url = Some(b"http://proxy.example:3128".to_vec());
        o.proxy.user = Some(b"pu".to_vec());
        o.login.user = Some(b"lu".to_vec());
        o.login.bearer = Some(b"t".to_vec());
        o.http.cookies.send = Some(b"a=1".to_vec());
        o.http.cookies.new_session = true;
        let copy = o.try_clone().unwrap();
        assert_eq!(
            copy.proxy.url.as_deref(),
            Some(&b"http://proxy.example:3128"[..])
        );
        assert_eq!(copy.proxy.user.as_deref(), Some(&b"pu"[..]));
        assert_eq!(copy.login.user.as_deref(), Some(&b"lu"[..]));
        assert_eq!(copy.login.bearer.as_deref(), Some(&b"t"[..]));
        assert_eq!(copy.http.cookies.send.as_deref(), Some(&b"a=1"[..]));
        assert!(copy.http.cookies.new_session);
    }

    /// `CURLOPT_PROXYUSERPWD`: split at the first colon, each part
    /// URL-decoded, one that decodes to a zero byte refused; none clears
    /// both.
    #[test]
    fn a_proxy_s_user_and_password_are_split_and_decoded() {
        let mut p = Proxy::default();
        p.set_user_password(Some(b"us%3Aer:pa:ss")).unwrap();
        assert_eq!(
            (p.user.as_deref(), p.password.as_deref()),
            (Some(&b"us:er"[..]), Some(&b"pa:ss"[..]))
        );
        assert_eq!(
            p.set_user_password(Some(b"u:p%00")),
            Err(ProxyUserError::Malformed)
        );
        p.set_user_password(None).unwrap();
        assert_eq!((p.user, p.password), (None, None));
    }

    /// Methods combine as sets; a set of one method is that method, of
    /// more, or with `ONLY` or `OTHER`, none.
    #[test]
    fn auth_methods_are_sets() {
        use AuthMethods as A;
        assert_eq!(A::BASIC | A::BASIC, A::BASIC);
        assert_eq!(A::ANY | A::DIGEST, A::ANY);
        assert_eq!(A::BASIC.single(), Some(A::BASIC));
        assert_eq!((A::BASIC | A::DIGEST).single(), None);
        assert_eq!(A::ONLY.single(), None);
        assert_eq!((A::DIGEST | A::ONLY).single(), None);
        assert_eq!(A::OTHER.single(), None, "never used");
        assert_eq!((A::BASIC | A::OTHER).single(), None);
        assert!(A::ANY.contains(A::OTHER));
        assert_eq!(format!("{:?}", A::BASIC | A::OTHER), "{BASIC, OTHER}");
        assert_eq!(format!("{:?}", A::DIGEST | A::ONLY), "{DIGEST, ONLY}");
        assert_eq!(format!("{:?}", A::NONE), "{}");
    }
}
