//! What a transfer reports about itself (`curl_easy_getinfo`): written by
//! the engine as the transfer runs, readable from inside its callbacks,
//! and kept in the `Easy` after it ends, until the next transfer starts.

mod certinfo;
mod headers;

use std::net::SocketAddr;
use std::time::Duration;

pub use certinfo::{CertInfo, MAX_CERTS};
pub use headers::{HeaderCursor, HeaderError, HeaderStore, HeaderView, Origins, Request};

use curl_alloc::TryVec;

use crate::time::Instant;
use curl_alloc::OutOfMemory;

use crate::conn::{ConnNumber, ProxyError};
use crate::error::UrlErrorKind;
use crate::options::{AuthMethods, Method};
use crate::url::Url;
use crate::version::Protocol;

/// The ends of a connection: the peer's address, and the local one if
/// it was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ends {
    pub remote: SocketAddr,
    pub local: Option<SocketAddr>,
}

/// An operating system error number (`errno`), never 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OsErrno(std::num::NonZeroI32);

impl OsErrno {
    /// The error numbered `n`; None for 0, which is no error.
    pub fn new(n: i32) -> Option<OsErrno> {
        std::num::NonZeroI32::new(n).map(OsErrno)
    }

    /// The number, as the system gives it.
    pub fn get(self) -> i32 {
        self.0.get()
    }

    /// What kind of error the number is.
    pub fn kind(self) -> std::io::ErrorKind {
        std::io::Error::from_raw_os_error(self.get()).kind()
    }
}

/// The HTTP version a status line says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseVersion {
    Http10,
    Http11,
    Http2,
    Http3,
}

impl ResponseVersion {
    pub(crate) fn major(self) -> u8 {
        match self {
            ResponseVersion::Http10 | ResponseVersion::Http11 => 1,
            ResponseVersion::Http2 => 2,
            ResponseVersion::Http3 => 3,
        }
    }
}

/// One transfer's report. The default is that of a transfer never run.
#[derive(Debug, Default)]
pub struct TransferReport {
    timings: Timings,
    sizes: Sizes,
    speeds: Speeds,
    headers: HeaderStore,
    filetime: Option<i64>,
    /// A time condition ruled the file out (`info.timecond`).
    condition_unmet: bool,
    protocol: Option<Protocol>,
    /// The last status line's code and version (`info.httpcode`,
    /// `info.httpversion`).
    response: Option<(u16, ResponseVersion)>,
    /// How long the last response to say asked to wait before trying
    /// again, at most six hours (`info.retry_after`).
    retry_after: Option<Duration>,
    /// The URL the transfer used, without its credentials, as text.
    url: Option<Vec<u8>>,
    used_proxy: bool,
    /// Where the last response's `Location:` points, resolved, when it
    /// was not followed (`info.wouldredirect`).
    redirect_url: Option<Vec<u8>>,
    /// The last `Content-Type:` a response gave, not empty
    /// (`info.contenttype`).
    content_type: Option<Vec<u8>>,
    /// The ends of the connection last used (`info.primary`).
    primary: Option<Ends>,
    /// The connection the transfer last used, unless the pool closed it
    /// as it came back (`state.last_conn_id`).
    conn: Option<ConnNumber>,
    /// The number the pool of the multi the handle was last added to
    /// gave it (`data->id`): kept as transfers start over.
    transfer: Option<u64>,
    /// How many connections the transfer made (`info.numconnects`).
    connects: u32,
    /// How many redirects the transfer followed (`state.followlocation`).
    redirects: u32,
    /// The method of the last request, a redirect having perhaps changed
    /// it (`state.httpreq`).
    method: Method,
    /// The referer the last request sent: the application's, or the URL
    /// a followed redirect came from (`state.referer`).
    referer: Option<Vec<u8>>,
    /// Why the transfer failed, as it first said (`CURLOPT_ERRORBUFFER`);
    /// none when keeping it ran out of memory.
    failure: Option<Vec<u8>>,
    /// How many reasons were given, the first among them.
    reasons: u32,
    /// The methods the server's challenges offered
    /// (`info.httpauthavail`).
    auth_offered: AuthMethods,
    /// The method the last request authenticated with, or was chosen
    /// for the next (`info.httpauthpicked`).
    auth_used: AuthMethods,
    /// The methods the proxy's challenges offered (`info.proxyauthavail`).
    proxy_auth_offered: AuthMethods,
    /// The status a proxy answered `CONNECT` with (`info.httpproxycode`).
    connect_code: Option<u16>,
    /// What a SOCKS proxy's handshake failed at (`info.pxcode`).
    proxy_error: Option<ProxyError>,
    /// The method the last request authenticated with to the proxy, or
    /// was chosen for the next (`info.proxyauthpicked`).
    proxy_auth_used: AuthMethods,
    /// The error number of the last socket call that failed: a connect,
    /// a send or a receive (`state.os_errno`).
    os_errno: Option<OsErrno>,
    /// The peer's chain, for a transfer that asked for it
    /// (`info.certs`).
    certinfo: Option<Box<CertInfo>>,
    /// What the TLS library made of the origin's certificate, its own
    /// code, 0 being verified: the handle's, kept as transfers start over
    /// (C's `set.ssl.certverifyresult`).
    verify_result: i64,
}

impl TransferReport {
    /// Start over for a transfer starting at `now` (`Curl_pgrsStart`,
    /// `Curl_headers_cleanup`).
    pub(crate) fn restart(&mut self, now: Instant) {
        *self = self.cleared();
        self.timings.start = Some(now);
    }

    /// An empty report, whose header cursors are not this one's.
    pub(crate) fn cleared(&self) -> TransferReport {
        TransferReport {
            headers: HeaderStore::after(&self.headers),
            verify_result: self.verify_result,
            transfer: self.transfer,
            ..TransferReport::default()
        }
    }

    /// What a reset of the handle leaves (`curl_easy_reset`): cleared,
    /// but for the last socket failure's number, which C keeps in the
    /// handle's state rather than its info (`Curl_initinfo` leaves
    /// `state.os_errno`).
    pub(crate) fn reset(&self) -> TransferReport {
        TransferReport {
            os_errno: self.os_errno,
            verify_result: 0,
            ..self.cleared()
        }
    }

    /// Every request's response headers.
    pub fn headers(&self) -> &HeaderStore {
        &self.headers
    }

    pub(crate) fn headers_mut(&mut self) -> &mut HeaderStore {
        &mut self.headers
    }

    pub fn timings(&self) -> &Timings {
        &self.timings
    }

    pub fn sizes(&self) -> &Sizes {
        &self.sizes
    }

    pub fn speeds(&self) -> &Speeds {
        &self.speeds
    }

    /// When the resource was last modified, in seconds since the epoch,
    /// where the protocol says (`CURLINFO_FILETIME_T`).
    pub fn filetime(&self) -> Option<i64> {
        self.filetime
    }

    pub(crate) fn set_filetime(&mut self, t: i64) {
        self.filetime = Some(t);
    }

    /// The time condition was not met, so the file was not transferred,
    /// or the last response was a 304, whatever asked for it
    /// (`CURLINFO_CONDITION_UNMET`).
    pub fn condition_unmet(&self) -> bool {
        self.condition_unmet || self.response_code() == Some(304)
    }

    pub(crate) fn set_condition_unmet(&mut self) {
        self.condition_unmet = true;
    }

    /// The protocol the transfer used, once it is known
    /// (`CURLINFO_SCHEME`).
    pub fn protocol(&self) -> Option<Protocol> {
        self.protocol
    }

    pub(crate) fn set_protocol(&mut self, protocol: Option<Protocol>) {
        self.protocol = protocol;
    }

    /// The code of the last response, interim ones included
    /// (`CURLINFO_RESPONSE_CODE`).
    pub fn response_code(&self) -> Option<u16> {
        self.response.map(|(code, _)| code)
    }

    /// The HTTP version of the last response (`CURLINFO_HTTP_VERSION`).
    pub fn response_version(&self) -> Option<ResponseVersion> {
        self.response.map(|(_, version)| version)
    }

    pub(crate) fn set_response(&mut self, code: u16, version: ResponseVersion) {
        self.response = Some((code, version));
    }

    /// The media type of the last response that gave one
    /// (`CURLINFO_CONTENT_TYPE`).
    pub fn content_type(&self) -> Option<&[u8]> {
        self.content_type.as_deref()
    }

    pub(crate) fn set_content_type(&mut self, value: &[u8]) -> Result<(), OutOfMemory> {
        let mut owned = Vec::new();
        owned.try_extend_from_slice(value)?;
        self.content_type = Some(owned);
        Ok(())
    }

    /// The ends of the connection the transfer last used
    /// (`CURLINFO_PRIMARY_IP`, `CURLINFO_LOCAL_IP` and their ports).
    pub fn primary(&self) -> Option<Ends> {
        self.primary
    }

    pub(crate) fn set_primary(&mut self, ends: Ends) {
        self.primary = Some(ends);
    }

    /// The number of the connection the transfer last used, the `N` of
    /// its "Connection #N", unless the pool closed it as it came back
    /// (`CURLINFO_CONN_ID`).
    /// What the TLS library made of the origin's certificate when last
    /// asked, 0 for verified or never asked (`CURLINFO_SSL_VERIFYRESULT`).
    pub fn verify_result(&self) -> i64 {
        self.verify_result
    }

    pub(crate) fn set_verify_result(&mut self, result: i64) {
        self.verify_result = result;
    }

    pub fn certinfo(&self) -> Option<&CertInfo> {
        self.certinfo.as_deref()
    }

    pub(crate) fn set_certinfo(&mut self, info: Option<Box<CertInfo>>) {
        self.certinfo = info;
    }

    pub fn conn_number(&self) -> Option<u64> {
        self.conn.map(ConnNumber::get)
    }

    pub(crate) fn set_conn(&mut self, conn: Option<ConnNumber>) {
        self.conn = conn;
    }

    /// The number the pool of the multi the handle was last added to
    /// gave it, counting from 0 (`CURLINFO_XFER_ID`).
    pub fn transfer_number(&self) -> Option<u64> {
        self.transfer
    }

    pub(crate) fn set_transfer(&mut self, number: u64) {
        self.transfer = Some(number);
    }

    /// How many new connections the transfer made
    /// (`CURLINFO_NUM_CONNECTS`).
    pub fn connects(&self) -> u32 {
        self.connects
    }

    pub(crate) fn count_connect(&mut self) {
        self.connects = self.connects.saturating_add(1);
    }

    /// How many redirects the transfer followed (`CURLINFO_REDIRECT_COUNT`).
    pub fn redirects(&self) -> u32 {
        self.redirects
    }

    /// The methods the server's challenges offered
    /// (`CURLINFO_HTTPAUTH_AVAIL`).
    pub fn auth_offered(&self) -> AuthMethods {
        self.auth_offered
    }

    pub(crate) fn add_auth_offered(&mut self, methods: AuthMethods) {
        self.auth_offered = self.auth_offered | methods;
    }

    /// The method the last request authenticated with, or that was chosen
    /// for the next one (`CURLINFO_HTTPAUTH_USED`).
    pub fn auth_used(&self) -> AuthMethods {
        self.auth_used
    }

    pub(crate) fn set_auth_used(&mut self, method: AuthMethods) {
        self.auth_used = method;
    }

    /// The status a proxy last answered `CONNECT` with
    /// (`CURLINFO_HTTP_CONNECTCODE`).
    pub fn connect_code(&self) -> Option<u16> {
        self.connect_code
    }

    pub(crate) fn set_connect_code(&mut self, code: u16) {
        self.connect_code = Some(code);
    }

    /// What a SOCKS proxy's handshake failed at
    /// (`CURLINFO_PROXY_ERROR`).
    pub fn proxy_error(&self) -> Option<ProxyError> {
        self.proxy_error
    }

    pub(crate) fn set_proxy_error(&mut self, error: ProxyError) {
        self.proxy_error = Some(error);
    }

    /// The methods the proxy's challenges offered
    /// (`CURLINFO_PROXYAUTH_AVAIL`).
    pub fn proxy_auth_offered(&self) -> AuthMethods {
        self.proxy_auth_offered
    }

    pub(crate) fn add_proxy_auth_offered(&mut self, methods: AuthMethods) {
        self.proxy_auth_offered = self.proxy_auth_offered | methods;
    }

    /// The method the last request authenticated with to the proxy, or
    /// that was chosen for the next one (`CURLINFO_PROXYAUTH_USED`).
    pub fn proxy_auth_used(&self) -> AuthMethods {
        self.proxy_auth_used
    }

    pub(crate) fn set_proxy_auth_used(&mut self, method: AuthMethods) {
        self.proxy_auth_used = method;
    }

    pub(crate) fn count_redirect(&mut self) {
        self.redirects = self.redirects.saturating_add(1);
    }

    /// The method of the last request, without the application's custom
    /// one; `Easy::effective_method` names it.
    pub fn method(&self) -> Method {
        self.method
    }

    pub(crate) fn set_method(&mut self, method: Method) {
        self.method = method;
    }

    /// The referer the last request sent (`CURLINFO_REFERER`).
    pub fn referer(&self) -> Option<&[u8]> {
        self.referer.as_deref()
    }

    pub(crate) fn set_referer(&mut self, referer: Vec<u8>) {
        self.referer = Some(referer);
    }

    /// How long a response asked to wait before the next try, in whole
    /// seconds (`CURLINFO_RETRY_AFTER`); none if no response said. A
    /// wait it gave as nonsense, or a date passed, is zero.
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// The transfer's last connection went through a proxy
    /// (`CURLINFO_USED_PROXY`).
    pub fn used_proxy(&self) -> bool {
        self.used_proxy
    }

    pub(crate) fn set_used_proxy(&mut self, used: bool) {
        self.used_proxy = used;
    }

    pub(crate) fn set_retry_after(&mut self, wait: Duration) {
        self.retry_after = Some(wait);
    }

    /// The URL the transfer used, its credentials taken out
    /// (`CURLINFO_EFFECTIVE_URL`).
    pub fn url(&self) -> Option<&[u8]> {
        self.url.as_deref()
    }

    /// Keep `url`'s text without its credentials. The transfer's start
    /// made sure the URL reads back with them, so without them it can
    /// fail only for memory.
    pub(crate) fn set_url(&mut self, url: &Url) -> Result<(), OutOfMemory> {
        let text = match url.shown() {
            Ok(text) => text,
            Err(UrlErrorKind::OutOfMemory) => return Err(OutOfMemory),
            Err(e) => unreachable!("a URL that read back with credentials fails without: {e:?}"),
        };
        self.url = Some(text);
        Ok(())
    }

    /// Where the response would have redirected to, had it been followed
    /// (`CURLINFO_REDIRECT_URL`).
    pub fn redirect_url(&self) -> Option<&[u8]> {
        self.redirect_url.as_deref()
    }

    pub(crate) fn set_redirect_url(&mut self, url: Vec<u8>) {
        self.redirect_url = Some(url);
    }

    /// The operating system's error number for the last socket call of
    /// the transfer that failed: an attempt to connect, a send or a
    /// receive, whether or not the transfer failed with it
    /// (`CURLINFO_OS_ERRNO`). None before one fails.
    pub fn os_errno(&self) -> Option<OsErrno> {
        self.os_errno
    }

    /// A socket call failed with `e` (`data->state.os_errno = sockerr`).
    /// An error without a number, or numbered 0, leaves what was kept, as
    /// C sets it only from a socket's error.
    pub(crate) fn socket_failed(&mut self, e: &std::io::Error) {
        if let Some(n) = e.raw_os_error().and_then(OsErrno::new) {
            self.os_errno = Some(n);
        }
    }

    /// Why the transfer failed, in the words of the first reason given.
    pub fn failure(&self) -> Option<&[u8]> {
        self.failure.as_deref()
    }

    /// How many reasons for failing the transfer gave: a handler that
    /// gave one leaves its caller nothing to add.
    pub(crate) fn reasons(&self) -> u32 {
        self.reasons
    }

    /// Keep `detail` as the reason, unless one was given already.
    pub(crate) fn record_failure(&mut self, detail: &[u8]) {
        self.reasons = self.reasons.saturating_add(1);
        if self.failure.is_some() {
            return;
        }
        let mut kept = Vec::new();
        if kept.try_extend_from_slice(detail).is_ok() {
            self.failure = Some(kept);
        }
    }

    pub(crate) fn speeds_mut(&mut self) -> &mut Speeds {
        &mut self.speeds
    }

    pub(crate) fn timings_mut(&mut self) -> &mut Timings {
        &mut self.timings
    }

    pub(crate) fn sizes_mut(&mut self) -> &mut Sizes {
        &mut self.sizes
    }
}

/// The points in a transfer a time is taken at (`timerid`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Timer {
    /// The transfer starts running.
    StartOp,
    /// A request starts: the first, or one after a redirect.
    StartSingle,
    /// The request has its connection.
    PostQueue,
    NameLookup,
    Connect,
    AppConnect,
    /// The request is about to be sent.
    PreTransfer,
    /// The first byte of the response.
    StartTransfer,
    /// The request is sent.
    PostTransfer,
    Redirect,
}

impl Timer {
    /// Its name in the trace (`pgrs_timer_names`).
    pub(crate) fn name(self) -> &'static str {
        match self {
            Timer::StartOp => "PGRS-STARTOP",
            Timer::StartSingle => "PGRS-STARTSINGLE",
            Timer::PostQueue => "PGRS-POSTQUEUE",
            Timer::NameLookup => "PGRS-NAMELOOKUP",
            Timer::Connect => "PGRS-CONNECT",
            Timer::AppConnect => "PGRS-APPCONNECT",
            Timer::PreTransfer => "PGRS-PRETRANSFER",
            Timer::StartTransfer => "PGRS-STARTTRANSFER",
            Timer::PostTransfer => "PGRS-POSTRANSFER",
            Timer::Redirect => "PGRS-REDIRECT",
        }
    }
}

/// What taking a time did, as C traces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Marked {
    /// A point in time was kept.
    Set,
    /// A phase grew by this many µs.
    Added(u64),
    /// The first response byte was counted already.
    Ignored,
}

/// How long a transfer took to reach each point (`struct Progress`'s
/// `delta` and `total`). Each phase sums over every request of the
/// transfer, counted from that request's start, and is at least a
/// microsecond once reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timings {
    /// The transfer's start; `None` before it ran.
    start: Option<Instant>,
    /// When the transfer started running and its last request started;
    /// `None` before it ran. Its time limits are judged from them.
    starts: Option<Starts>,
    /// Since the start, in µs: when the last queueing started, and the
    /// last redirect happened.
    startqueue: u64,
    startredirect: u64,
    /// Sums over the requests, in µs.
    queued: u64,
    namelookup: u64,
    connect: u64,
    appconnect: u64,
    pretransfer: u64,
    starttransfer: u64,
    posttransfer: u64,
    /// The whole transfer, set once it is over.
    total: u64,
    /// This request's first response byte is counted already.
    starttransfer_added: bool,
}

/// When a transfer started running (`TIMER_STARTOP`) and its last request
/// started (`TIMER_STARTSINGLE`): its total and connect limits are judged
/// from them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Starts {
    pub(crate) op: Instant,
    pub(crate) single: Instant,
}

impl Timings {
    /// When the transfer and its last request started, once it ran.
    pub(crate) fn starts(&self) -> Option<Starts> {
        self.starts
    }

    /// Take the time of `timer` as `now` (`Curl_pgrsTimeWas`).
    pub(crate) fn mark(&mut self, timer: Timer, now: Instant) -> Marked {
        let since_start = self.since_start(now);
        let since_single = since_start.saturating_sub(self.since_single_start());
        let phase = match timer {
            Timer::StartOp => {
                self.starts = Some(Starts {
                    op: now,
                    single: now,
                });
                self.startqueue = since_start;
                return Marked::Set;
            }
            Timer::StartSingle => {
                self.starts
                    .as_mut()
                    .expect("a request starts after its transfer")
                    .single = now;
                self.starttransfer_added = false;
                return Marked::Set;
            }
            Timer::PostQueue => {
                // Queue time sums over every request.
                self.queued += since_start.saturating_sub(self.startqueue);
                return Marked::Set;
            }
            Timer::Redirect => {
                self.startredirect = since_start;
                // The transfer queues again.
                self.startqueue = since_start;
                return Marked::Set;
            }
            Timer::StartTransfer if self.starttransfer_added => return Marked::Ignored,
            Timer::StartTransfer => {
                self.starttransfer_added = true;
                &mut self.starttransfer
            }
            Timer::NameLookup => &mut self.namelookup,
            Timer::Connect => &mut self.connect,
            Timer::AppConnect => &mut self.appconnect,
            Timer::PreTransfer => &mut self.pretransfer,
            Timer::PostTransfer => &mut self.posttransfer,
        };
        let added = since_single.max(1);
        *phase += added;
        Marked::Added(added)
    }

    /// The transfer is over (`Curl_pgrsCompleted`), or a progress pass
    /// takes stock of it: the total so far. A pass reads the clock once,
    /// so a transfer done within one can take no time, while each phase
    /// it reached counts at least a microsecond: the total is never less
    /// than a phase within it.
    pub(crate) fn completed(&mut self, now: Instant) {
        let phases = [
            self.namelookup,
            self.connect,
            self.appconnect,
            self.pretransfer,
            self.starttransfer,
            self.posttransfer,
        ];
        self.total = phases.into_iter().fold(self.since_start(now), u64::max);
    }

    /// Microseconds from the transfer's start to `now`.
    pub(crate) fn since_start_us(&self, now: Instant) -> u64 {
        self.since_start(now)
    }

    /// Milliseconds from the last request's start to `now`
    /// (`Curl_pgrs_since_ms` from `TIMER_STARTSINGLE`).
    pub(crate) fn since_single_ms(&self, now: Instant) -> u64 {
        self.since_start(now)
            .saturating_sub(self.since_single_start())
            / 1000
    }

    /// Milliseconds from the transfer's first request's start to `now`
    /// (`Curl_pgrs_since_ms` from `TIMER_STARTOP`): every request it
    /// made again or was redirected to counted.
    pub(crate) fn since_op_ms(&self, now: Instant) -> u64 {
        let op = self.starts.map_or(0, |s| self.since_start(s.op));
        self.since_start(now).saturating_sub(op) / 1000
    }

    /// Microseconds from the transfer's start to its last request's.
    fn since_single_start(&self) -> u64 {
        self.starts.map_or(0, |s| self.since_start(s.single))
    }

    fn since_start(&self, now: Instant) -> u64 {
        let start = self
            .start
            .expect("a transfer's times are taken after its start");
        u64::try_from(now.since(start).as_micros()).unwrap_or(u64::MAX)
    }

    /// `CURLINFO_TOTAL_TIME_T`: until the transfer is over, as of its last
    /// progress pass.
    pub fn total(&self) -> Duration {
        Duration::from_micros(self.total)
    }

    pub fn queue(&self) -> Duration {
        Duration::from_micros(self.queued)
    }

    pub fn namelookup(&self) -> Duration {
        Duration::from_micros(self.namelookup)
    }

    pub fn connect(&self) -> Duration {
        Duration::from_micros(self.connect)
    }

    pub fn appconnect(&self) -> Duration {
        Duration::from_micros(self.appconnect)
    }

    pub fn pretransfer(&self) -> Duration {
        Duration::from_micros(self.pretransfer)
    }

    pub fn posttransfer(&self) -> Duration {
        Duration::from_micros(self.posttransfer)
    }

    pub fn starttransfer(&self) -> Duration {
        Duration::from_micros(self.starttransfer)
    }

    /// When the last redirect happened, from the start.
    pub fn redirect(&self) -> Duration {
        Duration::from_micros(self.startredirect)
    }
}

/// How much the current request moved (`struct Progress`'s counters),
/// counted from zero again for every request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sizes {
    /// Head and trailer bytes received over every request, against the
    /// transfer's limit (`info.header_size`).
    pub(crate) header: u64,
    pub(crate) download: u64,
    pub(crate) delivered: u64,
    pub(crate) download_expected: Option<u64>,
    pub(crate) upload: u64,
    pub(crate) upload_expected: Option<u64>,
    /// Bytes sent of every request, head and body (`info.request_size`).
    pub(crate) request: u64,
}

impl Sizes {
    /// A request starts: what it moves is counted from nothing, and its
    /// sizes are not known yet (`Curl_pgrsReset`). Heads and requests
    /// are counted over the whole transfer.
    pub(crate) fn new_request(&mut self) {
        self.download = 0;
        self.delivered = 0;
        self.upload = 0;
        self.download_expected = None;
        self.upload_expected = None;
    }

    /// Bytes of every response head and trailer received
    /// (`CURLINFO_HEADER_SIZE`).
    pub fn header(&self) -> u64 {
        self.header
    }

    /// Bytes sent of every request, head and body
    /// (`CURLINFO_REQUEST_SIZE`).
    pub fn request(&self) -> u64 {
        self.request
    }

    /// Body bytes sent (`CURLINFO_SIZE_UPLOAD_T`).
    pub fn upload(&self) -> u64 {
        self.upload
    }

    /// The size of the body to send, where the request announced it
    /// (`CURLINFO_CONTENT_LENGTH_UPLOAD_T`).
    pub fn upload_expected(&self) -> Option<u64> {
        self.upload_expected
    }

    /// The body's size as the response announced it
    /// (`CURLINFO_CONTENT_LENGTH_DOWNLOAD_T`).
    pub fn download_expected(&self) -> Option<u64> {
        self.download_expected
    }

    /// Body bytes received, before content decoding
    /// (`CURLINFO_SIZE_DOWNLOAD_T`).
    pub fn download(&self) -> u64 {
        self.download
    }

    /// Bytes given to the write handler, after content decoding
    /// (`CURLINFO_SIZE_DELIVERED`).
    pub fn delivered(&self) -> u64 {
        self.delivered
    }
}

/// Average speeds since the transfer started, in bytes a second, as of
/// its last progress pass (`CURLINFO_SPEED_DOWNLOAD_T`,
/// `CURLINFO_SPEED_UPLOAD_T`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Speeds {
    pub(crate) download: u64,
    pub(crate) upload: u64,
}

impl Speeds {
    pub fn download(&self) -> u64 {
        self.download
    }

    pub fn upload(&self) -> u64 {
        self.upload
    }
}

/// What the debug test build answers for some infos in place of the
/// transfer's own, read from the environment at each question, as C's
/// `curl_easy_getinfo` does in its debug build: the tool's `--write-out`
/// and the C ABI's getinfo each apply them to the infos C's does.
#[cfg(feature = "debug-hooks")]
pub mod debug_info {
    /// `CURL_TIME`: every time, in microseconds, both speeds and the
    /// local port.
    pub fn time() -> Option<u64> {
        number("CURL_TIME")
    }

    /// `CURL_DEBUG_SIZE`: the sizes of the headers and of the request.
    pub fn size() -> Option<u64> {
        number("CURL_DEBUG_SIZE")
    }

    /// The variable `name`'s leading digits, if it is set: 0 if it has
    /// none or they overflow (`curlx_str_number`).
    fn number(name: &str) -> Option<u64> {
        // Read without allocating, as C's `getenv`, cut at 32 bytes: a
        // number of more than 19 digits overflows anyway, so only one led
        // by zeros whose digits run past the cut reads otherwise than in C.
        let mut buf = [0u8; 32];
        let value = curl_os::env::var_into(name.as_bytes(), &mut buf)?;
        Some(leading_number(value))
    }

    pub(super) fn leading_number(text: &[u8]) -> u64 {
        let mut n: u64 = 0;
        for &b in text.iter().take_while(|b| b.is_ascii_digit()) {
            match n
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(b - b'0')))
                .filter(|&n| n <= i64::MAX as u64)
            {
                Some(next) => n = next,
                None => return 0,
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The debug build's numbers as `curlx_str_number` reads them.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn reads_the_debug_numbers_as_c() {
        use debug_info::leading_number;
        assert_eq!(leading_number(b"13"), 13);
        assert_eq!(leading_number(b"4019 bytes"), 4019);
        assert_eq!(leading_number(b"x1"), 0);
        assert_eq!(leading_number(b""), 0);
        assert_eq!(leading_number(b"9223372036854775807"), i64::MAX as u64);
        assert_eq!(leading_number(b"9223372036854775808"), 0);
    }

    /// `CURL_TIME` and `CURL_DEBUG_SIZE` answer as their leading
    /// numbers, read in a child of this binary given them: the
    /// environment is the whole process's.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn the_debug_infos_are_read_from_the_environment() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "report::tests::debug_infos_in_a_child",
                "--test-threads=1",
            ])
            .env("CURL_CORE_CHILD", "debug-infos")
            .env("CURL_TIME", "123x")
            .env("CURL_DEBUG_SIZE", "0042")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The child of `the_debug_infos_are_read_from_the_environment`.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn debug_infos_in_a_child() {
        if std::env::var_os("CURL_CORE_CHILD").is_none_or(|m| m != "debug-infos") {
            return;
        }
        assert_eq!(debug_info::time(), Some(123));
        assert_eq!(debug_info::size(), Some(42));
    }

    /// The first reason given is kept; a new transfer starts without one.
    #[test]
    fn keeps_the_first_failure() {
        let mut r = TransferReport::default();
        assert_eq!(r.failure(), None);
        r.record_failure(b"first");
        r.record_failure(b"second");
        assert_eq!(r.failure(), Some(&b"first"[..]));
        r.restart(Instant::EPOCH);
        assert_eq!(r.failure(), None);
    }

    fn started(now: Instant) -> Timings {
        let mut r = TransferReport::default();
        r.restart(now);
        r.timings
    }

    fn at(us: u64) -> Instant {
        Instant::EPOCH.after(Duration::from_micros(us))
    }

    fn phases(t: &Timings) -> [Duration; 5] {
        [
            t.namelookup(),
            t.connect(),
            t.appconnect(),
            t.pretransfer(),
            t.starttransfer(),
        ]
    }

    /// unit1399: across a redirect each phase adds up, counted from the
    /// start of its own request, and STARTTRANSFER counts once per request.
    #[test]
    fn phases_add_up_across_a_redirect() {
        let start = 12_345_678_000_000;
        let mut t = started(at(start));
        t.mark(Timer::StartOp, at(start));
        t.mark(Timer::StartSingle, at(start));
        let now = start + 2_250_000;
        for timer in [
            Timer::NameLookup,
            Timer::Connect,
            Timer::AppConnect,
            Timer::PreTransfer,
            Timer::StartTransfer,
        ] {
            t.mark(timer, at(now));
        }
        assert_eq!(phases(&t), [Duration::from_micros(2_250_000); 5]);
        let now = now + 1_000_000;
        t.mark(Timer::Redirect, at(now));
        t.mark(Timer::StartSingle, at(now));
        let now = now + 1_500_000;
        for timer in [
            Timer::NameLookup,
            Timer::Connect,
            Timer::AppConnect,
            Timer::PreTransfer,
            Timer::StartTransfer,
        ] {
            t.mark(timer, at(now));
        }
        t.mark(Timer::StartTransfer, at(now + 1_000_000));
        t.mark(Timer::StartTransfer, at(now + 1_000_000));
        assert_eq!(phases(&t), [Duration::from_micros(3_750_000); 5]);
        assert_eq!(t.redirect(), Duration::from_micros(3_250_000));
        // The second request's time, for the connect timeout's texts, is
        // its own; the transfer's, for the others', is all of it.
        assert_eq!(t.since_single_ms(at(now)), 1_500);
        assert_eq!(t.since_op_ms(at(now)), 4_750);
        let starts = t.starts().unwrap();
        assert_eq!((starts.op, starts.single), (at(start), at(now - 1_500_000)));
    }

    #[test]
    fn a_phase_reached_at_its_start_counts_a_microsecond() {
        let mut t = started(at(5));
        t.mark(Timer::StartOp, at(5));
        t.mark(Timer::StartSingle, at(5));
        t.mark(Timer::PreTransfer, at(5));
        assert_eq!(t.pretransfer(), Duration::from_micros(1));
        // Over at once: the total holds the phase.
        t.mark(Timer::PostTransfer, at(5));
        t.completed(at(5));
        assert_eq!(t.total(), Duration::from_micros(1));
    }

    /// Queueing time sums over requests, each from when it started queueing.
    #[test]
    fn queue_time_sums_over_requests() {
        let mut t = started(at(0));
        t.mark(Timer::StartOp, at(10));
        t.mark(Timer::PostQueue, at(40));
        t.mark(Timer::Redirect, at(100));
        t.mark(Timer::PostQueue, at(150));
        assert_eq!(t.queue(), Duration::from_micros(30 + 50));
        assert_eq!(t.total(), Duration::ZERO, "not over yet");
        t.completed(at(200));
        assert_eq!(t.total(), Duration::from_micros(200));
    }
}
