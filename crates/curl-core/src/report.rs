//! What a transfer reports about itself (`curl_easy_getinfo`): written by
//! the engine as the transfer runs, readable from inside its callbacks,
//! and kept in the `Easy` after it ends, until the next transfer starts.

mod headers;

use std::net::SocketAddr;
use std::time::Duration;

pub use headers::{HeaderCursor, HeaderError, HeaderStore, HeaderView, Origins, Request};

use curl_alloc::TryVec;

use crate::time::Instant;
use curl_alloc::OutOfMemory;

use crate::error::UrlErrorKind;
use crate::options::Method;
use crate::url::{GetOptions, Part, Url};
use crate::version::Protocol;

/// The ends of a connection: the peer's address, and the local one if
/// it was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ends {
    pub remote: SocketAddr,
    pub local: Option<SocketAddr>,
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
    protocol: Option<Protocol>,
    /// The last status line's code and version (`info.httpcode`,
    /// `info.httpversion`).
    response: Option<(u16, ResponseVersion)>,
    /// How long the last response to say asked to wait before trying
    /// again, at most six hours (`info.retry_after`).
    retry_after: Option<Duration>,
    /// The URL the transfer used, without its credentials, as text.
    url: Option<Vec<u8>>,
    /// Where the last response's `Location:` points, resolved, when it
    /// was not followed (`info.wouldredirect`).
    redirect_url: Option<Vec<u8>>,
    /// The last `Content-Type:` a response gave, not empty
    /// (`info.contenttype`).
    content_type: Option<Vec<u8>>,
    /// The ends of the connection last used (`info.primary`).
    primary: Option<Ends>,
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
            ..TransferReport::default()
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
    pub(crate) fn set_url(&mut self, mut url: Url) -> Result<(), OutOfMemory> {
        url.forget_credentials();
        let get = GetOptions {
            get_empty: true,
            ..GetOptions::NONE
        };
        let text = match url.get(Part::Url, get) {
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "marked by connections, from step 11")
    )]
    AppConnect,
    /// The request is about to be sent.
    PreTransfer,
    /// The first byte of the response.
    StartTransfer,
    /// The request is sent.
    PostTransfer,
    Redirect,
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
    pub(crate) fn mark(&mut self, timer: Timer, now: Instant) {
        let since_start = self.since_start(now);
        let since_single = since_start.saturating_sub(self.since_single_start());
        let phase = match timer {
            Timer::StartOp => {
                self.starts = Some(Starts {
                    op: now,
                    single: now,
                });
                self.startqueue = since_start;
                return;
            }
            Timer::StartSingle => {
                self.starts
                    .as_mut()
                    .expect("a request starts after its transfer")
                    .single = now;
                self.starttransfer_added = false;
                return;
            }
            Timer::PostQueue => {
                // Queue time sums over every request.
                self.queued += since_start.saturating_sub(self.startqueue);
                return;
            }
            Timer::Redirect => {
                self.startredirect = since_start;
                // The transfer queues again.
                self.startqueue = since_start;
                return;
            }
            Timer::StartTransfer if self.starttransfer_added => return,
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
        *phase += since_single.max(1);
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // The second request's time, for the timeout texts, is its own.
        assert_eq!(t.since_single_ms(at(now)), 1_500);
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
