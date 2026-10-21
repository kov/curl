//! What a transfer reports about itself (`curl_easy_getinfo`): written by
//! the engine as the transfer runs, readable from inside its callbacks,
//! and kept in the `Easy` after it ends, until the next transfer starts.

mod headers;

use std::time::Duration;

pub use headers::{HeaderCursor, HeaderError, HeaderStore, HeaderView, Origins, Request};

use crate::time::Instant;

/// One transfer's report. The default is that of a transfer never run.
#[derive(Clone, Debug, Default)]
pub struct TransferReport {
    timings: Timings,
    sizes: Sizes,
    speeds: Speeds,
    headers: HeaderStore,
    filetime: Option<i64>,
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "marked by connections, from step 11")
    )]
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "marked by redirects, from stage 3")
    )]
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
    /// Since the start, in µs: when the transfer started running, the
    /// last request started, the last queueing started, and the last
    /// redirect happened.
    startop: u64,
    startsingle: u64,
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

impl Timings {
    /// Take the time of `timer` as `now` (`Curl_pgrsTimeWas`).
    pub(crate) fn mark(&mut self, timer: Timer, now: Instant) {
        let since_start = self.since_start(now);
        let phase = match timer {
            Timer::StartOp => {
                self.startop = since_start;
                self.startqueue = since_start;
                return;
            }
            Timer::StartSingle => {
                self.startsingle = since_start;
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
        *phase += since_start.saturating_sub(self.startsingle).max(1);
    }

    /// The transfer is over (`Curl_pgrsCompleted`), or a progress pass
    /// takes stock of it: the total so far.
    pub(crate) fn completed(&mut self, now: Instant) {
        self.total = self.since_start(now);
    }

    /// Microseconds from the transfer's start to `now`.
    pub(crate) fn since_start_us(&self, now: Instant) -> u64 {
        self.since_start(now)
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
    pub(crate) download: u64,
    pub(crate) delivered: u64,
    pub(crate) download_expected: Option<u64>,
    pub(crate) upload: u64,
    pub(crate) upload_expected: Option<u64>,
}

impl Sizes {
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
    }

    #[test]
    fn a_phase_reached_at_its_start_counts_a_microsecond() {
        let mut t = started(at(5));
        t.mark(Timer::StartSingle, at(5));
        t.mark(Timer::PreTransfer, at(5));
        assert_eq!(t.pretransfer(), Duration::from_micros(1));
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
