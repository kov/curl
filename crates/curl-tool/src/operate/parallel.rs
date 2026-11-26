//! Running the transfers at once, one multi driving them
//! (`src/tool_operate.c`'s `parallel_transfers`), with the meter that
//! shows them all on one line (`src/tool_progress.c`).

use std::io::Write as _;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};
use curl_core::error::{ErrorKind, MultiErrorKind};
use curl_core::handler::{Handler, ProgressHandler, ProgressNow, ProgressVerdict};
use curl_core::multi::{Ids, Multi, MultiKind, NoEvents, TransferCx, TransferId, WaitMode};
use curl_core::options::Progress;

use super::{
    Again, Attempt, Ended, Ending, Handle, Made, PerTransfer, Pre, Shared, Told, Transfers, create,
    ends_run, settle,
};
use crate::easysrc::Setopt;
use crate::options::CommandLine;

/// How many run at once unless `--parallel-max` says (`PARALLEL_DEFAULT`).
const PARALLEL_DEFAULT: usize = 50;

/// The reason of a transfer stopped for another's failure.
const ABORTED: &[u8] = b"Transfer aborted due to critical error in another transfer";

/// The longest a wait for the transfers lasts (`parallel_transfers`).
const WAIT_MAX: Duration = Duration::from_secs(1);

/// Run every transfer the command line asks for, at most `--parallel-max`
/// at once, in the order they are made, and end those left at the end
/// (`parallel_transfers`, `run_all_transfers`). The result is the first
/// failure.
pub(super) fn run_all(line: &CommandLine<'_>, run: &Shared<'_, '_>) -> Ending {
    let multi = match new_multi(line) {
        Ok(multi) => multi,
        Err(OutOfMemory) => return Err(ErrorKind::OutOfMemory),
    };
    let max = line
        .global
        .parallel_max
        .map_or(PARALLEL_DEFAULT, |n| usize::from(n.get()));
    let mut p = Parallel {
        run,
        transfers: Transfers::new(&line.operations, run.msgs),
        list: Vec::new(),
        multi,
        max,
        all_added: 0,
        meter: Meter::new(),
        terminal: false,
    };
    let result = p.drive();
    p.end_all(result)
}

/// The multi the transfers run in: its own connections, at most
/// `--parallel-max-host` to a host (`CURLMOPT_MAX_HOST_CONNECTIONS`).
fn new_multi(line: &CommandLine<'_>) -> Result<Multi, OutOfMemory> {
    // C's tool makes its multi with `curl_multi_init`, whose row 0 holds
    // the multi's own handle, so the transfers run and report in C's order
    // as the ids wrap around.
    let mut multi = Multi::new(MultiKind::Application, Ids::AsC)?;
    multi.conn_limits_mut().max_host = line.global.parallel_host.map(NonZeroU32::from);
    multi.set_quick_exit(super::quick_exit());
    Ok(multi)
}

/// What a transfer's progress handler tells the meter, and what the
/// driver tells the handler (C's `per_transfer`'s counts and `abort`).
#[derive(Default)]
struct Gauge {
    downloaded: AtomicU64,
    download_total: AtomicU64,
    uploaded: AtomicU64,
    upload_total: AtomicU64,
    /// What attempts before this one downloaded and kept, the resumed
    /// one counting on from them (`dlretry`).
    kept: AtomicU64,
    /// Another transfer failed critically: this one stops.
    abort: AtomicBool,
}

/// The handler every parallel transfer has (`xferinfo_cb`): it keeps the
/// counts and draws nothing, so the library draws no meter of its own.
struct Gauged(TryArc<Gauge>);

impl Gauge {
    /// Keep what the attempt's progress says. An unknown size counts as
    /// 0, as C's; what earlier attempts kept counts in, and in a size
    /// that is known.
    fn told(&self, now: ProgressNow) {
        let kept = self.kept.load(Ordering::Relaxed);
        let mut downloaded = now.downloaded;
        add_off(&mut downloaded, kept);
        self.downloaded.store(downloaded, Ordering::Relaxed);
        let mut total = now.download_total.unwrap_or(0);
        if total != 0 {
            add_off(&mut total, kept);
        }
        self.download_total.store(total, Ordering::Relaxed);
        self.uploaded.store(now.uploaded, Ordering::Relaxed);
        let total = now.upload_total.unwrap_or(0);
        self.upload_total.store(total, Ordering::Relaxed);
    }
}

impl ProgressHandler for Gauged {
    fn progress(&self, _: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict {
        let g = &self.0;
        g.told(now);
        if g.abort.load(Ordering::Relaxed) {
            ProgressVerdict::Abort
        } else {
            ProgressVerdict::Continue
        }
    }
}

/// Where a transfer's handle is.
enum Place {
    /// With the tool: not added yet, waiting to be added again, or not to
    /// be added at all.
    Here(Handle),
    /// In the multi.
    Added(TransferId),
}

/// A transfer in the list (C's `per_transfer` in `transfers`).
struct Entry<'a, 'l> {
    per: PerTransfer<'a, 'l>,
    place: Place,
    counted: Counted,
    /// Not added again before this second since the epoch, for a retry
    /// (`startat`).
    start_at: u64,
    /// It failed as it was made, and ends so at the end.
    unfinished: Option<Ended>,
}

impl<'a, 'l> Entry<'a, 'l> {
    /// A transfer just made, to the list.
    #[inline(always)]
    fn boxed(
        per: PerTransfer<'a, 'l>,
        easy: Handle,
        unfinished: Option<Ended>,
    ) -> Result<Box<Entry<'a, 'l>>, ErrorKind> {
        let counted = Counted::new().map_err(|_| ErrorKind::OutOfMemory)?;
        try_box(Entry {
            per,
            place: Place::Here(easy),
            counted,
            start_at: 0,
            unfinished,
        })
        .map_err(|_| ErrorKind::OutOfMemory)
    }

    /// Added, or not to be (C's `added`, `skip`).
    fn passed(&self) -> bool {
        matches!(self.place, Place::Added(_)) || self.per.skip || self.unfinished.is_some()
    }
}

struct Parallel<'r, 'a, 'l> {
    run: &'r Shared<'r, 'l>,
    transfers: Transfers<'a, 'l>,
    /// Every transfer made and not ended, in the order made. Boxed: one
    /// ended is taken out of the middle, and the rest move up.
    #[expect(
        clippy::vec_box,
        reason = "an entry is a few hundred bytes: removing one moves those after it"
    )]
    list: Vec<Box<Entry<'a, 'l>>>,
    multi: Multi,
    max: usize,
    /// How many are in the multi (`all_added`).
    all_added: usize,
    meter: Meter,
    /// The output of the transfer made last goes to a terminal: no meter
    /// (C's `global->noprogress`, set by each transfer made).
    terminal: bool,
}

/// Seconds since the epoch, as C's `time(NULL)`.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Whether a transfer to be added again at the second `start_at` waits
/// still, at the second `now`.
fn waiting(now: u64, start_at: u64) -> bool {
    now < start_at
}

/// The second a transfer tried again after `wait` is added again at, from
/// the second `now`: the wait is counted in whole seconds, so one shorter
/// than a second is none (`check_finished`).
fn start_at(now: u64, wait: Duration) -> u64 {
    let secs = u64::try_from(wait.as_millis() / 1000).unwrap_or(u64::MAX);
    now.saturating_add(secs)
}

/// The failure of a transfer that ended as it was made.
fn failure(ended: Ended) -> ErrorKind {
    match ended {
        Ended::Ran(Err(e)) | Ended::Said(e) => e,
        _ => unreachable!("a transfer failed as it was made"),
    }
}

impl<'a, 'l> Parallel<'_, 'a, 'l> {
    /// Make the next transfer and those skipped before it, each onto the
    /// list (`create_transfer`, while it skips).
    fn create_next(&mut self) -> Result<(), ErrorKind> {
        loop {
            match self.transfers.advance() {
                Ok(true) => {}
                Ok(false) => return Ok(()),
                Err(ending) => return ending,
            }
            // Boxed straight from what was made: an entry is a few hundred
            // bytes, and each move of it a copy.
            let entry = match create(self.run, self.transfers.item()) {
                Made::Ready(per, easy) => Entry::boxed(per, easy, None)?,
                Made::Unfinished(per, easy, ended) => Entry::boxed(per, easy, Some(ended))?,
                Made::Failed(e) => return Err(e),
                Made::Abandoned => {
                    self.transfers.abandon();
                    continue;
                }
            };
            self.terminal = entry.per.terminal;
            let skip = entry.per.skip;
            let unfinished = entry.unfinished;
            self.list
                .try_push(entry)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            if let Some(ended) = unfinished {
                return Err(failure(ended));
            }
            if !skip {
                return Ok(());
            }
        }
    }

    /// Add transfers until as many run as may, each made ready for its
    /// attempt, and the one after each made (`add_parallel_transfers`).
    /// Whether more are left to add, and whether any was.
    fn add_more(&mut self) -> Result<(bool, bool), ErrorKind> {
        if self.all_added >= self.max {
            // Not looked at: there may be.
            return Ok((true, false));
        }
        if self.list.is_empty() {
            self.create_next()?;
        }
        let now = unix_now();
        let (mut sleeping, mut added) = (false, false);
        // Stopped by the cap, transfers may be left (C's `per` not NULL).
        let mut capped = false;
        let mut at = 0;
        while at < self.list.len() {
            if self.all_added >= self.max {
                capped = true;
                break;
            }
            let entry = &mut self.list[at];
            at += 1;
            if entry.passed() {
                continue;
            }
            if waiting(now, entry.start_at) {
                sleeping = true;
                continue;
            }
            let Place::Here(easy) = &mut entry.place else {
                unreachable!("not added");
            };
            match entry.per.pre_transfer(self.run, easy) {
                Ok(()) => {}
                Err(Pre::Failed(e)) => return Err(e),
                Err(Pre::Unopened) => return Err(ErrorKind::ReadError),
            }
            // Connecting at once is not waiting to multiplex
            // (`add_parallel_transfers`).
            let pipewait = !self.run.global.parallel_immediate;
            Setopt::new(easy, None)
                .unwritten("C sets it with `curl_easy_setopt` as it adds", |o| {
                    o.http.pipewait = pipewait;
                    Ok(())
                })
                .expect("setting a flag cannot fail");
            let oom = |_| ErrorKind::OutOfMemory;
            let gauged = Handler::progress(Gauged(entry.counted.gauge.clone())).map_err(oom)?;
            // It lets a `-T .` upload waiting for its input go on.
            let gauged = match &entry.per.stdin {
                Some(stdin) => stdin.progress(gauged).map_err(oom)?,
                None => gauged,
            };
            Setopt::new(easy, None)
                .unwritten("C sets it with `curl_easy_setopt` as it adds", |o| {
                    o.progress = Progress::Handler(gauged);
                    Ok(())
                })
                .expect("setting a handler cannot fail");
            // The debug build forbids reuse when asked.
            #[cfg(feature = "debug-hooks")]
            if curl_os::env::is_set(b"CURL_FORBID_REUSE") {
                Setopt::new(easy, None)
                    .unwritten("C's debug build sets it with `curl_easy_setopt`", |o| {
                        o.limits.reuse.forbid = true;
                        Ok(())
                    })
                    .expect("setting a flag cannot fail");
            }
            // The handle's box goes to the multi; what is left behind is
            // empty, and its drop saves nothing.
            match self.multi.add(easy.take(), (), &mut NoEvents) {
                Ok(id) => entry.place = Place::Added(id),
                Err(refused) => {
                    easy.put_back(refused.easy);
                    return Err(ErrorKind::OutOfMemory);
                }
            }
            self.create_next()?;
            self.all_added += 1;
            added = true;
        }
        Ok((capped || sleeping, added))
    }
}

impl Parallel<'_, '_, '_> {
    /// Drive the multi until every transfer is done, or, after a critical
    /// failure or one with `--fail-early`, until those running stopped
    /// (`parallel_transfers`). The first failure.
    fn drive(&mut self) -> Ending {
        let (mut more, _) = self.add_more()?;
        // Driven by events, C's runs on libuv, which this build has not:
        // it says so, and runs none of those it added.
        #[cfg(feature = "debug-hooks")]
        if self.run.global.test_event {
            self.run
                .msgs
                .error(&[b"Testing --parallel event-based requires libuv"]);
            return Ok(());
        }
        if self.all_added == 0 {
            return Ok(());
        }
        let mut result = Ok(());
        let mut still_running = true;
        let mut wrapitup = false;
        let mut failed = None;
        let start = Instant::now();
        while still_running || more {
            if wrapitup {
                if !still_running {
                    break;
                }
                // Those running stop at their next progress (C flags them
                // once; flagging them again changes nothing).
                for entry in &self.list {
                    if matches!(entry.place, Place::Added(_)) {
                        entry.counted.gauge.abort.store(true, Ordering::Relaxed);
                    }
                }
            } else if more {
                // A failure before this adding is kept: the adding's own
                // counts only if none came first (`parallel_transfers`).
                match self.add_more() {
                    Ok((left, _)) => more = left,
                    Err(e) => {
                        result = result.and(Err(e));
                        break;
                    }
                }
            }
            let ran = self
                .multi
                .wait(&mut [], WAIT_MAX, WaitMode::Poll, &mut NoEvents)
                .and_then(|_| self.multi.perform(&mut NoEvents));
            match ran {
                Ok(running) => still_running = running > 0,
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
            let checked = self.check_finished(&mut wrapitup, &mut more, &mut still_running);
            if result.is_ok() {
                result = checked;
            }
            self.meter_line(start, false);
        }
        self.meter_line(start, true);
        match failed {
            Some(MultiErrorKind::OutOfMemory) => Err(ErrorKind::OutOfMemory),
            // The others are not expected.
            Some(_) => Err(ErrorKind::BadFunctionArgument),
            None => result,
        }
    }

    /// End each transfer that completed, or make it ready to be added
    /// again for a retry, then add more (`check_finished`). What the
    /// transfers ended with: a failure, the last of them unless it was
    /// one stopped for another's.
    fn check_finished(
        &mut self,
        wrapitup: &mut bool,
        more: &mut bool,
        still_running: &mut bool,
    ) -> Ending {
        let run = self.run;
        let fail_early = run.global.fail_early;
        let mut result = Ok(());
        let mut checked = false;
        while let Some(msg) = self.multi.info_read() {
            let (id, ended) = (msg.id, msg.result);
            let removed = self
                .multi
                .remove(id, &mut NoEvents)
                .expect("its message was just read");
            let at = self
                .list
                .iter()
                .position(|e| matches!(e.place, Place::Added(added) if added == id))
                .expect("every transfer added is listed");
            let mut easy = Handle::back(removed.easy);
            let entry = &mut self.list[at];
            let aborted = entry.counted.gauge.abort.load(Ordering::Relaxed);
            let told = match ended {
                Err(ErrorKind::AbortedByCallback) if aborted => Told::As(ABORTED),
                _ => Told::Not,
            };
            let per = &mut entry.per;
            let settled = settle(per.op, run, &per.url, &easy, &per.out, ended, told);
            let attempt = Attempt {
                result: settled,
                upload: per.upload.is_some(),
                method: per.method,
            };
            let again = per
                .retrying
                .check(per.op, run.msgs, &mut easy, &per.out, attempt);
            self.all_added -= 1;
            checked = true;
            match again {
                Again::After(wait) => {
                    let kept = entry.per.retrying.kept;
                    self.meter.reset_retry(&entry.counted, kept);
                    entry.start_at = start_at(unix_now(), wait);
                    entry.place = Place::Here(easy);
                }
                Again::No(settled) => {
                    // Counted once, as it goes for good.
                    self.meter.finalize(&entry.counted);
                    let retries = entry.per.retrying.retries;
                    let done = entry.per.end(run, &easy, Ended::Settled(settled, retries));
                    if done.is_err() && (!aborted || result.is_ok()) {
                        result = done;
                    }
                    if ends_run(result, fail_early) {
                        *wrapitup = true;
                    }
                    self.list.remove(at);
                    drop(easy);
                }
            }
        }
        if !*wrapitup && checked {
            match self.add_more() {
                Ok((left, added)) => {
                    *more = left;
                    if added {
                        *still_running = true;
                    }
                }
                Err(e) => {
                    *more = false;
                    result = Err(e);
                }
            }
            if ends_run(result, fail_early) {
                *wrapitup = true;
            }
        }
        result
    }

    /// End every transfer still listed, with the run's `result`, taking
    /// those in the multi out first (`run_all_transfers`'s cleanup).
    fn end_all(mut self, result: Ending) -> Ending {
        let mut result = result;
        for entry in std::mem::take(&mut self.list) {
            let entry = *entry;
            let easy = match entry.place {
                Place::Here(easy) => easy,
                Place::Added(id) => Handle::back(
                    self.multi
                        .remove(id, &mut NoEvents)
                        .expect("an added transfer is in the multi")
                        .easy,
                ),
            };
            let ended = match entry.unfinished {
                Some(ended) => ended,
                None if entry.per.skip => Ended::Skipped(result),
                None => Ended::Ran(result),
            };
            let done = entry.per.end(self.run, &easy, ended);
            // The first failure stays.
            if result.is_ok() {
                result = done;
            }
        }
        result
    }

    /// Draw the meter, at most every half second unless `last`
    /// (`progress_meter`).
    fn meter_line(&mut self, start: Instant, last: bool) {
        if self.run.global.no_progress || self.terminal || self.run.msgs.silent {
            return;
        }
        let census = self.multi.census();
        let (counts, live) = (census.counts, census.working());
        let counted = self.list.iter().map(|e| &e.counted);
        let mut err = crate::stderr::Stderr;
        let now = Instant::now();
        let line = Line {
            start,
            now,
            added: counts.added_ever,
            live,
            last,
        };
        self.meter.draw(&mut err, counted, line);
    }
}

/// The meter of all the transfers (`progress_meter`'s statics).
struct Meter {
    header: bool,
    stamp: Option<Instant>,
    /// What transfers that ended got (`all_dlalready`, `all_ulalready`),
    /// and their totals (`all_dltotal_done`, `all_ultotal_done`); those
    /// of the transfers still listed are added each line.
    downloaded: u64,
    uploaded: u64,
    download_total: u64,
    upload_total: u64,
    /// The last few draws' counts, for the speed.
    speeds: [(u64, u64, Option<Instant>); SPEEDS],
    speed_at: usize,
    wrapped: bool,
}

/// How many draws the speed is taken over (`SPEEDCNT`).
const SPEEDS: usize = 10;

/// What C's 64-bit counts stop at.
const OFF_MAX: u64 = i64::MAX as u64;

fn add_off(to: &mut u64, n: u64) {
    *to = to.saturating_add(n).min(OFF_MAX);
}

impl Meter {
    fn new() -> Meter {
        Meter {
            header: false,
            stamp: None,
            downloaded: 0,
            uploaded: 0,
            download_total: 0,
            upload_total: 0,
            speeds: [(0, 0, None); SPEEDS],
            speed_at: 0,
            wrapped: false,
        }
    }

    /// Count a transfer's numbers as it goes for good
    /// (`progress_finalize`).
    fn finalize(&mut self, counted: &Counted) {
        let g = &counted.gauge;
        add_off(&mut self.downloaded, g.downloaded.load(Ordering::Relaxed));
        add_off(&mut self.uploaded, g.uploaded.load(Ordering::Relaxed));
        add_off(
            &mut self.download_total,
            g.download_total.load(Ordering::Relaxed),
        );
        add_off(
            &mut self.upload_total,
            g.upload_total.load(Ordering::Relaxed),
        );
    }

    /// A transfer to be tried again counts from nothing but what its
    /// attempts `kept`, its sizes not known; the speed starts over, as
    /// the counts went down (`progress_reset_retry`).
    fn reset_retry(&mut self, counted: &Counted, kept: u64) {
        let g = &counted.gauge;
        g.kept.store(kept, Ordering::Relaxed);
        g.downloaded.store(kept, Ordering::Relaxed);
        g.uploaded.store(0, Ordering::Relaxed);
        g.download_total.store(0, Ordering::Relaxed);
        g.upload_total.store(0, Ordering::Relaxed);
        self.speed_at = 0;
        self.wrapped = false;
    }

    /// Onto `out`, the header once, then the line of the transfers
    /// `counted` if half a second passed since the last or it is the last.
    fn draw<'c>(
        &mut self,
        out: &mut dyn std::io::Write,
        counted: impl Iterator<Item = &'c Counted>,
        line: Line,
    ) {
        // Nowhere to report a failed write, as in C.
        if !std::mem::replace(&mut self.header, true) {
            let _ = out
                .write_all(b"DL% UL%  Dled  Uled  Xfers  Live Total     Current  Left    Speed\n");
        }
        let due = self
            .stamp
            .is_none_or(|at| line.now.duration_since(at) > Duration::from_millis(500));
        if !(line.last || due) {
            return;
        }
        self.stamp = Some(line.now);
        let mut buf = [0u8; 128];
        let len = self.line(&mut buf, counted, line);
        let _ = out.write_all(&buf[..len]);
    }

    /// The line as C prints it, into `buf`; its length.
    fn line<'c>(
        &mut self,
        buf: &mut [u8],
        counted: impl Iterator<Item = &'c Counted>,
        line: Line,
    ) -> usize {
        let Line {
            start,
            now,
            added,
            live,
            last,
        } = line;
        let spent = now.duration_since(start).as_secs();
        let (mut dlnow, mut ulnow) = (0, 0);
        add_off(&mut dlnow, self.downloaded);
        add_off(&mut ulnow, self.uploaded);
        let (mut dltotal, mut ultotal) = (self.download_total, self.upload_total);
        let (mut dlknown, mut ulknown) = (true, true);
        for c in counted {
            let g = &c.gauge;
            add_off(&mut dlnow, g.downloaded.load(Ordering::Relaxed));
            add_off(&mut ulnow, g.uploaded.load(Ordering::Relaxed));
            let total = g.download_total.load(Ordering::Relaxed);
            if total == 0 {
                dlknown = false;
            } else {
                add_off(&mut dltotal, total);
            }
            let total = g.upload_total.load(Ordering::Relaxed);
            if total == 0 {
                ulknown = false;
            } else {
                add_off(&mut ultotal, total);
            }
        }
        let dlpercent = percent(dlknown, dlnow, dltotal);
        let ulpercent = percent(ulknown, ulnow, ultotal);
        // The speed, the higher of the two, over the last few draws.
        let at = self.speed_at;
        self.speeds[at] = (dlnow, ulnow, Some(now));
        self.speed_at += 1;
        if self.speed_at >= SPEEDS {
            self.wrapped = true;
            self.speed_at = 0;
        }
        let (since, dl, ul) = if self.wrapped {
            let (dl, ul, stamp) = self.speeds[self.speed_at];
            let stamp = stamp.expect("every draw stamped once wrapped");
            (stamp, dlnow - dl, ulnow - ul)
        } else {
            (start, dlnow, ulnow)
        };
        let ms = (now.duration_since(since).as_millis() as u64).max(1);
        let per_sec = |n: u64| (n as f64 / (ms as f64 / 1000.0)) as u64;
        let speed = per_sec(dl).max(per_sec(ul));
        let (left, total) = if dlknown && speed > 0 {
            let total = dltotal;
            let left = total.saturating_sub(dlnow) / speed;
            (time(left), time(total / speed))
        } else {
            (time(0), time(0))
        };
        let spent = time(spent);
        let mut cursor = std::io::Cursor::new(buf);
        let _ = write!(
            cursor,
            "\r{:<3} {:<3} {} {} {:5} {:5}  {} {} {} {} {:>5}",
            Percent(dlpercent),
            Percent(ulpercent),
            Max5(dlnow),
            Max5(ulnow),
            added,
            live,
            total,
            spent,
            left,
            Max5(speed),
            if last { "\n" } else { "" },
        );
        usize::try_from(cursor.position()).expect("within the buffer")
    }
}

/// The moment a line is drawn at, and what it says of the multi.
#[derive(Clone, Copy)]
struct Line {
    /// When the transfers started.
    start: Instant,
    now: Instant,
    /// Transfers added so far, each attempt counted.
    added: u64,
    /// Transfers running, not waiting for a connection.
    live: u32,
    /// The last line, drawn whenever it is due.
    last: bool,
}

/// `now` of `total` as a percentage, if every total is `known`; a count
/// too large to multiply is divided first.
fn percent(known: bool, now: u64, total: u64) -> Option<u64> {
    (known && total > 0).then(|| {
        if now < OFF_MAX / 100 {
            now * 100 / total
        } else {
            now / (total / 100)
        }
    })
}

/// What the meter keeps of one transfer: what its handler tells, and
/// whether its totals are counted (`dltotal_added`, `ultotal_added`).
struct Counted {
    gauge: TryArc<Gauge>,
}

impl Counted {
    fn new() -> Result<Counted, OutOfMemory> {
        Ok(Counted {
            gauge: TryArc::try_new(Gauge::default())?,
        })
    }
}

/// A percentage of three columns, `--` when unknown: `%3ld` into C's
/// buffer of four.
struct Percent(Option<u64>);

impl std::fmt::Display for Percent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(p) = self.0 else {
            return f.pad("--");
        };
        let mut buf = [0u8; 24];
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        let _ = write!(cursor, "{p:3}");
        let len = usize::try_from(cursor.position()).map_or(3, |n| n.min(3));
        f.pad(std::str::from_utf8(&buf[..len]).expect("digits"))
    }
}

/// A count in at most five columns, with a suffix past 99999
/// (`max5data`).
struct Max5(u64);

impl std::fmt::Display for Max5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const UNITS: [char; 6] = ['k', 'M', 'G', 'T', 'P', 'E'];
        let mut bytes = self.0;
        if bytes < 100_000 {
            return write!(f, "{bytes:5}");
        }
        for unit in UNITS {
            let n = bytes / 1024;
            if n < 100 {
                return write!(f, "{n:2}.{}{unit}", (bytes % 1024) * 10 / 1024);
            }
            if n < 10_000 {
                return write!(f, "{n:4}{unit}");
            }
            bytes = n;
        }
        unreachable!("a 63-bit count is under 100E")
    }
}

/// A time in eight columns (`timebuf`): blank for none.
fn time(seconds: u64) -> Time {
    Time(seconds)
}

struct Time(u64);

impl std::fmt::Display for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let seconds = self.0;
        if seconds == 0 {
            return f.write_str("        ");
        }
        let h = seconds / 3600;
        if h <= 99 {
            let m = (seconds - h * 3600) / 60;
            let s = seconds - h * 3600 - m * 60;
            return write!(f, "{h:02}:{m:02}:{s:02}");
        }
        let d = seconds / 86400;
        let h = (seconds - d * 86400) / 3600;
        if d <= 999 {
            return write!(f, "{d:3}d {h:02}h");
        }
        let m = d / 30;
        if m <= 999 {
            return write!(f, "{m:3}m {:02}d", d % 30);
        }
        let y = d / 365;
        if y <= 99999 {
            write!(f, "{y:7}y")
        } else {
            f.write_str(" >99999y")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(d: impl std::fmt::Display) -> String {
        format!("{d}")
    }

    /// A table of tool unit test 1622's, read from its source: each
    /// value and what it is shown as.
    fn tool1622(name: &str) -> Vec<(u64, Vec<u8>)> {
        let rows = curl_core::c_source::table("tests/tunit/tool1622.c", name, |c| panic!("{c}"));
        let rows: Vec<_> = rows
            .iter()
            .filter_map(|row| {
                let [n, out] = row.group() else {
                    panic!("{row:?}")
                };
                let out = out.bytes()?;
                Some((u64::try_from(n.int()).unwrap(), out.to_vec()))
            })
            .collect();
        assert!(rows.len() >= 6, "{name} was read");
        rows
    }

    /// Counts in five columns past what tool unit test 1622 asks:
    /// rounding at each unit, and the largest.
    #[test]
    fn counts_fit_five_columns() {
        for (n, s) in [
            (102_400, " 100k"),
            (10_240_000, " 9.7M"),
            (OFF_MAX, "8191P"),
        ] {
            assert_eq!(shown(Max5(n)), s, "{n}");
        }
    }

    /// A time of hours, minutes and seconds each, past tool unit test
    /// 1622's.
    #[test]
    fn times_fit_eight_columns() {
        assert_eq!(shown(time(3_661)), "01:01:01");
    }

    /// Counts in five columns, as `max5data`: tool unit test 1622's
    /// cases.
    #[test]
    fn tool1622_max5data() {
        for (n, want) in tool1622("datacases[]") {
            assert_eq!(shown(Max5(n)).as_bytes(), want, "{n}");
        }
    }

    /// Times in eight columns, blank for none, as `timebuf`: tool unit
    /// test 1622's cases.
    #[test]
    fn tool1622_timebuf() {
        for (n, want) in tool1622("timecases[]") {
            assert_eq!(shown(time(n)).as_bytes(), want, "{n}");
        }
    }

    /// Tool unit test 1622's widths: every count and time from 0 through
    /// 2^62 - 1, each one more than twice the last, and its byte counts,
    /// each as wide as its column.
    #[test]
    fn tool1622_widths() {
        let mut n: u64 = 0;
        for _ in 0..63 {
            assert_eq!(shown(time(n)).len(), 8, "{n}");
            assert_eq!(shown(Max5(n)).len(), 5, "{n}");
            n = n * 2 + 1;
        }
        let check =
            curl_core::c_source::table("tests/tunit/tool1622.c", "check[]", |c| panic!("{c}"));
        let check: Vec<u64> = check
            .iter()
            .map(|n| u64::try_from(n.int()).unwrap())
            .take_while(|&n| n != 0)
            .collect();
        assert_eq!(check.len(), 5, "the byte counts were read");
        for n in check {
            assert_eq!(shown(Max5(n)).len(), 5, "{n}");
        }
    }

    /// A percentage is three columns, cut as C's buffer cuts it.
    #[test]
    fn percentages_fit_three_columns() {
        assert_eq!(format!("{:<3}|", Percent(None)), "-- |");
        assert_eq!(format!("{:<3}|", Percent(Some(7))), "  7|");
        assert_eq!(format!("{:<3}|", Percent(Some(100))), "100|");
        assert_eq!(format!("{:<3}|", Percent(Some(12345))), "123|");
    }

    /// A transfer's numbers as its handler last told them.
    fn counted(downloaded: u64, download_total: u64, uploaded: u64, upload_total: u64) -> Counted {
        let c = Counted::new().unwrap();
        let g = &c.gauge;
        g.downloaded.store(downloaded, Ordering::Relaxed);
        g.download_total.store(download_total, Ordering::Relaxed);
        g.uploaded.store(uploaded, Ordering::Relaxed);
        g.upload_total.store(upload_total, Ordering::Relaxed);
        c
    }

    /// The progress an attempt of `c` tells.
    fn told(
        c: &Counted,
        downloaded: u64,
        download_total: Option<u64>,
        uploaded: u64,
        upload_total: Option<u64>,
    ) {
        c.gauge.told(ProgressNow {
            download_total,
            downloaded,
            upload_total,
            uploaded,
        });
    }

    /// The line `meter` draws of `list` at `line`.
    fn drawn(meter: &mut Meter, list: &mut [Counted], line: Line) -> String {
        let mut buf = [0u8; 128];
        let n = meter.line(&mut buf, list.iter(), line);
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    fn at(start: Instant, ms: u64, added: u64, live: u32, last: bool) -> Line {
        Line {
            start,
            now: start + Duration::from_millis(ms),
            added,
            live,
            last,
        }
    }

    /// The line drawn, its fields worked out as `progress_meter` works
    /// them out: a carriage return first, the percentages of the totals
    /// once every one is known, the speed since the start, the times from
    /// it, and at the end four blanks and a newline where the others end
    /// in five blanks.
    #[test]
    fn draws_lines_as_c_does() {
        let start = Instant::now();
        // Ended transfers' counts only: 13 bytes in 2 s is 6 a second,
        // 13 / 6 is 2 s in all, and none left.
        let mut meter = Meter::new();
        meter.downloaded = 13;
        meter.download_total = 13;
        assert_eq!(
            drawn(&mut meter, &mut [], at(start, 2000, 2, 0, true)),
            "\r100 --     13     0     2     0  00:00:02 00:00:02              6     \n"
        );
        assert_eq!(
            drawn(&mut meter, &mut [], at(start, 2000, 2, 1, false)),
            "\r100 --     13     0     2     1  00:00:02 00:00:02              6      "
        );
        // 50 of 200 down and 25 of 100 up in 1 s: 50 a second, 4 s in
        // all, 3 s left. The totals count once, however often drawn.
        let mut meter = Meter::new();
        let mut list = [counted(50, 200, 25, 100)];
        for _ in 0..2 {
            assert_eq!(
                drawn(&mut meter, &mut list, at(start, 1000, 1, 1, false)),
                "\r 25  25    50    25     1     1  00:00:04 00:00:01 00:00:03    50      "
            );
        }
        // A size not known leaves its percentage and the times blank.
        let mut meter = Meter::new();
        let mut list = [counted(50, 200, 0, 0), counted(10, 0, 0, 0)];
        assert_eq!(
            drawn(&mut meter, &mut list, at(start, 1000, 2, 2, false)),
            "\r--  --     60     0     2     2           00:00:01             60      "
        );
        // Nothing moved: no speed, and no times from it.
        let mut meter = Meter::new();
        let mut list = [counted(0, 200, 0, 0)];
        assert_eq!(
            drawn(&mut meter, &mut list, at(start, 1000, 1, 1, false)),
            "\r  0 --      0     0     1     1           00:00:01              0      "
        );
    }

    /// A transfer's counts and totals stay in those of the ended
    /// (`progress_finalize`).
    #[test]
    fn an_ended_transfer_stays_counted() {
        let start = Instant::now();
        let mut meter = Meter::new();
        meter.finalize(&counted(10, 10, 4, 4));
        meter.finalize(&counted(0, 0, 0, 0));
        assert_eq!(
            drawn(&mut meter, &mut [], at(start, 1000, 1, 0, false)),
            "\r100 100    10     4     1     0  00:00:01 00:00:01             10      "
        );
    }

    /// A transfer tried again counts once: its attempt's counts and sizes
    /// go, but for what a resumed attempt kept, which the next counts on
    /// from, and the speed starts over (`progress_reset_retry`; tests
    /// 3039 and 3040).
    #[test]
    fn a_transfer_tried_again_counts_once() {
        let start = Instant::now();
        let mut meter = Meter::new();
        let mut list = [counted(100, 100, 6, 6)];
        for k in 0..10 {
            drawn(&mut meter, &mut list, at(start, 1000 * k, 1, 1, false));
        }
        assert!(meter.wrapped);
        meter.reset_retry(&list[0], 0);
        assert_eq!((meter.speed_at, meter.wrapped), (0, false));
        assert_eq!(
            drawn(&mut meter, &mut list, at(start, 10_000, 2, 0, false)),
            "\r--  --      0     0     2     0           00:00:10              0      "
        );
        // The next attempt's progress: one transfer's sizes, not two;
        // the speed since the start, the draws before forgotten.
        told(&list[0], 100, Some(100), 6, Some(6));
        assert_eq!(
            drawn(&mut meter, &mut list, at(start, 11_000, 3, 1, false)),
            "\r100 100   100     6     3     1  00:00:11 00:00:11              9      "
        );
        meter.finalize(&list[0]);
        assert_eq!(
            drawn(&mut meter, &mut [], at(start, 12_000, 3, 0, true)),
            "\r100 100   100     6     3     0  00:00:12 00:00:12              8     \n"
        );
        // 40 bytes kept by a resumed attempt count in the next one's.
        let mut meter = Meter::new();
        let list = [counted(40, 0, 0, 0)];
        meter.reset_retry(&list[0], 40);
        told(&list[0], 10, Some(60), 0, None);
        let g = &list[0].gauge;
        assert_eq!(g.downloaded.load(Ordering::Relaxed), 50);
        assert_eq!(g.download_total.load(Ordering::Relaxed), 100);
        told(&list[0], 10, None, 0, None);
        assert_eq!(g.download_total.load(Ordering::Relaxed), 0, "not known");
    }

    /// Once ten lines are drawn, the speed is over the last ten
    /// (`speedstore`): 1000 bytes at 10 s, 10 at 1 s, is 110 a second.
    #[test]
    fn the_speed_is_over_the_last_ten_lines() {
        let start = Instant::now();
        for (download, speed) in [(true, "  110"), (false, "  220")] {
            let mut meter = Meter::new();
            let mut list = [counted(0, 0, 0, 0)];
            let mut last = String::new();
            for k in 0..=10u64 {
                let g = &list[0].gauge;
                if download {
                    g.downloaded.store(k * k * 10, Ordering::Relaxed);
                } else {
                    g.uploaded.store(k * k * 20, Ordering::Relaxed);
                }
                last = drawn(&mut meter, &mut list, at(start, k * 1000, 1, 1, false));
            }
            assert!(last.ends_with(&format!("{speed}      ")), "{last:?}");
        }
    }

    /// A count too large to multiply by 100 is divided first.
    #[test]
    fn percentages_of_large_counts() {
        assert_eq!(percent(true, 50, 200), Some(25));
        assert_eq!(percent(false, 50, 200), None);
        assert_eq!(percent(true, 50, 0), None);
        let large = OFF_MAX / 100;
        assert_eq!(percent(true, large, 250), Some(large / 2));
        assert_eq!(percent(true, large - 1, 250), Some((large - 1) * 100 / 250));
    }

    /// The header goes once; a line goes when half a second passed since
    /// the last, or when it is the last (`progress_meter`).
    #[test]
    fn draws_at_most_every_half_second() {
        let start = Instant::now();
        let mut meter = Meter::new();
        let mut out = Vec::new();
        let mut draw = |ms, last| {
            out.clear();
            meter.draw(&mut out, std::iter::empty(), at(start, ms, 0, 0, last));
            String::from_utf8(out.clone()).unwrap()
        };
        let first = draw(0, false);
        assert!(first.starts_with("DL% UL%  Dled"), "{first:?}");
        assert_eq!(first.matches('\r').count(), 1, "{first:?}");
        assert_eq!(draw(500, false), "");
        assert!(draw(501, false).starts_with('\r'));
        assert!(draw(502, true).ends_with('\n'));
    }

    /// A transfer tried again waits whole seconds: one second less than
    /// it may, as C counts from the second it is in.
    #[test]
    fn retries_wait_whole_seconds() {
        assert_eq!(start_at(100, Duration::from_millis(999)), 100);
        assert_eq!(start_at(100, Duration::from_millis(2500)), 102);
        assert!(waiting(101, 102));
        assert!(!waiting(102, 102));
        assert!(!waiting(103, 102));
    }
}
