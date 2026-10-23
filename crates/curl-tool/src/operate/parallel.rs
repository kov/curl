//! Running the transfers at once, one multi driving them
//! (`src/tool_operate.c`'s `parallel_transfers`), with the meter that
//! shows them all on one line (`src/tool_progress.c`).

use std::io::Write as _;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box, try_box_or_back};
use curl_core::conn::io::{SystemNet, Waker};
use curl_core::error::{ErrorKind, MultiErrorKind};
use curl_core::handler::{Handler, ProgressHandler, ProgressNow, ProgressVerdict};
use curl_core::id::ArenaPolicy;
use curl_core::multi::{Env, Multi, NoEvents, TransferCx, TransferId, WaitMode};
use curl_core::options::Progress;
use curl_core::time::SystemClock;

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
    // A waker, as every C multi has; without the descriptors for one, it
    // goes without.
    let waker = match Waker::new() {
        Ok(w) => Some(TryArc::try_new(w)?),
        Err(_) => None,
    };
    let env = Env {
        clock: try_box(SystemClock::new())?,
        net: try_box(SystemNet)?,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker,
    };
    let mut multi = Multi::new(env)?;
    multi.conn_limits_mut().max_host = line.global.parallel_host.map(NonZeroU32::from);
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
    /// Another transfer failed critically: this one stops.
    abort: AtomicBool,
}

/// The handler every parallel transfer has (`xferinfo_cb`): it keeps the
/// counts and draws nothing, so the library draws no meter of its own.
struct Gauged(TryArc<Gauge>);

impl ProgressHandler for Gauged {
    fn progress(&self, _: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict {
        let g = &self.0;
        // An unknown size counts as 0, as C's.
        g.downloaded.store(now.downloaded, Ordering::Relaxed);
        let total = now.download_total.unwrap_or(0);
        g.download_total.store(total, Ordering::Relaxed);
        g.uploaded.store(now.uploaded, Ordering::Relaxed);
        let total = now.upload_total.unwrap_or(0);
        g.upload_total.store(total, Ordering::Relaxed);
        if g.abort.load(Ordering::Relaxed) {
            ProgressVerdict::Abort
        } else {
            ProgressVerdict::Continue
        }
    }
}

/// Where a transfer's handle is.
#[expect(
    clippy::large_enum_variant,
    reason = "few are listed: transfers are made one ahead of those added"
)]
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
    gauge: TryArc<Gauge>,
    /// Its totals are in the meter's already (`dltotal_added`,
    /// `ultotal_added`).
    download_counted: bool,
    upload_counted: bool,
    /// Not added again before this second since the epoch, for a retry
    /// (`startat`).
    start_at: u64,
    /// It failed as it was made, and ends so at the end.
    unfinished: Option<Ended>,
}

impl Entry<'_, '_> {
    /// Added, or not to be (C's `added`, `skip`).
    fn passed(&self) -> bool {
        matches!(self.place, Place::Added(_)) || self.per.skip || self.unfinished.is_some()
    }
}

struct Parallel<'r, 'a, 'l> {
    run: &'r Shared<'r, 'l>,
    transfers: Transfers<'a, 'l>,
    /// Every transfer made and not ended, in the order made.
    list: Vec<Entry<'a, 'l>>,
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
            let (per, easy, unfinished) = match create(self.run, self.transfers.item()) {
                Made::Ready(per, easy) => (per, easy, None),
                Made::Unfinished(per, easy, ended) => (per, easy, Some(ended)),
                Made::Failed(e) => return Err(e),
            };
            self.terminal = per.terminal;
            let skip = per.skip;
            let entry = Entry {
                per,
                place: Place::Here(easy),
                gauge: TryArc::try_new(Gauge::default()).map_err(|_| ErrorKind::OutOfMemory)?,
                download_counted: false,
                upload_counted: false,
                start_at: 0,
                unfinished,
            };
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
        let mut at = 0;
        while at < self.list.len() && self.all_added < self.max {
            let entry = &mut self.list[at];
            at += 1;
            if entry.passed() {
                continue;
            }
            if now < entry.start_at {
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
            let gauged = Handler::progress(Gauged(entry.gauge.clone()))
                .map_err(|_| ErrorKind::OutOfMemory)?;
            Setopt::new(easy, None)
                .unwritten("C sets it with `curl_easy_setopt` as it adds", |o| {
                    o.progress = Progress::Handler(gauged);
                    Ok(())
                })
                .expect("setting a handler cannot fail");
            // The handle goes to the multi; what is left behind is a
            // handle of no options, whose drop saves nothing.
            let boxed = match try_box_or_back(std::mem::take(&mut **easy)) {
                Ok(boxed) => boxed,
                Err(taken) => {
                    **easy = taken;
                    return Err(ErrorKind::OutOfMemory);
                }
            };
            match self.multi.add(boxed, (), &mut NoEvents) {
                Ok(id) => entry.place = Place::Added(id),
                Err(refused) => {
                    **easy = *refused.easy;
                    return Err(ErrorKind::OutOfMemory);
                }
            }
            self.create_next()?;
            self.all_added += 1;
            added = true;
        }
        Ok((at < self.list.len() || sleeping, added))
    }
}

impl Parallel<'_, '_, '_> {
    /// Drive the multi until every transfer is done, or, after a critical
    /// failure or one with `--fail-early`, until those running stopped
    /// (`parallel_transfers`). The first failure.
    fn drive(&mut self) -> Ending {
        let (mut more, _) = self.add_more()?;
        if self.all_added == 0 {
            return Ok(());
        }
        let mut result = Ok(());
        let mut still_running = true;
        let (mut wrapitup, mut wrapped) = (false, false);
        let mut failed = None;
        let start = Instant::now();
        while still_running || more {
            if wrapitup {
                if !still_running {
                    break;
                }
                // Those running stop at their next progress.
                if !std::mem::replace(&mut wrapped, true) {
                    for entry in &self.list {
                        if matches!(entry.place, Place::Added(_)) {
                            entry.gauge.abort.store(true, Ordering::Relaxed);
                        }
                    }
                }
            } else if more {
                // C sets its result to what this adding comes to, which
                // forgets a failure before it (DIVERGENCE.md).
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
            let mut easy = Handle(*removed.easy);
            let entry = &mut self.list[at];
            let aborted = entry.gauge.abort.load(Ordering::Relaxed);
            let told = if aborted && ended == Err(ErrorKind::AbortedByCallback) {
                Told::As(ABORTED)
            } else {
                Told::Not
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
            self.meter.finalize(entry);
            self.all_added -= 1;
            checked = true;
            match again {
                Again::After(wait) => {
                    // In whole seconds.
                    let secs = u64::try_from(wait.as_millis() / 1000).unwrap_or(u64::MAX);
                    entry.start_at = unix_now().saturating_add(secs);
                    entry.place = Place::Here(easy);
                }
                Again::No(settled) => {
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
            let easy = match entry.place {
                Place::Here(easy) => easy,
                Place::Added(id) => Handle(
                    *self
                        .multi
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
        let counts = self.multi.counts();
        let live = counts.running - self.multi.pending();
        self.meter
            .draw(&mut self.list, start, counts.added_ever, live, last);
    }
}

/// The meter of all the transfers (`progress_meter`'s statics).
struct Meter {
    header: bool,
    stamp: Option<Instant>,
    /// What transfers ended or tried again got (`all_dlalready`,
    /// `all_ulalready`), and the totals counted (`all_dltotal`,
    /// `all_ultotal`).
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

    /// Count a transfer's numbers before it goes, or is tried again
    /// (`progress_finalize`).
    fn finalize(&mut self, entry: &mut Entry<'_, '_>) {
        let g = &entry.gauge;
        add_off(&mut self.downloaded, g.downloaded.load(Ordering::Relaxed));
        add_off(&mut self.uploaded, g.uploaded.load(Ordering::Relaxed));
        if !std::mem::replace(&mut entry.download_counted, true) {
            add_off(
                &mut self.download_total,
                g.download_total.load(Ordering::Relaxed),
            );
        }
        if !std::mem::replace(&mut entry.upload_counted, true) {
            add_off(
                &mut self.upload_total,
                g.upload_total.load(Ordering::Relaxed),
            );
        }
    }

    /// The header once, then a line if half a second passed since the
    /// last or this is the `last`: `added` transfers so far, `live` of
    /// them running.
    fn draw(
        &mut self,
        list: &mut [Entry<'_, '_>],
        start: Instant,
        added: u64,
        live: u32,
        last: bool,
    ) {
        let now = Instant::now();
        let mut err = std::io::stderr().lock();
        // Nowhere to report a failed write, as in C.
        if !std::mem::replace(&mut self.header, true) {
            let _ = err
                .write_all(b"DL% UL%  Dled  Uled  Xfers  Live Total     Current  Left    Speed\n");
        }
        let due = self
            .stamp
            .is_none_or(|at| now.duration_since(at) > Duration::from_millis(500));
        if !(last || due) {
            return;
        }
        self.stamp = Some(now);
        let mut line = [0u8; 128];
        let len = self.line(&mut line, list, start, now, added, live, last);
        let _ = err.write_all(&line[..len]);
    }

    /// The line as C prints it, into `buf`; its length.
    #[expect(clippy::too_many_arguments, reason = "the line's every field")]
    fn line(
        &mut self,
        buf: &mut [u8],
        list: &mut [Entry<'_, '_>],
        start: Instant,
        now: Instant,
        added: u64,
        live: u32,
        last: bool,
    ) -> usize {
        let spent = now.duration_since(start).as_secs();
        let (mut dlnow, mut ulnow) = (0, 0);
        add_off(&mut dlnow, self.downloaded);
        add_off(&mut ulnow, self.uploaded);
        let (mut dlknown, mut ulknown) = (true, true);
        for entry in list.iter_mut() {
            let g = &entry.gauge;
            add_off(&mut dlnow, g.downloaded.load(Ordering::Relaxed));
            add_off(&mut ulnow, g.uploaded.load(Ordering::Relaxed));
            let total = g.download_total.load(Ordering::Relaxed);
            if total == 0 {
                dlknown = false;
            } else if !std::mem::replace(&mut entry.download_counted, true) {
                add_off(&mut self.download_total, total);
            }
            let total = g.upload_total.load(Ordering::Relaxed);
            if total == 0 {
                ulknown = false;
            } else if !std::mem::replace(&mut entry.upload_counted, true) {
                add_off(&mut self.upload_total, total);
            }
        }
        let percent = |known: bool, now: u64, total: u64| {
            (known && total > 0).then(|| {
                if now < OFF_MAX / 100 {
                    now * 100 / total
                } else {
                    now / (total / 100)
                }
            })
        };
        let dlpercent = percent(dlknown, dlnow, self.download_total);
        let ulpercent = percent(ulknown, ulnow, self.upload_total);
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
            let total = self.download_total;
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

    /// Counts in five columns, as `max5data`: C's unit test 1622's
    /// cases, and the largest.
    #[test]
    fn counts_fit_five_columns() {
        for (n, s) in [
            (0, "    0"),
            (99_999, "99999"),
            (100_000, "97.6k"),
            (131_072, " 128k"),
            (12_645_826, "12.0M"),
            (1_099_445_657_078_333, " 999T"),
            (OFF_MAX, "8191P"),
        ] {
            assert_eq!(shown(Max5(n)), s, "{n}");
        }
    }

    /// Times in eight columns, blank for none, as `timebuf`: C's unit
    /// test 1622's cases.
    #[test]
    fn times_fit_eight_columns() {
        for (n, s) in [
            (0, "        "),
            (1, "00:00:01"),
            (524_287, "  6d 01h"),
            (134_217_727, " 51m 23d"),
            (4_294_967_295, "    136y"),
            (4_398_046_511_103, " >99999y"),
        ] {
            assert_eq!(shown(time(n)), s, "{n}");
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

    /// The line drawn: a carriage return first, and the last ends in four
    /// blanks and a newline where the others end in five blanks.
    #[test]
    fn draws_lines_as_c_does() {
        let mut meter = Meter::new();
        meter.downloaded = 13;
        meter.download_total = 13;
        let now = Instant::now();
        let start = now - Duration::from_secs(2);
        let mut buf = [0u8; 128];
        let n = meter.line(&mut buf, &mut [], start, now, 2, 0, true);
        assert_eq!(
            std::str::from_utf8(&buf[..n]).unwrap(),
            "\r100 --     13     0     2     0  00:00:02 00:00:02              6     \n"
        );
        let n = meter.line(&mut buf, &mut [], start, now, 2, 1, false);
        assert!(
            std::str::from_utf8(&buf[..n])
                .unwrap()
                .ends_with("     1  00:00:02 00:00:02              6      "),
            "{:?}",
            std::str::from_utf8(&buf[..n])
        );
    }
}
