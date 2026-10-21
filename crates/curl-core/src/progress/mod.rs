//! A transfer's progress (`lib/progress.c`): its speed, the low-speed
//! check, the progress handler and the meter.

mod meter;

#[cfg(test)]
#[rustfmt::skip]
mod c_tests;
#[cfg(test)]
mod tests;

use std::io::Write as _;
use std::time::Duration;

use crate::error::ErrorKind;
use crate::handler::{Handler, ProgressNow, ProgressVerdict, TextSink};
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};
use crate::options::{LowSpeed, Progress};
use crate::report::Speeds;
use crate::text::Text;
use crate::time::Instant;
use crate::trace;

/// How many speed records are kept: one a second, for five seconds
/// (`CURL_SPEED_RECORDS`).
const RECORDS: usize = 6;

const SECOND_US: u64 = 1_000_000;

/// How long the low-speed check waits between looks.
pub(crate) const SPEED_CHECK_EVERY: Duration = Duration::from_secs(1);

/// A transfer's recent speed (C's speed records, `current_speed`,
/// `lastshow_us` and `keeps_speed`).
#[derive(Debug)]
pub(crate) struct Speedometer {
    /// Bytes moved, and microseconds since the start, of each record.
    records: [(u64, u64); RECORDS],
    /// Records made since the last start over (C's `speeder_c`).
    made: u32,
    /// Bytes a second over the records kept.
    current: u64,
    /// When the progress was last shown, in microseconds since the
    /// start; `None` shows it at the next pass that takes stock.
    last_shown: Option<u64>,
    /// Since when the speed has stayed under the low-speed limit.
    slow_since: Option<Instant>,
}

impl Default for Speedometer {
    /// A transfer's, at its start (`Curl_pgrsStart`).
    fn default() -> Speedometer {
        Speedometer {
            records: [(0, 0); RECORDS],
            made: 0,
            current: 0,
            last_shown: Some(0),
            slow_since: None,
        }
    }
}

impl Speedometer {
    /// Measure from scratch, as after an unpause (`Curl_pgrsRecvPause`).
    pub(crate) fn start_over(&mut self) {
        self.made = 0;
        self.slow_since = None;
    }

    /// Forget how long the speed has been low (`keeps_speed`).
    pub(crate) fn forget_slow(&mut self) {
        self.slow_since = None;
    }

    /// Take stock `elapsed_us` after the start, with `moved` bytes moved:
    /// the averages into `speeds`, and the current speed of both
    /// directions together.
    /// Whether to show the progress: at the first pass, then once a second,
    /// and whenever the request is `done` (`progress_calc`).
    fn take_stock(
        &mut self,
        elapsed_us: u64,
        moved: Moved,
        done: bool,
        speeds: &mut Speeds,
    ) -> bool {
        speeds.download = per_second(moved.down, elapsed_us);
        speeds.upload = per_second(moved.up, elapsed_us);
        let amount = moved.down.saturating_add(moved.up);
        if self.made == 0 {
            self.records[0] = (amount, elapsed_us);
            self.made = 1;
            // The overall average, to start with.
            self.current = speeds.download.saturating_add(speeds.upload);
            self.last_shown = Some(elapsed_us);
            return true;
        }
        let next = self.made as usize % RECORDS;
        let mut latest = (next + RECORDS - 1) % RECORDS;
        // A record a second at most: more often ruins the history.
        if elapsed_us.saturating_sub(self.records[latest].1) >= SECOND_US {
            self.made = self.made.wrapping_add(1);
            latest = next;
            self.records[latest] = (amount, elapsed_us);
        } else if done {
            // Without a speed yet, the last record takes the end. With
            // one, it stays: the last piece of a rate-limited transfer
            // would read faster than it went.
            if self.current == 0 {
                self.records[latest] = (amount, elapsed_us);
            }
        } else {
            return false;
        }
        let oldest = oldest_record(self.made, latest);
        let (new, old) = (self.records[latest], self.records[oldest]);
        let duration = new.1.saturating_sub(old.1).max(1);
        self.current = per_second(new.0.saturating_sub(old.0), duration);
        if let Some(shown) = self.last_shown
            && !done
            && elapsed_us.saturating_sub(shown) < SECOND_US
        {
            return false;
        }
        self.last_shown = Some(elapsed_us);
        true
    }

    /// The low-speed check at `now` (`pgrs_speedcheck`): TimedOut once the
    /// speed has stayed under the limit for its whole time.
    fn speed_check(&mut self, low: LowSpeed, now: Instant) -> Result<(), ErrorKind> {
        if self.current >= low.limit.get() {
            self.slow_since = None;
            return Ok(());
        }
        match self.slow_since {
            None => self.slow_since = Some(now),
            Some(since) if now.since(since) >= Duration::from_secs(low.time.get().into()) => {
                return Err(ErrorKind::OperationTimedout);
            }
            Some(_) => {}
        }
        Ok(())
    }
}

/// Where the oldest record kept is, with `made` made and the latest at
/// `latest`: the first until the ring is full, then the one after the
/// latest.
fn oldest_record(made: u32, latest: usize) -> usize {
    if (made as usize) < RECORDS {
        0
    } else {
        (latest + 1) % RECORDS
    }
}

/// Bytes moved so far, each way.
#[derive(Clone, Copy, Debug)]
struct Moved {
    down: u64,
    up: u64,
}

/// `bytes` moved in `us` microseconds, a second (`trspeed`).
fn per_second(bytes: u64, us: u64) -> u64 {
    let per = u128::from(bytes) * u128::from(SECOND_US) / u128::from(us.max(1));
    u64::try_from(per).unwrap_or(u64::MAX)
}

/// Take stock of the transfer and tell the application, by its handler or
/// the meter (`Curl_pgrsUpdate`). A handler's abort is AbortedByCallback
/// ("Callback aborted").
pub(crate) fn update<H: Host>(cx: &mut StepCx<'_, H>, done: bool) -> Result<(), ErrorKind> {
    let now = cx.now();
    let report = cx.easy().report();
    let elapsed_us = report.timings().since_start_us(now);
    let sizes = *report.sizes();
    let moved = Moved {
        down: sizes.download(),
        up: sizes.upload(),
    };
    let (speedometer, report) = cx.progress_parts();
    report.timings_mut().completed(now);
    let show = speedometer.take_stock(elapsed_us, moved, done, report.speeds_mut());
    match cx.easy().options().progress.clone() {
        Progress::Off => return Ok(()),
        Progress::Meter => {}
        Progress::Handler(handler) => {
            let now = ProgressNow {
                download_total: sizes.download_expected(),
                downloaded: sizes.download(),
                upload_total: sizes.upload_expected(),
                uploaded: sizes.upload(),
            };
            match handler.progress(&mut TransferCx::new(cx), now) {
                ProgressVerdict::Continue => return Ok(()),
                ProgressVerdict::Abort => {
                    let why = format_args!("Callback aborted");
                    return Err(trace::fail(cx, ErrorKind::AbortedByCallback, why));
                }
                ProgressVerdict::ContinueWithMeter => {}
            }
        }
    }
    if show {
        draw(cx, elapsed_us);
    }
    Ok(())
}

/// Take stock, then check the speed unless the request is `done`
/// (`Curl_pgrsCheck`). While the low-speed limit applies and the
/// transfer is not paused, it looks again in a second.
pub(crate) fn check<H: Host>(
    cx: &mut StepCx<'_, H>,
    done: bool,
) -> Result<Option<Duration>, ErrorKind> {
    update(cx, done)?;
    let Some(low) = cx.easy().options().limits.low_speed else {
        return Ok(None);
    };
    // A paused transfer is not judged on its speed.
    if done || cx.pause().recv_paused() || cx.pause().send_paused() {
        return Ok(None);
    }
    let now = cx.now();
    if let Err(kind) = cx.speedometer_mut().speed_check(low, now) {
        let (limit, time) = (low.limit, low.time);
        return Err(trace::fail(
            cx,
            kind,
            format_args!(
                "Operation too slow. Less than {limit} bytes/sec transferred the last {time} seconds"
            ),
        ));
    }
    Ok(Some(SPEED_CHECK_EVERY))
}

/// The request is over, `done` or cut short: a last pass that shows the
/// progress whatever the time since the last showing, and the meter's
/// line ended (`Curl_pgrsDone`).
pub(crate) fn finish<H: Host>(cx: &mut StepCx<'_, H>, done: bool) -> Result<(), ErrorKind> {
    cx.speedometer_mut().last_shown = None;
    update(cx, done)?;
    if let Progress::Meter = cx.easy().options().progress {
        to_stderr(cx.easy().options().callbacks.stderr.as_ref(), b"\n");
    }
    Ok(())
}

/// Draw a line of the meter, its titles first the first time a handle
/// draws one (`progress_meter`).
fn draw<H: Host>(cx: &mut StepCx<'_, H>, elapsed_us: u64) {
    let current_speed = cx.speedometer_mut().current;
    let easy = cx.easy_mut();
    let first = !easy.meter_titled;
    easy.meter_titled = true;
    let report = easy.report();
    let reading = meter::Reading {
        spent_us: elapsed_us,
        download: meter::Dir {
            total: report.sizes().download_expected(),
            cur: report.sizes().download(),
            speed: report.speeds().download(),
        },
        upload: meter::Dir {
            total: report.sizes().upload_expected(),
            cur: report.sizes().upload(),
            speed: report.speeds().upload(),
        },
        current_speed,
    };
    let sink = easy.options().callbacks.stderr.as_ref();
    if first {
        to_stderr(sink, meter::HEADER.as_bytes());
    }
    let mut text = Text::<256>::new();
    meter::line(&reading, &mut text).expect("a meter line fits its buffer");
    to_stderr(sink, text.bytes());
}

/// Text for the user, to the handle's sink or the process's standard
/// error.
pub(crate) fn to_stderr(sink: Option<&Handler<dyn TextSink>>, text: &[u8]) {
    match sink {
        Some(sink) => sink.write(text),
        // As C's fprintf: a failed write to standard error has nowhere
        // else to be told.
        None => std::io::stderr().write_all(text).unwrap_or(()),
    }
}
