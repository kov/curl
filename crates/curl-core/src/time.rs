//! Time, as the engine sees it: instants read from a clock it is given.
//!
//! Nothing below the multi reads the time itself. A pass reads its clock
//! once and passes that `Instant` down, so under a `ManualClock` every
//! timeout is deterministic and a test takes no time to wait for one.

use std::num::NonZeroU64;
use std::time::Duration;

/// A point in time: microseconds since its clock's epoch. Instants from
/// different clocks are not comparable; each multi has one clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    /// The clock's epoch.
    pub const EPOCH: Instant = Instant(0);

    /// The time from `earlier` to this instant, or zero if `earlier` is
    /// later.
    pub fn since(self, earlier: Instant) -> Duration {
        Duration::from_micros(self.0.saturating_sub(earlier.0))
    }

    /// The instant `d` after this one, at most the latest representable.
    pub fn after(self, d: Duration) -> Instant {
        Instant(self.0.saturating_add(micros(d)))
    }
}

/// `d` in whole microseconds, saturating.
fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

/// A time limit: a whole number of milliseconds, never zero, which C's
/// options use to mean no limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeLimit(NonZeroU64);

impl TimeLimit {
    /// The limit of `ms` milliseconds, or none for zero.
    pub fn from_millis(ms: u64) -> Option<TimeLimit> {
        NonZeroU64::new(ms).map(TimeLimit)
    }

    pub fn duration(self) -> Duration {
        Duration::from_millis(self.0.get())
    }
}

/// Where a multi reads the time.
pub trait Clock {
    fn now(&self) -> Instant;

    /// The calendar time: whole seconds since 1970-01-01 00:00:00 UTC,
    /// negative before (`time(NULL)`). Read only where a date is compared
    /// with the present, never for a time limit.
    fn unix_time(&self) -> i64;
}

/// The system's monotonic clock, with its epoch when it was made.
#[derive(Debug)]
pub struct SystemClock {
    epoch: std::time::Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        SystemClock {
            epoch: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant(micros(self.epoch.elapsed()))
    }

    fn unix_time(&self) -> i64 {
        let secs = |d: Duration| i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(after) => secs(after),
            Err(before) => -secs(before.duration()),
        }
    }
}

/// A clock that moves only when told. Its clones share one time, so a test
/// keeps one and gives another to the multi.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Debug)]
pub struct ManualClock(curl_alloc::TryRc<ManualTime>);

#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct ManualTime {
    now: std::cell::Cell<Instant>,
    /// The calendar time at the clock's epoch.
    unix_epoch: std::cell::Cell<i64>,
}

#[cfg(any(test, feature = "test-util"))]
impl ManualClock {
    /// A clock at its epoch, which is 1970's.
    pub fn new() -> Result<Self, curl_alloc::OutOfMemory> {
        Ok(ManualClock(curl_alloc::TryRc::try_new(ManualTime {
            now: std::cell::Cell::new(Instant::EPOCH),
            unix_epoch: std::cell::Cell::new(0),
        })?))
    }

    /// Move the time `d` forward.
    pub fn advance(&self, d: Duration) {
        self.0.now.set(self.0.now.get().after(d));
    }

    /// Make the calendar time `secs` now; it moves with the clock.
    pub fn set_unix_time(&self, secs: i64) {
        self.0.unix_epoch.set(secs - self.elapsed_secs());
    }

    fn elapsed_secs(&self) -> i64 {
        i64::try_from(self.0.now.get().since(Instant::EPOCH).as_secs()).expect("u64 µs in i64 s")
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.0.now.get()
    }

    fn unix_time(&self) -> i64 {
        self.0.unix_epoch.get() + self.elapsed_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_saturate() {
        let t = Instant::EPOCH.after(Duration::from_millis(5));
        assert_eq!(t.since(Instant::EPOCH), Duration::from_millis(5));
        assert_eq!(Instant::EPOCH.since(t), Duration::ZERO);
        assert_eq!(t.after(Duration::MAX), Instant(u64::MAX));
        // Below a microsecond counts as nothing.
        assert_eq!(t.after(Duration::from_nanos(999)), t);
    }

    #[test]
    fn a_manual_clock_moves_when_told_for_every_clone() {
        let clock = ManualClock::new().unwrap();
        let given: Box<dyn Clock> = Box::new(clock.clone());
        assert_eq!(given.now(), Instant::EPOCH);
        clock.advance(Duration::from_secs(3));
        assert_eq!(given.now().since(Instant::EPOCH), Duration::from_secs(3));
    }

    #[test]
    fn the_system_clock_starts_at_its_epoch_and_does_not_go_back() {
        let clock = SystemClock::new();
        let a = clock.now();
        let b = clock.now();
        assert!(a.since(Instant::EPOCH) < Duration::from_secs(1) && b >= a);
    }
}
