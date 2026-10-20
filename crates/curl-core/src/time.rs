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
}

/// A clock that moves only when told. Its clones share one time, so a test
/// keeps one and gives another to the multi.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Debug)]
pub struct ManualClock(curl_alloc::TryRc<std::cell::Cell<Instant>>);

#[cfg(any(test, feature = "test-util"))]
impl ManualClock {
    /// A clock at its epoch.
    pub fn new() -> Result<Self, curl_alloc::OutOfMemory> {
        Ok(ManualClock(curl_alloc::TryRc::try_new(
            std::cell::Cell::new(Instant::EPOCH),
        )?))
    }

    /// Move the time `d` forward.
    pub fn advance(&self, d: Duration) {
        self.0.set(self.0.get().after(d));
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.0.get()
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
