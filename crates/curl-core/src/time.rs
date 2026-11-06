//! Time, as the engine sees it: instants read from the system's monotonic
//! clock, or under `test-util` from a clock the test gives.
//!
//! Nothing below the multi reads the time itself. The drive reads its
//! clock before each step and passes that `Instant` down, so under a
//! `ManualClock` every timeout is deterministic and a test takes no time
//! to wait for one.

use std::num::NonZeroU64;
use std::time::Duration;

/// A point in time: microseconds since its clock's epoch, plus one, so
/// that `Option<Instant>` takes no more room than an instant. Every
/// instant is the system clock's, but in a test given a clock of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(NonZeroU64);

impl Instant {
    /// The clock's epoch.
    pub const EPOCH: Instant = Instant(NonZeroU64::MIN);

    /// The time from `earlier` to this instant, or zero if `earlier` is
    /// later.
    pub fn since(self, earlier: Instant) -> Duration {
        Duration::from_micros(self.0.get().saturating_sub(earlier.0.get()))
    }

    /// The milliseconds from `earlier` to this instant, negative if
    /// `earlier` is later, counted as C counts them (`curlx_timediff_ms`):
    /// the whole seconds between their readings in thousands, plus the
    /// difference of their microseconds divided towards zero. That is one
    /// more than the whole milliseconds between them when this instant's
    /// microseconds into its second are fewer than `earlier`'s (and not by
    /// whole milliseconds).
    pub fn ms_since(self, earlier: Instant) -> i64 {
        // The reading C's `curltime` holds: the clock's seconds, and the
        // microseconds into the second.
        let split = |t: Instant| {
            let us = t.0.get() - Instant::EPOCH.0.get();
            let secs = i64::try_from(us / 1_000_000).expect("u64 µs in i64 s");
            let micros = i64::try_from(us % 1_000_000).expect("under a second");
            (secs, micros)
        };
        let ((s1, u1), (s0, u0)) = (split(self), split(earlier));
        (s1 - s0) * 1000 + (u1 - u0) / 1000
    }

    /// The instant `d` after this one, at most the latest representable.
    pub fn after(self, d: Duration) -> Instant {
        Instant(self.0.saturating_add(micros(d)))
    }
}

/// `d` in whole milliseconds, saturating: a limit to hold an
/// [`Instant::ms_since`] against.
pub fn millis(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
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

/// Where a multi reads the time, for the tests that give it one
/// (`multi::Env::clock`). A normal build has no clock to choose: every
/// multi and share reads the system's, as C reads the OS's monotonic
/// clock (`curlx_now`).
#[cfg(any(test, feature = "test-util"))]
pub trait Clock: Send {
    fn now(&self) -> Instant;

    /// The calendar time: whole seconds since 1970-01-01 00:00:00 UTC,
    /// negative before (`time(NULL)`). Read only where a date is compared
    /// with the present, never for a time limit.
    fn unix_time(&self) -> i64;

    /// Which time it reads: two clocks of one identity read one time, as
    /// the clones of a `ManualClock` do, and every `SystemClock`. A
    /// share's users must read one ([`ClockId`]).
    fn identity(&self) -> ClockId;
}

/// Which time a clock reads (`Clock::identity`).
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockId(usize);

#[cfg(any(test, feature = "test-util"))]
impl ClockId {
    /// The system's time, which every `SystemClock` reads.
    pub const SYSTEM: ClockId = ClockId(0);

    /// The time of whatever `at` points to, which no two live values
    /// share: a clock's own, or the state its clones share.
    pub fn of<T: ?Sized>(at: &T) -> ClockId {
        ClockId((at as *const T).cast::<()>() as usize)
    }
}

/// A multi's clock, held once and shared: the multi reads it, and so does
/// each QUIC connection it makes, which keeps reading the clock it was
/// made under wherever it is used later. The time a connection hands its
/// library never comes from another clock, so it never runs back. In a
/// normal build it is the system's, and takes no room.
#[cfg(not(any(test, feature = "test-util")))]
#[derive(Clone, Debug)]
pub(crate) struct SharedClock;

#[cfg(not(any(test, feature = "test-util")))]
impl SharedClock {
    /// The system's clock.
    pub(crate) fn system() -> Self {
        SharedClock
    }

    pub(crate) fn now(&self) -> Instant {
        SystemClock::new().now()
    }

    pub(crate) fn unix_time(&self) -> i64 {
        SystemClock::new().unix_time()
    }
}

/// A multi's clock, held once and shared (as in a normal build): the
/// system's, or the one a test gave the multi.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone)]
pub(crate) enum SharedClock {
    System,
    Given(curl_alloc::TryArc<std::sync::Mutex<Box<dyn Clock>>>),
}

#[cfg(any(test, feature = "test-util"))]
impl SharedClock {
    /// `clock`, held once; the system's needs no holding.
    pub(crate) fn new(clock: Box<dyn Clock>) -> Result<Self, curl_alloc::OutOfMemory> {
        if clock.identity() == ClockId::SYSTEM {
            return Ok(SharedClock::System);
        }
        // A test's clock: the library accounts for holding it, not for the
        // lock std makes.
        Ok(SharedClock::Given(curl_alloc::TryArc::try_new(
            curl_alloc::track::untracked_mutex(clock),
        )?))
    }

    fn get(given: &std::sync::Mutex<Box<dyn Clock>>) -> std::sync::MutexGuard<'_, Box<dyn Clock>> {
        given.lock().expect("no reading of a clock panics")
    }

    pub(crate) fn now(&self) -> Instant {
        match self {
            SharedClock::System => SystemClock::new().now(),
            SharedClock::Given(given) => Self::get(given).now(),
        }
    }

    pub(crate) fn unix_time(&self) -> i64 {
        match self {
            SharedClock::System => SystemClock::new().unix_time(),
            SharedClock::Given(given) => Self::get(given).unix_time(),
        }
    }

    pub(crate) fn identity(&self) -> ClockId {
        match self {
            SharedClock::System => ClockId::SYSTEM,
            SharedClock::Given(given) => Self::get(given).identity(),
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clock for SharedClock {
    fn now(&self) -> Instant {
        SharedClock::now(self)
    }

    fn unix_time(&self) -> i64 {
        SharedClock::unix_time(self)
    }

    fn identity(&self) -> ClockId {
        SharedClock::identity(self)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl std::fmt::Debug for SharedClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedClock")
    }
}

// The system's clock is the tests' to give a multi; a normal build reads
// it with nothing to give.
#[cfg(any(test, feature = "test-util"))]
pub use system::SystemClock;
#[cfg(not(any(test, feature = "test-util")))]
pub(crate) use system::SystemClock;

mod system {
    use std::time::Duration;

    use super::Instant;

    /// The system's monotonic clock (C's `curlx_now`), and its calendar
    /// time (`time(NULL)`).
    #[derive(Debug)]
    pub struct SystemClock(());

    impl Default for SystemClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SystemClock {
        pub fn new() -> Self {
            SystemClock(())
        }

        pub fn now(&self) -> Instant {
            Instant::EPOCH.after(curl_os::time::monotonic())
        }

        pub fn unix_time(&self) -> i64 {
            let secs = |d: Duration| i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(after) => secs(after),
                Err(before) => -secs(before.duration()),
            }
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    impl super::Clock for SystemClock {
        fn now(&self) -> Instant {
            SystemClock::now(self)
        }

        fn unix_time(&self) -> i64 {
            SystemClock::unix_time(self)
        }

        fn identity(&self) -> super::ClockId {
            super::ClockId::SYSTEM
        }
    }
}

/// A clock that moves only when told. Its clones share one time, so a test
/// keeps one and gives another to the multi.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Debug)]
pub struct ManualClock(curl_alloc::TryArc<ManualTime>);

#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct ManualTime {
    /// Now, and the calendar time at the clock's epoch.
    at: std::sync::Mutex<(Instant, i64)>,
}

#[cfg(any(test, feature = "test-util"))]
impl ManualClock {
    /// A clock at its epoch, which is 1970's.
    pub fn new() -> Result<Self, curl_alloc::OutOfMemory> {
        Ok(ManualClock(curl_alloc::TryArc::try_new(ManualTime {
            at: curl_alloc::track::untracked_mutex((Instant::EPOCH, 0)),
        })?))
    }

    fn at(&self) -> std::sync::MutexGuard<'_, (Instant, i64)> {
        self.0.at.lock().expect("no test panics holding the clock")
    }

    /// Move the time `d` forward.
    pub fn advance(&self, d: Duration) {
        let mut at = self.at();
        at.0 = at.0.after(d);
    }

    /// Make the calendar time `secs` now; it moves with the clock.
    pub fn set_unix_time(&self, secs: i64) {
        let elapsed = self.elapsed_secs();
        self.at().1 = secs - elapsed;
    }

    fn elapsed_secs(&self) -> i64 {
        i64::try_from(self.at().0.since(Instant::EPOCH).as_secs()).expect("u64 µs in i64 s")
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.at().0
    }

    fn unix_time(&self) -> i64 {
        let epoch = self.at().1;
        epoch + self.elapsed_secs()
    }

    fn identity(&self) -> ClockId {
        ClockId::of(&*self.0)
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
        assert_eq!(t.after(Duration::MAX), Instant(NonZeroU64::MAX));
        assert_eq!(size_of::<Option<Instant>>(), size_of::<Instant>());
        // Below a microsecond counts as nothing.
        assert_eq!(t.after(Duration::from_nanos(999)), t);
    }

    /// unit1323's `curlx_timediff_ms` table: 12.419 ms across a second's
    /// turn counts as 13, either way round.
    #[test]
    fn unit1323_ms_since() {
        let at = |secs: u64, micros: u32| Instant::EPOCH.after(Duration::new(secs, micros * 1000));
        for (first, second, ms) in [
            (at(36762, 8345), at(36761, 995_926), 13),
            (at(36761, 995_926), at(36762, 8345), -13),
            (at(36761, 995_926), at(0, 0), 36_761_995),
            (at(0, 0), at(36761, 995_926), -36_761_995),
        ] {
            assert_eq!(first.ms_since(second), ms, "{first:?} {second:?}");
        }
        // Within a second, and across one with the later microseconds
        // more: whole milliseconds, as `since` counts them.
        assert_eq!(at(5, 900_999).ms_since(at(5, 100_000)), 800);
        assert_eq!(at(6, 100_999).ms_since(at(5, 100_000)), 1000);
    }

    #[test]
    fn a_manual_clock_moves_when_told_for_every_clone() {
        let clock = ManualClock::new().unwrap();
        let given: Box<dyn Clock> = Box::new(clock.clone());
        assert_eq!(given.now(), Instant::EPOCH);
        clock.advance(Duration::from_secs(3));
        assert_eq!(given.now().since(Instant::EPOCH), Duration::from_secs(3));
    }

    /// The system clock's calendar time is the system's, in seconds since
    /// 1970 (`time(NULL)`).
    #[test]
    fn the_system_clock_tells_the_calendar_time() {
        let told = SystemClock::new().unix_time();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let now = i64::try_from(now).unwrap();
        assert!((now - 1..=now).contains(&told), "{told} for {now}");
    }

    /// A manual clock's clones are one clock, another manual clock is
    /// not, and every system clock is the system's.
    #[test]
    fn a_clock_s_identity_is_the_time_it_reads() {
        let clock = ManualClock::new().unwrap();
        let other = ManualClock::new().unwrap();
        assert_eq!(clock.identity(), clock.clone().identity());
        assert_ne!(clock.identity(), other.identity());
        assert_ne!(clock.identity(), ClockId::SYSTEM);
        assert_eq!(Clock::identity(&SystemClock::new()), ClockId::SYSTEM);
        let held = SharedClock::new(Box::new(clock.clone())).unwrap();
        assert_eq!(held.identity(), clock.identity());
        // The system's is not held at all.
        let system = SharedClock::new(Box::new(SystemClock::new())).unwrap();
        assert!(matches!(system, SharedClock::System));
    }

    #[test]
    fn system_clocks_made_apart_read_one_time() {
        let early = SystemClock::new();
        std::thread::sleep(Duration::from_millis(5));
        let late = SystemClock::new();
        let a = early.now();
        let b = late.now();
        let c = early.now();
        assert!(a <= b && b <= c, "{a:?} {b:?} {c:?}");
    }
}
