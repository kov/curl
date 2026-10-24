//! When each transfer must next run, and what the application is told
//! about it: the expire timers of `lib/multi.c` and the timer tree of
//! `lib/splay.c`.
//!
//! `Deadlines` is the only owner of a transfer's time limits. Its timers
//! decide when the transfer wakes; its two anchors decide whether it is
//! late. `TimerQueue` orders the transfers by their next wake-up and is
//! never asked whether one is late. `TimerAnnounce` decides when the
//! application's timer callback hears of a change.

use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec};

use crate::id::Key;
use crate::report::Starts;
use crate::time::{Instant, TimeLimit};

/// The longest wait a timer is armed for, or announced: C caps both at
/// `INT_MAX` milliseconds, about 24.8 days.
const MAX_WAIT: Duration = Duration::from_millis(i32::MAX as u64);

/// How long a connection may take when no limit is set
/// (`DEFAULT_CONNECT_TIMEOUT`).
const DEFAULT_CONNECT: Duration = Duration::from_secs(300);

/// A reason for a transfer to wake, each armed at most once at a time
/// (C's `expire_id`). The protocols' own timers join as they arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimerKind {
    /// The whole transfer's limit, armed at each leg's start.
    Total,
    /// The connection's limit, armed at each leg's start when set.
    Connect,
    /// The low-speed check's next look (`EXPIRE_SPEEDCHECK`).
    SpeedCheck,
    /// The next connect attempt is due (`EXPIRE_HAPPY_EYEBALLS`).
    Eyeballs,
    /// The protocol's own wait, which its state says
    /// (`ProtoState::wake_at`): HTTP's for a 100 (`EXPIRE_100_TIMEOUT`).
    Proto,
    /// A speed limit's wait, or its next tokens (`EXPIRE_TOOFAST`).
    TooFast,
    /// The HTTPS connect's wait before a second attempt, armed as its
    /// race starts while the attempts are not all known
    /// (`EXPIRE_ALPN_EYEBALLS`).
    AlpnEyeballs,
}

impl TimerKind {
    const COUNT: usize = 7;

    /// The name C's trace gives it (`Curl_trc_timer_name`). The
    /// protocol's own wait is HTTP's for a 100, the only one there is.
    pub(crate) fn name(self) -> &'static str {
        match self {
            TimerKind::Total => "TIMEOUT",
            TimerKind::Connect => "CONNECTTIMEOUT",
            TimerKind::SpeedCheck => "SPEEDCHECK",
            TimerKind::Eyeballs => "HAPPY_EYEBALLS",
            TimerKind::Proto => "100_TIMEOUT",
            TimerKind::TooFast => "TOOFAST",
            TimerKind::AlpnEyeballs => "ALPN_EYEBALLS",
        }
    }

    /// Every kind, in the order C's `expire_id` has them, which breaks a
    /// tie between two timers due at once.
    const ALL: [TimerKind; TimerKind::COUNT] = [
        TimerKind::Total,
        TimerKind::Connect,
        TimerKind::SpeedCheck,
        TimerKind::Eyeballs,
        TimerKind::Proto,
        TimerKind::TooFast,
        TimerKind::AlpnEyeballs,
    ];

    fn slot(self) -> usize {
        self as usize
    }

    fn bit(self) -> u8 {
        1 << self.slot()
    }
}

/// Where a transfer is, as far as its limits care: still connecting
/// (before C's `MSTATE_DO`) or past it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Connecting,
    Transferring,
}

/// What is left of a transfer's time (`timeleft_now_ms`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimeLeft {
    /// No limit applies.
    Unlimited,
    /// This much, in whole milliseconds, at least one.
    Remaining(Duration),
    /// The limit has passed by this much, in whole milliseconds. As in C,
    /// a limit reached exactly counts as passed by one.
    Expired(Duration),
}

/// A transfer's time limits and armed timers. The instants the limits are
/// judged from are the report's (`Starts`).
#[derive(Debug)]
pub(crate) struct Deadlines {
    total: Option<TimeLimit>,
    connect: Option<TimeLimit>,
    /// When each timer fires, if its bit is in `set`. A timer stays
    /// armed until an expiry pass at or after its instant, even once it
    /// is in the past. Kept apart from the bits, as every transfer's slot
    /// holds them.
    at: [Instant; TimerKind::COUNT],
    set: u8,
}

impl Deadlines {
    /// A transfer's limits, no timer armed.
    pub(crate) fn new(total: Option<TimeLimit>, connect: Option<TimeLimit>) -> Self {
        Deadlines {
            total,
            connect,
            at: [Instant::EPOCH; TimerKind::COUNT],
            set: 0,
        }
    }

    /// A new leg starts at `now` (C's SETUP state): both limits are armed
    /// from it. The total limit is still judged from the transfer's start,
    /// so it wakes the transfer later than it is due; C does the same.
    /// Returns the timers armed, and when each fires, in the order C
    /// arms them (`multistate_setup`).
    pub(crate) fn start_leg(&mut self, now: Instant) -> [Option<(TimerKind, Instant)>; 2] {
        let total = self.total.map(|total| {
            (
                TimerKind::Total,
                self.arm_in(TimerKind::Total, now, total.duration()),
            )
        });
        let connect = self.connect.map(|connect| {
            let at = self.arm_in(TimerKind::Connect, now, connect.duration());
            (TimerKind::Connect, at)
        });
        [total, connect]
    }

    /// Arm `kind` to fire `wait` after `now`, replacing its last arming.
    /// Returns when it fires.
    pub(crate) fn arm_in(&mut self, kind: TimerKind, now: Instant, wait: Duration) -> Instant {
        // C counts in whole milliseconds.
        let ms =
            Duration::from_millis(u64::try_from(wait.min(MAX_WAIT).as_millis()).expect("capped"));
        let at = now.after(ms);
        self.at[kind.slot()] = at;
        self.set |= kind.bit();
        at
    }

    /// When `kind` fires, if armed.
    fn armed(&self, kind: TimerKind) -> Option<Instant> {
        (self.set & kind.bit() != 0).then(|| self.at[kind.slot()])
    }

    /// Whether any timer is armed.
    pub(crate) fn any(&self) -> bool {
        self.set != 0
    }

    /// The timer that fires first, the earliest armed of a tie
    /// (`timeouts.first`).
    pub(crate) fn first(&self) -> Option<TimerKind> {
        TimerKind::ALL
            .into_iter()
            .filter_map(|k| self.armed(k).map(|at| (at, k)))
            .min_by_key(|&(at, _)| at)
            .map(|(_, k)| k)
    }

    /// The armed timers, the first to fire first, a tie in `first`'s
    /// order (`timeouts.first` and its list), with when each fires.
    pub(crate) fn in_order(&self) -> impl Iterator<Item = (Instant, TimerKind)> + Clone + use<> {
        let mut all = TimerKind::ALL.map(|k| self.armed(k).map(|at| (at, k)));
        all.sort_unstable_by_key(|armed| armed.map(|(at, k)| (at, k.slot())));
        all.into_iter().flatten()
    }

    pub(crate) fn clear(&mut self, kind: TimerKind) {
        self.set &= !kind.bit();
    }

    pub(crate) fn clear_all(&mut self) {
        self.set = 0;
    }

    /// The earliest armed timer, past or not.
    pub(crate) fn wake_at(&self) -> Option<Instant> {
        TimerKind::ALL
            .into_iter()
            .filter_map(|k| self.armed(k))
            .min()
    }

    /// An expiry pass at `now` found this transfer due: every timer due by
    /// then has fired (`add_next_timeout`). Only for a transfer the queue
    /// just gave out; a transfer run for another reason keeps its past
    /// timers, which still wake it.
    pub(crate) fn expire(&mut self, now: Instant) {
        for k in TimerKind::ALL {
            if self.armed(k).is_some_and(|at| at <= now) {
                self.clear(k);
            }
        }
    }

    /// What is left at `now` of the time of a transfer that started at
    /// `starts` (`timeleft_now_ms`).
    pub(crate) fn time_left(&self, starts: Starts, now: Instant, phase: Phase) -> TimeLeft {
        // C's arithmetic, in signed milliseconds where 0 means no limit.
        let left = |limit: Duration, anchor: Instant| -> i64 {
            let limit = i64::try_from(limit.as_millis()).unwrap_or(i64::MAX);
            let since = i64::try_from(now.since(anchor).as_millis()).unwrap_or(i64::MAX);
            match limit.saturating_sub(since) {
                0 => -1,
                l => l,
            }
        };
        let connect = match phase {
            Phase::Connecting => left(
                self.connect.map_or(DEFAULT_CONNECT, TimeLimit::duration),
                starts.single,
            ),
            Phase::Transferring => 0,
        };
        let total = self.total.map_or(0, |t| left(t.duration(), starts.op));
        let ms = match (connect, total) {
            (0, t) => t,
            (c, 0) => c,
            (c, t) => c.min(t),
        };
        match ms {
            0 => TimeLeft::Unlimited,
            1.. => TimeLeft::Remaining(Duration::from_millis(ms.unsigned_abs())),
            _ => TimeLeft::Expired(Duration::from_millis(ms.unsigned_abs())),
        }
    }
}

/// One transfer waiting in the queue.
#[derive(Debug)]
struct Entry<T> {
    at: Instant,
    /// Insertion order: of transfers due at the same instant, the one
    /// queued first comes out first, as from C's tree.
    seq: u64,
    key: Key<T>,
}

impl<T> Entry<T> {
    fn before(&self, other: &Entry<T>) -> bool {
        (self.at, self.seq) < (other.at, other.seq)
    }
}

/// The transfers with an armed timer, by their next wake-up: a binary
/// min-heap with each transfer's position indexed by its key's row.
#[derive(Debug)]
pub(crate) struct TimerQueue<T> {
    heap: Vec<Entry<T>>,
    /// The heap position of the transfer in each row, if queued.
    position: Vec<Option<usize>>,
    next_seq: u64,
}

impl<T> TimerQueue<T> {
    pub(crate) fn new() -> Self {
        TimerQueue {
            heap: Vec::new(),
            position: Vec::new(),
            next_seq: 0,
        }
    }

    /// Make room for keys with rows below `rows`, so updating them never
    /// allocates. Called when a transfer is added.
    pub(crate) fn reserve(&mut self, rows: u32) -> Result<(), OutOfMemory> {
        let rows = rows as usize;
        if self.position.len() < rows {
            self.position
                .try_reserve(rows - self.position.len())
                .map_err(|_| OutOfMemory)?;
            while self.position.len() < rows {
                self.position.try_push(None)?;
            }
        }
        // At most one entry per row.
        if self.heap.capacity() < rows {
            self.heap
                .try_reserve(rows - self.heap.len())
                .map_err(|_| OutOfMemory)?;
        }
        Ok(())
    }

    /// Queue `key` to wake at `at`, or take it out with `None`. A
    /// transfer whose wake-up is unchanged keeps its place among those
    /// due at the same instant; a changed one goes behind them.
    pub(crate) fn update(&mut self, key: Key<T>, at: Option<Instant>) {
        let row = row_of(key);
        let queued = self.position.get(row).copied().flatten();
        if let Some(i) = queued {
            assert_eq!(self.heap[i].key, key, "a stale key in the timer queue");
            if Some(self.heap[i].at) == at {
                return;
            }
            self.take(i);
        }
        if let Some(at) = at {
            assert!(
                row < self.position.len(),
                "a timer for a key never reserved"
            );
            assert!(
                self.heap.len() < self.heap.capacity(),
                "timer queue capacity is reserved at add"
            );
            let seq = self.next_seq;
            self.next_seq += 1;
            self.heap
                .try_push(Entry { at, seq, key })
                .expect("within the reserved capacity");
            let last = self.heap.len() - 1;
            self.position[row] = Some(last);
            self.sift_up(last);
        }
    }

    /// Take `key` out; whether it was queued.
    pub(crate) fn remove(&mut self, key: Key<T>) -> bool {
        let queued = self.contains(key);
        self.update(key, None);
        queued
    }

    /// When `key` is queued to wake.
    #[cfg(any(test, debug_assertions))]
    pub(crate) fn wake_of(&self, key: Key<T>) -> Option<Instant> {
        let i = self.position.get(row_of(key)).copied().flatten()?;
        (self.heap[i].key == key).then_some(self.heap[i].at)
    }

    #[cfg(any(test, debug_assertions))]
    pub(crate) fn len(&self) -> usize {
        self.heap.len()
    }

    pub(crate) fn contains(&self, key: Key<T>) -> bool {
        self.position
            .get(row_of(key))
            .copied()
            .flatten()
            .is_some_and(|i| self.heap[i].key == key)
    }

    /// The next transfer to wake, and when.
    pub(crate) fn peek(&self) -> Option<(Instant, Key<T>)> {
        self.heap.first().map(|e| (e.at, e.key))
    }

    /// Take out the next transfer due by `now` (`splaygetbest`).
    pub(crate) fn pop_due(&mut self, now: Instant) -> Option<Key<T>> {
        let first = self.heap.first()?;
        if first.at > now {
            return None;
        }
        let key = first.key;
        self.take(0);
        Some(key)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Remove the entry at heap position `i`.
    fn take(&mut self, i: usize) {
        let last = self.heap.len() - 1;
        self.heap.swap(i, last);
        let gone = self.heap.pop().expect("not empty");
        self.position[row_of(gone.key)] = None;
        if i < self.heap.len() {
            self.position[row_of(self.heap[i].key)] = Some(i);
            self.sift_down(i);
            self.sift_up(i);
        }
    }

    fn sift_up(&mut self, mut i: usize) {
        while i > 0 {
            let parent = (i - 1) / 2;
            if !self.heap[i].before(&self.heap[parent]) {
                break;
            }
            self.swap(i, parent);
            i = parent;
        }
    }

    fn sift_down(&mut self, mut i: usize) {
        loop {
            let mut best = i;
            for child in [2 * i + 1, 2 * i + 2] {
                if child < self.heap.len() && self.heap[child].before(&self.heap[best]) {
                    best = child;
                }
            }
            if best == i {
                break;
            }
            self.swap(i, best);
            i = best;
        }
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        self.position[row_of(self.heap[a].key)] = Some(a);
        self.position[row_of(self.heap[b].key)] = Some(b);
    }
}

fn row_of<T>(key: Key<T>) -> usize {
    usize::try_from(key.index()).expect("a u32 row fits a usize")
}

/// When the multi must next run: now, because a transfer is dirty; at an
/// instant; or not until something happens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Due {
    Now,
    At(Instant),
    Never,
}

/// What the application's timer is told (the timer callback's
/// `timeout_ms`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerChange {
    /// Run the multi after this long, in whole milliseconds, rounded up;
    /// zero means at once.
    Set(Duration),
    /// No run is due: stop the timer (C's -1).
    Clear,
}

/// The time from `now` to `at` in milliseconds, rounded up, zero if past
/// (`Curl_timeouts_next_ms`).
pub(crate) fn wait_ms(now: Instant, at: Instant) -> Duration {
    let us = at.since(now).as_micros();
    let ms = us.div_ceil(1000);
    Duration::from_millis(u64::try_from(ms).unwrap_or(u64::MAX)).min(MAX_WAIT)
}

/// What the timer callback was last told, so it hears only of changes
/// (`Curl_update_timer`).
#[derive(Debug, Default)]
pub(crate) struct TimerAnnounce {
    /// The instant last announced, until `forget`.
    last_due: Option<Instant>,
    /// Whether the last announcement set the timer.
    set: bool,
}

impl TimerAnnounce {
    /// The change to announce at `now`, if any, recorded as announced.
    pub(crate) fn update(&mut self, now: Instant, due: Due) -> Option<TimerChange> {
        let (at, change) = match due {
            Due::Now => (Some(now), TimerChange::Set(Duration::ZERO)),
            Due::At(at) => (Some(at), TimerChange::Set(wait_ms(now, at))),
            Due::Never => (None, TimerChange::Clear),
        };
        let announce = match change {
            TimerChange::Clear => self.set,
            // Set after none, or set to a different instant: even if the
            // wait is the same, it counts from a different time.
            TimerChange::Set(_) => !self.set || self.last_due != at,
        };
        if !announce {
            return None;
        }
        self.last_due = at;
        self.set = change != TimerChange::Clear;
        Some(change)
    }

    /// The application ran the timer: announce the next instant even if it
    /// is the same (`curl_multi_socket_action` with `CURL_SOCKET_TIMEOUT`).
    pub(crate) fn forget(&mut self) {
        self.last_due = None;
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod c_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Arena, ArenaPolicy};

    fn at_ms(ms: u64) -> Instant {
        Instant::EPOCH.after(Duration::from_millis(ms))
    }

    fn filled(n: u32) -> (Arena<u32>, Vec<Key<u32>>) {
        let mut arena = Arena::new(ArenaPolicy::new(n.max(16), 0).unwrap()).unwrap();
        let keys = (0..n).map(|i| arena.reserve().unwrap().fill(i)).collect();
        (arena, keys)
    }

    fn queue(keys: &[Key<u32>]) -> TimerQueue<u32> {
        let mut q = TimerQueue::new();
        for &k in keys {
            q.reserve(k.index() + 1).unwrap();
        }
        q
    }

    /// Unit 1309's first part: each queued transfer is removed once, and
    /// removing it again fails.
    #[test]
    fn unit1309_remove_each_once() {
        const NODES: u32 = 50;
        let (_arena, keys) = filled(NODES);
        let mut q = queue(&keys);
        for (i, &k) in keys.iter().enumerate() {
            q.update(k, Some(at_ms((541 * i as u64) % 1023)));
            assert!(q.contains(k));
        }
        for i in 0..NODES as usize {
            let k = keys[(i + 7) % NODES as usize];
            assert!(q.remove(k), "remove {i}");
            assert!(!q.contains(k));
            assert!(!q.remove(k), "double remove {i}");
        }
        assert!(q.is_empty());
    }

    /// Unit 1309's second and third parts: transfers come out in the order
    /// C's tree gives them, those due together in the order queued.
    #[test]
    fn unit1309_due_order() {
        // Each key 1 to 3 times; payload `key * 10 + copy`.
        let mut wanted = Vec::new();
        for i in 0..50u64 {
            for j in 0..=i % 3 {
                wanted.push(((541 * i) % 1023, (541 * i) % 1023 * 10 + j));
            }
        }
        let (_arena, keys) = filled(u32::try_from(wanted.len()).unwrap());
        let mut q = queue(&keys);
        for (&k, &(at, _)) in keys.iter().zip(&wanted) {
            q.update(k, Some(at_ms(at)));
        }
        let mut got = Vec::new();
        for now in (0..=1100).step_by(100) {
            while let Some(k) = q.pop_due(at_ms(now)) {
                let payload = wanted[k.index() as usize].1;
                got.push((now, payload / 10, payload % 10));
            }
        }
        assert!(q.is_empty());
        assert_eq!(got, c_tests::UNIT1309_DUE_WITH_COPIES);

        let wanted: Vec<u64> = (0..50).map(|i| (541 * i) % 128).collect();
        let (_arena, keys) = filled(50);
        let mut q = queue(&keys);
        for (&k, &at) in keys.iter().zip(&wanted) {
            q.update(k, Some(at_ms(at)));
        }
        let mut got = Vec::new();
        for now in (0..=128).step_by(32) {
            while let Some(k) = q.pop_due(at_ms(now)) {
                got.push((now, u64::from(k.index()), wanted[k.index() as usize]));
            }
        }
        assert_eq!(got, c_tests::UNIT1309_DUE_SHARED);
    }

    /// Unit 1309's last part: the wait to an instant is rounded up to whole
    /// milliseconds, whatever the clock's sub-second part.
    #[test]
    fn unit1309_wait_rounds_up() {
        let us = |s: u64, us: u64| Instant::EPOCH.after(Duration::from_micros(s * 1_000_000 + us));
        assert_eq!(
            wait_ms(us(11, 100_000), us(12, 250_000)),
            Duration::from_millis(1150)
        );
        assert_eq!(
            wait_ms(us(11, 100_000), us(11, 100_001)),
            Duration::from_millis(1)
        );
        assert_eq!(wait_ms(us(12, 0), us(11, 0)), Duration::ZERO);
    }

    #[test]
    fn an_unchanged_wake_up_keeps_its_place() {
        let (_arena, keys) = filled(3);
        let mut q = queue(&keys);
        for &k in &keys {
            q.update(k, Some(at_ms(5)));
        }
        q.update(keys[0], Some(at_ms(5)));
        assert_eq!(q.peek(), Some((at_ms(5), keys[0])));
        q.update(keys[0], Some(at_ms(6)));
        q.update(keys[0], Some(at_ms(5)));
        let order: Vec<_> = std::iter::from_fn(|| q.pop_due(at_ms(5))).collect();
        assert_eq!(order, [keys[1], keys[2], keys[0]]);
    }

    #[test]
    #[should_panic = "a stale key"]
    fn a_stale_key_is_caught() {
        let (mut arena, keys) = filled(1);
        let mut q = queue(&keys);
        q.update(keys[0], Some(at_ms(1)));
        arena.remove(keys[0]);
        // Churn until the arena hands the row out again.
        let reused = loop {
            let k = arena.reserve().unwrap().fill(9);
            if k.index() == keys[0].index() {
                break k;
            }
            arena.remove(k);
        };
        q.update(reused, None);
    }

    /// Unit 1303: the time left, against both limits and both anchors.
    #[test]
    fn unit1303_time_left() {
        for case in c_tests::UNIT1303 {
            let start = Instant::EPOCH.after(Duration::from_secs(c_tests::UNIT1303_BASE));
            let mut d = Deadlines::new(
                TimeLimit::from_millis(case.timeout_ms),
                TimeLimit::from_millis(case.connect_timeout_ms),
            );
            d.start_leg(start);
            let starts = Starts {
                op: start,
                single: start,
            };
            let now =
                Instant::EPOCH.after(Duration::from_micros(case.now_s * 1_000_000 + case.now_us));
            let phase = if case.connecting {
                Phase::Connecting
            } else {
                Phase::Transferring
            };
            let got = match d.time_left(starts, now, phase) {
                TimeLeft::Unlimited => 0,
                TimeLeft::Remaining(d) => i64::try_from(d.as_millis()).unwrap(),
                TimeLeft::Expired(d) => -i64::try_from(d.as_millis()).unwrap(),
            };
            assert_eq!(got, case.result, "{}", case.comment);
        }
    }

    #[test]
    fn limits_are_armed_per_leg_and_judged_from_their_anchors() {
        let mut d = Deadlines::new(
            TimeLimit::from_millis(10_000),
            TimeLimit::from_millis(3_000),
        );
        assert_eq!(d.wake_at(), None);
        d.start_leg(at_ms(4_000));
        let starts = Starts {
            op: at_ms(0),
            single: at_ms(4_000),
        };
        assert_eq!(d.wake_at(), Some(at_ms(7_000)));
        // The connect limit counts from the leg, the total from the start.
        assert_eq!(
            d.time_left(starts, at_ms(6_000), Phase::Connecting),
            TimeLeft::Remaining(Duration::from_secs(1))
        );
        assert_eq!(
            d.time_left(starts, at_ms(6_000), Phase::Transferring),
            TimeLeft::Remaining(Duration::from_secs(4))
        );
        d.expire(at_ms(7_000));
        // The total wakes from the leg, though it is due from the start.
        assert_eq!(d.wake_at(), Some(at_ms(14_000)));
        assert_eq!(
            d.time_left(starts, at_ms(12_000), Phase::Transferring),
            TimeLeft::Expired(Duration::from_secs(2))
        );
        d.arm_in(
            TimerKind::Connect,
            at_ms(12_000),
            Duration::from_millis(1_000),
        );
        assert_eq!(d.wake_at(), Some(at_ms(13_000)));
        d.clear(TimerKind::Connect);
        assert_eq!(d.wake_at(), Some(at_ms(14_000)));
        d.expire(at_ms(14_000));
        assert_eq!(d.wake_at(), None);
        d.arm_in(
            TimerKind::Total,
            at_ms(12_000),
            Duration::from_secs(100 * 86_400),
        );
        assert_eq!(d.wake_at(), Some(at_ms(12_000 + i32::MAX as u64)), "capped");
        d.clear_all();
        assert_eq!(d.wake_at(), None);
    }

    /// Unit 3230: the timer callback hears only of changes.
    #[test]
    fn unit3230_timer_updates() {
        let now = at_ms(1_000);
        let mut a = TimerAnnounce::default();
        let mut told = Vec::new();
        let mut update = |a: &mut TimerAnnounce, due| {
            let change = a.update(now, due);
            told.extend(change);
            change
        };
        assert_eq!(
            update(&mut a, Due::Never),
            None,
            "callback invoked without a timeout"
        );
        assert!(!a.set);
        assert!(update(&mut a, Due::At(now.after(Duration::from_secs(600)))).is_some());
        assert!(a.set);
        assert!(update(&mut a, Due::At(now.after(Duration::from_secs(1200)))).is_some());
        assert_eq!(
            update(&mut a, Due::At(now.after(Duration::from_secs(1200)))),
            None
        );
        let last = a.last_due;
        a.forget();
        assert!(update(&mut a, Due::At(now.after(Duration::from_secs(1200)))).is_some());
        assert_eq!(a.last_due, last, "timer refresh changed expiry");
        assert!(a.set);
        assert!(update(&mut a, Due::Never).is_some());
        assert!(!a.set);
        assert_eq!(update(&mut a, Due::Never), None);
        assert!(update(&mut a, Due::Now).is_some());
        assert!(a.set);
        assert!(update(&mut a, Due::Never).is_some());
        assert!(!a.set);
        let ms = |c: &TimerChange| match c {
            TimerChange::Set(d) => i64::try_from(d.as_millis()).unwrap(),
            TimerChange::Clear => -1,
        };
        let told: Vec<i64> = told.iter().map(ms).collect();
        assert_eq!(told.len(), 6, "wrong timer callback count");
        assert!(told[0] >= 0 && told[1] > told[0] && told[2] >= 0);
        assert_eq!(&told[3..], [-1, 0, -1]);
    }

    #[test]
    fn a_dirty_transfer_is_announced_at_each_new_instant() {
        let mut a = TimerAnnounce::default();
        assert_eq!(
            a.update(at_ms(1), Due::Now),
            Some(TimerChange::Set(Duration::ZERO))
        );
        assert_eq!(a.update(at_ms(1), Due::Now), None);
        assert_eq!(
            a.update(at_ms(2), Due::Now),
            Some(TimerChange::Set(Duration::ZERO))
        );
    }
}
