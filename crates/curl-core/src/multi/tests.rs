use super::*;
use curl_alloc::TryArc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::conn::io::{Events, FakeNet, Net, PollFd, Waker};
use crate::options::{IpVersion, Options};
use crate::time::{ManualClock, TimeLimit};

/// Logs every timer call, and aborts the one numbered `abort_at` (from 1).
#[derive(Default)]
struct RecordingEvents {
    timer: Vec<TimerChange>,
    abort_at: Option<usize>,
}

impl MultiEvents<NoHost> for RecordingEvents {
    fn timer(&mut self, _cx: &mut EventCx<'_, NoHost>, change: TimerChange) -> Result<(), Abort> {
        self.timer.push(change);
        if Some(self.timer.len()) == self.abort_at {
            return Err(Abort);
        }
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }
}

fn multi() -> (Multi, ManualClock) {
    let clock = ManualClock::new().unwrap();
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(FakeNet::new(clock.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), clock)
}

fn easy(url: &str) -> Easy {
    let mut easy = Easy::new();
    easy.options_mut().set_url(Some(url.as_bytes())).unwrap();
    easy
}

fn messages(m: &mut Multi) -> Vec<(u32, Result<(), ErrorKind>, u32)> {
    std::iter::from_fn(|| {
        m.info_read()
            .map(|msg| (msg.id.index(), msg.result, msg.remaining))
    })
    .collect()
}

const SET_NOW: TimerChange = TimerChange::Set(Duration::ZERO);

#[test]
fn completions_are_read_in_id_order() {
    let (mut m, _clock) = multi();
    let ev = &mut NoEvents;
    let ids: Vec<_> = ["null://a", "stall://b", "null://c", "nope://d"]
        .into_iter()
        .map(|u| m.add(Box::new(easy(u)), (), ev).unwrap())
        .collect();
    let no_url = m.add(Box::new(Easy::new()), (), ev).unwrap();
    let no_host = m.add(Box::new(easy("null://")), (), ev).unwrap();
    assert_eq!(
        m.counts().running,
        6,
        "added transfers count as running before they run"
    );
    assert_eq!(m.perform(ev), Ok(1));
    let got = messages(&mut m);
    assert_eq!(
        got,
        [
            (ids[0].index(), Ok(()), 4),
            (ids[2].index(), Ok(()), 3),
            (ids[3].index(), Err(ErrorKind::UnsupportedProtocol), 2),
            (no_url.index(), Err(ErrorKind::UrlMalformat), 1),
            (no_host.index(), Err(ErrorKind::UrlMalformat), 0),
        ]
    );
    assert!(m.info_read().is_none());
    assert_eq!(
        m.counts(),
        Counts {
            running: 1,
            current: 6,
            added_ever: 6
        }
    );
}

#[test]
fn removing_twice_finds_nothing_the_second_time() {
    let (mut m, _clock) = multi();
    let ev = &mut NoEvents;
    let id = m.add(Box::new(easy("null://a")), (), ev).unwrap();
    let removed = m.remove(id, ev).expect("in the multi");
    assert_eq!(removed.easy.options().url(), Some(&b"null://a"[..]));
    assert!(m.remove(id, ev).is_none());
    assert_eq!(
        m.counts(),
        Counts {
            running: 0,
            current: 0,
            added_ever: 1
        }
    );
    // Removed before it ran: no message.
    assert_eq!(m.perform(ev), Ok(0));
    assert!(m.info_read().is_none());
}

#[test]
fn removing_a_running_transfer_gives_its_connection_back() {
    let (mut m, _clock) = multi();
    let ev = &mut NoEvents;
    let id = m.add(Box::new(easy("stall://a")), (), ev).unwrap();
    m.perform(ev).unwrap();
    assert_eq!(m.caches.pool.len(), 1);
    m.remove(id, ev).unwrap();
    assert_eq!(m.caches.pool.len(), 0);
}

#[test]
fn the_timer_hears_of_add_and_remove() {
    let (mut m, _clock) = multi();
    let mut ev = RecordingEvents::default();
    let id = m.add(Box::new(easy("stall://a")), (), &mut ev).unwrap();
    assert_eq!(ev.timer, [SET_NOW], "inside the add");
    m.perform(&mut ev).unwrap();
    assert_eq!(ev.timer, [SET_NOW, TimerChange::Clear]);
    let other = m.add(Box::new(easy("stall://b")), (), &mut ev).unwrap();
    m.remove(other, &mut ev).unwrap().status.unwrap();
    assert_eq!(
        ev.timer[2..],
        [SET_NOW, TimerChange::Clear],
        "inside the remove"
    );
    m.remove(id, &mut ev).unwrap().status.unwrap();
    assert_eq!(ev.timer.len(), 4, "no change, no call");
}

#[test]
fn a_timer_abort_inside_add_refuses_the_transfer() {
    let (mut m, _clock) = multi();
    let mut ev = RecordingEvents {
        abort_at: Some(1),
        ..RecordingEvents::default()
    };
    let refused = m.add(Box::new(easy("null://a")), (), &mut ev).unwrap_err();
    assert_eq!(refused.kind, MultiErrorKind::AbortedByCallback);
    assert_eq!(refused.easy.options().url(), Some(&b"null://a"[..]));
    assert_eq!(m.counts().current, 0);
    // Dead but empty: the next add starts over.
    let id = m.add(refused.easy, (), &mut ev).unwrap();
    m.perform(&mut ev).unwrap();
    assert_eq!(messages(&mut m), [(id.index(), Ok(()), 0)]);
}

#[test]
fn a_dead_multi_fails_its_transfers_and_takes_no_more() {
    let (mut m, _clock) = multi();
    let mut ev = RecordingEvents {
        abort_at: Some(2),
        ..RecordingEvents::default()
    };
    let id = m.add(Box::new(easy("stall://a")), (), &mut ev).unwrap();
    assert_eq!(m.perform(&mut ev), Err(MultiErrorKind::AbortedByCallback));
    assert_eq!(m.timeout(), Some(Duration::ZERO));
    let refused = m.add(Box::new(easy("null://b")), (), &mut ev).unwrap_err();
    assert_eq!(refused.kind, MultiErrorKind::AbortedByCallback);
    assert_eq!(m.perform(&mut ev), Ok(0));
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::AbortedByCallback), 0)]
    );
    assert_eq!(m.caches.pool.len(), 0, "the connection was given back");
    assert_eq!(ev.timer.len(), 2, "a dead multi tells the timer nothing");
    m.remove(id, &mut ev).unwrap();
    m.add(refused.easy, (), &mut ev).unwrap();
    assert_eq!(ev.timer.len(), 3);
}

#[test]
fn timers_wake_transfers_through_socket_action() {
    let (mut m, clock) = multi();
    let mut ev = RecordingEvents::default();
    let mut e = easy("stall://a");
    e.options_mut().limits.total = TimeLimit::from_millis(1500);
    let id = m.add(Box::new(e), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(
        ev.timer,
        [SET_NOW, TimerChange::Set(Duration::from_millis(1500))]
    );
    assert_eq!(m.timeout(), Some(Duration::from_millis(1500)));
    clock.advance(Duration::from_micros(1_000_001));
    assert_eq!(m.timeout(), Some(Duration::from_millis(500)), "rounded up");
    // Early: nothing is due, but the timer is told again.
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(ev.timer.len(), 3);
    clock.advance(Duration::from_millis(499));
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert!(m.info_read().is_none(), "1 ms early");
    clock.advance(Duration::from_millis(1));
    assert_eq!(m.socket_action(SocketEvent::Timeout, &mut ev), Ok(0));
    assert_eq!(ev.timer.last(), Some(&TimerChange::Clear));
    assert!(m.timers.is_empty());
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::OperationTimedout), 0)]
    );
    assert_eq!(m.caches.pool.len(), 0);
}

#[test]
fn a_timer_abort_inside_remove_still_removes() {
    let (mut m, _clock) = multi();
    let mut ev = RecordingEvents {
        abort_at: Some(2),
        ..RecordingEvents::default()
    };
    let id = m.add(Box::new(easy("stall://a")), (), &mut ev).unwrap();
    let removed = m.remove(id, &mut ev).expect("in the multi");
    assert_eq!(removed.status, Err(MultiErrorKind::AbortedByCallback));
    assert_eq!(removed.easy.options().url(), Some(&b"stall://a"[..]));
    assert_eq!(m.counts().current, 0);
    // Dead and empty: the next add starts over.
    m.add(removed.easy, (), &mut ev).unwrap();
}

/// A clock that jumps forward by `lag` right after its next reading, as if
/// running the transfers took that long.
struct LaggingClock {
    inner: ManualClock,
    lag: std::sync::Arc<crate::test_cell::Cell<Duration>>,
}

impl Clock for LaggingClock {
    fn now(&self) -> Instant {
        let t = self.inner.now();
        self.inner.advance(self.lag.take());
        t
    }

    fn unix_time(&self) -> i64 {
        self.inner.unix_time()
    }
}

fn lagging_multi() -> (Multi, std::sync::Arc<crate::test_cell::Cell<Duration>>) {
    let lag = std::sync::Arc::new(crate::test_cell::Cell::new(Duration::ZERO));
    let inner = ManualClock::new().unwrap();
    let env = Env {
        clock: Box::new(LaggingClock {
            inner: inner.clone(),
            lag: lag.clone(),
        }),
        net: Box::new(FakeNet::new(inner)),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), lag)
}

fn stall_within(ms: u64) -> Easy {
    let mut e = easy("stall://a");
    e.options_mut().limits.total = TimeLimit::from_millis(ms);
    e
}

#[test]
fn socket_action_catches_what_came_due_while_it_ran() {
    let (mut m, lag) = lagging_multi();
    let ev = &mut NoEvents;
    let late = m.add(Box::new(stall_within(10)), (), ev).unwrap();
    m.perform(ev).unwrap();
    // Something to run, which takes long enough for `late` to come due.
    m.add(Box::new(easy("stall://b")), (), ev).unwrap();
    lag.set(Duration::from_millis(10));
    m.socket_action(SocketEvent::Timeout, ev).unwrap();
    assert_eq!(
        messages(&mut m),
        [(late.index(), Err(ErrorKind::OperationTimedout), 0)]
    );
}

#[test]
fn socket_action_runs_nothing_late_when_nothing_ran() {
    let (mut m, lag) = lagging_multi();
    let ev = &mut NoEvents;
    m.add(Box::new(stall_within(10)), (), ev).unwrap();
    m.perform(ev).unwrap();
    lag.set(Duration::from_millis(10));
    m.socket_action(SocketEvent::Timeout, ev).unwrap();
    assert!(
        m.info_read().is_none(),
        "due only after the reading the run used"
    );
}

/// The timer component: each limit armed as a leg starts, with what is
/// left of it, and the first due named as it fires on a socket action
/// (`multi_mark_expired_as_dirty`); a perform fires it silently, as C's
/// does.
#[test]
fn timers_are_traced_as_c_arms_and_fires_them() {
    let (mut m, clock) = multi();
    let ev = &mut NoEvents;
    let (mut e, lines) = traced("stall://a");
    e.options_mut().limits.total = TimeLimit::from_millis(1500);
    e.options_mut().limits.connect = TimeLimit::from_millis(1000);
    let components = crate::components::Components::new().unwrap();
    components.configure(b"timer");
    e.set_components(Some(components));
    m.add(Box::new(e), (), ev).unwrap();
    m.perform(ev).unwrap();
    clock.advance(Duration::from_millis(1000));
    m.socket_action(SocketEvent::Timeout, ev).unwrap();
    clock.advance(Duration::from_millis(500));
    m.perform(ev).unwrap();
    let timers: Vec<_> = trace_of(&lines)
        .into_iter()
        .filter(|l| l.starts_with("[TIMER]"))
        .collect();
    assert_eq!(
        timers,
        [
            "[TIMER] [TIMEOUT] set for 1500000us\n",
            "[TIMER] [CONNECTTIMEOUT] set for 1000000us\n",
            "[TIMER] [CONNECTTIMEOUT] has expired\n",
        ]
    );
}

#[test]
fn a_fired_timer_queues_the_next_one() {
    let (mut m, clock) = multi();
    let ev = &mut NoEvents;
    let mut e = stall_within(3000);
    e.options_mut().limits.connect = TimeLimit::from_millis(1000);
    m.add(Box::new(e), (), ev).unwrap();
    m.perform(ev).unwrap();
    assert_eq!(m.timeout(), Some(Duration::from_millis(1000)));
    clock.advance(Duration::from_millis(1000));
    // Connected already: the connect limit only wakes the transfer.
    assert_eq!(m.socket_action(SocketEvent::Timeout, ev), Ok(1));
    assert_eq!(m.timeout(), Some(Duration::from_millis(2000)));
}

#[test]
fn transfers_on_later_rows_get_timers() {
    let (mut m, _clock) = multi();
    let ev = &mut NoEvents;
    for ms in [3000, 2000, 1000] {
        m.add(Box::new(stall_within(ms)), (), ev).unwrap();
    }
    m.perform(ev).unwrap();
    assert_eq!(m.timeout(), Some(Duration::from_millis(1000)));
}

/// C leaves a refused transfer in `running_handles` for good, though its
/// `CURLMINFO_XFERS_RUNNING` drops at the next perform (ENGINE.md 7.8);
/// it does count it as added.
#[test]
fn a_refused_add_counts_nothing_as_running() {
    let (mut m, _clock) = multi();
    let mut ev = RecordingEvents {
        abort_at: Some(1),
        ..RecordingEvents::default()
    };
    m.add(Box::new(easy("null://a")), (), &mut ev).unwrap_err();
    assert_eq!(
        m.counts(),
        Counts {
            running: 0,
            current: 0,
            added_ever: 1
        }
    );
}

#[test]
fn a_transfer_s_easy_is_reached_by_its_id() {
    let (mut m, _clock) = multi();
    let ev = &mut NoEvents;
    let id = m.add(Box::new(easy("null://a")), (), ev).unwrap();
    assert_eq!(m.easy(id).unwrap().options().url(), Some(&b"null://a"[..]));
    m.easy_mut(id)
        .unwrap()
        .options_mut()
        .set_url(Some(b"null://b"))
        .unwrap();
    assert_eq!(m.easy(id).unwrap().options().url(), Some(&b"null://b"[..]));
    m.remove(id, ev).unwrap();
    assert!(m.easy(id).is_none());
    assert!(m.easy_mut(id).is_none());
}

#[test]
fn a_url_without_a_scheme_is_guessed() {
    let (mut m, _clock) = multi();
    let ev = &mut NoEvents;
    // Guessed as http, a name the resolver, which knows only literal
    // addresses, cannot resolve.
    let id = m.add(Box::new(easy("example.com/a")), (), ev).unwrap();
    m.perform(ev).unwrap();
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::CouldntResolveHost), 0)]
    );
}

/// Logs every notification and timer call; on `EasyDone(trigger)` it
/// removes `remove`, adds `add` and turns `EasyDone` off if `disable`.
#[derive(Default)]
struct NotifyEvents {
    log: Vec<Notification>,
    timer: Vec<TimerChange>,
    trigger: Option<TransferId>,
    remove: Option<TransferId>,
    add: Option<Easy>,
    disable: bool,
    removed: Vec<Easy>,
    added: Vec<TransferId>,
    read_in_timer: bool,
    read: Vec<(TransferId, Result<(), ErrorKind>)>,
}

impl MultiEvents<NoHost> for NotifyEvents {
    fn timer(&mut self, cx: &mut EventCx<'_, NoHost>, change: TimerChange) -> Result<(), Abort> {
        self.timer.push(change);
        while self.read_in_timer
            && let Some(m) = cx.info_read()
        {
            self.read.push((m.id, m.result));
        }
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }

    fn notify(&mut self, cx: &mut NotifyCx<'_, NoHost>, n: Notification) {
        self.log.push(n);
        if self.trigger.is_none_or(|t| n != Notification::EasyDone(t)) {
            return;
        }
        if let Some(b) = self.remove.take() {
            let removed = cx.remove(b, self).expect("in the multi");
            self.removed.push(*removed.easy);
        }
        if let Some(e) = self.add.take() {
            let id = cx.add(Box::new(e), (), self).expect("added");
            self.added.push(id);
        }
        if self.disable {
            cx.set_notify(NotifyKind::EasyDone, false);
        }
    }
}

fn notifying(m: &mut Multi) {
    m.set_notify(NotifyKind::InfoRead, true);
    m.set_notify(NotifyKind::EasyDone, true);
}

/// The order C's notify callback sees for the same transfers.
#[test]
fn notifications_come_in_the_order_things_happened() {
    let (mut m, _clock) = multi();
    notifying(&mut m);
    let mut ev = NotifyEvents::default();
    let a = m.add(Box::new(easy("null://a")), (), &mut ev).unwrap();
    let b = m.add(Box::new(easy("nope://b")), (), &mut ev).unwrap();
    let c = m.add(Box::new(easy("null://c")), (), &mut ev).unwrap();
    ev.trigger = Some(a);
    m.perform(&mut ev).unwrap();
    assert_eq!(
        ev.log,
        [
            Notification::EasyDone(a),
            Notification::InfoRead,
            Notification::EasyDone(b),
            Notification::EasyDone(c),
        ]
    );
    assert_eq!(m.notify.len(), 0, "delivered and gone");
}

#[test]
fn info_read_is_notified_again_once_every_message_is_read() {
    let (mut m, _clock) = multi();
    notifying(&mut m);
    let mut ev = NotifyEvents::default();
    let a = m.add(Box::new(easy("null://a")), (), &mut ev).unwrap();
    ev.trigger = Some(a);
    m.perform(&mut ev).unwrap();
    let b = m.add(Box::new(easy("null://b")), (), &mut ev).unwrap();
    m.perform(&mut ev).unwrap();
    assert_eq!(messages(&mut m).len(), 2);
    let c = m.add(Box::new(easy("null://c")), (), &mut ev).unwrap();
    m.perform(&mut ev).unwrap();
    assert_eq!(
        ev.log,
        [
            Notification::EasyDone(a),
            Notification::InfoRead,
            Notification::EasyDone(b),
            Notification::EasyDone(c),
            Notification::InfoRead,
        ]
    );
}

#[test]
fn notifications_are_off_until_enabled() {
    let (mut m, _clock) = multi();
    let mut ev = NotifyEvents::default();
    m.add(Box::new(easy("null://a")), (), &mut ev).unwrap();
    m.set_notify(NotifyKind::EasyDone, true);
    m.set_notify(NotifyKind::EasyDone, false);
    m.perform(&mut ev).unwrap();
    assert_eq!(ev.log, []);
    m.set_notify(NotifyKind::InfoRead, true);
    m.add(Box::new(easy("null://b")), (), &mut ev).unwrap();
    messages(&mut m);
    m.perform(&mut ev).unwrap();
    assert_eq!(ev.log, [Notification::InfoRead]);
}

#[test]
fn a_kind_turned_off_before_delivery_is_dropped() {
    let (mut m, _clock) = multi();
    notifying(&mut m);
    let mut ev = NotifyEvents::default();
    let a = m.add(Box::new(easy("null://a")), (), &mut ev).unwrap();
    m.add(Box::new(easy("null://b")), (), &mut ev).unwrap();
    ev.trigger = Some(a);
    ev.disable = true;
    m.perform(&mut ev).unwrap();
    assert_eq!(ev.log, [Notification::EasyDone(a), Notification::InfoRead]);
}

/// C drops a removed transfer's notification as stale.
#[test]
fn a_removed_transfer_s_notification_reaches_no_one() {
    let (mut m, _clock) = multi();
    notifying(&mut m);
    let mut ev = NotifyEvents::default();
    let a = m.add(Box::new(easy("null://a")), (), &mut ev).unwrap();
    let b = m.add(Box::new(easy("null://b")), (), &mut ev).unwrap();
    ev.trigger = Some(a);
    ev.remove = Some(b);
    ev.add = Some(easy("null://c"));
    m.perform(&mut ev).unwrap();
    let c = ev.added[0];
    assert_eq!(ev.log, [Notification::EasyDone(a), Notification::InfoRead]);
    assert_eq!(
        ev.removed[0].options().url(),
        Some(&b"null://b"[..]),
        "the removed transfer's Easy comes back"
    );
    // Added from the callback: the timer heard of it inside the add, and
    // it runs at the next pass.
    assert_eq!(ev.timer.last(), Some(&SET_NOW));
    m.perform(&mut ev).unwrap();
    assert_eq!(ev.log[2..], [Notification::EasyDone(c)]);
}

#[test]
fn the_timer_callback_can_read_messages() {
    let (mut m, _clock) = multi();
    let mut ev = NotifyEvents::default();
    let a = m.add(Box::new(easy("nope://a")), (), &mut ev).unwrap();
    m.perform(&mut ev).unwrap();
    ev.read_in_timer = true;
    m.add(Box::new(easy("null://b")), (), &mut ev).unwrap();
    assert_eq!(ev.read, [(a, Err(ErrorKind::UnsupportedProtocol))]);
}

#[test]
fn socket_action_delivers_notifications() {
    let (mut m, clock) = multi();
    m.set_notify(NotifyKind::EasyDone, true);
    let mut ev = NotifyEvents::default();
    let id = m.add(Box::new(stall_within(10)), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(ev.log, []);
    clock.advance(Duration::from_millis(10));
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(ev.log, [Notification::EasyDone(id)]);
}

/// Calls every context method from inside the callbacks and records what
/// it saw.
#[derive(Default)]
struct Probe {
    target: Option<TransferId>,
    in_timer: Vec<String>,
    in_notify: Vec<String>,
}

fn probe_options(options: Option<&Options>) -> String {
    format!("{:?}", options.and_then(Options::url).map(<[u8]>::to_vec))
}

impl MultiEvents<NoHost> for Probe {
    fn timer(&mut self, cx: &mut EventCx<'_, NoHost>, _: TimerChange) -> Result<(), Abort> {
        let Some(id) = self.target else { return Ok(()) };
        let c = cx.counts();
        self.in_timer
            .push(format!("counts {} {}", c.running, c.current));
        self.in_timer.push(probe_options(cx.options(id)));
        cx.options_mut(id)
            .unwrap()
            .set_url(Some(b"null://changed"))
            .unwrap();
        let dup = cx.duplicate(id).unwrap().unwrap();
        self.in_timer.push(probe_options(Some(dup.options())));
        cx.set_notify(NotifyKind::EasyDone, true);
        cx.conn_limits_mut().max_host = NonZeroU32::new(7);
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }

    fn notify(&mut self, cx: &mut NotifyCx<'_, NoHost>, n: Notification) {
        let Notification::EasyDone(id) = n else {
            return;
        };
        let c = cx.counts();
        self.in_notify
            .push(format!("counts {} {}", c.running, c.current));
        self.in_notify.push(format!("timeout {:?}", cx.timeout()));
        self.in_notify.push(probe_options(cx.options(id)));
        cx.options_mut(id)
            .unwrap()
            .set_url(Some(b"null://again"))
            .unwrap();
        let dup = cx.duplicate(id).unwrap().unwrap();
        self.in_notify.push(probe_options(Some(dup.options())));
        let read = cx.info_read().map(|m| m.id);
        self.in_notify.push(format!("read {}", read == Some(id)));
        cx.conn_limits_mut().max_total = NonZeroU32::new(8);
    }
}

#[test]
fn callbacks_reach_the_multi_through_their_contexts() {
    let (mut m, _clock) = multi();
    let mut ev = Probe::default();
    let first = m.add(Box::new(stall_within(5000)), (), &mut ev).unwrap();
    m.perform(&mut ev).unwrap();
    ev.target = Some(first);
    // The timer hears of the add, and changes the first transfer's URL.
    let id = m.add(Box::new(easy("null://b")), (), &mut ev).unwrap();
    let url = |o: &str| format!("{:?}", Some(o.as_bytes().to_vec()));
    assert_eq!(
        ev.in_timer,
        [
            "counts 2 2".to_owned(),
            url("stall://a"),
            url("null://changed")
        ]
    );
    ev.target = None;
    m.perform(&mut ev).unwrap();
    assert_eq!(
        ev.in_notify,
        [
            "counts 1 2".to_owned(),
            "timeout Some(5s)".to_owned(),
            url("null://b"),
            url("null://again"),
            "read true".to_owned(),
        ]
    );
    assert_eq!(
        m.easy(id).unwrap().options().url(),
        Some(&b"null://again"[..])
    );
    let limits = m.conn_limits_mut();
    let n = NonZeroU32::new;
    assert_eq!((limits.max_host, limits.max_total), (n(7), n(8)));
}

fn multi_with_waker() -> (Multi, ManualClock, TryArc<Waker>) {
    let clock = ManualClock::new().unwrap();
    let waker = TryArc::try_new(Waker::new().unwrap()).unwrap();
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(FakeNet::new(clock.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: Some(waker.clone()),
    };
    (Multi::new(env).unwrap(), clock, waker)
}

/// How far `f` moved the clock: how long a wait over `FakeNet` slept.
fn slept(clock: &ManualClock, f: impl FnOnce()) -> Duration {
    let start = clock.now();
    f();
    clock.now().since(start)
}

#[test]
fn wait_with_nothing_to_wait_for_returns_at_once() {
    let (mut m, clock) = multi();
    let max = Duration::from_secs(3);
    let took = slept(&clock, || {
        assert_eq!(m.wait(&mut [], max, WaitMode::Wait), Ok(0));
    });
    assert_eq!(took, Duration::ZERO);
}

#[test]
fn poll_sleeps_out_its_timeout_with_nothing_to_wait_for() {
    let (mut m, clock) = multi();
    let max = Duration::from_secs(3);
    let took = slept(&clock, || {
        assert_eq!(m.wait(&mut [], max, WaitMode::Poll), Ok(0));
    });
    assert_eq!(took, max);
}

#[test]
fn the_multi_s_own_timeout_cuts_a_wait_short() {
    let (mut m, clock) = multi();
    let ev = &mut NoEvents;
    m.add(Box::new(stall_within(1500)), (), ev).unwrap();
    let max = Duration::from_secs(10);
    let took = slept(&clock, || {
        m.wait(&mut [], max, WaitMode::Poll).unwrap();
    });
    assert_eq!(took, Duration::ZERO, "a transfer to run: no wait at all");
    m.perform(ev).unwrap();
    let took = slept(&clock, || {
        m.wait(&mut [], max, WaitMode::Poll).unwrap();
    });
    assert_eq!(took, Duration::from_millis(1500));
}

#[test]
fn ready_extra_descriptors_are_reported_in_their_entries() {
    use std::io::Write as _;
    use std::os::fd::AsFd as _;
    let (mut m, clock) = multi();
    let (mut a, b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (_c, d) = std::os::unix::net::UnixStream::pair().unwrap();
    a.write_all(b"x").unwrap();
    let mut extra = [
        PollFd::new(d.as_fd(), Events::IN),
        PollFd::new(b.as_fd(), Events::IN),
    ];
    let max = Duration::from_secs(3);
    let took = slept(&clock, || {
        assert_eq!(m.wait(&mut extra, max, WaitMode::Wait), Ok(1));
    });
    assert_eq!(took, Duration::ZERO);
    assert!(extra[0].revents().is_empty());
    assert!(extra[1].revents().contains(Events::IN));
}

/// More descriptors than fit on the stack are waited on all the same:
/// eleven of the application's, and eleven transfers' sockets.
#[test]
fn a_wait_takes_more_than_fit_on_the_stack() {
    use std::io::Write as _;
    use std::os::fd::AsFd as _;
    let (mut m, _clock) = multi();
    let pairs: Vec<_> = (0..11)
        .map(|_| std::os::unix::net::UnixStream::pair().unwrap())
        .collect();
    (&pairs[10].0).write_all(b"x").unwrap();
    let mut extra: Vec<PollFd<'_>> = pairs
        .iter()
        .map(|(_, b)| PollFd::new(b.as_fd(), Events::IN))
        .collect();
    assert_eq!(
        m.wait(&mut extra, Duration::from_secs(3), WaitMode::Wait),
        Ok(1)
    );
    assert!(extra[10].revents().contains(Events::IN));

    let clock = ManualClock::new().unwrap();
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 8999));
    let mut net = FakeNet::new(clock.clone()).with_peer(at, crate::conn::io::Peer::Accepts);
    for _ in 0..11 {
        net = net.with_conversation(at, crate::conn::io::Conversation::replies(&[], false));
    }
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let ev = &mut NoEvents;
    for _ in 0..11 {
        m.add(Box::new(easy("http://127.0.0.1:8999/")), (), ev)
            .unwrap();
    }
    for _ in 0..5 {
        m.perform(ev).unwrap();
    }
    assert_eq!(m.wait(&mut [], Duration::ZERO, WaitMode::Wait), Ok(0));
}

#[test]
fn a_wake_ends_a_wait_without_counting_and_is_consumed() {
    let (mut m, clock, waker) = multi_with_waker();
    let max = Duration::from_secs(3);
    assert!(m.waker().is_some_and(|w| TryArc::ptr_eq(&w, &waker)));
    waker.wake().unwrap();
    // A wait that would not wait leaves the wake pending.
    assert_eq!(m.wait(&mut [], max, WaitMode::Wait), Ok(0));
    let took = slept(&clock, || {
        assert_eq!(m.wait(&mut [], max, WaitMode::Poll), Ok(0));
    });
    assert_eq!(took, Duration::ZERO, "woken");
    let took = slept(&clock, || {
        assert_eq!(m.wait(&mut [], max, WaitMode::Poll), Ok(0));
    });
    assert_eq!(took, max, "the wake was consumed");
}

/// A network whose every poll fails.
struct BrokenNet;

impl Net for BrokenNet {
    fn poll(
        &mut self,
        _: &mut [crate::conn::io::SocketPoll<'_>],
        _: &mut [PollFd<'_>],
        _: Duration,
    ) -> std::io::Result<u32> {
        Err(std::io::Error::from_raw_os_error(9))
    }

    fn connect(
        &mut self,
        _: std::net::SocketAddr,
        _: crate::conn::io::SocketOptions,
    ) -> std::io::Result<(Box<dyn crate::conn::io::Socket>, crate::conn::io::Connect)> {
        Err(std::io::Error::from_raw_os_error(9))
    }

    fn close(&mut self, _: Box<dyn crate::conn::io::Socket>) {}

    fn resolve(
        &mut self,
        name: &[u8],
        family: crate::conn::io::Family,
    ) -> Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure> {
        let _ = (name, family);
        Err(crate::conn::io::ResolveFailure::Failed)
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        None
    }
}

#[test]
fn a_failed_poll_is_unrecoverable() {
    let env = Env {
        clock: Box::new(ManualClock::new().unwrap()),
        net: Box::new(BrokenNet),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    assert_eq!(
        m.wait(&mut [], Duration::from_secs(1), WaitMode::Poll),
        Err(MultiErrorKind::UnrecoverablePoll)
    );
}

#[test]
fn driving_a_transfer_to_completion_leaves_others_messages() {
    let (mut m, clock) = multi();
    let ev = &mut NoEvents;
    let sibling = m.add(Box::new(easy("nope://a")), (), ev).unwrap();
    let id = m.add(Box::new(stall_within(2500)), (), ev).unwrap();
    let took = slept(&clock, || {
        assert_eq!(
            drive_to_completion(&mut m, id, ev),
            Ok(Err(ErrorKind::OperationTimedout))
        );
    });
    assert_eq!(
        took,
        Duration::from_millis(2500),
        "the waits slept until the limit"
    );
    assert_eq!(
        messages(&mut m),
        [(sibling.index(), Err(ErrorKind::UnsupportedProtocol), 0)],
        "the driven transfer's message is read, the sibling's is not"
    );
    let done = m.add(Box::new(easy("null://b")), (), ev).unwrap();
    assert_eq!(drive_to_completion(&mut m, done, ev), Ok(Ok(())));
    m.remove(done, ev).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, done, ev),
        Err(MultiErrorKind::BadEasyHandle)
    );
}

/// Takes `victim` out of the multi when it is reported done.
struct RemoveWhenDone {
    victim: TransferId,
    removed: bool,
}

impl MultiEvents<NoHost> for RemoveWhenDone {
    fn notify(&mut self, cx: &mut NotifyCx<'_, NoHost>, n: Notification) {
        if n == Notification::EasyDone(self.victim) {
            self.removed = cx.remove(self.victim, &mut NoEvents).is_some();
        }
    }
}

#[test]
fn driving_a_transfer_a_callback_takes_out_is_an_error() {
    let (mut m, _clock) = multi();
    m.set_notify(NotifyKind::EasyDone, true);
    let id = m
        .add(Box::new(stall_within(1500)), (), &mut NoEvents)
        .unwrap();
    let ev = &mut RemoveWhenDone {
        victim: id,
        removed: false,
    };
    assert_eq!(
        drive_to_completion(&mut m, id, ev),
        Err(MultiErrorKind::BadEasyHandle)
    );
    assert!(ev.removed);
}

fn us(n: u64) -> Duration {
    Duration::from_micros(n)
}

/// The phases of a transfer that times out exchanging: each reached at
/// once, so a microsecond; no response, so no STARTTRANSFER; the total
/// from its first run to its end.
#[test]
fn a_report_times_the_phases_a_transfer_reached() {
    let (mut m, clock) = multi();
    let ev = &mut NoEvents;
    let id = m.add(Box::new(stall_within(1000)), (), ev).unwrap();
    clock.advance(Duration::from_millis(5));
    m.perform(ev).unwrap();
    clock.advance(Duration::from_millis(1000));
    m.perform(ev).unwrap();
    let t = *m.easy(id).unwrap().report().timings();
    assert_eq!(t.total(), Duration::from_secs(1), "from the first run");
    assert_eq!(
        [t.namelookup(), t.pretransfer(), t.posttransfer()],
        [us(1); 3]
    );
    assert_eq!(t.starttransfer(), Duration::ZERO, "nothing received");
    assert_eq!(
        [t.connect(), t.appconnect(), t.queue()],
        [Duration::ZERO; 3]
    );
}

/// A URL that parses but grows past C's limit when read back fails its
/// transfer as `URL_MALFORMAT`, saying nothing, as C fails it at the
/// read-back; the report keeps no URL.
#[test]
fn a_url_too_long_to_read_back_fails_its_transfer() {
    let (mut m, _clock) = multi();
    let ev = &mut NoEvents;
    // `file:/x` reads back as `file:///x`: two bytes longer.
    let mut url = b"file:/".to_vec();
    url.resize(7_999_999, b'a');
    let (e, lines) = traced(std::str::from_utf8(&url).unwrap());
    let id = m.add(Box::new(e), (), ev).unwrap();
    m.perform(ev).unwrap();
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::UrlMalformat), 0)]
    );
    assert!(
        trace_of(&lines).iter().all(|l| !l.contains("URL")),
        "{:?}",
        trace_of(&lines)
    );
    assert_eq!(m.easy(id).unwrap().report().url(), None);
    // An empty query is read back with its `?` (`CURLU_GET_EMPTY`): one
    // byte that takes this URL to the limit.
    let mut url = b"file:/".to_vec();
    url.resize(7_999_997, b'a');
    url.push(b'?');
    let (e, _) = traced(std::str::from_utf8(&url).unwrap());
    let id = m.add(Box::new(e), (), ev).unwrap();
    m.perform(ev).unwrap();
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::UrlMalformat), 0)]
    );
}

/// A transfer that ends before it was about to send gets the times it
/// skipped (`mstate_enter_completed`).
#[test]
fn a_transfer_failing_before_its_request_gets_the_skipped_times() {
    let (mut m, clock) = multi();
    let ev = &mut NoEvents;
    let no_url = m.add(Box::new(Easy::new()), (), ev).unwrap();
    let unsupported = m.add(Box::new(easy("nope://a")), (), ev).unwrap();
    clock.advance(Duration::from_millis(5));
    m.perform(ev).unwrap();
    for id in [no_url, unsupported] {
        let t = *m.easy(id).unwrap().report().timings();
        assert_eq!(
            [t.pretransfer(), t.posttransfer(), t.starttransfer()],
            [us(1); 3]
        );
        assert_eq!(t.namelookup(), Duration::ZERO);
        assert_eq!(
            t.total(),
            us(1),
            "it ended where it began, holding its phases"
        );
    }
}

/// One the dead multi ends before it ever ran gets a report all the same.
#[test]
fn a_transfer_a_dead_multi_ends_unstarted_gets_a_report() {
    let (mut m, clock) = multi();
    let mut ev = RecordingEvents {
        abort_at: Some(2),
        ..RecordingEvents::default()
    };
    let id = m.add(Box::new(easy("null://a")), (), &mut ev).unwrap();
    // A later add moves the wake-up, and that timer call aborts.
    clock.advance(Duration::from_millis(1));
    let refused = m.add(Box::new(easy("null://b")), (), &mut ev).unwrap_err();
    assert_eq!(refused.kind, MultiErrorKind::AbortedByCallback);
    m.perform(&mut ev).unwrap();
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::AbortedByCallback), 0)]
    );
    let t = *m.easy(id).unwrap().report().timings();
    assert_eq!(
        [t.pretransfer(), t.posttransfer(), t.starttransfer()],
        [us(1); 3]
    );
}

/// Each run of an `Easy` gets a fresh report; a copy and a reset start
/// with none.
#[test]
fn every_run_reports_afresh() {
    let (mut m, clock) = multi();
    let ev = &mut NoEvents;
    let id = m.add(Box::new(stall_within(1000)), (), ev).unwrap();
    m.perform(ev).unwrap();
    clock.advance(Duration::from_millis(1000));
    m.perform(ev).unwrap();
    let mut e = m.remove(id, ev).unwrap().easy;
    assert_eq!(e.report().timings().total(), Duration::from_secs(1));
    assert_eq!(
        e.try_clone().unwrap().report().timings().total(),
        Duration::ZERO
    );
    e.options_mut().limits.total = None;
    e.options_mut().set_url(Some(b"null://a")).unwrap();
    let id = m.add(e, (), ev).unwrap();
    m.perform(ev).unwrap();
    let mut e = m.remove(id, ev).unwrap().easy;
    assert_eq!(
        e.report().timings().total(),
        us(1),
        "the second run's, done in no time, holding its phases"
    );
    assert_eq!(e.report().timings().pretransfer(), us(1));
    e.reset();
    assert_eq!(e.report().timings().pretransfer(), Duration::ZERO);
}

/// What the timer and notify callbacks read of a failed transfer.
#[derive(Default)]
struct Inspect {
    target: Option<TransferId>,
    timer_failure: Option<Vec<u8>>,
    notify_failure: Option<Vec<u8>>,
    owner_seen: bool,
    pause: Option<Result<(), ErrorKind>>,
}

impl MultiEvents<NoHost> for Inspect {
    fn timer(&mut self, cx: &mut EventCx<'_, NoHost>, _: TimerChange) -> Result<(), Abort> {
        if let Some(id) = self.target
            && let Some(why) = cx.info(id).and_then(|r| r.failure())
        {
            self.timer_failure = Some(why.to_vec());
        }
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }

    fn notify(&mut self, cx: &mut NotifyCx<'_, NoHost>, n: Notification) {
        let Notification::EasyDone(id) = n else {
            return;
        };
        if Some(id) != self.target {
            return;
        }
        self.notify_failure = cx.info(id).and_then(|r| r.failure().map(<[u8]>::to_vec));
        self.owner_seen = cx.owner(id).is_some();
        self.pause = Some(cx.pause(id, PauseRequest::CONT, &mut NoEvents));
    }
}

/// The callbacks read a transfer's report and owner by its id, and a
/// completed one has nothing to pause; the multi walks its transfers and
/// counts their unread messages.
#[test]
fn callbacks_read_reports_and_the_multi_counts_messages() {
    let (mut m, _clock) = multi();
    let mut ev = Inspect::default();
    m.set_notify(NotifyKind::EasyDone, true);
    let missing = m
        .add(
            Box::new(easy("file:///nonexistent/curl-core-test")),
            (),
            &mut ev,
        )
        .unwrap();
    let other = m.add(Box::new(easy("null://b")), (), &mut ev).unwrap();
    assert_eq!(m.unread(), 0);
    let walked: Vec<_> =
        std::iter::successors(m.next_transfer(None), |&id| m.next_transfer(Some(id))).collect();
    assert_eq!(walked, [missing, other]);
    assert!(m.owner(missing).is_some());
    ev.target = Some(missing);
    m.perform(&mut ev).unwrap();
    let why = b"Could not open file /nonexistent/curl-core-test".to_vec();
    assert_eq!(ev.notify_failure.as_ref(), Some(&why));
    assert!(ev.owner_seen);
    assert_eq!(ev.pause, Some(Err(ErrorKind::BadFunctionArgument)));
    assert_eq!(m.unread(), 2);
    m.info_read().unwrap();
    assert_eq!(m.unread(), 1);
    // The timer hears of the remove, and reads the transfer left.
    m.remove(other, &mut ev).unwrap();
    assert_eq!(ev.timer_failure, Some(why));
    assert_eq!(m.unread(), 0);
    assert_eq!(m.next_transfer(Some(missing)), None);
    assert!(m.owner(other).is_none());
}

/// Keeps the trace's text lines.
#[derive(Clone, Default)]
struct TextLines(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl crate::handler::DebugHandler for TextLines {
    fn debug(&self, _: &mut TransferCx<'_>, kind: crate::handler::DebugKind, data: &[u8]) {
        if kind == crate::handler::DebugKind::Text {
            let line = String::from_utf8(data.to_vec()).unwrap();
            self.0.lock().unwrap().push(line);
        }
    }
}

/// A multi over fake peers: 127.0.0.1 port 1 accepts, 2 refuses, 3 never
/// answers, 4 accepts after 5 ms.
fn networked() -> (Multi, ManualClock) {
    use crate::conn::io::Peer;
    let clock = ManualClock::new().unwrap();
    let at = |port| std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let net = FakeNet::new(clock.clone())
        .with_peer(at(1), Peer::Accepts)
        .with_peer(at(2), Peer::Refuses)
        .with_peer(at(3), Peer::Silent)
        .with_peer(at(4), Peer::AcceptsAfter(Duration::from_millis(5)))
        .with_peer(
            std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 1)),
            Peer::Accepts,
        )
        .with_peer(
            std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 2)),
            Peer::Refuses,
        )
        .with_peer(
            std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 4)),
            Peer::Silent,
        )
        .with_name("v4.test", &[[127, 0, 0, 1].into()]);
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), clock)
}

/// A connection established before the next attempt was due leaves no
/// wait for that attempt behind (`Curl_expire_done`, HAPPY_EYEBALLS).
#[test]
fn an_established_connection_forgets_the_next_attempt() {
    use crate::conn::io::{Conversation, Peer};
    let clock = ManualClock::new().unwrap();
    let v6 = std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 7));
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
    let net = FakeNet::new(clock.clone())
        .with_peer(v6, Peer::AcceptsAfter(Duration::from_millis(5)))
        .with_peer(([127, 0, 0, 1], 7).into(), Peer::Accepts)
        .with_conversation(v6, Conversation::new(head, false));
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    m.add(Box::new(easy("http://localhost:7/")), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    let next = Some(Duration::from_millis(200));
    assert_eq!(m.timeout(), next, "the next attempt's");
    clock.advance(Duration::from_millis(5));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.timeout(), None, "the body still to come");
}

/// A transfer driven through `socket_action` alone, watching only what
/// the multi tells its timer and socket callbacks, ends as one driven by
/// waits on the multi's own sockets, at the same time
/// (`curl_easy_perform_ev`). A socket announced for the wrong events, or
/// not at all, leaves it waiting until its time runs out.
#[test]
fn events_drive_a_transfer_as_waits_do() {
    use crate::conn::io::{Conversation, Peer};
    let run = |by_events: bool| {
        let clock = ManualClock::new().unwrap();
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 7));
        let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::AcceptsAfter(Duration::from_millis(5)))
            .with_conversation(at, Conversation::new(reply, false));
        let env = Env {
            clock: Box::new(clock.clone()),
            net: Box::new(net),
            arena: ArenaPolicy::new(16, 0).unwrap(),
            waker: None,
        };
        let mut m: Multi = Multi::new(env).unwrap();
        let mut e = easy("http://127.0.0.1:7/");
        e.options_mut().limits.total = TimeLimit::from_millis(1000);
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        let start = clock.now();
        let result = if by_events {
            drive_by_events(&mut m, id)
        } else {
            drive_to_completion(&mut m, id, &mut NoEvents)
        };
        let took = clock.now().since(start);
        let easy = m.remove(id, &mut NoEvents).unwrap().easy;
        let report = easy.report();
        (
            result,
            report.response_code(),
            report.sizes().download(),
            took,
        )
    };
    let waited = run(false);
    assert_eq!(waited, (Ok(Ok(())), Some(200), 3, Duration::from_millis(5)));
    assert_eq!(run(true), waited);
}

/// A network whose peers hang up once the multi waits for them, and that
/// fails a run polling over and over without waiting.
struct Patient {
    net: FakeNet,
    opened: Vec<crate::conn::io::SocketKey>,
    hurried: u32,
}

impl Net for Patient {
    fn poll(
        &mut self,
        sockets: &mut [crate::conn::io::SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> std::io::Result<u32> {
        if timeout.is_zero() {
            self.hurried += 1;
            assert!(self.hurried < 10, "polled again and again without waiting");
        } else if !sockets.is_empty() {
            for &key in &self.opened {
                self.net.hang_up(key);
            }
        }
        // As long as a fake clock goes.
        self.net
            .poll(sockets, fds, timeout.min(Duration::from_secs(3600)))
    }

    fn connect(
        &mut self,
        addr: std::net::SocketAddr,
        options: crate::conn::io::SocketOptions,
    ) -> std::io::Result<(Box<dyn crate::conn::io::Socket>, crate::conn::io::Connect)> {
        let (socket, connect) = self.net.connect(addr, options)?;
        self.opened.push(socket.key());
        Ok((socket, connect))
    }

    fn close(&mut self, socket: Box<dyn crate::conn::io::Socket>) {
        self.net.close(socket);
    }

    fn resolve(
        &mut self,
        name: &[u8],
        family: crate::conn::io::Family,
    ) -> Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure> {
        self.net.resolve(name, family)
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.net.link_local_scope()
    }
}

/// With nothing due, a transfer driven by events waits for its socket for
/// as long as it takes: after the timer ran out with no new one set, it
/// does not poll without waiting until the socket is ready.
#[test]
fn events_wait_for_a_socket_with_nothing_due() {
    use crate::conn::io::{Conversation, Peer};
    let clock = ManualClock::new().unwrap();
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 7));
    // A peer that never answers, until it hangs up.
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, Conversation::replies(&[], false));
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(Patient {
            net,
            opened: Vec::new(),
            hurried: 0,
        }),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let id = m
        .add(Box::new(easy("http://127.0.0.1:7/")), (), &mut NoEvents)
        .unwrap();
    assert_eq!(drive_by_events(&mut m, id), Ok(Err(ErrorKind::GotNothing)));
}

/// Driven by events, a transfer's timers are waited for as the multi
/// sets them: one with no socket to watch sleeps until its time is up,
/// and one whose socket stays silent until its connect timeout, neither
/// woken late (`curl_easy_perform_ev`'s timer callback).
#[test]
fn events_wait_for_the_timer_the_multi_sets() {
    let (mut m, clock) = networked();
    let mut e = easy("stall://a");
    e.options_mut().limits.total = crate::time::TimeLimit::from_millis(1000);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let start = clock.now();
    assert_eq!(
        drive_by_events(&mut m, id),
        Ok(Err(ErrorKind::OperationTimedout))
    );
    assert_eq!(clock.now().since(start), Duration::from_millis(1000));
    let (mut m, clock) = networked();
    let mut e = easy("tcp://127.0.0.1:3/");
    e.options_mut().limits.connect = crate::time::TimeLimit::from_millis(700);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let start = clock.now();
    assert_eq!(
        drive_by_events(&mut m, id),
        Ok(Err(ErrorKind::OperationTimedout))
    );
    assert_eq!(clock.now().since(start), Duration::from_millis(700));
    // A socket ready part way through a wait leaves the rest of it to
    // count down, the timer not set again.
    let (mut m, clock) = networked();
    let mut e = easy("http://127.0.0.1:4/");
    e.options_mut().limits.total = crate::time::TimeLimit::from_millis(1000);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let start = clock.now();
    assert_eq!(
        drive_by_events(&mut m, id),
        Ok(Err(ErrorKind::OperationTimedout))
    );
    assert_eq!(clock.now().since(start), Duration::from_millis(1000));
}

/// A verbose transfer of `url`, and its trace.
fn traced(url: &str) -> (Easy, TextLines) {
    let mut e = easy(url);
    let lines = TextLines::default();
    e.options_mut().output.verbose = true;
    e.options_mut().callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    (e, lines)
}

/// Lines of the trace without the debug build's warning, which carries the
/// ids too when they are on.
fn trace_of(lines: &TextLines) -> Vec<String> {
    lines
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|l| {
            let text = l
                .strip_prefix('[')
                .and_then(|l| l.split_once("] "))
                .map_or(l.as_str(), |(_, text)| text);
            !text.starts_with("!!!") && !text.starts_with("This is a debug build")
        })
        .cloned()
        .collect()
}

/// A host name longer than 65535 bytes is refused before it is looked up,
/// as `Curl_peer_from_url` refuses it (test 399).
#[test]
fn a_host_name_too_long_is_refused() {
    let (mut m, _clock) = networked();
    let long = format!("http://{}/", "a".repeat(0x10000));
    let (e, lines) = traced(&long);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::UrlMalformat), 0)]
    );
    assert_eq!(trace_of(&lines), ["Too long hostname (maximum is 65535)\n"]);
    // One byte shorter goes on to be looked up.
    let (e, _) = traced(&format!("http://{}/", "a".repeat(0xffff)));
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_ne!(
        messages(&mut m)[0],
        (id.index(), Err(ErrorKind::UrlMalformat), 0)
    );
}

/// A connect refused is C's: the attempt's line, then the failure, then
/// the connection closed (test 1 run against a closed port).
#[test]
fn a_refused_connect_fails_as_c_says() {
    let (mut m, _clock) = networked();
    let (e, lines) = traced("tcp://127.0.0.1:2/");
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    // The socket is looked at as soon as the connect starts
    // (`cf_tcp_connect`): a refusal already there fails in the same pass.
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::CouldntConnect), 0)]
    );
    let why = "Failed to connect to 127.0.0.1:2 after 0 ms: Could not connect to server";
    assert_eq!(
        trace_of(&lines),
        [
            "  Trying 127.0.0.1:2...\n".to_owned(),
            "connect to 127.0.0.1 port 2 from 127.0.0.1 port 40000 failed: Connection refused\n"
                .to_owned(),
            format!("{why}\n"),
            "closing connection #0\n".to_owned(),
        ]
    );
    let easy = m.easy(id).unwrap();
    assert_eq!(easy.report().failure(), Some(why.as_bytes()));
    // The name was known at once, and no connection made. A time taken
    // at once counts as a microsecond (`Curl_pgrsTimeWas`).
    let t = easy.report().timings();
    assert_eq!(t.namelookup(), Duration::from_micros(1));
    assert_eq!(t.connect(), Duration::ZERO);
}

/// With the ids on, each line a transfer traces starts with its number
/// and its connection's, `x` for one it has none of; a failure's reason
/// does not (`trc_infof`, `Curl_failf`).
#[test]
fn the_ids_start_each_line_but_a_failure() {
    let (mut m, _clock) = networked();
    let (mut e, lines) = traced("tcp://127.0.0.1:2/");
    let components = crate::components::Components::new().unwrap();
    components.configure(b"lib-ids");
    e.set_components(Some(components.clone()));
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let why = "Failed to connect to 127.0.0.1:2 after 0 ms: Could not connect to server";
    assert_eq!(
        trace_of(&lines),
        [
            "[0-0]   Trying 127.0.0.1:2...\n".to_owned(),
            "[0-0] connect to 127.0.0.1 port 2 from 127.0.0.1 port 40000 failed: Connection refused\n"
                .to_owned(),
            format!("{why}\n"),
            "[0-0] closing connection #0\n".to_owned(),
        ]
    );
}

/// An accepted connect is traced, timed, and the request goes on.
#[test]
fn an_accepted_connect_goes_on_to_the_request() {
    let (mut m, clock) = networked();
    let (e, lines) = traced("tcp://127.0.0.1:4/");
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.counts().running, 1);
    // The wait ends when the peer answers.
    let start = clock.now();
    let ready = m.wait(&mut [], Duration::from_secs(1), WaitMode::Wait);
    assert_eq!(ready, Ok(1));
    assert_eq!(clock.now().since(start), Duration::from_millis(5));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(id.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines),
        [
            "  Trying 127.0.0.1:4...\n",
            "Established connection to 127.0.0.1 (127.0.0.1 port 4) from 127.0.0.1 port 40000 \n",
            "Connection #0 to host 127.0.0.1:4 left intact\n",
        ]
    );
    let t = m.easy(id).unwrap().report().timings();
    assert_eq!(t.namelookup(), Duration::from_micros(1));
    assert_eq!(t.connect(), Duration::from_millis(5));
}

/// A peer that never answers times out at the connect limit, which the
/// multi's timeout and `wait` bring about, polling the socket meanwhile.
#[test]
fn a_silent_peer_times_out_at_the_connect_limit() {
    let (mut m, clock) = networked();
    let (mut e, lines) = traced("tcp://127.0.0.1:3/");
    e.options_mut().limits.connect = TimeLimit::from_millis(1500);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let start = clock.now();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.timeout(), Some(Duration::from_millis(1500)));
    // The wait polls the connecting socket: nothing is ready, so the
    // fake moves the clock by the whole timeout.
    assert_eq!(
        m.wait(&mut [], Duration::from_secs(10), WaitMode::Wait)
            .unwrap(),
        0
    );
    assert_eq!(clock.now().since(start), Duration::from_millis(1500));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::OperationTimedout), 0)]
    );
    // Timed from its first run to the timeout.
    let total = m.easy(id).unwrap().report().timings().total();
    assert_eq!(total, Duration::from_millis(1500));
    assert_eq!(
        trace_of(&lines),
        [
            "  Trying 127.0.0.1:3...\n",
            "Connection timed out after 1500 milliseconds\n",
            "closing connection #0\n",
        ]
    );
}

/// A host with no address, and one whose connect fails before any poll.
#[test]
fn unresolved_and_immediate_failures() {
    let (mut m, _clock) = networked();
    let (named, named_lines) = traced("tcp://example.com:80/");
    let named = m.add(Box::new(named), (), &mut NoEvents).unwrap();
    let (nobody, nobody_lines) = traced("tcp://[::1]:9/");
    let nobody = m.add(Box::new(nobody), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        messages(&mut m),
        [
            (named.index(), Err(ErrorKind::CouldntResolveHost), 1),
            (nobody.index(), Err(ErrorKind::CouldntConnect), 0)
        ]
    );
    assert_eq!(
        trace_of(&named_lines),
        [
            "Could not resolve host: example.com (Domain name not found)\n",
            "Could not resolve host: example.com\n",
            "Could not resolve: example.com:80\n",
            "closing connection #0\n",
        ]
    );
    assert_eq!(
        trace_of(&nobody_lines),
        [
            "  Trying [::1]:9...\n",
            "Immediate connect fail for ::1: Connection refused\n",
            "connect to ::1 port 9 from :: port 0 failed: Connection refused\n",
            "Failed to connect to ::1:9 after 0 ms: Could not connect to server\n",
            "closing connection #1\n",
        ]
    );
}

/// A transfer through proxies, `proxy` and `pre` the pre-proxy, set up
/// to fail: the error and the failure's first trace lines.
fn through_proxies(
    url: &str,
    proxy: &str,
    pre: Option<&str>,
    tunnel: bool,
    connect_to: Option<&str>,
) -> (Result<(), ErrorKind>, Vec<String>) {
    let (mut m, _clock) = networked();
    let (mut e, lines) = traced(url);
    let o = e.options_mut();
    o.proxy.make_mut().unwrap().url = Some(proxy.as_bytes().to_vec());
    o.proxy.make_mut().unwrap().pre_proxy = pre.map(|p| p.as_bytes().to_vec());
    o.proxy.make_mut().unwrap().tunnel = tunnel;
    if let Some(to) = connect_to {
        o.connect_to.set([to.as_bytes()]).unwrap();
    }
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    for _ in 0..4 {
        m.perform(&mut NoEvents).unwrap();
        m.wait(&mut [], Duration::from_secs(1), WaitMode::Wait)
            .unwrap();
    }
    let done = messages(&mut m);
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(done[0].0, id.index());
    let failure = trace_of(&lines)
        .into_iter()
        .filter(|l| l.starts_with("Could not resolve") || l.starts_with("Failed to connect"))
        .collect();
    (done[0].1, failure)
}

/// A proxy whose name is not found is the name the failure gives, with
/// its port, whatever its kind; the first of two, the pre-proxy, is the
/// one looked up first (`Curl_conn_get_first_peer`, test with the C
/// build's `-x socks5://nonexist.invalid`).
#[test]
fn an_unresolved_proxy_is_named_in_the_failure() {
    let names = |port| {
        [
            "Could not resolve proxy: example.com (Domain name not found)\n".to_string(),
            "Could not resolve proxy: example.com\n".to_string(),
            format!("Could not resolve: example.com:{port}\n"),
        ]
    };
    let url = "http://v4.test:1/";
    for kind in ["socks4", "socks4a", "socks5", "socks5h"] {
        for tunnel in [false, true] {
            let proxy = format!("{kind}://example.com");
            let ran = through_proxies(url, &proxy, None, tunnel, None);
            assert_eq!(
                ran,
                (Err(ErrorKind::CouldntResolveProxy), names(1080).to_vec()),
                "{proxy}"
            );
        }
    }
    for tunnel in [false, true] {
        let ran = through_proxies(url, "http://example.com", None, tunnel, None);
        assert_eq!(
            ran,
            (Err(ErrorKind::CouldntResolveProxy), names(80).to_vec())
        );
        let pre = Some("socks5://example.com");
        let ran = through_proxies(url, "http://127.0.0.1:2", pre, tunnel, None);
        assert_eq!(
            ran,
            (Err(ErrorKind::CouldntResolveProxy), names(1080).to_vec())
        );
    }
}

/// A connection to a proxy that fails names the origin, then the proxy
/// it went over: the SOCKS one, which is first when there are two; a
/// connect-to's peer is never shown with a proxy, which is connected to
/// in its place (`cf_ip_happy_connect`, against the C build).
#[test]
fn a_failed_connect_names_the_first_proxy() {
    let failed = |what: &str| {
        (
            Err(ErrorKind::CouldntConnect),
            vec![format!(
                "Failed to connect to {what} after 0 ms: Could not connect to server\n"
            )],
        )
    };
    let url = "http://v4.test:1/";
    let pre = Some("socks5://127.0.0.1:2");
    let ran = through_proxies(url, "http://v4.test:3", pre, false, None);
    assert_eq!(ran, failed("v4.test:3 over proxy 127.0.0.1"));
    let ran = through_proxies(url, "http://v4.test:3", pre, true, None);
    assert_eq!(ran, failed("v4.test:1 over proxy 127.0.0.1"));
    let to = Some("::127.0.0.1:1");
    for (proxy, tunnel) in [
        ("http://127.0.0.1:2", true),
        ("socks5://127.0.0.1:2", false),
    ] {
        let ran = through_proxies(url, proxy, None, tunnel, to);
        assert_eq!(ran, failed("v4.test:1 over proxy 127.0.0.1"), "{proxy}");
    }
}

/// Removing a transfer while it connects closes its socket, traced to the
/// transfer as `multi_done` traces it.
#[test]
fn removing_a_connecting_transfer_closes_its_socket() {
    let (mut m, _clock) = networked();
    let (e, lines) = traced("tcp://127.0.0.1:3/");
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let mut open = 0;
    m.sockets(|_, _| open += 1);
    assert_eq!(open, 1);
    m.remove(id, &mut NoEvents).unwrap();
    let mut open = 0;
    m.sockets(|_, _| open += 1);
    assert_eq!(open, 0);
    assert_eq!(m.caches.pool.len(), 0);
    assert_eq!(
        trace_of(&lines),
        ["  Trying 127.0.0.1:3...\n", "closing connection #0\n"]
    );
    // So too when the multi goes with the transfer in it.
    let (e, lines) = traced("tcp://127.0.0.1:3/");
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    drop(m);
    assert_eq!(trace_of(&lines)[2], "closing connection #1\n");
}

/// A setup does not move on while receiving is paused
/// (`multistate_connecting`), and does once it is not.
#[test]
fn a_paused_transfer_does_not_connect() {
    let (mut m, clock) = networked();
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:4/")), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    let watched = |m: &Multi| {
        let mut watched = Vec::new();
        m.sockets(|s, e| watched.push((s.key().get(), e)));
        watched
    };
    assert_eq!(watched(&m), [(1000, Events::OUT)]);
    m.pause(id, PauseRequest::RECV, &mut NoEvents).unwrap();
    // Paused, it waits on nothing (`mstate_connecting_pollset`).
    assert_eq!(watched(&m), []);
    clock.advance(Duration::from_millis(10));
    // The peer answered, but the transfer is not told.
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.counts().running, 1);
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    assert_eq!(watched(&m), [(1000, Events::OUT)]);
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(id.index(), Ok(()), 0)]);
}

/// A transfer to the same host and port reuses the connection the last
/// one left, with neither a connect nor its times (`Curl_conn_connect`
/// returns at once); another port gets its own.
#[test]
fn the_next_transfer_reuses_the_connection_left() {
    let (mut m, clock) = networked();
    let (first, _) = traced("tcp://127.0.0.1:4/");
    let first = m.add(Box::new(first), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.wait(&mut [], Duration::from_secs(1), WaitMode::Wait)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(first.index(), Ok(()), 0)]);
    clock.advance(Duration::from_millis(7));
    let (second, lines) = traced("tcp://127.0.0.1:4/");
    let second = m.add(Box::new(second), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(second.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines),
        [
            "Reusing existing tcp: connection with host 127.0.0.1\n",
            "Connection #0 to host 127.0.0.1:4 left intact\n",
        ]
    );
    let t = m.easy(second).unwrap().report().timings();
    assert_eq!(
        (t.namelookup(), t.connect()),
        (Duration::ZERO, Duration::ZERO)
    );
    let (third, lines) = traced("tcp://127.0.0.1:1/");
    let third = m.add(Box::new(third), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(third.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines)[0],
        "  Trying 127.0.0.1:1...\n",
        "another port, another connection"
    );
    assert_eq!(
        trace_of(&lines)[2],
        "Connection #1 to host 127.0.0.1:1 left intact\n"
    );
    // Each transfer numbered as it joined the pool, and the connection
    // it used by the pool's number for it.
    let numbers = |id| {
        let r = m.easy(id).unwrap().report();
        (r.transfer_number(), r.conn_number())
    };
    assert_eq!(
        [first, second, third].map(numbers),
        [(Some(0), Some(0)), (Some(1), Some(0)), (Some(2), Some(1))]
    );
}

/// A network that counts the sockets it closes.
struct Closes(FakeNet, std::sync::Arc<AtomicU32>);

impl Net for Closes {
    fn poll(
        &mut self,
        sockets: &mut [crate::conn::io::SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> std::io::Result<u32> {
        self.0.poll(sockets, fds, timeout)
    }

    fn connect(
        &mut self,
        addr: std::net::SocketAddr,
        options: crate::conn::io::SocketOptions,
    ) -> std::io::Result<(Box<dyn crate::conn::io::Socket>, crate::conn::io::Connect)> {
        self.0.connect(addr, options)
    }

    fn close(&mut self, socket: Box<dyn crate::conn::io::Socket>) {
        self.1.fetch_add(1, Ordering::Relaxed);
        self.0.close(socket);
    }

    fn resolve(
        &mut self,
        name: &[u8],
        family: crate::conn::io::Family,
    ) -> Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure> {
        self.0.resolve(name, family)
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.0.link_local_scope()
    }
}

/// One network behind several owners: a share and the multis whose
/// transfers use its connections.
struct OneNet(std::sync::Arc<std::sync::Mutex<Closes>>);

impl Net for OneNet {
    fn poll(
        &mut self,
        sockets: &mut [crate::conn::io::SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> std::io::Result<u32> {
        self.0.lock().unwrap().poll(sockets, fds, timeout)
    }

    fn connect(
        &mut self,
        addr: std::net::SocketAddr,
        options: crate::conn::io::SocketOptions,
    ) -> std::io::Result<(Box<dyn crate::conn::io::Socket>, crate::conn::io::Connect)> {
        self.0.lock().unwrap().connect(addr, options)
    }

    fn close(&mut self, socket: Box<dyn crate::conn::io::Socket>) {
        self.0.lock().unwrap().close(socket);
    }

    fn resolve(
        &mut self,
        name: &[u8],
        family: crate::conn::io::Family,
    ) -> Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure> {
        self.0.lock().unwrap().resolve(name, family)
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.0.lock().unwrap().link_local_scope()
    }
}

/// Handles given one share that keeps connections use one connection,
/// in multis of their own: it outlives the multi that made it, and closes
/// with the share (`curl_share_cleanup`). Each use of the share's pool is
/// one the application is told of, where C locks it (test 1554): as a
/// transfer joins, searches, adds a connection and gives it back.
#[test]
fn a_share_keeps_connections_across_handles() {
    use crate::conn::io::Peer;
    use crate::share::{Kind, Share, Told};
    let clock = ManualClock::new().unwrap();
    let closed = std::sync::Arc::new(AtomicU32::new(0));
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let net = std::sync::Arc::new(std::sync::Mutex::new(Closes(
        FakeNet::new(clock.clone()).with_peer(at, Peer::Accepts),
        closed.clone(),
    )));
    let env = || Env {
        clock: Box::new(clock.clone()),
        net: Box::new(OneNet(net.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let share = Share::with_net(Box::new(OneNet(net.clone()))).unwrap();
    share.keep(Kind::Connections).unwrap();
    let told = Told::new(&share);
    let mut connects = Vec::new();
    let mut uses = Vec::new();
    let mut numbers = Vec::new();
    for _ in 0..2 {
        let mut m: Multi = Multi::new(env()).unwrap();
        let mut e = easy("tcp://127.0.0.1:1/");
        e.set_share_watched(share.clone(), told.handler());
        e.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
        connects.push(e.report().connects());
        uses.push(told.uses());
        numbers.push((e.report().transfer_number(), e.report().conn_number()));
        drop(m);
    }
    assert_eq!(connects, [1, 0], "the second reused the first's");
    // Numbered by the share's pool, whatever their multis.
    assert_eq!(numbers, [(Some(0), Some(0)), (Some(1), Some(0))]);
    // Joined, searched, added and given back; then the same but added.
    let c = Kind::Connections;
    assert_eq!(uses, [vec![c; 4], vec![c; 3]], "the second added none");
    assert_eq!(closed.load(Ordering::Relaxed), 0, "kept by the share");
    // A handle whose share keeps no connections uses its multi's.
    let other = Share::new().unwrap();
    let mut e = easy("tcp://127.0.0.1:1/");
    e.set_share_watched(other, told.handler());
    e.perform_in(&mut Multi::new(env()).unwrap(), crate::easy::Drive::Waits)
        .unwrap();
    assert_eq!(e.report().connects(), 1);
    let numbers = (e.report().transfer_number(), e.report().conn_number());
    assert_eq!(numbers, (Some(0), Some(0)), "numbered by its multi's");
    assert_eq!(told.uses(), [], "none told of");
    assert_eq!(closed.load(Ordering::Relaxed), 1, "closed with its multi");
    // The watch held a clone of it.
    drop((e, told, share));
    assert_eq!(closed.load(Ordering::Relaxed), 2, "closed with the share");
}

/// A connection of a share's pool that a transfer does not give back,
/// for it may not be reused, is closed through the transfer's network
/// once the transfer is done with the pool: at once, not with the share.
#[test]
fn a_share_s_connection_not_kept_is_closed_at_once() {
    use crate::conn::io::Peer;
    use crate::share::{Kind, Share};
    let clock = ManualClock::new().unwrap();
    let closed = std::sync::Arc::new(AtomicU32::new(0));
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let net = std::sync::Arc::new(std::sync::Mutex::new(Closes(
        FakeNet::new(clock.clone()).with_peer(at, Peer::Accepts),
        closed.clone(),
    )));
    let env = || Env {
        clock: Box::new(clock.clone()),
        net: Box::new(OneNet(net.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let share = Share::with_net(Box::new(OneNet(net.clone()))).unwrap();
    share.keep(Kind::Connections).unwrap();
    let mut m: Multi = Multi::new(env()).unwrap();
    let mut e = easy("tcp://127.0.0.1:1/");
    e.set_share(Some(share.clone()));
    e.options_mut().limits.reuse.forbid = true;
    e.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
    assert_eq!(closed.load(Ordering::Relaxed), 1, "closed as given back");
}

/// The connections left idle are closed with their multi
/// (`Curl_cpool_destroy`).
#[test]
fn a_multi_closes_its_idle_connections_when_dropped() {
    use crate::conn::io::Peer;
    let clock = ManualClock::new().unwrap();
    let closed = std::sync::Arc::new(AtomicU32::new(0));
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let net = Closes(
        FakeNet::new(clock.clone()).with_peer(at, Peer::Accepts),
        closed.clone(),
    );
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:1/")), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(id.index(), Ok(()), 0)]);
    assert_eq!(closed.load(Ordering::Relaxed), 0, "kept");
    drop(m);
    assert_eq!(closed.load(Ordering::Relaxed), 1);
}

/// C names an IPv6 host with its brackets where it shows the URL's host,
/// and without where it names the host itself: "Reusing existing" and
/// the connect failure.
#[test]
fn an_ipv6_host_is_named_as_c_names_it() {
    let (mut m, _clock) = networked();
    let (first, lines) = traced("tcp://[::1]:1/");
    let first = m.add(Box::new(first), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(first.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines),
        [
            "  Trying [::1]:1...\n",
            "Established connection to [::1] (::1 port 1) from ::1 port 40000 \n",
            "Connection #0 to host [::1]:1 left intact\n",
        ]
    );
    let (second, lines) = traced("tcp://[::1]:1/");
    let second = m.add(Box::new(second), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(second.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines),
        [
            "Reusing existing tcp: connection with host ::1\n",
            "Connection #0 to host [::1]:1 left intact\n",
        ]
    );
}

/// `localhost` and the names under it are the loopback addresses, IPv6
/// first, reported as C reports a resolved name; each refused address
/// is traced, and the setup fails once none is left.
#[test]
fn localhost_names_are_the_loopback_addresses() {
    let (mut m, _clock) = networked();
    let (refused, lines) = traced("tcp://localhost:2/");
    let refused = m.add(Box::new(refused), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.wait(&mut [], Duration::from_secs(1), WaitMode::Wait)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.wait(&mut [], Duration::from_secs(1), WaitMode::Wait)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        messages(&mut m),
        [(refused.index(), Err(ErrorKind::CouldntConnect), 0)]
    );
    assert_eq!(
        trace_of(&lines)[..7],
        [
            "Host localhost:2 was resolved.\n",
            "IPv6: ::1\n",
            "IPv4: 127.0.0.1\n",
            "  Trying [::1]:2...\n",
            "connect to ::1 port 2 from ::1 port 40000 failed: Connection refused\n",
            "  Trying 127.0.0.1:2...\n",
            "connect to 127.0.0.1 port 2 from 127.0.0.1 port 40000 failed: Connection refused\n",
        ]
    );
    assert!(trace_of(&lines)[7].starts_with("Failed to connect to localhost:2 after "));
    let (named, lines) = traced("tcp://Foo.LocalHost.:1/");
    let named = m.add(Box::new(named), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(named.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines)[..5],
        [
            "Host Foo.LocalHost.:1 was resolved.\n",
            "IPv6: ::1\n",
            "IPv4: 127.0.0.1\n",
            "  Trying [::1]:1...\n",
            "Established connection to Foo.LocalHost. (::1 port 1) from ::1 port 40000 \n",
        ]
    );
}

/// An address that does not answer gives way to the next once the happy
/// eyeballs delay has passed: the transfer's timer wakes it then, and
/// the attempt that connects wins.
#[test]
fn a_silent_address_gives_way_after_the_eyeballs_delay() {
    let (mut m, clock) = networked();
    let (e, lines) = traced("tcp://localhost:4/");
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(trace_of(&lines).last().unwrap(), "  Trying [::1]:4...\n");
    assert_eq!(m.timeout(), Some(Duration::from_millis(200)));
    clock.advance(Duration::from_millis(199));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(trace_of(&lines).len(), 4, "not yet");
    clock.advance(Duration::from_millis(1));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(trace_of(&lines)[4], "  Trying 127.0.0.1:4...\n");
    clock.advance(Duration::from_millis(5));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(id.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines)[5],
        "Established connection to localhost (127.0.0.1 port 4) from 127.0.0.1 port 40001 \n"
    );
}

/// `e` tracing `components`.
fn tracing(mut e: Easy, components: &[u8]) -> Easy {
    let c = crate::components::Components::new().unwrap();
    c.configure(components);
    e.set_components(Some(c));
    e
}

/// The race traced as C's happy eyeballs filter traces it: each attempt
/// as it starts, the first or the next, the delay armed for the next
/// while an address is left, and the winner by its place among those
/// running. The C build traces the same lines connecting to a silent
/// IPv6 address and a listening IPv4 one.
#[test]
fn the_race_is_traced_as_c_s_happy_eyeballs() {
    let (mut m, clock) = networked();
    let (e, lines) = traced("tcp://localhost:4/");
    let e = tracing(e, b"happy-eyeballs,timer");
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    clock.advance(Duration::from_millis(200));
    m.perform(&mut NoEvents).unwrap();
    clock.advance(Duration::from_millis(5));
    m.perform(&mut NoEvents).unwrap();
    let raced: Vec<_> = trace_of(&lines)
        .into_iter()
        .filter(|l| {
            l.starts_with("[HAPPY-EYEBALLS]")
                || l.starts_with("[TIMER] [HAPPY")
                || l.contains("Trying")
        })
        .collect();
    assert_eq!(
        raced,
        [
            "[HAPPY-EYEBALLS] starting first attempt for ipv6 -> 0\n",
            "  Trying [::1]:4...\n",
            "[HAPPY-EYEBALLS] next HAPPY_EYEBALLS timeout in 200ms\n",
            "[TIMER] [HAPPY_EYEBALLS] set for 200000us\n",
            "[HAPPY-EYEBALLS] happy eyeballs timeout expired, start next attempt\n",
            "[HAPPY-EYEBALLS] starting next attempt for ipv4 -> 0\n",
            "  Trying 127.0.0.1:4...\n",
            "[HAPPY-EYEBALLS] connect attempt #1 successful\n",
            "[HAPPY-EYEBALLS] Connected to localhost (127.0.0.1) port 4\n",
            "[TIMER] [HAPPY_EYEBALLS] cleared\n",
        ]
    );
}

/// The last attempt failing ends the race, said between the attempt's
/// failure and the transfer's.
#[test]
fn a_race_with_no_attempt_left_says_so() {
    let (mut m, _clock) = networked();
    let (e, lines) = traced("tcp://127.0.0.1:2/");
    let e = tracing(e, b"happy-eyeballs");
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::CouldntConnect), 0)]
    );
    let lines = trace_of(&lines);
    let at = lines
        .iter()
        .position(|l| l == "[HAPPY-EYEBALLS] no more attempts to try\n")
        .unwrap();
    assert!(
        lines[at - 1].starts_with("connect to 127.0.0.1 port 2 from "),
        "{lines:?}"
    );
    assert!(
        lines[at + 1].starts_with("Failed to connect to 127.0.0.1:2 after "),
        "{lines:?}"
    );
    assert_eq!(
        lines[0],
        "[HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0\n"
    );
}

/// One transfer of `url` on `m`, tracing the DNS component: its lines
/// and the cache's, but the C debug build's `hostip_resolv` line, which
/// starts each lookup and is checked apart.
fn dns_lines(m: &mut Multi, url: &str, set: impl FnOnce(&mut Options)) -> Vec<String> {
    let (mut e, lines) = traced(url);
    // A connection of its own, the name looked up again.
    e.options_mut().limits.reuse.fresh = true;
    set(e.options_mut());
    let e = tracing(e, b"dns");
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.remove(id, &mut NoEvents).unwrap();
    let lines = trace_of(&lines);
    let starts = lines
        .iter()
        .filter(|l| l.contains("] hostip_resolv("))
        .count();
    let lookups = lines.iter().filter(|l| l.contains("cache lookup")).count();
    let debug_build = cfg!(feature = "debug-hooks");
    assert_eq!(starts, if debug_build { lookups } else { 0 }, "{lines:?}");
    lines
        .into_iter()
        .filter(|l| {
            (l.starts_with("[DNS]") && !l.contains("] hostip_resolv("))
                || l.starts_with("Hostname")
                || l.starts_with("Negative")
        })
        .map(|l| l.trim_end().to_owned())
        .collect()
}

/// The DNS component traces the cache as C's does: each lookup, what
/// answered a name it did not have and its keeping, the queries named
/// as the IP version and an address's own family make them.
#[test]
fn the_dns_cache_is_traced_as_c_looks_in_it() {
    let (mut m, _clock) = networked();
    assert_eq!(
        dns_lines(&mut m, "tcp://v4.test:1/", |_| {}),
        [
            "[DNS] cache lookup v4.test:1 queries=A+AAAA -> 0 not found",
            "[DNS] [A+AAAA] hostip_resolv started -> 81",
            "[DNS] [A+AAAA] resolve complete for v4.test:1",
            "[DNS] cached entry for v4.test:1 queries=A+AAAA",
        ]
    );
    assert_eq!(
        dns_lines(&mut m, "tcp://v4.test:1/", |_| {}),
        [
            "[DNS] cache lookup v4.test:1 queries=A+AAAA -> 0 found",
            "Hostname v4.test was found in DNS cache",
        ]
    );
    assert_eq!(
        dns_lines(&mut m, "tcp://127.0.0.1:1/", |o| o.ip_version =
            IpVersion::V6),
        [
            "[DNS] cache lookup 127.0.0.1:1 queries=A+AAAA -> 0 not found",
            "[DNS] [A+AAAA] hostip_resolv started -> 0",
            "[DNS] cached entry for 127.0.0.1:1 queries=A+AAAA",
        ]
    );
    assert_eq!(
        dns_lines(&mut m, "tcp://localhost:1/", |o| o.ip_version =
            IpVersion::V4),
        [
            "[DNS] cache lookup localhost:1 queries=A -> 0 not found",
            "[DNS] [A] hostip_resolv started -> 0",
            "[DNS] cached entry for localhost:1 queries=A",
        ]
    );
}

/// A name the resolver says no to is kept so, and found so the next
/// time; a stale answer is said to be, then resolved again.
#[test]
fn the_dns_cache_traces_what_it_keeps_and_lets_go() {
    let (mut m, clock) = networked();
    assert_eq!(
        dns_lines(&mut m, "tcp://example.com:80/", |_| {}),
        [
            "[DNS] cache lookup example.com:80 queries=A+AAAA -> 0 not found",
            "[DNS] [A+AAAA] hostip_resolv started -> 81",
            "[DNS] cache negative name resolve for example.com:80 type=A+AAAA",
        ]
    );
    assert_eq!(
        dns_lines(&mut m, "tcp://example.com:80/", |_| {}),
        [
            "[DNS] cache entry does not have type=A+AAAA addresses",
            "[DNS] cache lookup example.com:80 queries=A+AAAA -> 6 not found",
            "Negative DNS entry",
        ]
    );
    dns_lines(&mut m, "tcp://v4.test:1/", |_| {});
    clock.advance(Duration::from_secs(61));
    assert_eq!(
        dns_lines(&mut m, "tcp://v4.test:1/", |_| {}),
        [
            "Hostname in DNS cache was stale, zapped",
            "[DNS] cache lookup v4.test:1 queries=A+AAAA -> 0 not found",
            "[DNS] [A+AAAA] hostip_resolv started -> 81",
            "[DNS] [A+AAAA] resolve complete for v4.test:1",
            "[DNS] cached entry for v4.test:1 queries=A+AAAA",
        ]
    );
}

/// A resolve list is read into the multi's cache when the transfer
/// starts, once for each time it is set: the name then answers from the
/// cache, under the entry's name. Set again, it replaces what it gave.
#[test]
fn a_resolve_list_is_read_once_for_each_setting() {
    let (mut m, _clock) = networked();
    let (mut e, lines) = traced("tcp://Foo.Test:1/");
    e.options_mut()
        .resolve
        .set([&b"foo.test:1:127.0.0.1"[..]])
        .unwrap();
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(id.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines)[..6],
        [
            "[DNS] added foo.test:1:127.0.0.1 to cache\n",
            "Hostname Foo.Test was found in DNS cache\n",
            "Host foo.test:1 was resolved.\n",
            "IPv6: (none)\n",
            "IPv4: 127.0.0.1\n",
            "  Trying 127.0.0.1:1...\n",
        ]
    );
    // The same handle again: the list was read.
    let e = m.remove(id, &mut NoEvents).unwrap().easy;
    lines.0.lock().unwrap().clear();
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(id.index(), Ok(()), 0)]);
    assert!(
        !trace_of(&lines).iter().any(|l| l.starts_with("[DNS]")),
        "not read again: {:?}",
        trace_of(&lines)
    );
    let mut e = m.remove(id, &mut NoEvents).unwrap().easy;
    lines.0.lock().unwrap().clear();
    e.options_mut().set_url(Some(b"tcp://foo.test:1/")).unwrap();
    e.options_mut()
        .resolve
        .set([&b"foo.test:1:[::1]"[..], b"*:1:127.0.0.1"])
        .unwrap();
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        trace_of(&lines)[..5],
        [
            "RESOLVE foo.test:1 - old addresses discarded\n",
            "[DNS] added foo.test:1:[::1] to cache\n",
            "[DNS] added *:1:127.0.0.1 to cache\n",
            "RESOLVE *:1 using wildcard\n",
            // The connection kept serves the same peer, whatever its
            // addresses now are.
            "Reusing existing tcp: connection with host foo.test\n",
        ]
    );
    // Any other name on the port is the wildcard's.
    let mut e = m.remove(id, &mut NoEvents).unwrap().easy;
    lines.0.lock().unwrap().clear();
    e.options_mut()
        .set_url(Some(b"tcp://other.test:1/"))
        .unwrap();
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m).last().unwrap().1, Ok(()));
    assert_eq!(
        trace_of(&lines)[..2],
        [
            "Hostname other.test was found in DNS cache\n",
            "Host *:1 was resolved.\n",
        ]
    );
    m.remove(id, &mut NoEvents).unwrap();
}

/// An answer older than the cache's timeout is not used: one found stale
/// is dropped, and a transfer's end drops those gone stale by then.
#[test]
fn stale_answers_are_dropped() {
    let (mut m, clock) = networked();
    let run = |m: &mut Multi, url: &str| {
        let (e, lines) = traced(url);
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        m.wait(&mut [], Duration::from_secs(1), WaitMode::Wait)
            .unwrap();
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(messages(m).last().unwrap().1, Ok(()));
        m.remove(id, &mut NoEvents).unwrap();
        trace_of(&lines)
    };
    // Each step waits out the idle connection's time too (118 seconds),
    // so that the name is looked up again.
    let wait = Duration::from_secs(119);
    run(&mut m, "tcp://localhost:1/");
    clock.advance(wait);
    let again = run(&mut m, "tcp://localhost:1/");
    let zapped = "Hostname in DNS cache was stale, zapped\n".to_string();
    assert!(again.contains(&zapped), "{again:?}");
    clock.advance(wait);
    // The end of this transfer drops `localhost:1`'s answer, so the next
    // finds nothing kept.
    run(&mut m, "tcp://127.0.0.1:4/");
    let pruned = run(&mut m, "tcp://localhost:1/");
    assert!(!pruned.contains(&zapped), "{pruned:?}");
    assert!(pruned.contains(&"Host localhost:1 was resolved.\n".to_string()));
}

/// A name neither the cache nor the shortcuts know is asked of the
/// resolver; that it does not exist is kept, for the family asked, and
/// told from the cache after (`fetch_entry`, `Curl_async_failed`).
#[test]
fn the_resolver_s_answers_are_kept() {
    let (mut m, _clock) = networked();
    let mut run = |url: &str, ip| {
        let (mut e, lines) = traced(url);
        e.options_mut().ip_version = ip;
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        let result = messages(&mut m).last().map(|r| r.1);
        m.remove(id, &mut NoEvents).unwrap();
        (result, trace_of(&lines))
    };
    let failed = Some(Err(ErrorKind::CouldntResolveHost));
    let (result, lines) = run("tcp://nowhere.test:1/", IpVersion::Any);
    assert_eq!(result, failed);
    assert_eq!(
        lines,
        [
            "Could not resolve host: nowhere.test (Domain name not found)\n",
            "Could not resolve host: nowhere.test\n",
            "Could not resolve: nowhere.test:1\n",
            "closing connection #0\n",
        ]
    );
    let (result, lines) = run("tcp://nowhere.test:1/", IpVersion::Any);
    assert_eq!(result, failed);
    assert_eq!(
        lines,
        [
            "Negative DNS entry\n",
            "Could not resolve host: nowhere.test\n",
            "Could not resolve: nowhere.test:1\n",
            "Could not resolve: nowhere.test\n",
            "closing connection #1\n",
        ]
    );
    // No IPv6 address: kept as such, which says nothing of IPv4.
    let (result, lines) = run("tcp://v4.test:1/", IpVersion::V6);
    assert_eq!(result, failed);
    let no_data = "Could not resolve host: v4.test (DNS server returned answer with no data)\n";
    assert_eq!(lines[0], no_data);
    let (result, lines) = run("tcp://v4.test:1/", IpVersion::Any);
    assert_eq!(result, Some(Ok(())));
    assert_eq!(
        lines[..3],
        [
            "Host v4.test:1 was resolved.\n",
            "IPv6: (none)\n",
            "IPv4: 127.0.0.1\n"
        ]
    );
    // An answer for both answers for one.
    let (result, lines) = run("tcp://v4.test:1/", IpVersion::V4);
    assert_eq!(result, Some(Ok(())));
    assert_eq!(lines[0], "Hostname v4.test was found in DNS cache\n");
}

/// A transfer may keep answers for ever (`CURLOPT_DNS_CACHE_TIMEOUT` of
/// -1): neither its lookup nor its end finds them stale.
#[test]
fn answers_may_be_kept_for_ever() {
    let (mut m, clock) = networked();
    let run = |m: &mut Multi, url: &str| {
        let (mut e, lines) = traced(url);
        e.options_mut().limits.reuse.dns_max_age = None;
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        m.wait(&mut [], Duration::from_secs(1), WaitMode::Wait)
            .unwrap();
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(messages(m).last().unwrap().1, Ok(()));
        m.remove(id, &mut NoEvents).unwrap();
        trace_of(&lines)
    };
    run(&mut m, "tcp://localhost:1/");
    clock.advance(Duration::from_secs(119));
    // Its end would drop what has gone stale.
    run(&mut m, "tcp://127.0.0.1:4/");
    let again = run(&mut m, "tcp://localhost:1/");
    assert_eq!(again[0], "Hostname localhost was found in DNS cache\n");
}

/// An entry the list cannot be read with fails the transfer, and the list
/// is read again by the next.
#[test]
fn a_bad_resolve_entry_fails_the_transfer() {
    let (mut m, _clock) = networked();
    let (mut e, lines) = traced("tcp://foo.test:1/");
    e.options_mut()
        .resolve
        .set([&b"foo.test:1:127.0.0.1,example.com"[..]])
        .unwrap();
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::SetoptOptionSyntax), 0)]
    );
    assert_eq!(
        trace_of(&lines),
        [
            "Resolve IP address 'example.com' found is illegal\n",
            "Could not parse CURLOPT_RESOLVE entry 'foo.test:1:127.0.0.1,example.com'\n",
        ]
    );
    let e = m.remove(id, &mut NoEvents).unwrap().easy;
    lines.0.lock().unwrap().clear();
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::SetoptOptionSyntax), 0)]
    );
    m.remove(id, &mut NoEvents).unwrap();
}

/// A transfer that leaves the pool over the multi's limit says so before
/// it keeps its connection, the idle one longest unused closed
/// (`cpool_conn_now_idle`).
#[test]
fn a_full_pool_is_traced_by_the_transfer_filling_it() {
    let (mut m, _clock) = networked();
    m.conn_limits_mut().max_connects = NonZeroU32::new(1);
    let (a, a_lines) = traced("tcp://127.0.0.1:1/");
    let (b, b_lines) = traced("tcp://localhost:1/");
    m.add(Box::new(a), (), &mut NoEvents).unwrap();
    m.add(Box::new(b), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.counts().running, 0);
    assert_eq!(
        trace_of(&a_lines).last().unwrap(),
        "Connection #0 to host 127.0.0.1:1 left intact\n"
    );
    let b_lines = trace_of(&b_lines);
    assert_eq!(
        b_lines[b_lines.len() - 2..],
        [
            "Connection pool is full, closing the oldest of 2/1\n",
            "Connection #1 to host localhost:1 left intact\n",
        ]
    );
    assert_eq!(m.caches.pool.len(), 1);
}

/// A transfer whose connection the full pool closes as it comes back has
/// no connection left to name (`Curl_cpool_return`'s `last_conn_id` of
/// -1); one still setting up names its own.
#[test]
fn a_connection_closed_as_it_comes_back_is_no_one_s() {
    let (mut m, _clock) = networked();
    m.conn_limits_mut().max_connects = NonZeroU32::new(1);
    let a = m
        .add(Box::new(easy("tcp://127.0.0.1:3/")), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    let (b, lines) = traced("tcp://127.0.0.1:1/");
    let b = m.add(Box::new(b), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(b.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines).last().unwrap(),
        "Connection pool is full, closing the oldest of 2/1\n"
    );
    assert_eq!(m.easy(b).unwrap().report().conn_number(), None);
    assert_eq!(m.easy(a).unwrap().report().conn_number(), Some(0));
    m.remove(a, &mut NoEvents).unwrap();
}

/// A transfer that forbids reuse closes its connection when done with it,
/// and one that wants a fresh one does not look for an idle one
/// (`multi_conn_should_close`, `reuse_fresh`).
#[test]
fn a_transfer_can_refuse_to_share_its_connection() {
    let (mut m, _clock) = networked();
    let mut run = |forbid, fresh| {
        let (mut e, lines) = traced("tcp://127.0.0.1:1/");
        e.options_mut().limits.reuse.forbid = forbid;
        e.options_mut().limits.reuse.fresh = fresh;
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        m.remove(id, &mut NoEvents).unwrap();
        trace_of(&lines)
    };
    let closed = run(true, false);
    assert_eq!(closed.last().unwrap(), "shutting down connection #0\n");
    run(false, false);
    let fresh = run(false, true);
    assert_eq!(
        fresh[..2],
        [
            "Hostname 127.0.0.1 was found in DNS cache\n",
            "  Trying 127.0.0.1:1...\n"
        ]
    );
    assert_eq!(
        fresh.last().unwrap(),
        "Connection #2 to host 127.0.0.1:1 left intact\n"
    );
    assert_eq!(m.caches.pool.len(), 2, "#1 kept too");
}

/// A transfer that would pass the host limit waits, running not at all,
/// until a connection is given back; then it looks again, and reuses it
/// (`multistate_connect`, `multi_schedule_pending`).
#[test]
fn a_transfer_waits_for_room_under_the_host_limit() {
    let (mut m, clock) = networked();
    m.conn_limits_mut().max_host = NonZeroU32::new(1);
    let (a, a_lines) = traced("tcp://127.0.0.1:4/");
    let (b, b_lines) = traced("tcp://127.0.0.1:4/");
    let a = m.add(Box::new(a), (), &mut NoEvents).unwrap();
    let b = m.add(Box::new(b), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        trace_of(&b_lines),
        ["No more connections allowed to host\n"]
    );
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        trace_of(&b_lines).len(),
        1,
        "it does not run while it waits"
    );
    assert_eq!(m.counts().running, 2);
    clock.advance(Duration::from_millis(5));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        trace_of(&a_lines).last().unwrap(),
        "Connection #0 to host 127.0.0.1:4 left intact\n"
    );
    assert_eq!(
        trace_of(&b_lines)[1..],
        [
            "Reusing existing tcp: connection with host 127.0.0.1\n",
            "Connection #0 to host 127.0.0.1:4 left intact\n",
        ]
    );
    assert_eq!(
        messages(&mut m),
        [(a.index(), Ok(()), 1), (b.index(), Ok(()), 0)]
    );
}

/// A waiting transfer reads its IP version as it looks again: changed to
/// IPv4 while it waits, it no longer takes the connection made for any
/// family and makes its own, as the C build does (`allocate_conn` reads
/// `set.ipver` for each look, `url_match_conn` compares it).
#[test]
fn a_waiting_transfer_reads_its_ip_version_as_it_looks_again() {
    let (mut m, clock) = networked();
    m.conn_limits_mut().max_host = NonZeroU32::new(1);
    let (a, _) = traced("tcp://127.0.0.1:4/");
    let (b, b_lines) = traced("tcp://127.0.0.1:4/");
    let a = m.add(Box::new(a), (), &mut NoEvents).unwrap();
    let b = m.add(Box::new(b), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        trace_of(&b_lines),
        ["No more connections allowed to host\n"]
    );
    m.easy_mut(b).unwrap().options_mut().ip_version = IpVersion::V4;
    clock.advance(Duration::from_millis(5));
    m.perform(&mut NoEvents).unwrap();
    clock.advance(Duration::from_millis(5));
    m.perform(&mut NoEvents).unwrap();
    let b_lines = trace_of(&b_lines);
    assert!(
        !b_lines.iter().any(|l| l.starts_with("Reusing")),
        "{b_lines:?}"
    );
    assert_eq!(
        b_lines.last().unwrap(),
        "Connection #1 to host 127.0.0.1:4 left intact\n"
    );
    assert_eq!(
        messages(&mut m),
        [(a.index(), Ok(()), 1), (b.index(), Ok(()), 0)]
    );
    assert_eq!(m.easy(b).unwrap().report().connects(), 1);
}

/// A waiting transfer that finds room lets the next one waiting look
/// too, while it is still connecting, and one that finds none lets no
/// one (`multistate_connect`'s `multi_schedule_pending`).
#[test]
fn a_transfer_finding_room_lets_the_next_look() {
    let (mut m, clock) = networked();
    m.conn_limits_mut().max_total = NonZeroU32::new(2);
    let mut add = |url: &str, fresh| {
        let (mut e, lines) = traced(url);
        e.options_mut().limits.reuse.fresh = fresh;
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        (id, lines)
    };
    // One never connects, one is done after 5 ms; two wait for room.
    let (stuck, _) = add("tcp://127.0.0.1:3/", false);
    let (late, _) = add("tcp://127.0.0.1:4/", false);
    let (fresh, _) = add("tcp://127.0.0.1:4/", true);
    let (next, next_lines) = add("tcp://127.0.0.1:1/", false);
    m.perform(&mut NoEvents).unwrap();
    assert_ne!(m.timeout(), Some(Duration::ZERO), "a wait wakes no one");
    clock.advance(Duration::from_millis(5));
    // The idle connection to :4 is closed for the fresh one, which is
    // still connecting when the next looks, and waits again.
    m.perform(&mut NoEvents).unwrap();
    let total = "No connections available, total of 2 reached.\n";
    assert_eq!(trace_of(&next_lines), [total, total]);
    for id in [stuck, late, fresh, next] {
        m.remove(id, &mut NoEvents).unwrap();
    }
}

/// Under the total limit, an idle connection to another host is closed
/// to make room.
#[test]
fn an_idle_connection_makes_room_under_the_total_limit() {
    let (mut m, _clock) = networked();
    m.conn_limits_mut().max_total = NonZeroU32::new(1);
    for url in ["tcp://127.0.0.1:1/", "tcp://localhost:1/"] {
        let (e, lines) = traced(url);
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(messages(&mut m), [(id.index(), Ok(()), 0)]);
        assert!(trace_of(&lines).last().unwrap().ends_with("left intact\n"));
        m.remove(id, &mut NoEvents).unwrap();
    }
    assert_eq!(m.caches.pool.len(), 1);
}

/// A waiting transfer's time runs on: once it is up, the timer finds it
/// late and lets it look again, and it fails there (`multi_handle_timeout`,
/// twice).
#[test]
fn a_waiting_transfer_runs_out_of_time() {
    let (mut m, clock) = networked();
    m.conn_limits_mut().max_total = NonZeroU32::new(1);
    let (a, _) = traced("tcp://127.0.0.1:3/");
    let (mut b, b_lines) = traced("tcp://127.0.0.1:1/");
    b.options_mut().limits.total = TimeLimit::from_millis(100);
    let a = m.add(Box::new(a), (), &mut NoEvents).unwrap();
    let b = m.add(Box::new(b), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    clock.advance(Duration::from_millis(100));
    m.perform(&mut NoEvents).unwrap();
    let late = "Operation timed out after 100 milliseconds with 0 bytes received\n";
    assert_eq!(
        trace_of(&b_lines),
        [
            "No connections available, total of 1 reached.\n",
            late,
            "PENDING handle timeout\n",
            late,
        ]
    );
    assert_eq!(
        messages(&mut m),
        [(b.index(), Err(ErrorKind::OperationTimedout), 0)]
    );
    m.remove(a, &mut NoEvents).unwrap();
}

/// A waiting transfer comes out of the multi, and then the one it waited
/// on, with nothing left of either (test 1557).
#[test]
fn a_waiting_transfer_is_removed_cleanly() {
    let (mut m, _clock) = networked();
    m.conn_limits_mut().max_host = NonZeroU32::new(1);
    let a = m
        .add(Box::new(easy("tcp://127.0.0.1:3/")), (), &mut NoEvents)
        .unwrap();
    let b = m
        .add(Box::new(easy("tcp://127.0.0.1:3/")), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.remove(b, &mut NoEvents).unwrap();
    m.remove(a, &mut NoEvents).unwrap();
    assert_eq!(m.counts().running, 0);
    assert_eq!(m.caches.pool.len(), 0);
}

/// With no limit set, the pool keeps twice the transfers in the multi,
/// and closes only a connection idle for a second.
#[test]
fn the_pool_s_limit_is_guessed_from_the_transfers() {
    let (mut m, clock) = networked();
    let mut run = |url: &str| {
        let (e, lines) = traced(url);
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        m.remove(id, &mut NoEvents).unwrap();
        clock.advance(Duration::from_secs(1));
        trace_of(&lines)
    };
    run("tcp://127.0.0.1:1/");
    run("tcp://localhost:1/");
    // A third, with one transfer in the multi: one too many.
    let third = run("tcp://[::1]:1/");
    assert_eq!(
        third[third.len() - 2..],
        [
            "Connection pool is full, closing the oldest of 3/2\n",
            "Connection #2 to host [::1]:1 left intact\n",
        ]
    );
    let (e, lines) = traced("tcp://127.0.0.1:1/");
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.remove(id, &mut NoEvents).unwrap();
    assert_eq!(
        trace_of(&lines)[0],
        "Hostname 127.0.0.1 was found in DNS cache\n",
        "#0, the oldest, was closed: {:?}",
        trace_of(&lines)
    );
}

/// A connect-to entry sends the connection to its peer, and the
/// connection serves only transfers going through that same peer
/// (`url_match_conn`, `url_match_destination`).
#[test]
fn a_connection_serves_only_the_peer_it_goes_through() {
    let (mut m, _clock) = networked();
    let mut run = |to: &[&[u8]]| {
        let (mut e, lines) = traced("tcp://foo.test:9/");
        e.options_mut().connect_to.set(to.iter().copied()).unwrap();
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        let result = messages(&mut m).last().unwrap().1;
        m.remove(id, &mut NoEvents).unwrap();
        (result, trace_of(&lines))
    };
    let (result, first) = run(&[b"other:9:x:1", b"::127.0.0.1:1"]);
    assert_eq!(result, Ok(()));
    assert_eq!(
        first[..2],
        [
            "  Trying 127.0.0.1:1...\n",
            "Established connection to 127.0.0.1 (127.0.0.1 port 1) from 127.0.0.1 port 40000 \n",
        ]
    );
    let (_, again) = run(&[b"foo.test:9:127.0.0.1:1"]);
    assert_eq!(
        again[0],
        "Reusing existing tcp: connection with host foo.test\n"
    );
    // Another peer, to the same addresses: a connection of its own.
    let (result, other) = run(&[b"::localhost:1"]);
    assert_eq!(result, Ok(()));
    assert_eq!(other[0], "Host localhost:1 was resolved.\n");
    // No peer: the URL's host, which nothing resolves.
    let (result, direct) = run(&[]);
    assert_eq!(result, Err(ErrorKind::CouldntResolveHost));
    assert_eq!(direct[2], "Could not resolve: foo.test:9\n");
    // A failure names both.
    let (result, refused) = run(&[b":9:127.0.0.1:2"]);
    assert_eq!(result, Err(ErrorKind::CouldntConnect));
    assert!(
        refused[2].starts_with("Failed to connect to foo.test:9 via 127.0.0.1:2 after "),
        "{refused:?}"
    );
    let (result, bad) = run(&[b"::localhost:x"]);
    assert_eq!(result, Err(ErrorKind::SetoptOptionSyntax));
    assert_eq!(bad, ["No valid port number in 'localhost:x'\n"]);
}

/// `IpVersion` limits the addresses tried, not those reported, and a
/// connection kept for any family serves only a transfer that takes any.
#[test]
fn an_ip_version_limits_the_addresses_tried() {
    let (mut m, _clock) = networked();
    let (v4, lines) = traced("tcp://localhost:1/");
    let mut v4 = v4;
    v4.options_mut().ip_version = crate::options::IpVersion::V4;
    let v4 = m.add(Box::new(v4), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(v4.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines)[..5],
        [
            "Host localhost:1 was resolved.\n",
            "IPv6: ::1\n",
            "IPv4: 127.0.0.1\n",
            "  Trying 127.0.0.1:1...\n",
            "Established connection to localhost (127.0.0.1 port 1) from 127.0.0.1 port 40000 \n",
        ]
    );
    let (any, lines) = traced("tcp://localhost:1/");
    let any = m.add(Box::new(any), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(any.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines)[0],
        "Reusing existing tcp: connection with host localhost\n"
    );
    let (v6, lines) = traced("tcp://localhost:1/");
    let mut v6 = v6;
    v6.options_mut().ip_version = crate::options::IpVersion::V6;
    let v6 = m.add(Box::new(v6), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(messages(&mut m), [(v6.index(), Ok(()), 0)]);
    assert_eq!(
        trace_of(&lines)[0],
        "Hostname localhost was found in DNS cache\n"
    );
    assert_eq!(
        trace_of(&lines)[4],
        "  Trying [::1]:1...\n",
        "not the IPv4 one"
    );
}

/// A setup moves no bytes the pause judges, so a pause never blocks it:
/// the transfer runs again, though it does not connect while receiving
/// is paused (`Curl_xfer_is_blocked` before `xfer_setup`).
#[test]
fn a_pause_never_blocks_a_setup() {
    let (mut m, _clock) = networked();
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:3/")), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_ne!(m.timeout(), Some(Duration::ZERO));
    m.pause(id, PauseRequest::RECV, &mut NoEvents).unwrap();
    assert_eq!(m.timeout(), Some(Duration::ZERO));
}

/// A fake network the test reaches while the multi holds it.
struct SharedNet(std::sync::Arc<std::sync::Mutex<FakeNet>>);

impl Net for SharedNet {
    fn poll(
        &mut self,
        sockets: &mut [crate::conn::io::SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> std::io::Result<u32> {
        self.0.lock().unwrap().poll(sockets, fds, timeout)
    }

    fn connect(
        &mut self,
        addr: std::net::SocketAddr,
        options: crate::conn::io::SocketOptions,
    ) -> std::io::Result<(Box<dyn crate::conn::io::Socket>, crate::conn::io::Connect)> {
        self.0.lock().unwrap().connect(addr, options)
    }

    fn close(&mut self, socket: Box<dyn crate::conn::io::Socket>) {
        self.0.lock().unwrap().close(socket);
    }

    fn resolve(
        &mut self,
        name: &[u8],
        family: crate::conn::io::Family,
    ) -> Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure> {
        self.0.lock().unwrap().resolve(name, family)
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.0.lock().unwrap().link_local_scope()
    }
}

/// A transfer's sockets are set as its options say before they connect:
/// `TCP_NODELAY` unless told otherwise, as C sets it by default.
#[test]
fn sockets_are_set_as_the_options_say() {
    use crate::conn::io::{Peer, SocketKey};
    let clock = ManualClock::new().unwrap();
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 3));
    let net = std::sync::Arc::new(std::sync::Mutex::new(
        FakeNet::new(clock.clone()).with_peer(at, Peer::Silent),
    ));
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(SharedNet(net.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let url = "tcp://127.0.0.1:3/";
    m.add(Box::new(easy(url)), (), &mut NoEvents).unwrap();
    let mut delaying = easy(url);
    delaying.options_mut().socket.nodelay = false;
    m.add(Box::new(delaying), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let nodelay = |n| {
        net.lock()
            .unwrap()
            .socket_options(SocketKey::new(n))
            .nodelay
    };
    assert_eq!([nodelay(1000), nodelay(1001)], [true, false]);
}

/// Connections are numbered in the order they are made, and one found
/// dead is named by its number as C names it, without the `#`.
#[test]
fn connections_are_numbered_in_their_traces() {
    use crate::conn::io::{Peer, SocketKey};
    let clock = ManualClock::new().unwrap();
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 4));
    let net = std::sync::Arc::new(std::sync::Mutex::new(
        FakeNet::new(clock.clone()).with_peer(at, Peer::AcceptsAfter(Duration::from_millis(5))),
    ));
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(SharedNet(net.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let url = "tcp://127.0.0.1:4/";
    let (a, _) = traced(url);
    let (b, b_lines) = traced(url);
    m.add(Box::new(a), (), &mut NoEvents).unwrap();
    m.add(Box::new(b), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    clock.advance(Duration::from_millis(5));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.counts().running, 0);
    assert_eq!(
        trace_of(&b_lines)[..2],
        [
            "Hostname 127.0.0.1 was found in DNS cache\n",
            "  Trying 127.0.0.1:4...\n"
        ],
        "the first transfer's answer is kept"
    );
    assert_eq!(
        trace_of(&b_lines)[2..],
        [
            "Established connection to 127.0.0.1 (127.0.0.1 port 4) from 127.0.0.1 port 40001 \n",
            "Connection #1 to host 127.0.0.1:4 left intact\n",
        ]
    );
    // Both hang up while idle; the next search, within the second of the
    // last prune, finds each dead.
    net.lock().unwrap().hang_up(SocketKey::new(1000));
    net.lock().unwrap().hang_up(SocketKey::new(1001));
    let (c, c_lines) = traced(url);
    m.add(Box::new(c), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        trace_of(&c_lines)[..6],
        [
            "Connection 0 seems to be dead, terminating\n",
            "shutting down connection #0\n",
            "Connection 1 seems to be dead, terminating\n",
            "shutting down connection #1\n",
            "Hostname 127.0.0.1 was found in DNS cache\n",
            "  Trying 127.0.0.1:4...\n",
        ]
    );
}

/// A wake ends a wait on a transfer's socket, with no descriptors of the
/// application's beside it.
#[test]
fn a_wake_ends_a_wait_on_a_transfer_s_socket() {
    use crate::conn::io::Peer;
    let clock = ManualClock::new().unwrap();
    let waker = TryArc::try_new(Waker::new().unwrap()).unwrap();
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 3));
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(FakeNet::new(clock.clone()).with_peer(at, Peer::Silent)),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: Some(waker.clone()),
    };
    let mut m: Multi = Multi::new(env).unwrap();
    m.add(Box::new(easy("tcp://127.0.0.1:3/")), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    waker.wake().unwrap();
    let took = slept(&clock, || {
        assert_eq!(
            m.wait(&mut [], Duration::from_secs(3), WaitMode::Wait),
            Ok(0)
        );
    });
    assert_eq!(took, Duration::ZERO, "woken");
}

/// A network for the IPv6 scope tests: `::1` port 5 accepts in scopes 9,
/// 10 and the loopback's, `fe80::1` port 6 in scope 3, and the one
/// interface with a link-local address is in scope 3.
fn scoped_net() -> (Multi, std::num::NonZeroU32) {
    use crate::conn::io::Peer;
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
    let clock = ManualClock::new().unwrap();
    let lo = curl_os::net::interface_index(b"lo").expect("Linux has a loopback");
    let at = |ip: Ipv6Addr, port, scope| SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope));
    let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let three = std::num::NonZeroU32::new(3).unwrap();
    let net = FakeNet::new(clock.clone())
        .with_peer(at(Ipv6Addr::LOCALHOST, 5, 9), Peer::Accepts)
        .with_peer(at(Ipv6Addr::LOCALHOST, 5, 10), Peer::Accepts)
        .with_peer(at(Ipv6Addr::LOCALHOST, 5, lo.get()), Peer::Accepts)
        .with_peer(at(link_local, 6, 3), Peer::Accepts)
        .with_link_local_scope(three);
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), lo)
}

/// Run `e` alone on `m` to its end; its result and trace, without the
/// line saying a name was in the cache, as the address after the first
/// transfer is.
fn run_traced(m: &mut Multi, e: Easy, lines: &TextLines) -> (Result<(), ErrorKind>, Vec<String>) {
    let h = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let done = messages(m);
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(done[0].0, h.index());
    let mut trace = trace_of(lines);
    trace.retain(|l| !l.ends_with("was found in DNS cache\n"));
    (done[0].1, trace)
}

/// The URL's zone is the socket address's scope, a number as it is and a
/// name as its interface's index (`get_scope_id`, `peer_create`).
#[test]
fn a_zone_is_the_socket_address_s_scope() {
    let (mut m, lo) = scoped_net();
    let (e, lines) = traced("tcp://[::1%259]:5/");
    let (result, trace) = run_traced(&mut m, e, &lines);
    assert_eq!(result, Ok(()));
    assert_eq!(trace[0], "  Trying [::1]:5 scope_id=9...\n");
    let (e, lines) = traced("tcp://[::1%25lo]:5/");
    let (result, trace) = run_traced(&mut m, e, &lines);
    assert_eq!(result, Ok(()));
    assert_eq!(trace[0], format!("  Trying [::1]:5 scope_id={lo}...\n"));
    // An interface no one has leaves no scope, without an error.
    let (e, lines) = traced("tcp://[::1%25nosuch0]:5/");
    let (result, trace) = run_traced(&mut m, e, &lines);
    assert_eq!(result, Err(ErrorKind::CouldntConnect));
    assert_eq!(trace[0], "  Trying [::1]:5...\n");
}

/// A link-local address with no scope takes a local interface's; one
/// with a scope keeps it (`get_scope_id`).
#[test]
fn a_link_local_address_without_a_scope_takes_an_interface_s() {
    let (mut m, _) = scoped_net();
    for url in ["tcp://[fe80::1]:6/", "tcp://[fe80::1%25nosuch0]:6/"] {
        let (e, lines) = traced(url);
        let (result, trace) = run_traced(&mut m, e, &lines);
        assert_eq!(result, Ok(()), "{url}");
        assert_eq!(
            trace[..2],
            [
                "determined scope_id=3 for link-local address from local interface\n",
                "  Trying [fe80::1]:6 scope_id=3...\n",
            ],
            "{url}"
        );
    }
    let (e, lines) = traced("tcp://[fe80::1%254]:6/");
    let (result, trace) = run_traced(&mut m, e, &lines);
    assert_eq!(result, Err(ErrorKind::CouldntConnect));
    assert_eq!(trace[0], "  Trying [fe80::1]:6 scope_id=4...\n");
}

/// The application's scope takes the place of the URL's zone
/// (`CURLOPT_ADDRESS_SCOPE`).
#[test]
fn the_application_s_scope_overrides_the_zone() {
    let (mut m, _) = scoped_net();
    let (mut e, lines) = traced("tcp://[::1%2510]:5/");
    e.options_mut().address_scope = std::num::NonZeroU32::new(9);
    let (result, trace) = run_traced(&mut m, e, &lines);
    assert_eq!(result, Ok(()));
    assert_eq!(trace[0], "  Trying [::1]:5 scope_id=9...\n");
    // A connection in scope 9 serves a URL that names it.
    let (e, lines) = traced("tcp://[::1%259]:5/");
    let (result, trace) = run_traced(&mut m, e, &lines);
    assert_eq!(result, Ok(()));
    assert_eq!(trace[0], "Reusing existing tcp: connection with host ::1\n");
}

/// A connection serves a transfer in the same scope, however its zone
/// spells it, and none in another (`Curl_peer_equal`).
#[test]
fn connections_are_reused_within_a_scope() {
    let (mut m, lo) = scoped_net();
    let reused = "Reusing existing tcp: connection with host ::1\n";
    let index = format!("tcp://[::1%25{lo}]:5/");
    let steps = [
        ("tcp://[::1%259]:5/", "  Trying [::1]:5 scope_id=9...\n"),
        ("tcp://[::1%2510]:5/", "  Trying [::1]:5 scope_id=10...\n"),
        ("tcp://[::1%25009]:5/", reused),
        (
            "tcp://[::1%25lo]:5/",
            &format!("  Trying [::1]:5 scope_id={lo}...\n"),
        ),
        (&index, reused),
    ];
    for (url, first) in steps {
        let (e, lines) = traced(url);
        let (result, trace) = run_traced(&mut m, e, &lines);
        assert_eq!(result, Ok(()), "{url}");
        assert_eq!(trace[0], first, "{url}");
    }
}
