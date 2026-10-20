use super::*;
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
        arena: ArenaPolicy::new(16, 0).unwrap(),
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
        .map(|u| m.add(easy(u), (), ev).unwrap())
        .collect();
    let no_url = m.add(Easy::new(), (), ev).unwrap();
    let no_host = m.add(easy("null://"), (), ev).unwrap();
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
    let id = m.add(easy("null://a"), (), ev).unwrap();
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
    let id = m.add(easy("stall://a"), (), ev).unwrap();
    m.perform(ev).unwrap();
    assert_eq!(m.pool.len(), 1);
    m.remove(id, ev).unwrap();
    assert_eq!(m.pool.len(), 0);
}

#[test]
fn the_timer_hears_of_add_and_remove() {
    let (mut m, _clock) = multi();
    let mut ev = RecordingEvents::default();
    let id = m.add(easy("stall://a"), (), &mut ev).unwrap();
    assert_eq!(ev.timer, [SET_NOW], "inside the add");
    m.perform(&mut ev).unwrap();
    assert_eq!(ev.timer, [SET_NOW, TimerChange::Clear]);
    let other = m.add(easy("stall://b"), (), &mut ev).unwrap();
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
    let refused = m.add(easy("null://a"), (), &mut ev).unwrap_err();
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
    let id = m.add(easy("stall://a"), (), &mut ev).unwrap();
    assert_eq!(m.perform(&mut ev), Err(MultiErrorKind::AbortedByCallback));
    assert_eq!(m.timeout(), Some(Duration::ZERO));
    let refused = m.add(easy("null://b"), (), &mut ev).unwrap_err();
    assert_eq!(refused.kind, MultiErrorKind::AbortedByCallback);
    assert_eq!(m.perform(&mut ev), Ok(0));
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::AbortedByCallback), 0)]
    );
    assert_eq!(m.pool.len(), 0, "the connection was given back");
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
    let id = m.add(e, (), &mut ev).unwrap();
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
    assert_eq!(m.pool.len(), 0);
}

#[test]
fn a_timer_abort_inside_remove_still_removes() {
    let (mut m, _clock) = multi();
    let mut ev = RecordingEvents {
        abort_at: Some(2),
        ..RecordingEvents::default()
    };
    let id = m.add(easy("stall://a"), (), &mut ev).unwrap();
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
    lag: std::rc::Rc<std::cell::Cell<Duration>>,
}

impl Clock for LaggingClock {
    fn now(&self) -> Instant {
        let t = self.inner.now();
        self.inner.advance(self.lag.take());
        t
    }
}

fn lagging_multi() -> (Multi, std::rc::Rc<std::cell::Cell<Duration>>) {
    let lag = std::rc::Rc::new(std::cell::Cell::new(Duration::ZERO));
    let env = Env {
        clock: Box::new(LaggingClock {
            inner: ManualClock::new().unwrap(),
            lag: lag.clone(),
        }),
        arena: ArenaPolicy::new(16, 0).unwrap(),
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
    let late = m.add(stall_within(10), (), ev).unwrap();
    m.perform(ev).unwrap();
    // Something to run, which takes long enough for `late` to come due.
    m.add(easy("stall://b"), (), ev).unwrap();
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
    m.add(stall_within(10), (), ev).unwrap();
    m.perform(ev).unwrap();
    lag.set(Duration::from_millis(10));
    m.socket_action(SocketEvent::Timeout, ev).unwrap();
    assert!(
        m.info_read().is_none(),
        "due only after the reading the run used"
    );
}

#[test]
fn a_fired_timer_queues_the_next_one() {
    let (mut m, clock) = multi();
    let ev = &mut NoEvents;
    let mut e = stall_within(3000);
    e.options_mut().limits.connect = TimeLimit::from_millis(1000);
    m.add(e, (), ev).unwrap();
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
        m.add(stall_within(ms), (), ev).unwrap();
    }
    m.perform(ev).unwrap();
    assert_eq!(m.timeout(), Some(Duration::from_millis(1000)));
}

#[test]
fn a_refused_add_counts_nothing_as_running() {
    let (mut m, _clock) = multi();
    let mut ev = RecordingEvents {
        abort_at: Some(1),
        ..RecordingEvents::default()
    };
    m.add(easy("null://a"), (), &mut ev).unwrap_err();
    let counts = m.counts();
    assert_eq!((counts.running, counts.current), (0, 0));
}

#[test]
fn a_transfer_s_easy_is_reached_by_its_id() {
    let (mut m, _clock) = multi();
    let ev = &mut NoEvents;
    let id = m.add(easy("null://a"), (), ev).unwrap();
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
    // Guessed as http, which this build cannot run yet.
    let id = m.add(easy("example.com/a"), (), ev).unwrap();
    m.perform(ev).unwrap();
    assert_eq!(
        messages(&mut m),
        [(id.index(), Err(ErrorKind::UnsupportedProtocol), 0)]
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
            self.removed.push(removed.easy);
        }
        if let Some(e) = self.add.take() {
            let id = cx.add(e, (), self).expect("added");
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
    let a = m.add(easy("null://a"), (), &mut ev).unwrap();
    let b = m.add(easy("nope://b"), (), &mut ev).unwrap();
    let c = m.add(easy("null://c"), (), &mut ev).unwrap();
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
    let a = m.add(easy("null://a"), (), &mut ev).unwrap();
    ev.trigger = Some(a);
    m.perform(&mut ev).unwrap();
    let b = m.add(easy("null://b"), (), &mut ev).unwrap();
    m.perform(&mut ev).unwrap();
    assert_eq!(messages(&mut m).len(), 2);
    let c = m.add(easy("null://c"), (), &mut ev).unwrap();
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
    m.add(easy("null://a"), (), &mut ev).unwrap();
    m.set_notify(NotifyKind::EasyDone, true);
    m.set_notify(NotifyKind::EasyDone, false);
    m.perform(&mut ev).unwrap();
    assert_eq!(ev.log, []);
    m.set_notify(NotifyKind::InfoRead, true);
    m.add(easy("null://b"), (), &mut ev).unwrap();
    messages(&mut m);
    m.perform(&mut ev).unwrap();
    assert_eq!(ev.log, [Notification::InfoRead]);
}

#[test]
fn a_kind_turned_off_before_delivery_is_dropped() {
    let (mut m, _clock) = multi();
    notifying(&mut m);
    let mut ev = NotifyEvents::default();
    let a = m.add(easy("null://a"), (), &mut ev).unwrap();
    m.add(easy("null://b"), (), &mut ev).unwrap();
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
    let a = m.add(easy("null://a"), (), &mut ev).unwrap();
    let b = m.add(easy("null://b"), (), &mut ev).unwrap();
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
    let a = m.add(easy("nope://a"), (), &mut ev).unwrap();
    m.perform(&mut ev).unwrap();
    ev.read_in_timer = true;
    m.add(easy("null://b"), (), &mut ev).unwrap();
    assert_eq!(ev.read, [(a, Err(ErrorKind::UnsupportedProtocol))]);
}

#[test]
fn socket_action_delivers_notifications() {
    let (mut m, clock) = multi();
    m.set_notify(NotifyKind::EasyDone, true);
    let mut ev = NotifyEvents::default();
    let id = m.add(stall_within(10), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(ev.log, []);
    clock.advance(Duration::from_millis(10));
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(ev.log, [Notification::EasyDone(id)]);
}
