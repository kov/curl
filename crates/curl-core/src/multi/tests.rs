use super::*;
use crate::time::{ManualClock, TimeLimit};

/// Logs every timer call, and aborts the one numbered `abort_at` (from 1).
#[derive(Default)]
struct RecordingEvents {
    timer: Vec<TimerChange>,
    abort_at: Option<usize>,
}

impl MultiEvents<NoHost> for RecordingEvents {
    fn timer(&mut self, change: TimerChange) -> Result<(), Abort> {
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
