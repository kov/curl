//! The multi under allocation failure: a scenario run once for every
//! allocation it makes, each run with that allocation and every later one
//! refused (`ENGINE.md` 8.2). Every run must end cleanly, with refusals
//! reported as `OutOfMemory` where an operation can allocate, and leave
//! nothing allocated behind it.
//!
//! The tracker's limit is process-wide, so this is its own test binary
//! without the libtest harness.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::time::Duration;

use curl_alloc::track::{self, Tracker};
use curl_alloc::{OutOfMemory, TryArc, try_box};
use curl_core::conn::io::{FakeNet, Net};
use curl_core::easy::Easy;
use curl_core::error::MultiErrorKind;
use curl_core::id::ArenaPolicy;
use curl_core::multi::Multi;
use curl_core::multi::{
    Abort, AddError, Env, EventCx, MultiEvents, NoHost, Notification, NotifyCx, NotifyKind,
    SocketEvent, TimerChange, WaitMode,
};
use curl_core::time::{Clock, ManualClock, TimeLimit};
use curl_os::wake::Waker;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker;

fn main() {
    // Reported as libtest does, the name before the run, so that a run that
    // aborts still shows which test it was in.
    track::untracked(|| {
        use std::io::Write as _;
        print!("test add_perform_remove_survives_every_allocation_failing ... ");
        std::io::stdout().flush().unwrap();
    });
    add_perform_remove_survives_every_allocation_failing();
    track::untracked(|| println!("ok"));
}

/// More transfers than the arena's first 16 rows, so it grows.
const TRANSFERS: usize = 20;

#[derive(Default)]
struct Events {
    timer_calls: u32,
    notified: u32,
}

impl MultiEvents<NoHost> for Events {
    fn timer(&mut self, _: &mut EventCx<'_, NoHost>, _: TimerChange) -> Result<(), Abort> {
        self.timer_calls += 1;
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }

    fn notify(&mut self, _: &mut NotifyCx<'_, NoHost>, _: Notification) {
        self.notified += 1;
    }
}

/// What a run got through.
#[derive(Debug, Default, PartialEq, Eq)]
struct Outcome {
    added: usize,
    messages: usize,
    removed: usize,
}

/// Add transfers that complete, fail and time out, drive them, read them
/// and take them out. `Err` where setting up refused; an add refused for
/// memory skips that transfer; nothing after the adds may allocate.
fn scenario() -> Result<Outcome, OutOfMemory> {
    let clock = ManualClock::new()?;
    let boxed: Box<dyn Clock> = try_box(clock.clone())?;
    let net: Box<dyn Net> = try_box(FakeNet::new(clock.clone()))?;
    let waker = TryArc::try_new(Waker::new().expect("a socket pair"))?;
    let env = Env {
        clock: boxed,
        net,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: Some(waker),
    };
    let mut m: Multi = Multi::new(env)?;
    match m.wait(&mut [], Duration::ZERO, WaitMode::Poll) {
        Ok(0) | Err(MultiErrorKind::OutOfMemory) => {}
        other => panic!("an idle wait got {other:?}"),
    }
    m.set_notify(NotifyKind::InfoRead, true);
    m.set_notify(NotifyKind::EasyDone, true);
    let mut ev = Events::default();
    let mut out = Outcome::default();
    let mut ids = [None; TRANSFERS];
    for (i, id) in ids.iter_mut().enumerate() {
        let mut easy = Easy::new();
        let url: &[u8] = match i % 3 {
            0 => b"null://a",
            1 => b"stall://a",
            _ => b"nope://a",
        };
        if easy.options_mut().set_url(Some(url)).is_err() {
            continue;
        }
        easy.options_mut().limits.total = TimeLimit::from_millis(1000);
        match m.add(easy, (), &mut ev) {
            Ok(added) => {
                *id = Some(added);
                out.added += 1;
            }
            Err(AddError {
                kind: MultiErrorKind::OutOfMemory,
                ..
            }) => {}
            Err(e) => panic!("add refused with {:?}, not for memory", e.kind),
        }
    }
    m.perform(&mut ev).expect("a pass allocates nothing");
    m.socket_action(SocketEvent::Timeout, &mut ev)
        .expect("a pass allocates nothing");
    clock.advance(Duration::from_millis(1000));
    let running = m
        .socket_action(SocketEvent::Timeout, &mut ev)
        .expect("a pass allocates nothing");
    assert_eq!(running, 0, "every transfer has completed or timed out");
    while m.info_read().is_some() {
        out.messages += 1;
    }
    assert_eq!(out.messages, out.added);
    for id in ids.into_iter().flatten() {
        let removed = m.remove(id, &mut ev).expect("in the multi");
        removed.status.expect("the timer callback never aborts");
        out.removed += 1;
    }
    assert!(ev.notified > 0 || out.added == 0);
    Ok(out)
}

fn add_perform_remove_survives_every_allocation_failing() {
    let full = Outcome {
        added: TRANSFERS,
        messages: TRANSFERS,
        removed: TRANSFERS,
    };
    let mut limit = 0;
    loop {
        let live = track::live_tracked();
        let (outcome, refused) = track::fail_after(limit, scenario);
        assert_eq!(
            track::live_tracked(),
            live,
            "a run allowed {limit} allocations left blocks behind"
        );
        if !refused {
            assert_eq!(outcome, Ok(full), "a run with nothing refused");
            // Every allocation of the scenario has been refused in turn.
            assert!(limit > 0, "the scenario allocates nothing");
            track::untracked(|| eprintln!("torture: {limit} allocations, each refused in turn"));
            return;
        }
        limit += 1;
        assert!(limit < 100_000, "the scenario never ran to the end");
    }
}
