//! Random sequences of calls, checking the multi against a model of what
//! the application can see. The debug build's `check` runs after each call
//! as well, so a broken table fails here too.

use proptest::prelude::*;

use super::*;
use crate::conn::io::FakeNet;
use crate::time::{ManualClock, TimeLimit};

#[derive(Clone, Debug)]
enum Op {
    Add(Url),
    /// Remove the n-th transfer ever added (live or not).
    Remove(usize),
    /// Remove the n-th transfer ever added from the next `EasyDone`.
    RemoveInNotify(usize),
    Perform,
    Timeout,
    Advance(u64),
    Read,
    Notify(NotifyKind, bool),
    /// Abort the next timer call.
    AbortTimer,
}

#[derive(Clone, Copy, Debug)]
enum Url {
    Null,
    /// Never completes; times out after the total limit, if any. The
    /// connect limit only wakes it, as it is connected at once.
    Stall {
        total: Option<u64>,
        connect: Option<u64>,
    },
    Unsupported,
    Missing,
}

fn op() -> impl Strategy<Value = Op> {
    let url = prop_oneof![
        Just(Url::Null),
        (
            proptest::option::of(1..3000u64),
            proptest::option::of(1..3000u64)
        )
            .prop_map(|(total, connect)| Url::Stall { total, connect }),
        Just(Url::Unsupported),
        Just(Url::Missing),
    ];
    let kind = prop_oneof![Just(NotifyKind::InfoRead), Just(NotifyKind::EasyDone)];
    prop_oneof![
        4 => url.prop_map(Op::Add),
        2 => (0..16usize).prop_map(Op::Remove),
        1 => (0..16usize).prop_map(Op::RemoveInNotify),
        3 => Just(Op::Perform),
        2 => Just(Op::Timeout),
        2 => (0..2000u64).prop_map(Op::Advance),
        2 => Just(Op::Read),
        1 => (kind, any::<bool>()).prop_map(|(k, on)| Op::Notify(k, on)),
        1 => Just(Op::AbortTimer),
    ]
}

fn easy_for(url: Url) -> Easy {
    let mut easy = Easy::new();
    let text: &[u8] = match url {
        Url::Null => b"null://a",
        Url::Stall { .. } => b"stall://a",
        Url::Unsupported => b"nope://a",
        Url::Missing => return easy,
    };
    easy.options_mut().set_url(Some(text)).unwrap();
    if let Url::Stall { total, connect } = url {
        let limits = &mut easy.options_mut().limits;
        limits.total = total.and_then(TimeLimit::from_millis);
        limits.connect = connect.and_then(TimeLimit::from_millis);
    }
    easy
}

#[derive(Default)]
struct Events {
    abort_next: bool,
    remove_on_done: Option<TransferId>,
    removed_in_notify: Vec<TransferId>,
}

impl MultiEvents<NoHost> for Events {
    fn timer(&mut self, _cx: &mut EventCx<'_, NoHost>, _: TimerChange) -> Result<(), Abort> {
        if std::mem::take(&mut self.abort_next) {
            return Err(Abort);
        }
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }

    fn notify(&mut self, cx: &mut NotifyCx<'_, NoHost>, n: Notification) {
        if let Notification::EasyDone(id) = n {
            assert!(
                cx.options(id).is_some(),
                "notified of a transfer not in the multi"
            );
            if let Some(victim) = self.remove_on_done.take()
                && cx.remove(victim, self).is_some()
            {
                self.removed_in_notify.push(victim);
            }
        }
    }
}

fn run(ops: &[Op]) {
    let clock = ManualClock::new().unwrap();
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(FakeNet::new(clock.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    let mut ev = Events::default();
    let mut ids: Vec<TransferId> = Vec::new();
    let mut live: Vec<TransferId> = Vec::new();
    let mut read: Vec<TransferId> = Vec::new();
    let mut added = 0u64;
    let mut added_refused = 0u64;
    for op in ops {
        match *op {
            Op::Add(url) => {
                let armed = ev.abort_next;
                match m.add(easy_for(url), (), &mut ev) {
                    Ok(id) => {
                        assert!(!ids.contains(&id), "{id:?} handed out twice");
                        ids.push(id);
                        live.push(id);
                        added += 1;
                    }
                    Err(refused) => {
                        assert_eq!(
                            refused.kind,
                            MultiErrorKind::AbortedByCallback,
                            "only a timer abort refuses here"
                        );
                        // A refusal by the timer callback counts as added, as
                        // in C; one by a dead multi never reached the count.
                        if armed && !ev.abort_next {
                            added_refused += 1;
                        }
                        let back = refused.easy.options().url().map(<[u8]>::to_vec);
                        let sent = easy_for(url).options().url().map(<[u8]>::to_vec);
                        assert_eq!(back, sent, "the refused Easy comes back");
                    }
                }
            }
            Op::Remove(n) => {
                let Some(&id) = ids.get(n) else { continue };
                let was_live = live.contains(&id);
                let removed = m.remove(id, &mut ev);
                assert_eq!(removed.is_some(), was_live, "removing {id:?}");
                live.retain(|&l| l != id);
                assert!(m.easy(id).is_none(), "a removed id still names a transfer");
            }
            Op::RemoveInNotify(n) => ev.remove_on_done = ids.get(n).copied(),
            Op::Perform => {
                let _ = m.perform(&mut ev);
            }
            Op::Timeout => {
                let _ = m.socket_action(SocketEvent::Timeout, &mut ev);
            }
            Op::Advance(ms) => clock.advance(Duration::from_millis(ms)),
            Op::Read => {
                while let Some(msg) = m.info_read() {
                    assert!(
                        live.contains(&msg.id),
                        "a message for a transfer not in the multi"
                    );
                    assert!(!read.contains(&msg.id), "{:?}'s message read twice", msg.id);
                    read.push(msg.id);
                }
            }
            Op::Notify(kind, on) => m.set_notify(kind, on),
            Op::AbortTimer => ev.abort_next = true,
        }
        for id in ev.removed_in_notify.drain(..) {
            live.retain(|&l| l != id);
        }
        let counts = m.counts();
        assert_eq!(counts.current as usize, live.len());
        assert_eq!(counts.added_ever, added + added_refused);
        assert!(counts.running <= counts.current);
    }
    for id in live {
        m.remove(id, &mut ev).expect("live");
    }
    assert_eq!(
        m.caches.pool.len(),
        0,
        "a connection outlived its transfers"
    );
    assert!(m.timers.is_empty(), "a timer outlived its transfer");
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_calls_keep_the_multi_consistent(ops in proptest::collection::vec(op(), 0..64)) {
        run(&ops);
    }
}
