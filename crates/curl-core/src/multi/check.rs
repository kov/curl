//! The multi's invariants, recomputed from scratch and compared with what
//! the multi keeps up to date, after every call in the debug build.

use super::{Host, Multi, RecvPause, TransferState};

/// Where the multi is when checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum At {
    /// Between calls from the application: nothing is queued to deliver.
    Rest,
    /// Inside a call a notification made: delivery is under way.
    Delivering,
}

impl<H: Host> Multi<H> {
    /// Panic if any table disagrees with the transfers' states.
    pub(super) fn check_invariants(&self, at: At) {
        let mut running = 0;
        let mut current = 0;
        // Those of the multi's own pool; a share's may be any multi's.
        let mut own_leases = 0;
        let mut queued = 0;
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            let run = self
                .slots
                .get(id)
                .and_then(|s| s.run.as_ref())
                .unwrap_or_else(|| panic!("{id:?}'s run is out of its slot between calls"));
            current += 1;
            if !run.state.is_completed() {
                running += 1;
            }
            if run
                .state
                .lease()
                .is_some_and(|l| matches!(l.home(), crate::conn::Home::Multi))
            {
                own_leases += 1;
            }
            assert!(
                !matches!(run.state, TransferState::Done(_)),
                "{id:?} rests in Done"
            );
            // The trace's state says PENDING exactly while the transfer
            // waits for a connection: one let out is in CONNECT at once.
            let mstate = self.slots.get(id).expect("just found").mstate;
            assert_eq!(
                mstate == super::mstate::MState::Pending,
                matches!(run.state, TransferState::Pending(_)),
                "{id:?} is traced in {mstate:?} in {:?}",
                run.state
            );
            let pause = self.slots.get(id).expect("just found").pause;
            assert!(
                pause.recv != RecvPause::Held || run.state.holds_output(),
                "{id:?} is paused on output it does not hold"
            );
            let wake = if run.state.is_completed() {
                None
            } else {
                run.deadlines.wake_at()
            };
            assert_eq!(
                self.timers.wake_of(id),
                wake,
                "{id:?}'s timer queue entry disagrees with its deadlines"
            );
            queued += usize::from(wake.is_some());
        }
        let counts = self.counts.get();
        assert_eq!(
            (counts.running, counts.current),
            (running, current),
            "the counts disagree with a recount"
        );
        assert_eq!(
            self.timers.len(),
            queued,
            "the timer queue holds stale entries"
        );
        assert_eq!(
            self.caches.pool.leased(),
            own_leases,
            "the pool's leased connections are not the transfers' leases"
        );
        // Removal takes a transfer off every socket (`Curl_multi_ev_xfer_done`),
        // and a connection's close takes it off its own.
        self.sockets.each_user(|user, key| match user {
            super::SocketOwner::Transfer(id) => assert!(
                self.slots.get(id).is_some(),
                "{key:?} names {id:?}, which is not in the multi"
            ),
            super::SocketOwner::Conn(id) => assert!(
                self.shutdowns.holds(id),
                "{key:?} names {id:?}, which is not shutting down"
            ),
            super::SocketOwner::Resolver => assert!(
                self.alive.count > 0,
                "{key:?}, the resolver's wake, is listened on with no transfer alive"
            ),
        });
        // A transfer is alive from its first step until it is done.
        let mut alive = 0;
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            let slot = self.slots.get(id).expect("just found");
            alive += u32::from(slot.run.as_ref().is_some_and(|r| r.alive));
        }
        assert_eq!(
            alive, self.alive.count,
            "the transfers alive are not the count"
        );
        let mut row = 0;
        while let Some(r) = self.dirty.first_from(row) {
            assert!(
                self.slots.key_at(r).is_some(),
                "dirty row {r} holds no transfer"
            );
            row = r + 1;
        }
        if at == At::Rest {
            assert!(
                self.notify.get(0).is_none(),
                "notifications left undelivered"
            );
        }
    }
}
