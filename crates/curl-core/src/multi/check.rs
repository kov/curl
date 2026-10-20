//! The multi's invariants, recomputed from scratch and compared with what
//! the multi keeps up to date, after every call in the debug build.

use super::{Host, Multi, TransferState};

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
        let mut leases = 0;
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
            if run.state.holds_lease() {
                leases += 1;
            }
            assert!(
                !matches!(run.state, TransferState::Done(_)),
                "{id:?} rests in Done"
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
            self.pool.len(),
            leases,
            "the pool holds connections no one leases"
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
