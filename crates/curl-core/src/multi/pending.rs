//! The transfers waiting for room for a connection (C's `multi->pending`):
//! the plan each looks again with, held here while it waits, and the
//! order they are let out in.

use curl_alloc::OutOfMemory;

use super::TransferId;
use super::sched::RowSet;
use super::state::Plan;

/// One transfer waiting, in its id's row.
#[derive(Debug)]
struct Entry<P> {
    id: TransferId,
    plan: P,
}

/// The waiting transfers by row, let out one at a time in ascending
/// order from the row after the one let out last, round to the first
/// (`multi_schedule_pending`). Room is reserved as a transfer is added,
/// so a transfer starts waiting without allocating. An entry is reached
/// only by the id it was entered with: one for a row since handed to
/// another transfer finds nothing.
#[derive(Debug)]
pub(crate) struct PendingQueue<P = Plan> {
    entries: Vec<Option<Entry<P>>>,
    /// The rows of `entries` holding one, walked a word at a time: an
    /// index over them, changed only with them.
    rows: RowSet,
    /// The row last let out (`last_pending_mid`).
    after: Option<u32>,
}

impl<P> Default for PendingQueue<P> {
    fn default() -> Self {
        PendingQueue {
            entries: Vec::new(),
            rows: RowSet::default(),
            after: None,
        }
    }
}

impl<P: std::fmt::Debug> PendingQueue<P> {
    /// Make room for the transfers in rows below `rows`.
    pub(crate) fn reserve(&mut self, rows: u32) -> Result<(), OutOfMemory> {
        self.rows.reserve(rows)?;
        let rows = rows as usize;
        if self.entries.len() < rows {
            self.entries
                .try_reserve_exact(rows - self.entries.len())
                .map_err(|_| OutOfMemory)?;
            self.entries.resize_with(rows, || None);
        }
        Ok(())
    }

    /// Transfer `id` waits, to look again with `plan`.
    pub(crate) fn enter(&mut self, id: TransferId, plan: P) {
        let row = id.index();
        let entry = self
            .entries
            .get_mut(row as usize)
            .expect("room is reserved at add");
        if let Some(held) = entry {
            panic!("{id:?} waits in a row {:?} waits in", held.id);
        }
        *entry = Some(Entry { id, plan });
        self.rows.insert(row);
    }

    /// Transfer `id`'s plan, if it waits; it waits no longer.
    pub(crate) fn take(&mut self, id: TransferId) -> Option<P> {
        let row = id.index();
        let entry = self.entries.get_mut(row as usize)?;
        if entry.as_ref().is_none_or(|e| e.id != id) {
            return None;
        }
        self.rows.remove(row);
        entry.take().map(|e| e.plan)
    }

    /// The next transfer to let out and its plan: the first waiting after
    /// the one let out last, or else the first of all, which a look
    /// finding none after starts the next one from too
    /// (`multi_schedule_pending`).
    pub(crate) fn next(&mut self) -> Option<(TransferId, P)> {
        let row = match self.after.and_then(|r| self.rows.first_from(r + 1)) {
            Some(row) => row,
            None => {
                self.after = None;
                self.rows.first_from(0)?
            }
        };
        let entry = self.entries[row as usize]
            .take()
            .expect("the index names the rows holding one");
        self.rows.remove(row);
        self.after = Some(row);
        Some((entry.id, entry.plan))
    }

    /// Whether transfer `id` waits.
    #[cfg(any(test, debug_assertions))]
    pub(crate) fn holds(&self, id: TransferId) -> bool {
        self.entries
            .get(id.index() as usize)
            .is_some_and(|e| e.as_ref().is_some_and(|e| e.id == id))
    }

    /// How many wait, panicking if the index disagrees with the entries.
    #[cfg(any(test, debug_assertions))]
    pub(crate) fn checked_len(&self) -> usize {
        let mut indexed = 0;
        let mut from = 0;
        while let Some(row) = self.rows.first_from(from) {
            let entry = self.entries[row as usize].as_ref();
            assert!(
                entry.is_some_and(|e| e.id.index() == row),
                "row {row} is indexed waiting, holding {entry:?}"
            );
            indexed += 1;
            from = row + 1;
        }
        let held = self.entries.iter().flatten().count();
        assert_eq!(indexed, held, "the waiting rows' index is short");
        held
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Arena, ArenaPolicy};

    /// Ids in rows 0 to 7, in order.
    fn ids() -> Vec<TransferId> {
        let mut arena =
            Arena::<(), super::super::Transfer>::new(ArenaPolicy::new(16, 0).unwrap()).unwrap();
        (0..8).map(|_| arena.reserve().unwrap().fill(())).collect()
    }

    fn queue() -> PendingQueue<u32> {
        let mut q = PendingQueue::default();
        q.reserve(16).unwrap();
        q
    }

    fn rows(q: &mut PendingQueue<u32>) -> Vec<u32> {
        std::iter::from_fn(|| {
            q.next().map(|(id, row)| {
                assert_eq!(id.index(), row, "an id comes out with its own plan");
                row
            })
        })
        .collect()
    }

    /// Let out in row order after the one let out last, whatever order
    /// they came in, then round to the first (`multi_schedule_pending`):
    /// the one let out last, waiting again, comes after those after it.
    #[test]
    fn the_next_is_the_first_row_after_the_last_let_out() {
        let ids = ids();
        let mut q = queue();
        q.enter(ids[3], 3);
        assert_eq!(q.next().map(|(id, _)| id), Some(ids[3]));
        for row in [1, 3, 5] {
            q.enter(ids[row], row as u32);
        }
        assert_eq!(q.next().map(|(id, _)| id), Some(ids[5]));
        q.enter(ids[4], 4);
        assert_eq!(rows(&mut q), [1, 3, 4]);
    }

    /// A look that finds none starts the next from the first row.
    #[test]
    fn a_look_finding_none_starts_the_next_from_the_first() {
        let ids = ids();
        let mut q = queue();
        q.enter(ids[5], 5);
        assert_eq!(rows(&mut q), [5]);
        for row in [7, 2] {
            q.enter(ids[row], row as u32);
        }
        assert_eq!(rows(&mut q), [2, 7]);
    }

    /// One taken out waits no more; an id that does not wait finds
    /// nothing.
    #[test]
    fn a_transfer_taken_out_is_let_out_no_more() {
        let ids = ids();
        let mut q = queue();
        for row in [1, 2, 6] {
            q.enter(ids[row], row as u32);
        }
        assert_eq!(q.take(ids[2]), Some(2));
        assert_eq!(q.take(ids[2]), None);
        assert_eq!(q.take(ids[3]), None);
        assert!(!q.holds(ids[2]) && q.holds(ids[6]));
        assert_eq!(q.checked_len(), 2);
        assert_eq!(rows(&mut q), [1, 6]);
        assert_eq!(q.checked_len(), 0);
    }
}
