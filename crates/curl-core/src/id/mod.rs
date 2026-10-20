//! Generational ids: keys into an arena that fail by themselves once what
//! they named is gone.
//!
//! An `Arena` hands out rows as C's `Curl_uint32_tbl_add` does, with the
//! growth policy of `multi_xfers_add` in `lib/multi.c`: the next free row
//! after the one last handed out, wrapping around, and growth well before
//! the table is full, so a removed transfer's row is not reused at once.
//! The order a multi visits its transfers and reports their messages is
//! the order of these rows, so it matches C's under any add/remove churn.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::num::NonZeroU32;

use curl_alloc::{OutOfMemory, TryVec};

#[cfg(test)]
#[rustfmt::skip]
mod c_order;

/// The size of an arena when made, and how many leading rows it never
/// hands out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaPolicy {
    initial: u32,
    reserved: u32,
}

impl ArenaPolicy {
    /// `initial` rows, the first `reserved` of them never handed out; the
    /// C ABI reserves row 0 so that ids equal C's, where an internal
    /// handle holds it. `None` unless some row is left to hand out.
    pub fn new(initial: u32, reserved: u32) -> Option<Self> {
        (reserved < initial && initial < MAX_ROWS).then_some(ArenaPolicy { initial, reserved })
    }
}

/// C keeps `UINT_MAX` free as its invalid id.
const MAX_ROWS: u32 = u32::MAX - 1;

/// A key into an `Arena<T>`: its row and the row's generation when the
/// key was made.
pub struct Key<T> {
    row: u32,
    generation: NonZeroU32,
    _of: PhantomData<fn() -> T>,
}

impl<T> Key<T> {
    /// The row: C's id for the same transfer (`mid`).
    pub fn index(self) -> u32 {
        self.row
    }
}

impl<T> Clone for Key<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Key<T> {}

impl<T> PartialEq for Key<T> {
    fn eq(&self, other: &Self) -> bool {
        (self.row, self.generation) == (other.row, other.generation)
    }
}

impl<T> Eq for Key<T> {}

impl<T> Hash for Key<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.row, self.generation).hash(state);
    }
}

impl<T> fmt::Debug for Key<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({}#{})", self.row, self.generation)
    }
}

struct Row<T> {
    /// Bumped when the value is removed, so keys to it go stale. After
    /// 2^32 - 1 values in one row it wraps, and a key that old could match
    /// again.
    generation: NonZeroU32,
    value: Option<T>,
}

/// Values reached by `Key`s, in rows handed out as C hands out its ids.
pub struct Arena<T> {
    rows: Vec<Row<T>>,
    reserved: u32,
    /// Rows holding a value, reserved rows included, as C counts its
    /// internal handle.
    used: u32,
    /// The row last handed out, where the next search starts.
    last_added: Option<u32>,
}

impl<T> Arena<T> {
    pub fn new(policy: ArenaPolicy) -> Result<Self, OutOfMemory> {
        let mut arena = Arena {
            rows: Vec::new(),
            reserved: policy.reserved,
            used: policy.reserved,
            last_added: policy.reserved.checked_sub(1),
        };
        arena.grow_to(policy.initial)?;
        Ok(arena)
    }

    fn capacity(&self) -> u32 {
        u32::try_from(self.rows.len()).expect("rows fit their u32 ids")
    }

    fn grow_to(&mut self, rows: u32) -> Result<(), OutOfMemory> {
        let more = (rows - self.capacity()) as usize;
        self.rows.try_reserve_exact(more)?;
        for _ in 0..more {
            self.rows.try_push(Row {
                generation: NonZeroU32::MIN,
                value: None,
            })?;
        }
        Ok(())
    }

    /// Make sure a row is free for one more value, growing the table as
    /// `multi_xfers_add` does: by half, at least 128 and at most 2048 rows,
    /// once fewer than an eighth of the rows (at least 4) are free.
    pub fn reserve(&mut self) -> Result<Vacancy<'_, T>, OutOfMemory> {
        let capacity = self.capacity();
        let unused = capacity - self.used;
        if capacity < MAX_ROWS && unused < (capacity >> 3).max(4) {
            let growth = (capacity >> 1).clamp(128, 2048);
            self.grow_to(capacity.saturating_add(growth).min(MAX_ROWS))?;
        }
        if self.used == self.capacity() {
            return Err(OutOfMemory);
        }
        Ok(Vacancy { arena: self })
    }

    pub fn get(&self, key: Key<T>) -> Option<&T> {
        let row = self.rows.get(key.row as usize)?;
        row.value
            .as_ref()
            .filter(|_| row.generation == key.generation)
    }

    pub fn get_mut(&mut self, key: Key<T>) -> Option<&mut T> {
        let row = self.rows.get_mut(key.row as usize)?;
        row.value
            .as_mut()
            .filter(|_| row.generation == key.generation)
    }

    /// Take the value out; every key to it is stale from then on.
    pub fn remove(&mut self, key: Key<T>) -> Option<T> {
        let row = self.rows.get_mut(key.row as usize)?;
        if row.generation != key.generation {
            return None;
        }
        let value = row.value.take()?;
        row.generation = row.generation.checked_add(1).unwrap_or(NonZeroU32::MIN);
        self.used -= 1;
        Some(value)
    }

    /// The key of the first value in a row after `after`'s, or the first
    /// of all: rows in ascending order, as C walks its ids.
    pub fn next_after(&self, after: Option<Key<T>>) -> Option<Key<T>> {
        let start = after.map_or(0, |k| k.row as usize + 1);
        let (row, entry) = self
            .rows
            .iter()
            .enumerate()
            .skip(start)
            .find(|(_, r)| r.value.is_some())?;
        Some(Key {
            row: u32::try_from(row).expect("rows fit their u32 ids"),
            generation: entry.generation,
            _of: PhantomData,
        })
    }

    /// The number of values.
    pub fn len(&self) -> u32 {
        self.used - self.reserved
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A free row an `Arena::reserve` made sure of; filling it cannot fail.
pub struct Vacancy<'a, T> {
    arena: &'a mut Arena<T>,
}

impl<T> Vacancy<'_, T> {
    /// Put `value` in the next free row after the one last handed out,
    /// wrapping around, as `Curl_uint32_tbl_add` picks it.
    pub fn fill(self, value: T) -> Key<T> {
        let arena = self.arena;
        let rows = arena.capacity();
        let start = arena.last_added.map_or(rows, |last| last.min(rows)) + 1;
        let free = |row: &u32| *row >= arena.reserved && arena.rows[*row as usize].value.is_none();
        let row = (start..rows)
            .chain(0..start)
            .find(free)
            .expect("`reserve` left a row free");
        let entry = &mut arena.rows[row as usize];
        entry.value = Some(value);
        arena.used += 1;
        arena.last_added = Some(row);
        Key {
            row,
            generation: entry.generation,
            _of: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An add/remove churn replayed on a C multi; see `c_order`.
    pub(super) struct Churn {
        pub(super) rows: u32,
        pub(super) ops: &'static [Op],
    }

    pub(super) enum Op {
        /// Handle number, and the id C gave it.
        Add(u16, u32),
        Remove(u16),
    }

    /// Ids come out in C's order through growth, fragmentation and
    /// wrap-around, for both kinds of multi C makes.
    #[test]
    fn hands_out_ids_as_c_does() {
        for churn in [&c_order::PERFORM, &c_order::MULTI] {
            let mut arena = Arena::new(ArenaPolicy::new(churn.rows, 1).unwrap()).unwrap();
            let mut keys = std::collections::HashMap::new();
            let mut grew = false;
            for (i, op) in churn.ops.iter().enumerate() {
                match *op {
                    Op::Add(handle, id) => {
                        let key = arena.reserve().unwrap().fill(handle);
                        assert_eq!(key.index(), id, "add #{i} of the {}-row churn", churn.rows);
                        grew |= id >= churn.rows;
                        keys.insert(handle, key);
                    }
                    Op::Remove(handle) => {
                        assert_eq!(arena.remove(keys[&handle]), Some(handle));
                    }
                }
            }
            assert!(grew, "the {}-row churn grows the table", churn.rows);
        }
    }

    #[test]
    fn stale_keys_fail_their_lookup() {
        let mut arena = Arena::new(ArenaPolicy::new(16, 0).unwrap()).unwrap();
        let old = arena.reserve().unwrap().fill("old");
        assert_eq!(arena.remove(old), Some("old"));
        // Add and remove until the search wraps around to the old row.
        let new = loop {
            let key = arena.reserve().unwrap().fill("new");
            if key.index() == old.index() {
                break key;
            }
            arena.remove(key);
        };
        assert_eq!(arena.get(old), None);
        assert!(arena.get_mut(old).is_none());
        assert_eq!(arena.remove(old), None);
        assert_eq!(arena.get(new), Some(&"new"));
        assert_eq!(arena.len(), 1);
    }

    #[test]
    fn walks_rows_in_ascending_order() {
        let mut arena = Arena::new(ArenaPolicy::new(8, 1).unwrap()).unwrap();
        let keys: Vec<_> = (0..5).map(|n| arena.reserve().unwrap().fill(n)).collect();
        arena.remove(keys[2]);
        let mut seen = Vec::new();
        let mut at = None;
        while let Some(k) = arena.next_after(at) {
            seen.push(*arena.get(k).unwrap());
            at = Some(k);
        }
        assert_eq!(seen, [0, 1, 3, 4]);
        assert_eq!(keys[0].index(), 1, "the reserved row is never handed out");
    }

    #[test]
    fn policies_leave_a_row_to_hand_out() {
        assert!(ArenaPolicy::new(1, 1).is_none());
        assert!(ArenaPolicy::new(0, 0).is_none());
        assert!(ArenaPolicy::new(MAX_ROWS, 0).is_none());
        assert!(ArenaPolicy::new(2, 1).is_some());
    }
}
