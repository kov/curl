//! Which transfers to run: the dirty set, and the multi's counts.

use curl_alloc::{OutOfMemory, TryVec};

/// A set of arena rows, walked in ascending order (C's `uint32_bset`).
/// Room is reserved when a transfer is added, so changing it never
/// allocates; the first 64 rows are held in place, so a multi of no more
/// transfers than that allocates nothing for it.
#[derive(Debug, Default)]
pub(crate) struct RowSet {
    /// Rows 0 to 63.
    first: u64,
    /// The rows from 64, a word for each 64.
    rest: Vec<u64>,
    /// The rows room is reserved for.
    rows: u32,
}

impl RowSet {
    /// Make room for rows below `rows`.
    pub(crate) fn reserve(&mut self, rows: u32) -> Result<(), OutOfMemory> {
        let words = (rows as usize).div_ceil(64).saturating_sub(1);
        if self.rest.len() < words {
            self.rest.try_reserve_exact(words - self.rest.len())?;
            while self.rest.len() < words {
                self.rest.try_push(0)?;
            }
        }
        self.rows = self.rows.max(rows);
        Ok(())
    }

    /// The word holding row word `w`'s 64 rows, if room is made for it.
    fn word_mut(&mut self, w: usize) -> Option<&mut u64> {
        match w {
            0 => Some(&mut self.first),
            _ => self.rest.get_mut(w - 1),
        }
    }

    fn word(&self, w: usize) -> Option<u64> {
        match w {
            0 => Some(self.first),
            _ => self.rest.get(w - 1).copied(),
        }
    }

    pub(crate) fn insert(&mut self, row: u32) {
        assert!(row < self.rows, "room is reserved at add");
        let (w, bit) = place(row);
        *self.word_mut(w).expect("room is reserved at add") |= bit;
    }

    pub(crate) fn remove(&mut self, row: u32) {
        let (w, bit) = place(row);
        if let Some(word) = self.word_mut(w) {
            *word &= !bit;
        }
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, row: u32) -> bool {
        let (w, bit) = place(row);
        self.word(w).is_some_and(|word| word & bit != 0)
    }

    /// The first row in the set at or after `from`.
    pub(crate) fn first_from(&self, from: u32) -> Option<u32> {
        let (mut w, _) = place(from);
        let mut word = self.word(w)? & (u64::MAX << (from % 64));
        loop {
            if word != 0 {
                let row = w * 64 + word.trailing_zeros() as usize;
                return Some(u32::try_from(row).expect("rows fit their u32 ids"));
            }
            w += 1;
            word = self.word(w)?;
        }
    }

    pub(crate) fn clear(&mut self) {
        self.first = 0;
        self.rest.fill(0);
    }
}

fn place(row: u32) -> (usize, u64) {
    (row as usize / 64, 1 << (row % 64))
}

/// How many transfers a multi has, by where they are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Added and not yet completed, waiting ones included: what
    /// `curl_multi_perform` reports as running.
    pub running: u32,
    /// In the multi, completed or not.
    pub current: u32,
    /// Ever added.
    pub added_ever: u64,
}

/// What a multi's transfers are doing at one moment: its counts, and
/// how many of them wait or have completed unread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Census {
    pub counts: Counts,
    /// Of those `counts` says run, the ones waiting for a connection the
    /// multi's limits allow none of yet (`CURLMINFO_XFERS_PENDING`).
    pub pending: u32,
    /// Completed, their message not read yet (`CURLMINFO_XFERS_DONE`).
    pub unread: u32,
}

impl Census {
    /// Of those `counts` says run, the ones worked on: not waiting for a
    /// connection (`CURLMINFO_XFERS_RUNNING`).
    pub fn working(&self) -> u32 {
        self.counts.running - self.pending
    }
}

/// The multi's counts, changed only as transfers come, complete and go.
/// The debug build checks them against a recount after every call.
#[derive(Debug, Default)]
pub(crate) struct Tally(Counts, u32);

impl Tally {
    pub(crate) fn get(&self) -> Counts {
        self.0
    }

    pub(crate) fn added(&mut self) {
        self.0.running += 1;
        self.0.current += 1;
        self.0.added_ever += 1;
    }

    /// How many transfers are the multi's own, `Counts` holding them too,
    /// as C's do.
    pub(crate) fn internals(&self) -> u32 {
        self.1
    }

    pub(crate) fn internal_added(&mut self) {
        self.1 += 1;
    }

    pub(crate) fn internal_removed(&mut self) {
        self.1 -= 1;
    }

    /// An add the timer callback refused: the transfer is gone again, but
    /// it was added.
    pub(crate) fn add_undone(&mut self) {
        self.0.running -= 1;
        self.0.current -= 1;
    }

    pub(crate) fn completed(&mut self) {
        self.0.running -= 1;
    }

    pub(crate) fn removed(&mut self, completed: bool) {
        if !completed {
            self.0.running -= 1;
        }
        self.0.current -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_are_walked_in_order() {
        let mut set = RowSet::default();
        set.reserve(200).unwrap();
        for row in [3, 64, 130, 199] {
            set.insert(row);
        }
        assert_eq!(set.first_from(0), Some(3));
        assert_eq!(set.first_from(4), Some(64));
        assert_eq!(set.first_from(65), Some(130));
        assert_eq!(set.first_from(131), Some(199));
        assert_eq!(set.first_from(200), None);
        set.remove(64);
        assert!(!set.contains(64) && set.contains(130));
        assert_eq!(set.first_from(4), Some(130));
        set.clear();
        assert_eq!(set.first_from(0), None);
    }

    /// The first 64 rows take no memory of their own, the 65th a word:
    /// a multi of a few transfers allocates nothing for its sets, as
    /// test 2500's budget of allocations needs.
    #[test]
    fn the_first_word_of_rows_is_held_in_place() {
        let mut set = RowSet::default();
        set.reserve(64).unwrap();
        for row in [0, 31, 63] {
            set.insert(row);
        }
        assert_eq!(set.rest.capacity(), 0, "64 rows allocate nothing");
        assert_eq!(set.first_from(1), Some(31));
        assert_eq!(set.first_from(64), None);
        set.reserve(65).unwrap();
        set.insert(64);
        assert_eq!(set.rest.len(), 1);
        assert_eq!(set.first_from(32), Some(63));
        assert_eq!(set.first_from(64), Some(64));
    }

    /// unit3211's `uint32_bset` checks, its sets and capacities read from
    /// its source: rows added and found, walked in ascending order,
    /// every other removed, cleared and added again, and kept as room
    /// for twice as many is made. C's capacity rounded up to 64 rows, its
    /// add past the capacity refused and its shrinking have no
    /// counterpart: room is made at a transfer's add, a row past it is a
    /// bug that asserts, and the set never shrinks. Its `u8_strset`,
    /// `u32_ptrset` and `ptrarray` have none either: options are fields,
    /// and HTTP/2's streams and the connections shutting down are held in
    /// std's collections.
    #[test]
    fn unit3211_row_sets() {
        let checks = crate::c_source::calls("tests/unit/unit3211.c", "t3211_check_bset");
        assert_eq!(checks.len(), 2, "the calls were read");
        let walk = |set: &RowSet| {
            let mut rows = Vec::new();
            while let Some(row) = set.first_from(rows.last().map_or(0, |r| r + 1)) {
                rows.push(row);
            }
            rows
        };
        for check in checks {
            let [name, capacity, s, _] = &check[..] else {
                panic!("{check:?}")
            };
            let name = std::str::from_utf8(name.str()).unwrap();
            let table = format!("{}[]", s.word());
            let rows: Vec<u32> =
                crate::c_source::table("tests/unit/unit3211.c", &table, |c| panic!("{c}"))
                    .iter()
                    .map(|v| u32::try_from(v.int()).unwrap())
                    .collect();
            assert!(rows.len() >= 10, "{name} was read");
            let capacity = u32::try_from(capacity.int()).unwrap();
            let mut set = RowSet::default();
            set.reserve(capacity).unwrap();
            set.clear();
            assert_eq!(walk(&set), [], "{name}");
            for (i, &row) in rows.iter().enumerate() {
                set.insert(row);
                assert!(rows[i + 1..].iter().all(|&r| !set.contains(r)), "{name}");
            }
            assert!(rows.iter().all(|&r| set.contains(r)), "{name}");
            assert_eq!(walk(&set), rows, "{name}");
            for &row in rows.iter().step_by(2) {
                set.remove(row);
                assert!(!set.contains(row), "{name}");
            }
            let odd: Vec<u32> = rows.iter().skip(1).step_by(2).copied().collect();
            assert!(odd.iter().all(|&r| set.contains(r)), "{name}");
            assert_eq!(walk(&set).len(), rows.len() / 2, "{name}");
            set.clear();
            assert!(rows.iter().all(|&r| !set.contains(r)), "{name}");
            for &row in &rows {
                set.insert(row);
            }
            set.reserve(capacity * 2).unwrap();
            assert!(rows.iter().all(|&r| set.contains(r)), "{name}");
            assert_eq!(walk(&set), rows, "{name}");
        }
    }
}
