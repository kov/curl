//! Which transfers to run: the dirty set, and the multi's counts.

use curl_alloc::{OutOfMemory, TryVec};

/// A set of arena rows, walked in ascending order (C's `uint32_bset`).
/// Room is reserved when a transfer is added, so changing it never
/// allocates.
#[derive(Debug, Default)]
pub(crate) struct RowSet {
    words: Vec<u64>,
}

impl RowSet {
    /// Make room for rows below `rows`.
    pub(crate) fn reserve(&mut self, rows: u32) -> Result<(), OutOfMemory> {
        let words = (rows as usize).div_ceil(64);
        if self.words.len() < words {
            self.words.try_reserve_exact(words - self.words.len())?;
            while self.words.len() < words {
                self.words.try_push(0)?;
            }
        }
        Ok(())
    }

    pub(crate) fn insert(&mut self, row: u32) {
        let (w, bit) = place(row);
        *self.words.get_mut(w).expect("room is reserved at add") |= bit;
    }

    pub(crate) fn remove(&mut self, row: u32) {
        let (w, bit) = place(row);
        if let Some(word) = self.words.get_mut(w) {
            *word &= !bit;
        }
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, row: u32) -> bool {
        let (w, bit) = place(row);
        self.words.get(w).is_some_and(|word| word & bit != 0)
    }

    /// The first row in the set at or after `from`.
    pub(crate) fn first_from(&self, from: u32) -> Option<u32> {
        let (mut w, _) = place(from);
        let mut word = *self.words.get(w)? & (u64::MAX << (from % 64));
        loop {
            if word != 0 {
                let row = w * 64 + word.trailing_zeros() as usize;
                return Some(u32::try_from(row).expect("rows fit their u32 ids"));
            }
            w += 1;
            word = *self.words.get(w)?;
        }
    }

    pub(crate) fn clear(&mut self) {
        self.words.fill(0);
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

/// The multi's counts, changed only as transfers come, complete and go.
/// The debug build checks them against a recount after every call.
#[derive(Debug, Default)]
pub(crate) struct Tally(Counts);

impl Tally {
    pub(crate) fn get(&self) -> Counts {
        self.0
    }

    pub(crate) fn added(&mut self) {
        self.0.running += 1;
        self.0.current += 1;
        self.0.added_ever += 1;
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
}
