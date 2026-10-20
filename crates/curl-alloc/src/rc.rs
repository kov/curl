//! Fallible reference-counted pointers, since std's `Rc::try_new` and
//! `Arc::try_new` exist only on nightly.
//!
//! The value and its count live in one block from `try_box`; the last
//! handle dropped frees it. There are no weak references: nothing needs
//! them yet.

#![allow(unsafe_code)]

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::atomic::{self, AtomicUsize, Ordering};

use crate::{OutOfMemory, try_box};

/// A reference-counted pointer for one thread, made fallibly.
pub type TryRc<T> = Shared<T, Cell<usize>>;

/// A reference-counted pointer shared between threads, made fallibly.
pub type TryArc<T> = Shared<T, AtomicUsize>;

/// A count of handles: `Cell<usize>` for one thread, `AtomicUsize` for
/// several.
pub trait Count: Sealed {}
impl Count for Cell<usize> {}
impl Count for AtomicUsize {}

/// The counting `Shared` needs, kept out of reach so only the two counts
/// above exist.
pub trait Sealed {
    fn one() -> Self;
    fn increment(&self);
    /// Count one handle gone; true if it was the last.
    fn decrement(&self) -> bool;
    fn get(&self) -> usize;
}

impl Sealed for Cell<usize> {
    fn one() -> Self {
        Cell::new(1)
    }

    fn increment(&self) {
        let n = self
            .get()
            .checked_add(1)
            .expect("fewer handles than usize::MAX");
        self.set(n);
    }

    fn decrement(&self) -> bool {
        let n = self.get() - 1;
        self.set(n);
        n == 0
    }

    fn get(&self) -> usize {
        Cell::get(self)
    }
}

impl Sealed for AtomicUsize {
    fn one() -> Self {
        AtomicUsize::new(1)
    }

    fn increment(&self) {
        // A new handle comes from an existing one, which keeps the value
        // alive: no ordering is needed, as in std's `Arc`.
        let old = self.fetch_add(1, Ordering::Relaxed);
        assert!(
            old < isize::MAX.unsigned_abs(),
            "fewer handles than isize::MAX"
        );
    }

    fn decrement(&self) -> bool {
        // Every use of the value happens before the last handle frees it,
        // as in std's `Arc`.
        if self.fetch_sub(1, Ordering::Release) != 1 {
            return false;
        }
        atomic::fence(Ordering::Acquire);
        true
    }

    fn get(&self) -> usize {
        self.load(Ordering::Relaxed)
    }
}

struct Inner<T, C> {
    count: C,
    value: T,
}

/// A handle to a value shared by count; see `TryRc` and `TryArc`.
pub struct Shared<T, C: Count> {
    inner: NonNull<Inner<T, C>>,
    /// Owns an `Inner`, for drop checking.
    _owns: PhantomData<Inner<T, C>>,
}

// SAFETY: with an atomic count, handles on several threads only read the
// value and change the count atomically, as std's `Arc`; that needs the
// value to be `Send` (the last handle drops it on any thread) and `Sync`
// (every handle reads it).
unsafe impl<T: Send + Sync> Send for Shared<T, AtomicUsize> {}
// SAFETY: as above.
unsafe impl<T: Send + Sync> Sync for Shared<T, AtomicUsize> {}

impl<T, C: Count> Shared<T, C> {
    /// Move `value` to the heap with a count of one, or fail if the
    /// allocation does.
    pub fn try_new(value: T) -> Result<Self, OutOfMemory> {
        let inner = try_box(Inner {
            count: C::one(),
            value,
        })?;
        Ok(Shared {
            inner: NonNull::from(Box::leak(inner)),
            _owns: PhantomData,
        })
    }

    fn inner(&self) -> &Inner<T, C> {
        // SAFETY: the block stays allocated while any handle exists, and
        // this one does; it is only ever read through shared references.
        unsafe { self.inner.as_ref() }
    }

    /// The number of handles to this value.
    pub fn count(this: &Self) -> usize {
        this.inner().count.get()
    }

    /// Whether both handles point to the same value.
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        a.inner == b.inner
    }
}

impl<T, C: Count> Clone for Shared<T, C> {
    fn clone(&self) -> Self {
        self.inner().count.increment();
        Shared {
            inner: self.inner,
            _owns: PhantomData,
        }
    }
}

impl<T, C: Count> Drop for Shared<T, C> {
    fn drop(&mut self) {
        if self.inner().count.decrement() {
            // SAFETY: the count reached zero, so this was the last handle
            // and nothing else refers to the block, which came from
            // `try_box` through `Box::leak`.
            drop(unsafe { Box::from_raw(self.inner.as_ptr()) });
        }
    }
}

impl<T, C: Count> Deref for Shared<T, C> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner().value
    }
}

impl<T: fmt::Debug, C: Count> fmt::Debug for Shared<T, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts its drops, to see the value dropped once, by the last handle.
    struct Drops<'a>(&'a Cell<u32>);

    impl Drop for Drops<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn the_last_handle_drops_the_value() {
        let drops = Cell::new(0);
        let a = TryRc::try_new(Drops(&drops)).unwrap();
        let b = a.clone();
        assert_eq!(TryRc::count(&a), 2);
        assert!(TryRc::ptr_eq(&a, &b));
        drop(a);
        assert_eq!((drops.get(), TryRc::count(&b)), (0, 1));
        drop(b);
        assert_eq!(drops.get(), 1);
        assert!(!TryRc::ptr_eq(
            &TryRc::try_new(1).unwrap(),
            &TryRc::try_new(1).unwrap()
        ));
    }

    #[test]
    fn shares_between_threads() {
        let value = TryArc::try_new(vec![1u8, 2, 3]).unwrap();
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let mine = value.clone();
                std::thread::spawn(move || mine.iter().map(|&b| u32::from(b)).sum::<u32>())
            })
            .collect();
        for t in threads {
            assert_eq!(t.join().unwrap(), 6);
        }
        assert_eq!(TryArc::count(&value), 1);
        assert_eq!(*TryArc::try_new(()).unwrap(), (), "zero-sized values");
    }
}
