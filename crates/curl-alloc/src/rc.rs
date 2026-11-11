//! Fallible reference-counted pointers, since std's `Rc::try_new` and
//! `Arc::try_new` exist only on nightly.
//!
//! The value and its count live in one block from `try_box`; the last
//! handle dropped frees it. The value may be unsized, a trait object made
//! from a sized one in the same block (`Shared::try_new_unsize`). There
//! are no weak references: nothing needs them yet.

#![allow(unsafe_code)]

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
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

/// The block a `Shared` keeps its count and its value in. Only
/// `Shared::try_new_unsize` hands one out, boxed, for its caller to unsize;
/// nothing outside this module can make one, read it or change its count.
/// So every `Box<SharedBlock>` there is is a block just made, with a count
/// of one and nothing else referring to it, and the value's metadata is the
/// compiler's own.
pub struct SharedBlock<T: ?Sized, C> {
    count: C,
    /// Last, so that the block unsizes with it.
    value: T,
}

/// A handle to a value shared by count; see `TryRc` and `TryArc`.
pub struct Shared<T: ?Sized, C: Count> {
    inner: NonNull<SharedBlock<T, C>>,
    /// Owns a `SharedBlock`, for drop checking.
    _owns: PhantomData<SharedBlock<T, C>>,
}

// SAFETY: with an atomic count, handles on several threads only read the
// value and change the count atomically, as std's `Arc`; that needs the
// value to be `Send` (the last handle drops it on any thread) and `Sync`
// (every handle reads it).
unsafe impl<T: ?Sized + Send + Sync> Send for Shared<T, AtomicUsize> {}
// SAFETY: as above.
unsafe impl<T: ?Sized + Send + Sync> Sync for Shared<T, AtomicUsize> {}

impl<T: ?Sized, C: Count> Shared<T, C> {
    /// Move `value` to the heap with a count of one, in one block, and make
    /// it a `T` with `unsize`, which is `|b| b` where `T` is a trait `S`
    /// implements: the box coerces as it is returned. Fail, dropping
    /// `value`, if the allocation does.
    ///
    /// Stable Rust lets no pointer of ours unsize itself (`CoerceUnsized`),
    /// but a `Box` does, so the caller's closure does the coercion and the
    /// compiler checks it. Whatever box it returns is a block from here
    /// with a count of one (see `SharedBlock`), so it cannot get it wrong.
    pub fn try_new_unsize<S>(
        value: S,
        unsize: impl FnOnce(Box<SharedBlock<S, C>>) -> Box<SharedBlock<T, C>>,
    ) -> Result<Self, OutOfMemory> {
        let block = try_box(SharedBlock {
            count: C::one(),
            value,
        })?;
        Ok(Shared {
            inner: NonNull::from(Box::leak(unsize(block))),
            _owns: PhantomData,
        })
    }

    fn inner(&self) -> &SharedBlock<T, C> {
        // SAFETY: the block stays allocated while any handle exists, and
        // this one does; it is only ever read through shared references.
        unsafe { self.inner.as_ref() }
    }

    /// The number of handles to this value.
    pub fn count(this: &Self) -> usize {
        this.inner().count.get()
    }

    /// Whether both handles point to the same value: the same block,
    /// whatever metadata each pointer carries, as a trait's vtable may be
    /// made more than once.
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        std::ptr::addr_eq(a.inner.as_ptr(), b.inner.as_ptr())
    }
}

impl<T, C: Count> Shared<T, C> {
    /// Move `value` to the heap with a count of one, or fail if the
    /// allocation does.
    pub fn try_new(value: T) -> Result<Self, OutOfMemory> {
        Self::try_new_unsize(value, |b| b)
    }

    /// This handle as a pointer, to hold where only a pointer fits; opaque,
    /// not the value's address. `from_raw` takes it back.
    pub fn into_raw(this: Self) -> NonNull<()> {
        let this = ManuallyDrop::new(this);
        this.inner.cast()
    }

    /// The handle `into_raw` gave up.
    ///
    /// # Safety
    ///
    /// `raw` came from `into_raw` on a handle of this same type, and that
    /// one handle has not been taken back since; or the result is not
    /// dropped, and is only read while a handle is held.
    pub unsafe fn from_raw(raw: NonNull<()>) -> Self {
        Shared {
            inner: raw.cast(),
            _owns: PhantomData,
        }
    }
}

impl<T: ?Sized, C: Count> Clone for Shared<T, C> {
    fn clone(&self) -> Self {
        self.inner().count.increment();
        Shared {
            inner: self.inner,
            _owns: PhantomData,
        }
    }
}

impl<T: ?Sized, C: Count> Drop for Shared<T, C> {
    fn drop(&mut self) {
        if self.inner().count.decrement() {
            self.drop_last();
        }
    }
}

impl<T: ?Sized, C: Count> Shared<T, C> {
    /// Free the block, its count gone to zero. Out of line, as std's
    /// `Arc::drop_slow`: most drops are not the last, and the value's drop
    /// inlined at each would sit in the code around it.
    #[inline(never)]
    fn drop_last(&mut self) {
        // SAFETY: the count reached zero, so this was the last handle
        // and nothing else refers to the block, which came from
        // `try_box` through `Box::leak`; a pointer to an unsized value
        // carries the metadata its box had, which gives the layout it
        // was allocated with.
        drop(unsafe { Box::from_raw(self.inner.as_ptr()) });
    }
}

impl<T: ?Sized, C: Count> Deref for Shared<T, C> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner().value
    }
}

impl<T: ?Sized + fmt::Debug, C: Count> fmt::Debug for Shared<T, C> {
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
    fn a_handle_survives_being_a_pointer() {
        let drops = Cell::new(0);
        let a = TryRc::try_new(Drops(&drops)).unwrap();
        let b = a.clone();
        let raw = TryRc::into_raw(a);
        assert_eq!((drops.get(), TryRc::count(&b)), (0, 2), "not dropped");
        // SAFETY: from `into_raw` just above, taken back once.
        let a = unsafe { TryRc::from_raw(raw) };
        assert!(TryRc::ptr_eq(&a, &b));
        drop(a);
        drop(b);
        assert_eq!(drops.get(), 1);
    }

    /// A trait the tests' values are shared as.
    trait Named {
        fn name(&self) -> &str;
    }

    impl Named for Drops<'_> {
        fn name(&self) -> &str {
            "drops"
        }
    }

    impl Named for [u8; 3] {
        fn name(&self) -> &str {
            "bytes"
        }
    }

    #[test]
    fn an_unsized_value_is_dropped_once_by_the_last_handle() {
        let drops = Cell::new(0);
        let a = TryRc::<dyn Named + '_>::try_new_unsize(Drops(&drops), |b| b).unwrap();
        let b = a.clone();
        let c = b.clone();
        assert_eq!((a.name(), TryRc::count(&a)), ("drops", 3));
        assert!(TryRc::ptr_eq(&a, &c));
        drop(a);
        drop(b);
        assert_eq!((drops.get(), TryRc::count(&c)), (0, 1));
        drop(c);
        assert_eq!(drops.get(), 1);
        let other = TryRc::<dyn Named>::try_new_unsize([1, 2, 3], |b| b).unwrap();
        let again = TryRc::<dyn Named>::try_new_unsize([1, 2, 3], |b| b).unwrap();
        assert_eq!(other.name(), "bytes");
        assert!(!TryRc::ptr_eq(&other, &again));
    }

    #[test]
    fn an_unsized_value_is_shared_between_threads() {
        trait Sum: Send + Sync {
            fn sum(&self) -> u32;
        }
        impl Sum for Vec<u8> {
            fn sum(&self) -> u32 {
                self.iter().map(|&b| u32::from(b)).sum()
            }
        }
        let value = TryArc::<dyn Sum>::try_new_unsize(vec![1u8, 2, 3], |b| b).unwrap();
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let mine = value.clone();
                std::thread::spawn(move || mine.sum())
            })
            .collect();
        for t in threads {
            assert_eq!(t.join().unwrap(), 6);
        }
        assert_eq!(TryArc::count(&value), 1);
    }

    /// The count and the unsized value are one block.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn an_unsized_value_costs_one_allocation() {
        let drops = Cell::new(0);
        let (made, n) = crate::track::count_allocations(|| {
            TryArc::<dyn Named + Sync + '_>::try_new_unsize([7u8; 3], |b| b)
        });
        assert_eq!((made.unwrap().name(), n), ("bytes", 1));
        let (made, n) = crate::track::count_allocations(|| {
            TryRc::<dyn Named + '_>::try_new_unsize(Drops(&drops), |b| b)
        });
        assert_eq!(n, 1);
        drop(made);
        assert_eq!(drops.get(), 1);
    }

    /// A refused block reports it and drops the value it was to hold.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn a_refused_block_drops_its_value() {
        let drops = Cell::new(0);
        let (made, refused) = crate::track::fail_once_after_here(0, || {
            TryRc::<dyn Named + '_>::try_new_unsize(Drops(&drops), |b| b).map(|_| ())
        });
        assert_eq!((made, refused, drops.get()), (Err(OutOfMemory), true, 1));
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
