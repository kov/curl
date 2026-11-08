//! A mutual-exclusion lock that never allocates. std's `Mutex` is a boxed
//! pthread mutex where the system has no futex (macOS), made on its first
//! lock by an allocation that cannot fail: a block C, whose locks are in
//! place, does not make, and an abort under a memory limit. std's
//! `RwLock` is queue-based there and allocates nothing, so [`Lock`] is
//! one, taken only for writing: a `Mutex` in all but its allocation.

#![allow(unsafe_code)]

use core::fmt;
use core::ops::{Deref, DerefMut};
use std::sync::{LockResult, PoisonError, RwLock, RwLockWriteGuard, TryLockError, TryLockResult};

/// What a `Mutex` is, without its allocation: one holder at a time, and
/// poisoned by a panic while held.
#[derive(Default)]
pub struct Lock<T: ?Sized>(RwLock<T>);

// SAFETY: a `Lock` hands out its value only exclusively: through a
// `LockGuard`, which the `RwLock`'s write lock makes the one reference
// to it, or through `&mut self`. Never two threads reach it at once, so
// it needs to be `Send` alone, as `Mutex`'s value does; `RwLock`'s
// shared reads, which would need it `Sync`, are never taken.
unsafe impl<T: ?Sized + Send> Sync for Lock<T> {}

impl<T> Lock<T> {
    pub const fn new(value: T) -> Lock<T> {
        Lock(RwLock::new(value))
    }

    /// The value, the lock gone.
    pub fn into_inner(self) -> LockResult<T> {
        self.0.into_inner()
    }
}

impl<T: ?Sized> Lock<T> {
    /// Wait for the lock and hold it.
    pub fn lock(&self) -> LockResult<LockGuard<'_, T>> {
        self.0
            .write()
            .map(LockGuard)
            .map_err(|e| PoisonError::new(LockGuard(e.into_inner())))
    }

    /// Hold the lock if no one else does.
    pub fn try_lock(&self) -> TryLockResult<LockGuard<'_, T>> {
        match self.0.try_write() {
            Ok(guard) => Ok(LockGuard(guard)),
            Err(TryLockError::Poisoned(e)) => Err(TryLockError::Poisoned(PoisonError::new(
                LockGuard(e.into_inner()),
            ))),
            Err(TryLockError::WouldBlock) => Err(TryLockError::WouldBlock),
        }
    }

    /// The value, reached through the only reference to the lock.
    pub fn get_mut(&mut self) -> LockResult<&mut T> {
        self.0.get_mut()
    }
}

impl<T> From<T> for Lock<T> {
    fn from(value: T) -> Lock<T> {
        Lock::new(value)
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Lock<T> {
    /// The value if the lock is free, as `Mutex` shows it: through the
    /// write lock, never `RwLock`'s own `Debug`, whose read would share it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Lock");
        match self.0.try_write() {
            Ok(guard) => d.field("data", &&*guard),
            Err(TryLockError::Poisoned(e)) => d.field("data", &&*e.into_inner()),
            Err(TryLockError::WouldBlock) => d.field("data", &format_args!("<locked>")),
        };
        d.finish_non_exhaustive()
    }
}

/// The lock held: the one reference to its value until dropped.
pub struct LockGuard<'a, T: ?Sized>(RwLockWriteGuard<'a, T>);

impl<T: ?Sized> Deref for LockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> DerefMut for LockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for LockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T: ?Sized + fmt::Display> fmt::Display for LockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// One holder at a time: a second waits, or is told it would block.
    #[test]
    fn a_lock_has_one_holder_at_a_time() {
        let lock = Lock::new(0u32);
        let held = lock.lock().unwrap();
        assert!(matches!(lock.try_lock(), Err(TryLockError::WouldBlock)));
        assert_eq!(format!("{lock:?}"), "Lock { data: <locked>, .. }");
        drop(held);
        *lock.try_lock().unwrap() += 1;
        assert_eq!(format!("{lock:?}"), "Lock { data: 1, .. }");
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..1000 {
                        *lock.lock().unwrap() += 1;
                    }
                });
            }
        });
        assert_eq!(lock.into_inner().unwrap(), 4001);
    }

    /// A value that is `Send` but not `Sync` is shared through it, as
    /// through a `Mutex`.
    #[test]
    fn a_value_not_sync_is_shared() {
        let lock = Lock::new(Cell::new(1));
        std::thread::scope(|s| {
            s.spawn(|| lock.lock().unwrap().set(2));
        });
        assert_eq!(lock.lock().unwrap().get(), 2);
    }

    /// Neither making it nor holding it allocates, where a `Mutex`'s first
    /// lock does (macOS): the count that sees the `Mutex`'s block sees
    /// none for the lock.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn a_lock_allocates_nothing() {
        use crate::track::count_allocations;
        let (lock, n) = count_allocations(|| {
            let lock = Lock::new(1u32);
            *lock.lock().unwrap() += 1;
            *lock.try_lock().unwrap() += 1;
            lock
        });
        assert_eq!((*lock.lock().unwrap(), n), (3, 0));
        #[allow(clippy::disallowed_types, reason = "the control: std's lock")]
        let ((), n) = count_allocations(|| {
            let mutex = std::sync::Mutex::new(1u32);
            *mutex.lock().unwrap() += 1;
        });
        assert_eq!(n, u64::from(cfg!(target_os = "macos")), "std's Mutex");
    }

    /// A panic while it is held poisons it, as it poisons a `Mutex`.
    #[test]
    fn a_panic_while_held_poisons_it() {
        let lock = Lock::new(1);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = lock.lock().unwrap();
            panic!("held");
        }));
        assert!(panicked.is_err());
        assert_eq!(*lock.lock().unwrap_err().into_inner(), 1);
        assert!(matches!(lock.try_lock(), Err(TryLockError::Poisoned(_))));
    }
}
