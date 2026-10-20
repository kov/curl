//! A fallible `Box::new`, which std has only on nightly.

#![allow(unsafe_code)]

use std::alloc::{Layout, alloc};

use crate::OutOfMemory;

/// Move `value` to the heap, or fail if the allocation does.
pub fn try_box<T>(value: T) -> Result<Box<T>, OutOfMemory> {
    let layout = Layout::new::<T>();
    if layout.size() == 0 {
        // A zero-sized box allocates nothing, so it cannot fail.
        #[allow(clippy::disallowed_methods)]
        return Ok(Box::new(value));
    }
    // SAFETY: `layout` has a non-zero size, checked above.
    let ptr = unsafe { alloc(layout) }.cast::<T>();
    if ptr.is_null() {
        return Err(OutOfMemory);
    }
    // SAFETY: `ptr` is non-null, freshly allocated with `T`'s layout, so it
    // is valid for a write of `T` and nothing else refers to it.
    unsafe { ptr.write(value) };
    // SAFETY: `ptr` came from the global allocator with `Layout::new::<T>()`
    // and holds an initialised `T`, which is what `Box::from_raw` requires;
    // ownership passes to the box.
    Ok(unsafe { Box::from_raw(ptr) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boxes_values_and_zero_sized_types() {
        assert_eq!(*try_box(42u64).unwrap(), 42);
        assert_eq!(*try_box(()).unwrap(), ());
    }
}
