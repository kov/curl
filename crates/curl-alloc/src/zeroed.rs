//! A fallible zeroed byte buffer (`calloc`), which std has only on
//! nightly.
//!
//! `vec![0; n]` gets its zeroes from the allocator but aborts if the
//! allocation fails; reserving and resizing fails cleanly but writes
//! every byte, which for a large buffer costs what the allocator's
//! zeroed pages do not.

#![allow(unsafe_code)]

use std::alloc::{Layout, alloc_zeroed};

use crate::OutOfMemory;

/// `len` zero bytes, zeroed by the allocator, or fail if the allocation
/// does.
pub fn try_zeroed(len: usize) -> Result<Vec<u8>, OutOfMemory> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let layout = Layout::array::<u8>(len).map_err(|_| OutOfMemory)?;
    // SAFETY: `layout` has a non-zero size, checked above.
    let ptr = unsafe { alloc_zeroed(layout) };
    if ptr.is_null() {
        return Err(OutOfMemory);
    }
    // SAFETY: `ptr` came from the global allocator with the layout of
    // `len` bytes at alignment 1, which is `Vec<u8>`'s for a capacity of
    // `len`; all `len` bytes are initialised, to zero; ownership passes to
    // the vector.
    Ok(unsafe { Vec::from_raw_parts(ptr, len, len) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn makes_zeroed_buffers_of_any_length() {
        assert!(try_zeroed(0).unwrap().is_empty());
        let mut v = try_zeroed(4096).unwrap();
        assert_eq!(v.len(), 4096);
        assert_eq!(v.capacity(), 4096);
        assert!(v.iter().all(|&b| b == 0));
        // It is an ordinary vector: written, grown and dropped.
        v[4095] = 7;
        v.push(8);
        assert_eq!(&v[4094..], &[0, 7, 8]);
    }

    #[test]
    fn refuses_a_length_no_layout_has() {
        assert_eq!(try_zeroed(usize::MAX), Err(OutOfMemory));
    }
}
