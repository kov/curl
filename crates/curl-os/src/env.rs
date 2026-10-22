//! The process's environment, read through libc's `getenv`.
//!
//! The standard library's `std::env::var_os` copies a value it finds
//! with an allocation that cannot fail, so a value read under memory
//! pressure aborts the process. [`var`] copies it into a fallibly
//! allocated buffer instead, as C's `curl_getenv` copies with `strdup`;
//! [`is_set`] and [`var_into`] read without allocating, as C's bare
//! `getenv` does.
//!
//! None of these take the standard library's environment lock. The
//! value `getenv` points at is valid until the environment next changes,
//! and is copied before each function returns; a thread changing the
//! environment meanwhile (`std::env::set_var`, which is `unsafe` for
//! that reason, or C's `setenv`) races the read, as it races C's own
//! `getenv`. Keeping the environment still while other threads run is
//! the contract of whoever changes it.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char};

use curl_alloc::{OutOfMemory, TryVec};

/// The variable `name`'s value, copied: `None` when it is unset, an
/// empty value when it is set to one. `Err` when memory for the copy
/// cannot be allocated.
pub fn var(name: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
    with_value(name, |value| {
        value
            .map(|v| {
                let mut copy = Vec::new();
                copy.try_extend_from_slice(v)?;
                Ok(copy)
            })
            .transpose()
    })?
}

/// Whether the variable `name` is set, to anything, the empty value
/// included. Allocates nothing.
pub fn is_set(name: &[u8]) -> bool {
    with_value(name, |value| value.is_some()).unwrap_or(false)
}

/// The variable `name`'s value copied into `buf`, as much of it as
/// fits: `None` when it is unset. Allocates nothing.
pub fn var_into<'b>(name: &[u8], buf: &'b mut [u8]) -> Option<&'b [u8]> {
    with_value(name, |value| {
        value.map(|v| {
            let n = v.len().min(buf.len());
            buf[..n].copy_from_slice(&v[..n]);
            n
        })
    })
    .ok()
    .flatten()
    .map(|n| &buf[..n])
}

/// The longest name read without allocating for its terminating NUL.
const NAME_ON_STACK: usize = 128;

/// `f` given the variable `name`'s value as `getenv` finds it. `f` must
/// not keep the slice: it is copied or dropped before this returns. A
/// name holding `=` or NUL is never set; `Err` only when a name too long
/// for the stack cannot be copied to the heap.
fn with_value<R>(name: &[u8], f: impl FnOnce(Option<&[u8]>) -> R) -> Result<R, OutOfMemory> {
    if name.is_empty() || name.iter().any(|&b| b == 0 || b == b'=') {
        return Ok(f(None));
    }
    let mut stack = [0u8; NAME_ON_STACK + 1];
    let mut heap = Vec::new();
    let terminated: &[u8] = if name.len() <= NAME_ON_STACK {
        stack[..name.len()].copy_from_slice(name);
        &stack[..=name.len()]
    } else {
        heap.try_reserve_exact(name.len() + 1)?;
        heap.try_extend_from_slice(name)?;
        heap.try_push(0)?;
        &heap
    };
    let name = CStr::from_bytes_with_nul(terminated).expect("a NUL-free name, terminated");
    // SAFETY: `name` is a NUL-terminated string alive through the call.
    // `getenv` returns null or a pointer into the environment, valid
    // until the environment next changes (see the module's comment for
    // who keeps it still).
    let found: *const c_char = unsafe { libc::getenv(name.as_ptr()) };
    if found.is_null() {
        return Ok(f(None));
    }
    // SAFETY: a non-null `getenv` result is a NUL-terminated string,
    // valid as above; `f` is handed the slice for its call only, and
    // its result cannot borrow it.
    let value = unsafe { CStr::from_ptr(found) }.to_bytes();
    Ok(f(Some(value)))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;

    use super::*;

    fn set(name: &[u8], value: &[u8]) {
        // SAFETY: only `reads_set_unset_empty_and_non_utf8_values` reads
        // or changes the environment in this binary.
        unsafe { std::env::set_var(OsStr::from_bytes(name), OsStr::from_bytes(value)) };
    }

    fn unset(name: &[u8]) {
        // SAFETY: as in `set`.
        unsafe { std::env::remove_var(OsStr::from_bytes(name)) };
    }

    /// One test sets and reads every variable: `getenv` does not take
    /// the standard library's lock, so tests changing the environment
    /// in parallel would race it.
    #[test]
    fn reads_set_unset_empty_and_non_utf8_values() {
        const SET: &[u8] = b"CURL_OS_ENV_TEST_SET";
        const EMPTY: &[u8] = b"CURL_OS_ENV_TEST_EMPTY";
        const BYTES: &[u8] = b"CURL_OS_ENV_TEST_BYTES";
        const UNSET: &[u8] = b"CURL_OS_ENV_TEST_UNSET";
        const NOT_UTF8: &[u8] = b"a\xff\xfe\x80b";
        set(SET, b"value");
        set(EMPTY, b"");
        set(BYTES, NOT_UTF8);
        unset(UNSET);
        assert_eq!(var(SET), Ok(Some(Vec::from(&b"value"[..]))));
        assert_eq!(var(EMPTY), Ok(Some(Vec::new())));
        assert_eq!(var(BYTES), Ok(Some(Vec::from(NOT_UTF8))));
        assert_eq!(var(UNSET), Ok(None));

        assert!(is_set(SET));
        assert!(is_set(EMPTY));
        assert!(!is_set(UNSET));

        let mut buf = [0u8; 3];
        assert_eq!(var_into(SET, &mut buf), Some(&b"val"[..]));
        let mut buf = [0u8; 16];
        assert_eq!(var_into(SET, &mut buf), Some(&b"value"[..]));
        assert_eq!(var_into(BYTES, &mut buf), Some(NOT_UTF8));
        assert_eq!(var_into(UNSET, &mut buf), None);

        // Names that can never be set.
        assert_eq!(var(b""), Ok(None));
        assert_eq!(var(b"CURL_OS_ENV_TEST_SET=value"), Ok(None));
        assert_eq!(var(b"CURL_OS_ENV_TEST_SET\0"), Ok(None));

        // A name too long for the stack is read all the same.
        let mut long = [b'L'; NAME_ON_STACK + 10];
        long[..17].copy_from_slice(b"CURL_OS_ENV_TEST_");
        set(&long, b"long");
        assert_eq!(var(&long), Ok(Some(Vec::from(&b"long"[..]))));

        for name in [SET, EMPTY, BYTES, &long] {
            unset(name);
        }
    }
}
