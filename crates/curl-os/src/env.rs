//! The process's environment, read through libc's `getenv`, or on
//! Windows the system's `GetEnvironmentVariableA`.
//!
//! The standard library's `std::env::var_os` copies a value it finds
//! with an allocation that cannot fail, so a value read under memory
//! pressure aborts the process. [`var`] copies it into a fallibly
//! allocated buffer instead, as C's `curl_getenv` copies with `strdup`;
//! [`is_set`] and [`var_into`] read without allocating, as C's bare
//! `getenv` does (on Windows, but for a value longer than the stack
//! holds).
//!
//! None of these take the standard library's environment lock. The
//! value `getenv` points at is valid until the environment next changes,
//! and is copied before each function returns; a thread changing the
//! environment meanwhile (`std::env::set_var`, which is `unsafe` for
//! that reason, or C's `setenv`) races the read, as it races C's own
//! `getenv`. Keeping the environment still while other threads run is
//! the contract of whoever changes it.

#![allow(unsafe_code)]

use core::ffi::CStr;
#[cfg(unix)]
use core::ffi::c_char;

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
    lookup(name, f)
}

/// `f` given the value of `name`, as `getenv` finds it.
#[cfg(unix)]
fn lookup<R>(name: &CStr, f: impl FnOnce(Option<&[u8]>) -> R) -> Result<R, OutOfMemory> {
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

/// The most a value read on the stack holds, its NUL included: the
/// longest value the system keeps, in characters (C's `max`), each one
/// byte in a single-byte code page.
#[cfg(windows)]
const VALUE_ON_STACK: usize = 32_768;

/// `f` given the value of `name`, as `GetEnvironmentVariableA` finds it,
/// in the ANSI code page, as C's `curl_getenv` reads it on Windows: the
/// C library's `getenv` keeps a copy of its own, which a change made
/// through the system (std's `set_var` among them) does not reach. A
/// variable set empty is told from one not set by the error the call
/// leaves, which C does not look at. A value too long for the stack is
/// read into memory of its own.
#[cfg(windows)]
fn lookup<R>(name: &CStr, f: impl FnOnce(Option<&[u8]>) -> R) -> Result<R, OutOfMemory> {
    use windows_sys::Win32::Foundation::{ERROR_ENVVAR_NOT_FOUND, GetLastError, SetLastError};
    use windows_sys::Win32::System::Environment::GetEnvironmentVariableA;

    /// What the call says of `name` with `buf` for its value: unset, the
    /// value's length, or the room it needs, its NUL included.
    enum Read {
        Unset,
        Value(usize),
        Needs(usize),
    }
    let read = |buf: &mut [u8]| {
        let room = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `SetLastError` only sets the thread's error.
        unsafe { SetLastError(0) };
        // SAFETY: `name` is a C string alive through the call, and `buf`
        // is writable for the `room` bytes the call is told, which it
        // writes no further than.
        let rc = unsafe { GetEnvironmentVariableA(name.as_ptr().cast(), buf.as_mut_ptr(), room) };
        let rc = usize::try_from(rc).expect("a u32 fits");
        // SAFETY: `GetLastError` only reads the thread's error.
        if rc == 0 && unsafe { GetLastError() } == ERROR_ENVVAR_NOT_FOUND {
            Read::Unset
        } else if rc < buf.len() {
            Read::Value(rc)
        } else {
            Read::Needs(rc)
        }
    };
    let mut stack = [0u8; VALUE_ON_STACK];
    let mut heap: Vec<u8>;
    let mut at_most = &mut stack[..];
    loop {
        match read(at_most) {
            Read::Unset => return Ok(f(None)),
            Read::Value(n) => return Ok(f(Some(&at_most[..n]))),
            // It changed between the calls, or needs more than the stack.
            Read::Needs(n) => {
                heap = curl_alloc::try_zeroed(n)?;
                at_most = &mut heap[..];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt as _;

    use super::*;

    /// `bytes` as std names a variable or value.
    #[cfg(unix)]
    fn os(bytes: &[u8]) -> &std::ffi::OsStr {
        std::ffi::OsStr::from_bytes(bytes)
    }

    /// `bytes` as std names a variable or value: text, which std hands
    /// the system as UTF-16, and the system to `GetEnvironmentVariableA`
    /// in the ANSI code page.
    #[cfg(windows)]
    fn os(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).expect("ASCII")
    }

    fn set(name: &[u8], value: &[u8]) {
        // SAFETY: only `reads_set_unset_empty_and_non_utf8_values` reads
        // or changes the environment in this binary.
        unsafe { std::env::set_var(os(name), os(value)) };
    }

    fn unset(name: &[u8]) {
        // SAFETY: as in `set`.
        unsafe { std::env::remove_var(os(name)) };
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
        #[cfg(unix)]
        const NOT_UTF8: &[u8] = b"a\xff\xfe\x80b";
        // Set through std, a value is text.
        #[cfg(windows)]
        const NOT_UTF8: &[u8] = b"a-b";
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

        // The longest read on the stack.
        let mut most = [b'M'; NAME_ON_STACK];
        most[..17].copy_from_slice(b"CURL_OS_ENV_TEST_");
        assert_eq!(var(&most), Ok(None));
        set(&most, b"most");
        assert_eq!(var(&most), Ok(Some(Vec::from(&b"most"[..]))));

        for name in [SET, EMPTY, BYTES, &long, &most] {
            unset(name);
        }
    }
}
