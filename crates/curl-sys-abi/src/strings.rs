//! `curl_slist_*`, `curl_strequal`, `curl_strnequal` and `curl_getenv`.
//!
//! `struct curl_slist` is a C data structure the application walks and
//! builds itself, so it exists only here; options that take one convert it
//! for the Rust API. Its nodes and strings come from the allocator the
//! application installed, as in C.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::ffi::{self, curl_slist};
use crate::root;

/// Append a copy of `data` to `list`. Returns the list's head, which is
/// the new node when `list` is NULL, or NULL on failure, leaving `list`
/// unchanged.
///
/// # Safety
///
/// `list` is NULL or a list from this function; `data` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_slist_append(
    list: *mut curl_slist,
    data: *const c_char,
) -> *mut curl_slist {
    if data.is_null() {
        return ptr::null_mut();
    }
    let alloc = root::allocator();
    // SAFETY: `data` is a C string, as the caller guarantees.
    let copy = unsafe { alloc.strdup(data) };
    if copy.is_null() {
        return ptr::null_mut();
    }
    let node = alloc.malloc(size_of::<curl_slist>()).cast::<curl_slist>();
    if node.is_null() {
        // SAFETY: `copy` came from this allocator and is not used again.
        unsafe { alloc.free(copy.cast()) };
        return ptr::null_mut();
    }
    // SAFETY: `node` is a fresh allocation the size of a `curl_slist`,
    // and `malloc` returns memory aligned for any object.
    unsafe {
        node.write(curl_slist {
            data: copy,
            next: ptr::null_mut(),
        })
    };
    if list.is_null() {
        return node;
    }
    let mut last = list;
    // SAFETY: every node of the caller's list is a valid `curl_slist`.
    while let Some(next) = unsafe { ptr::NonNull::new((*last).next) } {
        last = next.as_ptr();
    }
    // SAFETY: `last` is the list's last node, which the caller lets us
    // change.
    unsafe { (*last).next = node };
    list
}
const _: ffi::proto::curl_slist_append = curl_slist_append;

/// # Safety
///
/// `list` is NULL or a list from `curl_slist_append`, not used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_slist_free_all(list: *mut curl_slist) {
    let alloc = root::allocator();
    let mut item = list;
    while !item.is_null() {
        // SAFETY: `item` is a node of the caller's list.
        let node = unsafe { item.read() };
        // SAFETY: the string and the node came from this allocator, and
        // nothing uses them once the list is freed.
        unsafe { alloc.free(node.data.cast()) };
        // SAFETY: as above.
        unsafe { alloc.free(item.cast()) };
        item = node.next;
    }
}
const _: ffi::proto::curl_slist_free_all = curl_slist_free_all;

/// The bytes of a C string up to its NUL, or at most `max`.
///
/// # Safety
///
/// `s` is readable up to its NUL or `max` bytes, whichever comes first.
unsafe fn bytes<'a>(s: *const c_char, max: usize) -> &'a [u8] {
    let s = s.cast::<u8>();
    let mut n = 0;
    while n < max {
        // SAFETY: the byte is before the NUL and within `max`.
        if unsafe { s.wrapping_add(n).read() } == 0 {
            break;
        }
        n += 1;
    }
    // SAFETY: the `n` bytes were just read.
    unsafe { core::slice::from_raw_parts(s, n) }
}

/// Whether the first `max` bytes of `a` and `b` match, ignoring ASCII
/// case, where a string's end counts as a NUL byte.
fn ascii_case_eq_prefix(a: &[u8], b: &[u8], max: usize) -> bool {
    let at = |s: &[u8], i: usize| s.get(i).copied().unwrap_or(0).to_ascii_uppercase();
    (0..max.min(a.len().max(b.len()) + 1)).all(|i| at(a, i) == at(b, i))
}

/// Case-insensitive comparison of ASCII letters only, independent of the
/// locale. Two NULL pointers are equal.
///
/// # Safety
///
/// Each argument is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_strequal(s1: *const c_char, s2: *const c_char) -> c_int {
    if s1.is_null() || s2.is_null() {
        return c_int::from(s1.is_null() && s2.is_null());
    }
    // SAFETY: `s1` is a C string, as the caller guarantees.
    let a = unsafe { bytes(s1, usize::MAX) };
    // SAFETY: so is `s2`.
    let b = unsafe { bytes(s2, usize::MAX) };
    c_int::from(ascii_case_eq_prefix(a, b, usize::MAX))
}
const _: ffi::proto::curl_strequal = curl_strequal;

/// As `curl_strequal`, for at most `n` bytes. Two NULL pointers are equal
/// when `n` is not zero.
///
/// # Safety
///
/// Each argument is NULL, or a C string or an array of at least `n`
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_strnequal(s1: *const c_char, s2: *const c_char, n: usize) -> c_int {
    if s1.is_null() || s2.is_null() {
        return c_int::from(s1.is_null() && s2.is_null() && n != 0);
    }
    // SAFETY: `s1` is readable up to its NUL or `n` bytes, as the caller
    // guarantees.
    let a = unsafe { bytes(s1, n) };
    // SAFETY: so is `s2`.
    let b = unsafe { bytes(s2, n) };
    c_int::from(ascii_case_eq_prefix(a, b, n))
}
const _: ffi::proto::curl_strnequal = curl_strnequal;

/// A copy of the environment variable, or NULL when it is unset or empty.
///
/// # Safety
///
/// `variable` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_getenv(variable: *const c_char) -> *mut c_char {
    if variable.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `variable` is a C string; the environment is not changed
    // while this runs, the same contract as C's `getenv`.
    let value = unsafe { libc::getenv(variable) };
    // SAFETY: a non-NULL result of `getenv` is a C string.
    if value.is_null() || unsafe { value.read() } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `value` is a C string.
    unsafe { root::allocator().strdup(value) }
}
const _: ffi::proto::curl_getenv = curl_getenv;

/// The bytes of `string`: `length` of them, or up to its NUL if 0. `None`
/// for NULL or a negative length.
///
/// # Safety
///
/// `string` is NULL, or readable for `length` bytes, or a C string if
/// `length` is 0.
unsafe fn given<'a>(string: *const c_char, length: c_int) -> Option<&'a [u8]> {
    if string.is_null() {
        return None;
    }
    let length = usize::try_from(length).ok()?;
    Some(match length {
        // SAFETY: a C string, as the caller guarantees.
        0 => unsafe { core::ffi::CStr::from_ptr(string) }.to_bytes(),
        // SAFETY: readable for `length` bytes, as the caller guarantees.
        n => unsafe { core::slice::from_raw_parts(string.cast::<u8>(), n) },
    })
}

/// `string` with every byte but letters, digits and `-._~` escaped as
/// `%XX`, in a C string the application frees with `curl_free`; NULL for
/// NULL, a negative length or no memory.
///
/// # Safety
///
/// As `given`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_escape(
    _curl: *mut ffi::CURL,
    string: *const c_char,
    length: c_int,
) -> *mut c_char {
    // SAFETY: as the caller guarantees.
    let Some(bytes) = (unsafe { given(string, length) }) else {
        return ptr::null_mut();
    };
    match curl_core::url::escape(bytes) {
        Ok(escaped) => root::allocator().c_string(&escaped),
        Err(_) => ptr::null_mut(),
    }
}
const _: ffi::proto::curl_easy_escape = curl_easy_escape;

/// `curl_easy_escape` without a handle, for programs of old.
///
/// # Safety
///
/// As `given`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_escape(string: *const c_char, length: c_int) -> *mut c_char {
    // SAFETY: as the caller guarantees.
    unsafe { curl_easy_escape(ptr::null_mut(), string, length) }
}
const _: ffi::proto::curl_escape = curl_escape;

/// `string` with its `%XX` escapes decoded, in a C string the application
/// frees with `curl_free`, its length in `outlength` if that is not NULL;
/// NULL for NULL, a negative length, a result too long for an `int` to
/// say, or no memory.
///
/// # Safety
///
/// As `given`; `outlength` is NULL or points at an `int`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_unescape(
    _curl: *mut ffi::CURL,
    string: *const c_char,
    length: c_int,
    outlength: *mut c_int,
) -> *mut c_char {
    // SAFETY: as the caller guarantees.
    let Some(bytes) = (unsafe { given(string, length) }) else {
        return ptr::null_mut();
    };
    let Ok(decoded) = curl_core::url::unescape(bytes) else {
        return ptr::null_mut();
    };
    let said = match c_int::try_from(decoded.len()) {
        Ok(n) => n,
        Err(_) if outlength.is_null() => 0,
        Err(_) => return ptr::null_mut(),
    };
    let out = root::allocator().c_string(&decoded);
    if !out.is_null() && !outlength.is_null() {
        // SAFETY: points at an `int`, as the caller guarantees.
        unsafe { outlength.write(said) };
    }
    out
}
const _: ffi::proto::curl_easy_unescape = curl_easy_unescape;

/// `curl_easy_unescape` without a handle or a length out.
///
/// # Safety
///
/// As `given`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_unescape(string: *const c_char, length: c_int) -> *mut c_char {
    // SAFETY: as the caller guarantees.
    unsafe { curl_easy_unescape(ptr::null_mut(), string, length, ptr::null_mut()) }
}
const _: ffi::proto::curl_unescape = curl_unescape;

#[cfg(test)]
mod tests {
    use super::*;

    fn eq(a: &str, b: &str) -> bool {
        ascii_case_eq_prefix(a.as_bytes(), b.as_bytes(), usize::MAX)
    }

    fn neq(a: &str, b: &str, n: usize) -> bool {
        ascii_case_eq_prefix(a.as_bytes(), b.as_bytes(), n)
    }

    /// Appends in order, returns the head and leaves the list alone on
    /// failure, as lib/slist.c.
    #[test]
    #[allow(
        clippy::multiple_unsafe_ops_per_block,
        reason = "one contract covers the whole sequence"
    )]
    fn slist_appends_in_order() {
        // SAFETY: each call gets NULL or a list built here, and C strings.
        unsafe {
            assert!(curl_slist_append(ptr::null_mut(), ptr::null()).is_null());
            let head = curl_slist_append(ptr::null_mut(), c"one".as_ptr());
            assert!(!head.is_null());
            assert_eq!(curl_slist_append(head, c"two".as_ptr()), head);
            assert_eq!(curl_slist_append(head, c"three".as_ptr()), head);
            assert!(curl_slist_append(head, ptr::null()).is_null());
            let mut got = Vec::new();
            let mut item = head;
            while !item.is_null() {
                got.push(core::ffi::CStr::from_ptr((*item).data).to_owned());
                item = (*item).next;
            }
            assert_eq!(got, [c"one", c"two", c"three"]);
            curl_slist_free_all(head);
            curl_slist_free_all(ptr::null_mut());
        }
    }

    /// As `casecompare` and `ncasecompare` in lib/strequal.c.
    #[test]
    fn compares_like_c() {
        assert!(eq("Hello", "hELLO"));
        assert!(!eq("Hello", "Hell"));
        assert!(!eq("Hell", "Hello"));
        assert!(eq("", ""));
        assert!(!eq("ä", "Ä"), "only ASCII letters fold");
        assert!(neq("Hello", "help", 3));
        assert!(!neq("Hello", "help", 4));
        assert!(neq("abc", "ABC", 10));
        assert!(!neq("ab", "abc", 10));
        assert!(neq("x", "y", 0));
    }
}
