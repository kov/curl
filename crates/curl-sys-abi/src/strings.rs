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

/// Whether the first `max` bytes of `a` and `b` match, ignoring ASCII
/// case, where a string's NUL counts as a byte: read in step, and no
/// further than the first that differs or `a`'s NUL, as lib/strequal.c's
/// `casecompare` and `ncasecompare` read them.
///
/// # Safety
///
/// Each is readable up to its NUL or `max` bytes, whichever comes first.
unsafe fn ascii_case_eq(a: *const c_char, b: *const c_char, max: usize) -> bool {
    let (a, b) = (a.cast::<u8>(), b.cast::<u8>());
    for i in 0..max {
        // SAFETY: neither string has ended before `i`, nor has `max`
        // been reached: `a`'s NUL returns below, and `b`'s, against a
        // byte of `a` that is not one, differs from it.
        let x = unsafe { a.wrapping_add(i).read() };
        // SAFETY: as above.
        let y = unsafe { b.wrapping_add(i).read() };
        if !x.eq_ignore_ascii_case(&y) {
            return false;
        }
        if x == 0 {
            return true;
        }
    }
    true
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
    // SAFETY: both are C strings, as the caller guarantees.
    c_int::from(unsafe { ascii_case_eq(s1, s2, usize::MAX) })
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
    // SAFETY: both are readable up to their NUL or `n` bytes, as the
    // caller guarantees.
    c_int::from(unsafe { ascii_case_eq(s1, s2, n) })
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
    let alloc = root::allocator();
    if bytes.is_empty() {
        return alloc.c_string(b"");
    }
    // As C does: escaped straight into a buffer of three times the
    // input's size and its terminator, refused past a sixteenth of the
    // address space.
    if bytes.len() > usize::MAX / 16 {
        return ptr::null_mut();
    }
    let size = bytes.len() * 3 + 1;
    let out = alloc.malloc(size).cast::<core::mem::MaybeUninit<u8>>();
    if out.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `out` is a fresh allocation of `size` bytes, disjoint from
    // `bytes` and reached through nothing else while the slice lives;
    // `MaybeUninit` needs them set to nothing.
    let room = unsafe { core::slice::from_raw_parts_mut(out, size) };
    let len = curl_core::url::escape_into(bytes, &mut room[..size - 1]);
    room[len].write(0);
    out.cast()
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
    // As C does: decoded straight into a buffer of the input's size and
    // its terminator, as decoding never lengthens.
    let Some(size) = bytes.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let alloc = root::allocator();
    let out = alloc.malloc(size).cast::<u8>();
    if out.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `out` is a fresh allocation of `size` bytes.
    unsafe { out.write_bytes(0, size) };
    // SAFETY: `size` bytes, initialised above, disjoint from `bytes` and
    // reached through nothing else while the slice lives.
    let room = unsafe { core::slice::from_raw_parts_mut(out, size) };
    let len = curl_core::url::unescape_into(bytes, &mut room[..bytes.len()]);
    room[len] = 0;
    let said = match c_int::try_from(len) {
        Ok(n) => n,
        Err(_) if outlength.is_null() => 0,
        Err(_) => {
            // SAFETY: from this allocator, and not used again.
            unsafe { alloc.free(out.cast()) };
            return ptr::null_mut();
        }
    };
    if !outlength.is_null() {
        // SAFETY: points at an `int`, as the caller guarantees.
        unsafe { outlength.write(said) };
    }
    out.cast()
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

    fn eq(a: &core::ffi::CStr, b: &core::ffi::CStr) -> bool {
        // SAFETY: both are C strings.
        unsafe { curl_strequal(a.as_ptr(), b.as_ptr()) == 1 }
    }

    fn neq(a: &core::ffi::CStr, b: &core::ffi::CStr, n: usize) -> bool {
        // SAFETY: as above.
        unsafe { curl_strnequal(a.as_ptr(), b.as_ptr(), n) == 1 }
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
    #[allow(
        clippy::multiple_unsafe_ops_per_block,
        reason = "one contract covers each group of calls"
    )]
    fn compares_like_c() {
        assert!(eq(c"Hello", c"hELLO"));
        assert!(!eq(c"Hello", c"Hell"));
        assert!(!eq(c"Hell", c"Hello"));
        assert!(eq(c"", c""));
        assert!(!eq(c"\u{e4}", c"\u{c4}"), "only ASCII letters fold");
        assert!(neq(c"Hello", c"help", 3));
        assert!(!neq(c"Hello", c"help", 4));
        assert!(neq(c"abc", c"ABC", 10));
        assert!(!neq(c"ab", c"abc", 10));
        assert!(!neq(c"abc", c"ab", 10));
        assert!(neq(c"x", c"y", 0));
        // The first byte that differs ends the reading: what would follow
        // it is never read, as in C.
        let cut = [b'a' as c_char, b'X' as c_char];
        // SAFETY: each is readable up to the byte that differs.
        unsafe {
            assert_eq!(curl_strequal(cut.as_ptr(), c"ab".as_ptr()), 0);
            assert_eq!(curl_strnequal(c"ab".as_ptr(), cut.as_ptr(), 5), 0);
        }
        // SAFETY: NULL is allowed for either.
        unsafe {
            assert_eq!(curl_strequal(ptr::null(), ptr::null()), 1);
            assert_eq!(curl_strequal(c"a".as_ptr(), ptr::null()), 0);
            assert_eq!(curl_strnequal(ptr::null(), ptr::null(), 1), 1);
            assert_eq!(curl_strnequal(ptr::null(), ptr::null(), 0), 0);
        }
    }
}
