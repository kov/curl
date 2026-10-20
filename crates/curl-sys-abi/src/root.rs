//! The shim's one global root: what the C ABI makes process-wide.
//!
//! `curl_global_init` counts its calls, and `curl_global_init_mem` swaps
//! the allocator that memory handed to the application comes from (and
//! that `curl_free` returns it to). The Rust library keeps no global state
//! of its own; this is where the C API's lives.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_long, c_void};
use std::sync::Mutex;

use crate::ffi::{
    self, CURLE_FAILED_INIT, CURLE_OK, CURLcode, curl_calloc_callback, curl_free_callback,
    curl_malloc_callback, curl_realloc_callback, curl_strdup_callback,
};

type Malloc = unsafe extern "C" fn(usize) -> *mut c_void;
type Free = unsafe extern "C" fn(*mut c_void);
type Realloc = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
type Strdup = unsafe extern "C" fn(*const c_char) -> *mut c_char;
type Calloc = unsafe extern "C" fn(usize, usize) -> *mut c_void;

/// Where memory handed to the application comes from.
#[derive(Clone, Copy)]
pub(crate) struct Allocator {
    malloc: Malloc,
    free: Free,
    // Kept to restore the full set the application installed; used once
    // the shim grows or zeroes memory it hands out.
    #[allow(dead_code)]
    realloc: Realloc,
    strdup: Strdup,
    #[allow(dead_code)]
    calloc: Calloc,
}

const SYSTEM: Allocator = Allocator {
    malloc: libc::malloc,
    free: libc::free,
    realloc: libc::realloc,
    strdup: libc::strdup,
    calloc: libc::calloc,
};

struct Root {
    /// `curl_global_init` calls not yet matched by `curl_global_cleanup`.
    initialized: u32,
    allocator: Allocator,
}

static ROOT: Mutex<Root> = Mutex::new(Root {
    initialized: 0,
    allocator: SYSTEM,
});

fn root() -> std::sync::MutexGuard<'static, Root> {
    // Panics abort, so the lock is never poisoned.
    ROOT.lock().expect("the global root lock is never poisoned")
}

/// The allocator currently installed.
pub(crate) fn allocator() -> Allocator {
    root().allocator
}

impl Allocator {
    /// A NUL-terminated copy of `bytes` the application frees with
    /// `curl_free`, or NULL if the allocation fails.
    pub(crate) fn c_string(&self, bytes: &[u8]) -> *mut c_char {
        if bytes.is_empty() {
            // As C does: an empty result is a strdup of "".
            // SAFETY: the literal is NUL-terminated; `strdup` is the
            // application's or the C library's and reads only up to the NUL.
            return unsafe { (self.strdup)(c"".as_ptr()) };
        }
        let Some(size) = bytes.len().checked_add(1) else {
            return core::ptr::null_mut();
        };
        // SAFETY: calling the installed `malloc` with a non-zero size.
        let p = unsafe { (self.malloc)(size) }.cast::<u8>();
        if p.is_null() {
            return p.cast();
        }
        // SAFETY: `p` is a fresh allocation of `size` = `bytes.len() + 1`
        // bytes, disjoint from `bytes`.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len()) };
        // SAFETY: `bytes.len()` is the last of the `size` bytes allocated.
        unsafe { p.wrapping_add(bytes.len()).write(0) };
        p.cast()
    }
}

fn global_init() -> CURLcode {
    let mut root = root();
    if root.initialized == 0 {
        // The defaults are installed again, as in C.
        root.allocator = SYSTEM;
    }
    root.initialized += 1;
    CURLE_OK
}

/// `flags` selects platform parts to initialise; none apply on Linux.
#[unsafe(no_mangle)]
pub extern "C" fn curl_global_init(_flags: c_long) -> CURLcode {
    global_init()
}
const _: ffi::proto::curl_global_init = curl_global_init;

#[unsafe(no_mangle)]
pub extern "C" fn curl_global_init_mem(
    _flags: c_long,
    m: curl_malloc_callback,
    f: curl_free_callback,
    r: curl_realloc_callback,
    s: curl_strdup_callback,
    c: curl_calloc_callback,
) -> CURLcode {
    let (Some(malloc), Some(free), Some(realloc), Some(strdup), Some(calloc)) = (m, f, r, s, c)
    else {
        return CURLE_FAILED_INIT;
    };
    let mut root = root();
    if root.initialized == 0 {
        // Callbacks given to an already initialised library are ignored,
        // but the call still needs its own cleanup, as in C.
        root.allocator = Allocator {
            malloc,
            free,
            realloc,
            strdup,
            calloc,
        };
    }
    root.initialized += 1;
    CURLE_OK
}
const _: ffi::proto::curl_global_init_mem = curl_global_init_mem;

#[unsafe(no_mangle)]
pub extern "C" fn curl_global_cleanup() {
    let mut root = root();
    // The allocator stays: memory handed out may still be freed with it.
    root.initialized = root.initialized.saturating_sub(1);
}
const _: ffi::proto::curl_global_cleanup = curl_global_cleanup;

/// NULL is passed on to the free callback too, as C does.
///
/// # Safety
///
/// `p` is NULL or memory this library handed to the application.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_free(p: *mut c_void) {
    let free = allocator().free;
    // SAFETY: the caller passes NULL or memory this library allocated with
    // the installed allocator, as `curl_free` requires.
    unsafe { free(p) };
}
const _: ffi::proto::curl_free = curl_free;
