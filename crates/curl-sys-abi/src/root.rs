//! The shim's one global root: what the C ABI makes process-wide.
//!
//! `curl_global_init` counts its calls, and `curl_global_init_mem` swaps
//! the allocator that memory handed to the application comes from (and
//! that `curl_free` returns it to). The Rust library keeps no global state
//! of its own; this is where the C API's lives.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_long, c_void};
use std::sync::Mutex;

use curl_core::components::{Components, Levels};

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
    realloc: Realloc,
    #[cfg_attr(
        feature = "debug-hooks",
        expect(
            dead_code,
            reason = "a debug build copies strings with `malloc`, as C's does"
        )
    )]
    strdup: Strdup,
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
    /// The last number `CURL_ENTROPY`'s sequence gave, once it has.
    #[cfg(feature = "debug-hooks")]
    entropy: Option<u32>,
}

static ROOT: Mutex<Root> = Mutex::new(Root {
    initialized: 0,
    allocator: SYSTEM,
    #[cfg(feature = "debug-hooks")]
    entropy: None,
});

/// Whether `CURL_ENTROPY` is set, which makes the debug build's random
/// numbers its own.
#[cfg(feature = "debug-hooks")]
pub(crate) fn forced_entropy_set() -> bool {
    // SAFETY: the name is a C string.
    !unsafe { libc::getenv(c"CURL_ENTROPY".as_ptr()) }.is_null()
}

/// The next of the numbers `CURL_ENTROPY` seeds, if it is set, as C's
/// debug build draws its random numbers (`randit`): the variable's first
/// four bytes, big-endian, then one more at each draw, for the whole
/// process as C's static is.
#[cfg(feature = "debug-hooks")]
pub(crate) fn forced_entropy() -> Option<u32> {
    // SAFETY: the name is a C string; the value is read at once, as C's
    // `getenv` is, before anything could change the environment.
    let value = unsafe { libc::getenv(c"CURL_ENTROPY".as_ptr()) };
    if value.is_null() {
        return None;
    }
    // SAFETY: `getenv` gives a C string.
    let given = unsafe { core::ffi::CStr::from_ptr(value) }.to_bytes();
    let mut root = root();
    let next = match root.entropy {
        Some(last) => last.wrapping_add(1),
        None => {
            let mut seed = [0u8; 4];
            let n = given.len().min(4);
            seed[..n].copy_from_slice(&given[..n]);
            u32::from_be_bytes(seed)
        }
    };
    root.entropy = Some(next);
    Some(next)
}

/// Which components trace, for every handle of the process
/// (`curl_global_trace`): part of the root, beside it only because the
/// handles read it without the root's lock. It outlives
/// `curl_global_cleanup`, as C's levels do.
static TRACE: Levels = Levels::new();

/// The process's trace setting, as every handle is given it.
pub(crate) fn components() -> Components {
    Components::of_static(&TRACE)
}

/// What the debug build's `CURL_DEBUG` asks, applied after any other
/// setting (`Curl_trc_opt`).
#[cfg(feature = "debug-hooks")]
fn trace_from_env() {
    // SAFETY: the name is a C string.
    let value = unsafe { libc::getenv(c"CURL_DEBUG".as_ptr()) };
    if !value.is_null() {
        // SAFETY: `getenv` gives a C string, read at once.
        components().configure(unsafe { core::ffi::CStr::from_ptr(value) }.to_bytes());
    }
}

#[cfg(not(feature = "debug-hooks"))]
fn trace_from_env() {}

/// Turn the components `config` names on or off for every handle, those
/// running included (`curl_global_trace`). NULL changes nothing.
///
/// # Safety
///
/// `config` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_global_trace(config: *const c_char) -> CURLcode {
    // As C holds its init lock around the change.
    let _root = root();
    if !config.is_null() {
        // SAFETY: as the caller guarantees.
        components().configure(unsafe { core::ffi::CStr::from_ptr(config) }.to_bytes());
    }
    trace_from_env();
    CURLE_OK
}
const _: ffi::proto::curl_global_trace = curl_global_trace;

/// The TLS libraries this build has, as `curl_global_sslset` lists
/// them: OpenSSL alone.
struct Backends([*const ffi::curl_ssl_backend; 2]);

// SAFETY: the pointers name the static below and a static C string,
// neither ever written.
unsafe impl Sync for Backends {}

static OPENSSL_BACKEND: Backend = Backend(ffi::curl_ssl_backend {
    id: ffi::CURLSSLBACKEND_OPENSSL,
    name: c"openssl".as_ptr(),
});

struct Backend(ffi::curl_ssl_backend);

// SAFETY: as for `Backends`.
unsafe impl Sync for Backend {}

static BACKENDS: Backends = Backends([&raw const OPENSSL_BACKEND.0, core::ptr::null()]);

/// Choose the TLS library by `id` or by `name` (`curl_global_sslset`).
/// This build has one, OpenSSL, always in use: choosing it succeeds, at
/// any time, and any other is not known, as in C built with one. The
/// list of those available is given in `avail` unless NULL.
///
/// # Safety
///
/// `name` is NULL or a C string; `avail` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_global_sslset(
    id: ffi::curl_sslbackend,
    name: *const c_char,
    avail: *mut *mut *const ffi::curl_ssl_backend,
) -> ffi::CURLsslset {
    if !avail.is_null() {
        // SAFETY: as the caller guarantees. C hands out the list as
        // writable too; nothing writes it.
        unsafe { avail.write(BACKENDS.0.as_ptr().cast_mut()) };
    }
    let named = !name.is_null()
        // SAFETY: as the caller guarantees.
        && unsafe { core::ffi::CStr::from_ptr(name) }
            .to_bytes()
            .eq_ignore_ascii_case(b"openssl");
    if id == ffi::CURLSSLBACKEND_OPENSSL || named {
        ffi::CURLSSLSET_OK
    } else {
        ffi::CURLSSLSET_UNKNOWN_BACKEND
    }
}
const _: ffi::proto::curl_global_sslset = curl_global_sslset;

fn root() -> std::sync::MutexGuard<'static, Root> {
    // Panics abort, so the lock is never poisoned.
    ROOT.lock().expect("the global root lock is never poisoned")
}

/// The allocator currently installed.
pub(crate) fn allocator() -> Allocator {
    root().allocator
}

// What the application or the C library installed, called as is.
#[cfg_attr(
    not(feature = "debug-hooks"),
    expect(dead_code, reason = "only the tracker grows or zeroes memory")
)]
impl Allocator {
    pub(crate) fn raw_malloc(&self, size: usize) -> *mut c_void {
        // SAFETY: the installed `malloc` takes any size.
        unsafe { (self.malloc)(size) }
    }

    pub(crate) fn raw_calloc(&self, n: usize, size: usize) -> *mut c_void {
        // SAFETY: the installed `calloc` takes any sizes.
        unsafe { (self.calloc)(n, size) }
    }

    /// # Safety
    ///
    /// `p` is NULL or came from this allocator and is not used again if
    /// this succeeds.
    pub(crate) unsafe fn raw_realloc(&self, p: *mut c_void, size: usize) -> *mut c_void {
        // SAFETY: as the caller guarantees.
        unsafe { (self.realloc)(p, size) }
    }

    /// # Safety
    ///
    /// `p` is NULL or came from this allocator and is not used again.
    pub(crate) unsafe fn raw_free(&self, p: *mut c_void) {
        // SAFETY: as the caller guarantees.
        unsafe { (self.free)(p) }
    }

    /// # Safety
    ///
    /// `s` is a C string.
    #[cfg(not(feature = "debug-hooks"))]
    unsafe fn raw_strdup(&self, s: *const c_char) -> *mut c_char {
        // SAFETY: as the caller guarantees.
        unsafe { (self.strdup)(s) }
    }
}

// Memory handed to the application: tracked, with the Rust caller as its
// source, when the hooks are built in.
impl Allocator {
    /// `size` bytes, or NULL.
    #[track_caller]
    pub(crate) fn malloc(&self, size: usize) -> *mut c_void {
        #[cfg(feature = "debug-hooks")]
        return crate::debug::malloc(self, size, crate::debug::Source::caller());
        #[cfg(not(feature = "debug-hooks"))]
        self.raw_malloc(size)
    }

    /// Free memory from this allocator.
    ///
    /// # Safety
    ///
    /// `p` is NULL or came from this allocator and is not used again.
    #[track_caller]
    pub(crate) unsafe fn free(&self, p: *mut c_void) {
        #[cfg(feature = "debug-hooks")]
        // SAFETY: as the caller guarantees.
        return unsafe { crate::debug::free(self, p, crate::debug::Source::caller()) };
        #[cfg(not(feature = "debug-hooks"))]
        // SAFETY: as the caller guarantees.
        unsafe {
            self.raw_free(p)
        }
    }

    /// A copy of the C string `s`, or NULL.
    ///
    /// # Safety
    ///
    /// `s` points to a NUL-terminated string.
    #[track_caller]
    pub(crate) unsafe fn strdup(&self, s: *const c_char) -> *mut c_char {
        #[cfg(feature = "debug-hooks")]
        // SAFETY: as the caller guarantees.
        return unsafe { crate::debug::strdup(self, s, crate::debug::Source::caller()) };
        #[cfg(not(feature = "debug-hooks"))]
        // SAFETY: as the caller guarantees.
        unsafe {
            self.raw_strdup(s)
        }
    }

    /// A NUL-terminated copy of `bytes` the application frees with
    /// `curl_free`, or NULL if the allocation fails.
    #[track_caller]
    pub(crate) fn c_string(&self, bytes: &[u8]) -> *mut c_char {
        if bytes.is_empty() {
            // As C does: an empty result is a strdup of "".
            // SAFETY: the literal is NUL-terminated.
            return unsafe { self.strdup(c"".as_ptr()) };
        }
        let Some(size) = bytes.len().checked_add(1) else {
            return core::ptr::null_mut();
        };
        let p = self.malloc(size).cast::<u8>();
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

/// The file TLS secrets are logged to (`SSLKEYLOGFILE`), the process's
/// as C's is: opened by the first global init, closed by the last
/// cleanup. Part of the root, beside it as the TLS library reaches it
/// from every handle without the root's lock.
pub(crate) static KEYLOG: curl_core::tls::KeyLog = curl_core::tls::KeyLog::new();

/// Initialise the libraries linked in, as C's global init does
/// (`Curl_ssl_init`): OpenSSL's configuration is read now, and the key
/// log opened (`ossl_init`).
fn libraries_init() {
    curl_openssl::init();
    KEYLOG.open();
}

/// What the libraries linked in let go of at the last cleanup
/// (`ossl_cleanup`).
fn libraries_cleanup() {
    KEYLOG.close();
}

/// The library initialised for a program that did not, as a handle is
/// made (`curl_easy_init`).
pub(crate) fn init_unless_done() {
    let mut root = root();
    if root.initialized == 0 {
        root.allocator = SYSTEM;
        trace_from_env();
        libraries_init();
        root.initialized = 1;
    }
}

fn global_init() -> CURLcode {
    let mut root = root();
    if root.initialized == 0 {
        // The defaults are installed again, as in C.
        root.allocator = SYSTEM;
        // `Curl_trc_init`.
        trace_from_env();
        libraries_init();
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
        trace_from_env();
        libraries_init();
    }
    root.initialized += 1;
    CURLE_OK
}
const _: ffi::proto::curl_global_init_mem = curl_global_init_mem;

/// The allocator `curl_global_init_mem` would install, installed even
/// though the library is initialised: a test's handle made before may
/// have initialised it (`curl_easy_init`), which the test cannot order.
#[cfg(test)]
pub(crate) fn install_mem(
    malloc: Malloc,
    free: Free,
    realloc: Realloc,
    strdup: Strdup,
    calloc: Calloc,
) {
    root().allocator = Allocator {
        malloc,
        free,
        realloc,
        strdup,
        calloc,
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn curl_global_cleanup() {
    let mut root = root();
    // The allocator stays: memory handed out may still be freed with it.
    if root.initialized == 1 {
        libraries_cleanup();
    }
    root.initialized = root.initialized.saturating_sub(1);
}
const _: ffi::proto::curl_global_cleanup = curl_global_cleanup;

/// NULL is passed on to the free callback too, as C does, except where
/// the debug hooks track memory and ignore it.
///
/// # Safety
///
/// `p` is NULL or memory this library handed to the application.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_free(p: *mut c_void) {
    // SAFETY: the caller passes NULL or memory this library allocated with
    // the installed allocator, as `curl_free` requires.
    unsafe { allocator().free(p) };
}
const _: ffi::proto::curl_free = curl_free;
