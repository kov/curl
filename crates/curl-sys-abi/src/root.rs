//! The shim's one global root: what the C ABI makes process-wide.
//!
//! `curl_global_init` counts its calls, and `curl_global_init_mem` swaps
//! the allocator that memory handed to the application comes from (and
//! that `curl_free` returns it to). The Rust library keeps no global state
//! of its own; this is where the C API's lives.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_long, c_void};
use core::sync::atomic::{AtomicPtr, Ordering};
use curl_alloc::Lock;

use curl_core::components::{Components, Levels};
use curl_core::conn::io::Winsock;

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
    /// Unused by a debug build, which copies strings with `malloc`, as
    /// C's does.
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

/// The system's allocator, where the installed one points when no
/// callbacks are.
static SYSTEM_TABLE: Allocator = SYSTEM;

impl Allocator {
    /// Whether `self` and `other` are the same five functions.
    fn same(&self, other: &Allocator) -> bool {
        use core::ptr::fn_addr_eq;
        fn_addr_eq(self.malloc, other.malloc)
            && fn_addr_eq(self.free, other.free)
            && fn_addr_eq(self.realloc, other.realloc)
            && fn_addr_eq(self.strdup, other.strdup)
            && fn_addr_eq(self.calloc, other.calloc)
    }
}

/// The allocator installed: part of the root, beside it because every
/// block handed to the application or given back reads it, and the
/// root's lock for each cost as much as the allocation. Written only with
/// the root's lock held, by the inits; read without it, as C reads its
/// `Curl_cmalloc` and the rest. An init racing other calls is the
/// application's error (`curl_global_init_mem(3)`): a call racing it may
/// use either allocator, but each read sees one table whole, the old or
/// the new, never some functions of each.
static ALLOCATOR: Installed = Installed::new(&SYSTEM_TABLE);

/// One allocator's table, published whole by swapping a single pointer.
struct Installed(AtomicPtr<Allocator>);

impl Installed {
    const fn new(table: &'static Allocator) -> Self {
        Self(AtomicPtr::new(core::ptr::from_ref(table).cast_mut()))
    }

    /// Install `table`. The caller holds the root's lock.
    fn store(&self, _root: &mut Root, table: &'static Allocator) {
        self.0
            .store(core::ptr::from_ref(table).cast_mut(), Ordering::Release);
    }

    fn load(&self) -> Allocator {
        let table = self.0.load(Ordering::Acquire);
        // SAFETY: `table` came from a `&'static Allocator` (`new`,
        // `store`), and nothing writes through it: `SYSTEM_TABLE` is
        // immutable, and a table `Root::table` leaked is never written
        // after it is published and never freed (leaked because a reader
        // may still hold one an init replaced, and nothing says when the
        // last is done: see `Root::table`). The Release store pairs
        // with this Acquire load, so the table's contents, written before
        // the store, are visible whole.
        unsafe { *table }
    }
}

/// A table `Root::table` leaked, and the one leaked before it.
struct Leaked {
    allocator: Allocator,
    older: Option<&'static Leaked>,
}

struct Root {
    /// `curl_global_init` calls not yet matched by `curl_global_cleanup`.
    initialized: u32,
    /// Winsock, started by the first init that asks for it
    /// (`CURL_GLOBAL_WIN32`) and held until the last cleanup; there is
    /// nothing to start on Unix.
    winsock: Option<Winsock>,
    /// The last number `CURL_ENTROPY`'s sequence gave, once it has.
    #[cfg(feature = "debug-hooks")]
    entropy: Option<u32>,
    /// Every table `curl_global_init_mem` has installed, newest first,
    /// kept so that one installed again is reused.
    leaked: Option<&'static Leaked>,
}

impl Root {
    /// A table holding `a`, to install, or `None` if there is no memory
    /// for one: the system's, one installed before, or a new one.
    ///
    /// A table is leaked, never freed, because a reader may still be
    /// using one an init has replaced, and with lock-free reads nothing
    /// says when the last has finished: a table must outlive every
    /// reader, so it lives as long as the process. One is leaked per
    /// distinct allocator installed, not per init; the list keeps each
    /// reachable, so a leak checker does not count it.
    fn table(&mut self, a: Allocator) -> Option<&'static Allocator> {
        if a.same(&SYSTEM) {
            return Some(&SYSTEM_TABLE);
        }
        let mut next = self.leaked;
        while let Some(t) = next {
            if t.allocator.same(&a) {
                return Some(&t.allocator);
            }
            next = t.older;
        }
        let leaked = Leaked {
            allocator: a,
            older: self.leaked,
        };
        // Made once for the process and never freed: not the library's
        // to account for in a memdump, nor for a torture test to refuse.
        #[cfg(feature = "debug-hooks")]
        let boxed = curl_alloc::track::untracked(|| curl_alloc::try_box(leaked));
        #[cfg(not(feature = "debug-hooks"))]
        let boxed = curl_alloc::try_box(leaked);
        let leaked: &'static Leaked = Box::leak(boxed.ok()?);
        self.leaked = Some(leaked);
        Some(&leaked.allocator)
    }
}

static ROOT: Lock<Root> = Lock::new(Root {
    initialized: 0,
    winsock: None,
    #[cfg(feature = "debug-hooks")]
    entropy: None,
    leaked: None,
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

/// The handles' random numbers in the debug build: `CURL_ENTROPY`'s
/// sequence, the root's, if it is set, or else the system's.
#[cfg(feature = "debug-hooks")]
pub(crate) struct RootEntropy;

#[cfg(feature = "debug-hooks")]
pub(crate) static ROOT_ENTROPY: RootEntropy = RootEntropy;

#[cfg(feature = "debug-hooks")]
impl curl_core::libraries::Random for RootEntropy {
    fn active(&self) -> bool {
        forced_entropy_set()
    }

    fn fill(&self, bytes: &mut [u8]) -> std::io::Result<()> {
        for chunk in bytes.chunks_mut(4) {
            let n = forced_entropy().expect("set, as checked");
            chunk.copy_from_slice(&n.to_ne_bytes()[..chunk.len()]);
        }
        Ok(())
    }
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
/// them: the one it was built with.
struct Backends([*const ffi::curl_ssl_backend; 2]);

// SAFETY: the pointers name the static below and a static C string,
// neither ever written.
unsafe impl Sync for Backends {}

static THE_BACKEND: Backend = Backend(ffi::curl_ssl_backend {
    id: crate::tlslib::ID,
    name: crate::tlslib::NAME.as_ptr(),
});

struct Backend(ffi::curl_ssl_backend);

// SAFETY: as for `Backends`.
unsafe impl Sync for Backend {}

static BACKENDS: Backends = Backends([&raw const THE_BACKEND.0, core::ptr::null()]);

/// Choose the TLS library by `id` or by `name` (`curl_global_sslset`).
/// This build has one, always in use: choosing it succeeds, at
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
            .eq_ignore_ascii_case(crate::tlslib::NAME.to_bytes());
    if id == crate::tlslib::ID || named {
        ffi::CURLSSLSET_OK
    } else {
        ffi::CURLSSLSET_UNKNOWN_BACKEND
    }
}
const _: ffi::proto::curl_global_sslset = curl_global_sslset;

fn root() -> curl_alloc::LockGuard<'static, Root> {
    // Panics abort, so the lock is never poisoned.
    ROOT.lock().expect("the global root lock is never poisoned")
}

/// The allocator currently installed.
pub(crate) fn allocator() -> Allocator {
    ALLOCATOR.load()
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

    /// `p` grown or shrunk to `size` bytes, or NULL with `p` untouched; a
    /// NULL `p` allocates.
    ///
    /// # Safety
    ///
    /// `p` is NULL or came from this allocator, and is not used again if
    /// this succeeds.
    #[track_caller]
    pub(crate) unsafe fn realloc(&self, p: *mut c_void, size: usize) -> *mut c_void {
        #[cfg(feature = "debug-hooks")]
        // SAFETY: as the caller guarantees.
        return unsafe { crate::debug::realloc(self, p, size, crate::debug::Source::caller()) };
        #[cfg(not(feature = "debug-hooks"))]
        // SAFETY: as the caller guarantees.
        unsafe {
            self.raw_realloc(p, size)
        }
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
/// log opened (`ossl_init`); GnuTLS is initialised (`gtls_init`);
/// Schannel has nothing to do. Whether the TLS library could be.
fn libraries_init() -> bool {
    crate::tlslib::init()
}

/// What the libraries linked in let go of at the last cleanup
/// (`ossl_cleanup`, `gtls_cleanup`).
fn libraries_cleanup() {
    crate::tlslib::cleanup();
    KEYLOG.close();
}

/// The library initialised for a program that did not, as a handle is
/// made (`curl_easy_init`, with `CURL_GLOBAL_DEFAULT`); `Err` if it could
/// not be.
pub(crate) fn init_unless_done() -> Result<(), ()> {
    let mut root = root();
    if root.initialized == 0 {
        ALLOCATOR.store(&mut root, &SYSTEM_TABLE);
        if first_init(&mut root, c_long::from(ffi::CURL_GLOBAL_DEFAULT)) != CURLE_OK {
            return Err(());
        }
        root.initialized = 1;
    }
    Ok(())
}

/// What the first init sets up, the allocator installed (`global_init`):
/// the trace, then Winsock if `flags` asks for it (`CURL_GLOBAL_WIN32`),
/// which the system may refuse, failing the init; then the libraries.
fn first_init(root: &mut Root, flags: c_long) -> CURLcode {
    // `Curl_trc_init`.
    trace_from_env();
    if flags & c_long::from(ffi::CURL_GLOBAL_WIN32) != 0 {
        match Winsock::start() {
            Ok(started) => root.winsock = Some(started),
            Err(_) => return CURLE_FAILED_INIT,
        }
    }
    if !libraries_init() {
        return CURLE_FAILED_INIT;
    }
    CURLE_OK
}

fn global_init(flags: c_long) -> CURLcode {
    let mut root = root();
    if root.initialized == 0 {
        // The defaults are installed again, as in C.
        ALLOCATOR.store(&mut root, &SYSTEM_TABLE);
        let code = first_init(&mut root, flags);
        if code != CURLE_OK {
            return code;
        }
    }
    root.initialized += 1;
    CURLE_OK
}

/// `flags` selects platform parts to initialise: Winsock on Windows
/// (`CURL_GLOBAL_WIN32`); none apply on Linux.
#[unsafe(no_mangle)]
pub extern "C" fn curl_global_init(flags: c_long) -> CURLcode {
    global_init(flags)
}
const _: ffi::proto::curl_global_init = curl_global_init;

#[unsafe(no_mangle)]
pub extern "C" fn curl_global_init_mem(
    flags: c_long,
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
        let Some(installed) = root.table(Allocator {
            malloc,
            free,
            realloc,
            strdup,
            calloc,
        }) else {
            return ffi::CURLE_OUT_OF_MEMORY;
        };
        ALLOCATOR.store(&mut root, installed);
        let code = first_init(&mut root, flags);
        if code != CURLE_OK {
            return code;
        }
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
    let mut root = root();
    let installed = root
        .table(Allocator {
            malloc,
            free,
            realloc,
            strdup,
            calloc,
        })
        .expect("a test has the memory for an allocator's table");
    ALLOCATOR.store(&mut root, installed);
}

#[unsafe(no_mangle)]
pub extern "C" fn curl_global_cleanup() {
    let mut root = root();
    // The allocator stays: memory handed out may still be freed with it.
    if root.initialized == 1 {
        libraries_cleanup();
        root.winsock = None;
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicBool;

    // A second allocator, each function at an address of its own.
    unsafe extern "C" fn other_malloc(size: usize) -> *mut c_void {
        // SAFETY: any size.
        unsafe { libc::malloc(size) }
    }
    unsafe extern "C" fn other_free(p: *mut c_void) {
        // SAFETY: as the caller guarantees.
        unsafe { libc::free(p) }
    }
    unsafe extern "C" fn other_realloc(p: *mut c_void, size: usize) -> *mut c_void {
        // SAFETY: as the caller guarantees.
        unsafe { libc::realloc(p, size) }
    }
    unsafe extern "C" fn other_strdup(s: *const c_char) -> *mut c_char {
        // SAFETY: as the caller guarantees, a C string.
        unsafe { libc::strdup(s) }
    }
    unsafe extern "C" fn other_calloc(n: usize, size: usize) -> *mut c_void {
        // SAFETY: any sizes.
        unsafe { libc::calloc(n, size) }
    }

    static OTHER: Allocator = Allocator {
        malloc: other_malloc,
        free: other_free,
        realloc: other_realloc,
        strdup: other_strdup,
        calloc: other_calloc,
    };

    fn local_root() -> Root {
        Root {
            initialized: 0,
            winsock: None,
            #[cfg(feature = "debug-hooks")]
            entropy: None,
            leaked: None,
        }
    }

    /// Whether each of the five functions differs between `a` and `b`, so
    /// that a table mixing them is neither.
    fn apart(a: &Allocator, b: &Allocator) -> bool {
        use core::ptr::fn_addr_eq;
        !fn_addr_eq(a.malloc, b.malloc)
            && !fn_addr_eq(a.free, b.free)
            && !fn_addr_eq(a.realloc, b.realloc)
            && !fn_addr_eq(a.strdup, b.strdup)
            && !fn_addr_eq(a.calloc, b.calloc)
    }

    /// Readers racing an init that swaps the allocator back and forth each
    /// see one table whole, never some of one's functions and some of the
    /// other's. Raced on a table of its own: the process's is the other
    /// tests'.
    #[test]
    fn a_read_racing_an_install_sees_one_table_whole() {
        const SWAPS: u32 = if cfg!(miri) { 200 } else { 1_000_000 };
        assert!(apart(&SYSTEM, &OTHER), "the two tables share a function");
        let installed = Installed::new(&SYSTEM_TABLE);
        let done = AtomicBool::new(false);
        let mut root = local_root();
        let seen = std::thread::scope(|s| {
            let readers: [_; 3] = core::array::from_fn(|_| {
                s.spawn(|| {
                    let (mut system, mut other) = (0u64, 0u64);
                    while !done.load(Ordering::Relaxed) {
                        let t = installed.load();
                        if t.same(&SYSTEM) {
                            system += 1;
                        } else if t.same(&OTHER) {
                            other += 1;
                        } else {
                            panic!("a read mixed the two tables");
                        }
                    }
                    (system, other)
                })
            });
            for i in 0..SWAPS {
                let next = if i % 2 == 0 { &OTHER } else { &SYSTEM_TABLE };
                installed.store(&mut root, next);
            }
            done.store(true, Ordering::Relaxed);
            readers.map(|r| r.join().expect("a reader saw one table whole"))
        });
        // The race happened: the readers saw both tables.
        assert!(seen.iter().any(|&(system, _)| system > 0), "{seen:?}");
        assert!(seen.iter().any(|&(_, other)| other > 0), "{seen:?}");
    }

    /// The system's allocator is the static table; another is leaked once
    /// and the same table given for it again, whatever is installed
    /// between. The process's root keeps the tables, which a local one
    /// would drop unfreed, and none is installed.
    #[test]
    fn an_allocator_installed_again_reuses_its_table() {
        let mut root = root();
        let system = root.table(SYSTEM).expect("no allocation");
        assert!(core::ptr::eq(system, &SYSTEM_TABLE));
        let other = root.table(OTHER).expect("memory for a table");
        assert!(other.same(&OTHER));
        assert!(!core::ptr::eq(other, &OTHER), "a copy, not the original");
        let third = Allocator {
            malloc: other_malloc,
            ..SYSTEM
        };
        let third = root.table(third).expect("memory for a table");
        assert!(!core::ptr::eq(third, other));
        let again = root.table(OTHER).expect("memory for a table");
        assert!(core::ptr::eq(again, other), "leaked a second table");
        let system = root.table(SYSTEM).expect("no allocation");
        assert!(core::ptr::eq(system, &SYSTEM_TABLE));
    }
}
