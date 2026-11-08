//! The hooks of a C debug build: the `curl_dbg_*` exports and the memory
//! tracker behind them.
//!
//! Test programs built against a debug libcurl route their own `malloc`,
//! `free`, `socket`, `fopen` and friends through `curl_dbg_*`, and
//! `CURL_MEMDEBUG` names a file where every such call is logged, the
//! "memdump" that tests/memanalyzer.pm checks for leaks and counts against
//! a test's limits. `curl_dbg_memlimit` makes the N+1th tracked call fail,
//! for torture tests. Memory the shim hands to the application goes
//! through the same tracker, logged with its Rust caller, so that it and
//! the application's own share one pool: either may be freed with
//! `curl_free` or `curl_dbg_free`, as in C.
//!
//! The tracked calls are lib/memdebug.c's, with one difference: no header
//! is put before each block. C records the size there and never reads it
//! back.
//!
//! The memdump and the limit are `curl_alloc::track`'s, shared with the
//! Rust allocations the global allocator tracks.
//!
//! The prototypes are those of lib/curl_setup.h, which `ffi` does not
//! cover; each is transcribed by hand beside its definition.

#![allow(unsafe_code)]

use core::ffi::{CStr, VaList, c_char, c_int, c_long, c_void};
use core::fmt::{self, Write};
use core::panic::Location;
use core::ptr;
use std::path::Path;

use curl_alloc::track::{self, Line, Ptr};

use crate::ffi::{CURL_SOCKET_BAD as SOCKET_BAD, curl_socket_t as Socket};
use crate::root::{self, Allocator};

/// Where a tracked call was made.
#[derive(Clone, Copy)]
pub(crate) enum Source {
    /// A C caller's `__FILE__` and `__LINE__`.
    C(*const c_char, c_int),
    /// The shim itself, handing memory to the application.
    Rust(&'static Location<'static>),
    /// A call C makes without a source: neither logged nor counted.
    Internal,
}

impl Source {
    #[track_caller]
    pub(crate) fn caller() -> Self {
        Source::Rust(Location::caller())
    }

    /// # Safety
    ///
    /// `file` is NULL or a C string that outlives the call.
    unsafe fn c(file: *const c_char, line: c_int) -> Self {
        if file.is_null() {
            Source::Internal
        } else {
            Source::C(file, line)
        }
    }

    fn is_internal(self) -> bool {
        matches!(self, Source::Internal)
    }

    /// Write `file:line`.
    fn write(self, line: &mut Line) {
        match self {
            Source::C(file, n) => {
                // SAFETY: a `Source::C` holds a C string, by its
                // constructor's contract.
                line.push(unsafe { CStr::from_ptr(file) }.to_bytes());
                let _ = write!(line, ":{n}");
            }
            Source::Rust(at) => {
                let _ = write!(line, "{}:{}", at.file(), at.line());
            }
            Source::Internal => {}
        }
    }
}

/// Log a line built by `build` after `kind` and the source, unless the
/// call is internal.
fn log_call(source: Source, kind: &str, build: impl FnOnce(&mut Line) -> fmt::Result) {
    if source.is_internal() {
        return;
    }
    let mut line = Line::new();
    line.push(kind.as_bytes());
    line.push(b" ");
    source.write(&mut line);
    line.push(b" ");
    let _ = build(&mut line);
    line.push(b"\n");
    track::log(&line);
}

/// Count a tracked call against the limit; true when it must fail, with
/// `errno` set as C sets it.
fn limit_reached(func: &str, source: Source) -> bool {
    if source.is_internal() || !track::limit_reached(func, |l| source.write(l)) {
        return false;
    }
    set_errno(libc::ENOMEM);
    true
}

fn set_errno(value: c_int) {
    #[cfg(all(unix, not(target_vendor = "apple")))]
    use libc::__errno_location as errno_location;
    #[cfg(target_vendor = "apple")]
    use libc::__error as errno_location;
    #[cfg(windows)]
    unsafe extern "C" {
        /// The UCRT's: where this thread's `errno` is.
        #[link_name = "_errno"]
        fn errno_location() -> *mut c_int;
    }
    // SAFETY: it takes nothing and cannot fail.
    let errno = unsafe { errno_location() };
    // SAFETY: it points to this thread's `errno`.
    unsafe { errno.write(value) };
}

/// A tracked `malloc` from `alloc`.
pub(crate) fn malloc(alloc: &Allocator, size: usize, source: Source) -> *mut c_void {
    if limit_reached("malloc", source) {
        return ptr::null_mut();
    }
    let p = alloc.raw_malloc(size);
    log_call(source, "MEM", |l| write!(l, "malloc({size}) = {}", Ptr(p)));
    p
}

/// A tracked `calloc` from `alloc`.
pub(crate) fn calloc(alloc: &Allocator, n: usize, size: usize, source: Source) -> *mut c_void {
    if limit_reached("calloc", source) {
        return ptr::null_mut();
    }
    let p = alloc.raw_calloc(n, size);
    log_call(source, "MEM", |l| {
        write!(l, "calloc({n},{size}) = {}", Ptr(p))
    });
    p
}

/// A tracked `realloc` from `alloc`; a NULL `p` allocates.
///
/// # Safety
///
/// `p` is NULL or a block from this pool, not used again if this succeeds.
pub(crate) unsafe fn realloc(
    alloc: &Allocator,
    p: *mut c_void,
    size: usize,
    source: Source,
) -> *mut c_void {
    if limit_reached("realloc", source) {
        return ptr::null_mut();
    }
    // SAFETY: as the caller guarantees.
    let q = unsafe { alloc.raw_realloc(p, size) };
    log_call(source, "MEM", |l| {
        write!(l, "realloc({}, {size}) = {}", Ptr(p), Ptr(q))
    });
    q
}

/// A tracked copy of a C string, in memory from `alloc`'s `malloc`, as a
/// C debug build makes it.
///
/// # Safety
///
/// `s` is a C string.
pub(crate) unsafe fn strdup(alloc: &Allocator, s: *const c_char, source: Source) -> *mut c_char {
    if limit_reached("strdup", source) {
        return ptr::null_mut();
    }
    // SAFETY: `s` is a C string, as the caller guarantees.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes_with_nul();
    let copy = alloc.raw_malloc(bytes.len()).cast::<u8>();
    if !copy.is_null() {
        // SAFETY: `copy` is a fresh block of `bytes.len()` bytes.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), copy, bytes.len()) };
    }
    let len = bytes.len();
    log_call(source, "MEM", |l| {
        write!(l, "strdup({}) ({len}) = {}", Ptr(s), Ptr(copy))
    });
    copy.cast()
}

/// A tracked `free`. NULL is ignored.
///
/// # Safety
///
/// `p` is NULL or a block from this pool, not used again.
pub(crate) unsafe fn free(alloc: &Allocator, p: *mut c_void, source: Source) {
    if p.is_null() {
        return;
    }
    log_call(source, "MEM", |l| write!(l, "free({})", Ptr(p)));
    // SAFETY: as the caller guarantees.
    unsafe { alloc.raw_free(p) };
}

/// Start logging to `logname`; later calls change nothing.
///
/// # Safety
///
/// `logname` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_memdebug(logname: *const c_char) {
    if logname.is_null() {
        return;
    }
    // SAFETY: `logname` is a C string, as the caller guarantees.
    let name = unsafe { CStr::from_ptr(logname) }.to_bytes();
    if name.is_empty() {
        return;
    }
    // A memdump that cannot be created leaves the test to fail on its
    // absence, as in C.
    #[cfg(unix)]
    let _ = track::start_log(Path::new(
        <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(name),
    ));
    // A name in the ANSI code page that is not UTF-8 is not opened: the
    // test fails on the absence.
    #[cfg(windows)]
    if let Ok(name) = core::str::from_utf8(name) {
        let _ = track::start_log(Path::new(name));
    }
}
const _: unsafe extern "C" fn(*const c_char) = curl_dbg_memdebug;

/// Let `limit` tracked calls succeed and fail the rest; later calls change
/// nothing.
#[unsafe(no_mangle)]
pub extern "C" fn curl_dbg_memlimit(limit: c_long) {
    track::set_limit(as_limit(limit));
}

/// C counts a `long` down and fails at zero, so a negative limit never
/// fails anything.
fn as_limit(limit: c_long) -> u64 {
    u64::try_from(limit).unwrap_or(u64::MAX)
}
const _: extern "C" fn(c_long) = curl_dbg_memlimit;

/// # Safety
///
/// `source` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_malloc(
    size: usize,
    line: c_int,
    source: *const c_char,
) -> *mut c_void {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    malloc(&root::allocator(), size, source)
}
const _: unsafe extern "C" fn(usize, c_int, *const c_char) -> *mut c_void = curl_dbg_malloc;

/// # Safety
///
/// `source` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_calloc(
    n: usize,
    size: usize,
    line: c_int,
    source: *const c_char,
) -> *mut c_void {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    calloc(&root::allocator(), n, size, source)
}
const _: unsafe extern "C" fn(usize, usize, c_int, *const c_char) -> *mut c_void = curl_dbg_calloc;

/// # Safety
///
/// `p` is NULL or a block from this pool; `source` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_realloc(
    p: *mut c_void,
    size: usize,
    line: c_int,
    source: *const c_char,
) -> *mut c_void {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    // SAFETY: as the caller guarantees.
    unsafe { realloc(&root::allocator(), p, size, source) }
}
const _: unsafe extern "C" fn(*mut c_void, usize, c_int, *const c_char) -> *mut c_void =
    curl_dbg_realloc;

/// # Safety
///
/// `s` and `source` are C strings; `source` may be NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_strdup(
    s: *const c_char,
    line: c_int,
    source: *const c_char,
) -> *mut c_char {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    // SAFETY: as the caller guarantees.
    unsafe { strdup(&root::allocator(), s, source) }
}
const _: unsafe extern "C" fn(*const c_char, c_int, *const c_char) -> *mut c_char = curl_dbg_strdup;

/// A tracked copy of the wide string `s`, as the Unicode build has it
/// (`curl_dbg_wcsdup`): counted once as `wcsdup`, logged with its size in
/// bytes.
///
/// # Safety
///
/// `s` is a zero-ended UTF-16 string; `source` is NULL or a C string.
#[cfg(all(windows, feature = "unicode"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_wcsdup(
    s: *const u16,
    line: c_int,
    source: *const c_char,
) -> *mut u16 {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    if limit_reached("wcsdup", source) {
        return ptr::null_mut();
    }
    let mut units = 0;
    // SAFETY: `s` is read up to its ending zero, which it has, as the
    // caller guarantees.
    while unsafe { s.wrapping_add(units).read() } != 0 {
        units += 1;
    }
    let len = (units + 1) * size_of::<u16>();
    let copy = root::allocator().raw_malloc(len).cast::<u16>();
    if !copy.is_null() {
        // SAFETY: `copy` is a fresh block of `len` bytes, `units + 1`
        // units; `s` has as many, its zero included.
        unsafe { ptr::copy_nonoverlapping(s, copy, units + 1) };
    }
    log_call(source, "MEM", |l| {
        write!(l, "wcsdup({}) ({len}) = {}", Ptr(s), Ptr(copy))
    });
    copy
}
#[cfg(all(windows, feature = "unicode"))]
const _: unsafe extern "C" fn(*const u16, c_int, *const c_char) -> *mut u16 = curl_dbg_wcsdup;

/// # Safety
///
/// `p` is NULL or a block from this pool; `source` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_free(p: *mut c_void, line: c_int, source: *const c_char) {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    // SAFETY: as the caller guarantees.
    unsafe { free(&root::allocator(), p, source) }
}
const _: unsafe extern "C" fn(*mut c_void, c_int, *const c_char) = curl_dbg_free;

/// # Safety
///
/// `source` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_socket(
    domain: c_int,
    kind: c_int,
    protocol: c_int,
    line: c_int,
    source: *const c_char,
) -> Socket {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    if limit_reached("socket", source) {
        return SOCKET_BAD;
    }
    // SAFETY: `socket` takes any arguments.
    let fd = unsafe { sys::socket(domain, kind, protocol) };
    if fd != SOCKET_BAD {
        log_call(source, "FD", |l| write!(l, "socket() = {fd}"));
    }
    fd
}
const _: unsafe extern "C" fn(c_int, c_int, c_int, c_int, *const c_char) -> Socket =
    curl_dbg_socket;

/// # Safety
///
/// `fds` points to two sockets' room; `source` is NULL or a C string.
#[cfg(unix)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_socketpair(
    domain: c_int,
    kind: c_int,
    protocol: c_int,
    fds: *mut Socket,
    line: c_int,
    source: *const c_char,
) -> c_int {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    // SAFETY: `fds` has room for two, as the caller guarantees.
    let rc = unsafe { libc::socketpair(domain, kind, protocol, fds) };
    if rc == 0 {
        // SAFETY: `socketpair` succeeded and wrote both.
        let first = unsafe { fds.read() };
        // SAFETY: as above.
        let second = unsafe { fds.wrapping_add(1).read() };
        let pair = [first, second];
        log_call(source, "FD", |l| {
            write!(l, "socketpair() = {} {}", pair[0], pair[1])
        });
    }
    rc
}
#[cfg(unix)]
const _: unsafe extern "C" fn(c_int, c_int, c_int, *mut Socket, c_int, *const c_char) -> c_int =
    curl_dbg_socketpair;

/// # Safety
///
/// As `accept(2)`; `source` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_accept(
    s: Socket,
    addr: *mut c_void,
    addrlen: *mut c_void,
    line: c_int,
    source: *const c_char,
) -> Socket {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    // SAFETY: as the caller guarantees.
    let fd = unsafe { sys::accept(s, addr.cast(), addrlen.cast()) };
    if fd != SOCKET_BAD {
        log_call(source, "FD", |l| write!(l, "accept() = {fd}"));
    }
    fd
}
const _: unsafe extern "C" fn(Socket, *mut c_void, *mut c_void, c_int, *const c_char) -> Socket =
    curl_dbg_accept;

/// # Safety
///
/// As `accept4(2)`; `source` is NULL or a C string. Only where the
/// system has `accept4`, as C's (`HAVE_ACCEPT4`): not macOS.
#[cfg(all(unix, not(target_vendor = "apple")))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_accept4(
    s: Socket,
    addr: *mut c_void,
    addrlen: *mut c_void,
    flags: c_int,
    line: c_int,
    source: *const c_char,
) -> Socket {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    // SAFETY: as the caller guarantees.
    let fd = unsafe { libc::accept4(s, addr.cast(), addrlen.cast(), flags) };
    if fd != SOCKET_BAD {
        log_call(source, "FD", |l| write!(l, "accept() = {fd}"));
    }
    fd
}
#[cfg(all(unix, not(target_vendor = "apple")))]
const _: unsafe extern "C" fn(
    Socket,
    *mut c_void,
    *mut c_void,
    c_int,
    c_int,
    *const c_char,
) -> Socket = curl_dbg_accept4;

/// Log a socket as closed without closing it.
///
/// # Safety
///
/// `source` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_mark_sclose(fd: Socket, line: c_int, source: *const c_char) {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    log_call(source, "FD", |l| write!(l, "sclose({fd})"));
}
const _: unsafe extern "C" fn(Socket, c_int, *const c_char) = curl_dbg_mark_sclose;

/// # Safety
///
/// The caller owns `fd`; `source` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_sclose(fd: Socket, line: c_int, source: *const c_char) -> c_int {
    // SAFETY: as the caller guarantees.
    unsafe { curl_dbg_mark_sclose(fd, line, source) };
    // SAFETY: the caller owns `fd` and gives it up.
    unsafe { sys::close(fd) }
}

/// The system's socket calls, by the C names `memdebug.c` calls them.
#[cfg(unix)]
mod sys {
    pub(super) use libc::{accept, close, socket};
}

/// Winsock's socket calls, a `SOCKET` as the headers' `curl_socket_t`.
#[cfg(windows)]
mod sys {
    use core::ffi::{c_int, c_void};

    use windows_sys::Win32::Networking::WinSock as ws;

    use super::Socket;

    /// # Safety
    ///
    /// None beyond Winsock's own: it takes any arguments.
    pub(super) unsafe fn socket(domain: c_int, kind: c_int, protocol: c_int) -> Socket {
        // SAFETY: as above.
        unsafe { ws::socket(domain, kind, protocol) as Socket }
    }

    /// # Safety
    ///
    /// As `accept`: `addr` and `len` are NULL or room for the address and
    /// its length.
    pub(super) unsafe fn accept(s: Socket, addr: *mut c_void, len: *mut c_void) -> Socket {
        // SAFETY: as the caller guarantees.
        unsafe { ws::accept(s as ws::SOCKET, addr.cast(), len.cast()) as Socket }
    }

    /// # Safety
    ///
    /// The caller owns `s` and gives it up.
    pub(super) unsafe fn close(s: Socket) -> c_int {
        // SAFETY: as the caller guarantees.
        unsafe { ws::closesocket(s as ws::SOCKET) }
    }
}
const _: unsafe extern "C" fn(Socket, c_int, *const c_char) -> c_int = curl_dbg_sclose;

/// How the debug build opens a file by name (`CURLX_FOPEN_LOW`,
/// `CURLX_FREOPEN_LOW`): the C library's calls on Unix.
#[cfg(unix)]
mod files {
    use core::ffi::c_char;

    /// # Safety
    ///
    /// As `fopen(3)`.
    pub(super) unsafe fn open(file: *const c_char, mode: *const c_char) -> *mut libc::FILE {
        // SAFETY: as the caller guarantees.
        unsafe { libc::fopen(file, mode) }
    }

    /// # Safety
    ///
    /// As `freopen(3)`.
    pub(super) unsafe fn reopen(
        file: *const c_char,
        mode: *const c_char,
        fh: *mut libc::FILE,
    ) -> *mut libc::FILE {
        // SAFETY: as the caller guarantees.
        unsafe { libc::freopen(file, mode, fh) }
    }
}

/// How the debug build opens a file by name on Windows
/// (`curlx_win32_fopen`, `curlx_win32_freopen`): the name and the mode
/// read as the build reads names, UTF-8 in the Unicode build and the
/// ANSI code page otherwise, a long name made absolute and marked
/// (`fix_excessive_path`), and opened by the C library's wide calls,
/// shared for reading and writing (`_SH_DENYNO`). A name or mode that
/// cannot be read fails with `EINVAL`. The conversions are not counted,
/// as C makes them with the system's `malloc`.
#[cfg(windows)]
mod files {
    use core::ffi::{CStr, c_char, c_int};

    use curl_alloc::track;

    /// The C library's `_SH_DENYNO`: others may read and write too.
    const SH_DENYNO: c_int = 0x40;

    unsafe extern "C" {
        /// The UCRT's `_wfsopen`.
        fn _wfsopen(file: *const u16, mode: *const u16, share: c_int) -> *mut libc::FILE;
        /// The UCRT's `_wfreopen_s`: the stream opened through `out`, the
        /// error returned.
        fn _wfreopen_s(
            out: *mut *mut libc::FILE,
            file: *const u16,
            mode: *const u16,
            fh: *mut libc::FILE,
        ) -> c_int;
    }

    /// The name and the mode in UTF-16, or `None` with `errno` set.
    ///
    /// # Safety
    ///
    /// `file` and `mode` are C strings.
    unsafe fn wide(file: *const c_char, mode: *const c_char) -> Option<(Vec<u16>, Vec<u16>)> {
        // SAFETY: as the caller guarantees.
        let file = unsafe { CStr::from_ptr(file) };
        // SAFETY: as the caller guarantees.
        let mode = unsafe { CStr::from_ptr(mode) };
        let both = track::untracked(|| {
            Some((
                curl_os::fs::wide_name(file).ok()?,
                curl_os::fs::wide_text(mode).ok()?,
            ))
        });
        if both.is_none() {
            super::set_errno(libc::EINVAL);
        }
        both
    }

    /// # Safety
    ///
    /// As `fopen(3)`.
    pub(super) unsafe fn open(file: *const c_char, mode: *const c_char) -> *mut libc::FILE {
        // SAFETY: as the caller guarantees.
        let Some((file, mode)) = (unsafe { wide(file, mode) }) else {
            return core::ptr::null_mut();
        };
        // SAFETY: both are zero-ended UTF-16, alive for the call.
        let f = unsafe { _wfsopen(file.as_ptr(), mode.as_ptr(), SH_DENYNO) };
        track::untracked(|| drop((file, mode)));
        f
    }

    /// # Safety
    ///
    /// As `freopen(3)`.
    pub(super) unsafe fn reopen(
        file: *const c_char,
        mode: *const c_char,
        fh: *mut libc::FILE,
    ) -> *mut libc::FILE {
        // SAFETY: as the caller guarantees.
        let Some((file, mode)) = (unsafe { wide(file, mode) }) else {
            return core::ptr::null_mut();
        };
        let mut f = core::ptr::null_mut();
        // SAFETY: `f` is room for the stream; the names are zero-ended
        // UTF-16, alive for the call; `fh` is the caller's stream.
        let e = unsafe { _wfreopen_s(&raw mut f, file.as_ptr(), mode.as_ptr(), fh) };
        super::set_errno(e);
        track::untracked(|| drop((file, mode)));
        f
    }
}

/// # Safety
///
/// `file`, `mode` and `source` are C strings; `source` may be NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_fopen(
    file: *const c_char,
    mode: *const c_char,
    line: c_int,
    source: *const c_char,
) -> *mut libc::FILE {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    // SAFETY: as the caller guarantees.
    let f = unsafe { files::open(file, mode) };
    log_call(source, "FILE", |l| {
        l.push(b"fopen(\"");
        // SAFETY: as the caller guarantees.
        l.push(unsafe { CStr::from_ptr(file) }.to_bytes());
        l.push(b"\",\"");
        // SAFETY: as the caller guarantees.
        l.push(unsafe { CStr::from_ptr(mode) }.to_bytes());
        write!(l, "\") = {}", Ptr(f))
    });
    f
}
const _: unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    c_int,
    *const c_char,
) -> *mut libc::FILE = curl_dbg_fopen;

/// # Safety
///
/// As `freopen(3)`; `source` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_freopen(
    file: *const c_char,
    mode: *const c_char,
    fh: *mut libc::FILE,
    line: c_int,
    source: *const c_char,
) -> *mut libc::FILE {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    // SAFETY: as the caller guarantees.
    let f = unsafe { files::reopen(file, mode, fh) };
    log_call(source, "FILE", |l| {
        l.push(b"freopen(\"");
        // SAFETY: as the caller guarantees.
        l.push(unsafe { CStr::from_ptr(file) }.to_bytes());
        l.push(b"\",\"");
        // SAFETY: as the caller guarantees.
        l.push(unsafe { CStr::from_ptr(mode) }.to_bytes());
        write!(l, "\",{}) = {}", Ptr(fh), Ptr(f))
    });
    f
}
const _: unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *mut libc::FILE,
    c_int,
    *const c_char,
) -> *mut libc::FILE = curl_dbg_freopen;

/// # Safety
///
/// As `fdopen(3)`; `source` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_fdopen(
    fd: c_int,
    mode: *const c_char,
    line: c_int,
    source: *const c_char,
) -> *mut libc::FILE {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    // SAFETY: as the caller guarantees.
    let f = unsafe { libc::fdopen(fd, mode) };
    log_call(source, "FILE", |l| {
        write!(l, "fdopen(\"{fd}\",\"")?;
        // SAFETY: as the caller guarantees.
        l.push(unsafe { CStr::from_ptr(mode) }.to_bytes());
        write!(l, "\") = {}", Ptr(f))
    });
    f
}
const _: unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char) -> *mut libc::FILE =
    curl_dbg_fdopen;

/// # Safety
///
/// `file` is an open stream the caller gives up; `source` is NULL or a C
/// string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_fclose(
    file: *mut libc::FILE,
    line: c_int,
    source: *const c_char,
) -> c_int {
    // SAFETY: as the caller guarantees.
    let source = unsafe { Source::c(source, line) };
    log_call(source, "FILE", |l| write!(l, "fclose({})", Ptr(file)));
    // SAFETY: as the caller guarantees.
    unsafe { libc::fclose(file) }
}
const _: unsafe extern "C" fn(*mut libc::FILE, c_int, *const c_char) -> c_int = curl_dbg_fclose;

/// Write a `curl_mprintf` format to the memdump.
///
/// # Safety
///
/// As `curl_mprintf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_dbg_log(format: *const c_char, args: ...) {
    // SAFETY: forwarded from the caller.
    unsafe { vlog(format, args) }
}
const _: unsafe extern "C" fn(*const c_char, ...) = curl_dbg_log;

/// # Safety
///
/// As `curl_mvprintf`.
unsafe fn vlog(format: *const c_char, args: VaList<'_>) {
    let mut line = Line::new();
    let buf = line.buffer();
    // SAFETY: the buffer has room for its length; the format and
    // arguments are the caller's.
    let n =
        unsafe { crate::printf::curl_mvsnprintf(buf.as_mut_ptr().cast(), buf.len(), format, args) };
    line.set_len(usize::try_from(n).unwrap_or(0));
    track::log(&line);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Memory tracking in the library, as the C suite's test 558 checks it
    /// for C's. Test 558 matches C's source file names in the memdump
    /// (`escape.c`); this checks the same property for ours: run as lib558
    /// runs, with `CURL_MEMDEBUG` set, the memdump records the program's
    /// own block and the escape's, each allocated and freed, and
    /// tests/memanalyze.pl, the analyser runtests.pl uses, finds nothing
    /// wrong in it. The library's start and end allocate nothing tracked,
    /// as in the reference build, whose dump of lib558 holds the same four
    /// records. Run in a process of its own, as the memdump is opened once
    /// per process.
    #[test]
    fn test558_libtest_memory_tracking_operational() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let memdump =
            std::env::temp_dir().join(format!("curl-sys-abi-memdump-{}", std::process::id()));
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "debug::tests::lib558", "--ignored"])
            .env("CURL_MEMDEBUG", &memdump)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{stdout}");
        assert!(stdout.contains("1 passed"), "the program ran: {stdout}");
        let log = std::fs::read_to_string(&memdump).unwrap_or_default();

        // The records are there: without them a clean analysis proves
        // nothing. Each block is allocated where its caller says and
        // freed by its address.
        let allocated = |source: &str, size: &str| {
            log.lines().find_map(|l| {
                let rest = l.strip_prefix(&format!("MEM {source}"))?;
                let (_, p) = rest.split_once(&format!(" malloc({size}) = "))?;
                Some(p.to_string())
            })
        };
        let freed = |source: &str, p: &str| {
            log.lines().any(|l| {
                l.starts_with(&format!("MEM {source}")) && l.ends_with(&format!(" free({p})"))
            })
        };
        let own =
            allocated("lib558.c:", "558").unwrap_or_else(|| panic!("no block of 558:\n{log}"));
        assert!(
            freed("lib558.c:", &own),
            "the block of 558 not freed:\n{log}"
        );
        // The escape of fourteen bytes, each `%XX`, and its end.
        let escaped = allocated(&source("crates/curl-sys-abi/src/strings.rs:"), "43")
            .unwrap_or_else(|| panic!("no escape:\n{log}"));
        assert!(
            freed(&source("crates/curl-sys-abi/src/root.rs:"), &escaped),
            "the escape not freed by curl_free:\n{log}"
        );

        let analysis = std::process::Command::new("perl")
            .arg("-I")
            .arg(root.join("tests"))
            .arg(root.join("tests/memanalyze.pl"))
            .arg(&memdump)
            .output()
            .unwrap();
        std::fs::remove_file(&memdump).ok();
        assert!(analysis.status.success(), "{analysis:?}");
        let report = String::from_utf8_lossy(&analysis.stdout);
        assert!(
            report.is_empty(),
            "memanalyze.pl found problems:\n{report}\n{log}"
        );
    }

    /// lib558, as the C suite's test program runs it: the memdump started
    /// as libtest's harness starts it, from `CURL_MEMDEBUG`, then the
    /// library started, a block of the program's own and the escape of
    /// fourteen bytes allocated and freed, and the library ended.
    #[test]
    #[ignore = "run by test558_libtest_memory_tracking_operational, CURL_MEMDEBUG set"]
    #[allow(
        clippy::multiple_unsafe_ops_per_block,
        reason = "one contract covers the whole sequence"
    )]
    fn lib558() {
        let name = std::env::var_os("CURL_MEMDEBUG").expect("CURL_MEMDEBUG set");
        let name = std::ffi::CString::new(name.as_encoded_bytes()).unwrap();
        let a: [u8; 14] = [
            0x2f, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7,
        ];
        // SAFETY: C strings, a buffer of the length given, and blocks
        // from this pool freed once.
        unsafe {
            curl_dbg_memdebug(name.as_ptr());
            let init = root::curl_global_init(c_long::from(crate::ffi::CURL_GLOBAL_ALL));
            assert_eq!(init, crate::ffi::CURLE_OK);
            let own = curl_dbg_malloc(558, 30, c"lib558.c".as_ptr());
            curl_dbg_free(own, 31, c"lib558.c".as_ptr());
            let escaped = crate::strings::curl_easy_escape(
                ptr::null_mut(),
                a.as_ptr().cast(),
                c_int::try_from(a.len()).unwrap(),
            );
            assert!(!escaped.is_null());
            root::curl_free(escaped.cast());
            root::curl_global_cleanup();
        }
        track::flush_log();
    }

    /// The memdump lines are the ones tests/memanalyzer.pm parses, and the
    /// application's pool and the shim's are one.
    #[test]
    #[allow(
        clippy::multiple_unsafe_ops_per_block,
        reason = "one contract covers the whole sequence"
    )]
    fn logs_what_memanalyze_reads() {
        let path = std::env::temp_dir().join(format!("curl-memdump-{}", std::process::id()));
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: C strings, and blocks from this pool freed once.
        let (app, ours) = unsafe {
            curl_dbg_memdebug(cpath.as_ptr());
            // Both live at once, so their addresses differ.
            let app = curl_dbg_malloc(16, 11, c"t.c".as_ptr());
            let ours = root::allocator().c_string(b"abc");
            crate::root::curl_free(app);
            curl_dbg_free(ours.cast(), 12, c"t.c".as_ptr());
            (app, ours)
        };
        // Held until the buffer fills or the process exits, as C's are.
        track::flush_log();
        let log = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let lines = [
            format!("MEM t.c:11 malloc(16) = {app:p}"),
            format!("free({app:p})"),
            format!("malloc(4) = {ours:p}"),
            format!("MEM t.c:12 free({ours:p})"),
        ];
        for want in &lines {
            assert!(
                log.lines().any(|l| l.contains(want.as_str())),
                "{want:?} not in\n{log}"
            );
        }
        assert_ne!(app, ours.cast());
        let ours_line = log.lines().find(|l| l.contains(&lines[2])).unwrap();
        assert!(
            ours_line.starts_with(&format!(
                "MEM {}",
                source("crates/curl-sys-abi/src/debug.rs:")
            )),
            "{ours_line}"
        );
    }

    /// On Windows `curl_dbg_fopen` and `curl_dbg_freopen` read a name as
    /// the build reads one, as C's `curlx_win32_fopen` does: UTF-8 in the
    /// Unicode build, a name that is not refused with `EINVAL`, and the
    /// ANSI code page otherwise; a name past `MAX_PATH` opens too.
    #[cfg(windows)]
    #[test]
    #[allow(
        clippy::multiple_unsafe_ops_per_block,
        reason = "one contract covers the whole sequence"
    )]
    fn opens_files_by_the_names_the_build_reads() {
        let dir = std::env::temp_dir().join(format!("curl-dbg-fopen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let at = dir.as_os_str().to_str().unwrap();
        // "café" as the build reads it: Windows-1252's é, which the
        // guest's ANSI code page is, or UTF-8's.
        let e: &[u8] = if cfg!(feature = "unicode") {
            b"\xc3\xa9"
        } else {
            b"\xe9"
        };
        let named = |tail: &[u8]| {
            std::ffi::CString::new([at.as_bytes(), b"\\caf", e, tail].concat()).unwrap()
        };
        let long = format!("\\{}", "d".repeat(250));
        std::fs::create_dir_all(format!("{at}\\caf\u{e9}3{long}")).unwrap();
        let source = c"t.c".as_ptr();
        // SAFETY: C strings, and streams opened here closed once.
        unsafe {
            let f = curl_dbg_fopen(named(b"").as_ptr(), c"wb".as_ptr(), 1, source);
            assert!(!f.is_null());
            let g = curl_dbg_freopen(named(b"2").as_ptr(), c"wb".as_ptr(), f, 2, source);
            assert!(!g.is_null());
            assert_eq!(curl_dbg_fclose(g, 3, source), 0);
            let name = named(format!("3{long}\\f").as_bytes());
            let f = curl_dbg_fopen(name.as_ptr(), c"wb".as_ptr(), 4, source);
            assert!(!f.is_null());
            assert_eq!(curl_dbg_fclose(f, 5, source), 0);
        }
        assert!(dir.join("caf\u{e9}").exists());
        assert!(dir.join("caf\u{e9}2").exists());
        assert!(
            std::path::PathBuf::from(format!("\\\\?\\{at}\\caf\u{e9}3{long}\\f")).exists(),
            "the long name"
        );
        if cfg!(feature = "unicode") {
            let bad = named(b"\xff");
            // SAFETY: C strings.
            let f = unsafe { curl_dbg_fopen(bad.as_ptr(), c"wb".as_ptr(), 6, source) };
            assert!(f.is_null());
            // SAFETY: the UCRT's `errno`, this thread's.
            let errno = unsafe { *libc_errno() };
            assert_eq!(errno, libc::EINVAL);
        }
        std::fs::remove_dir_all(format!(r"\\?\{at}")).unwrap();
    }

    #[cfg(windows)]
    unsafe extern "C" {
        /// The UCRT's: where this thread's `errno` is.
        #[link_name = "_errno"]
        fn libc_errno() -> *mut c_int;
    }

    /// The Unicode build's `curl_dbg_wcsdup` copies a wide string into a
    /// tracked block, which `curl_dbg_free` frees.
    #[cfg(all(windows, feature = "unicode"))]
    #[test]
    #[allow(
        clippy::multiple_unsafe_ops_per_block,
        reason = "one contract covers the whole sequence"
    )]
    fn copies_a_wide_string() {
        let s: Vec<u16> = "caf\u{e9}\0".encode_utf16().collect();
        // SAFETY: a zero-ended wide string, and the copy freed once.
        unsafe {
            let copy = curl_dbg_wcsdup(s.as_ptr(), 1, c"t.c".as_ptr());
            assert!(!copy.is_null());
            assert_eq!(core::slice::from_raw_parts(copy, s.len()), &s[..]);
            curl_dbg_free(copy.cast(), 2, c"t.c".as_ptr());
        }
    }

    /// A source file's name as the compiler gives it (`file!()`): with
    /// the platform's separator, a backslash on Windows, as C's
    /// `__FILE__` there.
    fn source(path: &str) -> String {
        path.replace('/', std::path::MAIN_SEPARATOR_STR)
    }
}
