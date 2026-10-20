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
//! The prototypes are those of lib/curl_setup.h, which `ffi` does not
//! cover; each is transcribed by hand beside its definition.

#![allow(unsafe_code)]

use core::ffi::{CStr, VaList, c_char, c_int, c_long, c_void};
use core::fmt::{self, Write};
use core::panic::Location;
use core::ptr;

use crate::root::{self, Allocator};

/// `curl_socket_t` on the platforms in scope.
type Socket = c_int;
const SOCKET_BAD: Socket = -1;

/// The tracker's state, held in the shim's root.
pub(crate) struct Tracker {
    log: Option<LogFile>,
    /// Tracked calls left before they fail, once a limit is set.
    limit: Option<c_long>,
}

impl Tracker {
    pub(crate) const fn new() -> Self {
        Tracker {
            log: None,
            limit: None,
        }
    }
}

/// The memdump stream, opened once and never closed: it is written
/// unbuffered, line by line, so nothing is lost when the process ends.
struct LogFile(*mut libc::FILE);

// SAFETY: a `FILE` may be used from any thread; the root's lock keeps the
// writes from interleaving.
unsafe impl Send for LogFile {}

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
}

/// One log line, built on the stack: logging must not allocate through
/// the tracker it logs. Longer lines are cut, as C cuts them at 1023
/// bytes.
struct Line {
    buf: [u8; 1024],
    len: usize,
}

impl Line {
    fn new() -> Self {
        Line {
            buf: [0; 1024],
            len: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        let room = self.buf.len() - 1 - self.len;
        let n = bytes.len().min(room);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Start a line with `kind` and where the call was made.
    fn start(kind: &str, source: Source) -> Self {
        let mut line = Line::new();
        line.push(kind.as_bytes());
        line.push(b" ");
        match source {
            Source::C(file, n) => {
                // SAFETY: a `Source::C` holds a C string, by its
                // constructor's contract.
                line.push(unsafe { CStr::from_ptr(file) }.to_bytes());
                let _ = write!(line, ":{n} ");
            }
            Source::Rust(at) => {
                let _ = write!(line, "{}:{} ", at.file(), at.line());
            }
            Source::Internal => {}
        }
        line
    }
}

impl Write for Line {
    /// Never fails: a full line is cut instead.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push(s.as_bytes());
        Ok(())
    }
}

/// A pointer as `%p` prints it.
struct Ptr<T>(*const T);

impl<T> fmt::Display for Ptr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_null() {
            f.write_str("(nil)")
        } else {
            write!(f, "{:#x}", self.0.addr())
        }
    }
}

/// Append `line` to the memdump, if there is one.
fn log(tracker: &Tracker, line: &Line) {
    let Some(LogFile(file)) = tracker.log else {
        return;
    };
    let bytes = line.bytes();
    // SAFETY: `file` is the stream `curl_dbg_memdebug` opened, which stays
    // open; `bytes` is readable for its length.
    unsafe { libc::fwrite(bytes.as_ptr().cast(), 1, bytes.len(), file) };
    // SAFETY: as above.
    unsafe { libc::fflush(file) };
}

/// Log a line built by `build`, unless the call is internal.
fn log_call(source: Source, kind: &str, build: impl FnOnce(&mut Line) -> fmt::Result) {
    if source.is_internal() {
        return;
    }
    let mut line = Line::start(kind, source);
    let _ = build(&mut line);
    line.push(b"\n");
    log(&root::root().tracker, &line);
}

/// Count a tracked call against the limit; true when it must fail.
fn limit_reached(func: &str, source: Source) -> bool {
    if source.is_internal() {
        return false;
    }
    let mut root = root::root();
    match &mut root.tracker.limit {
        Some(0) => {}
        Some(left) => {
            *left -= 1;
            return false;
        }
        None => return false,
    }
    let mut line = Line::start("LIMIT", source);
    let _ = writeln!(line, "{func} reached memlimit");
    log(&root.tracker, &line);
    let bytes = line.bytes();
    // SAFETY: standard error is open for the life of the process, as C
    // assumes; `bytes` is readable for its length. A failed write to it
    // has nowhere to be reported.
    unsafe { libc::write(2, bytes.as_ptr().cast(), bytes.len()) };
    set_errno(libc::ENOMEM);
    true
}

fn set_errno(value: c_int) {
    // SAFETY: `__errno_location` takes nothing and cannot fail.
    let errno = unsafe { libc::__errno_location() };
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
    let mut root = root::root();
    // SAFETY: `logname` is NULL or a C string, as the caller guarantees.
    if root.tracker.log.is_some() || logname.is_null() || unsafe { logname.read() } == 0 {
        return;
    }
    // SAFETY: both are C strings.
    let file = unsafe { libc::fopen(logname, c"w".as_ptr()) };
    if !file.is_null() {
        root.tracker.log = Some(LogFile(file));
    }
}
const _: unsafe extern "C" fn(*const c_char) = curl_dbg_memdebug;

/// Let `limit` tracked calls succeed and fail the rest; later calls change
/// nothing.
#[unsafe(no_mangle)]
pub extern "C" fn curl_dbg_memlimit(limit: c_long) {
    let mut root = root::root();
    if root.tracker.limit.is_none() {
        root.tracker.limit = Some(limit);
    }
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
    let fd = unsafe { libc::socket(domain, kind, protocol) };
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
    let fd = unsafe { libc::accept(s, addr.cast(), addrlen.cast()) };
    if fd != SOCKET_BAD {
        log_call(source, "FD", |l| write!(l, "accept() = {fd}"));
    }
    fd
}
const _: unsafe extern "C" fn(Socket, *mut c_void, *mut c_void, c_int, *const c_char) -> Socket =
    curl_dbg_accept;

/// # Safety
///
/// As `accept4(2)`; `source` is NULL or a C string.
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
    unsafe { libc::close(fd) }
}
const _: unsafe extern "C" fn(Socket, c_int, *const c_char) -> c_int = curl_dbg_sclose;

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
    let f = unsafe { libc::fopen(file, mode) };
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
    let f = unsafe { libc::freopen(file, mode, fh) };
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
    if root::root().tracker.log.is_none() {
        return;
    }
    let mut line = Line::new();
    // SAFETY: the buffer has room for its length; the format and
    // arguments are the caller's.
    let n = unsafe {
        crate::printf::curl_mvsnprintf(line.buf.as_mut_ptr().cast(), line.buf.len(), format, args)
    };
    line.len = usize::try_from(n).unwrap_or(0).min(line.buf.len() - 1);
    log(&root::root().tracker, &line);
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ours_line.starts_with("MEM crates/curl-sys-abi/src/debug.rs:"),
            "{ours_line}"
        );
    }
}
