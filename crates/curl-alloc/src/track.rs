//! The debug build's memory tracker (`DESIGN.md`, "Debug hooks").
//!
//! [`Tracker`] is a global allocator over the system one. Once
//! [`start_log`] or [`set_limit`] turns tracking on, every allocation not
//! made inside [`untracked`] is tracked: written to the memdump in the
//! lines tests/memanalyzer.pm reads, and counted against the limit, past
//! which it fails. Each block carries a tag saying whether it was tracked,
//! so freeing a block made before tracking started, or inside an
//! exclusion, logs nothing. The tag follows the caller's bytes: a block
//! starts where the system's does, so a block the runtime never frees,
//! such as standard output's buffer, is held by a pointer to its start,
//! which a leak checker such as valgrind sees as reachable. A tag before it
//! would leave such a block held only by a pointer into it, which valgrind
//! reports as possibly lost.
//!
//! The C side of the shim logs to the same memdump and counts against the
//! same limit through [`log`] and [`limit_reached`], so there is one of
//! each per process. Nothing here allocates while logging: lines are built
//! on the stack and gathered in a buffer of C's size, written out when it
//! fills and as the process exits, as C's `membuf` is: a file size limit
//! the program sets for a while (test 2380) then cuts no line short.
//!
//! Allocations are also counted per thread, tracked or not, for the
//! allocation budget tests: see [`count_allocations`].

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The source logged for allocations made by Rust code: a global allocator
/// is not told its caller.
const RUST_SOURCE: &str = "rust:0";

const TRACKED: u64 = 0x5452_4143_4b45_4421;
const PLAIN: u64 = 0x504c_4149_4e21_2121;

struct State {
    log: Option<File>,
    /// The lines not written to the memdump yet, `buf[..held]`.
    buf: [u8; LOG_BUFFER],
    held: usize,
    /// Tracked allocations left before they fail, once a limit is set.
    limit: Option<u64>,
    /// Tracked allocations refused so far.
    refused: u64,
    /// Refusals are not reported on standard error: a torture run makes
    /// one on purpose for every allocation it tries.
    quiet: bool,
    /// Only one allocation is refused: the limit is lifted after it.
    once: bool,
    /// Only the allocations of the thread that set the limit count
    /// against it (`fail_once_after_here`).
    here: bool,
}

/// The lines kept before they are written (C's `membuf`).
const LOG_BUFFER: usize = 10000;

static STATE: crate::Lock<State> = crate::Lock::new(State {
    log: None,
    buf: [0; LOG_BUFFER],
    held: 0,
    limit: None,
    refused: 0,
    quiet: false,
    once: false,
    here: false,
});

/// Tracked blocks not yet freed.
static LIVE: AtomicU64 = AtomicU64::new(0);

/// Whether tracking is on: set once, never cleared.
static ACTIVE: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// Depth of [`untracked`] calls on this thread.
    static EXCLUDED: Cell<u32> = const { Cell::new(0) };
    /// Allocations this thread made outside [`untracked`].
    static COUNT: Cell<u64> = const { Cell::new(0) };
    /// Bytes this thread allocated outside [`untracked`], less those it
    /// freed: what it holds, as far as it made what it frees.
    static HELD: Cell<i64> = const { Cell::new(0) };
    /// This thread set a limit that only its allocations count against.
    static LIMITED: Cell<bool> = const { Cell::new(false) };
    /// The largest block this thread allocated outside [`untracked`]
    /// without the allocator zeroing it, or grew.
    static UNZEROED: Cell<usize> = const { Cell::new(0) };
    /// The size [`count_sized`] counts the blocks of on this thread, and
    /// how many it made or grew to it.
    static SIZED: Cell<(usize, u64)> = const { Cell::new((0, 0)) };
}

fn state() -> crate::LockGuard<'static, State> {
    // Panics abort, so the lock is never poisoned.
    STATE.lock().expect("the tracker lock is never poisoned")
}

fn excluded() -> bool {
    EXCLUDED.with(|d| d.get() > 0)
}

/// Write the memdump to `path`, from now on. Only the first call that
/// opens a file has any effect, as in C.
pub fn start_log(path: &Path) -> io::Result<()> {
    if state().log.is_some() {
        return Ok(());
    }
    make_runtime_globals();
    // Opening allocates; the lock is not held, so that allocation can be
    // tracked or not without waiting on it. It is not tracked, so it is
    // never refused: std's open is the one this crate, below `curl-os`,
    // can reach.
    #[allow(clippy::disallowed_methods)]
    let file = untracked(|| File::create(path))?;
    let mut state = state();
    if state.log.is_none() {
        state.log = Some(file);
        // SAFETY: `flush_at_exit` is a function that lives as long as the
        // process, which takes the tracker's lock and nothing else.
        let registered = unsafe { atexit(flush_at_exit) };
        // A memdump not written at exit is short of its last lines, which
        // the test reading it then fails on, as it would in C.
        assert_eq!(registered, 0, "atexit has room for a handler");
    }
    ACTIVE.store(true, Ordering::Release);
    Ok(())
}

unsafe extern "C" {
    fn atexit(f: extern "C" fn()) -> std::ffi::c_int;
}

/// The lines held written out as the process exits (`curl_dbg_cleanup`).
extern "C" fn flush_at_exit() {
    flush_log();
}

/// Write the lines held to the memdump now, as a test reading it while the
/// process runs needs.
pub fn flush_log() {
    flush(&mut state());
}

fn flush(state: &mut State) {
    if let Some(mut file) = state.log.as_ref() {
        // A memdump that cannot be written has nowhere to report it; the
        // test then fails on the memdump it reads.
        let _unwritten = file.write_all(&state.buf[..state.held]);
    }
    state.held = 0;
}

/// Let `limit` more tracked allocations succeed and fail the rest. Only
/// the first call has any effect, as in C.
pub fn set_limit(limit: u64) {
    make_runtime_globals();
    let mut state = state();
    if state.limit.is_none() {
        state.limit = Some(limit);
    }
    ACTIVE.store(true, Ordering::Release);
}

/// Make, untracked, what the standard library makes on first use and never
/// frees, before tracking starts: the standard streams' buffers and, where
/// std's mutexes are boxed pthread mutexes (macOS), each stream's mutex on
/// its first lock. They are the runtime's, as C's stdio buffers are libc's and
/// unseen by its memory debugging; made later, they would read as leaks in
/// every memdump and could be refused under a limit, which std aborts on.
fn make_runtime_globals() {
    untracked(|| {
        drop(io::stdout().lock());
        drop(io::stderr().lock());
    });
}

/// Run `f` with its allocations untracked: for the standard library's
/// lazily created globals, which are made once and never freed.
pub fn untracked<R>(f: impl FnOnce() -> R) -> R {
    struct Leave;
    impl Drop for Leave {
        fn drop(&mut self) {
            EXCLUDED.with(|d| d.set(d.get() - 1));
        }
    }
    EXCLUDED.with(|d| d.set(d.get() + 1));
    let _leave = Leave;
    f()
}

/// Run `f` tracked again, inside [`untracked`]: for the calls a library
/// whose own allocations go untracked makes back into ours, which C's
/// tracker counts.
pub fn tracked<R>(f: impl FnOnce() -> R) -> R {
    struct Back(u32);
    impl Drop for Back {
        fn drop(&mut self) {
            EXCLUDED.with(|d| d.set(self.0));
        }
    }
    let _back = Back(EXCLUDED.with(|d| d.replace(0)));
    f()
}

/// Run `f` with `limit` more tracked allocations allowed and the rest
/// refused, then lift the limit; whether any was refused. For the Rust
/// torture tests, which run a scenario once for every allocation it makes;
/// unlike [`set_limit`], it can be called again. Refusals are not reported
/// on standard error meanwhile.
pub fn fail_after<R>(limit: u64, f: impl FnOnce() -> R) -> (R, bool) {
    refusing(limit, false, f)
}

/// Run `f` with `limit` more tracked allocations allowed, the next one
/// refused and the rest allowed again; whether one was refused. For the
/// torture tests that check a refusal is never taken for success.
pub fn fail_once_after<R>(limit: u64, f: impl FnOnce() -> R) -> (R, bool) {
    refusing(limit, true, f)
}

/// As [`fail_once_after`], counting only this thread's allocations, so
/// that tests running beside it on other threads are not refused: for a
/// test among others in a harness's threads.
pub fn fail_once_after_here<R>(limit: u64, f: impl FnOnce() -> R) -> (R, bool) {
    LIMITED.with(|l| l.set(true));
    let r = refusing_in(limit, true, true, f);
    LIMITED.with(|l| l.set(false));
    r
}

fn refusing<R>(limit: u64, once: bool, f: impl FnOnce() -> R) -> (R, bool) {
    refusing_in(limit, once, false, f)
}

fn refusing_in<R>(limit: u64, once: bool, here: bool, f: impl FnOnce() -> R) -> (R, bool) {
    let (previous, refused) = {
        let mut state = state();
        let previous = (state.limit.replace(limit), state.once, state.here);
        state.quiet = true;
        state.once = once;
        state.here = here;
        (previous, state.refused)
    };
    ACTIVE.store(true, Ordering::Release);
    let r = f();
    let mut state = state();
    (state.limit, state.once, state.here) = previous;
    state.quiet = false;
    let reached = state.refused > refused;
    (r, reached)
}

/// Tracked blocks not yet freed, for leak checks around a scenario.
pub fn live_tracked() -> u64 {
    LIVE.load(Ordering::Relaxed)
}

/// Run `f` and return how many allocations this thread made in it, for
/// the allocation budget tests.
pub fn count_allocations<R>(f: impl FnOnce() -> R) -> (R, u64) {
    let before = COUNT.with(Cell::get);
    let r = f();
    (r, COUNT.with(Cell::get) - before)
}

/// Run `f` and return how many bytes this thread holds after it beyond
/// those it held before, and how many allocations it made: for the
/// memory budget tests.
pub fn measure<R>(f: impl FnOnce() -> R) -> (R, Measured) {
    let (held, count) = (HELD.with(Cell::get), COUNT.with(Cell::get));
    let r = f();
    let measured = Measured {
        bytes: HELD.with(Cell::get) - held,
        allocations: COUNT.with(Cell::get) - count,
    };
    (r, measured)
}

/// Run `f` and return the largest block this thread allocated in it
/// without the allocator zeroing it, or grew: a large buffer that must
/// start zeroed is asked of it zeroed, not filled byte by byte.
pub fn largest_unzeroed<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let before = UNZEROED.with(|u| u.replace(0));
    let r = f();
    let largest = UNZEROED.with(|u| u.replace(before.max(u.get())));
    (r, largest)
}

/// Run `f` and return how many blocks of exactly `size` bytes, not zero,
/// this thread allocated or grew to in it: for the tests that a buffer
/// of a size of its own is made as often as C makes it.
pub fn count_sized<R>(size: usize, f: impl FnOnce() -> R) -> (R, u64) {
    assert_ne!(size, 0, "a zero-sized block is not allocated");
    let before = SIZED.with(|s| s.replace((size, 0)));
    let r = f();
    let (_, n) = SIZED.with(|s| s.replace(before));
    (r, n)
}

/// What [`measure`] saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measured {
    /// Allocated less freed, in bytes, without the tracker's tags.
    pub bytes: i64,
    pub allocations: u64,
}

/// One memdump line, built on the stack. Longer lines are cut at 1023
/// bytes, as C cuts them.
pub struct Line {
    buf: [u8; 1024],
    len: usize,
}

impl Line {
    pub fn new() -> Self {
        Line {
            buf: [0; 1024],
            len: 0,
        }
    }

    /// Append bytes, cutting what does not fit.
    pub fn push(&mut self, bytes: &[u8]) {
        let room = self.buf.len() - 1 - self.len;
        let n = bytes.len().min(room);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// The whole buffer, for a C formatter to write into; then
    /// [`Line::set_len`].
    pub fn buffer(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Keep the first `len` bytes of [`Line::buffer`], at most 1023.
    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(self.buf.len() - 1);
    }
}

impl Default for Line {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Write for Line {
    /// Never fails: a full line is cut instead.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push(s.as_bytes());
        Ok(())
    }
}

/// A pointer as C's `%p` prints it.
pub struct Ptr<T>(pub *const T);

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
pub fn log(line: &Line) {
    write_log(&mut state(), line);
}

/// Keep `line` for the memdump, writing out what is held first when it
/// does not fit (`curl_dbg_vlog`).
fn write_log(state: &mut State, line: &Line) {
    if state.log.is_none() {
        return;
    }
    let bytes = line.bytes();
    if LOG_BUFFER - state.held < bytes.len() {
        flush(state);
    }
    let held = state.held;
    state.buf[held..held + bytes.len()].copy_from_slice(bytes);
    state.held += bytes.len();
}

/// Count a tracked call against the limit. When the limit is spent, log
/// `LIMIT <source> <func> reached memlimit` to the memdump and to standard
/// error, and return true: the call must fail. `source` writes where the
/// call was made. A thread that is panicking is never refused, nor
/// counted: what it allocates is its message and its unwinding, and
/// refused, its panic would end as "memory allocation failed" instead.
pub fn limit_reached(func: &str, source: impl FnOnce(&mut Line)) -> bool {
    if std::thread::panicking() {
        return false;
    }
    let mut state = state();
    if state.here && !LIMITED.with(Cell::get) {
        return false;
    }
    match &mut state.limit {
        Some(0) => {}
        Some(left) => {
            *left -= 1;
            return false;
        }
        None => return false,
    }
    state.refused += 1;
    if state.once {
        state.limit = None;
    }
    let mut line = Line::new();
    line.push(b"LIMIT ");
    source(&mut line);
    let _ = writeln!(line, " {func} reached memlimit");
    write_log(&mut state, &line);
    if !state.quiet {
        // Standard error is unbuffered and does not allocate. A failed
        // write there has nowhere to be reported.
        let _ = io::stderr().write_all(line.bytes());
    }
    true
}

/// Log a Rust allocation event, built by `build` after the source.
fn log_rust(build: impl FnOnce(&mut Line) -> fmt::Result) {
    let mut line = Line::new();
    line.push(b"MEM ");
    line.push(RUST_SOURCE.as_bytes());
    line.push(b" ");
    let _ = build(&mut line);
    line.push(b"\n");
    log(&line);
}

/// Whether an allocation made now is tracked.
fn tracking() -> bool {
    ACTIVE.load(Ordering::Acquire) && !excluded()
}

fn count() {
    if !excluded() {
        COUNT.with(|c| c.set(c.get() + 1));
    }
}

/// A block of `size` bytes made or grown.
fn sized(size: usize) {
    if !excluded() {
        SIZED.with(|s| {
            let (wanted, n) = s.get();
            if wanted == size {
                s.set((wanted, n + 1));
            }
        });
    }
}

/// A block of `size` bytes made or grown without zeroing.
fn unzeroed(size: usize) {
    if !excluded() {
        UNZEROED.with(|u| u.set(u.get().max(size)));
    }
}

/// `bytes` more held by this thread, or fewer.
fn hold(bytes: i64) {
    if !excluded() {
        HELD.with(|h| h.set(h.get() + bytes));
    }
}

fn signed(size: usize) -> i64 {
    i64::try_from(size).expect("a block smaller than i64::MAX")
}

/// The room after each block's bytes, holding its tag.
const TAG: usize = size_of::<u64>();

/// The layout of a block of `size` bytes aligned as `layout` is, with its
/// tag after them.
fn outer(layout: Layout, size: usize) -> Option<Layout> {
    let size = size.checked_add(TAG)?;
    Layout::from_size_align(size, layout.align()).ok()
}

/// The global allocator of the debug test build.
pub struct Tracker;

impl Tracker {
    /// # Safety
    ///
    /// As `GlobalAlloc::alloc`.
    unsafe fn make(&self, layout: Layout, zeroed: bool) -> *mut u8 {
        let tracked = tracking();
        let func = if zeroed { "calloc" } else { "malloc" };
        if tracked && limit_reached(func, |l| l.push(RUST_SOURCE.as_bytes())) {
            return std::ptr::null_mut();
        }
        let Some(outer) = outer(layout, layout.size()) else {
            return std::ptr::null_mut();
        };
        let block = if zeroed {
            // SAFETY: `outer` is at least the tag in size, so not zero.
            unsafe { System.alloc_zeroed(outer) }
        } else {
            // SAFETY: as above.
            unsafe { System.alloc(outer) }
        };
        if block.is_null() {
            return block;
        }
        // SAFETY: `block` is a live system block of `outer`, made for
        // `layout.size()` bytes.
        unsafe { set_tag(block, layout.size(), if tracked { TRACKED } else { PLAIN }) };
        count();
        hold(signed(layout.size()));
        sized(layout.size());
        if !zeroed {
            unzeroed(layout.size());
        }
        if tracked {
            LIVE.fetch_add(1, Ordering::Relaxed);
            let size = layout.size();
            if zeroed {
                log_rust(|l| write!(l, "calloc(1,{size}) = {}", Ptr(block)));
            } else {
                log_rust(|l| write!(l, "malloc({size}) = {}", Ptr(block)));
            }
        }
        block
    }
}

/// The tag of a block of `size` bytes from [`Tracker`].
///
/// # Safety
///
/// `block` came from [`Tracker`], is live and is `size` bytes long.
unsafe fn tag(block: *mut u8, size: usize) -> u64 {
    // SAFETY: every block from `Tracker` was tagged just after its bytes,
    // at the size the caller gives; the slot may be unaligned.
    unsafe { tag_slot(block, size).read_unaligned() }
}

/// Tag a block of `size` bytes.
///
/// # Safety
///
/// `block` is a live system block of `outer(_, size)`.
unsafe fn set_tag(block: *mut u8, size: usize, tag: u64) {
    // SAFETY: the slot is the last `TAG` bytes of the system block, as the
    // caller says; it may be unaligned.
    unsafe { tag_slot(block, size).write_unaligned(tag) };
}

/// Where the tag of a block of `size` bytes is: just after them, aligned
/// as the size happens to leave it.
fn tag_slot(block: *mut u8, size: usize) -> *mut u64 {
    block.wrapping_add(size).cast::<u64>()
}

// SAFETY: every block is a system block of the requested alignment that
// starts at the caller's bytes, with its tag after them; `outer`
// reproduces the system layout from the caller's for dealloc and realloc.
unsafe impl GlobalAlloc for Tracker {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as the caller guarantees.
        unsafe { self.make(layout, false) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as the caller guarantees.
        unsafe { self.make(layout, true) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        hold(-signed(layout.size()));
        // SAFETY: the caller passes a live block of `layout` from this
        // allocator.
        if unsafe { tag(block, layout.size()) } == TRACKED {
            LIVE.fetch_sub(1, Ordering::Relaxed);
            log_rust(|l| write!(l, "free({})", Ptr(block)));
        }
        let outer = outer(layout, layout.size()).expect("a live block's layout fits");
        // SAFETY: `block` and `outer` are the system block and its layout.
        unsafe { System.dealloc(block, outer) };
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller passes a live block of `layout` from this
        // allocator.
        let was_tracked = unsafe { tag(block, layout.size()) } == TRACKED;
        let now = tracking();
        if now && limit_reached("realloc", |l| l.push(RUST_SOURCE.as_bytes())) {
            return std::ptr::null_mut();
        }
        let old = outer(layout, layout.size()).expect("a live block's layout fits");
        let Some(new) = outer(layout, new_size) else {
            return std::ptr::null_mut();
        };
        // SAFETY: `block` and `old` are the system block and its layout;
        // `new` is a valid layout of the same alignment, not zero in size.
        let moved = unsafe { System.realloc(block, old, new.size()) };
        if moved.is_null() {
            return moved;
        }
        // The copy leaves the old tag at the old size, or cuts it off: the
        // block is tagged again at its new one.
        let tag = if was_tracked || now { TRACKED } else { PLAIN };
        // SAFETY: `moved` is a live system block of `new`.
        unsafe { set_tag(moved, new_size, tag) };
        count();
        hold(signed(new_size) - signed(layout.size()));
        sized(new_size);
        unzeroed(new_size);
        if was_tracked {
            log_rust(|l| write!(l, "realloc({}, {new_size}) = {}", Ptr(block), Ptr(moved)));
        } else if now {
            LIVE.fetch_add(1, Ordering::Relaxed);
            log_rust(|l| write!(l, "malloc({new_size}) = {}", Ptr(moved)));
        }
        moved
    }
}

#[cfg(test)]
#[global_allocator]
static ALLOCATOR: Tracker = Tracker;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_this_threads_allocations() {
        let (v, n) = count_allocations(|| {
            let mut v: Vec<u64> = Vec::with_capacity(4);
            v.extend_from_slice(&[1, 2, 3, 4, 5]);
            v
        });
        assert_eq!(v.len(), 5);
        assert_eq!(n, 2, "one allocation and one growth");
        let ((), n) = count_allocations(|| drop(untracked(|| Vec::<u8>::with_capacity(8))));
        assert_eq!(n, 0, "exclusions are not counted");
    }

    #[test]
    fn measures_the_bytes_this_thread_holds() {
        let (v, m) = measure(|| {
            let mut v: Vec<u64> = Vec::with_capacity(4);
            v.extend_from_slice(&[1, 2, 3, 4, 5]);
            drop(Box::new([0u8; 100]));
            v
        });
        assert_eq!(v.capacity(), 8, "doubled");
        assert_eq!(
            m,
            Measured {
                bytes: 64,
                allocations: 3
            }
        );
        let ((), m) = measure(|| drop(v));
        assert_eq!(
            m,
            Measured {
                bytes: -64,
                allocations: 0
            }
        );
        let ((), m) = measure(|| untracked(|| drop(Vec::<u8>::with_capacity(8))));
        assert_eq!(
            m,
            Measured {
                bytes: 0,
                allocations: 0
            },
            "exclusions are not counted"
        );
    }

    #[test]
    fn keeps_alignment_and_contents() {
        #[repr(align(64))]
        struct Wide([u8; 64]);
        let b = Box::new(Wide([7; 64]));
        assert_eq!((&raw const *b).addr() % 64, 0);
        let mut v: Vec<Wide> = Vec::with_capacity(1);
        v.extend([Wide([1; 64]), Wide([2; 64])]);
        assert_eq!((v.as_ptr()).addr() % 64, 0);
        assert_eq!((b.0[63], v[0].0[0], v[1].0[63]), (7, 1, 2));
    }

    /// Each block's tag follows its bytes, wherever its size leaves it:
    /// grown and shrunk, a block is tagged at its new size, where freeing
    /// it reads (under Miri, a block not tagged again reads bytes never
    /// written).
    #[test]
    fn tags_follow_a_block_grown_and_shrunk() {
        let mut v: Vec<u8> = Vec::with_capacity(3);
        v.extend_from_slice(b"abcde");
        v.shrink_to_fit();
        assert_eq!((v.capacity(), &v[..]), (5, &b"abcde"[..]));
        v.truncate(1);
        v.shrink_to_fit();
        assert_eq!(&v[..], b"a");
        let zeroed: Vec<u64> = vec![0; 3];
        assert_eq!(zeroed.iter().sum::<u64>(), 0);
    }

    /// A panic under a limit makes its message: refused, it would abort
    /// as "memory allocation failed", and the panic would never read.
    #[test]
    fn a_panic_under_a_limit_reads_as_the_panic() {
        let n = 42;
        let (message, refused) = fail_once_after_here(0, || {
            std::panic::catch_unwind(|| panic!("the panic, {n}"))
                .unwrap_err()
                .downcast::<String>()
                .map(|s| *s)
                .map_err(drop)
        });
        assert_eq!(message.as_deref(), Ok("the panic, 42"));
        assert!(!refused, "nothing refused while panicking");
    }
}
