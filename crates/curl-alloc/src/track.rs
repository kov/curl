//! The debug build's memory tracker (`DESIGN.md`, "Debug hooks").
//!
//! [`Tracker`] is a global allocator over the system one. Once
//! [`start_log`] or [`set_limit`] turns tracking on, every allocation not
//! made inside [`untracked`] is tracked: written to the memdump in the
//! lines tests/memanalyzer.pm reads, and counted against the limit, past
//! which it fails. Each block carries a tag saying whether it was tracked,
//! so freeing a block made before tracking started, or inside an
//! exclusion, logs nothing.
//!
//! The C side of the shim logs to the same memdump and counts against the
//! same limit through [`log`] and [`limit_reached`], so there is one of
//! each per process. Nothing here allocates while logging: lines are built
//! on the stack and written to the file directly.
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
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The source logged for allocations made by Rust code: a global allocator
/// is not told its caller.
const RUST_SOURCE: &str = "rust:0";

const TRACKED: u64 = 0x5452_4143_4b45_4421;
const PLAIN: u64 = 0x504c_4149_4e21_2121;

struct State {
    log: Option<File>,
    /// Tracked allocations left before they fail, once a limit is set.
    limit: Option<u64>,
    /// Tracked allocations refused so far.
    refused: u64,
    /// Refusals are not reported on standard error: a torture run makes
    /// one on purpose for every allocation it tries.
    quiet: bool,
}

static STATE: Mutex<State> = Mutex::new(State {
    log: None,
    limit: None,
    refused: 0,
    quiet: false,
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
}

fn state() -> std::sync::MutexGuard<'static, State> {
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
    // Opening allocates; the lock is not held, so that allocation can be
    // tracked or not without waiting on it.
    let file = untracked(|| File::create(path))?;
    let mut state = state();
    if state.log.is_none() {
        state.log = Some(file);
    }
    ACTIVE.store(true, Ordering::Release);
    Ok(())
}

/// Let `limit` more tracked allocations succeed and fail the rest. Only
/// the first call has any effect, as in C.
pub fn set_limit(limit: u64) {
    let mut state = state();
    if state.limit.is_none() {
        state.limit = Some(limit);
    }
    ACTIVE.store(true, Ordering::Release);
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

/// Run `f` with `limit` more tracked allocations allowed and the rest
/// refused, then lift the limit; whether any was refused. For the Rust
/// torture tests, which run a scenario once for every allocation it makes;
/// unlike [`set_limit`], it can be called again. Refusals are not reported
/// on standard error meanwhile.
pub fn fail_after<R>(limit: u64, f: impl FnOnce() -> R) -> (R, bool) {
    let (previous, refused) = {
        let mut state = state();
        let previous = state.limit.replace(limit);
        state.quiet = true;
        (previous, state.refused)
    };
    ACTIVE.store(true, Ordering::Release);
    let r = f();
    let mut state = state();
    state.limit = previous;
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
    write_log(&state(), line);
}

fn write_log(state: &State, line: &Line) {
    if let Some(mut file) = state.log.as_ref() {
        // A memdump that cannot be written has nowhere to report it; the
        // test then fails on the memdump it reads.
        let _ = file.write_all(line.bytes());
    }
}

/// Count a tracked call against the limit. When the limit is spent, log
/// `LIMIT <source> <func> reached memlimit` to the memdump and to standard
/// error, and return true: the call must fail. `source` writes where the
/// call was made.
pub fn limit_reached(func: &str, source: impl FnOnce(&mut Line)) -> bool {
    let mut state = state();
    match &mut state.limit {
        Some(0) => {}
        Some(left) => {
            *left -= 1;
            return false;
        }
        None => return false,
    }
    state.refused += 1;
    let mut line = Line::new();
    line.push(b"LIMIT ");
    source(&mut line);
    let _ = writeln!(line, " {func} reached memlimit");
    write_log(&state, &line);
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

/// The room before each block, holding its tag in the last 8 bytes; a
/// multiple of the block's alignment.
fn header(layout: Layout) -> usize {
    layout.align().max(16)
}

/// The layout of a block with its header.
fn outer(layout: Layout) -> Option<Layout> {
    let size = layout.size().checked_add(header(layout))?;
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
        let Some(outer) = outer(layout) else {
            return std::ptr::null_mut();
        };
        let p = if zeroed {
            // SAFETY: `outer` is at least the header in size, so not zero.
            unsafe { System.alloc_zeroed(outer) }
        } else {
            // SAFETY: as above.
            unsafe { System.alloc(outer) }
        };
        if p.is_null() {
            return p;
        }
        // SAFETY: the block holds the header before the caller's bytes.
        let block = unsafe { p.add(header(layout)) };
        // SAFETY: the tag slot is in the header just written room for.
        unsafe { tag_slot(block).write(if tracked { TRACKED } else { PLAIN }) };
        count();
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

/// The tag of a block from [`Tracker`].
///
/// # Safety
///
/// `block` came from [`Tracker`] and is live.
unsafe fn tag(block: *mut u8) -> u64 {
    // SAFETY: every block from `Tracker` has its tag just before it.
    unsafe { tag_slot(block).read() }
}

/// Where a block's tag is: the last 8 bytes of its header, aligned to 8
/// since the header's size is a multiple of 16.
fn tag_slot(block: *mut u8) -> *mut u64 {
    block.cast::<u64>().wrapping_sub(1)
}

// SAFETY: every block is a system block of the requested alignment with
// the header before it; `outer` reproduces the system layout from the
// caller's for dealloc and realloc.
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
        // SAFETY: the caller passes a live block from this allocator.
        if unsafe { tag(block) } == TRACKED {
            LIVE.fetch_sub(1, Ordering::Relaxed);
            log_rust(|l| write!(l, "free({})", Ptr(block)));
        }
        let outer = outer(layout).expect("a live block's layout fits");
        // SAFETY: the system block starts a header before the caller's.
        let p = unsafe { block.sub(header(layout)) };
        // SAFETY: `p` and `outer` are the system block and its layout.
        unsafe { System.dealloc(p, outer) };
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller passes a live block from this allocator.
        let was_tracked = unsafe { tag(block) } == TRACKED;
        let now = tracking();
        if now && limit_reached("realloc", |l| l.push(RUST_SOURCE.as_bytes())) {
            return std::ptr::null_mut();
        }
        let h = header(layout);
        let outer = outer(layout).expect("a live block's layout fits");
        let Some(new_outer) = new_size.checked_add(h) else {
            return std::ptr::null_mut();
        };
        // SAFETY: the system block starts a header before the caller's.
        let p = unsafe { block.sub(h) };
        // SAFETY: `p` and `outer` are the system block and its layout;
        // `new_outer` is not zero.
        let q = unsafe { System.realloc(p, outer, new_outer) };
        if q.is_null() {
            return q;
        }
        // SAFETY: the new block keeps the header before the caller's bytes.
        let moved = unsafe { q.add(h) };
        count();
        if was_tracked {
            log_rust(|l| write!(l, "realloc({}, {new_size}) = {}", Ptr(block), Ptr(moved)));
        } else if now {
            LIVE.fetch_add(1, Ordering::Relaxed);
            // SAFETY: as in `make`.
            unsafe { tag_slot(moved).write(TRACKED) };
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
}
