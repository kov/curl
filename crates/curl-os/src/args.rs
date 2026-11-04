//! The process's command line, read and wiped in place.
//!
//! A password given on the command line is visible to anyone who can list
//! processes, for as long as the process runs. Like the C tool, the curl
//! tool overwrites such an argument with `*` once it has read it. That
//! needs the argument strings themselves, not a copy: glibc passes them to
//! the functions in `.init_array` before `main`, and `CAPTURE` keeps them.
//! On macOS the process's `argv` is where `_NSGetArgv` says, the strings
//! the system shows process listings, which C's tool writes there too
//! (`HAVE_WRITABLE_ARGV`).
//!
//! Only this module reads the argument strings: `std::env::args` and
//! `std::env::args_os` are banned by `clippy.toml`, so nothing reads them
//! while they are being wiped.
//!
//! On Windows the C library hands C's `main` its arguments in the ANSI
//! code page, which is what C's tool reads unless built for Unicode; the
//! copy is of those bytes, as they are, in the code page the files they
//! name are opened in. Their strings are the C library's copy, not what
//! process listings show, so C does not wipe them there (it has no
//! `HAVE_WRITABLE_ARGV`), and neither is there a `wipe` here.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int};
#[cfg(unix)]
use std::sync::Mutex;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicIsize, AtomicPtr, Ordering};

#[cfg(all(
    unix,
    not(any(all(target_os = "linux", target_env = "gnu"), target_vendor = "apple"))
))]
compile_error!("the command line is captured as glibc or macOS's dyld passes it");

#[cfg(target_os = "linux")]
static ARGC: AtomicIsize = AtomicIsize::new(-1);
#[cfg(unix)]
/// Held while the argument strings are read or written, so a copy never
/// sees a wipe half done.
static LOCK: Mutex<()> = Mutex::new(());
#[cfg(target_os = "linux")]
static ARGV: AtomicPtr<*mut c_char> = AtomicPtr::new(core::ptr::null_mut());

#[cfg(target_os = "linux")]
/// Called by glibc before `main`, with the process's arguments.
extern "C" fn capture(argc: c_int, argv: *mut *mut c_char, _envp: *mut *mut c_char) {
    ARGV.store(argv, Ordering::Release);
    ARGC.store(argc as isize, Ordering::Release);
}

#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array")]
static CAPTURE: extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) = capture;

#[cfg(target_vendor = "apple")]
/// The process's arguments, where the system keeps them for `main`
/// (`_NSGetArgc`, `_NSGetArgv`): their count and the array of their
/// strings.
fn captured() -> (usize, *mut *mut c_char) {
    // SAFETY: it takes no argument and gives a pointer to the count dyld
    // sets before any code of the program runs and keeps for the life of
    // the process.
    let argc_at = unsafe { libc::_NSGetArgc() };
    // SAFETY: as above, for the array.
    let argv_at = unsafe { libc::_NSGetArgv() };
    // SAFETY: `argc_at` points to that count, live and aligned.
    let argc: c_int = unsafe { argc_at.read() };
    // SAFETY: `argv_at` points to that array's pointer, live and aligned.
    let argv = unsafe { argv_at.read() };
    let argc = usize::try_from(argc).expect("the process has its arguments");
    assert!(!argv.is_null(), "the process has its arguments");
    (argc, argv)
}

#[cfg(target_os = "linux")]
/// The captured arguments: their count and the array of their strings.
fn captured() -> (usize, *mut *mut c_char) {
    // Reading `CAPTURE` keeps the linker from dropping it with nothing
    // else referring to it.
    std::hint::black_box(&CAPTURE);
    let argc = ARGC.load(Ordering::Acquire);
    let argv = ARGV.load(Ordering::Acquire);
    assert!(
        argc >= 0 && !argv.is_null(),
        "the command line was not captured before main"
    );
    (argc.unsigned_abs(), argv)
}

#[cfg(unix)]
/// Argument `index`: the pointer the system passed, through which the
/// string may be written.
fn argument(index: usize) -> Option<*mut c_char> {
    let (argc, argv) = captured();
    if index >= argc {
        return None;
    }
    // SAFETY: glibc, or dyld, passes an array of `argc` valid pointers,
    // which stays in place for the life of the process.
    Some(unsafe { argv.wrapping_add(index).read() })
}

#[cfg(unix)]
/// Call `f` with the bytes of argument string `arg`. The borrow ends when
/// `f` returns, so none is live when `wipe` writes the string.
fn with_bytes<R>(arg: *mut c_char, f: impl FnOnce(&[u8]) -> R) -> R {
    // SAFETY: `arg` is a NUL-terminated string the system passed, alive
    // for the life of the process. Callers hold `LOCK`, so `wipe` does not write
    // it while `f` reads it.
    f(unsafe { CStr::from_ptr(arg) }.to_bytes())
}

/// A copy of the command line's bytes, the program name first.
///
/// The copy is the one infallible allocation kept here: the command line
/// is the process's input, read before anything is tracked.
#[cfg(unix)]
#[allow(
    clippy::disallowed_methods,
    reason = "the command line is copied once, at start-up"
)]
pub fn command_line() -> Vec<Vec<u8>> {
    let _lock = LOCK.lock().expect("never poisoned: panics abort");
    let (argc, _) = captured();
    (0..argc)
        .map_while(argument)
        .map(|a| with_bytes(a, <[u8]>::to_vec))
        .collect()
}

#[cfg(unix)]
/// Overwrite argument `index` with `*` from byte `offset` to its end, so
/// that process listings no longer show it. Returns false if there is no
/// such argument, or it is shorter than `offset`.
pub fn wipe(index: usize, offset: usize) -> bool {
    let _lock = LOCK.lock().expect("never poisoned: panics abort");
    let Some(arg) = argument(index) else {
        return false;
    };
    let len = with_bytes(arg, <[u8]>::len);
    if offset > len {
        return false;
    }
    let start = arg.cast::<u8>().wrapping_add(offset);
    // SAFETY: `arg` is the pointer the system passed in `argv`, and the bytes
    // from `offset` to the NUL belong to its string, which the process may
    // write. No reference to the string is live: `with_bytes`' ended above,
    // and every other reader takes `LOCK`. The NUL stays, so the length
    // does not change.
    unsafe { start.write_bytes(b'*', len - offset) };
    true
}

#[cfg(windows)]
unsafe extern "C" {
    /// Where the C library keeps the count of `main`'s arguments.
    fn __p___argc() -> *mut c_int;
    /// Where it keeps the array of their strings, in the ANSI code page.
    fn __p___argv() -> *mut *mut *mut c_char;
}

/// A copy of the command line: the arguments the C library parsed for
/// `main`, the program name first, as the bytes C's tool reads them
/// (`main`'s `argv`), in the ANSI code page.
///
/// The copy is the one infallible allocation kept here: the command line
/// is the process's input, read before anything is tracked.
#[cfg(windows)]
#[allow(
    clippy::disallowed_methods,
    reason = "the command line is copied once, at start-up"
)]
pub fn command_line() -> Vec<Vec<u8>> {
    // SAFETY: neither function takes an argument; each gives a pointer to
    // the C library's value, which it sets before `main` and keeps for the
    // life of the process.
    let argc = unsafe { __p___argc() };
    // SAFETY: as above.
    let argv = unsafe { __p___argv() };
    // SAFETY: as above.
    let argc = unsafe { argc.read() };
    // SAFETY: as above.
    let argv = unsafe { argv.read() };
    let argc = usize::try_from(argc).unwrap_or(0);
    if argv.is_null() {
        return Vec::new();
    }
    (0..argc)
        .map(|i| {
            // SAFETY: `argv` holds `argc` pointers to NUL-terminated
            // strings, which the C library never frees.
            let arg = unsafe { argv.wrapping_add(i).read() };
            // SAFETY: as above.
            unsafe { CStr::from_ptr(arg) }.to_bytes().to_vec()
        })
        .collect()
}

/// The program's file, as C's tool names it to find what lies beside it
/// (`GetModuleFileName(0, ...)` without `UNICODE`): its whole path, in the
/// ANSI code page.
///
/// `None` if the system cannot say; `Err` when memory for the answer
/// cannot be allocated.
#[cfg(windows)]
pub fn program_file() -> Result<Option<Vec<u8>>, curl_alloc::OutOfMemory> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameA;
    let mut room = 512usize;
    loop {
        let mut buf: Vec<u8> = Vec::new();
        buf.try_reserve_exact(room)?;
        let size = u32::try_from(room).expect("a path's room fits");
        // SAFETY: a null module is the program's own; `buf` has room for
        // the `size` bytes the call is told, which it writes no further
        // than, and outlives the call.
        let n = unsafe { GetModuleFileNameA(core::ptr::null_mut(), buf.as_mut_ptr(), size) };
        let n = usize::try_from(n).expect("a u32 fits");
        if n == 0 {
            return Ok(None);
        }
        // A name cut short fills the buffer whole.
        if n < room {
            // SAFETY: the call wrote `n` bytes, below the room reserved.
            unsafe { buf.set_len(n) };
            return Ok(Some(buf));
        }
        room = room.checked_mul(2).expect("a path's room fits");
    }
}
