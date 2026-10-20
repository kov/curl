//! The process's command line, read and wiped in place.
//!
//! A password given on the command line is visible to anyone who can list
//! processes, for as long as the process runs. Like the C tool, the curl
//! tool overwrites such an argument with `*` once it has read it. That
//! needs the argument strings themselves, not a copy: glibc passes them to
//! the functions in `.init_array` before `main`, and `CAPTURE` keeps them.
//!
//! Only this module reads the argument strings: `std::env::args` and
//! `std::env::args_os` are banned by `clippy.toml`, so nothing reads them
//! while they are being wiped.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicIsize, AtomicPtr, Ordering};

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("the command line is captured as glibc passes it to `.init_array`");

static ARGC: AtomicIsize = AtomicIsize::new(-1);
/// Held while the argument strings are read or written, so a copy never
/// sees a wipe half done.
static LOCK: Mutex<()> = Mutex::new(());
static ARGV: AtomicPtr<*mut c_char> = AtomicPtr::new(core::ptr::null_mut());

/// Called by glibc before `main`, with the process's arguments.
extern "C" fn capture(argc: c_int, argv: *mut *mut c_char, _envp: *mut *mut c_char) {
    ARGV.store(argv, Ordering::Release);
    ARGC.store(argc as isize, Ordering::Release);
}

#[used]
#[unsafe(link_section = ".init_array")]
static CAPTURE: extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) = capture;

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

/// Argument `index`: the pointer glibc passed, through which the string
/// may be written.
fn argument(index: usize) -> Option<*mut c_char> {
    let (argc, argv) = captured();
    if index >= argc {
        return None;
    }
    // SAFETY: glibc passes an array of `argc` valid pointers, which stays
    // in place for the life of the process.
    Some(unsafe { argv.wrapping_add(index).read() })
}

/// Call `f` with the bytes of argument string `arg`. The borrow ends when
/// `f` returns, so none is live when `wipe` writes the string.
fn with_bytes<R>(arg: *mut c_char, f: impl FnOnce(&[u8]) -> R) -> R {
    // SAFETY: `arg` is a NUL-terminated string glibc passed, alive for the
    // life of the process. Callers hold `LOCK`, so `wipe` does not write
    // it while `f` reads it.
    f(unsafe { CStr::from_ptr(arg) }.to_bytes())
}

/// A copy of the command line, the program name first.
///
/// The copy is the one infallible allocation kept here: the command line
/// is the process's input, read before anything is tracked.
#[allow(
    clippy::disallowed_methods,
    reason = "the command line is copied once, at start-up"
)]
pub fn command_line() -> Vec<OsString> {
    let _lock = LOCK.lock().expect("never poisoned: panics abort");
    let (argc, _) = captured();
    (0..argc)
        .map_while(argument)
        .map(|a| with_bytes(a, |b| OsString::from_vec(b.to_vec())))
        .collect()
}

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
    // SAFETY: `arg` is the pointer glibc passed in `argv`, and the bytes
    // from `offset` to the NUL belong to its string, which the process may
    // write. No reference to the string is live: `with_bytes`' ended above,
    // and every other reader takes `LOCK`. The NUL stays, so the length
    // does not change.
    unsafe { start.write_bytes(b'*', len - offset) };
    true
}
