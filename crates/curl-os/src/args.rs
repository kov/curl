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
//!
//! On Windows the C library hands C's `main` its arguments in the ANSI
//! code page, which is what C's tool reads unless built for Unicode; the
//! copy is of those. Their strings are the C library's copy, not what
//! process listings show, so C does not wipe them there (it has no
//! `HAVE_WRITABLE_ARGV`), and neither is there a `wipe` here.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int};
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::sync::Mutex;
#[cfg(unix)]
use std::sync::atomic::{AtomicIsize, AtomicPtr, Ordering};

#[cfg(all(unix, not(all(target_os = "linux", target_env = "gnu"))))]
compile_error!("the command line is captured as glibc passes it to `.init_array`");

#[cfg(unix)]
static ARGC: AtomicIsize = AtomicIsize::new(-1);
#[cfg(unix)]
/// Held while the argument strings are read or written, so a copy never
/// sees a wipe half done.
static LOCK: Mutex<()> = Mutex::new(());
#[cfg(unix)]
static ARGV: AtomicPtr<*mut c_char> = AtomicPtr::new(core::ptr::null_mut());

#[cfg(unix)]
/// Called by glibc before `main`, with the process's arguments.
extern "C" fn capture(argc: c_int, argv: *mut *mut c_char, _envp: *mut *mut c_char) {
    ARGV.store(argv, Ordering::Release);
    ARGC.store(argc as isize, Ordering::Release);
}

#[cfg(unix)]
#[used]
#[unsafe(link_section = ".init_array")]
static CAPTURE: extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) = capture;

#[cfg(unix)]
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

#[cfg(unix)]
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
#[cfg(unix)]
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
    // SAFETY: `arg` is the pointer glibc passed in `argv`, and the bytes
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

/// A copy of the command line, the program name first: the arguments the
/// C library parsed for `main`, in the ANSI code page, as C's tool reads
/// them (`main`'s `argv`), each turned to UTF-16 from that code page for
/// the `OsString` that holds it.
///
/// The copy is the one infallible allocation kept here: the command line
/// is the process's input, read before anything is tracked.
#[cfg(windows)]
#[allow(
    clippy::disallowed_methods,
    reason = "the command line is copied once, at start-up"
)]
pub fn command_line() -> Vec<OsString> {
    use std::os::windows::ffi::OsStringExt as _;
    use windows_sys::Win32::Globalization::{CP_ACP, MultiByteToWideChar};
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
            let arg = unsafe { CStr::from_ptr(arg) }.to_bytes();
            if arg.is_empty() {
                return OsString::new();
            }
            let len = i32::try_from(arg.len()).expect("an argument fits");
            // SAFETY: `arg` is `len` readable bytes; a null output asks for
            // the room the conversion needs.
            let need = unsafe {
                MultiByteToWideChar(CP_ACP, 0, arg.as_ptr(), len, core::ptr::null_mut(), 0)
            };
            let mut wide =
                std::iter::repeat_n(0u16, usize::try_from(need).unwrap_or(0)).collect::<Vec<u16>>();
            // SAFETY: as above, with `wide` writable for the `need` units
            // the call is told.
            let n = unsafe {
                MultiByteToWideChar(CP_ACP, 0, arg.as_ptr(), len, wide.as_mut_ptr(), need)
            };
            wide.truncate(usize::try_from(n).unwrap_or(0));
            OsString::from_wide(&wide)
        })
        .collect()
}
