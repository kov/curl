//! Files and directories, by name: for `file:` URLs (`lib/file.c`), the
//! files the library writes whole, and the tool's. Each operation on a
//! name is a system call of its own taking it as a C string, so neither
//! the name nor a directory entry's is ever copied to the heap: std's
//! calls copy a name of 384 bytes or more with an allocation that cannot
//! fail. Reading, writing, seeking and an open file's status go through
//! the std `File` that opening gives. Standard error is pointed at a file
//! here too, as the tool's `--stderr` asks, a file's reads are made not to
//! wait, as `-T .` asks of standard input, and a file is closed saying
//! whether that went.
//!
//! On Windows a name is in the ANSI code page, as C's build without
//! Unicode takes it, and is opened through the system's UTF-16 calls, as
//! the C library opens it, a long one marked long as C marks it; the
//! UTF-16 is made in memory that may be refused, as C makes it. A file's
//! reads cannot be made not to wait there: C reads standard input in a
//! thread of its own instead.

#![allow(unsafe_code)]

use core::ffi::CStr;
use std::fs::File;
use std::io;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
#[cfg(unix)]
use std::ptr::NonNull;

/// What opening for writing does to what the file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    /// Nothing: it is emptied.
    Nothing,
    /// Everything: writes go after it.
    Everything,
    /// There is to be nothing yet: a file that exists is not opened
    /// (`O_EXCL`).
    Absent,
}

/// One of the process's standard streams, by its C library descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Std {
    In,
    Out,
    Err,
}

/// Make `stream` binary, as C's `CURL_BINMODE` does: from now on the C
/// library translates none of its line ends. Nothing to do on Unix.
#[cfg(unix)]
pub fn set_binary(stream: Std) {
    let _ = stream;
}

/// Whether `stream` is text or binary: binary on Unix, where there is no
/// difference.
#[cfg(unix)]
pub fn mode(stream: Std) -> crate::text::Mode {
    let _ = stream;
    crate::text::Mode::Binary
}

#[cfg(windows)]
unsafe extern "C" {
    /// The UCRT's: set descriptor `fd`'s mode, giving the one it had.
    fn _setmode(fd: core::ffi::c_int, mode: core::ffi::c_int) -> core::ffi::c_int;
}

/// The UCRT's `_O_TEXT` and `_O_BINARY`.
#[cfg(windows)]
const O_TEXT: core::ffi::c_int = 0x4000;
#[cfg(windows)]
const O_BINARY: core::ffi::c_int = 0x8000;

#[cfg(windows)]
fn descriptor(stream: Std) -> core::ffi::c_int {
    match stream {
        Std::In => 0,
        Std::Out => 1,
        Std::Err => 2,
    }
}

/// Make `stream` binary, as C's `CURL_BINMODE` does (`_setmode` with
/// `_O_BINARY`): from now on the C library translates none of its line
/// ends. The mode is the C library's, kept for its descriptor, which
/// every part of the process shares.
#[cfg(windows)]
pub fn set_binary(stream: Std) {
    // SAFETY: `_setmode` takes no pointers; descriptors 0 to 2 are the
    // C library's from its start, a stream it found none for among them.
    unsafe { _setmode(descriptor(stream), O_BINARY) };
}

/// Whether `stream` is text or binary, as the C library keeps it for its
/// descriptor: text from the start until [`set_binary`]. The C library
/// tells a mode only as it sets one: the one it had is set back at once.
#[cfg(windows)]
pub fn mode(stream: Std) -> crate::text::Mode {
    let fd = descriptor(stream);
    // SAFETY: as in `set_binary`.
    let was = unsafe { _setmode(fd, O_BINARY) };
    if was != -1 && was != O_BINARY {
        // SAFETY: as above, the mode given back the one it had.
        unsafe { _setmode(fd, was) };
    }
    match was {
        O_TEXT => crate::text::Mode::Text,
        _ => crate::text::Mode::Binary,
    }
}

/// Write some of `bytes` to `file` as the C library writes to a
/// descriptor open on it in `mode` (`_write`): how many of `bytes` went.
/// Binary goes as it is. Text has each line feed written after a
/// carriage return ([`crate::text::Writer`]), and to a console it goes as
/// the UCRT writes text there (`write_double_translated_ansi_nolock`):
/// read in the ANSI code page and written as UTF-16 (`WriteConsoleW`),
/// where binary goes to the console as bytes, for it to read in its own
/// code page.
#[cfg(windows)]
pub fn write_as_c(file: &File, mode: crate::text::Mode, bytes: &[u8]) -> io::Result<usize> {
    use crate::text::{Mode, Writer};
    use std::io::Write as _;
    let mut to = file;
    if mode == Mode::Binary {
        return to.write(bytes);
    }
    let Some(console) = crate::terminal::Console::of(file.as_handle()) else {
        return Writer::new(to, Mode::Text).write(bytes);
    };
    // A piece at a time, in the ANSI code page's bytes, each a unit or
    // fewer in UTF-16: 256 bytes are 512 at most with their line ends.
    let mut ansi = [0u8; 512];
    let mut room = &mut ansi[..];
    let piece = &bytes[..bytes.len().min(256)];
    let took = Writer::new(&mut room, Mode::Text).write(piece)?;
    let n = 512 - room.len();
    let mut wide = [0u16; 512];
    let units = crate::terminal::ansi_to_wide(&ansi[..n], &mut wide);
    console.write(&wide[..units])?;
    Ok(took)
}

/// Write some of `bytes` to `file`: Unix has no modes.
#[cfg(unix)]
pub fn write_as_c(file: &File, mode: crate::text::Mode, bytes: &[u8]) -> io::Result<usize> {
    use std::io::Write as _;
    let _ = mode;
    let mut to = file;
    to.write(bytes)
}

/// Write all of `bytes` to standard error as C writes to `stderr`, in
/// the mode the C library keeps for it ([`mode`], [`write_as_c`]),
/// through the handle the process has for it now (`GetStdHandle`, which
/// [`stderr_to`] changes).
#[cfg(windows)]
pub fn write_stderr(bytes: &[u8]) -> io::Result<()> {
    use std::mem::ManuallyDrop;
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
    // SAFETY: `GetStdHandle` takes no pointers.
    let handle = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    if handle.is_null() || handle == wf::INVALID_HANDLE_VALUE {
        return Err(io::Error::from_raw_os_error(
            wf::ERROR_INVALID_HANDLE as i32,
        ));
    }
    // SAFETY: the handle is the process's, open while it is its standard
    // error; the `File` borrows it for the writes and never closes it.
    let file = ManuallyDrop::new(unsafe { File::from_raw_handle(handle) });
    write_all_as_c(&file, mode(Std::Err), bytes)
}

/// Write all of `bytes` to `file` as [`write_as_c`] writes some.
pub fn write_all_as_c(file: &File, mode: crate::text::Mode, bytes: &[u8]) -> io::Result<()> {
    let mut rest = bytes;
    while !rest.is_empty() {
        match write_as_c(file, mode, rest) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => rest = &rest[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Write all of `bytes` to standard error, as C writes to `stderr`.
#[cfg(unix)]
pub fn write_stderr(bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    io::stderr().write_all(bytes)
}

#[cfg(unix)]
/// Whether `e` is a refusal to look in or change a directory (`EACCES`),
/// as distinct from an operation not permitted (`EPERM`), which std
/// reports with the same kind.
pub fn denied(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EACCES)
}

#[cfg(unix)]
/// The longest name the system takes, its ending zero byte included
/// (`PATH_MAX`).
const NAME_MAX_BYTES: usize = libc::PATH_MAX as usize;

#[cfg(unix)]
/// Call `f` with `name` as a C string, as C sees it: to its first zero
/// byte, if it has one. It is copied to a buffer on the stack, not the
/// heap; one too long for the system is refused with the error the system
/// gives it (`ENAMETOOLONG`), without calling `f`.
pub fn with_c_name<T>(name: &[u8], f: impl FnOnce(&CStr) -> io::Result<T>) -> io::Result<T> {
    let name = name.split(|&b| b == 0).next().unwrap_or_default();
    if name.len() >= NAME_MAX_BYTES {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    let mut buf = [0u8; NAME_MAX_BYTES];
    buf[..name.len()].copy_from_slice(name);
    let c = CStr::from_bytes_until_nul(&buf).expect("a zero byte after the name");
    f(c)
}

#[cfg(unix)]
/// What `stat(2)` says of a file, as much as is asked of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    mode: libc::mode_t,
    len: u64,
    modified: i64,
}

#[cfg(unix)]
impl Status {
    /// Whether it is a regular file.
    pub fn is_file(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
    }

    /// Whether it is a directory.
    pub fn is_dir(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFDIR
    }

    /// Its size in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether it is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// When it was last modified, in seconds after the epoch.
    pub fn modified(&self) -> i64 {
        self.modified
    }
}

#[cfg(unix)]
/// The status of the file at `path`, a symbolic link followed.
pub fn stat(path: &CStr) -> io::Result<Status> {
    let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `path` is a C string and `st` room for a `stat`, both alive
    // for the call, which fills `st` in when it returns 0.
    if unsafe { libc::stat(path.as_ptr(), st.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `stat` returned 0, so it filled `st` in.
    let st = unsafe { st.assume_init() };
    Ok(Status {
        mode: st.st_mode,
        len: u64::try_from(st.st_size).expect("the system reports no negative size"),
        modified: st.st_mtime,
    })
}

#[cfg(unix)]
/// Call `f` with the absolute name of the file at `path`, every symbolic
/// link, `.` and `..` resolved (`realpath(3)`), into a buffer on the
/// stack, not the heap. A file that does not exist has none.
pub fn real_path<T>(path: &CStr, f: impl FnOnce(&[u8]) -> T) -> io::Result<T> {
    let mut resolved = [0u8; NAME_MAX_BYTES];
    // SAFETY: `path` is a C string and `resolved` room for `PATH_MAX` bytes,
    // what `realpath` writes at most, its ending zero byte included; both
    // are alive for the call.
    let got = unsafe { libc::realpath(path.as_ptr(), resolved.as_mut_ptr().cast()) };
    if got.is_null() {
        return Err(io::Error::last_os_error());
    }
    let name = CStr::from_bytes_until_nul(&resolved).expect("realpath ends its name");
    Ok(f(name.to_bytes()))
}

#[cfg(unix)]
/// Remove the name `path` (`unlink(2)`).
pub fn remove(path: &CStr) -> io::Result<()> {
    // SAFETY: `path` is a C string, alive for the call.
    if unsafe { libc::unlink(path.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
/// Give the file `from` the name `to`, in place of any file that had it
/// (`rename(2)`).
pub fn rename(from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: both are C strings, alive for the call.
    if unsafe { libc::rename(from.as_ptr(), to.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/// Permissions `mode` as the system's calls take them: Linux's `mode_t`
/// is the `u32` they are given as.
fn mode_t(mode: u32) -> libc::mode_t {
    mode
}

#[cfg(target_vendor = "apple")]
/// Permissions `mode` as the system's calls take them: macOS's `mode_t`
/// is 16 bits, which every mode the options allow (at most `0o777`) fits.
fn mode_t(mode: u32) -> libc::mode_t {
    libc::mode_t::try_from(mode).expect("permissions fit a mode")
}

#[cfg(unix)]
/// Make the directory `path`, with permissions `mode` before the umask
/// (`mkdir(2)`).
pub fn make_dir(path: &CStr, mode: u32) -> io::Result<()> {
    // SAFETY: `path` is a C string, alive for the call.
    if unsafe { libc::mkdir(path.as_ptr(), mode_t(mode)) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
/// Set the access and modification times of the file at `path` to `t`
/// seconds after the epoch (`utimes(2)`), by name: no permission to read
/// or write it is needed, only to own it.
pub fn set_times(path: &CStr, t: i64) -> io::Result<()> {
    let at = libc::timeval {
        tv_sec: t,
        tv_usec: 0,
    };
    let times = [at, at];
    // SAFETY: `path` is a C string and `times` two `timeval`s, both alive
    // for the call, which only reads them.
    if unsafe { libc::utimes(path.as_ptr(), times.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
/// Open `path` to read it. A directory opens too.
pub fn open_read(path: &CStr) -> io::Result<File> {
    open(path, libc::O_RDONLY, 0)
}

#[cfg(unix)]
/// Open `path` to write it, creating it with permissions `mode` (before
/// the umask) if it does not exist.
pub fn open_write(path: &CStr, keep: Keep, mode: u32) -> io::Result<File> {
    let keep = match keep {
        Keep::Nothing => libc::O_TRUNC,
        Keep::Everything => libc::O_APPEND,
        Keep::Absent => libc::O_EXCL,
    };
    open(path, libc::O_WRONLY | libc::O_CREAT | keep, mode_t(mode))
}

/// This thread's `errno`, where the C library keeps it.
#[cfg(target_os = "linux")]
use libc::__errno_location as errno_location;
/// This thread's `errno`, where the C library keeps it.
#[cfg(target_vendor = "apple")]
use libc::__error as errno_location;

#[cfg(unix)]
fn open(path: &CStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<File> {
    // SAFETY: `path` is a C string, alive for the call; `open` reads the
    // mode argument only with O_CREAT, and takes it as an unsigned int.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            flags | libc::O_CLOEXEC,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `open` returned a new descriptor that nothing else owns.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// Cut `file`, opened to write, to `len` bytes (`ftruncate`); one opened
/// to keep everything goes on writing at its end, now there.
#[cfg(unix)]
pub fn truncate(file: &File, len: u64) -> io::Result<()> {
    file.set_len(len)
}

#[cfg(unix)]
/// Close `file` (`close(2)`), saying whether that went, which dropping
/// it does not: a write the kernel held may fail only then. The
/// descriptor is let go of either way, and not closed again.
pub fn close(file: File) -> io::Result<()> {
    let fd = OwnedFd::from(file).into_raw_fd();
    // SAFETY: `fd` was the file's own, which no one else holds, and is
    // not used again whatever `close` says.
    if unsafe { libc::close(fd) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
/// Standard input, read through a descriptor of its own: no buffer
/// stays behind, as `std::io::stdin`'s does until the process ends.
pub fn stdin() -> io::Result<File> {
    // SAFETY: `fcntl` reads descriptor 0 only for the call, and makes a
    // new descriptor, closed on exec, or fails.
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is the new descriptor, owned by nothing else.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

#[cfg(unix)]
/// Make reads of `file` not wait for data, as `curlx_nonblock` does
/// (`O_NONBLOCK`): a read that finds nothing fails with `WouldBlock`. The
/// flag belongs to the open file, so it holds for every descriptor of it:
/// for standard input itself when `file` is `stdin`'s.
pub fn set_nonblocking(file: &File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: `fcntl` reads the flags of `fd`, which `file` keeps open for
    // the call.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above; the call changes the flags only.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
/// Make standard error write where `to` writes, as `freopen` of `stderr`
/// does: every later write to descriptor 2, from anywhere in the process,
/// goes there.
pub fn stderr_to(to: &impl AsFd) -> io::Result<()> {
    // SAFETY: `to`'s descriptor is open for the call, as its borrow says;
    // `dup2` replaces descriptor 2 in one step, whatever it was.
    if unsafe { libc::dup2(to.as_fd().as_raw_fd(), libc::STDERR_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
/// A directory's entries, as `readdir` gives them, in no order.
#[derive(Debug)]
pub struct Dir {
    stream: NonNull<libc::DIR>,
}

#[cfg(unix)]
impl Dir {
    /// Open the directory at `path` to list it.
    pub fn open(path: &CStr) -> io::Result<Dir> {
        // SAFETY: `path` is a C string, alive for the call.
        let stream = unsafe { libc::opendir(path.as_ptr()) };
        NonNull::new(stream)
            .map(|stream| Dir { stream })
            .ok_or_else(io::Error::last_os_error)
    }

    /// The next entry's name, `.` and `..` among them; `None` after the
    /// last. The name is valid until the next call.
    pub fn next_name(&mut self) -> Option<io::Result<&[u8]>> {
        // `readdir` tells the end from a failure only by `errno`.
        // SAFETY: the call has no preconditions.
        let errno = unsafe { errno_location() };
        // SAFETY: it points to this thread's `errno`, valid to write.
        unsafe { *errno = 0 };
        // SAFETY: the stream is open, and only this `Dir`, which `&mut`
        // makes exclusive, reads it.
        let entry = unsafe { libc::readdir(self.stream.as_ptr()) };
        if entry.is_null() {
            let err = io::Error::last_os_error();
            return (err.raw_os_error() != Some(0)).then_some(Err(err));
        }
        // The record is only as long as its name: `d_name` is reached by a
        // pointer, as a reference to the whole array may reach past it.
        // SAFETY: a non-null entry is valid until the stream is read again
        // or closed, which the borrow of `self` prevents.
        let name = unsafe { (&raw const (*entry).d_name).cast::<core::ffi::c_char>() };
        // SAFETY: `d_name` holds the entry's name, ended by a NUL.
        let name = unsafe { CStr::from_ptr(name) };
        Some(Ok(name.to_bytes()))
    }
}

#[cfg(unix)]
impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: the stream is open and closed only here. A failure
        // leaves nothing to do.
        unsafe { libc::closedir(self.stream.as_ptr()) };
    }
}

#[cfg(windows)]
use std::os::windows::io::{AsHandle, AsRawHandle as _, FromRawHandle as _, IntoRawHandle as _};

#[cfg(windows)]
use windows_sys::Win32::Foundation as wf;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem as wfs;

/// What holds an open file, on either platform: a descriptor on Unix, a
/// handle on Windows.
#[cfg(unix)]
pub use std::os::fd::AsFd as AsFile;
#[cfg(windows)]
pub use std::os::windows::io::AsHandle as AsFile;

/// Whether `e` is a refusal to look in or change a directory
/// (`ERROR_ACCESS_DENIED`).
#[cfg(windows)]
pub fn denied(e: &io::Error) -> bool {
    e.raw_os_error() == Some(wf::ERROR_ACCESS_DENIED as i32)
}

/// The longest name the system takes, in bytes, its ending zero byte
/// included: C's `max_path_len`, past which it no longer makes a long name
/// one the system takes (`fix_excessive_path`).
#[cfg(windows)]
const NAME_MAX_BYTES: usize = 32_767;

/// Call `f` with `name` as a C string, as C sees it: to its first zero
/// byte, if it has one. It is copied to a buffer on the stack, not the
/// heap; one too long for the system is refused with the error the system
/// gives it (`ERROR_FILENAME_EXCED_RANGE`), without calling `f`.
#[cfg(windows)]
pub fn with_c_name<T>(name: &[u8], f: impl FnOnce(&CStr) -> io::Result<T>) -> io::Result<T> {
    let name = name.split(|&b| b == 0).next().unwrap_or_default();
    if name.len() >= NAME_MAX_BYTES {
        return Err(io::Error::from_raw_os_error(
            wf::ERROR_FILENAME_EXCED_RANGE as i32,
        ));
    }
    let mut buf = [0u8; NAME_MAX_BYTES];
    buf[..name.len()].copy_from_slice(name);
    let c = CStr::from_bytes_until_nul(&buf).expect("a zero byte after the name");
    f(c)
}

/// The system's last error.
#[cfg(windows)]
fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// Memory for `n` units, zeroed, or the error of running out.
#[cfg(windows)]
fn units(n: usize) -> io::Result<Vec<u16>> {
    use curl_alloc::TryVec as _;
    let mut v = Vec::new();
    v.try_resize(n, 0)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    Ok(v)
}

/// `name`, in the ANSI code page as C's build takes a file's name, in the
/// UTF-16 the system's calls take, ended by a zero; made absolute and
/// marked long (`\\?\`) when that is longer than `MAX_PATH`, as C's
/// `fix_excessive_path` makes it, so that a long name opens too.
#[cfg(windows)]
pub(crate) fn wide_name(name: &CStr) -> io::Result<Vec<u16>> {
    use windows_sys::Win32::Globalization::{CP_ACP, MultiByteToWideChar};
    /// `MAX_PATH`, the longest name the system takes unmarked.
    const MAX_PATH: usize = 260;
    let bytes = name.to_bytes_with_nul();
    let len = i32::try_from(bytes.len()).expect("a name fits");
    // SAFETY: `bytes` is `len` readable bytes; a null output asks for the
    // room the conversion needs.
    let need =
        unsafe { MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), len, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return Err(last_error());
    }
    let mut wide = units(usize::try_from(need).expect("positive"))?;
    // SAFETY: as above, `wide` writable for the `need` units it is told.
    let n = unsafe { MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), need) };
    if n <= 0 {
        return Err(last_error());
    }
    wide.truncate(usize::try_from(n).expect("positive"));
    let marked = |w: &[u16], prefix: &str| {
        w.len() >= prefix.len() && w.iter().zip(prefix.encode_utf16()).all(|(&a, b)| a == b)
    };
    if marked(&wide, r"\\?\") {
        return Ok(wide);
    }
    // SAFETY: `wide` is a NUL-terminated name; a null buffer asks for the
    // room the full name needs.
    let need = unsafe {
        wfs::GetFullPathNameW(wide.as_ptr(), 0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    let need = usize::try_from(need).expect("a u32 fits");
    if need == 0 || need <= MAX_PATH || need > NAME_MAX_BYTES {
        return Ok(wide);
    }
    let mut full = units(need)?;
    let room = u32::try_from(need).expect("fits");
    // SAFETY: `full` is writable for the `room` units the call is told.
    let got = unsafe {
        wfs::GetFullPathNameW(wide.as_ptr(), room, full.as_mut_ptr(), std::ptr::null_mut())
    };
    let got = usize::try_from(got).expect("a u32 fits");
    if got == 0 || got >= need {
        return Ok(wide);
    }
    full.truncate(got);
    let prefix: &str = if marked(&full, r"\\?\") {
        ""
    } else if marked(&full, r"\\.\") {
        full[2] = u16::from(b'?');
        ""
    } else if marked(&full, r"\\.") || marked(&full, r"\\?") {
        // Not a name C marks.
        return Ok(wide);
    } else if marked(&full, r"\\") {
        full.drain(..2);
        r"\\?\UNC\"
    } else {
        r"\\?\"
    };
    let mut out = units(prefix.len() + full.len() + 1)?;
    for (to, from) in out
        .iter_mut()
        .zip(prefix.encode_utf16().chain(full.iter().copied()))
    {
        *to = from;
    }
    Ok(out)
}

/// A handle the system returned, or its error.
#[cfg(windows)]
fn opened(handle: wf::HANDLE) -> io::Result<std::os::windows::io::OwnedHandle> {
    if handle == wf::INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    // SAFETY: `handle` was just opened and is owned by nothing else.
    Ok(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) })
}

/// Open `path` with `CreateFileW`, as the C library's `_sopen_s` opens it
/// for C (`curlx_win32_open`): shared for reading and writing, as
/// `_SH_DENYNO` asks.
#[cfg(windows)]
fn create(
    path: &CStr,
    access: u32,
    share: u32,
    disposition: u32,
    flags: u32,
) -> io::Result<std::os::windows::io::OwnedHandle> {
    let wide = wide_name(path)?;
    // SAFETY: `wide` is a NUL-terminated name alive through the call; no
    // security attributes or template are passed.
    let handle = unsafe {
        wfs::CreateFileW(
            wide.as_ptr(),
            access,
            share,
            std::ptr::null(),
            disposition,
            flags,
            std::ptr::null_mut(),
        )
    };
    opened(handle)
}

/// What a file is, as much as is asked of it.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Other,
}

/// What `_stati64` says of a file, as much as is asked of it.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    kind: Kind,
    len: u64,
    modified: i64,
}

#[cfg(windows)]
impl Status {
    /// Whether it is a regular file.
    pub fn is_file(&self) -> bool {
        self.kind == Kind::File
    }

    /// Whether it is a directory.
    pub fn is_dir(&self) -> bool {
        self.kind == Kind::Dir
    }

    /// Its size in bytes; a directory's is 0.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether it is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// When it was last modified, in seconds after the epoch.
    pub fn modified(&self) -> i64 {
        self.modified
    }
}

/// 100-nanosecond intervals from 1601 to 1970, where a `FILETIME` counts
/// from and Unix time does.
#[cfg(windows)]
const EPOCH_IN_FILETIME: i64 = 116_444_736_000_000_000;

/// The status of the file at `path`, a symbolic link followed.
#[cfg(windows)]
pub fn stat(path: &CStr) -> io::Result<Status> {
    let share = wfs::FILE_SHARE_READ | wfs::FILE_SHARE_WRITE | wfs::FILE_SHARE_DELETE;
    let file = create(
        path,
        wfs::FILE_READ_ATTRIBUTES,
        share,
        wfs::OPEN_EXISTING,
        wfs::FILE_FLAG_BACKUP_SEMANTICS,
    )?;
    let handle = file.as_raw_handle();
    // SAFETY: `handle` is open while `file` lives.
    if unsafe { wfs::GetFileType(handle) } != wfs::FILE_TYPE_DISK {
        return Ok(Status {
            kind: Kind::Other,
            len: 0,
            modified: 0,
        });
    }
    // SAFETY: all zeros is a value of the plain record the call fills.
    let mut info: wfs::BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is the record the call writes, alive through it; the
    // handle is open.
    if unsafe { wfs::GetFileInformationByHandle(handle, &raw mut info) } == 0 {
        return Err(last_error());
    }
    let dir = info.dwFileAttributes & wfs::FILE_ATTRIBUTE_DIRECTORY != 0;
    let written = (i64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
        | i64::from(info.ftLastWriteTime.dwLowDateTime);
    Ok(Status {
        kind: if dir { Kind::Dir } else { Kind::File },
        len: if dir {
            0
        } else {
            (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow)
        },
        modified: (written - EPOCH_IN_FILETIME).div_euclid(10_000_000),
    })
}

/// Call `f` with the absolute name of `path`, its `.` and `..` resolved,
/// into a buffer on the stack, not the heap: on Windows `_fullpath`'s, as
/// C's session cache keys a file there, which follows no link and needs
/// no file.
#[cfg(windows)]
pub fn real_path<T>(path: &CStr, f: impl FnOnce(&[u8]) -> T) -> io::Result<T> {
    let mut full = [0u8; NAME_MAX_BYTES + 1];
    let room = u32::try_from(full.len()).expect("fits");
    // SAFETY: `path` is a C string and `full` writable for the `room`
    // bytes the call is told; both are alive for the call.
    let n = unsafe {
        wfs::GetFullPathNameA(
            path.as_ptr().cast(),
            room,
            full.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };
    let n = usize::try_from(n).expect("a u32 fits");
    if n == 0 {
        return Err(last_error());
    }
    if n >= full.len() {
        return Err(io::Error::from_raw_os_error(
            wf::ERROR_FILENAME_EXCED_RANGE as i32,
        ));
    }
    Ok(f(&full[..n]))
}

/// `f` given where the system finds a file named `name` (`SearchPath`,
/// as C's tool asks it in `FindWin32CACert`): in the program's directory,
/// the current one, the system's directories and those of `PATH`, in the
/// order the system's search mode puts them. `None` if it finds none. A
/// path longer than C's buffer (`MAX_PATH`) is given empty, as C's buffer
/// then is.
#[cfg(windows)]
pub fn search_path<T>(name: &CStr, f: impl FnOnce(&[u8]) -> T) -> Option<T> {
    const MAX_PATH: usize = 260;
    let mut found = [0u8; MAX_PATH];
    let mut part: *mut u8 = std::ptr::null_mut();
    // SAFETY: `name` is a C string, `found` writable for the `MAX_PATH`
    // bytes the call is told and `part` a pointer for it to set, all alive
    // for the call; no path or extension is given.
    let n = unsafe {
        wfs::SearchPathA(
            std::ptr::null(),
            name.as_ptr().cast(),
            std::ptr::null(),
            MAX_PATH as u32,
            found.as_mut_ptr(),
            &raw mut part,
        )
    };
    let n = usize::try_from(n).expect("a u32 fits");
    match n {
        0 => None,
        n if n < MAX_PATH => Some(f(&found[..n])),
        _ => Some(f(b"")),
    }
}

/// A call's result that is true on success, an error if not.
#[cfg(windows)]
fn done(ok: windows_sys::core::BOOL) -> io::Result<()> {
    if ok == 0 { Err(last_error()) } else { Ok(()) }
}

/// Remove the name `path` (`DeleteFileW`, as the C library's `_unlink`).
#[cfg(windows)]
pub fn remove(path: &CStr) -> io::Result<()> {
    let wide = wide_name(path)?;
    // SAFETY: `wide` is a NUL-terminated name, alive for the call.
    done(unsafe { wfs::DeleteFileW(wide.as_ptr()) })
}

/// Give the file `from` the name `to`, in place of any file that had it,
/// as `curlx_win32_rename` does: `MoveFileExW`, tried again for a second
/// while it fails, as another process may still have either open.
#[cfg(windows)]
pub fn rename(from: &CStr, to: &CStr) -> io::Result<()> {
    use std::time::Duration;
    let (from, to) = (wide_name(from)?, wide_name(to)?);
    let start = crate::time::monotonic();
    loop {
        // SAFETY: both are NUL-terminated names, alive for the call.
        let ok =
            unsafe { wfs::MoveFileExW(from.as_ptr(), to.as_ptr(), wfs::MOVEFILE_REPLACE_EXISTING) };
        if ok != 0 {
            return Ok(());
        }
        let failed = last_error();
        if crate::time::monotonic() - start > Duration::from_secs(1) {
            return Err(failed);
        }
        // SAFETY: `Sleep` takes no pointers.
        unsafe { windows_sys::Win32::System::Threading::Sleep(1) };
    }
}

/// Make the directory `path` (`CreateDirectoryW`, as `curlx_win32_mkdir`):
/// Windows has no mode to give it, so `mode` is not used, as C drops it.
#[cfg(windows)]
pub fn make_dir(path: &CStr, mode: u32) -> io::Result<()> {
    let _ = mode;
    let wide = wide_name(path)?;
    // SAFETY: `wide` is a NUL-terminated name, alive for the call; no
    // security attributes are passed.
    done(unsafe { wfs::CreateDirectoryW(wide.as_ptr(), std::ptr::null()) })
}

/// Set the access and modification times of the file at `path` to `t`
/// seconds after the epoch, as C's tool sets them on Windows
/// (`tool_filetime.c`): opened for its attributes only, then
/// `SetFileTime`. A time a `FILETIME` cannot hold is refused; the tool
/// caps it first, as C's does.
#[cfg(windows)]
pub fn set_times(path: &CStr, t: i64) -> io::Result<()> {
    let ft = t
        .checked_mul(10_000_000)
        .and_then(|n| n.checked_add(EPOCH_IN_FILETIME))
        .filter(|&n| n >= 0)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let ft = wf::FILETIME {
        dwLowDateTime: (ft & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (ft >> 32) as u32,
    };
    let share = wfs::FILE_SHARE_READ | wfs::FILE_SHARE_WRITE | wfs::FILE_SHARE_DELETE;
    let file = create(
        path,
        wfs::FILE_WRITE_ATTRIBUTES,
        share,
        wfs::OPEN_EXISTING,
        0,
    )?;
    // SAFETY: the handle is open while `file` lives; both times are read
    // only, the creation time left as it is.
    done(unsafe {
        wfs::SetFileTime(
            file.as_raw_handle(),
            std::ptr::null(),
            &raw const ft,
            &raw const ft,
        )
    })
}

/// Open `path` to read it, as C's `curlx_open` with `O_RDONLY`. A
/// directory does not open, as it does not in the C library.
#[cfg(windows)]
pub fn open_read(path: &CStr) -> io::Result<File> {
    let share = wfs::FILE_SHARE_READ | wfs::FILE_SHARE_WRITE;
    let file = create(
        path,
        wf::GENERIC_READ,
        share,
        wfs::OPEN_EXISTING,
        wfs::FILE_ATTRIBUTE_NORMAL,
    )?;
    Ok(File::from(file))
}

/// Open `path` to write it, creating it if it does not exist: read-only if
/// `mode` gives its owner no write permission, as the C library makes a
/// file without `_S_IWRITE`.
#[cfg(windows)]
pub fn open_write(path: &CStr, keep: Keep, mode: u32) -> io::Result<File> {
    let (access, disposition) = match keep {
        Keep::Nothing => (wf::GENERIC_WRITE, wfs::CREATE_ALWAYS),
        // Every write goes at the end, as `O_APPEND`'s do.
        Keep::Everything => (
            wfs::FILE_GENERIC_WRITE & !wfs::FILE_WRITE_DATA,
            wfs::OPEN_ALWAYS,
        ),
        Keep::Absent => (wf::GENERIC_WRITE, wfs::CREATE_NEW),
    };
    let attributes = if mode & 0o200 == 0 {
        wfs::FILE_ATTRIBUTE_READONLY
    } else {
        wfs::FILE_ATTRIBUTE_NORMAL
    };
    let share = wfs::FILE_SHARE_READ | wfs::FILE_SHARE_WRITE;
    Ok(File::from(create(
        path,
        access,
        share,
        disposition,
        attributes,
    )?))
}

/// Cut `file`, opened to write, to `len` bytes, as the C library's
/// `_chsize_s` cuts one opened to append (`"ab"`), which it opens to write
/// anywhere. A file opened here to keep everything may only add to its
/// end, which cannot cut it, so it is cut through a handle of its own
/// opened to write (`ReOpenFile`); the file's own handle goes on writing
/// at its end, now there. Another file is cut through its own handle,
/// which may write anywhere, a read-only one's among them.
#[cfg(windows)]
pub fn truncate(file: &File, len: u64) -> io::Result<()> {
    if file.set_len(len).is_ok() {
        return Ok(());
    }
    // SAFETY: the handle is the open file's, borrowed for the call, which
    // makes a new one or none.
    let writable = unsafe {
        wfs::ReOpenFile(
            file.as_raw_handle(),
            wf::GENERIC_WRITE,
            wfs::FILE_SHARE_READ | wfs::FILE_SHARE_WRITE,
            0,
        )
    };
    if writable == wf::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `writable` was just made and is owned by nothing else.
    let writable =
        File::from(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(writable) });
    writable.set_len(len)
}

/// Close `file` (`CloseHandle`), saying whether that went, which dropping
/// it does not. The handle is let go of either way, and not closed again.
#[cfg(windows)]
pub fn close(file: File) -> io::Result<()> {
    let handle = file.into_raw_handle();
    // SAFETY: `handle` was the file's own, which no one else holds, and is
    // not used again whatever `CloseHandle` says.
    done(unsafe { wf::CloseHandle(handle) })
}

/// Standard input, read through a handle of its own: no buffer stays
/// behind, as `std::io::stdin`'s does until the process ends.
#[cfg(windows)]
pub fn stdin() -> io::Result<File> {
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
    // SAFETY: `GetStdHandle` takes no pointers.
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if input.is_null() || input == wf::INVALID_HANDLE_VALUE {
        return Err(io::Error::from_raw_os_error(
            wf::ERROR_INVALID_HANDLE as i32,
        ));
    }
    Ok(File::from(duplicate(input)?))
}

/// A handle of its own to what `handle` is open on.
#[cfg(windows)]
fn duplicate(handle: wf::HANDLE) -> io::Result<std::os::windows::io::OwnedHandle> {
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let mut copy: wf::HANDLE = std::ptr::null_mut();
    // SAFETY: `GetCurrentProcess` takes nothing, and gives a pseudo handle.
    let me = unsafe { GetCurrentProcess() };
    // SAFETY: both process handles are this process's pseudo handle, and
    // `copy` is where the call writes the new handle, alive through it.
    let ok = unsafe {
        wf::DuplicateHandle(
            me,
            handle,
            me,
            &raw mut copy,
            0,
            0,
            wf::DUPLICATE_SAME_ACCESS,
        )
    };
    done(ok)?;
    // SAFETY: `copy` was just made and is owned by nothing else.
    Ok(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(copy) })
}

/// Make standard error write where `to` writes, as C's tool `freopen`s
/// `stderr`: every later write through the process's standard error
/// handle (`GetStdHandle`, which std's `stderr` writes through) goes to a
/// copy of `to`'s handle, which stays open for the process.
#[cfg(windows)]
pub fn stderr_to(to: &impl AsHandle) -> io::Result<()> {
    use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, SetStdHandle};
    let copy = duplicate(to.as_handle().as_raw_handle())?;
    // SAFETY: `SetStdHandle` takes no pointers to memory; the handle given
    // is open, and is let go of below so that it stays so.
    done(unsafe { SetStdHandle(STD_ERROR_HANDLE, copy.as_raw_handle()) })?;
    let _: wf::HANDLE = copy.into_raw_handle();
    Ok(())
}

/// A directory's entries, as `FindFirstFile` and `FindNextFile` give them
/// (C's `win32_file_list`), in the ANSI code page, in no order.
#[cfg(windows)]
pub struct Dir {
    handle: wf::HANDLE,
    entry: wfs::WIN32_FIND_DATAA,
    /// The entry the find began with, not given yet.
    first: bool,
    done: bool,
}

#[cfg(windows)]
impl Dir {
    /// Open the directory at `path` to list it: `path\*`, as C asks, the
    /// separator left out after one.
    pub fn open(path: &CStr) -> io::Result<Dir> {
        use curl_alloc::TryVec as _;
        let bytes = path.to_bytes();
        let sep = !matches!(bytes.last(), Some(b'\\' | b'/'));
        let mut pattern = Vec::new();
        fn oom<E>(_: E) -> io::Error {
            io::ErrorKind::OutOfMemory.into()
        }
        pattern.try_reserve_exact(bytes.len() + 3).map_err(oom)?;
        pattern.try_extend_from_slice(bytes).map_err(oom)?;
        if sep {
            pattern.try_push(b'\\').map_err(oom)?;
        }
        pattern.try_extend_from_slice(b"*\0").map_err(oom)?;
        // SAFETY: all zeros is a value of the plain record the call fills.
        let mut entry: wfs::WIN32_FIND_DATAA = unsafe { std::mem::zeroed() };
        // SAFETY: `pattern` is a NUL-terminated name and `entry` the record
        // the call writes, both alive through it.
        let handle = unsafe { wfs::FindFirstFileA(pattern.as_ptr(), &raw mut entry) };
        if handle == wf::INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        Ok(Dir {
            handle,
            entry,
            first: true,
            done: false,
        })
    }

    /// The next entry's name, `.` and `..` among them; `None` after the
    /// last. The name is valid until the next call.
    pub fn next_name(&mut self) -> Option<io::Result<&[u8]>> {
        if self.done {
            return None;
        }
        if self.first {
            self.first = false;
        } else {
            // SAFETY: the find is open, and only this `Dir`, which `&mut`
            // makes exclusive, uses it; `entry` is the record it writes.
            if unsafe { wfs::FindNextFileA(self.handle, &raw mut self.entry) } == 0 {
                self.done = true;
                let err = last_error();
                return (err.raw_os_error() != Some(wf::ERROR_NO_MORE_FILES as i32))
                    .then_some(Err(err));
            }
        }
        let name = self.entry_name();
        let n = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        Some(Ok(&name[..n]))
    }

    /// The entry's name as bytes.
    fn entry_name(&self) -> &[u8] {
        // SAFETY: `cFileName` is an array of `i8`, which `u8` has the size
        // and alignment of, borrowed for as long as `self` is.
        unsafe {
            std::slice::from_raw_parts(
                self.entry.cFileName.as_ptr().cast::<u8>(),
                self.entry.cFileName.len(),
            )
        }
    }
}

#[cfg(windows)]
impl core::fmt::Debug for Dir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dir")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: the find is open and closed only here. A failure leaves
        // nothing to do.
        unsafe { wfs::FindClose(self.handle) };
    }
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use std::ffi::CString;
    use std::io::{Read as _, Write as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use super::*;

    /// A directory of its own for a test, removed after it.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir =
                std::env::temp_dir().join(format!("curl-os-fs-{}-{name}", std::process::id()));
            // Left over from a run that did not finish.
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).unwrap();
            Scratch(dir)
        }

        fn c(&self, name: &str) -> CString {
            c(&self.0.join(name))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn c(path: &Path) -> CString {
        CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    /// A file closed says so, and what was written to it stays.
    #[test]
    fn closes_a_file() {
        let s = Scratch::new("close-file");
        let mut f = open_write(&s.c("f"), Keep::Nothing, 0o600).unwrap();
        f.write_all(b"kept").unwrap();
        close(f).unwrap();
        assert_eq!(std::fs::read(s.0.join("f")).unwrap(), b"kept");
    }

    /// Standard error writes to the file it is pointed at, until pointed
    /// back. Another test's writes may land there meanwhile, so only this
    /// one's are looked for.
    #[test]
    fn points_standard_error_at_a_file() {
        let s = Scratch::new("stderr");
        let file = open_write(&s.c("err"), Keep::Nothing, 0o600).unwrap();
        let saved = std::io::stderr().as_fd().try_clone_to_owned().unwrap();
        stderr_to(&file).unwrap();
        let written = std::io::stderr().write_all(b"to the file\n");
        stderr_to(&saved).unwrap();
        written.unwrap();
        let mut read = String::new();
        std::fs::File::open(s.0.join("err"))
            .unwrap()
            .read_to_string(&mut read)
            .unwrap();
        assert!(read.contains("to the file\n"), "{read:?}");
    }

    /// A name is made absolute through its links and dots; a file that is
    /// not there has none.
    #[test]
    #[cfg_attr(miri, ignore = "Miri has no realpath")]
    fn a_real_path_resolves_links_and_dots() {
        let s = Scratch::new("realpath");
        std::fs::write(s.0.join("f"), b"").unwrap();
        std::os::unix::fs::symlink(s.0.join("f"), s.0.join("l")).unwrap();
        let want = std::fs::canonicalize(s.0.join("f")).unwrap();
        let got = real_path(&s.c("./l"), <[u8]>::to_vec).unwrap();
        assert_eq!(got, want.as_os_str().as_bytes());
        std::fs::create_dir(s.0.join("d")).unwrap();
        let got = real_path(&s.c("d/../f"), <[u8]>::to_vec).unwrap();
        assert_eq!(got, want.as_os_str().as_bytes());
        let missing = real_path(&s.c("missing"), <[u8]>::to_vec).unwrap_err();
        assert_eq!(missing.raw_os_error(), Some(libc::ENOENT));
    }

    /// Only `EACCES` is a refusal: `EPERM` is not, though std gives both
    /// the same kind, and neither is an error the system did not report.
    #[test]
    fn denied_is_eacces_alone() {
        assert!(denied(&io::Error::from_raw_os_error(libc::EACCES)));
        assert!(!denied(&io::Error::from_raw_os_error(libc::EPERM)));
        assert!(!denied(&io::Error::other("not the system's")));
    }

    /// Standard input reads through a descriptor of its own.
    #[test]
    fn standard_input_has_a_descriptor_of_its_own() {
        let fd = stdin().unwrap();
        assert!(fd.as_raw_fd() > libc::STDERR_FILENO, "{fd:?}");
    }

    /// The environment variable that tells the test binary it is the child
    /// `descriptors_may_be_missing_or_zero` runs itself in.
    const CHILD: &str = "CURL_OS_FS_DESCRIPTOR_CHILD";

    /// A file opened may be descriptor 0, and standard input closed or a
    /// descriptor limit below standard error's are errors, not crashes.
    /// Run in a child process, as it closes stdin and lowers the limit.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot start a process")]
    fn descriptors_may_be_missing_or_zero() {
        if std::env::var_os(CHILD).is_some() {
            return in_child();
        }
        let name = "fs::tests::descriptors_may_be_missing_or_zero";
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name, "--exact", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stdout}{stderr}");
        assert!(stdout.contains("1 passed"), "the child ran it: {stdout}");
    }

    fn in_child() {
        let s = Scratch::new("descriptors");
        std::fs::write(s.0.join("f"), b"zero").unwrap();
        // SAFETY: nothing in this process reads stdin.
        assert_eq!(unsafe { libc::close(libc::STDIN_FILENO) }, 0);
        let none = stdin().unwrap_err();
        assert_eq!(none.raw_os_error(), Some(libc::EBADF));
        let mut zero = open_read(&s.c("f")).unwrap();
        assert_eq!(zero.as_raw_fd(), 0, "the lowest free descriptor");
        let mut read = String::new();
        zero.read_to_string(&mut read).unwrap();
        assert_eq!(read, "zero");
        // SAFETY: a zeroed `rlimit` is valid, and is filled in by the call.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `limit` is valid to write and lives through the call.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) };
        assert_eq!(rc, 0);
        let saved = limit.rlim_cur;
        // Descriptor 2 is past a limit of 2, so `dup2` cannot make it.
        limit.rlim_cur = 2;
        // SAFETY: `limit` is valid and lives through the call.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) };
        assert_eq!(rc, 0);
        let past = stderr_to(&zero);
        limit.rlim_cur = saved;
        // SAFETY: as above.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) };
        assert_eq!(rc, 0);
        assert_eq!(past.unwrap_err().raw_os_error(), Some(libc::EBADF));
    }

    /// `name`, with `./` repeated before its last part until it is longer
    /// than std's 384-byte buffer on the stack: the same file, by a name
    /// std copies to the heap.
    fn long(name: &Path) -> Vec<u8> {
        let (dir, file) = (name.parent().unwrap(), name.file_name().unwrap());
        let mut long = dir.as_os_str().as_bytes().to_vec();
        long.push(b'/');
        while long.len() < 400 {
            long.extend_from_slice(b"./");
        }
        long.extend_from_slice(file.as_bytes());
        long
    }

    /// A name is taken to its first zero byte, as C sees it, and one the
    /// system would refuse as too long is refused before it is asked.
    #[test]
    fn takes_a_name_as_c_does() {
        let seen = |name: &[u8]| with_c_name(name, |c| Ok(c.to_bytes().to_vec()));
        assert_eq!(seen(b"a/b").unwrap(), b"a/b");
        assert_eq!(seen(b"a\0b").unwrap(), b"a");
        assert_eq!(seen(b"").unwrap(), b"");
        let mut cut = b"a\0".to_vec();
        cut.resize(2 * NAME_MAX_BYTES, b'b');
        assert_eq!(
            seen(&cut).unwrap(),
            b"a",
            "what is past the zero byte is not looked at"
        );
        let longest = vec![b'a'; NAME_MAX_BYTES - 1];
        assert_eq!(seen(&longest).unwrap(), longest);
        let mut called = false;
        let too_long = with_c_name(&[b'a'; NAME_MAX_BYTES], |_| {
            called = true;
            Ok(())
        });
        assert_eq!(
            too_long.unwrap_err().raw_os_error(),
            Some(libc::ENAMETOOLONG)
        );
        assert!(!called);
        // The system says the same of it.
        let mut name = vec![b'a'; NAME_MAX_BYTES];
        name.push(0);
        let c = CStr::from_bytes_with_nul(&name).unwrap();
        assert_eq!(
            stat(c).unwrap_err().raw_os_error(),
            Some(libc::ENAMETOOLONG)
        );
    }

    /// A file's status, by a name std would copy, as std reads it.
    #[test]
    fn states_a_file() {
        use std::os::unix::fs::MetadataExt as _;
        let s = Scratch::new("stat");
        std::fs::write(s.0.join("f"), b"hello").unwrap();
        let f = with_c_name(&long(&s.0.join("f")), stat).unwrap();
        let std = std::fs::metadata(s.0.join("f")).unwrap();
        assert!(f.is_file() && !f.is_dir());
        assert_eq!(f.len(), 5);
        assert!(!f.is_empty());
        assert_eq!(f.modified(), std.mtime());
        std::fs::write(s.0.join("e"), b"").unwrap();
        let e = stat(&s.c("e")).unwrap();
        assert!(e.is_file() && e.is_empty());
        let d = stat(&c(&s.0)).unwrap();
        assert!(d.is_dir() && !d.is_file());
        let missing = stat(&s.c("missing")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    }

    /// Names are made, moved and removed; a directory is made with the
    /// mode asked.
    #[test]
    fn makes_moves_and_removes_names() {
        use std::os::unix::fs::MetadataExt as _;
        let s = Scratch::new("names");
        // A umask takes no permission from the owner, nor from a mode
        // that gives none to anyone else.
        make_dir(&s.c("d"), 0o500).unwrap();
        let mode = std::fs::metadata(s.0.join("d")).unwrap().mode();
        assert_eq!(mode & 0o777, 0o500);
        let again = make_dir(&s.c("d"), 0o700).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
        std::fs::write(s.0.join("a"), b"moved").unwrap();
        std::fs::write(s.0.join("b"), b"replaced").unwrap();
        rename(&s.c("a"), &s.c("b")).unwrap();
        assert_eq!(std::fs::read(s.0.join("b")).unwrap(), b"moved");
        assert!(!s.0.join("a").exists());
        remove(&s.c("b")).unwrap();
        assert!(!s.0.join("b").exists());
        let missing = remove(&s.c("b")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        let missing = rename(&s.c("b"), &s.c("c")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    }

    /// A file's times are set by name, though it may not be read.
    #[test]
    #[cfg_attr(miri, ignore = "Miri has no utimes")]
    fn sets_a_file_s_times() {
        use std::os::unix::fs::MetadataExt as _;
        let s = Scratch::new("times");
        open_write(&s.c("f"), Keep::Nothing, 0o200).unwrap();
        for t in [1_000_000_000, -86_400, 0] {
            set_times(&s.c("f"), t).unwrap();
            let meta = std::fs::metadata(s.0.join("f")).unwrap();
            assert_eq!((meta.mtime(), meta.atime()), (t, t));
        }
        let missing = set_times(&s.c("missing"), 0).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn opens_files_to_read_and_write() {
        let s = Scratch::new("open");
        let missing = open_read(&s.c("missing")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        open_write(&s.c("f"), Keep::Nothing, 0o600)
            .unwrap()
            .write_all(b"hello")
            .unwrap();
        let mode = std::fs::metadata(s.0.join("f"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        open_write(&s.c("f"), Keep::Everything, 0o600)
            .unwrap()
            .write_all(b" world")
            .unwrap();
        let mut read = String::new();
        open_read(&s.c("f"))
            .unwrap()
            .read_to_string(&mut read)
            .unwrap();
        assert_eq!(read, "hello world");
        open_write(&s.c("f"), Keep::Nothing, 0o600)
            .unwrap()
            .write_all(b"new")
            .unwrap();
        assert_eq!(std::fs::read(s.0.join("f")).unwrap(), b"new");
        assert!(open_read(&c(&s.0)).unwrap().metadata().unwrap().is_dir());
        let in_missing = open_write(&s.c("no/f"), Keep::Nothing, 0o600).unwrap_err();
        assert_eq!(in_missing.kind(), io::ErrorKind::NotFound);
    }

    /// A file kept whole and cut takes what is written next where it was
    /// cut, as C's `ftruncate` leaves a file opened to append.
    #[test]
    fn a_file_kept_whole_is_cut_and_written_again() {
        let s = Scratch::new("cut");
        let mut f = open_write(&s.c("f"), Keep::Everything, 0o600).unwrap();
        f.write_all(b"old etag\n").unwrap();
        truncate(&f, 0).unwrap();
        f.write_all(b"new\n").unwrap();
        truncate(&f, 2).unwrap();
        f.write_all(b"xt").unwrap();
        drop(f);
        assert_eq!(std::fs::read(s.0.join("f")).unwrap(), b"next");
    }

    /// The descriptors the process has open on `dir`: none of the other
    /// tests', which open their own, so their comings and goings meanwhile
    /// do not count.
    #[cfg(target_os = "linux")]
    fn open_on(dir: &std::path::Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter(|fd| std::fs::read_link(fd.as_ref().unwrap().path()).is_ok_and(|to| to == dir))
            .count()
    }

    /// As above, on macOS: each descriptor below the limit asked where it
    /// is open (`F_GETPATH`).
    #[cfg(target_vendor = "apple")]
    fn open_on(dir: &std::path::Path) -> usize {
        use std::os::unix::ffi::OsStrExt as _;
        let mut count = 0;
        for fd in 0..4096 {
            let mut path = [0u8; libc::PATH_MAX as usize];
            // SAFETY: `F_GETPATH` writes at most `MAXPATHLEN` bytes, which
            // `path` has room for; a descriptor not open fails the call.
            if unsafe { libc::fcntl(fd, libc::F_GETPATH, path.as_mut_ptr()) } == 0 {
                let len = path.iter().position(|&b| b == 0).unwrap();
                if path[..len] == *dir.as_os_str().as_bytes() {
                    count += 1;
                }
            }
        }
        count
    }

    /// A listing closes its directory when it goes.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's descriptors are not in /proc/self/fd")]
    fn a_listing_closes_its_directory() {
        let s = Scratch::new("close");
        let dir = std::fs::canonicalize(&s.0).unwrap();
        let dirs: Vec<Dir> = (0..32).map(|_| Dir::open(&c(&s.0)).unwrap()).collect();
        assert_eq!(open_on(&dir), 32);
        drop(dirs);
        assert_eq!(open_on(&dir), 0);
    }

    /// A nonblocking file finds nothing in an empty pipe rather than wait
    /// for it, and reads what comes; a copy of it does not wait either.
    #[test]
    fn a_nonblocking_file_does_not_wait() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        let file = File::from(OwnedFd::from(reader));
        let copy = file.try_clone().unwrap();
        set_nonblocking(&file).unwrap();
        let mut buf = [0; 4];
        let nothing = (&copy).read(&mut buf).unwrap_err();
        assert_eq!(nothing.kind(), io::ErrorKind::WouldBlock);
        writer.write_all(b"ab").unwrap();
        assert_eq!((&file).read(&mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"ab");
    }

    #[test]
    fn lists_a_directory() {
        let s = Scratch::new("list");
        std::fs::write(s.0.join("a"), b"").unwrap();
        std::fs::create_dir(s.0.join("b")).unwrap();
        let mut dir = Dir::open(&c(&s.0)).unwrap();
        let mut names = Vec::new();
        while let Some(name) = dir.next_name() {
            names.push(String::from_utf8(name.unwrap().to_vec()).unwrap());
        }
        names.sort();
        assert_eq!(names, [".", "..", "a", "b"]);
        assert!(dir.next_name().is_none(), "still at the end");
        let missing = Dir::open(&s.c("missing")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        let not_dir = Dir::open(&s.c("a")).unwrap_err();
        assert_eq!(not_dir.raw_os_error(), Some(libc::ENOTDIR));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use std::ffi::CString;
    use std::io::{Read as _, Write as _};
    use std::path::{Path, PathBuf};

    use super::*;

    /// A directory of its own for a test, removed after it.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir =
                std::env::temp_dir().join(format!("curl-os-fs-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).unwrap();
            Scratch(dir)
        }

        fn c(&self, name: &str) -> CString {
            c(&self.0.join(name))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn c(path: &Path) -> CString {
        CString::new(path.to_str().unwrap()).unwrap()
    }

    /// A file kept whole and cut takes what is written next where it was
    /// cut, as C's `ftruncate` leaves a file opened to append.
    #[test]
    fn a_file_kept_whole_is_cut_and_written_again() {
        let s = Scratch::new("cut");
        let mut f = open_write(&s.c("f"), Keep::Everything, 0o600).unwrap();
        f.write_all(b"old etag\n").unwrap();
        truncate(&f, 0).unwrap();
        f.write_all(b"new\n").unwrap();
        truncate(&f, 2).unwrap();
        f.write_all(b"xt").unwrap();
        drop(f);
        assert_eq!(std::fs::read(s.0.join("f")).unwrap(), b"next");
    }

    #[test]
    fn opens_files_to_read_and_write() {
        let s = Scratch::new("open");
        let missing = open_read(&s.c("missing")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        open_write(&s.c("f"), Keep::Nothing, 0o600)
            .unwrap()
            .write_all(b"hello")
            .unwrap();
        open_write(&s.c("f"), Keep::Everything, 0o600)
            .unwrap()
            .write_all(b" world")
            .unwrap();
        let mut read = String::new();
        open_read(&s.c("f"))
            .unwrap()
            .read_to_string(&mut read)
            .unwrap();
        assert_eq!(read, "hello world");
        open_write(&s.c("f"), Keep::Nothing, 0o600)
            .unwrap()
            .write_all(b"new")
            .unwrap();
        assert_eq!(std::fs::read(s.0.join("f")).unwrap(), b"new");
        let there = open_write(&s.c("f"), Keep::Absent, 0o600).unwrap_err();
        assert_eq!(there.kind(), io::ErrorKind::AlreadyExists);
        // A directory does not open, as in the C library.
        let dir = open_read(&c(&s.0)).unwrap_err();
        assert!(denied(&dir), "{dir}");
        let in_missing = open_write(&s.c("no/f"), Keep::Nothing, 0o600).unwrap_err();
        assert_eq!(in_missing.kind(), io::ErrorKind::NotFound);
        // No write permission for its owner: made read-only.
        open_write(&s.c("ro"), Keep::Nothing, 0o400).unwrap();
        assert!(
            std::fs::metadata(s.0.join("ro"))
                .unwrap()
                .permissions()
                .readonly()
        );
        assert!(
            !std::fs::metadata(s.0.join("f"))
                .unwrap()
                .permissions()
                .readonly()
        );
        let mut p = std::fs::metadata(s.0.join("ro")).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false, reason = "Windows only")]
        p.set_readonly(false);
        std::fs::set_permissions(s.0.join("ro"), p).unwrap();
    }

    #[test]
    fn closes_a_file() {
        let s = Scratch::new("close-file");
        let mut f = open_write(&s.c("f"), Keep::Nothing, 0o600).unwrap();
        f.write_all(b"kept").unwrap();
        close(f).unwrap();
        assert_eq!(std::fs::read(s.0.join("f")).unwrap(), b"kept");
    }

    /// A file's status, as std reads it; a directory's length is 0.
    #[test]
    fn states_a_file() {
        let s = Scratch::new("stat");
        std::fs::write(s.0.join("f"), b"hello").unwrap();
        let f = stat(&s.c("f")).unwrap();
        assert!(f.is_file() && !f.is_dir());
        assert_eq!(f.len(), 5);
        let modified = std::fs::metadata(s.0.join("f"))
            .unwrap()
            .modified()
            .unwrap();
        let secs = modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(f.modified(), i64::try_from(secs).unwrap());
        let d = stat(&c(&s.0)).unwrap();
        assert!(d.is_dir() && !d.is_file() && d.is_empty());
        let missing = stat(&s.c("missing")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        let nul = stat(c"NUL").unwrap();
        assert!(!nul.is_file() && !nul.is_dir(), "a device");
    }

    /// A name longer than `MAX_PATH` is marked long, as C marks it, and
    /// opens; one longer than the system takes is refused first.
    #[test]
    fn a_long_name_opens() {
        let s = Scratch::new("long");
        let mut dir = s.0.clone();
        while dir.as_os_str().len() < 300 {
            dir.push("abcdefghijklmnopqrstuvwxyz");
        }
        let long = dir.join("f");
        let name = c(&long);
        // std makes a long name long itself.
        std::fs::create_dir_all(&dir).unwrap();
        open_write(&name, Keep::Nothing, 0o600)
            .unwrap()
            .write_all(b"far")
            .unwrap();
        assert_eq!(stat(&name).unwrap().len(), 3);
        assert_eq!(std::fs::read(&long).unwrap(), b"far");
        let wide = wide_name(&name).unwrap();
        assert_eq!(&wide[..4], [92, 92, 63, 92], r"\\?\");
        remove(&name).unwrap();
        let too_long = with_c_name(&[b'a'; NAME_MAX_BYTES], |_| Ok(()));
        assert_eq!(
            too_long.unwrap_err().raw_os_error(),
            Some(wf::ERROR_FILENAME_EXCED_RANGE as i32)
        );
    }

    /// Names are made, moved over another and removed.
    #[test]
    fn makes_moves_and_removes_names() {
        let s = Scratch::new("names");
        make_dir(&s.c("d"), 0o700).unwrap();
        assert!(s.0.join("d").is_dir());
        let again = make_dir(&s.c("d"), 0o700).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
        std::fs::write(s.0.join("a"), b"moved").unwrap();
        std::fs::write(s.0.join("b"), b"replaced").unwrap();
        rename(&s.c("a"), &s.c("b")).unwrap();
        assert_eq!(std::fs::read(s.0.join("b")).unwrap(), b"moved");
        assert!(!s.0.join("a").exists());
        remove(&s.c("b")).unwrap();
        assert_eq!(
            remove(&s.c("b")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let start = std::time::Instant::now();
        let missing = rename(&s.c("b"), &s.c("c")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        assert!(
            start.elapsed() >= std::time::Duration::from_secs(1),
            "tried for a second"
        );
    }

    #[test]
    fn sets_a_file_s_times() {
        let s = Scratch::new("times");
        open_write(&s.c("f"), Keep::Nothing, 0o600).unwrap();
        for t in [1_000_000_000, 0, -86_400] {
            set_times(&s.c("f"), t).unwrap();
            assert_eq!(stat(&s.c("f")).unwrap().modified(), t);
        }
        let missing = set_times(&s.c("missing"), 0).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        let past = set_times(&s.c("f"), i64::MIN).unwrap_err();
        assert_eq!(past.kind(), io::ErrorKind::InvalidInput);
    }

    /// `_fullpath`'s: absolute, its dots resolved, whether or not the file
    /// is there.
    #[test]
    fn a_real_path_is_absolute() {
        let s = Scratch::new("realpath");
        std::fs::create_dir(s.0.join("d")).unwrap();
        let want = s.0.join("f");
        let got = real_path(&s.c(r"d\..\f"), <[u8]>::to_vec).unwrap();
        assert_eq!(got, want.to_str().unwrap().as_bytes());
        let missing = real_path(&s.c("missing"), <[u8]>::to_vec).unwrap();
        assert_eq!(missing, s.0.join("missing").to_str().unwrap().as_bytes());
    }

    #[test]
    fn lists_a_directory() {
        let s = Scratch::new("list");
        std::fs::write(s.0.join("a"), b"").unwrap();
        std::fs::create_dir(s.0.join("b")).unwrap();
        for path in [
            c(&s.0),
            CString::new(format!("{}\\", s.0.display())).unwrap(),
        ] {
            let mut dir = Dir::open(&path).unwrap();
            let mut names = Vec::new();
            while let Some(name) = dir.next_name() {
                names.push(String::from_utf8(name.unwrap().to_vec()).unwrap());
            }
            names.sort();
            assert_eq!(names, [".", "..", "a", "b"]);
            assert!(dir.next_name().is_none(), "still at the end");
        }
        let missing = Dir::open(&s.c("missing")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        assert!(Dir::open(&s.c("a")).is_err(), "a file lists nothing");
    }

    /// Standard error writes to the file it is pointed at, until pointed
    /// back.
    #[test]
    fn points_standard_error_at_a_file() {
        let s = Scratch::new("stderr");
        let file = open_write(&s.c("err"), Keep::Nothing, 0o600).unwrap();
        let saved = std::io::stderr().as_handle().try_clone_to_owned().unwrap();
        stderr_to(&file).unwrap();
        let written = std::io::stderr().write_all(b"to the file\n");
        stderr_to(&saved).unwrap();
        written.unwrap();
        drop(file);
        let read = std::fs::read_to_string(s.0.join("err")).unwrap();
        assert!(read.contains("to the file\n"), "{read:?}");
    }

    #[test]
    fn standard_input_has_a_handle_of_its_own() {
        use std::os::windows::io::AsRawHandle as _;
        let own = stdin().unwrap();
        assert_ne!(own.as_raw_handle(), std::io::stdin().as_raw_handle());
    }

    /// The C library starts each standard stream as text, and keeps one
    /// made binary so, telling its mode without changing it. Only standard
    /// input is changed here: the harness writes to the others.
    #[test]
    fn a_standard_stream_is_text_until_made_binary() {
        assert_eq!(mode(Std::Err), crate::text::Mode::Text);
        assert_eq!(mode(Std::Err), crate::text::Mode::Text);
        assert_eq!(mode(Std::In), crate::text::Mode::Text);
        set_binary(Std::In);
        assert_eq!(mode(Std::In), crate::text::Mode::Binary);
        assert_eq!(mode(Std::Err), crate::text::Mode::Text);
    }

    /// Text goes to a file with each line feed after a carriage return,
    /// and to a console in the ANSI code page, as the UCRT writes it;
    /// binary goes to either as it is, which a console reads in its own
    /// code page.
    #[test]
    fn writes_as_the_c_library_does_in_each_mode() {
        use crate::text::Mode;
        let s = Scratch::new("as-c");
        let file = open_write(&s.c("f"), Keep::Nothing, 0o600).unwrap();
        write_all_as_c(&file, Mode::Text, b"a\nb\r\n").unwrap();
        write_all_as_c(&file, Mode::Binary, b"c\n").unwrap();
        drop(file);
        assert_eq!(std::fs::read(s.0.join("f")).unwrap(), b"a\r\nb\r\r\nc\n");
        let long = [b'\n'; 1000];
        let file = open_write(&s.c("g"), Keep::Nothing, 0o600).unwrap();
        write_all_as_c(&file, Mode::Text, &long).unwrap();
        drop(file);
        assert_eq!(std::fs::read(s.0.join("g")).unwrap(), b"\r\n".repeat(1000));
        let screen = crate::terminal::ScreenBuffer::new().unwrap();
        let console = File::from(screen.handle().try_clone_to_owned().unwrap());
        // `é` in the ANSI code page, and the console's own reading of it.
        let ansi = &[b'c', 0xe9];
        write_all_as_c(&console, Mode::Text, ansi).unwrap();
        write_all_as_c(&console, Mode::Binary, ansi).unwrap();
        let mut wide = [0u16; 2];
        let n = crate::terminal::ansi_to_wide(ansi, &mut wide);
        let mut want: Vec<u16> = wide[..n].to_vec();
        want.push(u16::from(b'c'));
        let got = screen.read(4).unwrap();
        assert_eq!(&got[..3], &want[..], "{got:x?}");
        assert_ne!(
            got[3], want[1],
            "the console's code page is not the ANSI one"
        );
    }
}
