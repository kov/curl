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

#![allow(unsafe_code)]

use core::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
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

/// Whether `e` is a refusal to look in or change a directory (`EACCES`),
/// as distinct from an operation not permitted (`EPERM`), which std
/// reports with the same kind.
pub fn denied(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EACCES)
}

/// The longest name the system takes, its ending zero byte included
/// (`PATH_MAX`).
const NAME_MAX_BYTES: usize = libc::PATH_MAX as usize;

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

/// What `stat(2)` says of a file, as much as is asked of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    mode: libc::mode_t,
    len: u64,
    modified: i64,
}

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

/// Remove the name `path` (`unlink(2)`).
pub fn remove(path: &CStr) -> io::Result<()> {
    // SAFETY: `path` is a C string, alive for the call.
    if unsafe { libc::unlink(path.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Give the file `from` the name `to`, in place of any file that had it
/// (`rename(2)`).
pub fn rename(from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: both are C strings, alive for the call.
    if unsafe { libc::rename(from.as_ptr(), to.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Make the directory `path`, with permissions `mode` before the umask
/// (`mkdir(2)`).
pub fn make_dir(path: &CStr, mode: u32) -> io::Result<()> {
    // SAFETY: `path` is a C string, alive for the call.
    if unsafe { libc::mkdir(path.as_ptr(), mode) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

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

/// Open `path` to read it. A directory opens too.
pub fn open_read(path: &CStr) -> io::Result<File> {
    open(path, libc::O_RDONLY, 0)
}

/// Open `path` to write it, creating it with permissions `mode` (before
/// the umask) if it does not exist.
pub fn open_write(path: &CStr, keep: Keep, mode: u32) -> io::Result<File> {
    let keep = match keep {
        Keep::Nothing => libc::O_TRUNC,
        Keep::Everything => libc::O_APPEND,
        Keep::Absent => libc::O_EXCL,
    };
    open(path, libc::O_WRONLY | libc::O_CREAT | keep, mode)
}

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

/// A directory's entries, as `readdir` gives them, in no order.
#[derive(Debug)]
pub struct Dir {
    stream: NonNull<libc::DIR>,
}

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
        // SAFETY: `__errno_location` has no preconditions.
        let errno = unsafe { libc::__errno_location() };
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

impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: the stream is open and closed only here. A failure
        // leaves nothing to do.
        unsafe { libc::closedir(self.stream.as_ptr()) };
    }
}

#[cfg(test)]
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

    /// The descriptors the process has open on `dir`: none of the other
    /// tests', which open their own, so their comings and goings meanwhile
    /// do not count.
    fn open_on(dir: &std::path::Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter(|fd| std::fs::read_link(fd.as_ref().unwrap().path()).is_ok_and(|to| to == dir))
            .count()
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
