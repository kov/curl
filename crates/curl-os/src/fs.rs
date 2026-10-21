//! Files and directories, for `file:` URLs (`lib/file.c`). Opening a file
//! and listing a directory are system calls of their own, so neither the
//! path nor an entry's name is ever copied; reading, writing, seeking and
//! the file's status go through the std `File` that opening gives.

#![allow(unsafe_code)]

use core::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::ptr::NonNull;

/// What opening for writing does to what the file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    /// Nothing: it is emptied.
    Nothing,
    /// Everything: writes go after it.
    Everything,
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
        // SAFETY: a non-null entry is valid until the stream is read again
        // or closed, which the borrow of `self` prevents.
        let name = unsafe { &(*entry).d_name };
        // SAFETY: `d_name` holds the entry's name, ended by a NUL.
        let name = unsafe { CStr::from_ptr(name.as_ptr()) };
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
    fn a_listing_closes_its_directory() {
        let s = Scratch::new("close");
        let dir = std::fs::canonicalize(&s.0).unwrap();
        let dirs: Vec<Dir> = (0..32).map(|_| Dir::open(&c(&s.0)).unwrap()).collect();
        assert_eq!(open_on(&dir), 32);
        drop(dirs);
        assert_eq!(open_on(&dir), 0);
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
