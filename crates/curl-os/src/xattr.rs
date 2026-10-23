//! A file's extended attributes (`fsetxattr(2)`), which `--xattr` stores
//! where a download came from in.

#![allow(unsafe_code)]

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};

/// Set the extended attribute `name` of the open file `fd` to `value`,
/// replacing it if it is there.
pub fn set(fd: BorrowedFd<'_>, name: &CStr, value: &[u8]) -> io::Result<()> {
    // SAFETY: the descriptor is open for the borrow; `name` is a
    // NUL-terminated string and `value` points to `value.len()` readable
    // bytes, both outliving the call, which only reads them.
    let rc = unsafe {
        libc::fsetxattr(
            fd.as_raw_fd(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use super::*;
    use std::os::fd::AsFd as _;

    /// The value of attribute `name` of `fd`, read back.
    fn get(fd: BorrowedFd<'_>, name: &CStr) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 256];
        // SAFETY: the descriptor is open for the borrow, `name` is a
        // NUL-terminated string, and `buf` has `buf.len()` writable bytes
        // the call writes at most.
        let n = unsafe {
            libc::fgetxattr(
                fd.as_raw_fd(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(usize::try_from(n).unwrap());
        Ok(buf)
    }

    /// An attribute set is there to read, replaced when set again; one in
    /// no namespace the file system knows is refused with the reason.
    #[test]
    fn sets_an_attribute() {
        let dir = std::env::temp_dir().join(format!("curl-os-xattr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file");
        let file = std::fs::File::create(&path).unwrap();
        let name = c"user.xdg.origin.url";
        match set(file.as_fd(), name, b"http://example.com/") {
            // A file system without user attributes (tmpfs before 6.6).
            Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {}
            other => {
                other.unwrap();
                assert_eq!(get(file.as_fd(), name).unwrap(), b"http://example.com/");
                set(file.as_fd(), name, b"x").unwrap();
                assert_eq!(get(file.as_fd(), name).unwrap(), b"x");
            }
        }
        let refused = set(file.as_fd(), c"nonamespace", b"x").unwrap_err();
        assert!(refused.raw_os_error().is_some(), "{refused}");
        drop(file);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
