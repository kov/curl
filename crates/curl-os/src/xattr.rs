//! A file's extended attributes (`fsetxattr(2)`), which `--xattr` stores
//! where a download came from in. Windows has none: C's tool writes an
//! alternate data stream of the file instead (`Zone.Identifier`), by the
//! file's name, which [`set_stream`] writes.

#![allow(unsafe_code)]

use std::ffi::CStr;
use std::io;
#[cfg(unix)]
use std::os::fd::{AsRawFd as _, BorrowedFd};

/// Write `text` as the alternate data stream `stream` of the file at
/// `path`, in place of what it held, as C's `fwrite_xattr` writes it on
/// Windows: the name made absolute first (`_fullpath`), so that a name
/// such as `X:stream` is not taken for a drive, then `path:stream`
/// opened as text, each line feed written as a carriage return and a
/// line feed, as `FOPEN_WRITETEXT` writes it.
#[cfg(windows)]
pub fn set_stream(path: &CStr, stream: &CStr, text: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    use curl_alloc::TryVec as _;

    fn oom<E>(_: E) -> io::Error {
        io::ErrorKind::OutOfMemory.into()
    }
    let mut name = Vec::new();
    crate::fs::real_path(path, |abs| {
        name.try_reserve_exact(abs.len() + 1 + stream.to_bytes().len() + 1)
            .map_err(oom)?;
        name.try_extend_from_slice(abs).map_err(oom)?;
        name.try_push(b':').map_err(oom)?;
        name.try_extend_from_slice(stream.to_bytes()).map_err(oom)?;
        name.try_push(0).map_err(oom)
    })??;
    let name = CStr::from_bytes_with_nul(&name).expect("one zero byte, at the end");
    let mut file = crate::fs::open_write(name, crate::fs::Keep::Nothing, 0o600)?;
    for (i, line) in text.split(|&b| b == b'\n').enumerate() {
        if i > 0 {
            file.write_all(b"\r\n")?;
        }
        file.write_all(line)?;
    }
    crate::fs::close(file)
}

/// Set the extended attribute `name` of the open file `fd` to `value`,
/// replacing it if it is there.
#[cfg(unix)]
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

#[cfg(all(test, windows))]
mod windows_tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use super::*;

    /// The stream is written whole, its line feeds as C's text mode writes
    /// them, in place of what it held; the file itself is left as it was.
    #[test]
    fn writes_a_stream_of_the_file() {
        let dir = std::env::temp_dir().join(format!("curl-os-ads-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file");
        std::fs::write(&path, b"body").unwrap();
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        set_stream(&c, c"Zone.Identifier", b"[ZoneTransfer]\nZoneId=3\n").unwrap();
        let stream = format!("{}:Zone.Identifier", path.display());
        assert_eq!(
            std::fs::read(&stream).unwrap(),
            b"[ZoneTransfer]\r\nZoneId=3\r\n"
        );
        set_stream(&c, c"Zone.Identifier", b"x").unwrap();
        assert_eq!(std::fs::read(&stream).unwrap(), b"x");
        assert_eq!(std::fs::read(&path).unwrap(), b"body");
        let missing = std::ffi::CString::new(dir.join("no/such").to_str().unwrap()).unwrap();
        assert!(set_stream(&missing, c"Zone.Identifier", b"x").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(all(test, unix))]
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
