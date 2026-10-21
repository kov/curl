//! Files the library writes whole, in place of what they held
//! (`Curl_fopen`): written under a name of their own beside the file and
//! renamed over it once complete, so that a reader never sees half of
//! one. A file that is not a regular one is written in place.

use std::ffi::CStr;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_os::fs::{self, Keep};

/// Why a file could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SaveError {
    OutOfMemory,
    /// It could not be opened, written or renamed (`CURLE_WRITE_ERROR`).
    Write,
}

impl From<OutOfMemory> for SaveError {
    fn from(_: OutOfMemory) -> Self {
        SaveError::OutOfMemory
    }
}

impl From<io::Error> for SaveError {
    fn from(_: io::Error) -> Self {
        SaveError::Write
    }
}

/// How many random letters and digits name the file written first.
const TEMP_NAME: usize = 40;

/// Write `text` to the file at `path`, in place of what it held.
pub(crate) fn replace(path: &[u8], text: &[u8]) -> Result<(), SaveError> {
    let target = c_path(path)?;
    // Opened as C's `fopen(.., "w")` opens it: emptied, made if missing.
    let mut file = fs::open_write(&target, Keep::Nothing, 0o666)?;
    let was = file.metadata()?;
    if !was.is_file() {
        file.write_all(text)?;
        return Ok(());
    }
    drop(file);
    let mut temp = Vec::new();
    temp.try_extend_from_slice(dir_of(path))?;
    let mut random = [0u8; TEMP_NAME];
    alphanumeric(&mut random)?;
    temp.try_extend_from_slice(&random)?;
    temp.try_extend_from_slice(b".tmp")?;
    let temp = c_path(&temp)?;
    let written = write_temp(&temp, &was, text);
    let renamed = written.and_then(|()| Ok(std::fs::rename(as_path(&temp), as_path(&target))?));
    if renamed.is_err() {
        let _ = std::fs::remove_file(as_path(&temp));
    }
    renamed
}

/// Write `text` to a new file at `temp`, with the mode of the file it is
/// to replace if the same user and group own them.
fn write_temp(temp: &CStr, was: &std::fs::Metadata, text: &[u8]) -> Result<(), SaveError> {
    let mut file = fs::open_write(temp, Keep::Absent, 0o600)?;
    let new = file.metadata()?;
    if new.uid() == was.uid() && new.gid() == was.gid() {
        file.set_permissions(std::fs::Permissions::from_mode(was.mode()))?;
    }
    file.write_all(text)?;
    Ok(())
}

/// The directory part of `path` with one slash after it, or nothing if
/// it names none (`dirslash`). A file directly under `/` has none.
fn dir_of(path: &[u8]) -> &[u8] {
    let mut n = path.len();
    while n > 0 && path[n - 1] != b'/' {
        n -= 1;
    }
    while n > 0 && path[n - 1] == b'/' {
        n -= 1;
    }
    if n == 0 { b"" } else { &path[..=n] }
}

/// Random letters and digits (`Curl_rand_alnum`).
fn alphanumeric(out: &mut [u8]) -> Result<(), SaveError> {
    const ALNUM: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut bytes = [0u8; TEMP_NAME];
    let bytes = &mut bytes[..out.len()];
    curl_os::random::fill(bytes)?;
    for (o, b) in out.iter_mut().zip(bytes.iter()) {
        // A slight bias to the first letters does not matter for a name.
        *o = ALNUM[usize::from(*b) % ALNUM.len()];
    }
    Ok(())
}

fn c_path(path: &[u8]) -> Result<std::ffi::CString, SaveError> {
    let mut v = Vec::new();
    v.try_reserve_exact(path.len() + 1)
        .map_err(|_| SaveError::OutOfMemory)?;
    v.try_extend_from_slice(path)?;
    // A name with a zero byte in it names no file.
    std::ffi::CString::new(v).map_err(|_| SaveError::Write)
}

fn as_path(c: &CStr) -> &std::path::Path {
    use std::os::unix::ffi::OsStrExt as _;
    std::path::Path::new(std::ffi::OsStr::from_bytes(c.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_directory_as_c() {
        assert_eq!(dir_of(b"/a/b/file"), b"/a/b/");
        assert_eq!(dir_of(b"a//b"), b"a/");
        assert_eq!(dir_of(b"file"), b"");
        assert_eq!(dir_of(b"/file"), b"");
    }

    #[test]
    fn replaces_a_file_and_keeps_its_mode() {
        let dir = std::env::temp_dir().join(format!("curl-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("jar");
        std::fs::write(&path, b"old and longer").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let bytes = path.as_os_str().as_encoded_bytes();
        replace(bytes, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o640);
        // Nothing is left beside it.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
