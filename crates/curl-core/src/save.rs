//! Files the library writes whole, in place of what they held
//! (`Curl_fopen`): written under a name of their own beside the file and
//! renamed over it once complete, so that a reader never sees half of
//! one. A file that is not a regular one is written in place.

use std::ffi::CStr;
use std::io::{self, Write as _};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_os::fs::{self, Keep};
use curl_os::text::{Mode, Writer};

/// Why a file could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveError {
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

/// Whether a cache (HSTS, alt-svc) is written back to its file as the
/// handle goes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CacheFile {
    /// Written back.
    #[default]
    ReadWrite,
    /// Read, never written (`CURLHSTS_READONLYFILE`, `CURLALTSVC_READONLYFILE`).
    ReadOnly,
}

/// How many random letters and digits name the file written first.
const TEMP_NAME: usize = 40;

/// Write `text` to the file at `path`, in place of what it held. On
/// Windows C looks at no file there first: it always writes a new one
/// and renames it over, in text mode.
pub(crate) fn replace(path: &[u8], text: &[u8]) -> Result<(), SaveError> {
    let target = c_path(path)?;
    // Opened as C's `fopen(.., "w")` opens it: emptied, made if missing.
    #[cfg(unix)]
    let was = {
        let file = fs::open_write(&target, Keep::Nothing, 0o666)?;
        let was = file.metadata()?;
        if !was.is_file() {
            Writer::new(file, Mode::TEXT).write_all(text)?;
            return Ok(());
        }
        was
    };
    let dir = dir_of(path);
    let mut temp = Vec::new();
    // One allocation, whatever the name's length.
    temp.try_reserve_exact(dir.len() + 1 + TEMP_NAME + b".tmp".len())
        .map_err(|_| SaveError::OutOfMemory)?;
    temp.try_extend_from_slice(dir)?;
    if !dir.is_empty() {
        temp.try_push(PATHSEP)?;
    }
    let mut random = [0u8; TEMP_NAME];
    alphanumeric(&mut random)?;
    temp.try_extend_from_slice(&random)?;
    temp.try_extend_from_slice(b".tmp")?;
    let temp = c_path(&temp)?;
    #[cfg(unix)]
    let written = write_temp(&temp, &was, text);
    #[cfg(windows)]
    let written = write_temp(&temp, text);
    let renamed = written.and_then(|()| Ok(fs::rename(&temp, &target)?));
    if renamed.is_err() {
        let _ = fs::remove(&temp);
    }
    renamed
}

/// Write `text` to a new file at `temp`, with the mode of the file it is
/// to replace if the same user and group own them.
#[cfg(unix)]
fn write_temp(temp: &CStr, was: &std::fs::Metadata, text: &[u8]) -> Result<(), SaveError> {
    let file = fs::open_write(temp, Keep::Absent, 0o600)?;
    let new = file.metadata()?;
    if new.uid() == was.uid() && new.gid() == was.gid() {
        file.set_permissions(std::fs::Permissions::from_mode(was.mode()))?;
    }
    // As text (`FOPEN_WRITETEXT`), which is binary here.
    Writer::new(file, Mode::TEXT).write_all(text)?;
    Ok(())
}

/// Write `text` to a new file at `temp`, readable and writable, in text
/// mode as C's `fdopen(.., "wt")` writes it: each line feed after a
/// carriage return. Windows has no mode to copy (`HAVE_FCHMOD`).
#[cfg(windows)]
fn write_temp(temp: &CStr, text: &[u8]) -> Result<(), SaveError> {
    let file = fs::open_write(temp, Keep::Absent, 0o600)?;
    Writer::new(file, Mode::TEXT).write_all(text)?;
    Ok(())
}

/// What C puts after the directory a temporary file is made in
/// (`PATHSEP`).
#[cfg(unix)]
const PATHSEP: u8 = b'/';
#[cfg(windows)]
const PATHSEP: u8 = b'\\';

/// Whether `b` separates a name's parts (`IS_SEP`): Windows takes both
/// slashes.
fn is_sep(b: u8) -> bool {
    b == b'/' || (cfg!(windows) && b == b'\\')
}

/// The directory part of `path`, without the separators after it, or
/// nothing if it names none (`dirslash`, which then adds one `PATHSEP`).
/// A file directly under `/` has none.
fn dir_of(path: &[u8]) -> &[u8] {
    let mut n = path.len();
    while n > 0 && !is_sep(path[n - 1]) {
        n -= 1;
    }
    while n > 0 && is_sep(path[n - 1]) {
        n -= 1;
    }
    &path[..n]
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
    // A name with a zero byte in it names no file. The vector has room
    // for the zero byte `new` adds, so it does not grow.
    #[allow(clippy::disallowed_methods)]
    std::ffi::CString::new(v).map_err(|_| SaveError::Write)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_directory_as_c() {
        assert_eq!(dir_of(b"/a/b/file"), b"/a/b");
        assert_eq!(dir_of(b"a//b"), b"a");
        assert_eq!(dir_of(b"file"), b"");
        assert_eq!(dir_of(b"/file"), b"");
        // A backslash separates only on Windows.
        let windows = cfg!(windows);
        assert_eq!(
            dir_of(br"c:\a\\b"),
            if windows { &br"c:\a"[..] } else { b"" }
        );
        assert_eq!(dir_of(br"c:\a/b"), br"c:\a");
    }

    /// On Windows the file is replaced whatever it was, and written as
    /// text, as C's `"wt"` writes it.
    #[cfg(windows)]
    #[test]
    fn a_file_is_replaced_in_text_mode() {
        let dir = scratch("text");
        let path = dir.join("jar");
        std::fs::write(&path, b"old and longer").unwrap();
        replace(path.as_os_str().as_encoded_bytes(), b"a\nb\n\nc").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"a\r\nb\r\n\r\nc");
        // Nothing is left beside it.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(replace(b"", b"new"), Err(SaveError::Write));
    }

    #[cfg(unix)]
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

    /// A fresh directory for one test.
    fn scratch(test: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("curl-save-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn a_regular_file_is_replaced_and_any_other_written_in_place() {
        let dir = scratch("rename");
        let path = dir.join("jar");
        std::fs::write(&path, b"old").unwrap();
        let before = std::fs::metadata(&path).unwrap().ino();
        replace(path.as_os_str().as_encoded_bytes(), b"new").unwrap();
        assert_ne!(std::fs::metadata(&path).unwrap().ino(), before);
        std::fs::remove_dir_all(&dir).unwrap();
        // No file could be made beside `/dev/null`.
        assert_eq!(replace(b"/dev/null", b"new"), Ok(()));
        assert_eq!(replace(b"", b"new"), Err(SaveError::Write));
    }

    // The user's groups from `/proc`, which only Linux has.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_mode_is_kept_only_where_the_group_is_the_same() {
        // A group of the user's other than the one new files get.
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let field = |name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .unwrap()
                .split_whitespace()
                .map(|g| g.parse::<u32>().unwrap())
                .collect::<Vec<_>>()
        };
        let egid = field("Gid:")[1];
        let Some(other) = field("Groups:").into_iter().find(|&g| g != egid) else {
            eprintln!("not run: the user is in no group but {egid}");
            return;
        };
        let dir = scratch("group");
        let path = dir.join("jar");
        std::fs::write(&path, b"old").unwrap();
        std::os::unix::fs::chown(&path, None, Some(other)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        replace(path.as_os_str().as_encoded_bytes(), b"new").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!((meta.gid(), meta.mode() & 0o777), (egid, 0o600));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_temporary_name_takes_every_letter_and_digit() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let mut name = [0u8; TEMP_NAME];
            alphanumeric(&mut name).unwrap();
            assert!(name.iter().all(u8::is_ascii_alphanumeric));
            seen.extend(name);
        }
        // 4000 draws miss one of 62 about once in 10^25 runs.
        assert_eq!(seen.len(), 62);
    }
}
