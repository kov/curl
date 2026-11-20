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

/// What a file's failed close does to its save: a write the kernel held
/// may fail only then.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OnClose {
    /// The save fails, and the target keeps what it held (the cookie jar,
    /// `cookie_output`).
    Fails,
    /// The save goes on as if it had closed (HSTS and alt-svc, whose
    /// `fclose` C does not check).
    Ignored,
}

impl OnClose {
    fn close(self, file: std::fs::File) -> Result<(), SaveError> {
        match (self, fs::close(file)) {
            (OnClose::Fails, Err(_)) => Err(SaveError::Write),
            _ => Ok(()),
        }
    }
}

/// How many random letters and digits name the file written first.
const TEMP_NAME: usize = 40;

/// Write `text` to the file at `path`, in place of what it held. On
/// Windows C looks at no file there first: it always writes a new one
/// and renames it over, in text mode.
pub(crate) fn replace(path: &[u8], text: &[u8], on_close: OnClose) -> Result<(), SaveError> {
    let target = c_path(path)?;
    // Opened as C's `fopen(.., "a")` opens it: made if missing, what it
    // holds kept until the new file replaces it; a file that is not a
    // regular one is written after what it holds.
    #[cfg(unix)]
    let was = {
        let file = fs::open_write(&target, Keep::Everything, 0o666)?;
        let was = file.metadata()?;
        if !was.is_file() {
            let mut out = Writer::new(file, Mode::TEXT);
            out.write_all(text)?;
            return on_close.close(out.into_inner());
        }
        was
    };
    let temp = temp_beside(path)?;
    #[cfg(unix)]
    let written = write_temp(&temp, &was, text, on_close);
    #[cfg(windows)]
    let written = write_temp(&temp, text, on_close);
    let renamed = written.and_then(|()| Ok(fs::rename(&temp, &target)?));
    if renamed.is_err() {
        let _ = fs::remove(&temp);
    }
    renamed
}

/// A random name for the file written first, in the directory of `path`,
/// the root's for a file directly under it (`dirslash`).
fn temp_beside(path: &[u8]) -> Result<std::ffi::CString, SaveError> {
    let dir = dir_of(path);
    let mut temp = Vec::new();
    // One allocation, whatever the name's length.
    temp.try_reserve_exact(dir.map_or(0, <[u8]>::len) + 1 + TEMP_NAME + b".tmp".len())
        .map_err(|_| SaveError::OutOfMemory)?;
    if let Some(dir) = dir {
        temp.try_extend_from_slice(dir)?;
        temp.try_push(PATHSEP)?;
    }
    let mut random = [0u8; TEMP_NAME];
    alphanumeric(&mut random)?;
    temp.try_extend_from_slice(&random)?;
    temp.try_extend_from_slice(b".tmp")?;
    c_path(&temp)
}

/// Write `text` to a new file at `temp`, with the mode of the file it is
/// to replace if the same user and group own them.
#[cfg(unix)]
fn write_temp(
    temp: &CStr,
    was: &std::fs::Metadata,
    text: &[u8],
    on_close: OnClose,
) -> Result<(), SaveError> {
    let file = fs::open_write(temp, Keep::Absent, 0o600)?;
    let new = file.metadata()?;
    if new.uid() == was.uid() && new.gid() == was.gid() {
        // A mode that cannot be copied leaves the new file's 0600, as C
        // lets it (`fchmod`'s failure ignored).
        file.set_permissions(std::fs::Permissions::from_mode(was.mode()))
            .ok();
    }
    // As text (`FOPEN_WRITETEXT`), which is binary here.
    let mut out = Writer::new(file, Mode::TEXT);
    out.write_all(text)?;
    on_close.close(out.into_inner())
}

/// Write `text` to a new file at `temp`, readable and writable, in text
/// mode as C's `fdopen(.., "wt")` writes it: each line feed after a
/// carriage return. Windows has no mode to copy (`HAVE_FCHMOD`).
#[cfg(windows)]
fn write_temp(temp: &CStr, text: &[u8], on_close: OnClose) -> Result<(), SaveError> {
    let file = fs::open_write(temp, Keep::Absent, 0o600)?;
    let mut out = Writer::new(file, Mode::TEXT);
    out.write_all(text)?;
    on_close.close(out.into_inner())
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

/// The directory part of `path`, without the separators after it, if it
/// names one (`dirslash`, which then adds one `PATHSEP`): a file directly
/// under `/` is in the empty one, the root, and a bare name in none.
fn dir_of(path: &[u8]) -> Option<&[u8]> {
    let mut n = path.len();
    while n > 0 && !is_sep(path[n - 1]) {
        n -= 1;
    }
    if n == 0 {
        return None;
    }
    while n > 0 && is_sep(path[n - 1]) {
        n -= 1;
    }
    Some(&path[..n])
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
        assert_eq!(dir_of(b"/a/b/file"), Some(&b"/a/b"[..]));
        assert_eq!(dir_of(b"a//b"), Some(&b"a"[..]));
        assert_eq!(dir_of(b"file"), None);
        // The root, which C's `dirslash` gives as one separator.
        assert_eq!(dir_of(b"/file"), Some(&b""[..]));
        assert_eq!(dir_of(b"//file"), Some(&b""[..]));
        // A backslash separates only on Windows.
        let windows = cfg!(windows);
        assert_eq!(
            dir_of(br"c:\a\\b"),
            if windows { Some(&br"c:\a"[..]) } else { None }
        );
        assert_eq!(dir_of(br"c:\a/b"), Some(&br"c:\a"[..]));
    }

    /// The file written first is beside the one it replaces: in its
    /// directory, the root's for a file under `/`, and the current one's
    /// for a bare name.
    #[test]
    fn the_first_file_is_written_beside_its_target() {
        let sep = char::from(PATHSEP);
        for (path, dir) in [
            (&b"/cookies"[..], format!("{sep}")),
            (b"/a/b/jar", format!("/a/b{sep}")),
            (b"jar", String::new()),
        ] {
            let temp = temp_beside(path).unwrap().into_string().unwrap();
            let name = temp.strip_prefix(&dir).unwrap_or_else(|| panic!("{temp}"));
            assert_eq!(name.len(), TEMP_NAME + 4, "{temp}");
            assert!(name.ends_with(".tmp"), "{temp}");
            assert!(!name.contains(['/', '\\']), "{temp}");
        }
    }

    /// On Windows the file is replaced whatever it was, and written as
    /// text, as C's `"wt"` writes it.
    #[cfg(windows)]
    #[test]
    fn a_file_is_replaced_in_text_mode() {
        let dir = scratch("text");
        let path = dir.join("jar");
        std::fs::write(&path, b"old and longer").unwrap();
        replace(
            path.as_os_str().as_encoded_bytes(),
            b"a\nb\n\nc",
            OnClose::Fails,
        )
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"a\r\nb\r\n\r\nc");
        // Nothing is left beside it.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(replace(b"", b"new", OnClose::Fails), Err(SaveError::Write));
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
        replace(bytes, b"new", OnClose::Fails).unwrap();
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
        replace(path.as_os_str().as_encoded_bytes(), b"new", OnClose::Fails).unwrap();
        assert_ne!(std::fs::metadata(&path).unwrap().ino(), before);
        std::fs::remove_dir_all(&dir).unwrap();
        // No file could be made beside `/dev/null`.
        assert_eq!(replace(b"/dev/null", b"new", OnClose::Fails), Ok(()));
        assert_eq!(replace(b"", b"new", OnClose::Fails), Err(SaveError::Write));
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
        replace(path.as_os_str().as_encoded_bytes(), b"new", OnClose::Fails).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!((meta.gid(), meta.mode() & 0o777), (egid, 0o600));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The file written first is named by random letters alone, not
    /// after the file it replaces, so a name as long as the file system
    /// takes is replaced too (CVE-2023-46219, where C's temporary name
    /// was the target's with a suffix, too long to make).
    #[cfg(unix)]
    #[test]
    fn a_file_named_as_long_as_the_system_takes_is_replaced() {
        let dir = scratch("long");
        let path = dir.join("j".repeat(255));
        std::fs::write(&path, b"old").unwrap();
        replace(path.as_os_str().as_encoded_bytes(), b"new", OnClose::Fails).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A save that cannot make its file beside the target fails with the
    /// target as it was, as C's `Curl_fopen` leaves it: it opens the
    /// target to append, which keeps what it holds, before it makes the
    /// new file (upstream 3ffedaa792).
    #[cfg(unix)]
    #[test]
    fn a_save_that_cannot_make_its_file_leaves_the_target_as_it_was() {
        let dir = scratch("readonly");
        let path = dir.join("jar");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let saved = replace(path.as_os_str().as_encoded_bytes(), b"new", OnClose::Fails);
        let left = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        // A user the directory's mode does not bind writes it anyway.
        if saved.is_ok() {
            assert_eq!(left, b"new");
            eprintln!("not run: the directory's mode does not bind this user");
            return;
        }
        assert_eq!(saved, Err(SaveError::Write));
        assert_eq!(left, b"old");
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
