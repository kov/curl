//! Finding the default configuration file, as `findfile(".curlrc", ...)`
//! in `src/tool_findfile.c` finds it on Unix.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use curl_alloc::{OutOfMemory, TryVec};

/// Whether the command line lets the default configuration file be read:
/// not if its first argument starts with `-q` or is `--disable`.
pub(crate) fn reads_curlrc(argv: &[OsString]) -> bool {
    argv.get(1).is_none_or(|first| {
        let first = first.as_encoded_bytes();
        !first.starts_with(b"-q") && first != b"--disable"
    })
}

/// Where to look, in order: a variable naming a directory, what to append
/// to it, and whether the file is `curlrc` there rather than `.curlrc`.
const PLACES: &[(&str, &str, bool)] = &[
    ("CURL_HOME", "", false),
    ("XDG_CONFIG_HOME", "", true),
    ("HOME", "", false),
    // `curlrc` is looked for in one directory only: the first of these
    // whose variable is set.
    ("CURL_HOME", "/.config", true),
    ("HOME", "/.config", true),
];

/// The default configuration file, if there is one: the first readable
/// one of the places C looks, and last `.curlrc` in the home directory the
/// user database names. `env` reads a variable, `home` asks the user
/// database, `readable` checks a file can be opened.
pub(crate) fn find_curlrc(
    env: impl Fn(&str) -> Option<OsString>,
    home: impl FnOnce() -> Result<Option<OsString>, OutOfMemory>,
    readable: impl Fn(&Path) -> bool,
) -> Result<Option<PathBuf>, OutOfMemory> {
    let mut without_dot_tried = false;
    for &(var, append, without_dot) in PLACES {
        let Some(dir) = env(var).filter(|d| !d.is_empty()) else {
            continue;
        };
        if without_dot {
            if without_dot_tried {
                continue;
            }
            without_dot_tried = true;
        }
        let name: &[u8] = if without_dot { b"curlrc" } else { b".curlrc" };
        let path = join(&[dir.as_bytes(), append.as_bytes(), b"/", name])?;
        if readable(&path) {
            return Ok(Some(path));
        }
    }
    if let Some(dir) = home()? {
        let path = join(&[dir.as_bytes(), b"/.curlrc"])?;
        if readable(&path) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn join(parts: &[&[u8]]) -> Result<PathBuf, OutOfMemory> {
    let mut path = Vec::new();
    for part in parts {
        path.try_extend_from_slice(part)?;
    }
    Ok(PathBuf::from(OsString::from_vec(path)))
}

/// Whether `path` can be opened for reading, as `checkhome` checks it.
pub(crate) fn readable(path: &Path) -> bool {
    std::fs::File::open(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(vars: &[(&str, &str)], files: &[&str]) -> Option<String> {
        find_with_home(vars, None, files)
    }

    fn find_with_home(vars: &[(&str, &str)], home: Option<&str>, files: &[&str]) -> Option<String> {
        let env = |v: &str| {
            vars.iter()
                .find(|(k, _)| *k == v)
                .map(|(_, d)| OsString::from(d))
        };
        let readable = |p: &Path| files.iter().any(|f| Path::new(f) == p);
        find_curlrc(env, || Ok(home.map(OsString::from)), readable)
            .unwrap()
            .map(|p| p.display().to_string())
    }

    /// The order of `findfile` with `CURLRC_DOTSCORE` 1.
    #[test]
    fn looks_where_c_looks() {
        let all = [
            "/c/.curlrc",
            "/x/curlrc",
            "/h/.curlrc",
            "/c/.config/curlrc",
            "/h/.config/curlrc",
        ];
        let vars = [
            ("CURL_HOME", "/c"),
            ("XDG_CONFIG_HOME", "/x"),
            ("HOME", "/h"),
        ];
        assert_eq!(find(&vars, &all).as_deref(), Some("/c/.curlrc"));
        assert_eq!(find(&vars, &all[1..]).as_deref(), Some("/x/curlrc"));
        assert_eq!(find(&vars, &all[2..]).as_deref(), Some("/h/.curlrc"));
        // A set `XDG_CONFIG_HOME` rules out the `.config` directories.
        assert_eq!(find(&vars, &all[3..]), None);
        let no_xdg = [("CURL_HOME", "/c"), ("HOME", "/h")];
        assert_eq!(
            find(&no_xdg, &all[3..]).as_deref(),
            Some("/c/.config/curlrc")
        );
        // So does a set `CURL_HOME`, for `HOME`'s.
        assert_eq!(find(&no_xdg, &all[4..]), None);
        assert_eq!(
            find(&[("HOME", "/h")], &all[4..]).as_deref(),
            Some("/h/.config/curlrc")
        );
        // An empty variable is skipped, and does not count as set.
        let empty_xdg = [("XDG_CONFIG_HOME", ""), ("HOME", "/h")];
        assert_eq!(
            find(&empty_xdg, &all[4..]).as_deref(),
            Some("/h/.config/curlrc")
        );
        assert_eq!(find(&[], &all), None);
    }

    /// Last, `.curlrc` in the user database's home directory, never
    /// `.config/curlrc` there.
    #[test]
    fn then_the_users_home() {
        let files = ["/p/.curlrc", "/p/.config/curlrc", "/h/.curlrc"];
        assert_eq!(
            find_with_home(&[], Some("/p"), &files).as_deref(),
            Some("/p/.curlrc")
        );
        assert_eq!(find_with_home(&[], Some("/p"), &files[1..]), None);
        let home = [("HOME", "/h")];
        assert_eq!(
            find_with_home(&home, Some("/p"), &files).as_deref(),
            Some("/h/.curlrc")
        );
        assert_eq!(find_with_home(&[], None, &files), None);
    }

    #[test]
    fn q_or_disable_first_skips_it() {
        let argv = |a: &[&str]| -> Vec<OsString> { a.iter().map(OsString::from).collect() };
        assert!(reads_curlrc(&argv(&["curl"])));
        assert!(reads_curlrc(&argv(&["curl", "-v", "-q"])));
        assert!(!reads_curlrc(&argv(&["curl", "-q"])));
        assert!(!reads_curlrc(&argv(&["curl", "-qV"])));
        assert!(!reads_curlrc(&argv(&["curl", "--disable"])));
        assert!(reads_curlrc(&argv(&["curl", "--disable-eprt"])));
    }
}
