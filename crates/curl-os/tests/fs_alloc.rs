//! The file operations take a name without allocating, whatever its
//! length, as C's do: under the debug build's torture mode an allocation
//! std makes to copy a name of 384 bytes or more could not be refused, and
//! would abort the tool. The tracker counts this binary's allocations.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;

use curl_alloc::track::{Tracker, count_allocations};
use curl_os::fs::{self, Keep};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker;

/// A directory of its own for the test, removed after it.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

/// `name` in `dir`, by a name longer than std's 384-byte stack buffer.
fn long(dir: &std::path::Path, name: &str) -> Vec<u8> {
    let mut long = dir.as_os_str().as_bytes().to_vec();
    long.push(b'/');
    while long.len() < 400 {
        long.extend_from_slice(b"./");
    }
    long.extend_from_slice(name.as_bytes());
    long
}

#[test]
fn takes_a_long_name_without_allocating() {
    let dir = std::env::temp_dir().join(format!("curl-os-fs-alloc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let s = Scratch(dir);
    let (f, g, d) = (long(&s.0, "f"), long(&s.0, "g"), long(&s.0, "d"));
    // The positive control: std copies the name.
    let path = std::ffi::OsStr::from_bytes(&f);
    let (_, n) = count_allocations(|| std::fs::metadata(path));
    assert!(n >= 1, "std allocated nothing for a long name");

    let count = |what: &str, op: &mut dyn FnMut() -> std::io::Result<()>| {
        let (r, n) = count_allocations(op);
        r.unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(n, 0, "{what} allocated");
    };
    count("open_write", &mut || {
        fs::with_c_name(&f, |c| fs::open_write(c, Keep::Nothing, 0o600)).map(drop)
    });
    count("open_read", &mut || {
        fs::with_c_name(&f, fs::open_read).map(drop)
    });
    count("stat", &mut || {
        fs::with_c_name(&f, fs::stat).map(|st| assert!(st.is_file()))
    });
    count("set_times", &mut || {
        fs::with_c_name(&f, |c| fs::set_times(c, 1_000_000_000))
    });
    count("rename", &mut || {
        fs::with_c_name(&f, |from| fs::with_c_name(&g, |to| fs::rename(from, to)))
    });
    count("remove", &mut || fs::with_c_name(&g, fs::remove));
    count("make_dir", &mut || {
        fs::with_c_name(&d, |c| fs::make_dir(c, 0o700))
    });
    assert!(s.0.join("d").is_dir() && !s.0.join("f").exists() && !s.0.join("g").exists());
}
