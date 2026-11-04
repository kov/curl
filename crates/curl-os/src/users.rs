//! The user database, or on Windows, which has none C reads, the user's
//! profile directory.

#![allow(unsafe_code)]

#[cfg(unix)]
use core::ffi::{CStr, c_char};

use curl_alloc::OutOfMemory;
#[cfg(unix)]
use curl_alloc::TryVec;

/// The user's profile directory, `USERPROFILE`, where C's netrc looks on
/// Windows for want of a user database (`Curl_parsenetrc`), read as
/// `curl_getenv` reads it: in the ANSI code page, which the files named
/// from it are opened in. `None` when it is unset or empty; `Err` when
/// memory for the answer cannot be allocated.
#[cfg(windows)]
pub fn home_directory() -> Result<Option<Vec<u8>>, OutOfMemory> {
    Ok(crate::env::var(b"USERPROFILE")?.filter(|v| !v.is_empty()))
}

/// The home directory of the effective user, from the user database, as
/// C's `getpwuid(geteuid())` finds it. `None` when the user has no entry
/// or an empty home directory; `Err` when memory for the lookup or the
/// answer cannot be allocated.
#[cfg(unix)]
pub fn home_directory() -> Result<Option<Vec<u8>>, OutOfMemory> {
    // SAFETY: `sysconf` takes any name and fails with -1.
    let hint = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut size = usize::try_from(hint)
        .ok()
        .filter(|&n| n > 0)
        .unwrap_or(1024);
    let mut buf: Vec<c_char> = Vec::new();
    loop {
        buf.try_reserve_exact(size)?;
        // SAFETY: the zeroed record is overwritten by `getpwuid_r` before
        // it is read, and all-zero is a valid `passwd`.
        let mut entry: libc::passwd = unsafe { core::mem::zeroed() };
        let mut found: *mut libc::passwd = core::ptr::null_mut();
        // SAFETY: `geteuid` cannot fail.
        let uid = unsafe { libc::geteuid() };
        // SAFETY: `entry` and `found` are valid to write, and `buf` has
        // `size` bytes of room for the strings the entry points to.
        let rc = unsafe {
            libc::getpwuid_r(uid, &raw mut entry, buf.as_mut_ptr(), size, &raw mut found)
        };
        if rc == libc::ERANGE {
            size = size.checked_mul(2).expect("a user entry fits in memory");
            continue;
        }
        if rc != 0 || found.is_null() || entry.pw_dir.is_null() {
            return Ok(None);
        }
        // SAFETY: on success `pw_dir` is a C string in `buf`, which is
        // alive until the copy below is made.
        let home = unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes();
        if home.is_empty() {
            return Ok(None);
        }
        let mut copy = Vec::new();
        copy.try_extend_from_slice(home)?;
        return Ok(Some(copy));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    /// The user's profile directory, as `USERPROFILE` holds it in the
    /// ANSI code page (1252 on the test machine: an accent is one byte,
    /// not UTF-8's two), and none with it unset or empty.
    #[test]
    #[cfg(windows)]
    fn finds_the_user_s_profile() {
        for (value, want) in [
            ("C:\\Users\\caf\u{e9}", "433a5c55736572735c636166e9"),
            ("", "none"),
        ] {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "users::tests::says_the_profile", "--nocapture"])
                .env("USERPROFILE", value)
                .env("CURL_OS_USERS_CHILD", "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success(), "{out:?}");
            assert!(stdout.contains("1 passed"), "{out:?}");
            assert!(
                stdout.contains(&format!("profile: [{want}]")),
                "{value:?}: {stdout}"
            );
        }
    }

    #[test]
    #[cfg(windows)]
    fn says_the_profile() {
        if std::env::var_os("CURL_OS_USERS_CHILD").is_none() {
            return;
        }
        let said = match super::home_directory().unwrap() {
            Some(home) => home.iter().map(|b| format!("{b:02x}")).collect(),
            None => "none".to_owned(),
        };
        println!("profile: [{said}]");
    }

    /// The user running the tests has an entry, as `getent passwd` shows.
    #[test]
    #[cfg(unix)]
    fn finds_this_users_home() {
        let home = super::home_directory()
            .unwrap()
            .expect("an entry for this user");
        let uid = std::process::Command::new("id")
            .arg("-u")
            .output()
            .unwrap()
            .stdout;
        let uid = String::from_utf8(uid).unwrap();
        let getent = std::process::Command::new("getent")
            .args(["passwd", uid.trim()])
            .output()
            .unwrap()
            .stdout;
        let getent = String::from_utf8(getent).unwrap();
        assert_eq!(
            getent.trim().split(':').nth(5).map(str::as_bytes),
            Some(&home[..])
        );
    }
}
