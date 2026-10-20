//! The user database.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

use curl_alloc::{OutOfMemory, TryVec};

/// The home directory of the effective user, from the user database, as
/// C's `getpwuid(geteuid())` finds it. `None` when the user has no entry
/// or an empty home directory; `Err` when memory for the lookup or the
/// answer cannot be allocated.
pub fn home_directory() -> Result<Option<OsString>, OutOfMemory> {
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
        return Ok(Some(OsString::from_vec(copy)));
    }
}

#[cfg(test)]
mod tests {
    /// The user running the tests has an entry, as `getent passwd` shows.
    #[test]
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
        assert_eq!(getent.trim().split(':').nth(5), home.to_str());
    }
}
