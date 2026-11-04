//! The user database, or on Windows, which has none C reads, the user's
//! profile directory.

#![allow(unsafe_code)]

#[cfg(unix)]
use core::ffi::{CStr, c_char};
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

use curl_alloc::{OutOfMemory, TryVec};

/// The user's profile directory, `USERPROFILE`, where C's netrc looks on
/// Windows for want of a user database (`Curl_parsenetrc`). `None` when it
/// is unset or empty; `Err` when memory for the answer cannot be
/// allocated. Read as the system keeps it, in UTF-16, which an `OsString`
/// holds whole.
#[cfg(windows)]
pub fn home_directory() -> Result<Option<OsString>, OutOfMemory> {
    use windows_sys::Win32::System::Environment::GetEnvironmentVariableW;
    const NAME: [u16; 12] = {
        let ascii = *b"USERPROFILE\0";
        let mut wide = [0u16; 12];
        let mut i = 0;
        while i < ascii.len() {
            wide[i] = ascii[i] as u16;
            i += 1;
        }
        wide
    };
    let mut wide: Vec<u16> = Vec::new();
    let mut room = 260usize;
    loop {
        wide.clear();
        wide.try_reserve_exact(room)?;
        let size = u32::try_from(room).expect("a variable's size fits");
        // SAFETY: `NAME` is a NUL-terminated UTF-16 string, and `wide` has
        // room for the `size` units the call is told, which it writes no
        // further than; both live through the call.
        let n = unsafe { GetEnvironmentVariableW(NAME.as_ptr(), wide.as_mut_ptr(), size) };
        let n = usize::try_from(n).expect("a u32 fits");
        if n == 0 {
            // Unset, or set empty: C's `curl_getenv` takes both as unset.
            return Ok(None);
        }
        if n >= room {
            // `n` is the room it needs, its NUL included.
            room = n;
            continue;
        }
        // SAFETY: the call wrote `n` units, below the room reserved.
        unsafe { wide.set_len(n) };
        return Ok(Some(wtf8(&wide)?));
    }
}

/// `wide` as an `OsString` holds it, without the infallible copy
/// `OsString::from_wide` makes: its WTF-8 encoding, UTF-8 with any lone
/// surrogate encoded as if it were a character.
#[cfg(windows)]
fn wtf8(wide: &[u16]) -> Result<OsString, OutOfMemory> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(wide.len() * 3)?;
    for unit in char::decode_utf16(wide.iter().copied()) {
        let mut buf = [0u8; 4];
        let encoded: &[u8] = match unit {
            Ok(c) => c.encode_utf8(&mut buf).as_bytes(),
            Err(lone) => {
                let s = u32::from(lone.unpaired_surrogate());
                buf[..3].copy_from_slice(&[
                    0xE0 | (s >> 12) as u8,
                    0x80 | ((s >> 6) & 0x3F) as u8,
                    0x80 | (s & 0x3F) as u8,
                ]);
                &buf[..3]
            }
        };
        bytes.try_extend_from_slice(encoded)?;
    }
    // SAFETY: `bytes` is the WTF-8 encoding of a UTF-16 string, made just
    // above, which is what an `OsString` holds on Windows.
    Ok(unsafe { OsString::from_encoded_bytes_unchecked(bytes) })
}

/// The home directory of the effective user, from the user database, as
/// C's `getpwuid(geteuid())` finds it. `None` when the user has no entry
/// or an empty home directory; `Err` when memory for the lookup or the
/// answer cannot be allocated.
#[cfg(unix)]
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
    /// The user's profile directory, as the system has it in
    /// `USERPROFILE`, and none with it unset or empty.
    #[test]
    #[cfg(windows)]
    fn finds_the_user_s_profile() {
        let home = super::home_directory().unwrap().expect("a profile");
        assert_eq!(Some(home), std::env::var_os("USERPROFILE"));
        let wide: Vec<u16> = "a\u{e9}\u{1f600}"
            .encode_utf16()
            .chain([0xD800, 0x62])
            .collect();
        let os = super::wtf8(&wide).unwrap();
        assert_eq!(
            std::os::windows::ffi::OsStrExt::encode_wide(os.as_os_str()).collect::<Vec<_>>(),
            wide
        );
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "users::tests::with_no_profile"])
            .env("USERPROFILE", "")
            .env("CURL_OS_USERS_CHILD", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "{out:?}"
        );
    }

    #[test]
    #[cfg(windows)]
    fn with_no_profile() {
        if std::env::var_os("CURL_OS_USERS_CHILD").is_none() {
            return;
        }
        assert_eq!(super::home_directory().unwrap(), None);
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
        assert_eq!(getent.trim().split(':').nth(5), home.to_str());
    }
}
