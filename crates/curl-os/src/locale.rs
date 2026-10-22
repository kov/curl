//! The process's locale (`setlocale`).

#![allow(unsafe_code)]

/// Take the locale the environment names (`LC_ALL`, each category's
/// `LC_*`, `LANG`) for every category but numbers, which keep the C
/// locale's, as C's tool sets it (`operate`): an operating-system error's
/// text comes in the environment's language and a time with its names,
/// while a number is read and written with a `.` whatever the language.
/// The C library starts in the C locale. Call it before any thread
/// starts: the locale is the process's.
pub fn from_environment_but_numbers() {
    // SAFETY: the empty string is a C string; the caller makes sure no
    // other thread runs, as `setlocale` is not thread-safe. A locale the
    // environment names that does not exist leaves the C locale, as it
    // leaves C's.
    unsafe { libc::setlocale(libc::LC_ALL, c"".as_ptr()) };
    // SAFETY: as above.
    unsafe { libc::setlocale(libc::LC_NUMERIC, c"C".as_ptr()) };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use super::*;

    /// Set in the child process `takes_the_environment_s_locale` runs.
    const CHILD: &str = "CURL_OS_LOCALE_CHILD";

    /// The locale of `category` now.
    fn current(category: libc::c_int) -> String {
        // SAFETY: a NULL locale only asks; the result is a C string the C
        // library keeps, read before anything else changes the locale.
        let name = unsafe { libc::setlocale(category, std::ptr::null()) };
        assert!(!name.is_null());
        // SAFETY: as above.
        unsafe { core::ffi::CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned()
    }

    /// Every category takes the environment's locale but numbers: the
    /// test binary runs `in_the_environment_s_locale` again with `LC_ALL`
    /// naming one the C library always has.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not run processes")]
    fn takes_the_environment_s_locale() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "locale::tests::in_the_environment_s_locale"])
            .env("LC_ALL", "C.UTF-8")
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "{out:?}"
        );
    }

    #[test]
    fn in_the_environment_s_locale() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        assert_eq!(current(libc::LC_CTYPE), "C");
        from_environment_but_numbers();
        for category in [
            libc::LC_CTYPE,
            libc::LC_MESSAGES,
            libc::LC_TIME,
            libc::LC_COLLATE,
        ] {
            assert_eq!(current(category), "C.UTF-8", "{category}");
        }
        assert_eq!(current(libc::LC_NUMERIC), "C");
    }
}
