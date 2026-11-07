//! The library's initialisation and its version.

#![allow(unsafe_code)]

use core::ffi::c_ulong;

/// `OPENSSL_INIT_LOAD_CONFIG`: read the configuration file.
#[cfg(ossl3)]
const LOAD_CONFIG: u64 = 0x0000_0040;
/// LibreSSL's.
#[cfg(libressl)]
const LOAD_CONFIG: u64 = 0x0000_0002;
/// The forks', as their headers define it (0: they read no file).
#[cfg(boringssl_like)]
const LOAD_CONFIG: u64 = openssl_sys::OPENSSL_INIT_LOAD_CONFIG as u64;

/// `OPENSSL_INIT_ENGINE_ALL_BUILTIN`: the built-in engines, rdrand,
/// dynamic, cryptodev, capi and padlock, as `crypto.h` defines it.
#[cfg(ossl3)]
const ENGINE_ALL_BUILTIN: u64 = 0x0000_0200 | 0x0000_0400 | 0x0000_1000 | 0x0000_2000 | 0x0000_4000;
/// LibreSSL has no engines: the flag is its no-op one
/// (`_OPENSSL_INIT_FLAG_NOOP`), which C passes all the same.
#[cfg(libressl)]
const ENGINE_ALL_BUILTIN: u64 = 0x8000_0000;
/// The forks', as their headers define it (0: they have no engines).
#[cfg(boringssl_like)]
const ENGINE_ALL_BUILTIN: u64 = openssl_sys::OPENSSL_INIT_ENGINE_ALL_BUILTIN as u64;

/// The library's name, as C's messages and version line say it
/// (`OSSL_PACKAGE`).
#[cfg(ossl3)]
pub(crate) const PACKAGE: &str = "OpenSSL";
/// LibreSSL's.
#[cfg(libressl)]
pub(crate) const PACKAGE: &str = "LibreSSL";
/// AWS-LC's.
#[cfg(awslc)]
pub(crate) const PACKAGE: &str = "AWS-LC";
/// BoringSSL's.
#[cfg(boringssl)]
pub(crate) const PACKAGE: &str = "BoringSSL";

/// The oldest library this build works with: 3.0.0.
const OLDEST: c_ulong = 0x3000_0000;

/// The library loaded is older than 3.0: it is not there for this build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TooOld;

/// Initialise the library as C's global init does (`ossl_init`), its
/// configuration read and its built-in engines loaded. A library older
/// than this build needs is left alone: it is one the build does not
/// have, and what would use it refuses.
pub fn init() {
    if supported(version_number()).is_ok() {
        init_ssl();
    }
}

/// Make the library ready to use, if it is one this build works with.
/// Each call after the first initialises nothing more.
pub(crate) fn ready() -> Result<(), TooOld> {
    supported(version_number())?;
    init_ssl();
    Ok(())
}

fn init_ssl() {
    // C ignores the result: a library that failed to initialise fails
    // what is asked of it next.
    // SAFETY: the flags are the library's own, and NULL asks for its
    // default settings; any thread may call it, any number of times.
    unsafe { crate::ffi::OPENSSL_init_ssl(LOAD_CONFIG | ENGINE_ALL_BUILTIN, core::ptr::null()) };
}

/// AWS-LC's: the version its headers say, as C prints it
/// (`AWSLC_VERSION_NUMBER_STRING`), `5.11.0`.
#[cfg(awslc)]
pub(crate) fn version_text() -> &'static str {
    core::ffi::CStr::from_bytes_with_nul(openssl_sys::AWSLC_VERSION_NUMBER_STRING)
        .ok()
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// BoringSSL's: none, as C's build that is given none says none
/// (`CURL_BORINGSSL_VERSION` unset).
#[cfg(boringssl)]
pub(crate) fn version_text() -> &'static str {
    ""
}

/// The version of the library loaded as text: `3.5.9`.
#[cfg(ossl3)]
pub(crate) fn version_text() -> &'static str {
    // SAFETY: a function of no state, for a value the library knows.
    let text = unsafe { openssl_sys::OpenSSL_version(crate::ffi::OPENSSL_VERSION_STRING) };
    // SAFETY: the library's static text for its version, alive for the
    // process.
    let text = unsafe { core::ffi::CStr::from_ptr(text) };
    text.to_str().unwrap_or("")
}

/// LibreSSL's: its version line, `LibreSSL 4.4.0`, less the name and the
/// blank after it if it starts with them, as C takes it.
#[cfg(libressl)]
pub(crate) fn version_text() -> &'static str {
    // SAFETY: a function of no state, for a value the library knows.
    let text = unsafe { openssl_sys::OpenSSL_version(crate::ffi::OPENSSL_VERSION) };
    // SAFETY: the library's static text for its version, alive for the
    // process.
    let text = unsafe { core::ffi::CStr::from_ptr(text) };
    let text = text.to_str().unwrap_or("");
    after_package(text)
}

/// `text` less `LibreSSL ` at its start, matched as C's
/// `curl_strnequal` does, without regard to case.
#[cfg(any(libressl, test))]
fn after_package(text: &str) -> &str {
    let lead = "LibreSSL ".len();
    match text.get(..lead) {
        Some(head) if head.eq_ignore_ascii_case("LibreSSL ") => &text[lead..],
        _ => text,
    }
}
/// The library as C names it in its version line (`Curl_ossl_version`):
/// `OpenSSL/3.5.9`; LibreSSL's with each blank of it an underscore;
/// `AWS-LC/5.11.0`; BoringSSL's name alone.
pub fn version() -> impl core::fmt::Display {
    struct Version;
    impl core::fmt::Display for Version {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            if cfg!(boringssl) {
                return f.write_str(PACKAGE);
            }
            write!(f, "{PACKAGE}/")?;
            write_version(f, version_text())
        }
    }
    Version
}

/// `text` as the version line has it: as it is from OpenSSL, its blanks
/// (`ISBLANK`: space and tab) made underscores from LibreSSL.
fn write_version(f: &mut core::fmt::Formatter<'_>, text: &str) -> core::fmt::Result {
    if cfg!(libressl) {
        for c in text.chars() {
            let mut buf = [0; 4];
            f.write_str(match c {
                ' ' | '\t' => "_",
                c => c.encode_utf8(&mut buf),
            })?;
        }
        Ok(())
    } else {
        f.write_str(text)
    }
}

/// The length of `version`'s text.
pub(crate) fn version_len() -> usize {
    if cfg!(boringssl) {
        PACKAGE.len()
    } else {
        PACKAGE.len() + 1 + version_text().len()
    }
}

/// The version of the library loaded, as `OPENSSL_VERSION_NUMBER` says
/// one: `0xMNN00PP0`. LibreSSL's says 2.0 whatever it is, the forks'
/// 1.1.1: C checks the library at build alone, as this crate does.
fn version_number() -> c_ulong {
    // SAFETY: it takes nothing and reads a constant.
    unsafe { openssl_sys::OpenSSL_version_num() }
}

/// Whether a library of version `number` is one this build works with.
fn supported(number: c_ulong) -> Result<(), TooOld> {
    if number < OLDEST && cfg!(ossl3) {
        Err(TooOld)
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #[cfg(any(ossl3, awslc))]
    use core::ffi::{c_char, c_int, c_void};
    #[cfg(any(ossl3, awslc))]
    use core::sync::atomic::{AtomicIsize, Ordering};

    use super::*;

    use curl_core::libraries::Ed25519;
    #[cfg(ossl3)]
    use curl_core::libraries::Ed25519Error;

    /// The library's allocations not yet freed, once `count_allocations`
    /// has installed its functions.
    #[cfg(any(ossl3, awslc))]
    static LIVE: AtomicIsize = AtomicIsize::new(0);

    #[cfg(any(ossl3, awslc))]
    type Malloc = extern "C" fn(usize, *const c_char, c_int) -> *mut c_void;
    #[cfg(any(ossl3, awslc))]
    type Realloc = extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void;
    #[cfg(any(ossl3, awslc))]
    type Free = extern "C" fn(*mut c_void, *const c_char, c_int);

    // SAFETY: the declarations are `crypto.h`'s and the C library's.
    #[cfg(any(ossl3, awslc))]
    unsafe extern "C" {
        fn CRYPTO_set_mem_functions(m: Malloc, r: Realloc, f: Free) -> c_int;
        fn malloc(size: usize) -> *mut c_void;
        fn realloc(p: *mut c_void, size: usize) -> *mut c_void;
        fn free(p: *mut c_void);
    }

    #[cfg(any(ossl3, awslc))]
    extern "C" fn counted_malloc(size: usize, _: *const c_char, _: c_int) -> *mut c_void {
        // SAFETY: the C library's own.
        let p = unsafe { malloc(size) };
        if !p.is_null() {
            LIVE.fetch_add(1, Ordering::Relaxed);
        }
        p
    }

    #[cfg(any(ossl3, awslc))]
    extern "C" fn counted_realloc(
        p: *mut c_void,
        size: usize,
        file: *const c_char,
        line: c_int,
    ) -> *mut c_void {
        if p.is_null() {
            return counted_malloc(size, file, line);
        }
        if size == 0 {
            counted_free(p, file, line);
            return core::ptr::null_mut();
        }
        // SAFETY: `p` came from `counted_malloc` or here, and is live.
        unsafe { realloc(p, size) }
    }

    #[cfg(any(ossl3, awslc))]
    extern "C" fn counted_free(p: *mut c_void, _: *const c_char, _: c_int) {
        if !p.is_null() {
            LIVE.fetch_sub(1, Ordering::Relaxed);
        }
        // SAFETY: `p` is null or came from the functions above, and is
        // freed once, as the library frees it.
        unsafe { free(p) };
    }

    /// Count the library's allocations from now on: in a process of its
    /// own (`in_a_child`), before the library has allocated anything.
    #[cfg(any(ossl3, awslc))]
    pub(crate) fn count_allocations() {
        // SAFETY: the functions are a matching set over the C library's
        // allocator, installed before the library allocates.
        let set =
            unsafe { CRYPTO_set_mem_functions(counted_malloc, counted_realloc, counted_free) };
        assert_eq!(set, 1, "installed before the library allocated");
    }

    /// The library's allocations not yet freed since `count_allocations`.
    #[cfg(any(ossl3, awslc))]
    pub(crate) fn live_allocations() -> isize {
        LIVE.load(Ordering::Relaxed)
    }

    /// The ids of the engines the library has loaded, as text.
    pub(crate) fn engines() -> Vec<String> {
        crate::engine::ids()
            .unwrap()
            .into_iter()
            .map(|id| String::from_utf8(id).unwrap())
            .collect()
    }

    /// Runs the ignored test `name` in a process of its own, with
    /// `OPENSSL_CONF` naming `conf`, and checks it passed.
    pub(crate) fn in_a_child(name: &str, conf: &std::path::Path) {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--ignored"])
            .env("OPENSSL_CONF", conf)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{out:?}");
        assert!(stdout.contains("1 passed"), "the test ran: {stdout}");
    }

    /// As C's `ossl_init`, `init` loads the built-in engines: checked
    /// with an empty configuration, which loads none of its own. Only
    /// the dynamic engine is there on every machine; rdrand is when the
    /// processor has the instruction. LibreSSL has none.
    #[cfg(ossl3)]
    #[test]
    fn init_loads_the_built_in_engines() {
        in_a_child("sys::tests::engines_after_init", "/dev/null".as_ref());
    }

    #[cfg(ossl3)]
    #[test]
    #[ignore = "run by init_loads_the_built_in_engines, OPENSSL_CONF empty"]
    fn engines_after_init() {
        assert_eq!(engines(), Vec::<String>::new(), "none before");
        init();
        assert!(engines().contains(&"dynamic".into()), "{:?}", engines());
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("rdrand") {
            assert!(engines().contains(&"rdrand".into()), "{:?}", engines());
        }
    }

    /// LibreSSL has no engines: none is listed once it is initialised
    /// (`OPENSSL_NO_ENGINE`).
    #[cfg(not(ossl3))]
    #[test]
    fn libressl_lists_no_engines() {
        init();
        assert_eq!(engines(), Vec::<String>::new());
    }

    /// Signing without `init` first initialises the library as `init`
    /// does, its built-in engines loaded.
    #[cfg(ossl3)]
    #[test]
    fn signing_initialises_the_library() {
        in_a_child("sys::tests::engines_after_signing", "/dev/null".as_ref());
    }

    #[cfg(ossl3)]
    #[test]
    #[ignore = "run by signing_initialises_the_library, OPENSSL_CONF empty"]
    fn engines_after_signing() {
        assert_eq!(engines(), Vec::<String>::new(), "none before");
        crate::ED25519.sign(&[1; 32], b"message").unwrap();
        assert!(engines().contains(&"dynamic".into()), "{:?}", engines());
    }

    /// A configuration under which no algorithm is fetched, Ed25519's
    /// included.
    pub(crate) const NO_ALGORITHM: &str = "openssl_conf = init\n\
                                           [init]\n\
                                           alg_section = algorithms\n\
                                           [algorithms]\n\
                                           default_properties = \"provider=none\"\n";

    /// A fresh file named for `test` in the temporary directory, holding
    /// `NO_ALGORITHM`.
    pub(crate) fn no_algorithm_file(test: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("curl-openssl-{test}-{}.cnf", std::process::id()));
        std::fs::write(&path, NO_ALGORITHM).unwrap();
        path
    }

    /// `init` reads the configuration `OPENSSL_CONF` names then, not when
    /// the library is first used: the file is emptied after `init`, and
    /// what it said still holds. OpenSSL 3's: LibreSSL's configuration has
    /// no algorithm section to refuse with.
    #[cfg(ossl3)]
    #[test]
    fn init_reads_the_configuration() {
        let path = no_algorithm_file("init");
        in_a_child("sys::tests::configured_at_init", &path);
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(ossl3)]
    #[test]
    #[ignore = "run by init_reads_the_configuration, OPENSSL_CONF set"]
    fn configured_at_init() {
        let path = std::env::var_os("OPENSSL_CONF").unwrap();
        init();
        std::fs::write(&path, "").unwrap();
        assert_eq!(
            crate::ED25519.sign(&[1; 32], b"message"),
            Err(Ed25519Error::Failed)
        );
    }

    /// Without `init`, the configuration is read at the first signing:
    /// the same file, emptied first, refuses nothing.
    #[test]
    fn without_init_the_configuration_is_read_later() {
        let path = no_algorithm_file("later");
        in_a_child("sys::tests::configured_later", &path);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    #[ignore = "run by without_init_the_configuration_is_read_later, OPENSSL_CONF set"]
    fn configured_later() {
        let path = std::env::var_os("OPENSSL_CONF").unwrap();
        std::fs::write(&path, "").unwrap();
        assert!(crate::ED25519.sign(&[1; 32], b"message").is_ok());
    }

    /// The flags are those C passes, as `crypto.h` defines them: the
    /// configuration read, and every built-in engine, including those
    /// this platform's library has none of (cryptodev, capi, padlock);
    /// LibreSSL's, whose engine flag does nothing; the forks', both 0.
    #[test]
    fn the_flags_are_c_s() {
        if cfg!(boringssl_like) {
            assert_eq!(LOAD_CONFIG, 0);
            assert_eq!(ENGINE_ALL_BUILTIN, 0);
        } else if cfg!(libressl) {
            assert_eq!(LOAD_CONFIG, 0x02);
            assert_eq!(ENGINE_ALL_BUILTIN, 0x8000_0000);
        } else {
            assert_eq!(LOAD_CONFIG, 0x40);
            assert_eq!(ENGINE_ALL_BUILTIN, 0x7600);
        }
    }

    /// The version line names the library as C's `Curl_ossl_version`
    /// does, `OpenSSL/` or `LibreSSL/` and the version it says it is;
    /// `version_len` is that text's length.
    #[test]
    fn the_version_is_named_as_c_names_it() {
        // BoringSSL's name alone, as C's build without
        // `CURL_BORINGSSL_VERSION` says it.
        if cfg!(boringssl) {
            assert_eq!(version().to_string(), "BoringSSL");
            assert_eq!(version_len(), "BoringSSL".len());
            return;
        }
        // "OpenSSL 3.5.9 29 Sep 2026", "LibreSSL 4.4.0", "AWS-LC 5.11.0".
        let said = openssl::version::version();
        let number = said.split(' ').nth(1).unwrap();
        let text = version().to_string();
        assert_eq!(text, format!("{PACKAGE}/{number}"));
        assert_eq!(version_len(), text.len());
    }

    /// LibreSSL's version line loses its name, in any case, only where it
    /// starts with it and a blank.
    #[test]
    fn libressl_s_name_is_taken_off_its_version() {
        assert_eq!(after_package("LibreSSL 4.4.0"), "4.4.0");
        assert_eq!(after_package("libressl 4.4.0"), "4.4.0");
        assert_eq!(after_package("LibreSSL4.4.0"), "LibreSSL4.4.0");
        assert_eq!(after_package("4.4.0"), "4.4.0");
        assert_eq!(after_package("LibreSSL "), "");
    }

    /// OpenSSL from 3.0; any LibreSSL or fork this crate builds against, whose
    /// number says nothing (C checks it at build alone).
    #[cfg(not(ossl3))]
    #[test]
    fn any_libressl_is_supported() {
        assert_eq!(supported(0x2000_0000), Ok(()));
        assert_eq!(ready(), Ok(()));
    }

    #[cfg(ossl3)]
    #[test]
    fn three_or_later_is_supported() {
        assert_eq!(supported(0x1010_1170), Err(TooOld));
        assert_eq!(supported(0x2fff_fff0), Err(TooOld));
        assert_eq!(supported(0x3000_0000), Ok(()));
        assert_eq!(supported(0x3050_0090), Ok(()));
        assert!(version_number() >= OLDEST);
        assert_eq!(ready(), Ok(()));
    }
}
