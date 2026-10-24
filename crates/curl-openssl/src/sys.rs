//! The library's initialisation and its version.

#![allow(unsafe_code)]

use core::ffi::c_ulong;

/// `OPENSSL_INIT_LOAD_CONFIG`: read the configuration file.
const LOAD_CONFIG: u64 = 0x0000_0040;

/// `OPENSSL_INIT_ENGINE_ALL_BUILTIN`: the built-in engines, rdrand,
/// dynamic, cryptodev, capi and padlock, as `crypto.h` defines it.
const ENGINE_ALL_BUILTIN: u64 = 0x0000_0200 | 0x0000_0400 | 0x0000_1000 | 0x0000_2000 | 0x0000_4000;

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
    unsafe { openssl_sys::OPENSSL_init_ssl(LOAD_CONFIG | ENGINE_ALL_BUILTIN, core::ptr::null()) };
}

/// The version of the library loaded as text: `3.5.9`.
pub(crate) fn version_text() -> &'static str {
    // SAFETY: a function of no state, for a value the library knows.
    let text = unsafe { openssl_sys::OpenSSL_version(crate::ffi::OPENSSL_VERSION_STRING) };
    // SAFETY: the library's static text for its version, alive for the
    // process.
    let text = unsafe { core::ffi::CStr::from_ptr(text) };
    text.to_str().unwrap_or("")
}

/// The library as C names it in its version line (`Curl_ossl_version`):
/// `OpenSSL/3.5.9`.
pub fn version() -> impl core::fmt::Display {
    struct Version;
    impl core::fmt::Display for Version {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "OpenSSL/{}", version_text())
        }
    }
    Version
}

/// The length of `version`'s text.
pub(crate) fn version_len() -> usize {
    "OpenSSL/".len() + version_text().len()
}

/// The version of the library loaded, as `OPENSSL_VERSION_NUMBER` says
/// one: `0xMNN00PP0`.
fn version_number() -> c_ulong {
    // SAFETY: it takes nothing and reads a constant.
    unsafe { openssl_sys::OpenSSL_version_num() }
}

/// Whether a library of version `number` is one this build works with.
fn supported(number: c_ulong) -> Result<(), TooOld> {
    if number < OLDEST { Err(TooOld) } else { Ok(()) }
}

#[cfg(test)]
pub(crate) mod tests {
    use core::ffi::{c_char, c_int, c_void};
    use core::sync::atomic::{AtomicIsize, Ordering};

    use super::*;

    use curl_core::libraries::{Ed25519, Ed25519Error};

    /// The library's allocations not yet freed, once `count_allocations`
    /// has installed its functions.
    static LIVE: AtomicIsize = AtomicIsize::new(0);

    type Malloc = extern "C" fn(usize, *const c_char, c_int) -> *mut c_void;
    type Realloc = extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void;
    type Free = extern "C" fn(*mut c_void, *const c_char, c_int);

    // SAFETY: the declarations are `crypto.h`'s and the C library's.
    unsafe extern "C" {
        fn CRYPTO_set_mem_functions(m: Malloc, r: Realloc, f: Free) -> c_int;
        fn malloc(size: usize) -> *mut c_void;
        fn realloc(p: *mut c_void, size: usize) -> *mut c_void;
        fn free(p: *mut c_void);
    }

    extern "C" fn counted_malloc(size: usize, _: *const c_char, _: c_int) -> *mut c_void {
        // SAFETY: the C library's own.
        let p = unsafe { malloc(size) };
        if !p.is_null() {
            LIVE.fetch_add(1, Ordering::Relaxed);
        }
        p
    }

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
    pub(crate) fn count_allocations() {
        // SAFETY: the functions are a matching set over the C library's
        // allocator, installed before the library allocates.
        let set =
            unsafe { CRYPTO_set_mem_functions(counted_malloc, counted_realloc, counted_free) };
        assert_eq!(set, 1, "installed before the library allocated");
    }

    /// The library's allocations not yet freed since `count_allocations`.
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
    /// processor has the instruction.
    #[test]
    fn init_loads_the_built_in_engines() {
        in_a_child("sys::tests::engines_after_init", "/dev/null".as_ref());
    }

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

    /// Signing without `init` first initialises the library as `init`
    /// does, its built-in engines loaded.
    #[test]
    fn signing_initialises_the_library() {
        in_a_child("sys::tests::engines_after_signing", "/dev/null".as_ref());
    }

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
    /// what it said still holds.
    #[test]
    fn init_reads_the_configuration() {
        let path = no_algorithm_file("init");
        in_a_child("sys::tests::configured_at_init", &path);
        std::fs::remove_file(&path).unwrap();
    }

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
    /// this platform's library has none of (cryptodev, capi, padlock).
    #[test]
    fn the_flags_are_c_s() {
        assert_eq!(LOAD_CONFIG, 0x40);
        assert_eq!(ENGINE_ALL_BUILTIN, 0x7600);
    }

    /// The version line names the library as C's `Curl_ossl_version`
    /// does, `OpenSSL/` and the version it says it is; `version_len` is
    /// that text's length.
    #[test]
    fn the_version_is_named_as_c_names_it() {
        // "OpenSSL 3.5.9 29 Sep 2026".
        let said = openssl::version::version();
        let number = said.split(' ').nth(1).unwrap();
        let text = version().to_string();
        assert_eq!(text, format!("OpenSSL/{number}"));
        assert_eq!(version_len(), text.len());
    }

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
