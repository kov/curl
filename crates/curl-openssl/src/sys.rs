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
mod tests {
    use super::*;

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
