//! Internationalized host names (`lib/idn.c`): a name in the locale's
//! characters (UTF-8, for Windows') looked up by its punycode form, and a
//! name in punycode shown in Unicode. From libidn2, as the reference build
//! has it; with the `apple-idn` feature from ICU on Apple's systems
//! (`USE_APPLE_IDN`); on Windows from its own conversions
//! (`USE_WIN32_IDN`), as both reference Windows builds have them, unless
//! the `libidn2` feature asks for libidn2 there. The build script makes
//! the choice (cfg `win_idn`, `apple_idn`, or neither for libidn2).

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use core::ffi::CStr;
use core::fmt;

use curl_core::idn::Idn;

#[cfg(apple_idn)]
mod apple;
#[cfg(apple_idn)]
pub use apple::AppleIdn;

#[cfg(win_idn)]
mod win;
#[cfg(win_idn)]
pub use win::WinIdn;

#[cfg(not(any(apple_idn, win_idn)))]
mod idn2;
#[cfg(not(any(apple_idn, win_idn)))]
pub use idn2::{Idn2, version};

/// The library each handle converts its names with.
#[cfg(not(any(apple_idn, win_idn)))]
pub const IDN: &dyn Idn = &Idn2;
/// The library each handle converts its names with.
#[cfg(apple_idn)]
pub const IDN: &dyn Idn = &AppleIdn;
/// The library each handle converts its names with.
#[cfg(win_idn)]
pub const IDN: &dyn Idn = &WinIdn;

/// The library as `curl -V` and `curl_version` name it (`idn_version`):
/// `libidn2/<version>`, `AppleIDN` or `WinIDN`.
pub struct Shown;

impl fmt::Display for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(not(any(apple_idn, win_idn)))]
        return write!(f, "libidn2/{}", version());
        #[cfg(apple_idn)]
        return f.write_str("AppleIDN");
        #[cfg(win_idn)]
        return f.write_str("WinIDN");
    }
}

/// The library's version as `curl_version_info` gives it in `libidn`, a C
/// string the library keeps; none for Apple's or Windows', whose C builds
/// leave it NULL.
pub fn version_c() -> Option<&'static CStr> {
    #[cfg(not(any(apple_idn, win_idn)))]
    return Some(idn2::version_c());
    #[cfg(any(apple_idn, win_idn))]
    return None;
}
