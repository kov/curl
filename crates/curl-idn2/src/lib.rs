//! Internationalized host names (`lib/idn.c`): a name in the locale's
//! characters (UTF-8, for Windows') looked up by its punycode form, and a
//! name in punycode shown in Unicode. From libidn2, as the reference build
//! has it, with the `apple-idn` feature from ICU on Apple's systems
//! (`USE_APPLE_IDN`), or with `win-idn` from Windows' own conversions
//! (`USE_WIN32_IDN`).

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use core::ffi::CStr;
use core::fmt;

use curl_core::idn::Idn;

#[cfg(all(feature = "apple-idn", feature = "win-idn"))]
compile_error!("one IDN library at a time: `apple-idn` or `win-idn`");
#[cfg(all(feature = "win-idn", not(windows)))]
compile_error!("`win-idn` is Windows' own IDN conversion, built only for Windows");

#[cfg(feature = "apple-idn")]
mod apple;
#[cfg(feature = "apple-idn")]
pub use apple::AppleIdn;

#[cfg(all(feature = "win-idn", windows))]
mod win;
#[cfg(all(feature = "win-idn", windows))]
pub use win::WinIdn;

#[cfg(not(any(feature = "apple-idn", feature = "win-idn")))]
mod idn2;
#[cfg(not(any(feature = "apple-idn", feature = "win-idn")))]
pub use idn2::{Idn2, version};

/// The library each handle converts its names with.
#[cfg(not(any(feature = "apple-idn", feature = "win-idn")))]
pub const IDN: &dyn Idn = &Idn2;
/// The library each handle converts its names with.
#[cfg(feature = "apple-idn")]
pub const IDN: &dyn Idn = &AppleIdn;
/// The library each handle converts its names with.
#[cfg(all(feature = "win-idn", windows))]
pub const IDN: &dyn Idn = &WinIdn;

/// The library as `curl -V` and `curl_version` name it (`idn_version`):
/// `libidn2/<version>`, `AppleIDN` or `WinIDN`.
pub struct Shown;

impl fmt::Display for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(not(any(feature = "apple-idn", feature = "win-idn")))]
        return write!(f, "libidn2/{}", version());
        #[cfg(feature = "apple-idn")]
        return f.write_str("AppleIDN");
        #[cfg(feature = "win-idn")]
        return f.write_str("WinIDN");
    }
}

/// The library's version as `curl_version_info` gives it in `libidn`, a C
/// string the library keeps; none for Apple's or Windows', whose C builds
/// leave it NULL.
pub fn version_c() -> Option<&'static CStr> {
    #[cfg(not(any(feature = "apple-idn", feature = "win-idn")))]
    return Some(idn2::version_c());
    #[cfg(any(feature = "apple-idn", feature = "win-idn"))]
    return None;
}
