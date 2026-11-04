//! Internationalized host names (`lib/idn.c`): a name in the locale's
//! characters looked up by its punycode form, and a name in punycode shown
//! in Unicode. From libidn2, as the reference build has it, or with the
//! `apple-idn` feature from ICU on Apple's systems (`USE_APPLE_IDN`).

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use core::ffi::CStr;
use core::fmt;

use curl_core::idn::Idn;

#[cfg(feature = "apple-idn")]
mod apple;
#[cfg(feature = "apple-idn")]
pub use apple::AppleIdn;

#[cfg(not(feature = "apple-idn"))]
mod idn2;
#[cfg(not(feature = "apple-idn"))]
pub use idn2::{Idn2, version};

/// The library each handle converts its names with.
#[cfg(not(feature = "apple-idn"))]
pub const IDN: &dyn Idn = &Idn2;
/// The library each handle converts its names with.
#[cfg(feature = "apple-idn")]
pub const IDN: &dyn Idn = &AppleIdn;

/// The library as `curl -V` and `curl_version` name it (`idn_version`):
/// `libidn2/<version>`, or `AppleIDN`.
pub struct Shown;

impl fmt::Display for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(not(feature = "apple-idn"))]
        return write!(f, "libidn2/{}", version());
        #[cfg(feature = "apple-idn")]
        return f.write_str("AppleIDN");
    }
}

/// The library's version as `curl_version_info` gives it in `libidn`, a C
/// string the library keeps; none for Apple's, whose C build leaves it
/// NULL.
pub fn version_c() -> Option<&'static CStr> {
    #[cfg(not(feature = "apple-idn"))]
    return Some(idn2::version_c());
    #[cfg(feature = "apple-idn")]
    return None;
}
