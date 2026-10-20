//! `curl_easy_strerror`, `curl_multi_strerror`, `curl_share_strerror` and
//! `curl_url_strerror`.
//!
//! Any integer is accepted: a code no table knows gets libcurl's "unknown"
//! string, as C gives it.

// `no_mangle` is the only unsafe thing here.
#![allow(unsafe_code)]

use core::ffi::c_char;

use crate::error_codes;
use crate::ffi::{self, CURLMcode, CURLSHcode, CURLUcode, CURLcode};

#[unsafe(no_mangle)]
pub extern "C" fn curl_easy_strerror(code: CURLcode) -> *const c_char {
    error_codes::easy_strerror(code).as_ptr()
}
const _: ffi::proto::curl_easy_strerror = curl_easy_strerror;

#[unsafe(no_mangle)]
pub extern "C" fn curl_multi_strerror(code: CURLMcode) -> *const c_char {
    error_codes::multi_strerror(code).as_ptr()
}
const _: ffi::proto::curl_multi_strerror = curl_multi_strerror;

#[unsafe(no_mangle)]
pub extern "C" fn curl_share_strerror(code: CURLSHcode) -> *const c_char {
    error_codes::share_strerror(code).as_ptr()
}
const _: ffi::proto::curl_share_strerror = curl_share_strerror;

#[unsafe(no_mangle)]
pub extern "C" fn curl_url_strerror(code: CURLUcode) -> *const c_char {
    error_codes::url_strerror(code).as_ptr()
}
const _: ffi::proto::curl_url_strerror = curl_url_strerror;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use curl_core::error::{ErrorKind, MultiErrorKind, ShareErrorKind, UrlErrorKind};

    use crate::error_codes::*;

    /// Each kind has its own code, whose string is the kind's message.
    #[test]
    fn kinds_round_trip_through_codes() {
        let mut seen = HashSet::new();
        for &k in ErrorKind::ALL {
            assert!(seen.insert(easy_code(k).0), "{k:?}");
            assert_eq!(easy_strerror(easy_code(k)).to_str(), Ok(k.message()));
        }
        seen.clear();
        for &k in MultiErrorKind::ALL {
            assert!(seen.insert(multi_code(k).0), "{k:?}");
            assert_eq!(multi_strerror(multi_code(k)).to_str(), Ok(k.message()));
        }
        seen.clear();
        for &k in ShareErrorKind::ALL {
            assert!(seen.insert(share_code(k).0), "{k:?}");
            assert_eq!(share_strerror(share_code(k)).to_str(), Ok(k.message()));
        }
        seen.clear();
        for &k in UrlErrorKind::ALL {
            assert!(seen.insert(url_code(k).0), "{k:?}");
            assert_eq!(url_strerror(url_code(k)).to_str(), Ok(k.message()));
        }
    }
}
