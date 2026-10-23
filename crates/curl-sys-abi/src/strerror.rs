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
    use std::collections::HashMap;
    use std::ffi::{CStr, c_int};
    use std::fmt::Debug;

    use curl_core::error::{ErrorKind, MultiErrorKind, UrlErrorKind};

    use crate::error_codes::*;
    use crate::ffi::{self, CURLMcode, CURLSHcode, CURLUcode, CURLcode};

    /// One C enum's errors: each has its own code, whose string is the
    /// error's message, and every code from `first` to `last` is a
    /// success in `ok`, one error's, or one the strerror table does not
    /// know (C's obsolete codes, `last` itself).
    fn covers<E: Copy + Debug>(
        errors: impl IntoIterator<Item = E>,
        code: impl Fn(E) -> c_int,
        message: impl Fn(E) -> &'static str,
        strerror: impl Fn(c_int) -> &'static CStr,
        ok: &[c_int],
        (first, last): (c_int, c_int),
    ) {
        let mut seen = HashMap::new();
        for e in errors {
            if let Some(other) = seen.insert(code(e), e) {
                panic!("{e:?} has the code of {other:?}");
            }
            assert_eq!(strerror(code(e)).to_str(), Ok(message(e)), "{e:?}");
        }
        let unknown = strerror(last);
        assert!(!seen.contains_key(&last));
        for n in first..=last {
            let known = strerror(n) != unknown;
            let error = seen.contains_key(&n);
            assert!(!(ok.contains(&n) && error), "success {n} is an error's");
            assert_eq!(known, ok.contains(&n) || error, "code {n}");
        }
    }

    /// The errors of each API, the core's and those only the shim
    /// produces together, are exactly the codes C's tables have a string
    /// for: none is lost, none moves.
    #[test]
    fn errors_are_every_c_code() {
        let easy = ErrorKind::ALL.iter().map(|&k| EasyError::Core(k));
        covers(
            easy.chain(EasyError::SHIM_ONLY.iter().copied()),
            |e| easy_code(e).0,
            EasyError::message,
            |n| easy_strerror(CURLcode(n)),
            &[ffi::CURLE_OK.0],
            (0, ffi::CURL_LAST.0),
        );
        let multi = MultiErrorKind::ALL.iter().map(|&k| MultiError::Core(k));
        covers(
            multi.chain(MultiError::SHIM_ONLY.iter().copied()),
            |e| multi_code(e).0,
            MultiError::message,
            |n| multi_strerror(CURLMcode(n)),
            &[ffi::CURLM_OK.0, ffi::CURLM_CALL_MULTI_PERFORM.0],
            (ffi::CURLM_CALL_MULTI_PERFORM.0, ffi::CURLM_LAST.0),
        );
        covers(
            ShareError::SHIM_ONLY.iter().copied(),
            |e| share_code(e).0,
            ShareError::message,
            |n| share_strerror(CURLSHcode(n)),
            &[ffi::CURLSHE_OK.0],
            (0, ffi::CURLSHE_LAST.0),
        );
        covers(
            UrlErrorKind::ALL.iter().copied(),
            |e| url_code(e).0,
            UrlErrorKind::message,
            |n| url_strerror(CURLUcode(n)),
            &[ffi::CURLUE_OK.0],
            (0, ffi::CURLUE_LAST.0),
        );
    }
}
