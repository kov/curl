//! The entry points of what this build leaves out, as C's build without
//! them has them: the export of TLS sessions (`USE_SSLS_EXPORT`). A
//! program linked against a libcurl with them loads, and is told they
//! are not built in.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_void};

use crate::ffi::{self, CURL, CURLE_NOT_BUILT_IN, CURLcode};

/// # Safety
///
/// Any arguments: none is read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_ssls_export(
    _curl: *mut CURL,
    _export: Option<ffi::curl_ssls_export_cb>,
    _userptr: *mut c_void,
) -> CURLcode {
    CURLE_NOT_BUILT_IN
}
const _: ffi::proto::curl_easy_ssls_export = curl_easy_ssls_export;

/// # Safety
///
/// Any arguments: none is read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_ssls_import(
    _curl: *mut CURL,
    _session_key: *const c_char,
    _shmac: *const u8,
    _shmac_len: usize,
    _sdata: *const u8,
    _sdata_len: usize,
) -> CURLcode {
    CURLE_NOT_BUILT_IN
}
const _: ffi::proto::curl_easy_ssls_import = curl_easy_ssls_import;

#[cfg(test)]
#[allow(
    clippy::multiple_unsafe_ops_per_block,
    reason = "one contract covers each test's calls"
)]
mod tests {
    use super::*;
    use core::ptr;

    /// Each says it is not built in, or has nothing, as C's build
    /// without it does.
    #[test]
    fn what_is_left_out_says_so() {
        // SAFETY: none of the arguments is read.
        unsafe {
            let null = ptr::null_mut();
            assert_eq!(curl_easy_ssls_export(null, None, null), CURLE_NOT_BUILT_IN);
            let p = ptr::null();
            assert_eq!(
                curl_easy_ssls_import(null, ptr::null(), p, 0, p, 0),
                CURLE_NOT_BUILT_IN
            );
        }
    }
}
