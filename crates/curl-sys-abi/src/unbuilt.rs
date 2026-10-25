//! The entry points of what this build leaves out, as C's build without
//! them has them: WebSockets (`CURL_DISABLE_WEBSOCKETS`), the headers of
//! a server push, which only a push callback is given and none is
//! called, and the export of TLS sessions (`USE_SSLS_EXPORT`). A program
//! linked against a libcurl with them loads, and is told they are not
//! built in.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_uint, c_void};
use core::ptr;

use crate::ffi::{
    self, CURL, CURLE_NOT_BUILT_IN, CURLcode, curl_off_t, curl_pushheaders, curl_ws_frame,
};

/// # Safety
///
/// Any arguments: none is read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_ws_recv(
    _curl: *mut CURL,
    _buffer: *mut c_void,
    _buflen: usize,
    _recv: *mut usize,
    _meta: *mut *const curl_ws_frame,
) -> CURLcode {
    CURLE_NOT_BUILT_IN
}
const _: ffi::proto::curl_ws_recv = curl_ws_recv;

/// # Safety
///
/// Any arguments: none is read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_ws_send(
    _curl: *mut CURL,
    _buffer: *const c_void,
    _buflen: usize,
    _sent: *mut usize,
    _fragsize: curl_off_t,
    _flags: c_uint,
) -> CURLcode {
    CURLE_NOT_BUILT_IN
}
const _: ffi::proto::curl_ws_send = curl_ws_send;

/// # Safety
///
/// Any arguments: none is read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_ws_start_frame(
    _curl: *mut CURL,
    _flags: c_uint,
    _frame_len: curl_off_t,
) -> CURLcode {
    CURLE_NOT_BUILT_IN
}
const _: ffi::proto::curl_ws_start_frame = curl_ws_start_frame;

/// # Safety
///
/// Any argument: it is not read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_ws_meta(_curl: *mut CURL) -> *const curl_ws_frame {
    ptr::null()
}
const _: ffi::proto::curl_ws_meta = curl_ws_meta;

/// # Safety
///
/// Any arguments: none is read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_pushheader_bynum(
    _h: *mut curl_pushheaders,
    _num: usize,
) -> *mut c_char {
    ptr::null_mut()
}
const _: ffi::proto::curl_pushheader_bynum = curl_pushheader_bynum;

/// # Safety
///
/// Any arguments: none is read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_pushheader_byname(
    _h: *mut curl_pushheaders,
    _name: *const c_char,
) -> *mut c_char {
    ptr::null_mut()
}
const _: ffi::proto::curl_pushheader_byname = curl_pushheader_byname;

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

    /// Each says it is not built in, or has nothing, as C's build
    /// without it does.
    #[test]
    fn what_is_left_out_says_so() {
        // SAFETY: none of the arguments is read.
        unsafe {
            let null = ptr::null_mut();
            assert_eq!(
                curl_ws_recv(null, null, 0, null.cast(), null.cast()),
                CURLE_NOT_BUILT_IN
            );
            assert_eq!(
                curl_ws_send(null, null, 0, null.cast(), 0, 0),
                CURLE_NOT_BUILT_IN
            );
            assert_eq!(curl_ws_start_frame(null, 0, 0), CURLE_NOT_BUILT_IN);
            assert!(curl_ws_meta(null).is_null());
            assert!(curl_pushheader_bynum(null.cast(), 0).is_null());
            assert!(curl_pushheader_byname(null.cast(), c"x".as_ptr()).is_null());
            assert_eq!(curl_easy_ssls_export(null, None, null), CURLE_NOT_BUILT_IN);
            let p = ptr::null();
            assert_eq!(
                curl_easy_ssls_import(null, p, p, 0, p, 0),
                CURLE_NOT_BUILT_IN
            );
        }
    }
}
