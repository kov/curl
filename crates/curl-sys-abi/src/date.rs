//! `curl_getdate` (`lib/parsedate.c`).

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char};

use curl_core::date;

use crate::ffi::{self, time_t};

/// The seconds since 1970 that the date `p` names, or -1 when it names
/// none, or a time `time_t` cannot hold. A date one second before 1970 is
/// given as 0, so that -1 means failure alone. `unused` is ignored, as C
/// ignores it.
///
/// # Safety
///
/// `p` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_getdate(p: *const c_char, unused: *const time_t) -> time_t {
    let _ = unused;
    if p.is_null() {
        return -1;
    }
    // SAFETY: a C string, as the caller guarantees.
    let text = unsafe { CStr::from_ptr(p) }.to_bytes();
    match date::parse(text).map(time_t::try_from) {
        Ok(Ok(-1)) => 0,
        Ok(Ok(t)) => t,
        Ok(Err(_)) | Err(_) => -1,
    }
}
const _: ffi::proto::curl_getdate = curl_getdate;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getdate_answers_as_c() {
        // SAFETY: C strings, or NULL.
        let get = |p: &CStr| unsafe { curl_getdate(p.as_ptr(), core::ptr::null()) };
        assert_eq!(get(c"Sun, 06 Nov 1994 08:49:37 GMT"), 784_111_777);
        assert_eq!(get(c"Thu, 31-Dec-1969 23:59:59 GMT"), 0);
        assert_eq!(get(c"Thu, 31-Dec-1969 23:59:58 GMT"), -2);
        assert_eq!(get(c"not a date"), -1);
        // SAFETY: NULL is allowed for both.
        let got = unsafe { curl_getdate(core::ptr::null(), core::ptr::null()) };
        assert_eq!(got, -1);
    }
}
