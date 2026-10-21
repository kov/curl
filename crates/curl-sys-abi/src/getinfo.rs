//! `curl_easy_getinfo` (`lib/getinfo.c`): what a transfer reports, in
//! the C types its `CURLINFO` asks for.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int, c_long, c_void};
use std::time::Duration;

use curl_core::report::TransferReport;
use curl_core::version::Protocol;

use crate::easy::{self, ShimEasy};
use crate::ffi::{
    self, CURL, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_OK, CURLE_RECURSIVE_API_CALL,
    CURLE_UNKNOWN_OPTION, CURLINFO, CURLcode, curl_off_t,
};
use crate::gate::EasyCall;

/// An answer in one of C's types.
enum Value {
    Long(c_long),
    Double(f64),
    Off(curl_off_t),
    Ptr(*mut c_void),
}

/// An answer in the type its info's number names.
enum Typed {
    Long(c_long),
    Double(f64),
    Off(curl_off_t),
    Str(*mut c_char),
}

impl Typed {
    /// # Safety
    ///
    /// `out` points at a writable value of this answer's type.
    unsafe fn write(self, out: *mut c_void) {
        /// # Safety
        ///
        /// As `write`, for `T`.
        unsafe fn put<T>(out: *mut c_void, v: T) {
            // SAFETY: as the caller guarantees.
            unsafe { out.cast::<T>().write(v) }
        }
        match self {
            // SAFETY: as the caller guarantees.
            Typed::Long(n) => unsafe { put(out, n) },
            // SAFETY: as the caller guarantees.
            Typed::Double(n) => unsafe { put(out, n) },
            // SAFETY: as the caller guarantees.
            Typed::Off(n) => unsafe { put(out, n) },
            // SAFETY: as the caller guarantees.
            Typed::Str(p) => unsafe { put(out, p) },
        }
    }
}

/// A time in a `long`, clamped as C clamps it where `long` is 32 bits.
#[allow(
    clippy::unnecessary_fallible_conversions,
    reason = "`c_long` is 32 bits on some targets"
)]
fn long_time(t: i64) -> c_long {
    c_long::try_from(t).unwrap_or(if t < 0 { c_long::MIN } else { c_long::MAX })
}

fn off(n: u64) -> curl_off_t {
    curl_off_t::try_from(n).unwrap_or(curl_off_t::MAX)
}

fn micros(d: Duration) -> curl_off_t {
    curl_off_t::try_from(d.as_micros()).unwrap_or(curl_off_t::MAX)
}

/// Seconds, from whole microseconds as C keeps them (`DOUBLE_SECS`).
fn secs(d: Duration) -> f64 {
    micros(d) as f64 / 1_000_000.0
}

/// C's protocol bit (`CURLPROTO_*`).
fn proto_bit(p: Protocol) -> c_long {
    match p {
        Protocol::File => ffi::CURLPROTO_FILE,
        Protocol::Http => ffi::CURLPROTO_HTTP,
    }
}

/// What `info` asks of the transfer, or none for one not known.
fn value(easy: &ShimEasy, r: &TransferReport, info: CURLINFO) -> Option<Value> {
    let t = r.timings();
    let (sizes, speeds) = (r.sizes(), r.speeds());
    let length = |n: Option<u64>| n.map_or(-1, off);
    Some(match info {
        ffi::CURLINFO_PRIVATE => Value::Ptr(easy.set.get().private),
        // No protocol yet has a response code.
        ffi::CURLINFO_RESPONSE_CODE => Value::Long(0),
        ffi::CURLINFO_FILETIME => Value::Long(r.filetime().map_or(-1, long_time)),
        ffi::CURLINFO_FILETIME_T => Value::Off(r.filetime().unwrap_or(-1)),
        ffi::CURLINFO_PROTOCOL => Value::Long(r.protocol().map_or(0, proto_bit)),
        ffi::CURLINFO_TOTAL_TIME => Value::Double(secs(t.total())),
        ffi::CURLINFO_NAMELOOKUP_TIME => Value::Double(secs(t.namelookup())),
        ffi::CURLINFO_CONNECT_TIME => Value::Double(secs(t.connect())),
        ffi::CURLINFO_APPCONNECT_TIME => Value::Double(secs(t.appconnect())),
        ffi::CURLINFO_PRETRANSFER_TIME => Value::Double(secs(t.pretransfer())),
        ffi::CURLINFO_STARTTRANSFER_TIME => Value::Double(secs(t.starttransfer())),
        ffi::CURLINFO_REDIRECT_TIME => Value::Double(secs(t.redirect())),
        ffi::CURLINFO_TOTAL_TIME_T => Value::Off(micros(t.total())),
        ffi::CURLINFO_NAMELOOKUP_TIME_T => Value::Off(micros(t.namelookup())),
        ffi::CURLINFO_CONNECT_TIME_T => Value::Off(micros(t.connect())),
        ffi::CURLINFO_APPCONNECT_TIME_T => Value::Off(micros(t.appconnect())),
        ffi::CURLINFO_PRETRANSFER_TIME_T => Value::Off(micros(t.pretransfer())),
        ffi::CURLINFO_POSTTRANSFER_TIME_T => Value::Off(micros(t.posttransfer())),
        ffi::CURLINFO_STARTTRANSFER_TIME_T => Value::Off(micros(t.starttransfer())),
        ffi::CURLINFO_REDIRECT_TIME_T => Value::Off(micros(t.redirect())),
        ffi::CURLINFO_QUEUE_TIME_T => Value::Off(micros(t.queue())),
        ffi::CURLINFO_SIZE_UPLOAD => Value::Double(sizes.upload() as f64),
        ffi::CURLINFO_SIZE_UPLOAD_T => Value::Off(off(sizes.upload())),
        ffi::CURLINFO_SIZE_DOWNLOAD => Value::Double(sizes.download() as f64),
        ffi::CURLINFO_SIZE_DOWNLOAD_T => Value::Off(off(sizes.download())),
        ffi::CURLINFO_SIZE_DELIVERED => Value::Off(off(sizes.delivered())),
        ffi::CURLINFO_SPEED_DOWNLOAD => Value::Double(speeds.download() as f64),
        ffi::CURLINFO_SPEED_DOWNLOAD_T => Value::Off(off(speeds.download())),
        ffi::CURLINFO_SPEED_UPLOAD => Value::Double(speeds.upload() as f64),
        ffi::CURLINFO_SPEED_UPLOAD_T => Value::Off(off(speeds.upload())),
        ffi::CURLINFO_CONTENT_LENGTH_DOWNLOAD => {
            Value::Double(length(sizes.download_expected()) as f64)
        }
        ffi::CURLINFO_CONTENT_LENGTH_DOWNLOAD_T => Value::Off(length(sizes.download_expected())),
        ffi::CURLINFO_CONTENT_LENGTH_UPLOAD => {
            Value::Double(length(sizes.upload_expected()) as f64)
        }
        ffi::CURLINFO_CONTENT_LENGTH_UPLOAD_T => Value::Off(length(sizes.upload_expected())),
        _ => return None,
    })
}

/// # Safety
///
/// `curl` is NULL or a live handle; the argument points where a value of
/// the info's type may be written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_getinfo(
    curl: *mut CURL,
    info: CURLINFO,
    mut args: ...
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { easy::handle(curl) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(EasyCall::Getinfo) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    // Every type's argument is a pointer.
    // SAFETY: as the caller guarantees.
    let out = unsafe { args.next_arg::<*mut c_void>() };
    if out.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    let Ok(v) = easy.with_report(|r| value(easy, r, info)) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    let Some(v) = v else {
        return CURLE_UNKNOWN_OPTION;
    };
    // The info's number names its type; a value of another is a bug here.
    let kind = info.0 & ffi::CURLINFO_TYPEMASK;
    let typed = match v {
        Value::Long(n) if kind == ffi::CURLINFO_LONG => Typed::Long(n),
        Value::Double(n) if kind == ffi::CURLINFO_DOUBLE => Typed::Double(n),
        Value::Off(n) if kind == ffi::CURLINFO_OFF_T => Typed::Off(n),
        Value::Ptr(p) if kind == ffi::CURLINFO_STRING => Typed::Str(p.cast()),
        _ => unreachable!("info {} answered in the wrong type", info.0 as c_int),
    };
    // SAFETY: the application points at a value of the info's type, which
    // `typed` is.
    unsafe { typed.write(out) };
    CURLE_OK
}
const _: ffi::proto::curl_easy_getinfo = curl_easy_getinfo;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_c_s_units() {
        let d = Duration::from_micros(1_500_250);
        assert_eq!(micros(d), 1_500_250);
        assert_eq!(secs(d), 1.50025);
        assert_eq!(micros(Duration::MAX), curl_off_t::MAX);
        assert_eq!(proto_bit(Protocol::File), 1 << 10);
    }
}
