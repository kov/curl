//! `curl_easy_getinfo` (`lib/getinfo.c`): what a transfer reports, in
//! the C types its `CURLINFO` asks for.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int, c_long, c_void};
use std::net::IpAddr;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _, try_box};
use curl_core::conn::ProxyError;
use curl_core::options::AuthMethods;
use curl_core::report::{ResponseVersion, TransferReport};
use curl_core::version::Protocol;

use crate::easy::{self, EasyRef, ShimEasy, StringInfos};
use crate::ffi::{
    self, CURL, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_OK, CURLE_RECURSIVE_API_CALL,
    CURLE_UNKNOWN_OPTION, CURLINFO, CURLcode, curl_off_t,
};
use crate::gate::{EasyCall, Recursive};
use crate::strings::{curl_slist_append, curl_slist_free_all};

/// An answer in one of C's types.
enum Value {
    Long(c_long),
    Double(f64),
    Off(curl_off_t),
    Ptr(*mut c_void),
    /// A list the application frees.
    List(*mut ffi::curl_slist),
    /// A structure of the handle's (`CURLINFO_PTR`).
    Struct(*mut c_void),
    /// No answer, for this reason.
    Failed(CURLcode),
}

/// An answer in the type its info's number names.
enum Typed {
    Long(c_long),
    Double(f64),
    Off(curl_off_t),
    Str(*mut c_char),
    List(*mut ffi::curl_slist),
    Ptr(*mut c_void),
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
            // SAFETY: as the caller guarantees.
            Typed::List(p) => unsafe { put(out, p) },
            // SAFETY: as the caller guarantees.
            Typed::Ptr(p) => unsafe { put(out, p) },
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
/// Methods as a `CURLAUTH_*` mask.
pub(crate) fn auth_mask(methods: AuthMethods) -> c_long {
    [
        (AuthMethods::BASIC, ffi::CURLAUTH_BASIC),
        (AuthMethods::DIGEST, ffi::CURLAUTH_DIGEST),
        (AuthMethods::BEARER, ffi::CURLAUTH_BEARER),
        (AuthMethods::AWS_SIGV4, ffi::CURLAUTH_AWS_SIGV4),
        (AuthMethods::HTTPSIG, ffi::CURLAUTH_HTTPSIG),
    ]
    .into_iter()
    .filter(|&(method, _)| methods.contains(method))
    .fold(0, |mask, (_, bit)| mask | bit as c_long)
}

fn proto_bit(p: Protocol) -> c_long {
    match p {
        Protocol::File => ffi::CURLPROTO_FILE,
        Protocol::Http => ffi::CURLPROTO_HTTP,
        Protocol::Https => ffi::CURLPROTO_HTTPS,
    }
}

/// `text` with a zero byte after it, as C reads it.
fn c_string(text: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(text.len() + 1)
        .map_err(|_| OutOfMemory)?;
    copy.try_extend_from_slice(text)?;
    copy.try_push(0)?;
    Ok(copy)
}

/// `text` as C reads it, kept in the handle's string infos where `which`
/// says, with a zero byte after it; the infos are made the first time.
fn kept(
    easy: &ShimEasy,
    which: fn(&mut StringInfos) -> &mut Vec<u8>,
    text: &[u8],
) -> Result<*const c_char, OutOfMemory> {
    let mut infos = easy.string_infos.borrow_mut();
    if infos.is_none() {
        *infos = Some(try_box(StringInfos::default())?);
    }
    let kept = which(infos.as_deref_mut().expect("made above"));
    if kept.strip_suffix(b"\0") != Some(text) {
        *kept = c_string(text)?;
    }
    Ok(kept.as_ptr().cast())
}

/// An address as C writes it for the infos (`Curl_addr2string`): an
/// IPv6 one without brackets.
fn ip_text(ip: IpAddr) -> Result<Vec<u8>, OutOfMemory> {
    let text = curl_alloc::try_format(format_args!("{ip}"))?;
    let mut bytes = Vec::new();
    bytes.try_extend_from_slice(text.as_bytes())?;
    Ok(bytes)
}

/// A string info's pointer, or the failure to keep it.
fn string(p: Result<*const c_char, OutOfMemory>) -> Value {
    match p {
        Ok(p) => Value::Ptr(p.cast_mut().cast()),
        Err(OutOfMemory) => Value::Failed(ffi::CURLE_OUT_OF_MEMORY),
    }
}

/// The last request's method (`CURLINFO_EFFECTIVE_METHOD`): the
/// application's custom one if it set one, as `Easy::effective_method`.
fn effective_method(easy: &ShimEasy) -> Result<Option<Value>, Recursive> {
    let custom = easy.with_options(|o| {
        let custom = o.http.custom.method.as_deref();
        custom.map(|c| string(kept(easy, |i| &mut i.method, c)))
    })?;
    match custom {
        Some(v) => Ok(Some(v)),
        None => {
            easy.with_report(|r| Some(string(kept(easy, |i| &mut i.method, r.method().name()))))
        }
    }
}

/// The jar's cookies, a line each in the Netscape format, as a list the
/// application frees (`CURLINFO_COOKIELIST`); NULL for none, or where
/// the list cannot be made.
fn cookie_list(easy: &ShimEasy) -> Result<Option<Value>, Recursive> {
    let lines = easy.with_easy(|e| match e {
        EasyRef::Easy(easy) => easy.cookie_list().ok(),
        // From a callback the jar is not reached.
        EasyRef::Frame(..) => None,
    })?;
    Ok(Some(list_of(lines.iter().flatten())))
}

/// The TLS library's crypto engines, an id each, as a list the
/// application frees (`CURLINFO_SSL_ENGINES`); NULL for none, or where
/// the list cannot be made.
fn engines() -> Value {
    use curl_core::tls::TlsBackend as _;
    match curl_openssl::OPENSSL.engines() {
        Ok(ids) => list_of(ids.iter()),
        Err(OutOfMemory) => Value::List(core::ptr::null_mut()),
    }
}

/// `lines` as a list the application frees; NULL for none, or where the
/// list cannot be made.
fn list_of<'a>(lines: impl Iterator<Item = &'a Vec<u8>>) -> Value {
    let mut list = core::ptr::null_mut();
    for line in lines {
        let longer = c_string(line).ok().map(|text| {
            // SAFETY: `list` is one this function made, and `text` a C
            // string.
            unsafe { curl_slist_append(list, text.as_ptr().cast()) }
        });
        match longer.filter(|l| !l.is_null()) {
            Some(longer) => list = longer,
            None => {
                // SAFETY: as above; it is not used again.
                unsafe { curl_slist_free_all(list) };
                return Value::List(core::ptr::null_mut());
            }
        }
    }
    Value::List(list)
}

/// What `info` asks of the transfer, or none for one not known.
fn value(easy: &ShimEasy, r: &TransferReport, info: CURLINFO) -> Option<Value> {
    #[cfg(feature = "debug-hooks")]
    {
        use curl_core::report::debug_info;
        if let Some(v) = debug_value(info, debug_info::time(), debug_info::size()) {
            return Some(v);
        }
    }
    let t = r.timings();
    let (sizes, speeds) = (r.sizes(), r.speeds());
    let length = |n: Option<u64>| n.map_or(-1, off);
    Some(match info {
        // -1 before any.
        ffi::CURLINFO_CONN_ID => Value::Off(r.conn_number().map_or(-1, off)),
        ffi::CURLINFO_XFER_ID => Value::Off(r.transfer_number().map_or(-1, off)),
        ffi::CURLINFO_PRIVATE => Value::Ptr(easy.set.get().private),
        // Empty before any transfer.
        ffi::CURLINFO_EFFECTIVE_URL => string(kept(
            easy,
            |i| &mut i.effective_url,
            r.url().unwrap_or_default(),
        )),
        // None when no response gave one.
        ffi::CURLINFO_CONTENT_TYPE => match r.content_type() {
            Some(media) => string(kept(easy, |i| &mut i.content_type, media)),
            None => Value::Ptr(core::ptr::null_mut()),
        },
        // None when no request sent one.
        ffi::CURLINFO_REFERER => match r.referer() {
            Some(referer) => string(kept(easy, |i| &mut i.referer, referer)),
            None => Value::Ptr(core::ptr::null_mut()),
        },
        // None when no response pointed elsewhere, or one was followed.
        ffi::CURLINFO_REDIRECT_URL => match r.redirect_url() {
            Some(url) => string(kept(easy, |i| &mut i.redirect_url, url)),
            None => Value::Ptr(core::ptr::null_mut()),
        },
        // Empty, and ports of -1, before any connection.
        ffi::CURLINFO_PRIMARY_IP => match r.primary() {
            Some(ends) => string(
                ip_text(ends.remote.ip()).and_then(|t| kept(easy, |i| &mut i.primary_ip, &t)),
            ),
            None => string(kept(easy, |i| &mut i.primary_ip, b"")),
        },
        ffi::CURLINFO_LOCAL_IP => match r.primary().and_then(|ends| ends.local) {
            Some(local) => {
                string(ip_text(local.ip()).and_then(|t| kept(easy, |i| &mut i.local_ip, &t)))
            }
            None => string(kept(easy, |i| &mut i.local_ip, b"")),
        },
        ffi::CURLINFO_PRIMARY_PORT => Value::Long(
            r.primary()
                .map_or(-1, |ends| c_long::from(ends.remote.port())),
        ),
        ffi::CURLINFO_LOCAL_PORT => Value::Long(r.primary().map_or(-1, |ends| {
            ends.local.map_or(0, |local| c_long::from(local.port()))
        })),
        // The handle's, empty before any chain is reported.
        ffi::CURLINFO_CERTINFO => {
            let mut infos = easy.string_infos.borrow_mut();
            if infos.is_none() {
                match try_box(StringInfos::default()) {
                    Ok(made) => *infos = Some(made),
                    Err(OutOfMemory) => return Some(Value::Failed(ffi::CURLE_OUT_OF_MEMORY)),
                }
            }
            let kept = &mut infos.as_deref_mut().expect("made above").certinfo;
            match kept.view(r.certinfo()) {
                Ok(view) => Value::Struct(view.cast()),
                Err(OutOfMemory) => Value::Failed(ffi::CURLE_OUT_OF_MEMORY),
            }
        }
        ffi::CURLINFO_SSL_VERIFYRESULT => {
            Value::Long(c_long::try_from(r.verify_result()).unwrap_or(c_long::MAX))
        }
        ffi::CURLINFO_NUM_CONNECTS => Value::Long(c_long::from(r.connects())),
        ffi::CURLINFO_USED_PROXY => Value::Long(c_long::from(r.used_proxy())),
        ffi::CURLINFO_REDIRECT_COUNT => Value::Long(c_long::from(r.redirects())),
        ffi::CURLINFO_HTTPAUTH_AVAIL => Value::Long(auth_mask(r.auth_offered())),
        ffi::CURLINFO_HTTPAUTH_USED => Value::Long(auth_mask(r.auth_used())),
        ffi::CURLINFO_PROXYAUTH_AVAIL => Value::Long(auth_mask(r.proxy_auth_offered())),
        ffi::CURLINFO_PROXY_ERROR => Value::Long(r.proxy_error().map_or(0, proxy_code)),
        ffi::CURLINFO_OS_ERRNO => Value::Long(r.os_errno().map_or(0, |e| c_long::from(e.get()))),
        ffi::CURLINFO_PROXYAUTH_USED => Value::Long(auth_mask(r.proxy_auth_used())),
        ffi::CURLINFO_REQUEST_SIZE => {
            Value::Long(c_long::try_from(sizes.request()).unwrap_or(c_long::MAX))
        }
        ffi::CURLINFO_RESPONSE_CODE => Value::Long(r.response_code().map_or(0, c_long::from)),
        ffi::CURLINFO_HTTP_CONNECTCODE => Value::Long(r.connect_code().map_or(0, c_long::from)),
        ffi::CURLINFO_HTTP_VERSION => Value::Long(r.response_version().map_or(
            ffi::CURL_HTTP_VERSION_NONE,
            |v| match v {
                ResponseVersion::Http10 => ffi::CURL_HTTP_VERSION_1_0,
                ResponseVersion::Http11 => ffi::CURL_HTTP_VERSION_1_1,
                ResponseVersion::Http2 => ffi::CURL_HTTP_VERSION_2_0,
                ResponseVersion::Http3 => ffi::CURL_HTTP_VERSION_3,
            },
        )),
        ffi::CURLINFO_RETRY_AFTER => Value::Off(off(r.retry_after().map_or(0, |d| d.as_secs()))),
        ffi::CURLINFO_FILETIME => Value::Long(r.filetime().map_or(-1, long_time)),
        ffi::CURLINFO_CONDITION_UNMET => Value::Long(r.condition_unmet().into()),
        ffi::CURLINFO_FILETIME_T => Value::Off(r.filetime().unwrap_or(-1)),
        ffi::CURLINFO_PROTOCOL => Value::Long(r.protocol().map_or(0, proto_bit)),
        // The build's, whatever the transfer set.
        ffi::CURLINFO_CAINFO => Value::Ptr(crate::version::ca_defaults().0.cast_mut().cast()),
        ffi::CURLINFO_CAPATH => Value::Ptr(crate::version::ca_defaults().1.cast_mut().cast()),
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
        ffi::CURLINFO_HEADER_SIZE => {
            Value::Long(c_long::try_from(sizes.header()).unwrap_or(c_long::MAX))
        }
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

/// What the debug test build answers for `info`, given `CURL_TIME` and
/// `CURL_DEBUG_SIZE`, as C's `getinfo_long`, `getinfo_offt` and
/// `getinfo_double` do: a time as microseconds, or as seconds in a
/// double.
#[cfg(feature = "debug-hooks")]
fn debug_value(info: CURLINFO, time: Option<u64>, size: Option<u64>) -> Option<Value> {
    let long = |n: u64| Value::Long(c_long::try_from(n).unwrap_or(c_long::MAX));
    match info {
        ffi::CURLINFO_LOCAL_PORT => time.map(long),
        ffi::CURLINFO_HEADER_SIZE | ffi::CURLINFO_REQUEST_SIZE => size.map(long),
        ffi::CURLINFO_TOTAL_TIME_T
        | ffi::CURLINFO_NAMELOOKUP_TIME_T
        | ffi::CURLINFO_CONNECT_TIME_T
        | ffi::CURLINFO_APPCONNECT_TIME_T
        | ffi::CURLINFO_PRETRANSFER_TIME_T
        | ffi::CURLINFO_POSTTRANSFER_TIME_T
        | ffi::CURLINFO_QUEUE_TIME_T
        | ffi::CURLINFO_STARTTRANSFER_TIME_T
        | ffi::CURLINFO_REDIRECT_TIME_T
        | ffi::CURLINFO_SPEED_DOWNLOAD_T
        | ffi::CURLINFO_SPEED_UPLOAD_T => time.map(|n| Value::Off(off(n))),
        ffi::CURLINFO_TOTAL_TIME
        | ffi::CURLINFO_NAMELOOKUP_TIME
        | ffi::CURLINFO_CONNECT_TIME
        | ffi::CURLINFO_APPCONNECT_TIME
        | ffi::CURLINFO_PRETRANSFER_TIME
        | ffi::CURLINFO_STARTTRANSFER_TIME
        | ffi::CURLINFO_REDIRECT_TIME
        | ffi::CURLINFO_SPEED_DOWNLOAD
        | ffi::CURLINFO_SPEED_UPLOAD => time.map(|n| Value::Double(n as f64)),
        _ => None,
    }
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
    let v = if info == ffi::CURLINFO_EFFECTIVE_METHOD {
        effective_method(easy)
    } else if info == ffi::CURLINFO_COOKIELIST {
        cookie_list(easy)
    } else if info == ffi::CURLINFO_SSL_ENGINES {
        Ok(Some(engines()))
    } else {
        easy.with_report(|r| value(easy, r, info))
    };
    let Ok(v) = v else {
        return CURLE_RECURSIVE_API_CALL;
    };
    let Some(v) = v else {
        return CURLE_UNKNOWN_OPTION;
    };
    if let Value::Failed(code) = v {
        return code;
    }
    // The info's number names its type; a value of another is a bug here.
    let kind = info.0 & ffi::CURLINFO_TYPEMASK;
    let typed = match v {
        Value::Long(n) if kind == ffi::CURLINFO_LONG => Typed::Long(n),
        Value::Double(n) if kind == ffi::CURLINFO_DOUBLE => Typed::Double(n),
        Value::Off(n) if kind == ffi::CURLINFO_OFF_T => Typed::Off(n),
        Value::Ptr(p) if kind == ffi::CURLINFO_STRING => Typed::Str(p.cast()),
        Value::List(p) if kind == ffi::CURLINFO_SLIST => Typed::List(p),
        Value::Struct(p) if kind == ffi::CURLINFO_PTR => Typed::Ptr(p),
        Value::Failed(_) => unreachable!("returned above"),
        _ => unreachable!("info {} answered in the wrong type", info.0 as c_int),
    };
    // SAFETY: the application points at a value of the info's type, which
    // `typed` is.
    unsafe { typed.write(out) };
    CURLE_OK
}
const _: ffi::proto::curl_easy_getinfo = curl_easy_getinfo;

/// A SOCKS proxy's error as its `CURLproxycode`.
fn proxy_code(e: ProxyError) -> c_long {
    match e {
        ProxyError::BadAddressType => 1,
        ProxyError::BadVersion => 2,
        ProxyError::Closed => 3,
        ProxyError::Gssapi => 4,
        ProxyError::GssapiPermsg => 5,
        ProxyError::GssapiProtection => 6,
        ProxyError::Identd => 7,
        ProxyError::IdentdDiffer => 8,
        ProxyError::LongHostname => 9,
        ProxyError::LongPasswd => 10,
        ProxyError::LongUser => 11,
        ProxyError::NoAuth => 12,
        ProxyError::RecvAddress => 13,
        ProxyError::RecvAuth => 14,
        ProxyError::RecvConnect => 15,
        ProxyError::RecvReqack => 16,
        ProxyError::ReplyAddressTypeNotSupported => 17,
        ProxyError::ReplyCommandNotSupported => 18,
        ProxyError::ReplyConnectionRefused => 19,
        ProxyError::ReplyGeneralServerFailure => 20,
        ProxyError::ReplyHostUnreachable => 21,
        ProxyError::ReplyNetworkUnreachable => 22,
        ProxyError::ReplyNotAllowed => 23,
        ProxyError::ReplyTtlExpired => 24,
        ProxyError::ReplyUnassigned => 25,
        ProxyError::RequestFailed => 26,
        ProxyError::ResolveHost => 27,
        ProxyError::SendAuth => 28,
        ProxyError::SendConnect => 29,
        ProxyError::SendRequest => 30,
        ProxyError::UnknownFail => 31,
        ProxyError::UnknownMode => 32,
        ProxyError::UserRejected => 33,
    }
}

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

    /// The debug build's stand-ins, for the infos C's takes them for.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn debug_values_stand_in_as_c_s() {
        let answer = |info, time, size| match debug_value(info, time, size) {
            None => "none".to_string(),
            Some(Value::Long(n)) => format!("long {n}"),
            Some(Value::Off(n)) => format!("off {n}"),
            Some(Value::Double(n)) => format!("double {n}"),
            Some(_) => "other".to_string(),
        };
        let t = Some(13);
        assert_eq!(answer(ffi::CURLINFO_TOTAL_TIME_T, t, None), "off 13");
        assert_eq!(answer(ffi::CURLINFO_QUEUE_TIME_T, t, None), "off 13");
        assert_eq!(answer(ffi::CURLINFO_SPEED_UPLOAD_T, t, None), "off 13");
        assert_eq!(answer(ffi::CURLINFO_CONNECT_TIME, t, None), "double 13");
        assert_eq!(answer(ffi::CURLINFO_LOCAL_PORT, t, None), "long 13");
        assert_eq!(answer(ffi::CURLINFO_PRIMARY_PORT, t, None), "none");
        assert_eq!(
            answer(ffi::CURLINFO_HEADER_SIZE, t, Some(4019)),
            "long 4019"
        );
        assert_eq!(answer(ffi::CURLINFO_REQUEST_SIZE, None, Some(1)), "long 1");
        assert_eq!(answer(ffi::CURLINFO_HEADER_SIZE, t, None), "none");
        assert_eq!(answer(ffi::CURLINFO_TOTAL_TIME_T, None, Some(1)), "none");
    }
}
