//! `curl_easy_setopt` (`lib/setopt.c`): each option's C argument checked
//! as C checks it and turned into the core's options, or into the
//! callbacks and settings the shim keeps for the adapters.
//!
//! An option the shim does not implement yet is `CURLE_NOT_BUILT_IN` if
//! libcurl knows its id, and `CURLE_UNKNOWN_OPTION` if not, as C answers
//! for options a build leaves out and for ids nobody defined.

#![allow(unsafe_code)]

#[rustfmt::skip]
mod known;

use core::ffi::{CStr, VaList, c_char, c_int, c_long, c_void};
use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use core::ptr::NonNull;

use curl_alloc::{OutOfMemory, TryRc, TryVec as _};
use curl_core::error::ErrorKind;
use curl_core::options::{
    ContinueWait, EyeballsDelay, FileMode, Follow, HttpVersion, IpVersion, Lines, LowSpeed,
    MaxRedirects, Method, Options, PostRedir, ProxyType, Resume, ReuseLimits, UserHeaders,
};
use curl_core::time::TimeLimit;

use crate::callbacks::{self, CCallbacks, CSettings, PostFields};
use crate::easy::{self, ShimEasy};
use crate::ffi::{
    self, CURL, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_NOT_BUILT_IN, CURLE_OK, CURLE_OUT_OF_MEMORY,
    CURLE_RECURSIVE_API_CALL, CURLE_UNKNOWN_OPTION, CURLcode, CURLoption, curl_off_t,
};
use crate::gate::EasyCall;

/// C's longest string option (`CURL_MAX_INPUT_LENGTH`).
const MAX_INPUT_LENGTH: usize = 8_000_000;

/// A function pointer passed through varargs as a pointer.
///
/// # Safety
///
/// `p` is NULL or a function of the type `F`, an `Option` of a function
/// pointer, describes.
pub(crate) unsafe fn function<F: Copy>(p: *mut c_void) -> F {
    assert_eq!(
        size_of::<F>(),
        size_of::<*mut c_void>(),
        "a function pointer"
    );
    // SAFETY: `F` is a nullable function pointer the size of `p`, and NULL
    // is its `None`, as the caller guarantees.
    unsafe { core::mem::transmute_copy(&p) }
}

/// The C argument an option takes, by its id's class (`CURLOPTTYPE_*`).
enum Arg {
    Long(c_long),
    Ptr(*mut c_void),
    Off(curl_off_t),
}

/// A checked change that failed.
enum Refused {
    Bad,
    OutOfMemory,
    NotBuiltIn,
    Unknown,
    /// A protocol, or a version of one, this build leaves out.
    Unsupported,
    /// A value that decodes to a zero byte (`CURLE_URL_MALFORMAT`).
    Malformed,
}

impl From<OutOfMemory> for Refused {
    fn from(_: OutOfMemory) -> Refused {
        Refused::OutOfMemory
    }
}

/// The string at `p`, or none for NULL; one longer than C takes is refused.
///
/// # Safety
///
/// `p` is NULL or a C string.
unsafe fn string<'a>(p: *mut c_void) -> Result<Option<&'a [u8]>, Refused> {
    if p.is_null() {
        return Ok(None);
    }
    // SAFETY: as the caller guarantees.
    let s = unsafe { CStr::from_ptr(p.cast::<c_char>()) }.to_bytes();
    if s.len() > MAX_INPUT_LENGTH {
        return Err(Refused::Bad);
    }
    Ok(Some(s))
}

/// A `CURLAUTH_*` mask as methods (`httpauth`): the legacy Digest bit
/// read as Digest; NTLM, Negotiate, AWS SigV4 and HTTP signatures, which
/// this build lacks, left out; none left of a mask that had some, not
/// built in.
fn auth_methods(mask: core::ffi::c_ulong) -> Result<curl_core::options::AuthMethods, Refused> {
    use curl_core::options::AuthMethods;
    if mask == ffi::CURLAUTH_NONE {
        return Ok(AuthMethods::NONE);
    }
    let digest = ffi::CURLAUTH_DIGEST | ffi::CURLAUTH_DIGEST_IE;
    let mut methods = AuthMethods::NONE;
    for (bits, method) in [
        (ffi::CURLAUTH_BASIC, AuthMethods::BASIC),
        (digest, AuthMethods::DIGEST),
        (ffi::CURLAUTH_BEARER, AuthMethods::BEARER),
        (ffi::CURLAUTH_ONLY, AuthMethods::ONLY),
    ] {
        if mask & bits != 0 {
            methods = methods | method;
        }
    }
    if (methods & !AuthMethods::ONLY).is_empty() {
        return Err(Refused::NotBuiltIn);
    }
    Ok(methods)
}

/// The lines of the list at `p`, in order; a node without a string is
/// passed over.
///
/// # Safety
///
/// `p` is NULL or a `curl_slist` whose nodes and strings live through
/// the walk.
unsafe fn list_lines<'a>(p: *mut c_void) -> impl Iterator<Item = &'a [u8]> {
    let mut node = p.cast::<ffi::curl_slist>().cast_const();
    core::iter::from_fn(move || {
        loop {
            // SAFETY: as the caller guarantees, `node` is NULL or a node.
            let here = unsafe { node.as_ref() }?;
            node = here.next;
            if !here.data.is_null() {
                // SAFETY: a node's string is a C string.
                return Some(unsafe { CStr::from_ptr(here.data) }.to_bytes());
            }
        }
    })
}

/// The HTTP version a request asks for (`setopt_HTTP_VERSION`): HTTP/2
/// and HTTP/3 are not in this build.
fn http_version(n: c_long) -> Result<HttpVersion, Refused> {
    match n {
        ffi::CURL_HTTP_VERSION_1_0 => Ok(HttpVersion::Http10),
        ffi::CURL_HTTP_VERSION_NONE | ffi::CURL_HTTP_VERSION_1_1 => Ok(HttpVersion::Http11),
        n if n < ffi::CURL_HTTP_VERSION_NONE => Err(Refused::Bad),
        _ => Err(Refused::Unsupported),
    }
}

/// A copy of the string at `p`, or none for NULL.
///
/// # Safety
///
/// As `string`.
unsafe fn owned(p: *mut c_void) -> Result<Option<Vec<u8>>, Refused> {
    // SAFETY: as the caller guarantees.
    let Some(s) = (unsafe { string(p) })? else {
        return Ok(None);
    };
    let mut copy = Vec::new();
    copy.try_extend_from_slice(s)?;
    Ok(Some(copy))
}

/// A time limit of `n` units of `ms` milliseconds (`setopt_set_timeout_*`).
fn time_limit(n: c_long, ms: u64) -> Result<Option<TimeLimit>, Refused> {
    let n = u64::try_from(n).map_err(|_| Refused::Bad)?;
    Ok(TimeLimit::from_millis(n.saturating_mul(ms)))
}

/// A resume offset: -1 is the end, below is refused.
fn resume(n: i64) -> Result<Option<Resume>, Refused> {
    match n {
        -1 => Ok(Some(Resume::AtEnd)),
        i64::MIN..=-2 => Err(Refused::Bad),
        n => Ok(NonZeroU64::new(n as u64).map(Resume::At)),
    }
}

/// A size limit: zero is none, below is refused.
fn max_filesize(n: i64) -> Result<Option<NonZeroU64>, Refused> {
    u64::try_from(n)
        .map(NonZeroU64::new)
        .map_err(|_| Refused::Bad)
}

/// The low-speed rule, from its two halves.
fn low_speed(set: &CSettings) -> Option<LowSpeed> {
    Some(LowSpeed {
        limit: NonZeroU64::new(u64::try_from(set.low_speed_limit).ok()?)?,
        time: NonZeroU16::new(u16::try_from(set.low_speed_time).ok()?)?,
    })
}

/// A `long` as the 64 bits an offset has.
#[allow(
    clippy::useless_conversion,
    reason = "`c_long` is 32 bits on some targets"
)]
fn wide(n: c_long) -> i64 {
    i64::from(n)
}

/// The size of the body an upload sends: -1 for unknown, below is refused.
fn in_file_size(
    options: &mut Options,
    me: NonNull<ShimEasy>,
    set: &mut CSettings,
    n: i64,
) -> Result<(), Refused> {
    if n < -1 {
        return Err(Refused::Bad);
    }
    set.in_file_size = n;
    Ok(callbacks::sync_upload(options, me, set)?)
}

/// The size of the fields a POST sends: -1 for up to their zero byte,
/// below is refused; a copy shorter than it is dropped
/// (`CURLOPT_POSTFIELDSIZE`).
fn post_fields_size(
    options: &mut Options,
    me: NonNull<ShimEasy>,
    set: &mut CSettings,
    n: i64,
) -> Result<(), Refused> {
    if n < -1 {
        return Err(Refused::Bad);
    }
    {
        // SAFETY: the handle is alive while its options are set.
        let mut post = unsafe { me.as_ref() }.post.borrow_mut();
        if post.size < n && matches!(post.fields, PostFields::Copied(_)) {
            post.fields = PostFields::None;
        }
        post.size = n;
    }
    Ok(callbacks::sync_upload(options, me, set)?)
}

/// A copy of the fields at `p`: `size` bytes, or up to their zero byte
/// for -1, at most C's longest input; none for NULL
/// (`setopt_copypostfields`).
///
/// # Safety
///
/// `p` is NULL, or points to `size` readable bytes, or to a C string for
/// a `size` of -1.
unsafe fn copy_post_fields(p: *mut c_void, size: i64) -> Result<PostFields, Refused> {
    let Some(at) = NonNull::new(p.cast::<u8>()) else {
        return Ok(PostFields::None);
    };
    let fields = match usize::try_from(size) {
        // SAFETY: as the caller guarantees.
        Ok(n) => unsafe { core::slice::from_raw_parts(at.as_ptr(), n) },
        Err(_) => {
            // SAFETY: as the caller guarantees.
            let fields = unsafe { CStr::from_ptr(at.as_ptr().cast()) }.to_bytes();
            if fields.len() > MAX_INPUT_LENGTH {
                return Err(Refused::Bad);
            }
            fields
        }
    };
    let mut copy = Vec::new();
    copy.try_extend_from_slice(fields)?;
    Ok(PostFields::Copied(TryRc::try_new(copy)?))
}

/// Apply `option` with `arg` to the handle at `me`.
fn apply(
    me: NonNull<ShimEasy>,
    options: &mut Options,
    ccb: &mut CCallbacks,
    set: &mut CSettings,
    errbuf: &mut *mut c_char,
    option: CURLoption,
    arg: Arg,
) -> Result<(), Refused> {
    use Arg::{Long, Off, Ptr};
    match (option, arg) {
        (ffi::CURLOPT_VERBOSE, Long(n)) => options.output.verbose = n != 0,
        (ffi::CURLOPT_HEADER, Long(n)) => options.output.include_header = n != 0,
        (ffi::CURLOPT_NOPROGRESS, Long(n)) => {
            set.no_progress = n != 0;
            callbacks::sync_progress(options, me, set, ccb)?;
        }
        (ffi::CURLOPT_NOBODY, Long(n)) => {
            if n != 0 {
                options.method = Method::Head;
            } else if options.method == Method::Head {
                options.method = Method::Get;
            }
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_POST, Long(n)) => {
            options.method = if n != 0 { Method::Post } else { Method::Get };
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_HTTPGET, Long(n)) => {
            if n != 0 {
                options.method = Method::Get;
                callbacks::sync_upload(options, me, set)?;
            }
        }
        (ffi::CURLOPT_POSTFIELDS, Ptr(p)) => {
            let fields = NonNull::new(p.cast::<u8>()).map_or(PostFields::None, PostFields::App);
            // SAFETY: the handle is alive while its options are set.
            unsafe { me.as_ref() }.post.borrow_mut().fields = fields;
            options.method = Method::Post;
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_COPYPOSTFIELDS, Ptr(p)) => {
            // SAFETY: as above.
            let shim = unsafe { me.as_ref() };
            let size = shim.post.borrow().size;
            // SAFETY: the application passes its fields, a C string unless
            // a size was set, or NULL.
            let copied = unsafe { copy_post_fields(p, size) }?;
            shim.post.borrow_mut().fields = copied;
            options.method = Method::Post;
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_POSTFIELDSIZE, Long(n)) => post_fields_size(options, me, set, wide(n))?,
        (ffi::CURLOPT_POSTFIELDSIZE_LARGE, Off(n)) => post_fields_size(options, me, set, n)?,
        (ffi::CURLOPT_UPLOAD | ffi::CURLOPT_PUT, Long(n)) => {
            options.method = if n != 0 { Method::Upload } else { Method::Get };
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_PATH_AS_IS, Long(n)) => options.url_rules.path_as_is = n != 0,
        (ffi::CURLOPT_FAILONERROR, Long(n)) => options.http.fail_on_error = n != 0,
        (ffi::CURLOPT_KEEP_SENDING_ON_ERROR, Long(n)) => {
            options.http.keep_sending_on_error = n != 0;
        }
        (ffi::CURLOPT_FOLLOWLOCATION, Long(n)) => {
            options.http.follow = match n {
                0 => Follow::No,
                1 => Follow::All,
                2 => Follow::ObeyCode,
                3 => Follow::FirstOnly,
                _ => return Err(Refused::Bad),
            };
        }
        (ffi::CURLOPT_MAXREDIRS, Long(n)) => {
            // Below -1 refused, -1 no limit, past 32767 taken as it
            // (`value_range`).
            options.http.max_redirects = match n {
                ..-1 => return Err(Refused::Bad),
                -1 => MaxRedirects(None),
                n => MaxRedirects(Some(u16::try_from(n.min(0x7fff)).expect("clamped"))),
            };
        }
        (ffi::CURLOPT_POSTREDIR, Long(n)) => {
            // Below CURL_REDIR_GET_ALL refused; bits past 303's ignored.
            if n < 0 {
                return Err(Refused::Bad);
            }
            options.http.post_redirect = PostRedir {
                post301: n & 1 != 0,
                post302: n & 2 != 0,
                post303: n & 4 != 0,
            };
        }
        (ffi::CURLOPT_AUTOREFERER, Long(n)) => options.http.auto_referer = n != 0,
        (ffi::CURLOPT_UNRESTRICTED_AUTH, Long(n)) => options.http.unrestricted_auth = n != 0,
        (ffi::CURLOPT_HTTPAUTH, Long(n)) => {
            // The mask as C reads it, an `unsigned long`.
            options.http.auth =
                curl_core::options::HttpAuth(auth_methods(n as core::ffi::c_ulong)?);
        }
        (ffi::CURLOPT_EXPECT_100_TIMEOUT_MS, Long(n)) => {
            // Negative refused, past 65535 taken as it (`value_range`).
            let ms = u64::try_from(n).map_err(|_| Refused::Bad)?.min(0xffff);
            options.http.continue_wait = ContinueWait(std::time::Duration::from_millis(ms));
        }
        (ffi::CURLOPT_SSL_VERIFYPEER, Long(n)) => options.tls.verify_peer = n != 0,
        // 1 is taken as 2, as C takes it.
        (ffi::CURLOPT_SSL_VERIFYHOST, Long(n)) => options.tls.verify_host = n != 0,
        // Nothing here raises or catches a signal: it is kept to.
        (ffi::CURLOPT_NOSIGNAL, Long(_)) => {}
        (ffi::CURLOPT_HTTP09_ALLOWED, Long(n)) => options.http.allow_09 = n != 0,
        (ffi::CURLOPT_FILETIME, Long(n)) => options.filetime = n != 0,
        (ffi::CURLOPT_IGNORE_CONTENT_LENGTH, Long(n)) => {
            options.http.ignore_content_length = n != 0;
        }
        (ffi::CURLOPT_HTTP_TRANSFER_DECODING, Long(n)) => options.http.raw = n == 0,
        (ffi::CURLOPT_HTTP_VERSION, Long(n)) => options.http.version = http_version(n)?,
        (ffi::CURLOPT_DISALLOW_USERNAME_IN_URL, Long(n)) => {
            options.url_rules.disallow_user = n != 0;
        }
        (ffi::CURLOPT_TIMEOUT, Long(n)) => options.limits.total = time_limit(n, 1000)?,
        (ffi::CURLOPT_TIMEOUT_MS, Long(n)) => options.limits.total = time_limit(n, 1)?,
        (ffi::CURLOPT_CONNECTTIMEOUT, Long(n)) => options.limits.connect = time_limit(n, 1000)?,
        (ffi::CURLOPT_MAXAGE_CONN, Long(n)) => options.limits.reuse.max_idle = time_limit(n, 1000)?,
        (ffi::CURLOPT_MAXLIFETIME_CONN, Long(n)) => {
            options.limits.reuse.max_age = time_limit(n, 1000)?;
        }
        (ffi::CURLOPT_DNS_CACHE_TIMEOUT, Long(n)) => {
            // -1 keeps answers for ever; any other negative is refused.
            options.limits.reuse.dns_max_age = match n {
                -1 => None,
                n => Some(std::time::Duration::from_secs(
                    u64::try_from(n).map_err(|_| Refused::Bad)?,
                )),
            };
        }
        (ffi::CURLOPT_FORBID_REUSE, Long(n)) => options.limits.reuse.forbid = n != 0,
        (ffi::CURLOPT_FRESH_CONNECT, Long(n)) => options.limits.reuse.fresh = n != 0,
        (ffi::CURLOPT_MAXCONNECTS, Long(n)) => {
            // Negative refused, past `INT_MAX` taken as it, 0 the default.
            let n = u32::try_from(n.min(c_long::from(c_int::MAX))).map_err(|_| Refused::Bad)?;
            options.limits.reuse.max_connects =
                NonZeroU32::new(n).unwrap_or(ReuseLimits::default().max_connects);
        }
        (ffi::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS, Long(n)) => {
            let ms = u64::try_from(n).map_err(|_| Refused::Bad)?;
            options.limits.eyeballs = EyeballsDelay(std::time::Duration::from_millis(ms));
        }
        (ffi::CURLOPT_IPRESOLVE, Long(n)) => {
            options.ip_version = match n {
                ffi::CURL_IPRESOLVE_WHATEVER => IpVersion::Any,
                ffi::CURL_IPRESOLVE_V4 => IpVersion::V4,
                ffi::CURL_IPRESOLVE_V6 => IpVersion::V6,
                _ => return Err(Refused::Bad),
            }
        }
        (ffi::CURLOPT_CONNECTTIMEOUT_MS, Long(n)) => options.limits.connect = time_limit(n, 1)?,
        (ffi::CURLOPT_LOW_SPEED_LIMIT, Long(n)) => {
            if n < 0 {
                return Err(Refused::Bad);
            }
            set.low_speed_limit = n;
            options.limits.low_speed = low_speed(set);
        }
        (ffi::CURLOPT_LOW_SPEED_TIME, Long(n)) => {
            if n < 0 {
                return Err(Refused::Bad);
            }
            set.low_speed_time = n.min(c_long::from(u16::MAX));
            options.limits.low_speed = low_speed(set);
        }
        (ffi::CURLOPT_MAXFILESIZE, Long(n)) => {
            options.limits.max_filesize = max_filesize(wide(n))?;
        }
        (ffi::CURLOPT_MAXFILESIZE_LARGE, Off(n)) => options.limits.max_filesize = max_filesize(n)?,
        (ffi::CURLOPT_RESUME_FROM, Long(n)) => options.resume = resume(wide(n))?,
        (ffi::CURLOPT_RESUME_FROM_LARGE, Off(n)) => options.resume = resume(n)?,
        (ffi::CURLOPT_INFILESIZE, Long(n)) => in_file_size(options, me, set, wide(n))?,
        (ffi::CURLOPT_INFILESIZE_LARGE, Off(n)) => in_file_size(options, me, set, n)?,
        (ffi::CURLOPT_NEW_FILE_PERMS, Long(n)) => {
            let bits = u16::try_from(n).ok().and_then(FileMode::new);
            options.new_file_mode = bits.ok_or(Refused::Bad)?;
        }
        (ffi::CURLOPT_URL, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            options.set_url(unsafe { string(p) }?)?;
        }
        (ffi::CURLOPT_PORT, Long(n)) => {
            // 0 for the URL's own.
            let port = u16::try_from(n).map_err(|_| Refused::Bad)?;
            options.port = std::num::NonZeroU16::new(port);
        }
        (ffi::CURLOPT_CURLU, Ptr(p)) => {
            // SAFETY: the application passes a handle from `curl_url` or
            // NULL.
            let shared = unsafe { crate::url::shared(p.cast()) };
            options.set_shared_url(shared.cloned());
        }
        (ffi::CURLOPT_REFERER, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            options.http.referer = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_USERPWD, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            options.login = match unsafe { string(p) }? {
                Some(pair) => curl_core::options::Login::from_pair(pair)?,
                None => curl_core::options::Login::default(),
            };
        }
        (ffi::CURLOPT_USERNAME, Ptr(p)) => {
            // SAFETY: as above.
            options.login.user = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_PASSWORD, Ptr(p)) => {
            // SAFETY: as above.
            options.login.password = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_NETRC, Long(n)) => {
            options.netrc.mode = match n {
                ffi::CURL_NETRC_IGNORED => curl_core::options::NetrcMode::Ignored,
                ffi::CURL_NETRC_OPTIONAL => curl_core::options::NetrcMode::Optional,
                ffi::CURL_NETRC_REQUIRED => curl_core::options::NetrcMode::Required,
                _ => return Err(Refused::Bad),
            };
        }
        (ffi::CURLOPT_PROXY, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            options.proxy.url = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_PROXYUSERPWD, Ptr(p)) => {
            use curl_core::options::ProxyUserError;
            // SAFETY: as above.
            let pair = unsafe { string(p) }?;
            options.proxy.set_user_password(pair).map_err(|e| match e {
                ProxyUserError::OutOfMemory => Refused::OutOfMemory,
                ProxyUserError::Malformed => Refused::Malformed,
            })?;
        }
        (ffi::CURLOPT_PROXYUSERNAME, Ptr(p)) => {
            // SAFETY: as above.
            options.proxy.user = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_PROXYPASSWORD, Ptr(p)) => {
            // SAFETY: as above.
            options.proxy.password = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_PROXYAUTH, Long(n)) => {
            // As `CURLOPT_HTTPAUTH`.
            options.proxy.auth =
                curl_core::options::HttpAuth(auth_methods(n as core::ffi::c_ulong)?);
        }
        (ffi::CURLOPT_NOPROXY, Ptr(p)) => {
            // SAFETY: as above.
            options.proxy.no_proxy = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_PROXYPORT, Long(n)) => {
            let port = u16::try_from(n).map_err(|_| Refused::Bad)?;
            options.proxy.port = NonZeroU16::new(port);
        }
        (ffi::CURLOPT_PROXYTYPE, Long(n)) => {
            options.proxy.kind = match n {
                ffi::CURLPROXY_HTTP => ProxyType::Http,
                ffi::CURLPROXY_HTTP_1_0 => ProxyType::Http10,
                ffi::CURLPROXY_HTTPS => ProxyType::Https,
                ffi::CURLPROXY_HTTPS2 => ProxyType::Https2,
                ffi::CURLPROXY_SOCKS4 => ProxyType::Socks4,
                ffi::CURLPROXY_SOCKS5 => ProxyType::Socks5,
                ffi::CURLPROXY_SOCKS4A => ProxyType::Socks4a,
                ffi::CURLPROXY_SOCKS5_HOSTNAME => ProxyType::Socks5Hostname,
                // Without an HTTP/3 proxy built in.
                ffi::CURLPROXY_HTTPS3 => return Err(Refused::NotBuiltIn),
                _ => return Err(Refused::Bad),
            };
        }
        (ffi::CURLOPT_HTTPPROXYTUNNEL, Long(n)) => options.proxy.tunnel = n != 0,
        (ffi::CURLOPT_NETRC_FILE, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            options.netrc.file = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_XOAUTH2_BEARER, Ptr(p)) => {
            // SAFETY: as above.
            options.login.bearer = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_CUSTOMREQUEST, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            options.http.custom_method = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_COOKIE, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            options.http.cookies.send = unsafe { owned(p) }?;
        }
        // NULL also forgets the jar, which `jar_option` does.
        // SAFETY: as above.
        (ffi::CURLOPT_COOKIEFILE, Ptr(p)) => match unsafe { string(p) }? {
            Some(name) => options.http.cookies.files.push(name)?,
            None => options.http.cookies.files = Lines::default(),
        },
        (ffi::CURLOPT_COOKIEJAR, Ptr(p)) => {
            // SAFETY: as above.
            options.http.cookies.save_to = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_COOKIESESSION, Long(n)) => options.http.cookies.new_session = n != 0,
        // On the jar alone, which `jar_option` reaches.
        (ffi::CURLOPT_COOKIELIST, Ptr(_)) => {}
        (ffi::CURLOPT_USERAGENT, Ptr(p)) => {
            // SAFETY: as above.
            options.http.user_agent = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_HTTPHEADER, Ptr(p)) => {
            // Copied: the core reads no list of the application's.
            // SAFETY: the application passes a list or NULL.
            options.http.headers = UserHeaders::new(unsafe { list_lines(p) })?;
            // A POST's body depends on its `Transfer-Encoding`.
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_CONNECT_TO, Ptr(p)) => {
            // SAFETY: the application passes a list or NULL.
            options.connect_to.set(unsafe { list_lines(p) })?;
        }
        (ffi::CURLOPT_RESOLVE, Ptr(p)) => {
            // SAFETY: the application passes a list or NULL.
            options.resolve.set(unsafe { list_lines(p) })?;
        }
        (ffi::CURLOPT_DEFAULT_PROTOCOL, Ptr(p)) => {
            // SAFETY: as above.
            options.set_default_protocol(unsafe { string(p) }?)?;
        }
        (ffi::CURLOPT_ERRORBUFFER, Ptr(p)) => {
            *errbuf = p.cast();
            callbacks::sync_error_buffer(options, me, *errbuf)?;
        }
        (ffi::CURLOPT_PRIVATE, Ptr(p)) => set.private = p,
        (ffi::CURLOPT_STDERR, Ptr(p)) => {
            ccb.stderr = if p.is_null() {
                callbacks::standard().2
            } else {
                p.cast()
            };
            callbacks::sync_text(options, me, ccb)?;
        }
        (ffi::CURLOPT_WRITEDATA, Ptr(p)) => ccb.write_data = p,
        (ffi::CURLOPT_HEADERDATA, Ptr(p)) => {
            ccb.header_data = p;
            callbacks::sync_text(options, me, ccb)?;
        }
        (ffi::CURLOPT_READDATA, Ptr(p)) => ccb.read_data = p,
        (ffi::CURLOPT_SEEKDATA, Ptr(p)) => ccb.seek_data = p,
        (ffi::CURLOPT_IOCTLDATA, Ptr(p)) => ccb.ioctl_data = p,
        (ffi::CURLOPT_XFERINFODATA, Ptr(p)) => ccb.progress_data = p,
        (ffi::CURLOPT_DEBUGDATA, Ptr(p)) => ccb.debug_data = p,
        (ffi::CURLOPT_TRAILERDATA, Ptr(p)) => ccb.trailer_data = p,
        (ffi::CURLOPT_TRAILERFUNCTION, Ptr(p)) => {
            // SAFETY: the application passes a function of the option's
            // type, or NULL.
            ccb.trailer = unsafe { function(p) };
            callbacks::sync_trailer(options, me, ccb)?;
        }
        // SAFETY: the application passes a function of the option's
        // type, or NULL.
        (ffi::CURLOPT_WRITEFUNCTION, Ptr(p)) => ccb.write = unsafe { function(p) },
        (ffi::CURLOPT_HEADERFUNCTION, Ptr(p)) => {
            // SAFETY: as above.
            ccb.header = unsafe { function(p) };
            callbacks::sync_text(options, me, ccb)?;
        }
        // SAFETY: as above.
        (ffi::CURLOPT_READFUNCTION, Ptr(p)) => ccb.read = unsafe { function(p) },
        // SAFETY: as above.
        (ffi::CURLOPT_SEEKFUNCTION, Ptr(p)) => ccb.seek = unsafe { function(p) },
        // SAFETY: as above.
        (ffi::CURLOPT_IOCTLFUNCTION, Ptr(p)) => ccb.ioctl = unsafe { function(p) },
        (ffi::CURLOPT_DEBUGFUNCTION, Ptr(p)) => {
            // SAFETY: as above.
            ccb.debug = unsafe { function(p) };
            callbacks::sync_text(options, me, ccb)?;
        }
        (ffi::CURLOPT_XFERINFOFUNCTION, Ptr(p)) => {
            // SAFETY: as above.
            ccb.xferinfo = unsafe { function(p) };
            callbacks::sync_progress(options, me, set, ccb)?;
        }
        (ffi::CURLOPT_PROGRESSFUNCTION, Ptr(p)) => {
            // SAFETY: as above.
            ccb.progress = unsafe { function(p) };
            callbacks::sync_progress(options, me, set, ccb)?;
        }
        (option, _) if known::KNOWN.binary_search(&option.0).is_ok() => {
            return Err(Refused::NotBuiltIn);
        }
        _ => return Err(Refused::Unknown),
    }
    Ok(())
}

/// The argument of `option`, read as its id's class says C passes it.
///
/// # Safety
///
/// The next argument in `args` is of the option's type.
unsafe fn read_arg(option: CURLoption, args: &mut VaList<'_>) -> Option<Arg> {
    Some(match option.0 / 10000 {
        // SAFETY: as the caller guarantees.
        0 => Arg::Long(unsafe { args.next_arg::<c_long>() }),
        // Objects, functions and blobs are all pointers.
        // SAFETY: as above.
        1 | 2 | 4 => Arg::Ptr(unsafe { args.next_arg::<*mut c_void>() }),
        // SAFETY: as above.
        3 => Arg::Off(unsafe { args.next_arg::<curl_off_t>() }),
        _ => return None,
    })
}

/// # Safety
///
/// `curl` is NULL or a live handle; the argument is of the option's type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_setopt(
    curl: *mut CURL,
    option: CURLoption,
    mut args: ...
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { easy::handle(curl) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(EasyCall::Setopt) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    // SAFETY: as the caller guarantees.
    let Some(arg) = (unsafe { read_arg(option, &mut args) }) else {
        return CURLE_UNKNOWN_OPTION;
    };
    if let (ffi::CURLOPT_SHARE, Arg::Ptr(sh)) = (option, &arg) {
        // SAFETY: the application passes a share or NULL.
        return match unsafe { crate::share::set(easy, *sh) } {
            Ok(()) => CURLE_OK,
            Err(_) => CURLE_BAD_FUNCTION_ARGUMENT,
        };
    }
    let jar = match (option, &arg) {
        (
            ffi::CURLOPT_COOKIEFILE | ffi::CURLOPT_COOKIEJAR | ffi::CURLOPT_COOKIELIST,
            Arg::Ptr(p),
        ) => Some(*p),
        _ => None,
    };
    let me = NonNull::from(easy);
    let (mut ccb, mut set, mut errbuf) = (easy.ccb.get(), easy.set.get(), easy.errbuf.get());
    let applied = easy.with_options(|o| apply(me, o, &mut ccb, &mut set, &mut errbuf, option, arg));
    let code = match applied {
        Ok(Ok(())) => CURLE_OK,
        Ok(Err(Refused::Bad)) => return CURLE_BAD_FUNCTION_ARGUMENT,
        Ok(Err(Refused::OutOfMemory)) => return CURLE_OUT_OF_MEMORY,
        Ok(Err(Refused::NotBuiltIn)) => return CURLE_NOT_BUILT_IN,
        Ok(Err(Refused::Unknown)) => return CURLE_UNKNOWN_OPTION,
        Ok(Err(Refused::Unsupported)) => return ffi::CURLE_UNSUPPORTED_PROTOCOL,
        Ok(Err(Refused::Malformed)) => return ffi::CURLE_URL_MALFORMAT,
        Err(_) => return CURLE_RECURSIVE_API_CALL,
    };
    // Kept only once the change is whole.
    easy.ccb.set(ccb);
    easy.set.set(set);
    easy.errbuf.set(errbuf);
    match jar {
        // SAFETY: the application passes a C string or NULL.
        Some(p) => unsafe { jar_option(easy, option, p) },
        None => code,
    }
}

/// What a cookie option does to the handle's jar, beyond its options.
///
/// # Safety
///
/// `p` is NULL or a C string.
unsafe fn jar_option(shim: &ShimEasy, option: CURLoption, p: *mut c_void) -> CURLcode {
    // SAFETY: as the caller guarantees; its length was checked with the
    // option.
    let given = unsafe { string(p) }.ok().flatten();
    let done = shim.with_easy(|e| {
        let easy = match e {
            easy::EasyRef::Easy(easy) => easy,
            // From a callback, only the options are reached: the jar the
            // files and the save name turn on is made as the next transfer
            // starts.
            easy::EasyRef::Frame(..) if option != ffi::CURLOPT_COOKIELIST => return Ok(()),
            easy::EasyRef::Frame(..) => return Err(ErrorKind::RecursiveApiCall),
        };
        match (option, given) {
            (ffi::CURLOPT_COOKIEFILE, None) => easy.forget_cookies(),
            (ffi::CURLOPT_COOKIEJAR, _) => easy.enable_cookies(),
            (ffi::CURLOPT_COOKIELIST, Some(command)) => return cookie_command(easy, command),
            _ => {}
        }
        Ok(())
    });
    match done {
        Ok(Ok(())) => CURLE_OK,
        Ok(Err(kind)) => crate::error_codes::easy_code(kind),
        Err(_) => CURLE_RECURSIVE_API_CALL,
    }
}

/// `CURLOPT_COOKIELIST`: a command, in any case, or a cookie to store.
fn cookie_command(easy: &mut curl_core::easy::Easy, command: &[u8]) -> Result<(), ErrorKind> {
    if command.eq_ignore_ascii_case(b"ALL") {
        easy.clear_cookies()
    } else if command.eq_ignore_ascii_case(b"SESS") {
        easy.clear_session_cookies()
    } else if command.eq_ignore_ascii_case(b"FLUSH") {
        // A jar that cannot be written fails nothing, as in C, which says
        // so only in the trace; outside a transfer, there is none here.
        easy.save_cookies().ok();
        Ok(())
    } else if command.eq_ignore_ascii_case(b"RELOAD") {
        easy.reload_cookies()
    } else {
        easy.add_cookie(command)
    }
}
const _: ffi::proto::curl_easy_setopt = curl_easy_setopt;

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated list is sorted, for the search, and holds the ids C
    /// defines, aliases' targets among them.
    #[test]
    fn knows_c_ids() {
        assert!(known::KNOWN.windows(2).all(|w| w[0] < w[1]));
        for id in [ffi::CURLOPT_URL, ffi::CURLOPT_PORT, ffi::CURLOPT_SSLCERT] {
            assert!(known::KNOWN.binary_search(&id.0).is_ok(), "{}", id.0);
        }
        assert!(known::KNOWN.binary_search(&9999).is_err());
    }

    #[test]
    fn checks_ranges_as_c() {
        assert!(matches!(resume(-2), Err(Refused::Bad)));
        assert!(matches!(resume(-1), Ok(Some(Resume::AtEnd))));
        assert!(matches!(resume(0), Ok(None)));
        assert!(matches!(max_filesize(-1), Err(Refused::Bad)));
        assert!(matches!(time_limit(-1, 1), Err(Refused::Bad)));
        assert_eq!(
            time_limit(2, 1000).ok().flatten().map(TimeLimit::duration),
            Some(std::time::Duration::from_secs(2))
        );
        let mut set = CSettings::new();
        set.low_speed_limit = 10;
        assert_eq!(low_speed(&set), None);
        set.low_speed_time = 3;
        assert!(low_speed(&set).is_some());
    }
}
