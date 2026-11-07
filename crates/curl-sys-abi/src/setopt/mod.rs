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
mod proxy_tls;
mod tls;

use core::ffi::{CStr, VaList, c_char, c_int, c_long, c_uint, c_void};
use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use core::ptr::NonNull;
use core::time::Duration;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_format};
use curl_core::altsvc::{AltSvcCtrl, Versions};
use curl_core::cookie::LoadError;
use curl_core::easy::CacheFile;
use curl_core::error::ErrorKind;
use curl_core::handler::{Handler, LineSource};
use curl_core::hsts::LoadError as CacheLoadError;
use curl_core::options::{
    BufferSize, ColdGroup, ConnectOnly, ContinueWait, EyeballsDelay, FileMode, Follow, HttpVersion,
    IpVersion, Lines, LowSpeed, MaxRedirects, Method, Options, PostRedir, Protocols, ProxyType,
    Resume, ReuseLimits, Schemes, Sockets, TimeCondition, UpkeepInterval, UploadBufferSize,
    UploadFlags, UseSsl, UserHeaders,
};
use curl_core::options::{
    Ccc, CreateDirs, FtpMethod, RtspRequest, RtspSession, SslAuth, TftpBlockSize,
};
use curl_core::time::TimeLimit;
use curl_core::tls::TlsSupport;

use crate::callbacks::{self, CCallbacks, CSettings, PostFields};
use crate::easy::{self, PostBody, ShimEasy};
use crate::error_codes::EasyError;
use crate::ffi::{
    self, CURL, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_NOT_BUILT_IN, CURLE_OK, CURLE_OUT_OF_MEMORY,
    CURLE_RECURSIVE_API_CALL, CURLE_UNKNOWN_OPTION, CURLcode, CURLoption, curl_off_t,
};
use crate::gate::EasyCall;
use crate::sockets::{self, CSockets};
use crate::tls::CTls;

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
    /// A body read before could not be rewound (`CURLE_SEND_FAIL_REWIND`).
    Rewind,
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
/// read as Digest; NTLM, which this build lacks, left out as a C build
/// without it leaves it out, and Negotiate likewise unless the build
/// claims `spnego`; any other bit below `CURLAUTH_ONLY` this build does
/// not implement kept as `OTHER`, and bits past 32 dropped, as C stores
/// the mask in 32 bits. A mask with no bit below `CURLAUTH_ONLY` left,
/// but for one of none, is not built in.
fn auth_methods(
    mask: core::ffi::c_ulong,
    spnego: bool,
) -> Result<curl_core::options::AuthMethods, Refused> {
    use curl_core::options::AuthMethods;
    if mask == ffi::CURLAUTH_NONE {
        return Ok(AuthMethods::NONE);
    }
    let digest = ffi::CURLAUTH_DIGEST | ffi::CURLAUTH_DIGEST_IE;
    let lacking = if spnego {
        ffi::CURLAUTH_NTLM
    } else {
        ffi::CURLAUTH_NTLM | ffi::CURLAUTH_NEGOTIATE
    };
    let mut rest = mask & 0x7fff_ffff & !lacking;
    if rest == 0 {
        return Err(Refused::NotBuiltIn);
    }
    let mut methods = AuthMethods::NONE;
    for (bits, method) in [
        (ffi::CURLAUTH_BASIC, AuthMethods::BASIC),
        (digest, AuthMethods::DIGEST),
        (ffi::CURLAUTH_NEGOTIATE, AuthMethods::NEGOTIATE),
        (ffi::CURLAUTH_BEARER, AuthMethods::BEARER),
        (ffi::CURLAUTH_AWS_SIGV4, AuthMethods::AWS_SIGV4),
        (ffi::CURLAUTH_HTTPSIG, AuthMethods::HTTPSIG),
    ] {
        if rest & bits != 0 {
            methods = methods | method;
            rest &= !bits;
        }
    }
    if rest != 0 {
        methods = methods | AuthMethods::OTHER;
    }
    if mask & ffi::CURLAUTH_ONLY != 0 {
        methods = methods | AuthMethods::ONLY;
    }
    Ok(methods)
}

/// `CURLOPT_GSSAPI_DELEGATION`'s flags, the other bits ignored, as C
/// masks them; an option unknown where the build does not claim
/// `gssapi`, as C leaves it out (`HAVE_GSSAPI`).
fn delegation(n: c_long, gssapi: bool) -> Result<curl_core::options::Delegation, Refused> {
    if !gssapi {
        return Err(Refused::Unknown);
    }
    Ok(curl_core::options::Delegation {
        by_policy: n & ffi::CURLGSSAPI_DELEGATION_POLICY_FLAG != 0,
        always: n & ffi::CURLGSSAPI_DELEGATION_FLAG != 0,
    })
}

/// A switch only a GSS-API build has (`CURLOPT_SOCKS5_GSSAPI_NEC`):
/// unknown where the build does not claim `gssapi`.
fn gss_bool(n: c_long, gssapi: bool) -> Result<bool, Refused> {
    if !gssapi {
        return Err(Refused::Unknown);
    }
    Ok(n != 0)
}

/// Whether the build claims Kerberos, GSS-API's or SSPI's, which C decides
/// when it is built (`HAVE_GSSAPI || USE_WINDOWS_SSPI`, `USE_KERBEROS5`).
pub(crate) fn kerberos() -> bool {
    curl_core::version::version().claims("Kerberos")
}

/// Whether the build claims SPNEGO, which C decides when it is built
/// (`USE_SPNEGO`).
fn spnego() -> bool {
    curl_core::version::version().claims("SPNEGO")
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

/// The application's `curl_slist`, walked each time the core reads the
/// option it was given for: the application may append to it while the
/// handle keeps it, and keeps it alive until it sets another, clears the
/// option or cleans the handle up, as C's documentation of each list
/// option asks.
struct Slist(NonNull<ffi::curl_slist>);

// SAFETY: the list is the application's, walked only by the transfers of
// the handle it was given to and of its copies (`curl_easy_duphandle`
// copies the pointer, as C's does); C lets one thread use a handle at a
// time, and makes the application keep its list from changing while
// another handle reads it, as C reads it too.
unsafe impl Send for Slist {}
// SAFETY: as above; walking the list changes nothing.
unsafe impl Sync for Slist {}

impl LineSource for Slist {
    fn lines(
        &self,
        line: &mut dyn FnMut(&[u8]) -> Result<(), OutOfMemory>,
    ) -> Result<(), OutOfMemory> {
        // SAFETY: the application keeps the list and its strings alive
        // while the handle has it, as the option's contract says.
        for text in unsafe { list_lines(self.0.as_ptr().cast()) } {
            line(text)?;
        }
        Ok(())
    }
}

/// A source of the list at `p`, or none for NULL.
fn slist(p: *mut c_void) -> Result<Option<Handler<dyn LineSource>>, OutOfMemory> {
    NonNull::new(p.cast::<ffi::curl_slist>())
        .map(|list| Handler::lines(Slist(list)))
        .transpose()
}

/// The HTTP version a request asks for (`setopt_HTTP_VERSION`).
fn http_version(n: c_long) -> Result<HttpVersion, Refused> {
    match n {
        ffi::CURL_HTTP_VERSION_NONE => Ok(HttpVersion::Any),
        ffi::CURL_HTTP_VERSION_1_0 => Ok(HttpVersion::Http10),
        ffi::CURL_HTTP_VERSION_1_1 => Ok(HttpVersion::Http11),
        ffi::CURL_HTTP_VERSION_2_0 => Ok(HttpVersion::Http2),
        ffi::CURL_HTTP_VERSION_2TLS => Ok(HttpVersion::Http2Tls),
        ffi::CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE => Ok(HttpVersion::Http2Prior),
        ffi::CURL_HTTP_VERSION_3 => Ok(HttpVersion::Http3),
        ffi::CURL_HTTP_VERSION_3ONLY => Ok(HttpVersion::Http3Only),
        n if n < ffi::CURL_HTTP_VERSION_NONE => Err(Refused::Bad),
        _ => Err(Refused::Unsupported),
    }
}

/// The schemes of a `CURLPROTO_*` mask, as C's deprecated `long`
/// options take it: a bit no scheme has is ignored, and the bit SOCKS
/// shares names all its schemes.
fn protocol_mask(mask: c_long) -> Protocols {
    // Widened as C widens it to `curl_prot_t`: a negative one sets all.
    #[allow(
        clippy::useless_conversion,
        reason = "a `long` is 32 bits on some targets"
    )]
    let mask = i64::from(mask);
    curl_core::version::Protocol::ALL
        .into_iter()
        .filter(|p| mask & crate::protocols::BITS[p.index()] != 0)
        .map(Protocols::of_protocol)
        .fold(Protocols::NONE, Protocols::union)
}

/// The schemes a `CURLOPT_PROTOCOLS_STR` list names, separated by
/// commas, or `all` alone (`protocol2num`): one this build leaves out
/// is refused, as is a list that names none.
fn protocol_list(list: &[u8]) -> Result<Protocols, Refused> {
    if list.eq_ignore_ascii_case(b"all") {
        return Ok(Protocols::ALL);
    }
    let mut set = Protocols::NONE;
    for name in list.split(|&b| b == b',').filter(|name| !name.is_empty()) {
        set = set.union(Protocols::built(name).ok_or(Refused::Unsupported)?);
    }
    if set.is_empty() {
        return Err(Refused::Bad);
    }
    Ok(set)
}

/// Set the schemes `field` names to `set`, or to their default for none
/// (`CURLOPT_PROTOCOLS_STR` and its kin given NULL).
fn set_schemes(
    options: &mut Options,
    field: fn(&mut Schemes) -> &mut Protocols,
    set: Option<Protocols>,
) -> Result<(), Refused> {
    match set {
        Some(set) => *field(options.schemes.make_mut()?) = set,
        // A group never made holds the defaults already.
        None => {
            if let Some(schemes) = options.schemes.made_mut() {
                let mut defaults = Schemes::NONE;
                *field(schemes) = *field(&mut defaults);
            }
        }
    }
    Ok(())
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

/// A CA file, directory or blob as the application set it: NULL sets none,
/// and the build's default is not used either (`custom_cafile`,
/// `custom_cablob`).
fn ca_setting(value: Option<Vec<u8>>) -> curl_core::options::CaSetting {
    match value {
        Some(text) => curl_core::options::CaSetting::Given(text),
        None => curl_core::options::CaSetting::Unset,
    }
}

/// A copy of the blob at `p`, or none for NULL (`Curl_setblobopt`): one
/// without data, empty or longer than C takes is refused. It is copied
/// whatever its flags say, `CURL_BLOB_NOCOPY` too.
///
/// # Safety
///
/// `p` is NULL or a `curl_blob` whose `data` holds `len` bytes.
unsafe fn blob(p: *mut c_void) -> Result<Option<Vec<u8>>, Refused> {
    if p.is_null() {
        return Ok(None);
    }
    // SAFETY: as the caller guarantees.
    let blob = unsafe { p.cast::<ffi::curl_blob>().read() };
    if blob.data.is_null() || blob.len == 0 || blob.len > MAX_INPUT_LENGTH {
        return Err(Refused::Bad);
    }
    // SAFETY: as the caller guarantees, `data` holds `len` bytes.
    let data = unsafe { core::slice::from_raw_parts(blob.data.cast::<u8>(), blob.len) };
    let mut copy = Vec::new();
    copy.try_extend_from_slice(data)?;
    Ok(Some(copy))
}

/// The TLS versions of a `CURLOPT_SSLVERSION` value
/// (`Curl_setopt_SSLVERSION`): the oldest in the low 16 bits, the
/// newest in the next. SSL 2 and 3 are refused, and the default is TLS
/// 1.2. A newest of SSL 2 or 3, which C takes and its TLS library reads
/// as none, is refused too.
fn ssl_version(
    n: c_long,
) -> Result<
    (
        curl_core::options::TlsMinVersion,
        curl_core::options::TlsMaxVersion,
    ),
    Refused,
> {
    use curl_core::options::{TlsMaxVersion as Max, TlsMinVersion as Min};
    let min = match n & 0xffff {
        ffi::CURL_SSLVERSION_DEFAULT | ffi::CURL_SSLVERSION_TLSv1_2 => Min::Tls1_2,
        ffi::CURL_SSLVERSION_TLSv1 => Min::Tls1,
        ffi::CURL_SSLVERSION_TLSv1_0 => Min::Tls1_0,
        ffi::CURL_SSLVERSION_TLSv1_1 => Min::Tls1_1,
        ffi::CURL_SSLVERSION_TLSv1_3 => Min::Tls1_3,
        _ => return Err(Refused::Bad),
    };
    // As C reads it, an `unsigned long`.
    let max = match (n as core::ffi::c_ulong & 0xffff_0000) as c_long {
        ffi::CURL_SSLVERSION_MAX_NONE => Max::None,
        ffi::CURL_SSLVERSION_MAX_DEFAULT => Max::Default,
        ffi::CURL_SSLVERSION_MAX_TLSv1_0 => Max::Tls1_0,
        ffi::CURL_SSLVERSION_MAX_TLSv1_1 => Max::Tls1_1,
        ffi::CURL_SSLVERSION_MAX_TLSv1_2 => Max::Tls1_2,
        ffi::CURL_SSLVERSION_MAX_TLSv1_3 => Max::Tls1_3,
        _ => return Err(Refused::Bad),
    };
    Ok((min, max))
}

/// A time limit of `n` units of `ms` milliseconds (`setopt_set_timeout_*`).
fn time_limit(n: c_long, ms: u64) -> Result<Option<TimeLimit>, Refused> {
    let n = u64::try_from(n).map_err(|_| Refused::Bad)?;
    Ok(TimeLimit::from_millis(n.saturating_mul(ms)))
}

/// The list of FTP commands `option` sets: those before the transfer,
/// after it, or just before its data.
fn quote_list(line: &mut curl_core::options::Line, option: CURLoption) -> &mut Lines {
    match option {
        ffi::CURLOPT_QUOTE => &mut line.quote,
        ffi::CURLOPT_POSTQUOTE => &mut line.postquote,
        _ => &mut line.prequote,
    }
}

/// A resume offset: -1 is the end, below is refused.
fn resume(n: i64) -> Result<Option<Resume>, Refused> {
    match n {
        -1 => Ok(Some(Resume::AtEnd)),
        i64::MIN..=-2 => Err(Refused::Bad),
        n => Ok(curl_core::options::ResumeOffset::new(n as u64).map(Resume::At)),
    }
}

/// A size limit: zero is none, below is refused.
fn max_filesize(n: i64) -> Result<Option<NonZeroU64>, Refused> {
    u64::try_from(n)
        .map(NonZeroU64::new)
        .map_err(|_| Refused::Bad)
}

/// A speed limit in bytes a second: negative refused, 0 none.
fn speed(n: i64) -> Result<Option<NonZeroU64>, Refused> {
    max_filesize(n)
}

/// The low-speed rule, from its two halves.
fn low_speed(set: &CSettings) -> Option<LowSpeed> {
    Some(LowSpeed {
        limit: NonZeroU64::new(u64::try_from(set.low_speed_limit).ok()?)?,
        time: NonZeroU16::new(u16::try_from(set.low_speed_time).ok()?)?,
    })
}

/// A `CURLAUTH_*` mask as SOCKS5 methods (`CURLOPT_SOCKS5_AUTH`): Basic
/// and GSS-API alone built in, and `CURLAUTH_ONLY` refused without one.
fn socks5_auth(mask: core::ffi::c_ulong) -> Result<curl_core::options::Socks5Auth, Refused> {
    let (basic, gssapi) = (ffi::CURLAUTH_BASIC, ffi::CURLAUTH_GSSAPI);
    if mask & !(basic | gssapi | ffi::CURLAUTH_ONLY) != 0 {
        return Err(Refused::NotBuiltIn);
    }
    let only = mask & ffi::CURLAUTH_ONLY != 0;
    if only && mask & (basic | gssapi) == 0 {
        return Err(Refused::Bad);
    }
    Ok(curl_core::options::Socks5Auth {
        basic: mask & basic != 0,
        gssapi: mask & gssapi != 0,
        only,
    })
}

/// The time condition the two settings make together.
fn time_condition(set: &CSettings) -> Option<TimeCondition> {
    use curl_core::options::Condition;
    let when = match set.time_condition {
        ffi::CURL_TIMECOND_IFMODSINCE => Condition::ModifiedSince,
        ffi::CURL_TIMECOND_IFUNMODSINCE => Condition::UnmodifiedSince,
        ffi::CURL_TIMECOND_LASTMOD => Condition::LastModified,
        _ => return None,
    };
    Some(TimeCondition {
        when,
        time: set.time_value,
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
    Ok(PostFields::Copied(TryArc::try_new(copy)?))
}

/// Refuse `option` as not built in if it asks for what the TLS library,
/// which can do what `has` says, cannot, as C's `curl_easy_setopt` does
/// before it reads the value (`Curl_ssl_supports`, and the engine's
/// check of the library's id).
fn tls_supports(option: CURLoption, has: &TlsSupport) -> Result<(), Refused> {
    let supported = match option {
        ffi::CURLOPT_CAPATH | ffi::CURLOPT_PROXY_CAPATH => has.ca_path,
        ffi::CURLOPT_CAINFO_BLOB | ffi::CURLOPT_PROXY_CAINFO_BLOB => has.ca_blob,
        ffi::CURLOPT_CA_CACHE_TIMEOUT => has.ca_cache,
        ffi::CURLOPT_CERTINFO => has.cert_info,
        ffi::CURLOPT_PINNEDPUBLICKEY | ffi::CURLOPT_PROXY_PINNEDPUBLICKEY => has.pinned_key,
        ffi::CURLOPT_SSL_CTX_FUNCTION | ffi::CURLOPT_SSL_CTX_DATA => has.context_handler,
        ffi::CURLOPT_SSL_CIPHER_LIST | ffi::CURLOPT_PROXY_SSL_CIPHER_LIST => has.ciphers,
        ffi::CURLOPT_TLS13_CIPHERS | ffi::CURLOPT_PROXY_TLS13_CIPHERS => has.tls13_ciphers,
        ffi::CURLOPT_SSL_EC_CURVES => has.curves,
        ffi::CURLOPT_SSL_SIGNATURE_ALGORITHMS => has.signature_algorithms,
        ffi::CURLOPT_CRLFILE | ffi::CURLOPT_PROXY_CRLFILE => has.crl_file,
        ffi::CURLOPT_ISSUERCERT | ffi::CURLOPT_PROXY_ISSUERCERT => has.issuer_cert,
        ffi::CURLOPT_ISSUERCERT_BLOB | ffi::CURLOPT_PROXY_ISSUERCERT_BLOB => has.issuer_cert_blob,
        ffi::CURLOPT_ECH => has.ech,
        ffi::CURLOPT_SSL_VERIFYSTATUS | ffi::CURLOPT_DOH_SSL_VERIFYSTATUS => has.cert_status,
        ffi::CURLOPT_SSLENGINE | ffi::CURLOPT_SSLENGINE_DEFAULT => has.engines,
        _ => true,
    };
    if supported {
        Ok(())
    } else {
        Err(Refused::NotBuiltIn)
    }
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
    {
        use curl_core::tls::TlsBackend as _;
        tls_supports(option, &crate::tlslib::TLS.support())?;
    }
    match (option, arg) {
        (ffi::CURLOPT_VERBOSE, Long(n)) => options.output.verbose = n != 0,
        (ffi::CURLOPT_HEADER, Long(n)) => options.output.include_header = n != 0,
        (ffi::CURLOPT_NOPROGRESS, Long(n)) => {
            set.no_progress = n != 0;
            callbacks::sync_progress(options, me, set, ccb)?;
        }
        (ffi::CURLOPT_NOBODY, Long(n)) => {
            set.no_body = n != 0;
            if set.no_body {
                set.method = Method::Head;
            } else if set.method == Method::Head {
                set.method = Method::Get;
            }
            options.method = set.method();
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_POST, Long(n)) => {
            if n != 0 {
                set.method = Method::Post;
                set.no_body = false;
            } else {
                set.method = Method::Get;
            }
            options.method = set.method();
            // SAFETY: the handle is alive while its options are set.
            unsafe { me.as_ref() }.post_body.set(PostBody::Own);
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_MIMEPOST, Ptr(p)) => {
            // SAFETY: the application passes a tree from `curl_mime_init`
            // or NULL.
            match unsafe { crate::mime::set_post(me, p) } {
                Ok(()) => {}
                Err(crate::mime::Refused::Attached) => return Err(Refused::Bad),
                Err(crate::mime::Refused::Rewind) => return Err(Refused::Rewind),
                Err(crate::mime::Refused::OutOfMemory) => return Err(Refused::OutOfMemory),
            }
            // SAFETY: as above.
            let shim = unsafe { me.as_ref() };
            shim.post_body.set(PostBody::Mime);
            crate::mime::forget_post_state(shim);
            set.method = Method::Post;
            set.no_body = false;
            options.method = set.method();
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_HTTPPOST, Ptr(p)) => {
            // SAFETY: the handle is alive while its options are set.
            let shim = unsafe { me.as_ref() };
            // Made a tree again at the next request, even if the same.
            crate::mime::forget_post_state(shim);
            shim.posted_or_make()?.chain.set(p.cast());
            shim.post_body.set(PostBody::Form);
            set.method = Method::Post;
            set.no_body = false;
            options.method = set.method();
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_MIME_OPTIONS, Long(n)) => {
            // A group never made already says no.
            if n & ffi::CURLMIMEOPT_FORMESCAPE != 0 {
                options.mime.make_mut()?.form_escape = true;
            } else if let Some(m) = options.mime.made_mut() {
                m.form_escape = false;
            }
        }
        (ffi::CURLOPT_HTTPGET, Long(n)) => {
            if n != 0 {
                set.method = Method::Get;
                set.no_body = false;
                options.method = set.method();
                callbacks::sync_upload(options, me, set)?;
            }
        }
        (ffi::CURLOPT_POSTFIELDS, Ptr(p)) => {
            let fields = NonNull::new(p.cast::<u8>()).map_or(PostFields::None, PostFields::App);
            // SAFETY: the handle is alive while its options are set.
            let shim = unsafe { me.as_ref() };
            shim.post.borrow_mut().fields = fields;
            shim.post_body.set(PostBody::Own);
            // A body to post leaves no body asked for as it was.
            set.method = Method::Post;
            options.method = set.method();
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
            shim.post_body.set(PostBody::Own);
            set.method = Method::Post;
            options.method = set.method();
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_POSTFIELDSIZE, Long(n)) => post_fields_size(options, me, set, wide(n))?,
        (ffi::CURLOPT_POSTFIELDSIZE_LARGE, Off(n)) => post_fields_size(options, me, set, n)?,
        (ffi::CURLOPT_UPLOAD | ffi::CURLOPT_PUT, Long(n)) => {
            if n != 0 {
                set.method = Method::Upload;
                set.no_body = false;
            } else {
                // The opposite of an upload is a GET, or HEAD still if no
                // body was asked for.
                set.method = Method::Get;
            }
            options.method = set.method();
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
        (ffi::CURLOPT_PROTOCOLS, Long(n)) => {
            set_schemes(options, |s| &mut s.allowed, Some(protocol_mask(n)))?;
        }
        (ffi::CURLOPT_REDIR_PROTOCOLS, Long(n)) => {
            set_schemes(options, |s| &mut s.redirect, Some(protocol_mask(n)))?;
        }
        (ffi::CURLOPT_MAXREDIRS, Long(n)) => {
            // Below -1 refused, -1 no limit, past 32767 taken as it
            // (`value_range`).
            options.http.max_redirects = match n {
                ..-1 => return Err(Refused::Bad),
                -1 => MaxRedirects::UNLIMITED,
                n => MaxRedirects::clamped(u64::try_from(n).expect("not negative")),
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
        (ffi::CURLOPT_DNS_SERVERS, Ptr(p)) if !cfg!(feature = "threaded-resolver") => {
            // SAFETY: the application passes a C string or null.
            let v = unsafe { owned(p) }?;
            options.dns.set(|d| &mut d.servers, v)?;
        }
        (ffi::CURLOPT_DNS_INTERFACE, Ptr(p)) if !cfg!(feature = "threaded-resolver") => {
            // SAFETY: the application passes a C string or null.
            let v = unsafe { owned(p) }?;
            options.dns.set(|d| &mut d.interface, v)?;
        }
        (ffi::CURLOPT_DNS_LOCAL_IP4, Ptr(p)) if !cfg!(feature = "threaded-resolver") => {
            // SAFETY: the application passes a C string or null.
            let v = unsafe { owned(p) }?;
            options.dns.set(|d| &mut d.local_ip4, v)?;
        }
        (ffi::CURLOPT_DNS_LOCAL_IP6, Ptr(p)) if !cfg!(feature = "threaded-resolver") => {
            // SAFETY: the application passes a C string or null.
            let v = unsafe { owned(p) }?;
            options.dns.set(|d| &mut d.local_ip6, v)?;
        }
        (ffi::CURLOPT_DOH_URL, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let url = unsafe { owned(p) }?;
            options.doh.set(|d| &mut d.url, url)?;
        }
        (ffi::CURLOPT_DOH_SSL_VERIFYPEER, Long(n)) => {
            options.doh.make_mut()?.verify_peer = n != 0;
        }
        (ffi::CURLOPT_DOH_SSL_VERIFYHOST, Long(n)) => {
            options.doh.make_mut()?.verify_host = n != 0;
        }
        (ffi::CURLOPT_DOH_SSL_VERIFYSTATUS, Long(n)) => {
            options.doh.make_mut()?.verify_status = n != 0;
        }
        (ffi::CURLOPT_PIPEWAIT, Long(n)) => options.http.pipewait = n != 0,
        // Out of 1 to 256, the weight stays as it was (`CURLOPT_STREAM_WEIGHT`).
        (ffi::CURLOPT_STREAM_WEIGHT, Long(n)) => {
            if let Some(w) = u16::try_from(n)
                .ok()
                .filter(|w| (1..=256).contains(w))
                .and_then(std::num::NonZeroU16::new)
            {
                options.http.stream_weight = Some(w);
            }
        }
        // A stream's dependency on another handle's: taken, and not sent,
        // as C's HTTP/2 sends none (`h2_pri_spec`).
        (ffi::CURLOPT_STREAM_DEPENDS | ffi::CURLOPT_STREAM_DEPENDS_E, Ptr(_)) => {}
        (ffi::CURLOPT_UNRESTRICTED_AUTH, Long(n)) => options.http.unrestricted_auth = n != 0,
        (ffi::CURLOPT_HTTPAUTH, Long(n)) => {
            // The mask as C reads it, an `unsigned long`.
            options.http.auth =
                curl_core::options::HttpAuth(auth_methods(n as core::ffi::c_ulong, spnego())?);
        }
        (ffi::CURLOPT_EXPECT_100_TIMEOUT_MS, Long(n)) => {
            // Negative refused, past 65535 taken as it (`value_range`).
            let ms = u64::try_from(n).map_err(|_| Refused::Bad)?;
            options.http.continue_wait = ContinueWait::clamped(ms);
        }
        (ffi::CURLOPT_SSL_VERIFYPEER, Long(n)) => options.tls.verify_peer = n != 0,
        // 1 is taken as 2, as C takes it.
        (ffi::CURLOPT_SSL_VERIFYHOST, Long(n)) => options.tls.verify_host = n != 0,
        (ffi::CURLOPT_SSLVERSION, Long(n)) => {
            let (min, max) = ssl_version(n)?;
            let t = options.tls.options.make_mut()?;
            t.min_version = min;
            t.max_version = max;
        }
        // The low eight bits, as C keeps them.
        (ffi::CURLOPT_SSL_OPTIONS, Long(n)) => {
            options.tls.options.make_mut()?.ssl_options =
                curl_core::options::SslOptions::from_bits(n as u8);
        }
        (ffi::CURLOPT_SSL_ENABLE_ALPN, Long(n)) => options.tls.options.make_mut()?.alpn = n != 0,
        (ffi::CURLOPT_CA_CACHE_TIMEOUT, Long(n)) => {
            // -1 keeps the store for ever, 0 keeps none; below -1 is
            // refused, past `INT_MAX` taken as it (`value_range`).
            options.tls.options.make_mut()?.ca_cache = match n {
                -1 => curl_core::options::CaCache::Forever,
                0 => curl_core::options::CaCache::Off,
                n => curl_core::options::CaCache::For(std::time::Duration::from_secs(
                    u64::try_from(n.min(c_long::from(c_int::MAX))).map_err(|_| Refused::Bad)?,
                )),
            };
        }
        (ffi::CURLOPT_CAINFO, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let file = ca_setting(unsafe { owned(p) }?);
            options.tls.options.make_mut()?.ca_file = file;
        }
        (ffi::CURLOPT_CAPATH, Ptr(p)) => {
            // SAFETY: as above.
            let path = ca_setting(unsafe { owned(p) }?);
            options.tls.options.make_mut()?.ca_path = path;
        }
        // NULL too names the certificates (`custom_cablob`).
        (ffi::CURLOPT_CAINFO_BLOB, Ptr(p)) => {
            // SAFETY: the application passes a blob or NULL.
            let blob = ca_setting(unsafe { blob(p) }?);
            options.tls.options.make_mut()?.ca_blob = blob;
        }
        (ffi::CURLOPT_SSL_CIPHER_LIST, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.tls.options.set(|t| &mut t.ciphers, value)?;
        }
        (ffi::CURLOPT_TLS13_CIPHERS, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.tls.options.set(|t| &mut t.tls13_ciphers, value)?;
        }
        (ffi::CURLOPT_SSL_EC_CURVES, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.tls.options.set(|t| &mut t.curves, value)?;
        }
        (ffi::CURLOPT_SSL_SIGNATURE_ALGORITHMS, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options
                .tls
                .options
                .set(|t| &mut t.signature_algorithms, value)?;
        }
        // Nothing here raises or catches a signal: it is kept to.
        (ffi::CURLOPT_NOSIGNAL, Long(_)) => {}
        (ffi::CURLOPT_HTTP09_ALLOWED, Long(n)) => options.http.allow_09 = n != 0,
        (ffi::CURLOPT_FILETIME, Long(n)) => options.filetime = n != 0,
        (ffi::CURLOPT_CRLF, Long(n)) => options.crlf = n != 0,
        (ffi::CURLOPT_IGNORE_CONTENT_LENGTH, Long(n)) => {
            options.http.ignore_content_length = n != 0;
        }
        (ffi::CURLOPT_HTTP_TRANSFER_DECODING, Long(n)) => options.http.raw = n == 0,
        (ffi::CURLOPT_HTTP_CONTENT_DECODING, Long(n)) => options.http.raw_content = n == 0,
        (ffi::CURLOPT_TRANSFER_ENCODING, Long(n)) => options.http.transfer_encoding = n != 0,
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
        (ffi::CURLOPT_DNS_SHUFFLE_ADDRESSES, Long(n)) => options.dns_shuffle = n != 0,
        (ffi::CURLOPT_QUICK_EXIT, Long(n)) => options.quick_exit = n != 0,
        (ffi::CURLOPT_CONNECT_ONLY, Long(n)) => {
            options.connect_only = match n {
                0 => ConnectOnly::No,
                1 => ConnectOnly::Yes,
                2 => ConnectOnly::WebSocket,
                _ => return Err(Refused::Bad),
            };
        }
        // Bits it does not know are ignored, as C ignores them.
        (ffi::CURLOPT_WS_OPTIONS, Long(n)) => {
            options.ws = curl_core::options::WsOptions {
                raw: n & ffi::CURLWS_RAW_MODE != 0,
                no_auto_pong: n & ffi::CURLWS_NOAUTOPONG != 0,
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
        (ffi::CURLOPT_UPKEEP_INTERVAL_MS, Long(n)) => {
            let ms = u64::try_from(n).map_err(|_| Refused::Bad)?;
            options.limits.reuse.upkeep = UpkeepInterval(std::time::Duration::from_millis(ms));
        }
        (ffi::CURLOPT_IPRESOLVE, Long(n)) => {
            options.ip_version = match n {
                ffi::CURL_IPRESOLVE_WHATEVER => IpVersion::Any,
                ffi::CURL_IPRESOLVE_V4 => IpVersion::V4,
                ffi::CURL_IPRESOLVE_V6 => IpVersion::V6,
                _ => return Err(Refused::Bad),
            }
        }
        (ffi::CURLOPT_ADDRESS_SCOPE, Long(n)) => {
            // Read as an `unsigned long`: past `UINT_MAX` refused, a
            // negative among them, where it has more bits than an
            // `unsigned int` (not on Windows); 0 none.
            #[allow(clippy::useless_conversion, reason = "a long is 32 bits on Windows")]
            let n = u32::try_from(n as core::ffi::c_ulong).map_err(|_| Refused::Bad)?;
            options.address_scope = NonZeroU32::new(n);
        }
        (ffi::CURLOPT_CONNECTTIMEOUT_MS, Long(n)) => options.limits.connect = time_limit(n, 1)?,
        (ffi::CURLOPT_TIMECONDITION, Long(n)) => {
            #[allow(clippy::useless_conversion, reason = "a long is 32 bits on Windows")]
            let last = ffi::CURL_TIMECOND_LAST.0.into();
            if !(ffi::CURL_TIMECOND_NONE..last).contains(&n) {
                return Err(Refused::Bad);
            }
            set.time_condition = n;
            options.time_condition = time_condition(set);
        }
        (ffi::CURLOPT_TIMEVALUE, Long(n)) => {
            set.time_value = wide(n);
            options.time_condition = time_condition(set);
        }
        (ffi::CURLOPT_TIMEVALUE_LARGE, Off(n)) => {
            set.time_value = n;
            options.time_condition = time_condition(set);
        }
        (ffi::CURLOPT_LOW_SPEED_LIMIT, Long(n)) => {
            if n < 0 {
                return Err(Refused::Bad);
            }
            set.low_speed_limit = n;
            options.flow.set(|g| &mut g.low_speed, low_speed(set))?;
        }
        (ffi::CURLOPT_LOW_SPEED_TIME, Long(n)) => {
            if n < 0 {
                return Err(Refused::Bad);
            }
            set.low_speed_time = n.min(c_long::from(u16::MAX));
            options.flow.set(|g| &mut g.low_speed, low_speed(set))?;
        }
        (ffi::CURLOPT_MAXFILESIZE, Long(n)) => {
            options
                .flow
                .set(|g| &mut g.max_filesize, max_filesize(wide(n))?)?;
        }
        (ffi::CURLOPT_MAXFILESIZE_LARGE, Off(n)) => options
            .flow
            .set(|g| &mut g.max_filesize, max_filesize(n)?)?,
        (ffi::CURLOPT_BUFFERSIZE, Long(n)) => {
            let n = u64::try_from(n).map_err(|_| Refused::Bad)?;
            options.limits.buffer_size = BufferSize::clamped(n);
        }
        (ffi::CURLOPT_UPLOAD_BUFFERSIZE, Long(n)) => {
            let n = u64::try_from(n).map_err(|_| Refused::Bad)?;
            options.limits.upload_buffer = UploadBufferSize::clamped(n);
        }
        (ffi::CURLOPT_MAX_RECV_SPEED_LARGE, Off(n)) => {
            options.flow.set(|g| &mut g.max_recv_speed, speed(n)?)?
        }
        (ffi::CURLOPT_MAX_SEND_SPEED_LARGE, Off(n)) => {
            options.flow.set(|g| &mut g.max_send_speed, speed(n)?)?
        }
        (ffi::CURLOPT_RESUME_FROM, Long(n)) => options.resume = resume(wide(n))?,
        (ffi::CURLOPT_RESUME_FROM_LARGE, Off(n)) => options.resume = resume(n)?,
        (ffi::CURLOPT_RANGE, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            options.range = unsafe { owned(p) }?;
        }
        (ffi::CURLOPT_INFILESIZE, Long(n)) => in_file_size(options, me, set, wide(n))?,
        (ffi::CURLOPT_INFILESIZE_LARGE, Off(n)) => in_file_size(options, me, set, n)?,
        (ffi::CURLOPT_NEW_FILE_PERMS, Long(n)) => {
            let bits = u16::try_from(n).ok().and_then(FileMode::new);
            options.new_file_mode = bits.ok_or(Refused::Bad)?;
        }
        (ffi::CURLOPT_SSH_AUTH_TYPES, Long(n)) => {
            // As C keeps it, its low 32 bits.
            options.ssh.make_mut()?.auth_types =
                curl_core::options::SshAuthTypes::from_bits(n as u32);
        }
        (ffi::CURLOPT_NEW_DIRECTORY_PERMS, Long(n)) => {
            let bits = u16::try_from(n).ok().and_then(FileMode::new);
            options.ssh.make_mut()?.new_directory_mode = bits.ok_or(Refused::Bad)?;
        }
        (ffi::CURLOPT_SSH_COMPRESSION, Long(n)) => options.ssh.make_mut()?.compression = n != 0,
        (ffi::CURLOPT_SSH_PUBLIC_KEYFILE, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.ssh.set(|g| &mut g.public_key, value)?;
        }
        (ffi::CURLOPT_SSH_PRIVATE_KEYFILE, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.ssh.set(|g| &mut g.private_key, value)?;
        }
        (ffi::CURLOPT_SSH_HOST_PUBLIC_KEY_MD5, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.ssh.set(|g| &mut g.host_key_md5, value)?;
        }
        (ffi::CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.ssh.set(|g| &mut g.host_key_sha256, value)?;
        }
        (ffi::CURLOPT_SSH_KNOWNHOSTS, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.ssh.set(|g| &mut g.known_hosts, value)?;
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
            // Kept as given, read only as a transfer starts (`set.uh`,
            // `Host::start_url`): the application need not have a URL
            // handle behind it until then. Setting it clears the text URL.
            set.curlu = p.cast_const().cast();
            options.set_shared_url(None);
        }
        (ffi::CURLOPT_ACCEPT_ENCODING, Ptr(p)) => {
            use curl_core::coding::AcceptEncoding;
            // SAFETY: the application passes a C string or NULL.
            options.http.accept_encoding = unsafe { owned(p) }?.map(|value| {
                // Empty asks for every coding the handle undoes.
                if value.is_empty() {
                    AcceptEncoding::All
                } else {
                    AcceptEncoding::Given(value)
                }
            });
        }
        (ffi::CURLOPT_REFERER, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.http.custom.set(|g| &mut g.referer, value)?;
        }
        // The user and the password; the Bearer token stays, as in C.
        (ffi::CURLOPT_USERPWD, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let pair = match unsafe { string(p) }? {
                Some(pair) => curl_core::options::Login::from_pair(pair)?,
                None => curl_core::options::Login::default(),
            };
            options.login.set(|g| &mut g.user, pair.user)?;
            options.login.set(|g| &mut g.password, pair.password)?;
        }
        (ffi::CURLOPT_USERNAME, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.login.set(|g| &mut g.user, value)?;
        }
        (ffi::CURLOPT_PASSWORD, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.login.set(|g| &mut g.password, value)?;
        }
        (ffi::CURLOPT_NETRC, Long(n)) => {
            options.netrc.make_mut()?.mode = match n {
                ffi::CURL_NETRC_IGNORED => curl_core::options::NetrcMode::Ignored,
                ffi::CURL_NETRC_OPTIONAL => curl_core::options::NetrcMode::Optional,
                ffi::CURL_NETRC_REQUIRED => curl_core::options::NetrcMode::Required,
                _ => return Err(Refused::Bad),
            };
        }
        (ffi::CURLOPT_PROXY, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.proxy.set(|g| &mut g.url, value)?;
        }
        (ffi::CURLOPT_PROXYUSERPWD, Ptr(p)) => {
            use curl_core::options::ProxyUserError;
            // SAFETY: as above.
            match unsafe { string(p) }? {
                Some(pair) => options
                    .proxy
                    .make_mut()?
                    .set_user_password(Some(pair))
                    .map_err(|e| match e {
                        ProxyUserError::OutOfMemory => Refused::OutOfMemory,
                        ProxyUserError::Malformed => Refused::Malformed,
                    })?,
                None => {
                    options.proxy.set(|g| &mut g.user, None)?;
                    options.proxy.set(|g| &mut g.password, None)?;
                }
            }
        }
        (ffi::CURLOPT_PROXYUSERNAME, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.proxy.set(|g| &mut g.user, value)?;
        }
        (ffi::CURLOPT_PROXYPASSWORD, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.proxy.set(|g| &mut g.password, value)?;
        }
        (ffi::CURLOPT_PROXYAUTH, Long(n)) => {
            // As `CURLOPT_HTTPAUTH`.
            options.proxy.make_mut()?.auth =
                curl_core::options::HttpAuth(auth_methods(n as core::ffi::c_ulong, spnego())?);
        }
        (ffi::CURLOPT_SOCKS5_AUTH, Long(n)) => {
            options.proxy.make_mut()?.socks5_auth = socks5_auth(n as core::ffi::c_ulong)?;
        }
        (ffi::CURLOPT_PRE_PROXY, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.proxy.set(|g| &mut g.pre_proxy, value)?;
        }
        (ffi::CURLOPT_NOPROXY, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.proxy.set(|g| &mut g.no_proxy, value)?;
        }
        (ffi::CURLOPT_PROXYPORT, Long(n)) => {
            let port = u16::try_from(n).map_err(|_| Refused::Bad)?;
            options.proxy.make_mut()?.port = NonZeroU16::new(port);
        }
        (ffi::CURLOPT_PROXYTYPE, Long(n)) => {
            options.proxy.make_mut()?.kind = match n {
                ffi::CURLPROXY_HTTP => ProxyType::Http,
                ffi::CURLPROXY_HTTP_1_0 => ProxyType::Http10,
                ffi::CURLPROXY_HTTPS => ProxyType::Https,
                ffi::CURLPROXY_HTTPS2 => ProxyType::Https2,
                // Only where the build tunnels through HTTP/3 proxies
                // (`USE_PROXY_HTTP3`, OpenSSL's alone).
                ffi::CURLPROXY_HTTPS3 if !proxies_over_h3() => return Err(Refused::NotBuiltIn),
                ffi::CURLPROXY_HTTPS3 => ProxyType::Https3,
                ffi::CURLPROXY_SOCKS4 => ProxyType::Socks4,
                ffi::CURLPROXY_SOCKS5 => ProxyType::Socks5,
                ffi::CURLPROXY_SOCKS4A => ProxyType::Socks4a,
                ffi::CURLPROXY_SOCKS5_HOSTNAME => ProxyType::Socks5Hostname,
                _ => return Err(Refused::Bad),
            };
        }
        (ffi::CURLOPT_HTTPPROXYTUNNEL, Long(n)) => options.proxy.make_mut()?.tunnel = n != 0,
        (ffi::CURLOPT_HAPROXYPROTOCOL, Long(n)) => options.proxy.make_mut()?.haproxy = n != 0,
        // The service names are kept whether or not GSS-API is built, as
        // C keeps them: SASL reads the origin's too.
        (ffi::CURLOPT_SERVICE_NAME, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.login.set(|g| &mut g.service, value)?;
        }
        (ffi::CURLOPT_PROXY_SERVICE_NAME | ffi::CURLOPT_SOCKS5_GSSAPI_SERVICE, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.proxy.set(|g| &mut g.service, value)?;
        }
        (ffi::CURLOPT_GSSAPI_DELEGATION, Long(n)) => {
            let delegation = delegation(n, kerberos())?;
            options.login.make_mut()?.delegation = delegation;
        }
        (ffi::CURLOPT_SOCKS5_GSSAPI_NEC, Long(n)) => {
            let nec = gss_bool(n, kerberos())?;
            options.proxy.make_mut()?.socks5_gssapi_nec = nec;
        }
        (ffi::CURLOPT_HAPROXY_CLIENT_IP, Ptr(p)) => {
            // SAFETY: as above.
            let ip = unsafe { owned(p) }?;
            // Setting one turns the protocol on, clearing it off.
            let on = ip.is_some();
            options.proxy.set(|g| &mut g.haproxy_client_ip, ip)?;
            if let Some(proxy) = options.proxy.made_mut() {
                proxy.haproxy = on;
            }
        }
        (ffi::CURLOPT_SUPPRESS_CONNECT_HEADERS, Long(n)) => {
            options.proxy.make_mut()?.suppress_connect_headers = n != 0;
        }
        (ffi::CURLOPT_PROXY_TRANSFER_MODE, Long(n)) => {
            options.proxy.make_mut()?.transfer_mode = n != 0;
        }
        (ffi::CURLOPT_NETRC_FILE, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.netrc.set(|g| &mut g.file, value)?;
        }
        (ffi::CURLOPT_XOAUTH2_BEARER, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.login.set(|g| &mut g.bearer, value)?;
        }
        (ffi::CURLOPT_SASL_AUTHZID, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.login.set(|g| &mut g.authzid, value)?;
        }
        (ffi::CURLOPT_LOGIN_OPTIONS, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.line.set(|g| &mut g.login_options, value)?;
        }
        (ffi::CURLOPT_USE_SSL, Long(n)) => {
            let level = match n {
                0 => UseSsl::None,
                1 => UseSsl::Try,
                2 => UseSsl::Control,
                3 => UseSsl::All,
                _ => return Err(Refused::Bad),
            };
            options.line.make_mut()?.use_ssl = level;
        }
        (ffi::CURLOPT_MAIL_FROM, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.line.set(|g| &mut g.mail_from, value)?;
        }
        (ffi::CURLOPT_MAIL_AUTH, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.line.set(|g| &mut g.mail_auth, value)?;
        }
        // The application's list, walked as each mail is sent.
        (ffi::CURLOPT_MAIL_RCPT, Ptr(p)) => match slist(p)? {
            Some(source) => options.line.make_mut()?.mail_rcpt.set_source(source)?,
            None => {
                if let Some(line) = options.line.made_mut() {
                    line.mail_rcpt.set([])?;
                }
            }
        },
        // Brought within TFTP's bounds, 0 among them (`value_range`).
        (ffi::CURLOPT_TFTP_BLKSIZE, Long(n)) => {
            let n = u64::try_from(n).map_err(|_| Refused::Bad)?;
            options.small.make_mut()?.tftp_blksize = Some(TftpBlockSize::clamped(n));
        }
        (ffi::CURLOPT_TFTP_NO_OPTIONS, Long(n)) => {
            if n != 0 || options.small.made_mut().is_some() {
                options.small.make_mut()?.tftp_no_options = n != 0;
            }
        }
        // One of C's eleven, counted from 1 (`setopt_RTSP_REQUEST`).
        (ffi::CURLOPT_RTSP_REQUEST, Long(n)) => {
            let kind = usize::try_from(n)
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| RtspRequest::ALL.get(i))
                .ok_or(Refused::Bad)?;
            if *kind != RtspRequest::default() || options.small.made_mut().is_some() {
                options.small.make_mut()?.rtsp_request = *kind;
            }
        }
        // An id set is the application's, from no origin of a server's
        // (`Curl_peer_unlink`).
        (ffi::CURLOPT_RTSP_SESSION_ID, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options
                .small
                .set(|g| &mut g.rtsp_session, value.map(RtspSession::given))?;
        }
        (ffi::CURLOPT_RTSP_STREAM_URI, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.small.set(|g| &mut g.rtsp_stream_uri, value)?;
        }
        (ffi::CURLOPT_RTSP_TRANSPORT, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.small.set(|g| &mut g.rtsp_transport, value)?;
        }
        // The handle's numbers, not its options: `curl_easy_setopt` sets
        // them; here only checked (`value_range`).
        (ffi::CURLOPT_RTSP_CLIENT_CSEQ | ffi::CURLOPT_RTSP_SERVER_CSEQ, Long(n)) => {
            keepalive_value(n)?;
        }
        (ffi::CURLOPT_INTERLEAVEFUNCTION | ffi::CURLOPT_INTERLEAVEDATA, Ptr(p)) => {
            // SAFETY: the handle outlives the call; its interleave group
            // is a cell of its own, apart from the options being set.
            let room = unsafe { me.as_ref() }.interleave_room()?;
            let mut c = room.get();
            match option {
                ffi::CURLOPT_INTERLEAVEDATA => c.data = p,
                // SAFETY: the application passes a function of the
                // option's type, or NULL, which sends RTP to the write
                // function.
                _ => c.function = unsafe { function(p) },
            }
            callbacks::sync_interleave(options, me, &c)?;
            room.set(c);
        }
        // The application's list, walked as each TELNET transfer starts.
        (ffi::CURLOPT_TELNETOPTIONS, Ptr(p)) => match slist(p)? {
            Some(source) => options.small.make_mut()?.telnet.set_source(source)?,
            None => {
                if let Some(small) = options.small.made_mut() {
                    small.telnet.set([])?;
                }
            }
        },
        (ffi::CURLOPT_MAIL_RCPT_ALLOWFAILS, Long(n)) => {
            options.line.make_mut()?.mail_rcpt_allowfails = n != 0;
        }
        (ffi::CURLOPT_SASL_IR, Long(n)) => options.line.make_mut()?.sasl_ir = n != 0,
        (ffi::CURLOPT_DIRLISTONLY, Long(n)) => options.line.make_mut()?.list_only = n != 0,
        (ffi::CURLOPT_APPEND, Long(n)) => options.line.make_mut()?.ftp.append = n != 0,
        (ffi::CURLOPT_TRANSFERTEXT, Long(n)) => options.line.make_mut()?.ftp.ascii = n != 0,
        (ffi::CURLOPT_FTP_USE_EPRT, Long(n)) => options.line.make_mut()?.ftp.use_eprt = n != 0,
        (ffi::CURLOPT_FTP_USE_EPSV, Long(n)) => options.line.make_mut()?.ftp.use_epsv = n != 0,
        (ffi::CURLOPT_FTP_USE_PRET, Long(n)) => options.line.make_mut()?.ftp.use_pret = n != 0,
        (ffi::CURLOPT_WILDCARDMATCH, Long(n)) => options.line.make_mut()?.ftp.wildcard = n != 0,
        (ffi::CURLOPT_FTP_SKIP_PASV_IP, Long(n)) => {
            options.line.make_mut()?.ftp.skip_pasv_ip = n != 0;
        }
        (ffi::CURLOPT_FTP_FILEMETHOD, Long(n)) => {
            options.line.make_mut()?.ftp.method = match n {
                0 | 1 => FtpMethod::MultiCwd,
                2 => FtpMethod::NoCwd,
                3 => FtpMethod::SingleCwd,
                _ => return Err(Refused::Bad),
            };
        }
        (ffi::CURLOPT_FTP_SSL_CCC, Long(n)) => {
            options.line.make_mut()?.ftp.ssl_ccc = match n {
                0 => Ccc::None,
                1 => Ccc::Passive,
                2 => Ccc::Active,
                _ => return Err(Refused::Bad),
            };
        }
        (ffi::CURLOPT_FTPSSLAUTH, Long(n)) => {
            options.line.make_mut()?.ftp.ssl_auth = match n {
                0 => SslAuth::Default,
                1 => SslAuth::Ssl,
                2 => SslAuth::Tls,
                _ => return Err(Refused::Bad),
            };
        }
        (ffi::CURLOPT_ACCEPTTIMEOUT_MS, Long(n)) => {
            let limit = time_limit(n, 1)?;
            options.line.make_mut()?.ftp.accept_timeout = limit;
        }
        (ffi::CURLOPT_FTP_CREATE_MISSING_DIRS, Long(n)) => {
            options.line.make_mut()?.ftp.create_dirs = match n {
                0 => CreateDirs::No,
                1 => CreateDirs::Create,
                2 => CreateDirs::Retry,
                _ => return Err(Refused::Bad),
            };
        }
        (ffi::CURLOPT_FTPPORT, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.line.set(|g| &mut g.ftp.port, value)?;
        }
        (ffi::CURLOPT_FTP_ACCOUNT, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.line.set(|g| &mut g.ftp.account, value)?;
        }
        (ffi::CURLOPT_FTP_ALTERNATIVE_TO_USER, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options
                .line
                .set(|g| &mut g.ftp.alternative_to_user, value)?;
        }
        // The application's lists, walked as each transfer sends them.
        (ffi::CURLOPT_QUOTE | ffi::CURLOPT_POSTQUOTE | ffi::CURLOPT_PREQUOTE, Ptr(p)) => {
            match slist(p)? {
                Some(source) => quote_list(options.line.make_mut()?, option).set_source(source)?,
                None => {
                    if let Some(line) = options.line.made_mut() {
                        quote_list(line, option).set([])?;
                    }
                }
            }
        }
        (ffi::CURLOPT_UPLOAD_FLAGS, Long(n)) => {
            options.line.make_mut()?.upload_flags = upload_flags(n);
        }
        (ffi::CURLOPT_SERVER_RESPONSE_TIMEOUT, Long(n)) => {
            let limit = time_limit(n, 1000)?;
            options.line.set(|g| &mut g.server_response, limit)?;
        }
        (ffi::CURLOPT_SERVER_RESPONSE_TIMEOUT_MS, Long(n)) => {
            let limit = time_limit(n, 1)?;
            options.line.set(|g| &mut g.server_response, limit)?;
        }
        (ffi::CURLOPT_CUSTOMREQUEST, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.http.custom.set(|g| &mut g.method, value)?;
        }
        (ffi::CURLOPT_AWS_SIGV4, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let mut given = unsafe { owned(p) };
            if let Ok(params) = &mut given {
                options
                    .http
                    .signing
                    .set(|g| &mut g.aws_sigv4, params.take())?;
            }
            // Set, it is the one method; cleared, it is taken out of
            // those asked for: as the string stands, refused or not.
            let auth = &mut options.http.auth.0;
            *auth = match options.http.signing.aws_sigv4 {
                Some(_) => curl_core::options::AuthMethods::AWS_SIGV4,
                None => *auth & !curl_core::options::AuthMethods::AWS_SIGV4,
            };
            given?;
        }
        (ffi::CURLOPT_HTTPSIG_ALGORITHM, Long(n)) => {
            use curl_core::options::SignatureAlgorithm as A;
            let algorithm = match n {
                ffi::CURLHTTPSIG_NONE => None,
                ffi::CURLHTTPSIG_ED25519 => Some(A::Ed25519),
                ffi::CURLHTTPSIG_HMAC_SHA256 => Some(A::HmacSha256),
                _ => return Err(Refused::Bad),
            };
            options
                .http
                .signing
                .set(|g| &mut g.message.algorithm, algorithm)?;
            // Set, it is the one method; cleared, it is taken out of
            // those asked for.
            let auth = &mut options.http.auth.0;
            *auth = match algorithm {
                Some(_) => curl_core::options::AuthMethods::HTTPSIG,
                None => *auth & !curl_core::options::AuthMethods::HTTPSIG,
            };
        }
        (ffi::CURLOPT_HTTPSIG_KEY, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.http.signing.set(|g| &mut g.message.key, value)?;
        }
        (ffi::CURLOPT_HTTPSIG_KEYID, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options.http.signing.set(|g| &mut g.message.key_id, value)?;
        }
        (ffi::CURLOPT_HTTPSIG_HEADERS, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            options
                .http
                .signing
                .set(|g| &mut g.message.components, value)?;
        }
        (ffi::CURLOPT_REQUEST_TARGET, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.http.custom.set(|g| &mut g.target, value)?;
        }
        (ffi::CURLOPT_COOKIE, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            options.http.cookies.set(|g| &mut g.send, value)?;
        }
        // NULL also forgets the jar, which `jar_option` does.
        // SAFETY: as above.
        (ffi::CURLOPT_COOKIEFILE, Ptr(p)) => match unsafe { string(p) }? {
            Some(name) => options.http.cookies.make_mut()?.files.push(name)?,
            None => {
                if let Some(cookies) = options.http.cookies.made_mut() {
                    cookies.files = Lines::default();
                }
            }
        },
        (ffi::CURLOPT_COOKIEJAR, Ptr(p)) => {
            // SAFETY: as above.
            let value = unsafe { owned(p) }?;
            // Clearing a group never made makes nothing, as C allocates
            // nothing to clear an option; `jar_option` makes the jar.
            match value {
                Some(_) => options.http.cookies.make_mut()?.set_save_to(value),
                None => {
                    if let Some(cookies) = options.http.cookies.made_mut() {
                        cookies.set_save_to(None);
                    }
                }
            }
        }
        (ffi::CURLOPT_COOKIESESSION, Long(n)) => {
            options.http.cookies.make_mut()?.new_session = n != 0
        }
        // On the jar alone, which `jar_option` reaches; a line longer
        // than C takes, which no keyword is, refused first (`cookielist`).
        (ffi::CURLOPT_COOKIELIST, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            unsafe { string(p) }?;
        }
        (ffi::CURLOPT_USERAGENT, Ptr(p)) => {
            // SAFETY: as above.
            options.http.user_agent = unsafe { owned(p) }?;
        }
        // Each list is the application's, read as C walks it: the
        // headers as each request starts, CONNECT_TO as each connection
        // is looked for, RESOLVE as the next transfer starts.
        (ffi::CURLOPT_HTTPHEADER, Ptr(p)) => {
            options.http.headers = match slist(p)? {
                Some(source) => UserHeaders::from_source(source)?,
                None => UserHeaders::default(),
            };
            // A POST's body depends on its `Transfer-Encoding`.
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_PROXYHEADER, Ptr(p)) => match slist(p)? {
            Some(source) => options.proxy.make_mut()?.headers = UserHeaders::from_source(source)?,
            None => {
                if let Some(proxy) = options.proxy.made_mut() {
                    proxy.headers = UserHeaders::default();
                }
            }
        },
        // Any bit but `CURLHEADER_SEPARATE`'s is ignored, as in C.
        (ffi::CURLOPT_HEADEROPT, Long(n)) => {
            options.proxy.make_mut()?.unified_headers = n & ffi::CURLHEADER_SEPARATE == 0;
        }
        (ffi::CURLOPT_CONNECT_TO, Ptr(p)) => match slist(p)? {
            Some(source) => options.connect_to.set_source(source)?,
            None => options.connect_to.set([])?,
        },
        (ffi::CURLOPT_HTTP200ALIASES, Ptr(p)) => match slist(p)? {
            Some(source) => {
                let custom = options.http.custom.make_mut()?;
                custom.aliases_200.set_source(source)?;
            }
            None => {
                if let Some(custom) = options.http.custom.made_mut() {
                    custom.aliases_200.set([])?;
                }
            }
        },
        (ffi::CURLOPT_RESOLVE, Ptr(p)) => match slist(p)? {
            Some(source) => options.resolve.set_source(source)?,
            None => options.resolve.set([])?,
        },
        (ffi::CURLOPT_PROTOCOLS_STR, Ptr(p)) => {
            // SAFETY: as above.
            let set = unsafe { string(p) }?.map(protocol_list).transpose()?;
            set_schemes(options, |s| &mut s.allowed, set)?;
        }
        (ffi::CURLOPT_REDIR_PROTOCOLS_STR, Ptr(p)) => {
            // SAFETY: as above.
            let set = unsafe { string(p) }?.map(protocol_list).transpose()?;
            set_schemes(options, |s| &mut s.redirect, set)?;
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
        (ffi::CURLOPT_READDATA, Ptr(p)) => {
            ccb.read_data = p;
            callbacks::sync_input(options, me, ccb)?;
        }
        (ffi::CURLOPT_SEEKDATA, Ptr(p)) => ccb.seek_data = p,
        (ffi::CURLOPT_IOCTLDATA, Ptr(p)) => ccb.ioctl_data = p,
        (ffi::CURLOPT_XFERINFODATA, Ptr(p)) => ccb.progress_data = p,
        (ffi::CURLOPT_DEBUGDATA, Ptr(p)) => ccb.debug_data = p,
        (ffi::CURLOPT_TRAILERDATA, Ptr(p)) => ccb.trailer_data = p,
        (
            ffi::CURLOPT_CHUNK_DATA
            | ffi::CURLOPT_FNMATCH_DATA
            | ffi::CURLOPT_CHUNK_BGN_FUNCTION
            | ffi::CURLOPT_CHUNK_END_FUNCTION
            | ffi::CURLOPT_FNMATCH_FUNCTION,
            Ptr(p),
        ) => {
            // SAFETY: the handle outlives the call; its wildcard group is
            // a cell of its own, apart from the options being set.
            let room = unsafe { me.as_ref() }.wildcard_room()?;
            let mut c = room.get();
            match option {
                ffi::CURLOPT_CHUNK_DATA => c.chunk_data = p,
                ffi::CURLOPT_FNMATCH_DATA => c.fnmatch_data = p,
                // SAFETY: the application passes a function of the
                // option's type, or NULL.
                ffi::CURLOPT_CHUNK_BGN_FUNCTION => c.chunk_bgn = unsafe { function(p) },
                // SAFETY: as above.
                ffi::CURLOPT_CHUNK_END_FUNCTION => c.chunk_end = unsafe { function(p) },
                // SAFETY: as above.
                _ => c.fnmatch = unsafe { function(p) },
            }
            callbacks::sync_wildcard(options, me, &c)?;
            room.set(c);
        }
        (
            ffi::CURLOPT_HSTSREADDATA
            | ffi::CURLOPT_HSTSWRITEDATA
            | ffi::CURLOPT_HSTSREADFUNCTION
            | ffi::CURLOPT_HSTSWRITEFUNCTION,
            Ptr(p),
        ) => {
            // SAFETY: the handle outlives the call; its HSTS group is a
            // cell of its own, apart from the options being set.
            let room = unsafe { me.as_ref() }.hsts_room()?;
            let mut c = room.get();
            match option {
                ffi::CURLOPT_HSTSREADDATA => c.read_data = p,
                ffi::CURLOPT_HSTSWRITEDATA => c.write_data = p,
                // SAFETY: the application passes a function of the
                // option's type, or NULL.
                ffi::CURLOPT_HSTSREADFUNCTION => c.read = unsafe { function(p) },
                // SAFETY: as above.
                _ => c.write = unsafe { function(p) },
            }
            callbacks::sync_hsts(options, me, &c)?;
            room.set(c);
        }
        // On the handle's cache and its files, which `hsts_option`
        // reaches; a name longer than C takes refused first
        // (`Curl_setstropt`).
        (ffi::CURLOPT_HSTS | ffi::CURLOPT_ALTSVC, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            unsafe { string(p) }?;
        }
        (ffi::CURLOPT_HSTS_CTRL | ffi::CURLOPT_ALTSVC_CTRL, Long(_)) => {}
        (ffi::CURLOPT_SSH_KEYFUNCTION, Ptr(p)) => {
            // SAFETY: the application passes a function of the option's
            // type, or NULL, which leaves the key to the known-hosts file.
            ccb.ssh_key = unsafe { function(p) };
            callbacks::sync_ssh_key(options, me, ccb)?;
        }
        (ffi::CURLOPT_SSH_KEYDATA, Ptr(p)) => ccb.ssh_key_data = p,
        // libssh2's alone in C: a build with libssh does not know them.
        #[cfg(not(feature = "libssh2"))]
        (ffi::CURLOPT_SSH_HOSTKEYFUNCTION | ffi::CURLOPT_SSH_HOSTKEYDATA, _) => {
            return Err(Refused::Unknown);
        }
        #[cfg(feature = "libssh2")]
        (ffi::CURLOPT_SSH_HOSTKEYFUNCTION | ffi::CURLOPT_SSH_HOSTKEYDATA, Ptr(p)) => {
            // SAFETY: the handle outlives the call; its host key group is
            // a cell of its own, apart from the options being set.
            let room = unsafe { me.as_ref() }.host_key_room()?;
            let mut c = room.get();
            match option {
                ffi::CURLOPT_SSH_HOSTKEYDATA => c.data = p,
                // SAFETY: the application passes a function of the
                // option's type, or NULL, which leaves the key to the
                // known-hosts file.
                _ => c.function = unsafe { function(p) },
            }
            callbacks::sync_ssh_host_key(options, me, &c)?;
            room.set(c);
        }
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
        (ffi::CURLOPT_READFUNCTION, Ptr(p)) => {
            // SAFETY: as above.
            ccb.read = unsafe { function(p) };
            callbacks::sync_input(options, me, ccb)?;
        }
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
        (ffi::CURLOPT_TCP_NODELAY, Long(n)) => tcp(options, |s| s.nodelay = n != 0)?,
        (ffi::CURLOPT_TCP_KEEPALIVE, Long(n)) => tcp(options, |s| s.keepalive.on = n != 0)?,
        (ffi::CURLOPT_TCP_KEEPIDLE, Long(n)) => {
            let secs = Duration::from_secs(keepalive_value(n)?.into());
            tcp(options, |s| s.keepalive.idle = secs)?;
        }
        (ffi::CURLOPT_TCP_KEEPINTVL, Long(n)) => {
            let secs = Duration::from_secs(keepalive_value(n)?.into());
            tcp(options, |s| s.keepalive.interval = secs)?;
        }
        (ffi::CURLOPT_TCP_KEEPCNT, Long(n)) => {
            let count = keepalive_value(n)?;
            tcp(options, |s| s.keepalive.count = count)?;
        }
        // Linux connects with `TCP_FASTOPEN_CONNECT`.
        #[cfg(not(windows))]
        (ffi::CURLOPT_TCP_FASTOPEN, Long(n)) => tcp(options, |s| s.fastopen = n != 0)?,
        // C's Windows build has no way to connect with data
        // (`CONNECT_DATA_IDEMPOTENT`, `MSG_FASTOPEN`, `TCP_FASTOPEN_CONNECT`)
        // and refuses the option.
        #[cfg(windows)]
        (ffi::CURLOPT_TCP_FASTOPEN, Long(_)) => return Err(Refused::NotBuiltIn),
        (ffi::CURLOPT_INTERFACE, Ptr(p)) => {
            // SAFETY: as above.
            let given = unsafe { string(p) }?;
            // Read for its syntax, empty unsetting it
            // (`setstropt_interface`).
            let interface = match given.map(curl_core::options::Interface::parse) {
                None => None,
                Some(Ok(parsed)) => parsed,
                Some(Err(curl_core::options::InterfaceError::Malformed)) => {
                    return Err(Refused::Bad);
                }
                Some(Err(curl_core::options::InterfaceError::OutOfMemory)) => {
                    return Err(Refused::OutOfMemory);
                }
            };
            tcp(options, |s| s.local.interface = interface)?;
        }
        (ffi::CURLOPT_UNIX_SOCKET_PATH | ffi::CURLOPT_ABSTRACT_UNIX_SOCKET, Ptr(p)) => {
            // SAFETY: as above.
            let path = unsafe { owned(p) }?;
            // NULL is none, and an empty one is kept, for the transfer
            // to fail on (`Curl_setstropt`); the last one set says which
            // namespace the path is in.
            let abstract_name = option == ffi::CURLOPT_ABSTRACT_UNIX_SOCKET;
            let unix = path.map(|path| curl_core::options::UnixSocket {
                path,
                abstract_name,
            });
            tcp(options, |s| s.unix = unix)?;
        }
        (ffi::CURLOPT_LOCALPORT, Long(n)) => {
            let port = u16::try_from(n).map_err(|_| Refused::Bad)?;
            tcp(options, |s| s.local.port = port)?;
        }
        (ffi::CURLOPT_LOCALPORTRANGE, Long(n)) => {
            let range = u16::try_from(n).map_err(|_| Refused::Bad)?;
            tcp(options, |s| s.local.port_range = range)?;
        }
        (ffi::CURLOPT_OPENSOCKETFUNCTION, Ptr(p)) => {
            // SAFETY: the application passes a function of the option's
            // type, or NULL.
            let f = unsafe { function(p) };
            socket_hooks(me, options, |c| c.open = f)?;
        }
        (ffi::CURLOPT_OPENSOCKETDATA, Ptr(p)) => socket_hooks(me, options, |c| c.open_data = p)?,
        (ffi::CURLOPT_SOCKOPTFUNCTION, Ptr(p)) => {
            // SAFETY: the application passes a function of the option's
            // type, or NULL.
            let f = unsafe { function(p) };
            socket_hooks(me, options, |c| c.sockopt = f)?;
        }
        (ffi::CURLOPT_SOCKOPTDATA, Ptr(p)) => socket_hooks(me, options, |c| c.sockopt_data = p)?,
        (ffi::CURLOPT_CLOSESOCKETFUNCTION, Ptr(p)) => {
            // SAFETY: the application passes a function of the option's
            // type, or NULL.
            let f = unsafe { function(p) };
            socket_hooks(me, options, |c| c.close = f)?;
        }
        (ffi::CURLOPT_CLOSESOCKETDATA, Ptr(p)) => socket_hooks(me, options, |c| c.close_data = p)?,
        (ffi::CURLOPT_PREREQFUNCTION, Ptr(p)) => {
            // SAFETY: the application passes a function of the option's
            // type, or NULL.
            let f = unsafe { function(p) };
            socket_hooks(me, options, |c| c.prereq = f)?;
        }
        (ffi::CURLOPT_PREREQDATA, Ptr(p)) => socket_hooks(me, options, |c| c.prereq_data = p)?,
        (ffi::CURLOPT_RESOLVER_START_FUNCTION, Ptr(p)) => {
            // SAFETY: the application passes a function of the option's
            // type, or NULL.
            let f = unsafe { function(p) };
            socket_hooks(me, options, |c| c.resolver_start = f)?;
        }
        (ffi::CURLOPT_RESOLVER_START_DATA, Ptr(p)) => {
            socket_hooks(me, options, |c| c.resolver_start_data = p)?;
        }
        (ffi::CURLOPT_SSL_CTX_FUNCTION, Ptr(p)) => {
            // SAFETY: the application passes a function of the option's
            // type, or NULL.
            let f = unsafe { function(p) };
            tls_hooks(me, options, |c| c.ctx = f)?;
        }
        (ffi::CURLOPT_SSL_CTX_DATA, Ptr(p)) => tls_hooks(me, options, |c| c.ctx_data = p)?,
        (option, arg) if tls::takes(option) => tls::apply(options, option, arg)?,
        (option, arg) if proxy_tls::takes(option) => proxy_tls::apply(options, option, arg)?,
        (option, _) if known::KNOWN.binary_search(&option.0).is_ok() => {
            return Err(Refused::NotBuiltIn);
        }
        _ => return Err(Refused::Unknown),
    }
    Ok(())
}

/// A TCP option of `options` changed by `change`: its group is made only
/// for a value that differs from the defaults.
fn tcp(options: &mut Options, change: impl FnOnce(&mut Sockets)) -> Result<(), OutOfMemory> {
    if let Some(made) = options.sockets.made_mut() {
        change(made);
        return Ok(());
    }
    let mut probe = <Sockets as ColdGroup>::NONE;
    change(&mut probe);
    let unset = <Sockets as ColdGroup>::UNSET;
    if (
        probe.nodelay,
        probe.keepalive,
        probe.fastopen,
        &probe.local,
        &probe.unix,
    ) != (
        unset.nodelay,
        unset.keepalive,
        unset.fastopen,
        &unset.local,
        &unset.unix,
    ) {
        *options.sockets.make_mut()? = probe;
    }
    Ok(())
}

/// A keepalive time or count (`value_range(&arg, 0, 0, INT_MAX)`):
/// negative is refused, past `INT_MAX` is `INT_MAX`.
fn keepalive_value(n: c_long) -> Result<u32, Refused> {
    if n < 0 {
        return Err(Refused::Bad);
    }
    Ok(u32::try_from(n.min(c_long::from(i32::MAX))).expect("clamped to INT_MAX"))
}

/// The application's socket functions changed by `change`, and the
/// handlers that call them made to match. A store for them is made the
/// first time a value is set.
fn socket_hooks(
    me: NonNull<ShimEasy>,
    options: &mut Options,
    change: impl FnOnce(&mut CSockets),
) -> Result<(), OutOfMemory> {
    // SAFETY: `me` is the live handle being set; only its socket store is
    // reached, which no other borrow holds.
    let easy = unsafe { me.as_ref() };
    let mut c = easy.sockets();
    change(&mut c);
    let room = easy.sockets_room()?;
    sockets::sync(options, me, &c)?;
    room.set(c);
    Ok(())
}

/// The `SSL_CTX` function or data of the handle at `me` changed by
/// `change`, and its context handler made to match.
fn tls_hooks(
    me: NonNull<ShimEasy>,
    options: &mut Options,
    change: impl FnOnce(&mut CTls),
) -> Result<(), OutOfMemory> {
    // SAFETY: `me` is the live handle being set; only its TLS store is
    // reached, which no other borrow holds.
    let easy = unsafe { me.as_ref() };
    let mut c = easy.tls();
    change(&mut c);
    let room = easy.tls_room()?;
    crate::tls::sync(options, me, &c)?;
    room.set(c);
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
        return match unsafe { crate::share::set_by_option(easy, *sh) } {
            Ok(()) => CURLE_OK,
            Err(crate::share::Refused::Running) => {
                refused(easy, option);
                CURLE_BAD_FUNCTION_ARGUMENT
            }
            Err(crate::share::Refused::InCallback) => CURLE_BAD_FUNCTION_ARGUMENT,
            Err(crate::share::Refused::OutOfMemory) => ffi::CURLE_OUT_OF_MEMORY,
        };
    }
    // SAFETY: as the caller guarantees.
    let code = unsafe { set_arg(easy, option, arg) };
    if code == CURLE_BAD_FUNCTION_ARGUMENT {
        refused(easy, option);
    }
    code
}

/// What every bad argument adds, whichever option's (the end of C's
/// `curl_easy_setopt`): `failf`'s line. A handle in a call that cannot
/// reach its transfer hears nothing, having nowhere to keep it.
fn refused(easy: &ShimEasy, option: CURLoption) {
    let Ok(line) = try_format(format_args!(
        "setopt {:#x} got bad argument\n",
        option.0 as c_uint
    )) else {
        return;
    };
    let line = line.as_bytes();
    let why = &line[..line.len() - 1];
    let reached = easy.with_easy(|e| match e {
        easy::EasyRef::Easy(mut easy) => easy.tell_failure(why),
        // SAFETY: the frame is the innermost lent, and the borrow ends
        // with this call, inside its callback.
        easy::EasyRef::Frame(frame, id) => unsafe { frame.tell_failure(id, why) },
    });
    if reached.is_ok() {
        callbacks::info(easy, line);
    }
}

/// Set an option to its argument, which has been read.
///
/// # Safety
///
/// A pointer argument is of the option's type, NULL or live.
unsafe fn set_arg(easy: &ShimEasy, option: CURLoption, arg: Arg) -> CURLcode {
    let hsts = match (option, &arg) {
        (ffi::CURLOPT_HSTS, Arg::Ptr(p)) => Some(HstsArg::File(*p)),
        (ffi::CURLOPT_HSTS_CTRL, Arg::Long(n)) => Some(HstsArg::Ctrl(*n)),
        (ffi::CURLOPT_ALTSVC, Arg::Ptr(p)) => Some(HstsArg::AltSvcFile(*p)),
        // No bits at all is refused before anything changes
        // (`Curl_altsvc_ctrl`).
        (ffi::CURLOPT_ALTSVC_CTRL, Arg::Long(0)) => return CURLE_BAD_FUNCTION_ARGUMENT,
        (ffi::CURLOPT_ALTSVC_CTRL, Arg::Long(n)) => Some(HstsArg::AltSvcCtrl(*n)),
        _ => None,
    };
    let jar = match (option, &arg) {
        (
            ffi::CURLOPT_COOKIEFILE | ffi::CURLOPT_COOKIEJAR | ffi::CURLOPT_COOKIELIST,
            Arg::Ptr(p),
        ) => Some(*p),
        _ => None,
    };
    let cseq = match (option, &arg) {
        (ffi::CURLOPT_RTSP_CLIENT_CSEQ | ffi::CURLOPT_RTSP_SERVER_CSEQ, Arg::Long(n)) => Some(*n),
        _ => None,
    };
    let me = NonNull::from(easy);
    let (mut ccb, mut set, mut errbuf) = (easy.ccb.get(), easy.set.get(), easy.errbuf.get());
    let applied = easy.with_options(|o| apply(me, o, &mut ccb, &mut set, &mut errbuf, option, arg));
    if option == ffi::CURLOPT_URL && applied.is_ok() {
        // The URL reported is the one set, or none, as C points
        // `state.url` at it: in place of the last transfer's, or of the
        // one under way's, set from its callback, until a request of it
        // starts again. A URL refused leaves the one set before, which
        // C's points it at all the same.
        let shown = easy.with_easy(|e| match e {
            easy::EasyRef::Easy(mut easy) => easy.show_set_url(),
            // SAFETY: as in `with_options`.
            easy::EasyRef::Frame(frame, id) => unsafe { frame.show_set_url(id) },
        });
        shown.expect("the handle was reached just above");
    }
    let code = match applied {
        Ok(Ok(())) => CURLE_OK,
        Ok(Err(Refused::Bad)) => return CURLE_BAD_FUNCTION_ARGUMENT,
        Ok(Err(Refused::Rewind)) => return ffi::CURLE_SEND_FAIL_REWIND,
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
    if option == ffi::CURLOPT_CURLU {
        // The URL reported goes, as C frees `state.url`: the last
        // transfer's, or the one under way's, set from its callback,
        // until a request of it starts again.
        let forgot = easy.with_easy(|e| match e {
            easy::EasyRef::Easy(mut easy) => easy.forget_url(),
            // SAFETY: as in `with_options`.
            easy::EasyRef::Frame(frame, id) => unsafe { frame.forget_url(id) },
        });
        forgot.expect("the handle was reached just above");
    }
    if let Some(n) = cseq {
        let Ok(n) = keepalive_value(n) else {
            unreachable!("checked as applied")
        };
        let set = easy.with_rtsp(|r| {
            r.map(|r| match option {
                ffi::CURLOPT_RTSP_CLIENT_CSEQ => r.set_next_client_cseq(n),
                _ => r.set_next_server_cseq(n),
            })
        });
        return match set {
            Ok(Ok(())) => code,
            Ok(Err(OutOfMemory)) => CURLE_OUT_OF_MEMORY,
            Err(_) => CURLE_RECURSIVE_API_CALL,
        };
    }
    if let Some(hsts) = hsts {
        // SAFETY: the application passes a C string or NULL.
        return unsafe { hsts_option(easy, hsts) };
    }
    match jar {
        // SAFETY: the application passes a C string or NULL.
        Some(p) => unsafe { jar_option(easy, option, p) },
        None => code,
    }
}

/// An HSTS or alt-svc option's argument.
#[derive(Clone, Copy)]
enum HstsArg {
    /// `CURLOPT_HSTS`'s file, or NULL.
    File(*mut c_void),
    /// `CURLOPT_HSTS_CTRL`'s bits.
    Ctrl(c_long),
    /// `CURLOPT_ALTSVC`'s file, or NULL.
    AltSvcFile(*mut c_void),
    /// `CURLOPT_ALTSVC_CTRL`'s bits, not none.
    AltSvcCtrl(c_long),
}

/// What an HSTS or alt-svc option does to the handle's cache and files,
/// beyond its options (`CURLOPT_HSTS`, `CURLOPT_HSTS_CTRL`,
/// `CURLOPT_ALTSVC`, `CURLOPT_ALTSVC_CTRL`).
///
/// # Safety
///
/// A file is NULL or a C string.
unsafe fn hsts_option(shim: &ShimEasy, arg: HstsArg) -> CURLcode {
    let file = match arg {
        // SAFETY: as the caller guarantees; its length was checked with
        // the option.
        HstsArg::File(p) | HstsArg::AltSvcFile(p) => unsafe { string(p) }.ok().flatten(),
        HstsArg::Ctrl(_) | HstsArg::AltSvcCtrl(_) => None,
    };
    let done = shim.with_easy(|e| {
        let mut easy = match e {
            easy::EasyRef::Easy(easy) => easy,
            easy::EasyRef::Frame(..) => return Err(EasyError::RecursiveApiCall),
        };
        let oom = |_| ErrorKind::OutOfMemory;
        match arg {
            HstsArg::File(_) => easy.add_hsts_file(file).map_err(oom)?,
            HstsArg::Ctrl(bits) if bits & c_long::from(ffi::CURLHSTS_ENABLE) != 0 => {
                let mode = match bits & c_long::from(ffi::CURLHSTS_READONLYFILE) {
                    0 => CacheFile::ReadWrite,
                    _ => CacheFile::ReadOnly,
                };
                easy.enable_hsts(mode).map_err(oom)?;
            }
            HstsArg::Ctrl(_) => easy.disable_hsts(),
            HstsArg::AltSvcFile(_) => easy.add_alt_svc_file(file).map_err(|e| match e {
                CacheLoadError::OutOfMemory => ErrorKind::OutOfMemory,
                CacheLoadError::Read => ErrorKind::ReadError,
                CacheLoadError::TooLarge => ErrorKind::TooLarge,
            })?,
            HstsArg::AltSvcCtrl(bits) => {
                let set = |flag: c_long| bits & flag != 0;
                let ctrl = AltSvcCtrl {
                    file: match set(ffi::CURLALTSVC_READONLYFILE) {
                        false => CacheFile::ReadWrite,
                        true => CacheFile::ReadOnly,
                    },
                    versions: Versions {
                        h1: set(ffi::CURLALTSVC_H1),
                        h2: set(ffi::CURLALTSVC_H2),
                        h3: set(ffi::CURLALTSVC_H3),
                    },
                };
                easy.enable_alt_svc(ctrl).map_err(oom)?;
            }
        }
        Ok(())
    });
    match done {
        Ok(Ok(())) => CURLE_OK,
        Ok(Err(kind)) => crate::error_codes::easy_code(kind),
        Err(_) => CURLE_RECURSIVE_API_CALL,
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
    // What a cookie command traces, held until the handle is no longer
    // borrowed: the debug function may call back into it.
    let mut notes: Vec<Vec<u8>> = Vec::new();
    let done = shim.with_easy(|e| {
        let mut easy = match e {
            easy::EasyRef::Easy(easy) => easy,
            // From a callback, only the options are reached: the jar the
            // files and the save name turn on is made as the next transfer
            // starts.
            easy::EasyRef::Frame(..) if option != ffi::CURLOPT_COOKIELIST => return Ok(()),
            easy::EasyRef::Frame(..) => return Err(EasyError::RecursiveApiCall),
        };
        match (option, given) {
            (ffi::CURLOPT_COOKIEFILE, None) => easy.forget_cookies(),
            (ffi::CURLOPT_COOKIEJAR, _) => {
                easy.enable_cookies().map_err(|_| ErrorKind::OutOfMemory)?;
            }
            (ffi::CURLOPT_COOKIELIST, Some(command)) => {
                return cookie_command(&mut easy, command, &mut notes).map_err(EasyError::from);
            }
            _ => {}
        }
        Ok(())
    });
    for line in &notes {
        callbacks::trace_text(shim, line);
    }
    match done {
        Ok(Ok(())) => CURLE_OK,
        Ok(Err(kind)) => crate::error_codes::easy_code(kind),
        Err(_) => CURLE_RECURSIVE_API_CALL,
    }
}

/// `CURLOPT_COOKIELIST`: a command, in any case, or a cookie to store;
/// what a verbose handle traces of it into `notes`.
fn cookie_command(
    easy: &mut curl_core::easy::EasyView<'_>,
    command: &[u8],
    notes: &mut Vec<Vec<u8>>,
) -> Result<(), ErrorKind> {
    let verbose = easy.options().output.verbose;
    let mut short = false;
    let note = |line: &[u8]| {
        if verbose && !short {
            let mut held = Vec::new();
            short = held.try_extend_from_slice(line).is_err() || notes.try_push(held).is_err();
        }
    };
    let oom = |_: OutOfMemory| ErrorKind::OutOfMemory;
    let done = if command.eq_ignore_ascii_case(b"ALL") {
        easy.clear_cookies().map_err(oom)
    } else if command.eq_ignore_ascii_case(b"SESS") {
        easy.clear_session_cookies().map_err(oom)
    } else if command.eq_ignore_ascii_case(b"FLUSH") {
        // A jar that cannot be written fails nothing, as in C, which says
        // so only in the trace; outside a transfer, there is none here.
        easy.save_cookies().ok();
        Ok(())
    } else if command.eq_ignore_ascii_case(b"RELOAD") {
        easy.reload_cookies(note).map_err(|e| match e {
            LoadError::OutOfMemory => ErrorKind::OutOfMemory,
            LoadError::Read => ErrorKind::ReadError,
        })
    } else {
        easy.add_cookie(command, note).map_err(oom)
    };
    match short {
        true => done.and(Err(ErrorKind::OutOfMemory)),
        false => done,
    }
}
const _: ffi::proto::curl_easy_setopt = curl_easy_setopt;

/// `CURLOPT_UPLOAD_FLAGS`' value: its low byte, whatever the rest, as
/// setopt.c keeps it (`(unsigned char)arg`).
fn upload_flags(n: c_long) -> UploadFlags {
    UploadFlags::from_bits(n.to_le_bytes()[0])
}

/// The build tunnels through HTTP/3 proxies: it claims proxy-HTTP3.
fn proxies_over_h3() -> bool {
    curl_core::version::version()
        .features
        .contains(&curl_core::version::Feature::ProxyHttp3)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One capability of a library's, to change.
    type Capability = fn(&mut TlsSupport) -> &mut bool;

    /// Every option C refuses where its TLS library lacks what the option
    /// asks for, with the capability it asks for.
    const TLS_GATED: &[(CURLoption, Capability)] = &[
        (ffi::CURLOPT_CAPATH, |t| &mut t.ca_path),
        (ffi::CURLOPT_PROXY_CAPATH, |t| &mut t.ca_path),
        (ffi::CURLOPT_CAINFO_BLOB, |t| &mut t.ca_blob),
        (ffi::CURLOPT_PROXY_CAINFO_BLOB, |t| &mut t.ca_blob),
        (ffi::CURLOPT_CA_CACHE_TIMEOUT, |t| &mut t.ca_cache),
        (ffi::CURLOPT_CERTINFO, |t| &mut t.cert_info),
        (ffi::CURLOPT_PINNEDPUBLICKEY, |t| &mut t.pinned_key),
        (ffi::CURLOPT_PROXY_PINNEDPUBLICKEY, |t| &mut t.pinned_key),
        (ffi::CURLOPT_SSL_CTX_FUNCTION, |t| &mut t.context_handler),
        (ffi::CURLOPT_SSL_CTX_DATA, |t| &mut t.context_handler),
        (ffi::CURLOPT_SSL_CIPHER_LIST, |t| &mut t.ciphers),
        (ffi::CURLOPT_PROXY_SSL_CIPHER_LIST, |t| &mut t.ciphers),
        (ffi::CURLOPT_TLS13_CIPHERS, |t| &mut t.tls13_ciphers),
        (ffi::CURLOPT_PROXY_TLS13_CIPHERS, |t| &mut t.tls13_ciphers),
        (ffi::CURLOPT_SSL_EC_CURVES, |t| &mut t.curves),
        (ffi::CURLOPT_SSL_SIGNATURE_ALGORITHMS, |t| {
            &mut t.signature_algorithms
        }),
        (ffi::CURLOPT_CRLFILE, |t| &mut t.crl_file),
        (ffi::CURLOPT_PROXY_CRLFILE, |t| &mut t.crl_file),
        (ffi::CURLOPT_ISSUERCERT, |t| &mut t.issuer_cert),
        (ffi::CURLOPT_PROXY_ISSUERCERT, |t| &mut t.issuer_cert),
        (ffi::CURLOPT_ISSUERCERT_BLOB, |t| &mut t.issuer_cert_blob),
        (ffi::CURLOPT_PROXY_ISSUERCERT_BLOB, |t| {
            &mut t.issuer_cert_blob
        }),
        (ffi::CURLOPT_ECH, |t| &mut t.ech),
        (ffi::CURLOPT_SSL_VERIFYSTATUS, |t| &mut t.cert_status),
        (ffi::CURLOPT_DOH_SSL_VERIFYSTATUS, |t| &mut t.cert_status),
        (ffi::CURLOPT_SSLENGINE, |t| &mut t.engines),
        (ffi::CURLOPT_SSLENGINE_DEFAULT, |t| &mut t.engines),
    ];

    /// An option is refused as not built in exactly when the library
    /// lacks the one capability C checks it against: each refused with
    /// that capability alone missing, and taken with it alone present.
    /// The options no library decides are taken with nothing.
    #[test]
    fn an_option_is_not_built_in_where_the_tls_library_lacks_what_it_asks() {
        let mut all = TlsSupport::NONE;
        for &(_, capability) in TLS_GATED {
            *capability(&mut all) = true;
        }
        for &(option, capability) in TLS_GATED {
            let mut lacking = all;
            *capability(&mut lacking) = false;
            assert!(
                matches!(tls_supports(option, &lacking), Err(Refused::NotBuiltIn)),
                "{option:?}"
            );
            let mut only = TlsSupport::NONE;
            *capability(&mut only) = true;
            assert!(tls_supports(option, &only).is_ok(), "{option:?}");
        }
        for option in [
            ffi::CURLOPT_CAINFO,
            ffi::CURLOPT_PROXY_CAINFO,
            ffi::CURLOPT_SSLCERT,
            ffi::CURLOPT_SSL_OPTIONS,
            ffi::CURLOPT_URL,
        ] {
            assert!(
                tls_supports(option, &TlsSupport::NONE).is_ok(),
                "{option:?}"
            );
        }
    }

    /// The build's TLS library refuses what C's build with it refuses:
    /// Schannel the CA path, the revocation list, the issuer, TLS 1.3's
    /// suites, the context callback, the curves, the signature
    /// algorithms, the stapled status and the engine; GnuTLS TLS 1.3's
    /// suites, the context callback, the curves, the signature
    /// algorithms and the engine; OpenSSL none of them, and LibreSSL the
    /// signature algorithms alone. None has Encrypted Client Hello.
    #[test]
    fn the_tls_library_s_lacking_options_are_not_built_in() {
        let c = crate::easy::curl_easy_init();
        let text = |option| {
            // SAFETY: a live handle, and a string option given a C string.
            unsafe { curl_easy_setopt(c, option, c"x".as_ptr()) }
        };
        let long = |option| {
            // SAFETY: a live handle, and a long option given a long.
            unsafe { curl_easy_setopt(c, option, 1 as c_long) }
        };
        let schannel = cfg!(feature = "schannel");
        let gnutls = cfg!(feature = "gnutls");
        let openssl = cfg!(feature = "openssl");
        let mbedtls = cfg!(feature = "mbedtls");
        let wolfssl = cfg!(feature = "wolfssl");
        let rustls = cfg!(feature = "rustls");
        let want = |lacks: bool| if lacks { CURLE_NOT_BUILT_IN } else { CURLE_OK };
        // Of OpenSSL's family, BoringSSL has neither a TLS 1.3 cipher list
        // nor a stapled status, which C's build over it does not build in.
        let support = curl_core::tls::TlsBackend::support(&crate::tlslib::TLS);
        let tls13_ciphers = (openssl || mbedtls || wolfssl || rustls) && support.tls13_ciphers;
        let cert_status = !(schannel || mbedtls || wolfssl || rustls) && support.cert_status;
        for (option, lacks) in [
            (ffi::CURLOPT_CAPATH, schannel || rustls),
            (ffi::CURLOPT_PROXY_CAPATH, schannel || rustls),
            (ffi::CURLOPT_CRLFILE, schannel || wolfssl),
            (ffi::CURLOPT_PROXY_CRLFILE, schannel || wolfssl),
            (
                ffi::CURLOPT_ISSUERCERT,
                schannel || mbedtls || wolfssl || rustls,
            ),
            (
                ffi::CURLOPT_PROXY_ISSUERCERT,
                schannel || mbedtls || wolfssl || rustls,
            ),
            (ffi::CURLOPT_TLS13_CIPHERS, !tls13_ciphers),
            (ffi::CURLOPT_PROXY_TLS13_CIPHERS, !tls13_ciphers),
            (ffi::CURLOPT_SSL_EC_CURVES, !openssl && !wolfssl),
            (ffi::CURLOPT_SSLENGINE, !openssl),
        ] {
            assert_eq!(text(option), want(lacks), "{option:?}");
        }
        // LibreSSL's lack of them is pinned by curl-openssl's own test.
        let sigalgs = curl_core::tls::TlsBackend::support(&crate::tlslib::TLS).signature_algorithms;
        assert_eq!(text(ffi::CURLOPT_SSL_SIGNATURE_ALGORITHMS), want(!sigalgs));
        for (option, lacks) in [
            (ffi::CURLOPT_SSL_VERIFYSTATUS, !cert_status),
            (ffi::CURLOPT_DOH_SSL_VERIFYSTATUS, !cert_status),
            (ffi::CURLOPT_SSLENGINE_DEFAULT, !openssl),
        ] {
            assert_eq!(long(option), want(lacks), "{option:?}");
        }
        // SAFETY: a live handle, and a pointer option given NULL.
        let ctx_data = unsafe {
            curl_easy_setopt(
                c,
                ffi::CURLOPT_SSL_CTX_DATA,
                core::ptr::null_mut::<c_void>(),
            )
        };
        assert_eq!(ctx_data, want(schannel || gnutls || rustls));
        // What all have.
        for option in [ffi::CURLOPT_CAINFO, ffi::CURLOPT_SSL_CIPHER_LIST] {
            assert_eq!(text(option), CURLE_OK, "{option:?}");
        }
        // Rustls pins no key.
        assert_eq!(text(ffi::CURLOPT_PINNEDPUBLICKEY), want(rustls));
        // wolfSSL reports no chain.
        assert_eq!(long(ffi::CURLOPT_CERTINFO), want(wolfssl));
        // mbedTLS and Rustls keep no CA cache.
        assert_eq!(long(ffi::CURLOPT_CA_CACHE_TIMEOUT), want(mbedtls || rustls));
        // What none has.
        assert_eq!(text(ffi::CURLOPT_ECH), CURLE_NOT_BUILT_IN);
        // SAFETY: the handle made above, not used again.
        unsafe { crate::easy::curl_easy_cleanup(c) };
    }

    /// An HTTP/3 proxy is taken only by a build with one: OpenSSL's, as
    /// C's CMake builds `USE_PROXY_HTTP3` over OpenSSL alone. Elsewhere it
    /// is not built in, and the proxy's type is left as it was.
    #[test]
    fn an_http3_proxy_is_taken_only_by_the_openssl_build() {
        let c = crate::easy::curl_easy_init();
        let kind = |n: c_long| {
            // SAFETY: a live handle, and a `long` option.
            unsafe { curl_easy_setopt(c, ffi::CURLOPT_PROXYTYPE, n) }
        };
        assert_eq!(kind(ffi::CURLPROXY_HTTPS2), CURLE_OK);
        let openssl = cfg!(feature = "openssl");
        let want = if openssl {
            CURLE_OK
        } else {
            CURLE_NOT_BUILT_IN
        };
        assert_eq!(kind(ffi::CURLPROXY_HTTPS3), want);
        // SAFETY: a live handle.
        let now = unsafe { crate::easy::handle(c) }
            .expect("a live handle")
            .with_options(|o| o.proxy.kind)
            .expect("reachable");
        let kept = if openssl {
            curl_core::options::ProxyType::Https3
        } else {
            curl_core::options::ProxyType::Https2
        };
        assert_eq!(now, kept);
        // SAFETY: the handle made above, not used again.
        unsafe { crate::easy::curl_easy_cleanup(c) };
    }

    /// The SSH options are taken as C's libssh build takes them: a
    /// directory's mode up to 0777, and the host key function and its
    /// data, libssh2's, unknown.
    #[test]
    fn takes_the_ssh_options_as_c_s_libssh_build() {
        let c = crate::easy::curl_easy_init();
        let long = |option, n: c_long| {
            // SAFETY: a live handle, and a `long` option.
            unsafe { curl_easy_setopt(c, option, n) }
        };
        let pointer = |option| {
            // SAFETY: a live handle, and an option NULL may be given.
            unsafe { curl_easy_setopt(c, option, core::ptr::null_mut::<c_void>()) }
        };
        let want_libssh2 = if cfg!(feature = "libssh2") {
            CURLE_OK
        } else {
            CURLE_UNKNOWN_OPTION
        };
        let answers = [
            long(ffi::CURLOPT_NEW_DIRECTORY_PERMS, 0o755),
            long(ffi::CURLOPT_NEW_DIRECTORY_PERMS, 0o1000),
            long(ffi::CURLOPT_SSH_AUTH_TYPES, -1),
            pointer(ffi::CURLOPT_SSH_KEYFUNCTION),
            pointer(ffi::CURLOPT_SSH_HOSTKEYFUNCTION),
            pointer(ffi::CURLOPT_SSH_HOSTKEYDATA),
        ];
        assert_eq!(
            answers,
            [
                CURLE_OK,
                CURLE_BAD_FUNCTION_ARGUMENT,
                CURLE_OK,
                CURLE_OK,
                // libssh2's alone.
                want_libssh2,
                want_libssh2,
            ]
        );
        // SAFETY: a live handle.
        let easy = unsafe { crate::easy::handle(c) }.expect("live");
        let mode = easy
            .with_options(|o| o.ssh.new_directory_mode.bits())
            .expect("reachable");
        assert_eq!(mode, 0o755);
        // The strings, copied up to their zero byte, and compression.
        let strings = [
            (ffi::CURLOPT_SSH_PUBLIC_KEYFILE, c"pub"),
            (ffi::CURLOPT_SSH_PRIVATE_KEYFILE, c"priv"),
            (ffi::CURLOPT_SSH_HOST_PUBLIC_KEY_MD5, c"md5"),
            (ffi::CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256, c"sha"),
            (ffi::CURLOPT_SSH_KNOWNHOSTS, c"kh"),
        ];
        for (option, value) in strings {
            // SAFETY: a live handle, and a C string option.
            let set = unsafe { curl_easy_setopt(c, option, value.as_ptr()) };
            assert_eq!(set, CURLE_OK);
        }
        assert_eq!(long(ffi::CURLOPT_SSH_COMPRESSION, 1), CURLE_OK);
        let mut data = 0u8;
        // SAFETY: a live handle, and a pointer option.
        let set = unsafe {
            curl_easy_setopt(
                c,
                ffi::CURLOPT_SSH_KEYDATA,
                (&raw mut data).cast::<c_void>(),
            )
        };
        assert_eq!(set, CURLE_OK);
        let kept = easy
            .with_options(|o| {
                let s = &o.ssh;
                [
                    s.public_key.clone(),
                    s.private_key.clone(),
                    s.host_key_md5.clone(),
                    s.host_key_sha256.clone(),
                    s.known_hosts.clone(),
                    Some(vec![u8::from(s.compression)]),
                ]
            })
            .expect("reachable");
        let want = [&b"pub"[..], b"priv", b"md5", b"sha", b"kh", &[1]];
        assert_eq!(kept, want.map(|w| Some(w.to_vec())));
        assert_eq!(
            easy.ccb.get().ssh_key_data,
            (&raw mut data).cast::<c_void>()
        );
        // The key function's adapter is there while the function is.
        unsafe extern "C" fn fine(
            _: *mut ffi::CURL,
            _: *const ffi::curl_khkey,
            _: *const ffi::curl_khkey,
            _: ffi::curl_khmatch,
            _: *mut c_void,
        ) -> core::ffi::c_int {
            ffi::CURLKHSTAT_FINE.0
        }
        type KeyFn = unsafe extern "C" fn(
            *mut ffi::CURL,
            *const ffi::curl_khkey,
            *const ffi::curl_khkey,
            ffi::curl_khmatch,
            *mut c_void,
        ) -> core::ffi::c_int;
        let handler = || {
            easy.with_options(|o| o.ssh.key_handler.is_some())
                .expect("reachable")
        };
        let f = fine as KeyFn as *mut c_void;
        // SAFETY: a live handle, and a function of the option's type.
        let set = unsafe { curl_easy_setopt(c, ffi::CURLOPT_SSH_KEYFUNCTION, f) };
        assert_eq!(set, CURLE_OK);
        assert!(handler());
        assert_eq!(pointer(ffi::CURLOPT_SSH_KEYFUNCTION), CURLE_OK);
        assert!(!handler());
        // SAFETY: a live handle, not used again.
        unsafe { crate::easy::curl_easy_cleanup(c) };
    }

    /// The flags are the value's low byte, any bits past the five C
    /// names kept.
    #[test]
    fn reads_upload_flags_as_c() {
        for (n, bits) in [
            (16, 16),
            (0, 0),
            (0x1f, 0x1f),
            (0x1ff, 0xff),
            (0x100, 0),
            (-1, 0xff),
        ] {
            assert_eq!(upload_flags(n).bits(), bits, "{n:#x}");
        }
        assert_eq!(upload_flags(16), UploadFlags::SEEN);
        let c = crate::easy::curl_easy_init();
        // SAFETY: a live handle, and a `long` option.
        let set = unsafe { curl_easy_setopt(c, ffi::CURLOPT_UPLOAD_FLAGS, 0x105 as c_long) };
        assert_eq!(set, ffi::CURLE_OK);
        // SAFETY: a live handle.
        let easy = unsafe { crate::easy::handle(c) }.expect("live");
        let flags = easy
            .with_options(|o| o.line.upload_flags)
            .expect("reachable");
        assert_eq!(flags.bits(), 5);
        // SAFETY: a live handle, not used again.
        unsafe { crate::easy::curl_easy_cleanup(c) };
    }

    /// Negotiate's bit is a method only where the build claims SPNEGO;
    /// elsewhere it is dropped as NTLM's is, alone not built in, and
    /// `CURLAUTH_ANY` holds every method but it (`httpauth`).
    #[test]
    fn reads_negotiate_only_where_claimed() {
        use curl_core::options::AuthMethods as M;
        let read = |mask, spnego| match auth_methods(mask, spnego) {
            Ok(m) => Ok(m),
            Err(Refused::NotBuiltIn) => Err(()),
            Err(_) => panic!("{mask:#x}: refused otherwise"),
        };
        let nego = ffi::CURLAUTH_NEGOTIATE;
        assert_eq!(read(nego, true), Ok(M::NEGOTIATE));
        assert_eq!(read(nego, false), Err(()));
        let basic = ffi::CURLAUTH_BASIC | nego;
        assert_eq!(read(basic, true), Ok(M::BASIC | M::NEGOTIATE));
        assert_eq!(read(basic, false), Ok(M::BASIC));
        assert_eq!(read(ffi::CURLAUTH_ANY, true), Ok(M::ANY));
        assert_eq!(read(ffi::CURLAUTH_ANY, false), Ok(M::ANY & !M::NEGOTIATE));
        assert_eq!(
            read(ffi::CURLAUTH_NTLM, true),
            Err(()),
            "NTLM still lacking"
        );
    }

    /// Delegation is two flags, the other bits dropped as C's mask drops
    /// them; with GSS-API unclaimed the option is unknown, as C lacks it.
    #[test]
    fn reads_delegation_as_c() {
        use curl_core::options::Delegation as D;
        let read = |n, gssapi| match delegation(n, gssapi) {
            Ok(d) => Some(d),
            Err(Refused::Unknown) => None,
            Err(_) => panic!("{n}: refused otherwise"),
        };
        let (none, policy) = (
            D::default(),
            D {
                by_policy: true,
                always: false,
            },
        );
        let always = D {
            by_policy: false,
            always: true,
        };
        let both = D {
            by_policy: true,
            always: true,
        };
        for (n, want) in [
            (0, none),
            (1, policy),
            (2, always),
            (3, both),
            (4, none),
            (7, both),
            (-1, both),
        ] {
            assert_eq!(read(n, true), Some(want), "{n}");
            assert_eq!(read(n, false), None, "{n}");
        }
    }

    /// NEC's switch is a GSS-API build's: unknown elsewhere.
    #[test]
    fn reads_gss_switches_only_where_claimed() {
        for (n, want) in [(0, false), (1, true), (2, true), (-1, true)] {
            assert!(matches!(gss_bool(n, true), Ok(on) if on == want), "{n}");
            assert!(matches!(gss_bool(n, false), Err(Refused::Unknown)), "{n}");
        }
    }

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

    /// A scheme list names schemes this build speaks, in any case, or is
    /// `all` alone; anything else is unsupported, and naming none a bad
    /// argument (`protocol2num`, test 1597).
    #[test]
    fn reads_scheme_lists_as_c() {
        let http = Protocols::of(&["http"]).unwrap();
        let both = Protocols::of(&["file", "http"]).unwrap();
        for (list, want) in [
            (&b"http"[..], Some(http)),
            (b"HTTP,,http,", Some(http)),
            (b",file,Http", Some(both)),
            (b"ALL", Some(Protocols::ALL)),
        ] {
            assert_eq!(protocol_list(list).ok(), want, "{list:?}");
        }
        for list in [
            &b"goobar"[..],
            b"http ",
            b" http",
            b"smb",
            // Known to libcurl, as proxies' schemes, but no transfer's.
            b"socks",
            b"SOCKS5h",
            b"http,socks4a",
            b"http,all",
            b"http,ft",
        ] {
            assert!(
                matches!(protocol_list(list), Err(Refused::Unsupported)),
                "{list:?}"
            );
        }
        for list in [&b""[..], b",,"] {
            assert!(matches!(protocol_list(list), Err(Refused::Bad)), "{list:?}");
        }
    }

    /// A `CURLPROTO_*` mask names its schemes by C's bits, the ones past
    /// 32 among them; a bit no scheme has names nothing.
    #[test]
    fn reads_scheme_masks_as_c() {
        assert_eq!(
            protocol_mask(ffi::CURLPROTO_HTTP),
            Protocols::of(&["http"]).unwrap()
        );
        assert_eq!(
            protocol_mask(ffi::CURLPROTO_FILE | ffi::CURLPROTO_GOPHERS),
            Protocols::of(&["file", "gophers"]).unwrap()
        );
        assert_eq!(protocol_mask(ffi::CURLPROTO_RTMP), Protocols::NONE);
        // Past bit 31 where a `long` has them: Windows' has 32 bits.
        #[cfg(not(windows))]
        {
            assert_eq!(protocol_mask(1 << 32), Protocols::of(&["mqtts"]).unwrap());
            let socks = protocol_mask(1 << 33);
            assert!(socks.contains(b"socks5h") && !socks.contains(b"http"));
        }
        let all = protocol_mask(-1);
        for scheme in [&b"http"[..], b"wss", b"socks4a", b"tftp"] {
            assert!(all.contains(scheme), "{scheme:?}");
        }
        assert_eq!(protocol_mask(0), Protocols::NONE);
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
        set.time_value = 7;
        assert_eq!(time_condition(&set), None);
        set.time_condition = ffi::CURL_TIMECOND_LASTMOD;
        assert_eq!(
            time_condition(&set),
            Some(TimeCondition {
                when: curl_core::options::Condition::LastModified,
                time: 7
            })
        );
    }
}
