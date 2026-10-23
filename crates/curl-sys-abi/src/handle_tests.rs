//! The handles through the C ABI, as a C program calls them: each option
//! as setopt.c checks it, each info against the report it comes from, and
//! each callback adapter against what C does with the function's answer.

#![allow(unsafe_code)]
#![allow(
    clippy::multiple_unsafe_ops_per_block,
    reason = "one contract covers each test's sequence of calls"
)]

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use core::ptr;
use std::time::Duration;

use curl_core::conn::io::Events;
use curl_core::multi::NotifyKind;
use curl_core::options::script::{Piece, Script};
use curl_core::options::{HttpVersion, Method, Options, Progress, Resume, UploadSource};
use curl_core::report::TransferReport;

use crate::callbacks::aborts;
use crate::easy::{self, curl_easy_cleanup, curl_easy_init, curl_easy_pause, curl_easy_perform};
use crate::ffi::{
    self, CURL, CURLE_ABORTED_BY_CALLBACK, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_NOT_BUILT_IN,
    CURLE_OK, CURLE_RECURSIVE_API_CALL, CURLE_UNKNOWN_OPTION, CURLINFO, CURLM, CURLM_OK, CURLcode,
    CURLoption, curl_header, curl_off_t,
};
use crate::getinfo::curl_easy_getinfo;
use crate::multi::{
    curl_multi_add_handle, curl_multi_cleanup, curl_multi_get_offt, curl_multi_info_read,
    curl_multi_init, curl_multi_notify_disable, curl_multi_notify_enable, curl_multi_perform,
    curl_multi_remove_handle, curl_multi_setopt, curl_multi_wait, notify_kind, running,
    wait_events, wait_revents,
};
use crate::setopt::curl_easy_setopt;

type WriteFn = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

fn long(c: *mut CURL, o: CURLoption, v: c_long) -> CURLcode {
    // SAFETY: a live handle and a `long` option, as each caller passes.
    unsafe { curl_easy_setopt(c, o, v) }
}

fn off(c: *mut CURL, o: CURLoption, v: curl_off_t) -> CURLcode {
    // SAFETY: a live handle and an offset option.
    unsafe { curl_easy_setopt(c, o, v) }
}

fn pointer<T>(c: *mut CURL, o: CURLoption, v: *mut T) -> CURLcode {
    // SAFETY: a live handle and a pointer option, whose target outlives
    // the handle's use of it.
    unsafe { curl_easy_setopt(c, o, v.cast::<c_void>()) }
}

/// A function option; `f` is a function of the option's type, or NULL.
fn function(c: *mut CURL, o: CURLoption, f: *const ()) -> CURLcode {
    // SAFETY: a live handle and a function option.
    unsafe { curl_easy_setopt(c, o, f.cast_mut().cast::<c_void>()) }
}

fn options<R>(c: *mut CURL, f: impl FnOnce(&mut Options) -> R) -> R {
    // SAFETY: a live handle.
    let easy = unsafe { easy::handle(c) }.expect("a live handle");
    easy.with_options(f).expect("reachable")
}

fn report<R>(c: *mut CURL, f: impl FnOnce(&TransferReport) -> R) -> R {
    // SAFETY: a live handle.
    let easy = unsafe { easy::handle(c) }.expect("a live handle");
    easy.with_report(f).expect("reachable")
}

fn ccb(c: *mut CURL) -> crate::callbacks::CCallbacks {
    // SAFETY: a live handle.
    unsafe { easy::handle(c) }.expect("a live handle").ccb.get()
}

fn info<T: Default>(c: *mut CURL, i: CURLINFO) -> T {
    let mut v = T::default();
    assert_eq!(
        // SAFETY: a live handle, and a value of the info's type.
        unsafe { curl_easy_getinfo(c, i, &raw mut v) },
        CURLE_OK,
        "{}",
        i.0
    );
    v
}

/// A file of `body`, named by `tag`, and its URL.
fn file(tag: &str, body: &[u8]) -> (std::path::PathBuf, std::ffi::CString) {
    let path = std::env::temp_dir().join(format!("curl-shim-{}-{tag}", std::process::id()));
    std::fs::write(&path, body).unwrap();
    let url = std::ffi::CString::new(format!("file://{}", path.display())).unwrap();
    (path, url)
}

unsafe extern "C" fn sink(_: *mut c_char, size: usize, n: usize, _: *mut c_void) -> usize {
    size * n
}

/// What a C stream got, read back from its start.
fn stream_text(f: *mut libc::FILE) -> String {
    let mut out = Vec::new();
    // SAFETY: a stream from `tmpfile`, open.
    unsafe {
        libc::fflush(f);
        libc::rewind(f);
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::fread(buf.as_mut_ptr().cast(), 1, buf.len(), f);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
    String::from_utf8(out).unwrap()
}

fn tmpfile() -> *mut libc::FILE {
    // SAFETY: no precondition.
    let f = unsafe { libc::tmpfile() };
    assert!(!f.is_null());
    f
}

fn close(f: *mut libc::FILE) {
    // SAFETY: a stream from `tmpfile`, not used again.
    unsafe { libc::fclose(f) };
}

#[test]
fn boolean_options_take_any_nonzero_value() {
    let c = curl_easy_init();
    for (o, get) in [
        (
            ffi::CURLOPT_VERBOSE,
            (|o: &mut Options| o.output.verbose) as fn(&mut Options) -> bool,
        ),
        (ffi::CURLOPT_HEADER, |o| o.output.include_header),
        (ffi::CURLOPT_PATH_AS_IS, |o| o.url_rules.path_as_is),
        (ffi::CURLOPT_DISALLOW_USERNAME_IN_URL, |o| {
            o.url_rules.disallow_user
        }),
        (ffi::CURLOPT_FAILONERROR, |o| o.http.fail_on_error),
        (ffi::CURLOPT_HTTP09_ALLOWED, |o| o.http.allow_09),
        (ffi::CURLOPT_IGNORE_CONTENT_LENGTH, |o| {
            o.http.ignore_content_length
        }),
        (ffi::CURLOPT_HTTP_TRANSFER_DECODING, |o| !o.http.raw),
        (ffi::CURLOPT_HTTP_CONTENT_DECODING, |o| !o.http.raw_content),
        (ffi::CURLOPT_TRANSFER_ENCODING, |o| o.http.transfer_encoding),
        (ffi::CURLOPT_SSL_VERIFYPEER, |o| o.tls.verify_peer),
        (ffi::CURLOPT_SSL_VERIFYHOST, |o| o.tls.verify_host),
        (ffi::CURLOPT_KEEP_SENDING_ON_ERROR, |o| {
            o.http.keep_sending_on_error
        }),
        (ffi::CURLOPT_AUTOREFERER, |o| o.http.auto_referer),
        (ffi::CURLOPT_UNRESTRICTED_AUTH, |o| o.http.unrestricted_auth),
        (ffi::CURLOPT_FILETIME, |o| o.filetime),
        (ffi::CURLOPT_HAPROXYPROTOCOL, |o| o.proxy.haproxy),
        (ffi::CURLOPT_SUPPRESS_CONNECT_HEADERS, |o| {
            o.proxy.suppress_connect_headers
        }),
        (ffi::CURLOPT_COOKIESESSION, |o| o.http.cookies.new_session),
    ] {
        for (v, on) in [(1, true), (0, false), (2, true), (-1, true), (0, false)] {
            assert_eq!(long(c, o, v), CURLE_OK);
            assert_eq!(options(c, get), on, "{} = {v}", o.0);
        }
    }
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_MIME_OPTIONS` turns form escaping on with its bit, and off
/// without it whatever else is set.
#[test]
fn mime_options_take_the_form_escape_bit() {
    let c = curl_easy_init();
    assert!(!options(c, |o| o.mime.form_escape));
    for (v, on) in [(1, true), (2, false), (3, true), (0, false)] {
        assert_eq!(long(c, ffi::CURLOPT_MIME_OPTIONS, v), CURLE_OK);
        assert_eq!(options(c, |o| o.mime.form_escape), on, "{v}");
    }
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_REQUEST_TARGET` is copied; NULL takes it away.
#[test]
fn a_request_target_is_kept() {
    let c = curl_easy_init();
    let target = |c| options(c, |o| o.http.request_target.clone());
    let mut given = *b"*\0";
    assert_eq!(
        pointer(c, ffi::CURLOPT_REQUEST_TARGET, given.as_mut_ptr()),
        CURLE_OK
    );
    given[0] = b'X';
    std::hint::black_box(&given);
    assert_eq!(target(c), Some(b"*".to_vec()));
    let null = ptr::null_mut::<c_char>();
    assert_eq!(pointer(c, ffi::CURLOPT_REQUEST_TARGET, null), CURLE_OK);
    assert_eq!(target(c), None);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_RANGE` is copied; NULL takes it away; duphandle copies it.
#[test]
fn a_range_is_kept() {
    let c = curl_easy_init();
    let range = |c| options(c, |o| o.range.clone());
    let mut given = *b"0-4\0";
    assert_eq!(pointer(c, ffi::CURLOPT_RANGE, given.as_mut_ptr()), CURLE_OK);
    given[0] = b'X';
    std::hint::black_box(&given);
    assert_eq!(range(c), Some(b"0-4".to_vec()));
    // SAFETY: a live handle.
    let d = unsafe { easy::curl_easy_duphandle(c) };
    assert_eq!(range(d), Some(b"0-4".to_vec()));
    let null = ptr::null_mut::<c_char>();
    assert_eq!(pointer(c, ffi::CURLOPT_RANGE, null), CURLE_OK);
    assert_eq!(range(c), None);
    // SAFETY: live handles, not used again.
    unsafe {
        curl_easy_cleanup(c);
        curl_easy_cleanup(d);
    }
}

/// The speed limits refuse a negative rate, take 0 for none, and are
/// copied with the handle. C's `curl_easy_duphandle` copies the rates
/// but not the limiter they were set into, so its copy is not limited
/// (it reads only `set.max_send_speed`, to cut a send): a 60000-byte
/// download at 20000 a second takes 3 s on the handle and none on its
/// copy.
#[test]
fn speed_limits_are_kept_and_copied() {
    let c = curl_easy_init();
    let speeds = |c| options(c, |o| (o.limits.max_recv_speed, o.limits.max_send_speed));
    let n = std::num::NonZeroU64::new;
    assert_eq!(off(c, ffi::CURLOPT_MAX_RECV_SPEED_LARGE, 20000), CURLE_OK);
    assert_eq!(off(c, ffi::CURLOPT_MAX_SEND_SPEED_LARGE, 30000), CURLE_OK);
    assert_eq!(
        off(c, ffi::CURLOPT_MAX_SEND_SPEED_LARGE, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(speeds(c), (n(20000), n(30000)));
    // SAFETY: a live handle.
    let d = unsafe { easy::curl_easy_duphandle(c) };
    assert_eq!(speeds(d), (n(20000), n(30000)));
    assert_eq!(off(c, ffi::CURLOPT_MAX_RECV_SPEED_LARGE, 0), CURLE_OK);
    assert_eq!(speeds(c), (None, n(30000)));
    // SAFETY: live handles, not used again.
    unsafe {
        curl_easy_cleanup(c);
        curl_easy_cleanup(d);
    }
}

/// `CURLOPT_BUFFERSIZE` refuses a negative size and holds the rest
/// between 1 KiB and 10 MiB (`value_range`).
#[test]
fn the_buffer_size_is_held_to_its_range() {
    use curl_core::options::BufferSize;
    let c = curl_easy_init();
    let size = |c| options(c, |o| o.limits.buffer_size);
    assert_eq!(size(c), BufferSize::default());
    assert_eq!(size(c).get(), 16384);
    assert_eq!(
        long(c, ffi::CURLOPT_BUFFERSIZE, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    for (asked, held) in [
        (0, 1024),
        (1023, 1024),
        (100_000, 100_000),
        (1 << 30, 10 << 20),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_BUFFERSIZE, asked), CURLE_OK);
        assert_eq!(size(c).get(), held, "{asked}");
    }
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_UPLOAD_BUFFERSIZE` refuses a negative size and holds the
/// rest between 16 KiB and 2 MiB (`value_range`).
#[test]
fn the_upload_buffer_size_is_held_to_its_range() {
    use curl_core::options::UploadBufferSize;
    let c = curl_easy_init();
    let size = |c| options(c, |o| o.limits.upload_buffer);
    assert_eq!(size(c), UploadBufferSize::default());
    assert_eq!(size(c).get(), 65536);
    assert_eq!(
        long(c, ffi::CURLOPT_UPLOAD_BUFFERSIZE, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    for (asked, held) in [
        (0, 16384),
        (16383, 16384),
        (16411, 16411),
        (1 << 30, 2 << 20),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_UPLOAD_BUFFERSIZE, asked), CURLE_OK);
        assert_eq!(size(c).get(), held, "{asked}");
    }
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_AWS_SIGV4` makes AWS SigV4 the one method; NULL takes it out
/// of the methods asked for and leaves the others. A string refused for
/// its length leaves the one before it, and the method as it says.
#[test]
fn aws_sigv4_is_the_one_method() {
    use curl_core::options::AuthMethods as M;
    let c = curl_easy_init();
    let state = |c| options(c, |o| (o.http.signing.aws_sigv4.clone(), o.http.auth.0));
    let mut given = *b"aws:amz:r:s\0";
    assert_eq!(
        pointer(c, ffi::CURLOPT_AWS_SIGV4, given.as_mut_ptr()),
        CURLE_OK
    );
    given[0] = b'X';
    std::hint::black_box(&given);
    assert_eq!(state(c), (Some(b"aws:amz:r:s".to_vec()), M::AWS_SIGV4));
    let any = ffi::CURLAUTH_BASIC | ffi::CURLAUTH_AWS_SIGV4;
    assert_eq!(long(c, ffi::CURLOPT_HTTPAUTH, any as c_long), CURLE_OK);
    let mut long_string = vec![b'a'; 8_000_001];
    long_string.push(0);
    assert_eq!(
        pointer(c, ffi::CURLOPT_AWS_SIGV4, long_string.as_mut_ptr()),
        ffi::CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(state(c), (Some(b"aws:amz:r:s".to_vec()), M::AWS_SIGV4));
    assert_eq!(long(c, ffi::CURLOPT_HTTPAUTH, any as c_long), CURLE_OK);
    let null = ptr::null_mut::<c_char>();
    assert_eq!(pointer(c, ffi::CURLOPT_AWS_SIGV4, null), CURLE_OK);
    assert_eq!(state(c), (None, M::BASIC));
    let mut empty = *b"\0";
    assert_eq!(
        pointer(c, ffi::CURLOPT_AWS_SIGV4, empty.as_mut_ptr()),
        CURLE_OK
    );
    assert_eq!(state(c), (Some(Vec::new()), M::AWS_SIGV4));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_HTTPSIG_ALGORITHM` takes the algorithms C knows and makes
/// a message signature the one method; none takes it out of the methods
/// asked for. Its strings are copied, and copied with the handle.
#[test]
fn a_message_signature_is_the_one_method() {
    use curl_core::options::{AuthMethods as M, SignatureAlgorithm as A};
    let c = curl_easy_init();
    let auth = |c| options(c, |o| o.http.auth.0);
    let algorithm = |c| options(c, |o| o.http.signing.message.algorithm);
    let strings = |c| {
        options(c, |o| {
            let s = &o.http.signing.message;
            (s.key.clone(), s.key_id.clone(), s.components.clone())
        })
    };
    assert_eq!(algorithm(c), None);
    assert_eq!(
        long(
            c,
            ffi::CURLOPT_HTTPSIG_ALGORITHM,
            ffi::CURLHTTPSIG_HMAC_SHA256
        ),
        CURLE_OK
    );
    assert_eq!((algorithm(c), auth(c)), (Some(A::HmacSha256), M::HTTPSIG));
    assert_eq!(
        long(c, ffi::CURLOPT_HTTPSIG_ALGORITHM, 3),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(
        long(c, ffi::CURLOPT_HTTPSIG_ALGORITHM, ffi::CURLHTTPSIG_ED25519),
        CURLE_OK
    );
    assert_eq!(algorithm(c), Some(A::Ed25519));
    let mut key = *b"00ff\0";
    let mut id = *b"k1\0";
    let mut components = *b"method path\0";
    for (option, value) in [
        (ffi::CURLOPT_HTTPSIG_KEY, key.as_mut_ptr()),
        (ffi::CURLOPT_HTTPSIG_KEYID, id.as_mut_ptr()),
        (ffi::CURLOPT_HTTPSIG_HEADERS, components.as_mut_ptr()),
    ] {
        assert_eq!(pointer(c, option, value), CURLE_OK);
    }
    key[0] = b'X';
    std::hint::black_box(&key);
    let set = (
        Some(b"00ff".to_vec()),
        Some(b"k1".to_vec()),
        Some(b"method path".to_vec()),
    );
    assert_eq!(strings(c), set);
    // SAFETY: a live handle.
    let d = unsafe { easy::curl_easy_duphandle(c) };
    assert_eq!(strings(d), set);
    assert_eq!((algorithm(d), auth(d)), (Some(A::Ed25519), M::HTTPSIG));
    let any = ffi::CURLAUTH_BASIC | ffi::CURLAUTH_HTTPSIG;
    assert_eq!(long(c, ffi::CURLOPT_HTTPAUTH, any as c_long), CURLE_OK);
    assert_eq!(
        long(c, ffi::CURLOPT_HTTPSIG_ALGORITHM, ffi::CURLHTTPSIG_NONE),
        CURLE_OK
    );
    assert_eq!((algorithm(c), auth(c)), (None, M::BASIC));
    // Taking SigV4 out leaves it, as C's mask keeps it.
    assert_eq!(long(c, ffi::CURLOPT_HTTPAUTH, any as c_long), CURLE_OK);
    let null = ptr::null_mut::<c_char>();
    assert_eq!(pointer(c, ffi::CURLOPT_AWS_SIGV4, null), CURLE_OK);
    assert_eq!(auth(c), M::BASIC | M::HTTPSIG);
    assert_eq!(pointer(c, ffi::CURLOPT_HTTPSIG_KEY, null), CURLE_OK);
    assert_eq!(strings(c).0, None);
    // SAFETY: live handles, not used again.
    unsafe {
        curl_easy_cleanup(c);
        curl_easy_cleanup(d);
    }
}

/// The HTTP options' strings and list are copied; NULL takes them away.
/// HTTP/2 and HTTP/3 are not built in, as in a C build without them.
#[test]
fn http_options_reach_the_request() {
    let c = curl_easy_init();
    let strings = |c| {
        options(c, |o| {
            (
                o.http.referer.clone(),
                o.http.user_agent.clone(),
                o.http
                    .headers
                    .lines()
                    .map(<[u8]>::to_vec)
                    .collect::<Vec<_>>(),
            )
        })
    };
    let mut referer = *b"http://r/\0";
    pointer(c, ffi::CURLOPT_REFERER, referer.as_mut_ptr());
    // Changed after: the handle kept a copy.
    referer[0] = b'X';
    std::hint::black_box(&referer);
    pointer(c, ffi::CURLOPT_USERAGENT, c"ua/1".as_ptr().cast_mut());
    let mut list = ptr::null_mut();
    for line in [c"X-A: 1", c"Accept;"] {
        // SAFETY: a list made here, and a C string.
        list = unsafe { crate::strings::curl_slist_append(list, line.as_ptr()) };
    }
    pointer(c, ffi::CURLOPT_HTTPHEADER, list);
    // Kept by the handle until the option is cleared, as C keeps it.
    let headers = list;
    let mut list = ptr::null_mut();
    for line in [c"a:1:127.0.0.1", c"-b:2"] {
        // SAFETY: a list made here, and a C string.
        list = unsafe { crate::strings::curl_slist_append(list, line.as_ptr()) };
    }
    let resolve = |c| {
        options(c, |o| {
            o.resolve.entries().map(<[u8]>::to_vec).collect::<Vec<_>>()
        })
    };
    assert_eq!(pointer(c, ffi::CURLOPT_RESOLVE, list), CURLE_OK);
    assert_eq!(resolve(c), [b"a:1:127.0.0.1".to_vec(), b"-b:2".to_vec()]);
    assert_eq!(
        pointer(c, ffi::CURLOPT_RESOLVE, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    // SAFETY: the list made above, which the handle no longer keeps.
    unsafe { crate::strings::curl_slist_free_all(list) };
    assert!(resolve(c).is_empty());
    let login = |c| options(c, |o| (o.login.user.clone(), o.login.password.clone()));
    let some = |s: &[u8]| Some(s.to_vec());
    pointer(c, ffi::CURLOPT_USERPWD, c"a:b:c".as_ptr().cast_mut());
    assert_eq!(login(c), (some(b"a"), some(b"b:c")));
    pointer(c, ffi::CURLOPT_PASSWORD, c"pw".as_ptr().cast_mut());
    assert_eq!(login(c), (some(b"a"), some(b"pw")));
    pointer(c, ffi::CURLOPT_USERNAME, c"u".as_ptr().cast_mut());
    assert_eq!(login(c), (some(b"u"), some(b"pw")));
    pointer(c, ffi::CURLOPT_USERPWD, c"x".as_ptr().cast_mut());
    assert_eq!(login(c), (some(b"x"), None));
    pointer(c, ffi::CURLOPT_USERPWD, ptr::null_mut::<c_char>());
    assert_eq!(login(c), (None, None));
    use curl_core::options::NetrcMode;
    let netrc = |c| options(c, |o| (o.netrc.mode, o.netrc.file.clone()));
    assert_eq!(
        long(c, ffi::CURLOPT_NETRC, ffi::CURL_NETRC_REQUIRED),
        CURLE_OK
    );
    pointer(c, ffi::CURLOPT_NETRC_FILE, c"/n".as_ptr().cast_mut());
    assert_eq!(netrc(c), (NetrcMode::Required, some(b"/n")));
    assert_eq!(
        long(c, ffi::CURLOPT_NETRC, ffi::CURL_NETRC_OPTIONAL),
        CURLE_OK
    );
    assert_eq!(netrc(c).0, NetrcMode::Optional);
    assert_eq!(long(c, ffi::CURLOPT_NETRC, 3), CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(long(c, ffi::CURLOPT_NETRC, -1), CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(
        long(c, ffi::CURLOPT_NETRC, ffi::CURL_NETRC_IGNORED),
        CURLE_OK
    );
    assert_eq!(netrc(c).0, NetrcMode::Ignored);
    pointer(c, ffi::CURLOPT_XOAUTH2_BEARER, c"tok".as_ptr().cast_mut());
    assert_eq!(options(c, |o| o.login.bearer.clone()), some(b"tok"));
    // The login's user and password go, the token stays (setopt.c sets
    // `STRING_USERNAME` and `STRING_PASSWORD` alone).
    pointer(c, ffi::CURLOPT_USERPWD, c"v:w".as_ptr().cast_mut());
    assert_eq!(login(c), (some(b"v"), some(b"w")));
    pointer(c, ffi::CURLOPT_USERPWD, ptr::null_mut::<c_char>());
    assert_eq!(login(c), (None, None));
    assert_eq!(options(c, |o| o.login.bearer.clone()), some(b"tok"));
    use curl_core::options::AuthMethods as M;
    let auth = |c| options(c, |o| o.http.auth.0);
    assert_eq!(auth(c), M::BASIC, "Basic unless set");
    let mask = |bits: core::ffi::c_ulong| bits as c_long;
    assert_eq!(
        long(c, ffi::CURLOPT_HTTPAUTH, mask(ffi::CURLAUTH_ANY)),
        CURLE_OK
    );
    assert_eq!(auth(c), M::ANY);
    assert_eq!(crate::getinfo::auth_mask(auth(c)), 1 | 2 | 64 | 128);
    let ie = ffi::CURLAUTH_DIGEST_IE | ffi::CURLAUTH_NTLM;
    assert_eq!(long(c, ffi::CURLOPT_HTTPAUTH, mask(ie)), CURLE_OK);
    assert_eq!(
        auth(c),
        M::DIGEST,
        "the legacy bit is Digest; NTLM is not built in"
    );
    let lacking = ffi::CURLAUTH_NTLM | ffi::CURLAUTH_ONLY;
    assert_eq!(
        long(c, ffi::CURLOPT_HTTPAUTH, mask(lacking)),
        ffi::CURLE_NOT_BUILT_IN
    );
    assert_eq!(auth(c), M::DIGEST, "unchanged");
    // Bits this build does not implement are kept, but for NTLM's; past
    // 32 bits, dropped; with none below `CURLAUTH_ONLY` left, refused.
    let unknown: core::ffi::c_ulong = 1 << 20;
    let sigv4 = ffi::CURLAUTH_AWS_SIGV4;
    for (bits, code, want) in [
        (unknown, CURLE_OK, M::OTHER),
        (unknown | ffi::CURLAUTH_NTLM, CURLE_OK, M::OTHER),
        (unknown | ffi::CURLAUTH_ONLY, CURLE_OK, M::OTHER | M::ONLY),
        (
            ffi::CURLAUTH_BASIC | sigv4,
            CURLE_OK,
            M::BASIC | M::AWS_SIGV4,
        ),
        (sigv4, CURLE_OK, M::AWS_SIGV4),
        (ffi::CURLAUTH_HTTPSIG, CURLE_OK, M::HTTPSIG),
        (
            ffi::CURLAUTH_BEARER | (1 << 30),
            CURLE_OK,
            M::BEARER | M::OTHER,
        ),
        (ffi::CURLAUTH_NTLM, CURLE_NOT_BUILT_IN, M::BEARER | M::OTHER),
        (ffi::CURLAUTH_ONLY, CURLE_NOT_BUILT_IN, M::BEARER | M::OTHER),
    ] {
        assert_eq!(
            long(c, ffi::CURLOPT_HTTPAUTH, mask(bits)),
            code,
            "{bits:#x}"
        );
        assert_eq!(auth(c), want, "{bits:#x}");
        assert_eq!(
            long(c, ffi::CURLOPT_PROXYAUTH, mask(bits)),
            code,
            "{bits:#x}"
        );
        assert_eq!(options(c, |o| o.proxy.auth.0), want, "{bits:#x}");
    }
    #[cfg(target_pointer_width = "64")]
    {
        let high: core::ffi::c_ulong = 1 << 40;
        assert_eq!(
            long(c, ffi::CURLOPT_HTTPAUTH, mask(high)),
            CURLE_NOT_BUILT_IN
        );
        let basic = ffi::CURLAUTH_BASIC | high;
        assert_eq!(long(c, ffi::CURLOPT_HTTPAUTH, mask(basic)), CURLE_OK);
        assert_eq!(auth(c), M::BASIC, "past 32 bits, dropped");
    }
    assert_eq!(long(c, ffi::CURLOPT_HTTPAUTH, 0), CURLE_OK);
    assert_eq!(auth(c), M::NONE);
    let reuse = |c| options(c, |o| o.limits.reuse);
    let max = |c| reuse(c).max_connects.get();
    assert_eq!(long(c, ffi::CURLOPT_MAXCONNECTS, 3), CURLE_OK);
    assert_eq!(max(c), 3);
    assert_eq!(long(c, ffi::CURLOPT_MAXCONNECTS, 0), CURLE_OK);
    assert_eq!(max(c), 5, "0 is the default");
    assert_eq!(long(c, ffi::CURLOPT_MAXCONNECTS, c_long::MAX), CURLE_OK);
    assert_eq!(max(c), i32::MAX as u32, "taken as INT_MAX");
    assert_eq!(
        long(c, ffi::CURLOPT_MAXCONNECTS, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(long(c, ffi::CURLOPT_MAXAGE_CONN, 7), CURLE_OK);
    assert_eq!(long(c, ffi::CURLOPT_MAXLIFETIME_CONN, 0), CURLE_OK);
    let limits = reuse(c);
    assert_eq!(
        limits.max_idle.map(|t| t.duration()),
        Some(std::time::Duration::from_secs(7))
    );
    assert_eq!(limits.max_age, None, "0 is no limit");
    assert_eq!(
        long(c, ffi::CURLOPT_MAXAGE_CONN, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(reuse(c).dns_max_age, Some(Duration::from_secs(60)));
    assert_eq!(long(c, ffi::CURLOPT_DNS_CACHE_TIMEOUT, 0), CURLE_OK);
    assert_eq!(reuse(c).dns_max_age, Some(Duration::ZERO));
    assert_eq!(long(c, ffi::CURLOPT_DNS_CACHE_TIMEOUT, -1), CURLE_OK);
    assert_eq!(reuse(c).dns_max_age, None);
    assert_eq!(
        long(c, ffi::CURLOPT_DNS_CACHE_TIMEOUT, -2),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(reuse(c).dns_max_age, None, "unchanged");
    assert_eq!(long(c, ffi::CURLOPT_FORBID_REUSE, 2), CURLE_OK);
    assert_eq!(long(c, ffi::CURLOPT_FRESH_CONNECT, 1), CURLE_OK);
    assert!(reuse(c).forbid && reuse(c).fresh);
    assert_eq!(long(c, ffi::CURLOPT_FORBID_REUSE, 0), CURLE_OK);
    assert!(!reuse(c).forbid);
    let mut list = ptr::null_mut();
    for line in [c"::a:1", c"b:2:c:3"] {
        // SAFETY: a list made here, and a C string.
        list = unsafe { crate::strings::curl_slist_append(list, line.as_ptr()) };
    }
    let connect_to = |c| {
        options(c, |o| {
            o.connect_to.iter().map(<[u8]>::to_vec).collect::<Vec<_>>()
        })
    };
    assert_eq!(pointer(c, ffi::CURLOPT_CONNECT_TO, list), CURLE_OK);
    assert_eq!(connect_to(c), [b"::a:1".to_vec(), b"b:2:c:3".to_vec()]);
    assert_eq!(
        pointer(c, ffi::CURLOPT_CONNECT_TO, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    // SAFETY: the list made above, which the handle no longer keeps.
    unsafe { crate::strings::curl_slist_free_all(list) };
    assert!(connect_to(c).is_empty());
    assert_eq!(
        strings(c),
        (
            Some(b"http://r/".to_vec()),
            Some(b"ua/1".to_vec()),
            vec![b"X-A: 1".to_vec(), b"Accept;".to_vec()]
        )
    );
    let null = ptr::null_mut::<c_char>();
    for o in [
        ffi::CURLOPT_REFERER,
        ffi::CURLOPT_USERAGENT,
        ffi::CURLOPT_HTTPHEADER,
    ] {
        assert_eq!(pointer(c, o, null), CURLE_OK);
    }
    assert_eq!(strings(c), (None, None, vec![]));
    // SAFETY: the list made above, which the handle no longer keeps.
    unsafe { crate::strings::curl_slist_free_all(headers) };
    // Nothing raises a signal: the option is taken and changes nothing.
    assert_eq!(long(c, ffi::CURLOPT_NOSIGNAL, 1), CURLE_OK);
    let version = |c| options(c, |o| o.http.version);
    assert_eq!(
        long(c, ffi::CURLOPT_HTTP_VERSION, ffi::CURL_HTTP_VERSION_1_0),
        CURLE_OK
    );
    assert_eq!(version(c), HttpVersion::Http10);
    assert_eq!(
        long(c, ffi::CURLOPT_HTTP_VERSION, ffi::CURL_HTTP_VERSION_NONE),
        CURLE_OK
    );
    assert_eq!(version(c), HttpVersion::Http11);
    for (v, code) in [
        (ffi::CURL_HTTP_VERSION_2_0, ffi::CURLE_UNSUPPORTED_PROTOCOL),
        (ffi::CURL_HTTP_VERSION_3, ffi::CURLE_UNSUPPORTED_PROTOCOL),
        (-1, CURLE_BAD_FUNCTION_ARGUMENT),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_HTTP_VERSION, v), code, "{v}");
    }
    assert_eq!(version(c), HttpVersion::Http11);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

#[test]
fn the_method_follows_nobody_and_upload_as_in_c() {
    let c = curl_easy_init();
    let method = |c| options(c, |o| o.method);
    let reads = |c| {
        options(c, |o| match &o.upload {
            UploadSource::Read { size, .. } => Some(*size),
            _ => None,
        })
    };
    assert_eq!(long(c, ffi::CURLOPT_NOBODY, 1), CURLE_OK);
    assert_eq!(method(c), Method::Head);
    assert_eq!(long(c, ffi::CURLOPT_NOBODY, 0), CURLE_OK);
    assert_eq!(method(c), Method::Get);
    assert_eq!(reads(c), None);
    assert_eq!(long(c, ffi::CURLOPT_UPLOAD, 1), CURLE_OK);
    assert_eq!((method(c), reads(c)), (Method::Upload, Some(None)));
    // No body is not a head once uploading.
    assert_eq!(long(c, ffi::CURLOPT_NOBODY, 0), CURLE_OK);
    assert_eq!(method(c), Method::Upload);
    assert_eq!(long(c, ffi::CURLOPT_INFILESIZE, 5), CURLE_OK);
    assert_eq!(reads(c), Some(Some(5)));
    assert_eq!(off(c, ffi::CURLOPT_INFILESIZE_LARGE, 7), CURLE_OK);
    assert_eq!(reads(c), Some(Some(7)));
    for bad in [-2, c_long::MIN] {
        assert_eq!(
            long(c, ffi::CURLOPT_INFILESIZE, bad),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
        assert_eq!(
            off(c, ffi::CURLOPT_INFILESIZE_LARGE, bad),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    assert_eq!(reads(c), Some(Some(7)), "a refused size changes nothing");
    assert_eq!(long(c, ffi::CURLOPT_INFILESIZE, -1), CURLE_OK);
    assert_eq!(reads(c), Some(None));
    assert_eq!(long(c, ffi::CURLOPT_INFILESIZE, 0), CURLE_OK);
    assert_eq!(reads(c), Some(Some(0)));
    assert_eq!(long(c, ffi::CURLOPT_UPLOAD, 0), CURLE_OK);
    assert_eq!((method(c), reads(c)), (Method::Get, None));
    assert_eq!(long(c, ffi::CURLOPT_PUT, 1), CURLE_OK);
    assert_eq!(method(c), Method::Upload);
    assert_eq!(long(c, ffi::CURLOPT_NOBODY, 1), CURLE_OK);
    assert_eq!((method(c), reads(c)), (Method::Head, None));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// The POST options combine as setopt.c and `Curl_pretransfer` combine
/// them: the fields, copied or not, sized or up to their zero byte, kept
/// across other methods; without them the read function.
#[test]
fn the_post_options_combine_as_in_c() {
    #[derive(Debug, PartialEq)]
    enum Body {
        None,
        Bytes(Vec<u8>),
        Lent(u64),
        Read(Option<u64>),
        Mime,
    }
    let c = curl_easy_init();
    let body = |c| {
        options(c, |o| match &o.upload {
            UploadSource::None => Body::None,
            UploadSource::Bytes(b) => Body::Bytes(b.to_vec()),
            UploadSource::Lent(b) => Body::Lent(curl_core::handler::LentBytes::size(&**b)),
            UploadSource::Read { size, .. } => Body::Read(*size),
            UploadSource::Mime(_) => Body::Mime,
        })
    };
    let method = |c| options(c, |o| o.method);
    assert_eq!(long(c, ffi::CURLOPT_POST, 1), CURLE_OK);
    assert_eq!((method(c), body(c)), (Method::Post, Body::Read(None)));
    assert_eq!(long(c, ffi::CURLOPT_POSTFIELDSIZE, 0), CURLE_OK);
    assert_eq!(body(c), Body::Read(Some(0)));
    assert_eq!(off(c, ffi::CURLOPT_POSTFIELDSIZE_LARGE, -1), CURLE_OK);
    let mut text = *b"abc\0def";
    assert_eq!(
        pointer(c, ffi::CURLOPT_COPYPOSTFIELDS, text.as_mut_ptr()),
        CURLE_OK
    );
    text[0] = b'X';
    assert_eq!(
        body(c),
        Body::Bytes(b"abc".to_vec()),
        "copied to its zero byte"
    );
    assert_eq!(long(c, ffi::CURLOPT_POSTFIELDSIZE, 2), CURLE_OK);
    assert_eq!(
        body(c),
        Body::Read(Some(2)),
        "a size above the last drops the copy"
    );
    assert_eq!(long(c, ffi::CURLOPT_POSTFIELDSIZE, 7), CURLE_OK);
    assert_eq!(
        pointer(c, ffi::CURLOPT_COPYPOSTFIELDS, text.as_mut_ptr()),
        CURLE_OK
    );
    assert_eq!(
        body(c),
        Body::Bytes(b"Xbc\0def".to_vec()),
        "sized, zero bytes and all"
    );
    assert_eq!(long(c, ffi::CURLOPT_POSTFIELDSIZE, 2), CURLE_OK);
    assert_eq!(
        body(c),
        Body::Bytes(b"Xb".to_vec()),
        "a smaller size cuts it"
    );
    assert_eq!(long(c, ffi::CURLOPT_POSTFIELDSIZE, -1), CURLE_OK);
    assert_eq!(
        pointer(c, ffi::CURLOPT_POSTFIELDS, text.as_mut_ptr()),
        CURLE_OK
    );
    assert_eq!(
        body(c),
        Body::Lent(3),
        "the application's, to its zero byte"
    );
    assert_eq!(long(c, ffi::CURLOPT_UPLOAD, 1), CURLE_OK);
    assert_eq!((method(c), body(c)), (Method::Upload, Body::Read(None)));
    assert_eq!(long(c, ffi::CURLOPT_POST, 1), CURLE_OK);
    assert_eq!(body(c), Body::Lent(3), "the fields are kept");
    assert_eq!(long(c, ffi::CURLOPT_HTTPGET, 1), CURLE_OK);
    assert_eq!((method(c), body(c)), (Method::Get, Body::None));
    assert_eq!(
        pointer(c, ffi::CURLOPT_POSTFIELDS, ptr::null_mut::<u8>()),
        CURLE_OK
    );
    assert_eq!((method(c), body(c)), (Method::Post, Body::Read(None)));
    assert_eq!(
        long(c, ffi::CURLOPT_POSTFIELDSIZE, -2),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    // From the read function, the size given stands, though a body
    // asked chunked is read to its end: the request decides that as it
    // is built.
    assert_eq!(long(c, ffi::CURLOPT_POSTFIELDSIZE, 5), CURLE_OK);
    assert_eq!(body(c), Body::Read(Some(5)));
    let mut te = *b"Transfer-Encoding: chunked\0";
    // SAFETY: a C string, alive for the call.
    let list =
        unsafe { crate::strings::curl_slist_append(ptr::null_mut(), te.as_mut_ptr().cast()) };
    assert_eq!(pointer(c, ffi::CURLOPT_HTTPHEADER, list), CURLE_OK);
    assert_eq!(body(c), Body::Read(Some(5)));
    assert_eq!(
        pointer(c, ffi::CURLOPT_POSTFIELDS, text.as_mut_ptr()),
        CURLE_OK
    );
    assert_eq!(body(c), Body::Lent(5));
    pointer(c, ffi::CURLOPT_HTTPHEADER, ptr::null_mut::<c_char>());
    // SAFETY: made above, no longer kept by the handle, not used again.
    unsafe { crate::strings::curl_slist_free_all(list) };
    assert_eq!(long(c, ffi::CURLOPT_POST, 0), CURLE_OK);
    assert_eq!(method(c), Method::Get);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

#[test]
fn limits_are_checked_as_in_c() {
    let c = curl_easy_init();
    let total = |c| options(c, |o| o.limits.total.map(|t| t.duration()));
    let connect = |c| options(c, |o| o.limits.connect.map(|t| t.duration()));
    let ms = Duration::from_millis;
    for (o, get, unit) in [
        (
            ffi::CURLOPT_TIMEOUT,
            total as fn(*mut CURL) -> Option<Duration>,
            1000,
        ),
        (ffi::CURLOPT_TIMEOUT_MS, total, 1),
        (ffi::CURLOPT_CONNECTTIMEOUT, connect, 1000),
        (ffi::CURLOPT_CONNECTTIMEOUT_MS, connect, 1),
    ] {
        assert_eq!(long(c, o, 3), CURLE_OK);
        assert_eq!(get(c), Some(ms(3 * unit)), "{}", o.0);
        assert_eq!(long(c, o, -1), CURLE_BAD_FUNCTION_ARGUMENT);
        assert_eq!(get(c), Some(ms(3 * unit)));
        assert_eq!(long(c, o, 0), CURLE_OK);
        assert_eq!(get(c), None);
    }
    let low = |c| {
        options(c, |o| {
            o.limits.low_speed.map(|l| (l.limit.get(), l.time.get()))
        })
    };
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_LIMIT, 10), CURLE_OK);
    assert_eq!(low(c), None, "no time yet");
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_TIME, 3), CURLE_OK);
    assert_eq!(low(c), Some((10, 3)));
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_TIME, 70000), CURLE_OK);
    assert_eq!(low(c), Some((10, 65535)), "C clamps to USHRT_MAX");
    assert_eq!(
        long(c, ffi::CURLOPT_LOW_SPEED_TIME, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_TIME, 0), CURLE_OK);
    assert_eq!(low(c), None, "no time");
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_TIME, 70000), CURLE_OK);
    assert_eq!(
        long(c, ffi::CURLOPT_LOW_SPEED_LIMIT, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(low(c), Some((10, 65535)));
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_LIMIT, 0), CURLE_OK);
    assert_eq!(low(c), None);
    let max = |c| options(c, |o| o.limits.max_filesize.map(|m| m.get()));
    assert_eq!(long(c, ffi::CURLOPT_MAXFILESIZE, 7), CURLE_OK);
    assert_eq!(max(c), Some(7));
    assert_eq!(
        long(c, ffi::CURLOPT_MAXFILESIZE, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(
        off(c, ffi::CURLOPT_MAXFILESIZE_LARGE, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(max(c), Some(7));
    assert_eq!(off(c, ffi::CURLOPT_MAXFILESIZE_LARGE, 1 << 40), CURLE_OK);
    assert_eq!(max(c), Some(1 << 40));
    assert_eq!(long(c, ffi::CURLOPT_MAXFILESIZE, 0), CURLE_OK);
    assert_eq!(max(c), None);
    let resume = |c| options(c, |o| o.resume);
    assert_eq!(long(c, ffi::CURLOPT_RESUME_FROM, 9), CURLE_OK);
    assert_eq!(resume(c), Some(Resume::At(9.try_into().unwrap())));
    assert_eq!(long(c, ffi::CURLOPT_RESUME_FROM, -1), CURLE_OK);
    assert_eq!(resume(c), Some(Resume::AtEnd));
    assert_eq!(
        long(c, ffi::CURLOPT_RESUME_FROM, -2),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(
        off(c, ffi::CURLOPT_RESUME_FROM_LARGE, -2),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(resume(c), Some(Resume::AtEnd));
    assert_eq!(off(c, ffi::CURLOPT_RESUME_FROM_LARGE, 1 << 40), CURLE_OK);
    assert_eq!(
        resume(c),
        Some(Resume::At((1u64 << 40).try_into().unwrap()))
    );
    assert_eq!(long(c, ffi::CURLOPT_RESUME_FROM, 0), CURLE_OK);
    assert_eq!(resume(c), None);
    let mode = |c| options(c, |o| o.new_file_mode.bits());
    assert_eq!(long(c, ffi::CURLOPT_NEW_FILE_PERMS, 0o600), CURLE_OK);
    assert_eq!(mode(c), 0o600);
    for bad in [0o1000, -1] {
        assert_eq!(
            long(c, ffi::CURLOPT_NEW_FILE_PERMS, bad),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    assert_eq!(mode(c), 0o600);
    let ip = |c| options(c, |o| o.ip_version);
    assert_eq!(
        long(c, ffi::CURLOPT_IPRESOLVE, ffi::CURL_IPRESOLVE_V6),
        CURLE_OK
    );
    assert_eq!(ip(c), curl_core::options::IpVersion::V6);
    for bad in [3, -1] {
        assert_eq!(
            long(c, ffi::CURLOPT_IPRESOLVE, bad),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    assert_eq!(ip(c), curl_core::options::IpVersion::V6);
    assert_eq!(
        long(c, ffi::CURLOPT_IPRESOLVE, ffi::CURL_IPRESOLVE_V4),
        CURLE_OK
    );
    assert_eq!(ip(c), curl_core::options::IpVersion::V4);
    assert_eq!(
        long(c, ffi::CURLOPT_IPRESOLVE, ffi::CURL_IPRESOLVE_WHATEVER),
        CURLE_OK
    );
    assert_eq!(ip(c), curl_core::options::IpVersion::Any);
    let scope = |c| options(c, |o| o.address_scope.map(std::num::NonZeroU32::get));
    assert_eq!(long(c, ffi::CURLOPT_ADDRESS_SCOPE, 7), CURLE_OK);
    assert_eq!(scope(c), Some(7));
    for bad in [-1, c_long::from(u32::MAX) + 1] {
        assert_eq!(
            long(c, ffi::CURLOPT_ADDRESS_SCOPE, bad),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    assert_eq!(scope(c), Some(7));
    assert_eq!(
        long(c, ffi::CURLOPT_ADDRESS_SCOPE, c_long::from(u32::MAX)),
        CURLE_OK
    );
    assert_eq!(scope(c), Some(u32::MAX));
    assert_eq!(long(c, ffi::CURLOPT_ADDRESS_SCOPE, 0), CURLE_OK);
    assert_eq!(scope(c), None);
    let he = |c| options(c, |o| o.limits.eyeballs.0);
    assert_eq!(he(c), std::time::Duration::from_millis(200), "C's default");
    assert_eq!(long(c, ffi::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS, 0), CURLE_OK);
    assert_eq!(he(c), std::time::Duration::ZERO);
    assert_eq!(
        long(c, ffi::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(he(c), std::time::Duration::ZERO);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// The redirect, wait and condition options, checked as setopt.c checks
/// them: refused out of range, clamped where C clamps.
#[test]
fn http_ranges_are_checked_as_in_c() {
    use curl_core::options::{Condition, Follow, MaxRedirects, PostRedir, TimeCondition};
    let c = curl_easy_init();
    let bad = CURLE_BAD_FUNCTION_ARGUMENT;
    let follow = |c| options(c, |o| o.http.follow);
    for (v, want) in [
        (0, Follow::No),
        (ffi::CURLFOLLOW_ALL, Follow::All),
        (ffi::CURLFOLLOW_OBEYCODE, Follow::ObeyCode),
        (ffi::CURLFOLLOW_FIRSTONLY, Follow::FirstOnly),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_FOLLOWLOCATION, v), CURLE_OK);
        assert_eq!(follow(c), want, "{v}");
    }
    for v in [4, -1] {
        assert_eq!(long(c, ffi::CURLOPT_FOLLOWLOCATION, v), bad, "{v}");
    }
    assert_eq!(follow(c), Follow::FirstOnly, "unchanged");
    let redirects = |c| options(c, |o| o.http.max_redirects);
    assert_eq!(redirects(c), MaxRedirects(Some(30)), "C's default");
    for (v, want) in [
        (-1, None),
        (0, Some(0)),
        (5, Some(5)),
        (0x8000, Some(0x7fff)),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_MAXREDIRS, v), CURLE_OK);
        assert_eq!(redirects(c), MaxRedirects(want), "{v}");
    }
    assert_eq!(long(c, ffi::CURLOPT_MAXREDIRS, -2), bad);
    assert_eq!(redirects(c), MaxRedirects(Some(0x7fff)), "unchanged");
    let post = |c| {
        options(c, |o| {
            let p = o.http.post_redirect;
            [p.post301, p.post302, p.post303]
        })
    };
    for (v, want) in [
        (ffi::CURL_REDIR_POST_ALL, [true; 3]),
        (ffi::CURL_REDIR_GET_ALL, [false; 3]),
        (ffi::CURL_REDIR_POST_301, [true, false, false]),
        (ffi::CURL_REDIR_POST_302, [false, true, false]),
        (ffi::CURL_REDIR_POST_303, [false, false, true]),
        // Bits past 303's are ignored.
        (8, [false; 3]),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_POSTREDIR, v), CURLE_OK);
        assert_eq!(post(c), want, "{v}");
    }
    long(c, ffi::CURLOPT_POSTREDIR, ffi::CURL_REDIR_POST_301);
    assert_eq!(long(c, ffi::CURLOPT_POSTREDIR, -1), bad);
    assert_eq!(
        options(c, |o| o.http.post_redirect),
        PostRedir {
            post301: true,
            post302: false,
            post303: false
        },
        "unchanged"
    );
    let wait = |c| options(c, |o| o.http.continue_wait.0);
    assert_eq!(wait(c), Duration::from_secs(1), "C's default");
    for (v, ms) in [(0, 0), (500, 500), (70000, 65535)] {
        assert_eq!(long(c, ffi::CURLOPT_EXPECT_100_TIMEOUT_MS, v), CURLE_OK);
        assert_eq!(wait(c), Duration::from_millis(ms), "{v}");
    }
    assert_eq!(long(c, ffi::CURLOPT_EXPECT_100_TIMEOUT_MS, -1), bad);
    assert_eq!(wait(c), Duration::from_millis(65535), "unchanged");
    let port = |c| options(c, |o| o.port.map(|p| p.get()));
    for (v, want) in [(80, Some(80)), (65535, Some(65535)), (0, None)] {
        assert_eq!(long(c, ffi::CURLOPT_PORT, v), CURLE_OK);
        assert_eq!(port(c), want, "{v}");
    }
    long(c, ffi::CURLOPT_PORT, 8080);
    for v in [65536, -1] {
        assert_eq!(long(c, ffi::CURLOPT_PORT, v), bad, "{v}");
    }
    assert_eq!(port(c), Some(8080), "unchanged");
    // The condition and its time, whichever is set first.
    let condition = |c| options(c, |o| o.time_condition);
    let at = |when, time| Some(TimeCondition { when, time });
    assert_eq!(long(c, ffi::CURLOPT_TIMEVALUE, 1000), CURLE_OK);
    assert_eq!(condition(c), None, "no condition yet");
    for (v, want) in [
        (
            ffi::CURL_TIMECOND_IFMODSINCE,
            at(Condition::ModifiedSince, 1000),
        ),
        (
            ffi::CURL_TIMECOND_IFUNMODSINCE,
            at(Condition::UnmodifiedSince, 1000),
        ),
        (
            ffi::CURL_TIMECOND_LASTMOD,
            at(Condition::LastModified, 1000),
        ),
        (ffi::CURL_TIMECOND_NONE, None),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_TIMECONDITION, v), CURLE_OK);
        assert_eq!(condition(c), want, "{v}");
    }
    long(c, ffi::CURLOPT_TIMECONDITION, ffi::CURL_TIMECOND_IFMODSINCE);
    for v in [4, -1] {
        assert_eq!(long(c, ffi::CURLOPT_TIMECONDITION, v), bad, "{v}");
    }
    assert_eq!(
        condition(c),
        at(Condition::ModifiedSince, 1000),
        "unchanged"
    );
    assert_eq!(off(c, ffi::CURLOPT_TIMEVALUE_LARGE, 1 << 40), CURLE_OK);
    assert_eq!(condition(c), at(Condition::ModifiedSince, 1 << 40));
    assert_eq!(long(c, ffi::CURLOPT_TIMEVALUE, -5), CURLE_OK);
    assert_eq!(condition(c), at(Condition::ModifiedSince, -5));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

#[test]
fn strings_are_copied_and_bounded() {
    let c = curl_easy_init();
    let url = c"file:///x";
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(
        options(c, |o| o.url().map(<[u8]>::to_vec)),
        Some(b"file:///x".to_vec())
    );
    let scheme = c"file";
    assert_eq!(
        pointer(c, ffi::CURLOPT_DEFAULT_PROTOCOL, scheme.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(
        options(c, |o| o.default_protocol().map(<[u8]>::to_vec)),
        Some(b"file".to_vec())
    );
    let mut long_one = vec![b'a'; 8_000_001];
    long_one.push(0);
    for o in [ffi::CURLOPT_URL, ffi::CURLOPT_DEFAULT_PROTOCOL] {
        assert_eq!(
            pointer(c, o, long_one.as_mut_ptr()),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    long_one[8_000_000] = 0;
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, long_one.as_mut_ptr()),
        CURLE_OK,
        "the longest C takes"
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_DEFAULT_PROTOCOL, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    assert_eq!(
        options(c, |o| (o.url().is_none(), o.default_protocol().is_none())),
        (true, true)
    );
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// The request's strings are copied and NULL takes them away; an empty
/// `CURLOPT_ACCEPT_ENCODING` asks for every coding; a `CURLU` handle
/// takes the URL's place.
#[test]
fn request_strings_reach_the_transfer() {
    use curl_core::coding::AcceptEncoding;
    let c = curl_easy_init();
    let null = ptr::null_mut::<c_char>();
    let encoding = |c| {
        options(c, |o| match &o.http.accept_encoding {
            None => None,
            Some(AcceptEncoding::All) => Some(None),
            Some(AcceptEncoding::Given(v)) => Some(Some(v.clone())),
        })
    };
    assert_eq!(encoding(c), None);
    pointer(c, ffi::CURLOPT_ACCEPT_ENCODING, c"".as_ptr().cast_mut());
    assert_eq!(encoding(c), Some(None));
    pointer(c, ffi::CURLOPT_ACCEPT_ENCODING, c"gzip".as_ptr().cast_mut());
    assert_eq!(encoding(c), Some(Some(b"gzip".to_vec())));
    pointer(c, ffi::CURLOPT_ACCEPT_ENCODING, null);
    assert_eq!(encoding(c), None);
    let jar_path = std::env::temp_dir().join(format!("curl-shim-{}-jar", std::process::id()));
    let jar = std::ffi::CString::new(jar_path.to_str().unwrap()).unwrap();
    pointer(c, ffi::CURLOPT_CUSTOMREQUEST, c"FOO".as_ptr().cast_mut());
    pointer(c, ffi::CURLOPT_COOKIE, c"a=1".as_ptr().cast_mut());
    pointer(c, ffi::CURLOPT_COOKIEFILE, c"/f1".as_ptr().cast_mut());
    pointer(c, ffi::CURLOPT_COOKIEFILE, c"/f2".as_ptr().cast_mut());
    assert_eq!(
        pointer(c, ffi::CURLOPT_COOKIEJAR, jar.as_ptr().cast_mut()),
        CURLE_OK
    );
    let strings = |c| {
        options(c, |o| {
            let k = &o.http.cookies;
            (
                o.http.custom_method.clone(),
                k.send.clone(),
                k.files.iter().map(<[u8]>::to_vec).collect::<Vec<_>>(),
                k.save_to.clone(),
            )
        })
    };
    assert_eq!(
        strings(c),
        (
            Some(b"FOO".to_vec()),
            Some(b"a=1".to_vec()),
            vec![b"/f1".to_vec(), b"/f2".to_vec()],
            Some(jar.as_bytes().to_vec())
        )
    );
    for o in [
        ffi::CURLOPT_CUSTOMREQUEST,
        ffi::CURLOPT_COOKIE,
        ffi::CURLOPT_COOKIEFILE,
        ffi::CURLOPT_COOKIEJAR,
    ] {
        assert_eq!(pointer(c, o, null), CURLE_OK);
    }
    assert_eq!(strings(c), (None, None, vec![], None));
    pointer(c, ffi::CURLOPT_URL, c"file:///x".as_ptr().cast_mut());
    let u = crate::url::curl_url();
    assert_eq!(pointer(c, ffi::CURLOPT_CURLU, u), CURLE_OK);
    // SAFETY: made above; the handle keeps its own reference.
    unsafe { crate::url::curl_url_cleanup(u) };
    let urls = |c| options(c, |o| (o.url().is_some(), o.shared_url().is_some()));
    assert_eq!(urls(c), (false, true), "in the URL's place");
    assert_eq!(pointer(c, ffi::CURLOPT_CURLU, null), CURLE_OK);
    assert_eq!(urls(c), (false, false));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    assert!(
        !jar_path.exists(),
        "no jar is written once its name is gone"
    );
}

type TrailerFn = unsafe extern "C" fn(*mut *mut ffi::curl_slist, *mut c_void) -> c_int;

/// What a trailer function adds, and answers.
struct Trailing {
    lines: Vec<&'static CStr>,
    answer: c_int,
}

unsafe extern "C" fn trailers(list: *mut *mut ffi::curl_slist, data: *mut c_void) -> c_int {
    // SAFETY: the test passes a `Trailing`, and the shim a list to add to.
    unsafe {
        let t = &*data.cast::<Trailing>();
        for line in &t.lines {
            *list = crate::strings::curl_slist_append(*list, line.as_ptr());
        }
        t.answer
    }
}

#[test]
fn callback_options_install_their_adapters() {
    let c = curl_easy_init();
    let installed = |c| {
        options(c, |o| {
            let cb = &o.callbacks;
            (
                cb.header.is_some(),
                cb.debug.is_some(),
                cb.stderr.is_some(),
                cb.failure.is_some(),
                cb.trailer.is_some(),
            )
        })
    };
    assert_eq!(
        installed(c),
        (false, false, false, false, false),
        "a new handle needs none"
    );
    let f = sink as WriteFn as *const ();
    let mut data = 0u8;
    assert_eq!(function(c, ffi::CURLOPT_HEADERFUNCTION, f), CURLE_OK);
    assert!(installed(c).0);
    assert_eq!(
        function(c, ffi::CURLOPT_HEADERFUNCTION, ptr::null()),
        CURLE_OK
    );
    assert!(!installed(c).0);
    assert_eq!(pointer(c, ffi::CURLOPT_HEADERDATA, &raw mut data), CURLE_OK);
    assert!(
        installed(c).0,
        "header data alone sends headers to the write function"
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_HEADERDATA, ptr::null_mut::<u8>()),
        CURLE_OK
    );
    assert!(!installed(c).0);
    let d = debug_count as DebugFn as *const ();
    assert_eq!(function(c, ffi::CURLOPT_DEBUGFUNCTION, d), CURLE_OK);
    assert!(installed(c).1);
    assert_eq!(
        function(c, ffi::CURLOPT_DEBUGFUNCTION, ptr::null()),
        CURLE_OK
    );
    assert!(!installed(c).1);
    let stream = tmpfile();
    assert_eq!(pointer(c, ffi::CURLOPT_STDERR, stream), CURLE_OK);
    assert!(installed(c).2);
    assert_eq!(
        pointer(c, ffi::CURLOPT_STDERR, ptr::null_mut::<libc::FILE>()),
        CURLE_OK
    );
    assert!(!installed(c).2, "NULL is standard error again");
    assert_eq!(ccb(c).stderr, crate::callbacks::standard().2);
    let mut buf = [0 as c_char; 256];
    assert_eq!(
        pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr()),
        CURLE_OK
    );
    assert!(installed(c).3);
    assert_eq!(
        pointer(c, ffi::CURLOPT_ERRORBUFFER, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    assert!(!installed(c).3);
    let t = trailers as TrailerFn as *const ();
    for _ in 0..2 {
        assert_eq!(function(c, ffi::CURLOPT_TRAILERFUNCTION, t), CURLE_OK);
        assert!(installed(c).4);
    }
    assert_eq!(
        function(c, ffi::CURLOPT_TRAILERFUNCTION, ptr::null()),
        CURLE_OK
    );
    assert!(!installed(c).4);
    let progress = |c| {
        options(c, |o| match o.progress {
            Progress::Off => 0,
            Progress::Meter => 1,
            Progress::Handler(_) => 2,
        })
    };
    assert_eq!(progress(c), 0);
    assert_eq!(long(c, ffi::CURLOPT_NOPROGRESS, 0), CURLE_OK);
    assert_eq!(progress(c), 1);
    let x = xferinfo as XferFn as *const ();
    assert_eq!(function(c, ffi::CURLOPT_XFERINFOFUNCTION, x), CURLE_OK);
    assert_eq!(progress(c), 2);
    assert_eq!(
        function(c, ffi::CURLOPT_XFERINFOFUNCTION, ptr::null()),
        CURLE_OK
    );
    assert_eq!(progress(c), 1);
    let p = old_progress as ProgressFn as *const ();
    assert_eq!(function(c, ffi::CURLOPT_PROGRESSFUNCTION, p), CURLE_OK);
    assert_eq!(progress(c), 2);
    assert_eq!(long(c, ffi::CURLOPT_NOPROGRESS, 1), CURLE_OK);
    assert_eq!(progress(c), 0);
    // The data options and the rest of the functions are kept for the
    // adapters.
    let mut d2 = 0u8;
    let at = (&raw mut d2).cast::<c_void>();
    for o in [
        ffi::CURLOPT_WRITEDATA,
        ffi::CURLOPT_READDATA,
        ffi::CURLOPT_SEEKDATA,
        ffi::CURLOPT_IOCTLDATA,
        ffi::CURLOPT_XFERINFODATA,
        ffi::CURLOPT_DEBUGDATA,
        ffi::CURLOPT_TRAILERDATA,
        ffi::CURLOPT_PRIVATE,
    ] {
        assert_eq!(pointer(c, o, at), CURLE_OK);
    }
    let k = ccb(c);
    assert_eq!(
        [
            k.write_data,
            k.read_data,
            k.seek_data,
            k.ioctl_data,
            k.progress_data,
            k.debug_data,
            k.trailer_data
        ],
        [at; 7]
    );
    assert_eq!(info::<*mut c_char>(c, ffi::CURLINFO_PRIVATE).cast(), at);
    for o in [
        ffi::CURLOPT_WRITEFUNCTION,
        ffi::CURLOPT_READFUNCTION,
        ffi::CURLOPT_SEEKFUNCTION,
        ffi::CURLOPT_IOCTLFUNCTION,
    ] {
        assert_eq!(function(c, o, f), CURLE_OK);
    }
    let k = ccb(c);
    assert!(k.write.is_some() && k.read.is_some() && k.seek.is_some() && k.ioctl.is_some());
    close(stream);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

#[test]
fn ids_are_told_apart_as_c_tells_them() {
    let c = curl_easy_init();
    assert_eq!(long(c, ffi::CURLOPT_LOCALPORT, 80), CURLE_NOT_BUILT_IN);
    for unknown in [9999, 10999, 50000] {
        assert_eq!(
            long(c, CURLoption(unknown), 0),
            CURLE_UNKNOWN_OPTION,
            "{unknown}"
        );
    }
    assert_eq!(
        long(ptr::null_mut(), ffi::CURLOPT_VERBOSE, 1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// Every info a file transfer answers, against the report it reads.
#[test]
fn infos_answer_from_the_report() {
    let (path, url) = file("infos", b"hello");
    let c = curl_easy_init();
    // Not run yet: no time is known, and the URL is empty.
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_FILETIME), -1);
    let before = info::<*const c_char>(c, ffi::CURLINFO_EFFECTIVE_URL);
    // SAFETY: getinfo gives a string that lives while the handle does.
    assert_eq!(unsafe { CStr::from_ptr(before) }, c"");
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_FILETIME_T), -1);
    // Never added to a multi, nor connected.
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_XFER_ID), -1);
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_CONN_ID), -1);
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let secs = |d: Duration| d.as_micros() as f64 / 1e6;
    let us = |d: Duration| d.as_micros() as curl_off_t;
    let (times, sizes, speeds, filetime) = report(c, |r| {
        let t = r.timings();
        (
            [
                t.total(),
                t.namelookup(),
                t.connect(),
                t.appconnect(),
                t.pretransfer(),
                t.starttransfer(),
                t.redirect(),
                t.posttransfer(),
                t.queue(),
            ],
            (
                r.sizes().download(),
                r.sizes().delivered(),
                r.sizes().upload(),
            ),
            (r.speeds().download(), r.speeds().upload()),
            r.filetime().expect("a file has one"),
        )
    });
    for (i, t) in [
        ffi::CURLINFO_TOTAL_TIME,
        ffi::CURLINFO_NAMELOOKUP_TIME,
        ffi::CURLINFO_CONNECT_TIME,
        ffi::CURLINFO_APPCONNECT_TIME,
        ffi::CURLINFO_PRETRANSFER_TIME,
        ffi::CURLINFO_STARTTRANSFER_TIME,
        ffi::CURLINFO_REDIRECT_TIME,
    ]
    .into_iter()
    .zip(times)
    {
        assert_eq!(info::<f64>(c, i), secs(t), "{}", i.0);
    }
    for (i, t) in [
        ffi::CURLINFO_TOTAL_TIME_T,
        ffi::CURLINFO_NAMELOOKUP_TIME_T,
        ffi::CURLINFO_CONNECT_TIME_T,
        ffi::CURLINFO_APPCONNECT_TIME_T,
        ffi::CURLINFO_PRETRANSFER_TIME_T,
        ffi::CURLINFO_STARTTRANSFER_TIME_T,
        ffi::CURLINFO_REDIRECT_TIME_T,
        ffi::CURLINFO_POSTTRANSFER_TIME_T,
        ffi::CURLINFO_QUEUE_TIME_T,
    ]
    .into_iter()
    .zip(times)
    {
        assert_eq!(info::<curl_off_t>(c, i), us(t), "{}", i.0);
    }
    assert_eq!(sizes, (5, 5, 0));
    assert_eq!(info::<f64>(c, ffi::CURLINFO_SIZE_DOWNLOAD), 5.0);
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_SIZE_DOWNLOAD_T), 5);
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_SIZE_DELIVERED), 5);
    // A file has no head.
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_HEADER_SIZE), 0);
    assert_eq!(info::<f64>(c, ffi::CURLINFO_SIZE_UPLOAD), 0.0);
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_SIZE_UPLOAD_T), 0);
    assert_eq!(
        info::<f64>(c, ffi::CURLINFO_SPEED_DOWNLOAD),
        speeds.0 as f64
    );
    assert_eq!(
        info::<curl_off_t>(c, ffi::CURLINFO_SPEED_DOWNLOAD_T),
        speeds.0 as curl_off_t
    );
    assert_eq!(info::<f64>(c, ffi::CURLINFO_SPEED_UPLOAD), speeds.1 as f64);
    assert_eq!(
        info::<curl_off_t>(c, ffi::CURLINFO_SPEED_UPLOAD_T),
        speeds.1 as curl_off_t
    );
    assert_eq!(info::<f64>(c, ffi::CURLINFO_CONTENT_LENGTH_DOWNLOAD), 5.0);
    assert_eq!(
        info::<curl_off_t>(c, ffi::CURLINFO_CONTENT_LENGTH_DOWNLOAD_T),
        5
    );
    assert_eq!(info::<f64>(c, ffi::CURLINFO_CONTENT_LENGTH_UPLOAD), -1.0);
    assert_eq!(
        info::<curl_off_t>(c, ffi::CURLINFO_CONTENT_LENGTH_UPLOAD_T),
        -1
    );
    assert_eq!(
        info::<c_long>(c, ffi::CURLINFO_FILETIME),
        filetime as c_long
    );
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_FILETIME_T), filetime);
    assert!(filetime > 1_000_000_000, "{filetime}");
    assert_eq!(
        info::<c_long>(c, ffi::CURLINFO_PROTOCOL),
        ffi::CURLPROTO_FILE
    );
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_RESPONSE_CODE), 0);
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_HTTP_VERSION), 0);
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_RETRY_AFTER), 0);
    // No response gave a type, and no connection was made.
    assert!(info::<*const c_char>(c, ffi::CURLINFO_CONTENT_TYPE).is_null());
    for ip in [ffi::CURLINFO_PRIMARY_IP, ffi::CURLINFO_LOCAL_IP] {
        // SAFETY: getinfo gives a string that lives while the handle does.
        assert_eq!(unsafe { CStr::from_ptr(info::<*const c_char>(c, ip)) }, c"");
    }
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_PRIMARY_PORT), -1);
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_LOCAL_PORT), -1);
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_NUM_CONNECTS), 0);
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_REQUEST_SIZE), 0);
    // The first transfer of its pool, on the pool's first connection.
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_XFER_ID), 0);
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_CONN_ID), 0);
    // The URL the transfer used, the same string each time it is asked.
    let effective = info::<*const c_char>(c, ffi::CURLINFO_EFFECTIVE_URL);
    // SAFETY: getinfo gives a string that lives while the handle does.
    assert_eq!(unsafe { CStr::from_ptr(effective) }, url.as_c_str());
    assert_eq!(
        info::<*const c_char>(c, ffi::CURLINFO_EFFECTIVE_URL),
        effective
    );
    // No response pointed elsewhere.
    assert!(info::<*const c_char>(c, ffi::CURLINFO_REDIRECT_URL).is_null());
    // No request sent a referer, followed, authenticated, met a proxy or
    // a condition.
    assert!(info::<*const c_char>(c, ffi::CURLINFO_REFERER).is_null());
    for i in [
        ffi::CURLINFO_REDIRECT_COUNT,
        ffi::CURLINFO_HTTPAUTH_AVAIL,
        ffi::CURLINFO_HTTPAUTH_USED,
        ffi::CURLINFO_PROXY_ERROR,
        ffi::CURLINFO_HTTP_CONNECTCODE,
        ffi::CURLINFO_CONDITION_UNMET,
    ] {
        assert_eq!(info::<c_long>(c, i), 0, "{}", i.0);
    }
    // The method sent, else the application's own.
    let method = |c| {
        let p = info::<*const c_char>(c, ffi::CURLINFO_EFFECTIVE_METHOD);
        // SAFETY: getinfo gives a string that lives while the handle does.
        unsafe { CStr::from_ptr(p) }.to_owned()
    };
    assert_eq!(method(c).as_c_str(), c"GET");
    pointer(c, ffi::CURLOPT_CUSTOMREQUEST, c"FOO".as_ptr().cast_mut());
    assert_eq!(method(c).as_c_str(), c"FOO");
    // A file older than the condition's time is not read, and the
    // condition is reported unmet (`file_do`).
    long(c, ffi::CURLOPT_TIMECONDITION, ffi::CURL_TIMECOND_IFMODSINCE);
    long(c, ffi::CURLOPT_TIMEVALUE, c_long::MAX);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_CONDITION_UNMET), 1);
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_SIZE_DOWNLOAD_T), 0);
    // An info not answered yet, and one of no type.
    let mut v: c_long = 0;
    // SAFETY: a live handle and a `long` to write.
    unsafe {
        assert_eq!(
            curl_easy_getinfo(c, ffi::CURLINFO_FTP_ENTRY_PATH, &raw mut v),
            CURLE_UNKNOWN_OPTION
        );
        assert_eq!(
            curl_easy_getinfo(c, CURLINFO(5), &raw mut v),
            CURLE_UNKNOWN_OPTION
        );
        let null = ptr::null_mut::<c_long>();
        assert_eq!(
            curl_easy_getinfo(c, ffi::CURLINFO_RESPONSE_CODE, null),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
        assert_eq!(
            curl_easy_getinfo(ptr::null_mut(), ffi::CURLINFO_RESPONSE_CODE, &raw mut v),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    std::fs::remove_file(path).unwrap();
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// Feeds `left` to the read function.
struct Feed {
    left: Vec<u8>,
    answer: Option<usize>,
}

unsafe extern "C" fn read(buf: *mut c_char, size: usize, n: usize, data: *mut c_void) -> usize {
    // SAFETY: the test passes a `Feed` and the shim room for `size * n`.
    let feed = unsafe { &mut *data.cast::<Feed>() };
    if let Some(a) = feed.answer {
        return a;
    }
    let k = feed.left.len().min(size * n);
    // SAFETY: as above.
    unsafe { ptr::copy_nonoverlapping(feed.left.as_ptr(), buf.cast(), k) };
    feed.left.drain(..k);
    k
}

type ReadFn = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

/// The read function's body is stored, and its abort and pause answers
/// end the upload as file:// ends it.
#[test]
fn the_read_function_feeds_an_upload() {
    let (path, url) = file("upload", b"");
    let run = |answer: Option<usize>| {
        let mut feed = Feed {
            left: b"abc".to_vec(),
            answer,
        };
        let mut buf = [0 as c_char; 256];
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        long(c, ffi::CURLOPT_UPLOAD, 1);
        long(c, ffi::CURLOPT_INFILESIZE, 3);
        function(c, ffi::CURLOPT_READFUNCTION, read as ReadFn as *const ());
        pointer(c, ffi::CURLOPT_READDATA, &raw mut feed);
        pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
        // SAFETY: a live handle, then not used again.
        let code = unsafe { curl_easy_perform(c) };
        let up = (
            info::<curl_off_t>(c, ffi::CURLINFO_SIZE_UPLOAD_T),
            info::<curl_off_t>(c, ffi::CURLINFO_CONTENT_LENGTH_UPLOAD_T),
        );
        // SAFETY: as above.
        unsafe { curl_easy_cleanup(c) };
        (code, up)
    };
    assert_eq!(run(None), (CURLE_OK, (3, 3)));
    assert_eq!(std::fs::read(&path).unwrap(), b"abc");
    let abort = ffi::CURL_READFUNC_ABORT as usize;
    assert_eq!(run(Some(abort)).0, CURLE_ABORTED_BY_CALLBACK);
    let pause = ffi::CURL_READFUNC_PAUSE as usize;
    assert_eq!(run(Some(pause)).0, ffi::CURLE_READ_ERROR);
    std::fs::remove_file(path).unwrap();
}

/// How many times the seek or ioctl function ran, and what it answers.
#[derive(Default)]
struct Rewinds {
    calls: u32,
    answer: c_int,
}

unsafe extern "C" fn seek(data: *mut c_void, offset: curl_off_t, origin: c_int) -> c_int {
    // SAFETY: the test passes a `Rewinds`.
    let r = unsafe { &mut *data.cast::<Rewinds>() };
    assert_eq!((offset, origin), (0, libc::SEEK_SET));
    r.calls += 1;
    r.answer
}

unsafe extern "C" fn ioctl(_: *mut CURL, cmd: c_int, data: *mut c_void) -> ffi::curlioerr {
    // SAFETY: the test passes a `Rewinds`.
    let r = unsafe { &mut *data.cast::<Rewinds>() };
    assert_eq!(cmd, ffi::CURLIOCMD_RESTARTREAD.0);
    r.calls += 1;
    ffi::curlioerr(r.answer as _)
}

type SeekFn = unsafe extern "C" fn(*mut c_void, curl_off_t, c_int) -> c_int;
type IoctlFn = unsafe extern "C" fn(*mut CURL, c_int, *mut c_void) -> ffi::curlioerr;

/// A body sent again is rewound by the seek function, else the ioctl
/// function, else `fseek` on the default read function's stream
/// (`cr_in_rewind`); each failure says why.
#[test]
fn a_rewind_asks_the_application() {
    enum How {
        Seek(c_int),
        Ioctl(c_int),
        Stream,
        /// A stream `fseek` cannot rewind.
        Pipe,
        ReadFunction,
    }
    let run = |how: How| {
        let mut rewinds = Rewinds::default();
        let mut feed = Feed {
            left: b"ab".repeat(100),
            answer: None,
        };
        let mut buf = [0 as c_char; 256];
        let stream = tmpfile();
        let mut pipe = ptr::null_mut::<libc::FILE>();
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, c"script://a".as_ptr().cast_mut());
        long(c, ffi::CURLOPT_UPLOAD, 1);
        // A read taken for a pause would wait for ever: fail instead.
        long(c, ffi::CURLOPT_TIMEOUT, 5);
        pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
        options(c, |o| {
            o.script =
                Some(Script::new(vec![Piece::Send(1), Piece::Rewind, Piece::SendAll]).unwrap());
        });
        match how {
            How::Seek(answer) => {
                rewinds.answer = answer;
                function(c, ffi::CURLOPT_READFUNCTION, read as ReadFn as *const ());
                pointer(c, ffi::CURLOPT_READDATA, &raw mut feed);
                function(c, ffi::CURLOPT_SEEKFUNCTION, seek as SeekFn as *const ());
                pointer(c, ffi::CURLOPT_SEEKDATA, &raw mut rewinds);
            }
            How::Ioctl(answer) => {
                rewinds.answer = answer;
                function(c, ffi::CURLOPT_READFUNCTION, read as ReadFn as *const ());
                pointer(c, ffi::CURLOPT_READDATA, &raw mut feed);
                function(c, ffi::CURLOPT_IOCTLFUNCTION, ioctl as IoctlFn as *const ());
                pointer(c, ffi::CURLOPT_IOCTLDATA, &raw mut rewinds);
            }
            How::Stream => {
                // SAFETY: a stream from `tmpfile`.
                unsafe { libc::fwrite(b"xy".as_ptr().cast(), 1, 2, stream) };
                pointer(c, ffi::CURLOPT_READDATA, stream);
            }
            How::ReadFunction => {
                function(c, ffi::CURLOPT_READFUNCTION, read as ReadFn as *const ());
                pointer(c, ffi::CURLOPT_READDATA, &raw mut feed);
            }
            How::Pipe => {
                let mut fds = [0; 2];
                // SAFETY: room for the pipe's two descriptors; the write
                // end is closed once written, the read end by `fclose`.
                unsafe {
                    assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
                    libc::write(fds[1], b"xyz".as_ptr().cast(), 3);
                    libc::close(fds[1]);
                    pipe = libc::fdopen(fds[0], c"r".as_ptr());
                }
                pointer(c, ffi::CURLOPT_READDATA, pipe);
            }
        }
        // SAFETY: a live handle, then not used again.
        let code = unsafe { curl_easy_perform(c) };
        // SAFETY: as above.
        unsafe { curl_easy_cleanup(c) };
        close(stream);
        if !pipe.is_null() {
            close(pipe);
        }
        // SAFETY: the shim ends what it writes with a zero byte.
        let why = unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_str()
            .unwrap()
            .to_owned();
        (code, rewinds.calls, why)
    };
    let fail = ffi::CURLE_SEND_FAIL_REWIND;
    assert_eq!(
        run(How::Seek(ffi::CURL_SEEKFUNC_OK)),
        (CURLE_OK, 1, String::new())
    );
    let failed = run(How::Seek(ffi::CURL_SEEKFUNC_FAIL));
    assert_eq!(
        failed,
        (fail, 1, "seek callback returned error 1".to_owned())
    );
    assert_eq!(
        run(How::Ioctl(ffi::CURLIOE_OK.0 as c_int)),
        (CURLE_OK, 1, String::new())
    );
    let failed = run(How::Ioctl(ffi::CURLIOE_FAILRESTART.0 as c_int));
    assert_eq!(
        failed,
        (fail, 1, "ioctl callback returned error 2".to_owned())
    );
    // The default read function reads `stream`, which `fseek` rewinds.
    assert_eq!(run(How::Stream).0, CURLE_OK);
    let failed = run(How::Pipe);
    assert_eq!(
        failed,
        (fail, 0, "necessary data rewind was not possible".to_owned())
    );
    let failed = run(How::ReadFunction);
    assert_eq!(
        failed,
        (fail, 0, "necessary data rewind was not possible".to_owned())
    );
}

/// A tree posted twice starts over, as the second transfer begins, the
/// parts the first one's reading reached, as C keeps that in the part
/// (`mime_part_rewind` past `MIMESTATE_BEGIN`): a part a function reads is
/// seeked though its function was never called, as its size is 0; a file
/// that is not regular fails the transfer; a part of nothing does not,
/// where C fails it too (DIVERGENCE.md).
#[test]
fn a_tree_posted_again_starts_over_what_was_reached() {
    thread_local!(static SEEKS: core::cell::Cell<u32> = const { core::cell::Cell::new(0) });
    unsafe extern "C" fn read(_: *mut c_char, _: usize, _: usize, _: *mut c_void) -> usize {
        panic!("a part of size 0 is not read");
    }
    unsafe extern "C" fn seek(_: *mut c_void, _: curl_off_t, _: c_int) -> c_int {
        SEEKS.with(|s| s.set(s.get() + 1));
        ffi::CURL_SEEKFUNC_OK
    }
    enum What {
        Function,
        DevNull,
        Nothing,
    }
    let twice = |what: What| {
        use crate::mime::{
            curl_mime_addpart, curl_mime_data_cb, curl_mime_filedata, curl_mime_free,
            curl_mime_init, curl_mime_name,
        };
        let c = curl_easy_init();
        // SAFETY: a live tree and part, freed after the handle.
        let m = unsafe {
            let m = curl_mime_init(c);
            let p = curl_mime_addpart(m);
            assert_eq!(curl_mime_name(p, c"f".as_ptr()), CURLE_OK);
            let set = match what {
                What::Function => {
                    curl_mime_data_cb(p, 0, Some(read), Some(seek), None, ptr::null_mut())
                }
                What::DevNull => curl_mime_filedata(p, c"/dev/null".as_ptr()),
                What::Nothing => CURLE_OK,
            };
            assert_eq!(set, CURLE_OK);
            m
        };
        pointer(c, ffi::CURLOPT_URL, c"script://a".as_ptr().cast_mut());
        pointer(c, ffi::CURLOPT_MIMEPOST, m);
        options(c, |o| {
            o.script = Some(Script::new(vec![Piece::SendAll]).unwrap());
        });
        // SAFETY: a live handle, then the tree it posts, then nothing.
        unsafe {
            let codes = [curl_easy_perform(c), curl_easy_perform(c)];
            curl_easy_cleanup(c);
            curl_mime_free(m);
            codes
        }
    };
    assert_eq!(twice(What::Function), [CURLE_OK, CURLE_OK]);
    assert_eq!(SEEKS.with(core::cell::Cell::get), 1);
    assert_eq!(
        twice(What::DevNull),
        [CURLE_OK, ffi::CURLE_SEND_FAIL_REWIND]
    );
    assert_eq!(twice(What::Nothing), [CURLE_OK, CURLE_OK]);
}

/// A part's read function answering -2, the value of a filling
/// function's `CURL_READFUNC_STOP_FILLING` that no part's function may
/// give, fails the transfer as a read error. C asks the function again
/// for ever (DIVERGENCE.md).
#[test]
fn a_part_read_answering_stop_filling_fails() {
    unsafe extern "C" fn read(_: *mut c_char, _: usize, _: usize, _: *mut c_void) -> usize {
        usize::MAX - 1
    }
    use crate::mime::{curl_mime_addpart, curl_mime_data_cb, curl_mime_free, curl_mime_init};
    let c = curl_easy_init();
    // SAFETY: a live tree and part, freed after the handle.
    unsafe {
        let m = curl_mime_init(c);
        let p = curl_mime_addpart(m);
        assert_eq!(
            curl_mime_data_cb(p, -1, Some(read), None, None, ptr::null_mut()),
            CURLE_OK
        );
        pointer(c, ffi::CURLOPT_URL, c"script://a".as_ptr().cast_mut());
        pointer(c, ffi::CURLOPT_MIMEPOST, m);
        long(c, ffi::CURLOPT_TIMEOUT, 5);
        options(c, |o| {
            o.script = Some(Script::new(vec![Piece::SendAll]).unwrap());
        });
        assert_eq!(curl_easy_perform(c), ffi::CURLE_READ_ERROR);
        curl_easy_cleanup(c);
        curl_mime_free(m);
    }
}

/// What the write function answers.
struct Answer(usize);

unsafe extern "C" fn answer(_: *mut c_char, _: usize, _: usize, data: *mut c_void) -> usize {
    // SAFETY: the test passes an `Answer`.
    unsafe { (*data.cast::<Answer>()).0 }
}

/// The write function's answers, each failure with C's reason.
#[test]
fn the_write_function_s_answer_decides() {
    let (path, url) = file("answers", b"hello");
    let run = |a: usize| {
        let mut a = Answer(a);
        let mut buf = [0 as c_char; 256];
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        function(
            c,
            ffi::CURLOPT_WRITEFUNCTION,
            answer as WriteFn as *const (),
        );
        pointer(c, ffi::CURLOPT_WRITEDATA, &raw mut a);
        pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
        // SAFETY: a live handle, then not used again.
        let code = unsafe { curl_easy_perform(c) };
        // SAFETY: as above.
        unsafe { curl_easy_cleanup(c) };
        // SAFETY: the shim ends what it writes with a zero byte.
        (
            code,
            unsafe { CStr::from_ptr(buf.as_ptr()) }
                .to_str()
                .unwrap()
                .to_owned(),
        )
    };
    assert_eq!(run(5), (CURLE_OK, String::new()));
    let short = run(1);
    assert_eq!(
        short,
        (
            ffi::CURLE_WRITE_ERROR,
            "Failure writing output to destination, passed 5 returned 1".to_owned()
        )
    );
    let error = run(ffi::CURL_WRITEFUNC_ERROR as usize);
    assert_eq!(
        error,
        (
            ffi::CURLE_WRITE_ERROR,
            "client returned ERROR on write of 5 bytes".to_owned()
        )
    );
    // file:// cannot pause.
    let pause = run(ffi::CURL_WRITEFUNC_PAUSE as usize);
    assert_eq!(pause.0, ffi::CURLE_WRITE_ERROR);
    assert_ne!(pause.1, error.1);
    assert_ne!(pause.1, short.1);
    std::fs::remove_file(path).unwrap();
}

/// The default write function writes to standard output.
#[test]
fn the_default_write_goes_to_standard_output() {
    let (path, url) = file("stdout", b"");
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    long(c, ffi::CURLOPT_HEADER, 1);
    let out = tmpfile();
    pointer(c, ffi::CURLOPT_WRITEDATA, out);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    assert!(stream_text(out).starts_with("Content-Length: 0\r\n"));
    close(out);
    // The process's standard output, by default: an empty file writes
    // only headers there, of which there are none without `HEADER`.
    long(c, ffi::CURLOPT_HEADER, 0);
    pointer(c, ffi::CURLOPT_WRITEDATA, crate::callbacks::standard().1);
    assert_eq!(ccb(c).write_data, crate::callbacks::standard().1);
    // SAFETY: a live handle, then not used again.
    unsafe {
        assert_eq!(curl_easy_perform(c), CURLE_OK);
        curl_easy_cleanup(c);
    }
    let fresh = curl_easy_init();
    assert_eq!(ccb(fresh).write_data, crate::callbacks::standard().1);
    assert_eq!(ccb(fresh).read_data, crate::callbacks::standard().0);
    assert!(!crate::callbacks::standard().1.is_null());
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(fresh) };
    std::fs::remove_file(path).unwrap();
}

/// Lines the header function got, by its data.
#[derive(Default)]
struct Lines(Vec<String>);

unsafe extern "C" fn lines(ptr: *mut c_char, size: usize, n: usize, data: *mut c_void) -> usize {
    // SAFETY: the test passes `Lines` and the shim `size * n` bytes.
    let (l, b) = unsafe {
        (
            &mut *data.cast::<Lines>(),
            core::slice::from_raw_parts(ptr.cast::<u8>(), size * n),
        )
    };
    l.0.push(String::from_utf8(b.to_vec()).unwrap());
    size * n
}

/// Headers go to the header function, else to the write function with
/// the header data, else nowhere.
#[test]
fn headers_go_where_c_sends_them() {
    let (path, url) = file("headers", b"hello");
    let run = |header_fn: bool, header_data: bool| {
        let (mut body, mut heads) = (Lines::default(), Lines::default());
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        long(c, ffi::CURLOPT_NOBODY, 1);
        function(c, ffi::CURLOPT_WRITEFUNCTION, lines as WriteFn as *const ());
        pointer(c, ffi::CURLOPT_WRITEDATA, &raw mut body);
        if header_fn {
            function(
                c,
                ffi::CURLOPT_HEADERFUNCTION,
                lines as WriteFn as *const (),
            );
        }
        if header_data {
            pointer(c, ffi::CURLOPT_HEADERDATA, &raw mut heads);
        }
        // SAFETY: a live handle, then not used again.
        unsafe {
            assert_eq!(curl_easy_perform(c), CURLE_OK);
            curl_easy_cleanup(c);
        }
        (body.0.len(), heads.0.first().cloned())
    };
    let first = Some("Content-Length: 5\r\n".to_owned());
    assert_eq!(
        run(false, true),
        (0, first.clone()),
        "to the write function"
    );
    assert_eq!(run(false, false), (0, None), "nowhere");
    assert_eq!(run(true, true), (0, first));
    std::fs::remove_file(path).unwrap();
}

type DebugFn =
    unsafe extern "C" fn(*mut CURL, ffi::curl_infotype, *mut c_char, usize, *mut c_void) -> c_int;

/// What the debug function saw.
#[derive(Default)]
struct Seen {
    handle: usize,
    texts: Vec<String>,
}

unsafe extern "C" fn debug_count(
    h: *mut CURL,
    kind: ffi::curl_infotype,
    ptr: *mut c_char,
    n: usize,
    data: *mut c_void,
) -> c_int {
    if data.is_null() {
        return 0;
    }
    // SAFETY: the test passes a `Seen` and the shim `n` bytes.
    let (s, b) = unsafe {
        (
            &mut *data.cast::<Seen>(),
            core::slice::from_raw_parts(ptr.cast::<u8>(), n),
        )
    };
    s.handle = h as usize;
    if kind == ffi::CURLINFO_TEXT {
        s.texts.push(String::from_utf8(b.to_vec()).unwrap());
    }
    0
}

/// The trace goes to the debug function, with the handle, else to the
/// STDERR stream after `* `.
#[test]
fn the_trace_goes_to_the_debug_function_or_the_stream() {
    let missing = c"file:///nonexistent/curl-shim-trace";
    let mut seen = Seen::default();
    let stream = tmpfile();
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_URL, missing.as_ptr().cast_mut());
    long(c, ffi::CURLOPT_VERBOSE, 1);
    pointer(c, ffi::CURLOPT_STDERR, stream);
    function(
        c,
        ffi::CURLOPT_DEBUGFUNCTION,
        debug_count as DebugFn as *const (),
    );
    pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut seen);
    let why = "Could not open file /nonexistent/curl-shim-trace\n";
    // SAFETY: a live handle.
    let code = unsafe { curl_easy_perform(c) };
    assert_eq!(code, ffi::CURLE_FILE_COULDNT_READ_FILE);
    assert_eq!(seen.handle, c as usize);
    assert!(seen.texts.iter().any(|t| t == why), "{:?}", seen.texts);
    assert_eq!(stream_text(stream), "");
    function(c, ffi::CURLOPT_DEBUGFUNCTION, ptr::null());
    // SAFETY: a live handle, then not used again.
    unsafe {
        assert_eq!(curl_easy_perform(c), ffi::CURLE_FILE_COULDNT_READ_FILE);
        curl_easy_cleanup(c);
    }
    assert!(
        stream_text(stream).contains(&format!("* {why}")),
        "{}",
        stream_text(stream)
    );
    close(stream);
}

/// A debug function that, as it is told text, asks for the handle's
/// response code: one called with the handle borrowed would fail it.
unsafe extern "C" fn debug_asking(
    h: *mut CURL,
    kind: ffi::curl_infotype,
    ptr: *mut c_char,
    n: usize,
    data: *mut c_void,
) -> c_int {
    let mut code: c_long = -1;
    // SAFETY: a live handle, and a long to the info.
    let asked = unsafe { curl_easy_getinfo(h, ffi::CURLINFO_RESPONSE_CODE, &raw mut code) };
    assert_eq!(asked, CURLE_OK);
    // SAFETY: as `debug_count` is called.
    unsafe { debug_count(h, kind, ptr, n, data) }
}

/// `CURLOPT_COOKIELIST` traces, as it is set, what C traces: a file a
/// reload cannot open, then what each file's lines say, in their order,
/// and a cookie added once the jar runs; to the debug function, which
/// may call back into the handle, else to the STDERR stream after `* `,
/// and nothing unless verbose. As the C build traces the same steps.
#[test]
fn a_cookie_list_is_traced_as_it_is_set() {
    let dir = std::env::temp_dir().join(format!("curl-shim-cookielist-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let jar = dir.join("jar");
    std::fs::write(
        &jar,
        ".example.com\tTRUE\t/\tFALSE\t0\tsess\tv1\nbroken line\n\
         Set-Cookie: bad\x01=x; domain=example.com\nSet-Cookie: =\n",
    )
    .unwrap();
    let missing = dir.join("missing");
    let c_path = |p: &std::path::Path| std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    let (jar, missing, dir_name) = (c_path(&jar), c_path(&missing), c_path(&dir));
    let run = |c: *mut CURL| {
        let set = |what: &std::ffi::CStr| {
            assert_eq!(
                pointer(c, ffi::CURLOPT_COOKIELIST, what.as_ptr().cast_mut()),
                CURLE_OK
            );
        };
        set(c"junk before the jar runs");
        set(c".a.com\tTRUE\t/\tFALSE\t0\tfirst\tx");
        for file in [&missing, &jar, &dir_name] {
            pointer(c, ffi::CURLOPT_COOKIEFILE, file.as_ptr().cast_mut());
        }
        set(c"RELOAD");
        set(c"junk after");
        set(c".b.com\tTRUE\t/\tFALSE\t0\tsecond\ty");
        set(c".b.com\tTRUE\t/\tFALSE\t0\tsecond\tz");
        set(c"Set-Cookie: hy=2; domain=b.com");
    };
    let expected = [
        format!(
            "WARNING: failed to open cookie file \"{}\"\n",
            missing.to_str().unwrap()
        ),
        "invalid octets in name, cookie dropped\n".to_string(),
        "invalid cookie, dropped\n".to_string(),
        format!(
            "WARNING: cookie filename points to a directory: \"{}\"\n",
            dir_name.to_str().unwrap()
        ),
        "Added cookie second=\"y\" for domain b.com, path /, expire 0\n".to_string(),
        "Replaced cookie second=\"z\" for domain b.com, path /, expire 0\n".to_string(),
        "Added cookie hy=\"2\" for domain b.com, path (nil), expire 0\n".to_string(),
    ];
    let mut seen = Seen::default();
    let c = curl_easy_init();
    long(c, ffi::CURLOPT_VERBOSE, 1);
    let f = debug_asking as DebugFn as *const ();
    function(c, ffi::CURLOPT_DEBUGFUNCTION, f);
    pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut seen);
    run(c);
    assert_eq!(seen.handle, c as usize);
    let texts: Vec<_> = seen
        .texts
        .iter()
        .filter(|t| !t.contains("debug build"))
        .collect();
    assert_eq!(texts, expected.iter().collect::<Vec<_>>());
    // SAFETY: a live handle, then not used again.
    unsafe { curl_easy_cleanup(c) };
    let stream = tmpfile();
    let c = curl_easy_init();
    long(c, ffi::CURLOPT_VERBOSE, 1);
    pointer(c, ffi::CURLOPT_STDERR, stream);
    run(c);
    // SAFETY: a live handle, then not used again.
    unsafe { curl_easy_cleanup(c) };
    let starred: String = expected.iter().map(|l| format!("* {l}")).collect();
    assert_eq!(stream_text(stream), starred);
    close(stream);
    let stream = tmpfile();
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_STDERR, stream);
    run(c);
    // SAFETY: a live handle, then not used again.
    unsafe { curl_easy_cleanup(c) };
    assert_eq!(stream_text(stream), "");
    close(stream);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A reason longer than ERRORBUFFER keeps its first 255 bytes.
#[test]
fn a_long_reason_is_cut_to_the_buffer() {
    let long_path = format!("file:///nonexistent/{}", "a".repeat(300));
    let url = std::ffi::CString::new(long_path).unwrap();
    let mut buf = [b'x' as c_char; 256];
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
    // SAFETY: a live handle, then not used again.
    unsafe {
        assert_eq!(curl_easy_perform(c), ffi::CURLE_FILE_COULDNT_READ_FILE);
        curl_easy_cleanup(c);
    }
    assert_eq!(buf[255], 0);
    // SAFETY: zero-terminated.
    let why = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    assert_eq!(why.len(), 255);
    assert!(why.starts_with(b"Could not open file /nonexistent/aaa"));
}

type XferFn =
    unsafe extern "C" fn(*mut c_void, curl_off_t, curl_off_t, curl_off_t, curl_off_t) -> c_int;
type ProgressFn = unsafe extern "C" fn(*mut c_void, f64, f64, f64, f64) -> c_int;

/// How the progress function answers, and what it saw last.
#[derive(Default)]
struct Meter {
    answer: c_int,
    calls: u32,
    last: (f64, f64),
}

unsafe extern "C" fn xferinfo(
    data: *mut c_void,
    dt: curl_off_t,
    dn: curl_off_t,
    _: curl_off_t,
    _: curl_off_t,
) -> c_int {
    if data.is_null() {
        return 0;
    }
    // SAFETY: the test passes a `Meter`.
    let m = unsafe { &mut *data.cast::<Meter>() };
    m.calls += 1;
    m.last = (dt as f64, dn as f64);
    m.answer
}

unsafe extern "C" fn old_progress(data: *mut c_void, dt: f64, dn: f64, _: f64, _: f64) -> c_int {
    if data.is_null() {
        return 0;
    }
    // SAFETY: the test passes a `Meter`.
    let m = unsafe { &mut *data.cast::<Meter>() };
    m.calls += 1;
    m.last = (dt, dn);
    m.answer
}

/// The progress function's answers: go on, go on with the meter, or
/// abort; the old function gets the same counts as doubles.
#[test]
fn the_progress_function_s_answer_decides() {
    let (path, url) = file("progress", b"hello");
    let run = |answer: c_int, old: bool| {
        let mut m = Meter {
            answer,
            ..Meter::default()
        };
        let stream = tmpfile();
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
        pointer(c, ffi::CURLOPT_STDERR, stream);
        long(c, ffi::CURLOPT_NOPROGRESS, 0);
        if old {
            function(
                c,
                ffi::CURLOPT_PROGRESSFUNCTION,
                old_progress as ProgressFn as *const (),
            );
        } else {
            function(
                c,
                ffi::CURLOPT_XFERINFOFUNCTION,
                xferinfo as XferFn as *const (),
            );
        }
        pointer(c, ffi::CURLOPT_XFERINFODATA, &raw mut m);
        // SAFETY: a live handle, then not used again.
        let code = unsafe { curl_easy_perform(c) };
        // SAFETY: as above.
        unsafe { curl_easy_cleanup(c) };
        let meter = stream_text(stream).contains("% Total");
        close(stream);
        (code, m.calls > 0, m.last, meter)
    };
    assert_eq!(run(0, false), (CURLE_OK, true, (5.0, 5.0), false));
    assert_eq!(run(0, true), (CURLE_OK, true, (5.0, 5.0), false));
    let with_meter = run(ffi::CURL_PROGRESSFUNC_CONTINUE, false);
    assert_eq!((with_meter.0, with_meter.3), (CURLE_OK, true));
    assert_eq!(run(1, false).0, CURLE_ABORTED_BY_CALLBACK);
    assert_eq!(run(-1, true).0, CURLE_ABORTED_BY_CALLBACK);
    std::fs::remove_file(path).unwrap();
}

/// What the multi's callbacks saw.
#[derive(Default)]
struct Calls {
    multi: usize,
    timers: Vec<c_long>,
    timer_answer: c_int,
    /// Set once added and running.
    performing: bool,
    /// What a setopt on the transfer being added answered, in the add's
    /// timer callback.
    adding_setopt: Option<CURLcode>,
    timer_getinfo: Option<CURLcode>,
    timer_pause: Option<CURLcode>,
    easy: usize,
    notes: Vec<(c_uint, usize)>,
    done_size: curl_off_t,
    done_pause: Option<CURLcode>,
}

unsafe extern "C" fn timer(m: *mut CURLM, ms: c_long, data: *mut c_void) -> c_int {
    // SAFETY: the test passes an `Calls`.
    let e = unsafe { &mut *data.cast::<Calls>() };
    e.multi = m as usize;
    e.timers.push(ms);
    if e.easy != 0 && !e.performing && e.adding_setopt.is_none() {
        let c = e.easy as *mut CURL;
        e.adding_setopt = Some(long(c, ffi::CURLOPT_TIMEOUT_MS, 100_000));
    }
    if e.easy != 0 && e.performing {
        let c = e.easy as *mut CURL;
        let mut n: curl_off_t = 0;
        // SAFETY: the test's live handle, in this multi.
        unsafe {
            e.timer_getinfo = Some(curl_easy_getinfo(
                c,
                ffi::CURLINFO_SIZE_DOWNLOAD_T,
                &raw mut n,
            ));
            e.timer_pause = Some(curl_easy_pause(c, ffi::CURLPAUSE_CONT));
        }
    }
    e.timer_answer
}

unsafe extern "C" fn notify(m: *mut CURLM, kind: c_uint, easy: *mut CURL, data: *mut c_void) {
    // SAFETY: the test passes an `Calls`.
    let e = unsafe { &mut *data.cast::<Calls>() };
    e.multi = m as usize;
    e.notes.push((kind, easy as usize));
    if kind == ffi::CURLMNOTIFY_EASY_DONE as c_uint {
        // SAFETY: the test's live handle, in this multi.
        unsafe {
            curl_easy_getinfo(easy, ffi::CURLINFO_SIZE_DOWNLOAD_T, &raw mut e.done_size);
            e.done_pause = Some(curl_easy_pause(easy, ffi::CURLPAUSE_CONT));
        }
    }
}

type TimerFn = unsafe extern "C" fn(*mut CURLM, c_long, *mut c_void) -> c_int;
type NotifyFn = unsafe extern "C" fn(*mut CURLM, c_uint, *mut CURL, *mut c_void);

/// The timer callback hears of a new transfer, with the multi, and may
/// set its options during the add, and read it but not pause it later;
/// the notify callback hears the transfer is done, then that a message
/// waits, and may read and pause it. A timer that answers -1 aborts the
/// add, and the handle is on its own again.
#[test]
fn the_multi_s_callbacks_run_with_their_frames() {
    let (path, url) = file("events", b"hello");
    let mut e = Calls::default();
    let m = curl_multi_init();
    let c = curl_easy_init();
    e.easy = c as usize;
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    // SAFETY: live handles throughout, until their cleanups, and data
    // that outlives them.
    unsafe {
        let t = timer as TimerFn as *const ();
        let n = notify as NotifyFn as *const ();
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_TIMERFUNCTION, t),
            CURLM_OK
        );
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_TIMERDATA, (&raw mut e).cast::<c_void>()),
            CURLM_OK
        );
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_NOTIFYFUNCTION, n),
            CURLM_OK
        );
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_NOTIFYDATA, (&raw mut e).cast::<c_void>()),
            CURLM_OK
        );
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_MAXCONNECTS, 1 as c_long),
            CURLM_OK
        );
        for o in [
            ffi::CURLMOPT_MAX_HOST_CONNECTIONS,
            ffi::CURLMOPT_MAX_TOTAL_CONNECTIONS,
        ] {
            assert_eq!(curl_multi_setopt(m, o, 2 as c_long), CURLM_OK);
            assert_eq!(
                curl_multi_setopt(m, o, -1 as c_long),
                ffi::CURLM_BAD_FUNCTION_ARGUMENT
            );
        }
        let limits = *crate::multi::multi(m).core_mut().conn_limits_mut();
        assert_eq!(limits.max_connects, core::num::NonZeroU32::new(1));
        assert_eq!(
            (limits.max_host, limits.max_total),
            (None, None),
            "-1 is taken as 0"
        );
        let (host, total) = (
            ffi::CURLMOPT_MAX_HOST_CONNECTIONS,
            ffi::CURLMOPT_MAX_TOTAL_CONNECTIONS,
        );
        assert_eq!(curl_multi_setopt(m, host, 2 as c_long), CURLM_OK);
        assert_eq!(curl_multi_setopt(m, total, 3 as c_long), CURLM_OK);
        let limits = *crate::multi::multi(m).core_mut().conn_limits_mut();
        let n = core::num::NonZeroU32::new;
        assert_eq!((limits.max_host, limits.max_total), (n(2), n(3)));
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_PUSHDATA, ptr::null_mut::<c_void>()),
            ffi::CURLM_UNKNOWN_OPTION
        );
        for k in [ffi::CURLMNOTIFY_INFO_READ, ffi::CURLMNOTIFY_EASY_DONE] {
            assert_eq!(curl_multi_notify_enable(m, k as c_uint), CURLM_OK);
        }
        assert_eq!(curl_multi_notify_enable(m, 2), ffi::CURLM_UNKNOWN_OPTION);
        assert_eq!(curl_multi_notify_disable(m, 2), ffi::CURLM_UNKNOWN_OPTION);
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        assert_eq!(e.multi, m as usize);
        assert_eq!(e.timers.first(), Some(&0), "run at once");
        assert_eq!(e.adding_setopt, Some(CURLE_OK));
        let total = options(c, |o| o.limits.total);
        assert_eq!(total, curl_core::time::TimeLimit::from_millis(100_000));
        e.performing = true;
        let mut offt: curl_off_t = -2;
        assert_eq!(
            curl_multi_get_offt(m, ffi::CURLMINFO_XFERS_CURRENT, &raw mut offt),
            CURLM_OK
        );
        assert_eq!(offt, 1);
        let mut running = 1;
        while running > 0 {
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
        }
        assert_eq!(e.timers.last(), Some(&-1), "nothing more to run");
        assert_eq!(e.timer_getinfo, Some(CURLE_OK));
        assert_eq!(e.timer_pause, Some(CURLE_RECURSIVE_API_CALL));
        e.performing = false;
        let done = ffi::CURLMNOTIFY_EASY_DONE as c_uint;
        let read = ffi::CURLMNOTIFY_INFO_READ as c_uint;
        assert_eq!(e.notes.len(), 2, "{:?}", e.notes);
        assert_eq!(e.notes[0], (done, c as usize));
        assert_eq!(e.notes[1].0, read);
        assert!(
            e.notes[1].1 != 0 && e.notes[1].1 != c as usize,
            "the multi's own handle"
        );
        assert_eq!(e.done_size, 5);
        assert_eq!(
            e.done_pause,
            Some(CURLE_BAD_FUNCTION_ARGUMENT),
            "done: nothing to pause"
        );
        for (i, want) in [
            (ffi::CURLMINFO_XFERS_CURRENT, 1),
            (ffi::CURLMINFO_XFERS_RUNNING, 0),
            (ffi::CURLMINFO_XFERS_PENDING, 0),
            (ffi::CURLMINFO_XFERS_DONE, 1),
            (ffi::CURLMINFO_XFERS_ADDED, 1),
        ] {
            assert_eq!(curl_multi_get_offt(m, i, &raw mut offt), CURLM_OK);
            assert_eq!(offt, want, "{}", i.0);
        }
        let mut q = 0;
        assert!(!curl_multi_info_read(m, &raw mut q).is_null());
        assert_eq!(
            curl_multi_get_offt(m, ffi::CURLMINFO_XFERS_DONE, &raw mut offt),
            CURLM_OK
        );
        assert_eq!(offt, 0, "read");
        assert_eq!(
            curl_multi_get_offt(m, ffi::CURLMinfo_offt(99), &raw mut offt),
            ffi::CURLM_UNKNOWN_OPTION
        );
        assert_eq!(offt, -1);
        let null = ptr::null_mut::<curl_off_t>();
        assert_eq!(
            curl_multi_get_offt(m, ffi::CURLMINFO_XFERS_DONE, null),
            ffi::CURLM_BAD_FUNCTION_ARGUMENT
        );
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        // Disabled, a kind is not told.
        for k in [ffi::CURLMNOTIFY_INFO_READ, ffi::CURLMNOTIFY_EASY_DONE] {
            assert_eq!(curl_multi_notify_disable(m, k as c_uint), CURLM_OK);
        }
        e.notes.clear();
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        running = 1;
        while running > 0 {
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
        }
        assert!(e.notes.is_empty());
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        // A timer that answers -1 aborts the change it was told of.
        e.timer_answer = -1;
        assert_eq!(curl_multi_add_handle(m, c), ffi::CURLM_ABORTED_BY_CALLBACK);
        assert_eq!(long(c, ffi::CURLOPT_TIMEOUT_MS, 5), CURLE_OK);
        curl_easy_cleanup(c);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
    std::fs::remove_file(path).unwrap();
}

/// A handle in a multi that is running a callback may not perform: the
/// multi is busy, though the handle itself is not.
#[test]
fn a_sibling_may_not_perform_inside_a_callback() {
    let (path, url) = file("sibling", b"hello");
    struct Inside {
        other: usize,
        code: Option<CURLcode>,
    }
    unsafe extern "C" fn write(_: *mut c_char, size: usize, n: usize, data: *mut c_void) -> usize {
        // SAFETY: the test passes an `Inside`.
        let i = unsafe { &mut *data.cast::<Inside>() };
        // SAFETY: the test's live handle.
        i.code = Some(unsafe { curl_easy_perform(i.other as *mut CURL) });
        size * n
    }
    let m = curl_multi_init();
    let (a, b) = (curl_easy_init(), curl_easy_init());
    let mut inside = Inside {
        other: b as usize,
        code: None,
    };
    for c in [a, b] {
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        function(c, ffi::CURLOPT_WRITEFUNCTION, write as WriteFn as *const ());
        pointer(c, ffi::CURLOPT_WRITEDATA, &raw mut inside);
    }
    // SAFETY: live handles throughout, until their cleanups.
    unsafe {
        assert_eq!(curl_multi_add_handle(m, b), CURLM_OK);
        // `a` performs alone; `b`'s multi is idle.
        inside.other = b as usize;
        assert_eq!(curl_easy_perform(a), CURLE_OK);
        assert_eq!(inside.code, Some(ffi::CURLE_FAILED_INIT), "added elsewhere");
        // Now `b`'s multi runs `a`'s write.
        assert_eq!(curl_multi_remove_handle(m, b), CURLM_OK);
        assert_eq!(curl_multi_add_handle(m, a), CURLM_OK);
        assert_eq!(curl_multi_add_handle(m, b), CURLM_OK);
        inside.code = None;
        let mut running = 1;
        while running > 0 {
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
        }
        assert_eq!(inside.code, Some(CURLE_RECURSIVE_API_CALL));
        curl_easy_cleanup(a);
        curl_easy_cleanup(b);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
    std::fs::remove_file(path).unwrap();
}

/// A wait polls the application's descriptors and reports what C reports.
#[test]
fn a_wait_reports_the_application_s_descriptors() {
    let (r, w) = std::os::unix::net::UnixStream::pair().unwrap();
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    (&w).write_all(b"x").unwrap();
    let m = curl_multi_init();
    let mut fds = [
        ffi::curl_waitfd {
            fd: r.as_raw_fd(),
            events: ffi::CURL_WAIT_POLLIN as i16,
            revents: 0,
        },
        ffi::curl_waitfd {
            fd: w.as_raw_fd(),
            events: ffi::CURL_WAIT_POLLOUT as i16,
            revents: 0,
        },
    ];
    let mut ret = -1;
    // SAFETY: a live multi and two entries.
    unsafe {
        assert_eq!(
            curl_multi_wait(m, fds.as_mut_ptr(), 2, 1000, &raw mut ret),
            CURLM_OK
        );
        assert_eq!(ret, 2);
        assert_eq!(fds[0].revents, ffi::CURL_WAIT_POLLIN as i16);
        assert_eq!(fds[1].revents, ffi::CURL_WAIT_POLLOUT as i16);
        assert_eq!(
            curl_multi_wait(m, fds.as_mut_ptr(), 2, -1, &raw mut ret),
            ffi::CURLM_BAD_FUNCTION_ARGUMENT
        );
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
}

/// A wait on a few sockets and descriptors allocates nothing, as C's
/// keeps them on its stack (`a_few_on_stack`): a loop of waits, as an
/// easy perform's while a transfer has nothing to read, costs no memory
/// (test 671).
#[cfg(feature = "debug-hooks")]
#[test]
fn a_wait_allocates_nothing() {
    use crate::multi::curl_multi_poll;
    use curl_alloc::track::measure;
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let url = std::ffi::CString::new(url).unwrap();
    let (r, w) = std::os::unix::net::UnixStream::pair().unwrap();
    let m = curl_multi_init();
    let c = curl_easy_init();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    let mut fds = [ffi::curl_waitfd {
        fd: r.as_raw_fd(),
        events: ffi::CURL_WAIT_POLLIN as i16,
        revents: 0,
    }];
    let (mut ret, mut running, mut sockets) = (0, 0, 0);
    // SAFETY: a live multi and handle, and one entry.
    unsafe {
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        // Connected and the request sent, the transfer waits to read.
        let mut peer = None;
        for _ in 0..100 {
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
            assert_eq!(
                crate::multi::curl_multi_waitfds(m, ptr::null_mut(), 0, &raw mut sockets),
                CURLM_OK
            );
            if peer.is_none() {
                peer = listener.accept().ok();
            }
            if sockets == 1 && peer.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!((running, sockets), (1, 1), "waiting on its socket");
        assert!(peer.is_some());
        (&w).write_all(b"x").unwrap();
        let ((), cost) = measure(|| {
            for _ in 0..10 {
                assert_eq!(
                    curl_multi_poll(m, fds.as_mut_ptr(), 1, 0, &raw mut ret),
                    CURLM_OK
                );
                assert_eq!(
                    curl_multi_wait(m, fds.as_mut_ptr(), 1, 0, &raw mut ret),
                    CURLM_OK
                );
            }
        });
        assert_eq!(ret, 1, "the descriptor is ready");
        assert_eq!(cost.allocations, 0);
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        curl_easy_cleanup(c);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
}

#[test]
fn c_numbers_translate_both_ways() {
    use ffi::{CURL_WAIT_POLLIN as IN, CURL_WAIT_POLLOUT as OUT, CURL_WAIT_POLLPRI as PRI};
    assert_eq!(wait_events(0), Events::NONE);
    assert_eq!(wait_events(IN as i16), Events::IN);
    assert_eq!(wait_events(PRI as i16), Events::PRI);
    assert_eq!(wait_events(OUT as i16), Events::OUT);
    assert_eq!(
        wait_events((IN | PRI | OUT) as i16),
        Events::IN | Events::PRI | Events::OUT
    );
    assert_eq!(wait_revents(Events::NONE), 0);
    assert_eq!(wait_revents(Events::IN), IN as i16);
    assert_eq!(wait_revents(Events::OUT), OUT as i16);
    assert_eq!(wait_revents(Events::PRI), PRI as i16);
    assert_eq!(
        wait_revents(Events::IN | Events::OUT | Events::PRI | Events::HUP),
        (IN | OUT | PRI) as i16
    );
    assert_eq!(notify_kind(0), Some(NotifyKind::InfoRead));
    assert_eq!(notify_kind(1), Some(NotifyKind::EasyDone));
    assert_eq!(notify_kind(2), None);
    assert_eq!(notify_kind(c_uint::MAX), None);
    assert_eq!(
        (running(0), running(7), running(u32::MAX)),
        (0, 7, c_int::MAX)
    );
    assert!(aborts(-1) && !aborts(0) && !aborts(1));
}

/// `fdset` and `waitfds` list the sockets the transfers wait on, as C's
/// do: a set bit and the highest descriptor, or an entry per socket and
/// the count needed.
#[test]
fn the_transfers_sockets_are_listed() {
    use crate::ffi::{
        CURL_WAIT_POLLOUT, CURLM_BAD_FUNCTION_ARGUMENT, CURLM_OUT_OF_MEMORY, curl_waitfd,
    };
    use crate::multi::{ShimMulti, curl_multi_fdset, curl_multi_waitfds};
    use curl_core::conn::io::{FakeNet, Peer};
    use curl_core::time::ManualClock;

    let clock = ManualClock::new().unwrap();
    let silent = std::net::SocketAddr::from(([127, 0, 0, 1], 3));
    let net = FakeNet::new(clock).with_peer(silent, Peer::Silent);
    let m: *mut CURLM = ShimMulti::boxed_with(Box::new(net))
        .unwrap()
        .as_ptr()
        .cast();
    let fdset = |read: &mut libc::fd_set, write: &mut libc::fd_set| {
        let mut max: c_int = 7;
        // SAFETY: a live multi and the caller's sets.
        let rc = unsafe {
            libc::FD_ZERO(read);
            libc::FD_ZERO(write);
            curl_multi_fdset(
                m,
                ptr::from_mut(read).cast(),
                ptr::from_mut(write).cast(),
                ptr::null_mut(),
                &raw mut max,
            )
        };
        assert_eq!(rc, CURLM_OK);
        max
    };
    let count = |ufds: *mut curl_waitfd, size: c_uint| {
        let mut n: c_uint = 99;
        // SAFETY: a live multi and `size` entries at `ufds`.
        let rc = unsafe { curl_multi_waitfds(m, ufds, size, &raw mut n) };
        (rc, n)
    };
    // SAFETY: zeroed `fd_set`s are valid; FD_ZERO clears them anyway.
    let (mut read, mut write) = unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    assert_eq!(fdset(&mut read, &mut write), -1, "nothing to wait on");
    assert_eq!(count(ptr::null_mut(), 0), (CURLM_OK, 0));
    // SAFETY: a live multi; neither entries nor a count is an error.
    let rc = unsafe { curl_multi_waitfds(m, ptr::null_mut(), 0, ptr::null_mut()) };
    assert_eq!(rc, CURLM_BAD_FUNCTION_ARGUMENT);

    let c = curl_easy_init();
    let url = c"tcp://127.0.0.1:3/";
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    let mut running_now: c_int = 0;
    // SAFETY: a fresh handle, added to the live multi and run once.
    unsafe {
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        assert_eq!(curl_multi_perform(m, &raw mut running_now), CURLM_OK);
    }
    assert_eq!(running_now, 1, "connecting");
    assert_eq!(fdset(&mut read, &mut write), 1000);
    // SAFETY: the sets `fdset` filled.
    unsafe {
        assert!(libc::FD_ISSET(1000, &write));
        assert!(!libc::FD_ISSET(1000, &read));
    }
    assert_eq!(count(ptr::null_mut(), 0), (CURLM_OK, 1));
    let mut entries = [curl_waitfd {
        fd: -1,
        events: 0,
        revents: 0,
    }; 2];
    assert_eq!(
        count(entries.as_mut_ptr(), 0),
        (CURLM_OUT_OF_MEMORY, 1),
        "no room"
    );
    assert_eq!(count(entries.as_mut_ptr(), 2), (CURLM_OK, 1));
    assert_eq!(
        (entries[0].fd, c_int::from(entries[0].events)),
        (1000, CURL_WAIT_POLLOUT)
    );
    assert_eq!(entries[1].fd, -1, "untouched");
    // SAFETY: the handle and multi made above, done with.
    unsafe {
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        curl_easy_cleanup(c);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
}

/// What the socket function saw, and the multi it assigns on.
struct SocketLog {
    m: *mut CURLM,
    calls: Vec<(*mut CURL, c_int, c_int, *mut c_void)>,
    abort: bool,
}

unsafe extern "C" fn socket_fn(
    easy: *mut CURL,
    s: ffi::curl_socket_t,
    what: c_int,
    data: *mut c_void,
    socketp: *mut c_void,
) -> c_int {
    // SAFETY: the test's log, given as the socket data.
    let log = unsafe { &mut *data.cast::<SocketLog>() };
    log.calls.push((easy, s, what, socketp));
    if socketp.is_null() {
        // SAFETY: inside the multi's socket function, as C allows.
        let rc = unsafe { crate::multi::curl_multi_assign(log.m, s, ptr::from_mut(log).cast()) };
        assert_eq!(rc, CURLM_OK);
    }
    if log.abort { -1 } else { 0 }
}

/// The socket function hears of a transfer's socket from `socket_action`
/// with the handle and the data, keeps what `curl_multi_assign` tags it
/// with, and hears it removed when the transfer is; -1 aborts.
#[test]
fn the_socket_function_is_called_as_c_calls_it() {
    use crate::ffi::{
        CURL_POLL_OUT, CURL_POLL_REMOVE, CURL_SOCKET_TIMEOUT, CURLM_ABORTED_BY_CALLBACK,
        CURLM_BAD_SOCKET,
    };
    use crate::multi::{ShimMulti, curl_multi_assign, curl_multi_socket_action};
    use curl_core::conn::io::{FakeNet, Peer};
    use curl_core::time::ManualClock;

    let clock = ManualClock::new().unwrap();
    let silent = std::net::SocketAddr::from(([127, 0, 0, 1], 3));
    let net = FakeNet::new(clock).with_peer(silent, Peer::Silent);
    let m: *mut CURLM = ShimMulti::boxed_with(Box::new(net))
        .unwrap()
        .as_ptr()
        .cast();
    let mut log = SocketLog {
        m,
        calls: Vec::new(),
        abort: false,
    };
    let me: *mut c_void = ptr::from_mut(&mut log).cast();
    let c = curl_easy_init();
    let url = c"tcp://127.0.0.1:3/";
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    let mut running_now: c_int = -1;
    // SAFETY: a live multi and handle; the log outlives them.
    unsafe {
        let f: ffi::curl_socket_callback = Some(socket_fn);
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_SOCKETFUNCTION, f),
            CURLM_OK
        );
        assert_eq!(curl_multi_setopt(m, ffi::CURLMOPT_SOCKETDATA, me), CURLM_OK);
        assert_eq!(
            curl_multi_assign(m, 1000, me),
            CURLM_BAD_SOCKET,
            "not yet watched"
        );
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        let rc = curl_multi_socket_action(m, CURL_SOCKET_TIMEOUT, 0, &raw mut running_now);
        assert_eq!((rc, running_now), (CURLM_OK, 1));
        let rc = curl_multi_socket_action(m, 1000, 0, &raw mut running_now);
        assert_eq!((rc, running_now), (CURLM_OK, 1), "still connecting");
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
    }
    assert_eq!(
        log.calls,
        [
            (c, 1000, CURL_POLL_OUT, ptr::null_mut()),
            (c, 1000, CURL_POLL_REMOVE, me),
        ]
    );
    // An abort ends the call with the count still told.
    log.calls.clear();
    log.abort = true;
    // SAFETY: as above.
    unsafe {
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        running_now = -1;
        let rc = curl_multi_socket_action(m, CURL_SOCKET_TIMEOUT, 0, &raw mut running_now);
        assert_eq!((rc, running_now), (CURLM_ABORTED_BY_CALLBACK, 1));
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        curl_easy_cleanup(c);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
    // The aborted announcement is not recorded, so no removal follows
    // (`mev_sh_entry_update` returns before marking it announced).
    assert_eq!(log.calls.len(), 1);
}

/// `curl_multi_cleanup` with a transfer still connecting removes its
/// socket through the socket function (`multi_done`, then
/// `Curl_multi_will_close`); without a socket function the multi records
/// no socket, so `curl_multi_assign` knows none.
#[test]
fn cleanup_removes_the_sockets_the_socket_function_was_told() {
    use crate::ffi::{CURL_POLL_OUT, CURL_POLL_REMOVE, CURL_SOCKET_TIMEOUT, CURLM_BAD_SOCKET};
    use crate::multi::{ShimMulti, curl_multi_assign, curl_multi_socket_action};
    use curl_core::conn::io::{FakeNet, Peer};
    use curl_core::time::ManualClock;

    let multi = || -> *mut CURLM {
        let clock = ManualClock::new().unwrap();
        let silent = std::net::SocketAddr::from(([127, 0, 0, 1], 3));
        let net = FakeNet::new(clock).with_peer(silent, Peer::Silent);
        ShimMulti::boxed_with(Box::new(net))
            .unwrap()
            .as_ptr()
            .cast()
    };
    let c = curl_easy_init();
    let url = c"tcp://127.0.0.1:3/";
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    let mut running: c_int = -1;
    let unwatched = multi();
    // SAFETY: a live multi and handle.
    unsafe {
        assert_eq!(curl_multi_add_handle(unwatched, c), CURLM_OK);
        let rc = curl_multi_socket_action(unwatched, CURL_SOCKET_TIMEOUT, 0, &raw mut running);
        assert_eq!((rc, running), (CURLM_OK, 1));
        assert_eq!(
            curl_multi_assign(unwatched, 1000, ptr::null_mut()),
            CURLM_BAD_SOCKET
        );
        assert_eq!(curl_multi_remove_handle(unwatched, c), CURLM_OK);
        assert_eq!(curl_multi_cleanup(unwatched), CURLM_OK);
    }
    let m = multi();
    let mut log = SocketLog {
        m,
        calls: Vec::new(),
        abort: false,
    };
    let me: *mut c_void = ptr::from_mut(&mut log).cast();
    // SAFETY: a live multi and handle; the log outlives the multi.
    unsafe {
        let f: ffi::curl_socket_callback = Some(socket_fn);
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_SOCKETFUNCTION, f),
            CURLM_OK
        );
        assert_eq!(curl_multi_setopt(m, ffi::CURLMOPT_SOCKETDATA, me), CURLM_OK);
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        let rc = curl_multi_socket_action(m, CURL_SOCKET_TIMEOUT, 0, &raw mut running);
        assert_eq!((rc, running), (CURLM_OK, 1));
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
        curl_easy_cleanup(c);
    }
    assert_eq!(
        log.calls,
        [
            (c, 1000, CURL_POLL_OUT, ptr::null_mut()),
            (c, 1000, CURL_POLL_REMOVE, me),
        ]
    );
}

/// Without a `CURLOPT_CONNECT_ONLY` connection there is nothing to read
/// or write: `CURLE_UNSUPPORTED_PROTOCOL`, nothing moved; a missing count
/// or buffer is a bad argument (`curl_easy_recv`, `curl_easy_send`).
#[test]
fn recv_and_send_need_a_connect_only_connection() {
    use crate::easy::{curl_easy_recv, curl_easy_send};
    let c = curl_easy_init();
    let mut buf = [0u8; 4];
    let mut n = 9;
    // SAFETY: a live handle, a buffer of 4 bytes and a count to write.
    unsafe {
        assert_eq!(
            curl_easy_recv(c, buf.as_mut_ptr().cast(), 4, &raw mut n),
            ffi::CURLE_UNSUPPORTED_PROTOCOL
        );
        assert_eq!(n, 0);
        n = 9;
        assert_eq!(
            curl_easy_send(c, buf.as_ptr().cast(), 4, &raw mut n),
            ffi::CURLE_UNSUPPORTED_PROTOCOL
        );
        assert_eq!(n, 0);
        assert_eq!(
            curl_easy_recv(c, ptr::null_mut(), 4, &raw mut n),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
        assert_eq!(
            curl_easy_send(c, buf.as_ptr().cast(), 4, ptr::null_mut()),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
        assert_eq!(
            curl_easy_recv(ptr::null_mut(), buf.as_mut_ptr().cast(), 4, &raw mut n),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
        curl_easy_cleanup(c);
    }
}

/// `curl_easy_perform_ev` runs the transfer by the events its multi
/// announces, waiting for a server that answers late, and refuses a handle
/// in a multi.
#[cfg(feature = "debug-hooks")]
#[test]
fn performs_by_events() {
    use crate::easy::curl_easy_perform_ev;
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let mut got = Vec::new();
        let mut buf = [0; 1024];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = peer.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlater")
            .unwrap();
    });
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform_ev(c) }, CURLE_OK);
    server.join().unwrap();
    let mut size: ffi::curl_off_t = 0;
    let m = curl_multi_init();
    // SAFETY: live handles, and an info of this type.
    unsafe {
        assert_eq!(
            crate::getinfo::curl_easy_getinfo(c, ffi::CURLINFO_SIZE_DOWNLOAD_T, &raw mut size),
            CURLE_OK
        );
        assert_eq!(curl_multi_add_handle(m, c), ffi::CURLM_OK);
        assert_eq!(curl_easy_perform_ev(c), ffi::CURLE_FAILED_INIT);
        assert_eq!(curl_multi_cleanup(m), ffi::CURLM_OK);
        curl_easy_cleanup(c);
    }
    assert_eq!(size, 5);
}

/// `curl_easy_header` and `curl_easy_nextheader` over a real response:
/// lookups by name in any case with index and amount, iteration in
/// arrival order, and the arguments C refuses (as lib1940 checks them).
#[test]
fn headers_are_looked_up_and_walked_as_in_c() {
    use crate::headers::{curl_easy_header, curl_easy_nextheader};
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let mut got = Vec::new();
        let mut buf = [0; 1024];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = peer.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        peer.write_all(
            b"HTTP/1.1 200 OK\r\nDate: today\r\nSet-Cookie: a=1\r\nServer: x \r\n\
              set-cookie: b=2\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
    });
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    let mut h = ptr::null_mut();
    // SAFETY: a live handle and a header pointer to write.
    unsafe {
        assert_eq!(
            curl_easy_header(
                c,
                c"date".as_ptr(),
                0,
                ffi::CURLH_HEADER as c_uint,
                -1,
                &raw mut h
            ),
            ffi::CURLHE_NOHEADERS
        );
    }
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    server.join().unwrap();
    let text = |p: *const c_char| {
        // SAFETY: a header's strings are C strings while it is shown.
        unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned()
    };
    let header = ffi::CURLH_HEADER as c_uint;
    // SAFETY: a live handle, and the headers it hands out, read before
    // the next call of the same function.
    unsafe {
        let get = |name: &CStr, i: usize, h: &mut *mut curl_header| {
            curl_easy_header(c, name.as_ptr(), i, header, -1, h)
        };
        assert_eq!(get(c"SET-COOKIE", 1, &mut h), ffi::CURLHE_OK);
        let one = &*h;
        assert_eq!(
            (text(one.name), text(one.value)),
            ("set-cookie".into(), "b=2".into())
        );
        assert_eq!((one.index, one.amount), (1, 2));
        assert_eq!(one.origin & 0xff, header);
        assert_ne!(one.origin, header, "a reserved bit is set");
        assert_eq!(get(c"server", 0, &mut h), ffi::CURLHE_OK);
        assert_eq!(text((*h).value), "x");
        assert_eq!(get(c"set-cookie", 2, &mut h), ffi::CURLHE_BADINDEX);
        assert_eq!(get(c"nope", 0, &mut h), ffi::CURLHE_MISSING);
        let bad = |name: *const c_char, origin: c_uint, req: c_int, out: *mut *mut curl_header| {
            curl_easy_header(c, name, 0, origin, req, out)
        };
        assert_eq!(
            bad(ptr::null(), header, -1, &raw mut h),
            ffi::CURLHE_BAD_ARGUMENT
        );
        assert_eq!(
            bad(c"x".as_ptr(), header, -1, ptr::null_mut()),
            ffi::CURLHE_BAD_ARGUMENT
        );
        assert_eq!(
            bad(c"x".as_ptr(), 0, -1, &raw mut h),
            ffi::CURLHE_BAD_ARGUMENT
        );
        assert_eq!(
            bad(c"x".as_ptr(), 32, -1, &raw mut h),
            ffi::CURLHE_BAD_ARGUMENT
        );
        assert_eq!(
            bad(c"x".as_ptr(), header, -2, &raw mut h),
            ffi::CURLHE_BAD_ARGUMENT
        );
        assert_eq!(
            bad(c"date".as_ptr(), header, 1, &raw mut h),
            ffi::CURLHE_NOREQUEST
        );
        assert_eq!(
            curl_easy_header(ptr::null_mut(), c"x".as_ptr(), 0, header, -1, &raw mut h),
            ffi::CURLHE_BAD_ARGUMENT
        );
        // Every header, in order; a lookup's header goes on from itself.
        let mut names = Vec::new();
        let mut at = curl_easy_nextheader(c, header, -1, ptr::null_mut());
        // Bounded, so a walk that goes round fails rather than grows.
        while !at.is_null() && names.len() < 10 {
            names.push(format!(
                "{}:{}/{}",
                text((*at).name),
                (*at).index,
                (*at).amount
            ));
            at = curl_easy_nextheader(c, header, -1, at);
        }
        assert_eq!(
            names,
            [
                "Date:0/1",
                "Set-Cookie:0/2",
                "Server:0/1",
                "set-cookie:1/2",
                "Content-Length:0/1"
            ]
        );
        assert_eq!(get(c"server", 0, &mut h), ffi::CURLHE_OK);
        let after = curl_easy_nextheader(c, header, -1, h);
        assert_eq!(text((*after).name), "set-cookie");
        assert!(
            curl_easy_nextheader(c, ffi::CURLH_TRAILER as c_uint, -1, ptr::null_mut()).is_null()
        );
        let mut foreign = *after;
        assert!(curl_easy_nextheader(c, header, -1, &raw mut foreign).is_null());
        assert!(curl_easy_nextheader(ptr::null_mut(), header, -1, ptr::null_mut()).is_null());
        curl_easy_cleanup(c);
    }
}

/// The lock functions' calls, as `(lock, data, handle)`.
static LOCKS: std::sync::Mutex<Vec<(bool, c_int, usize)>> = std::sync::Mutex::new(Vec::new());

unsafe extern "C" fn record_lock(
    curl: *mut CURL,
    data: ffi::curl_lock_data,
    _: ffi::curl_lock_access,
    _: *mut c_void,
) {
    LOCKS
        .lock()
        .unwrap()
        .push((true, data.0 as c_int, curl as usize));
}

unsafe extern "C" fn record_unlock(curl: *mut CURL, data: ffi::curl_lock_data, _: *mut c_void) {
    LOCKS
        .lock()
        .unwrap()
        .push((false, data.0 as c_int, curl as usize));
}

/// Handles on two threads use one share at once, with no lock functions
/// set: each stores cookies in its jar and reads files over its pool and
/// names, and every cookie is there at the end.
#[test]
fn a_share_is_used_from_two_threads_at_once() {
    use crate::share::{curl_share_cleanup, curl_share_init, curl_share_setopt};
    const EACH: usize = 100;
    let sh = curl_share_init();
    for data in [
        ffi::CURL_LOCK_DATA_COOKIE,
        ffi::CURL_LOCK_DATA_DNS,
        ffi::CURL_LOCK_DATA_CONNECT,
    ] {
        // SAFETY: a live share and an int, as the option takes.
        let set = unsafe { curl_share_setopt(sh, ffi::CURLSHOPT_SHARE, data.0 as c_int) };
        assert_eq!(set, ffi::CURLSHE_OK);
    }
    let (path, url) = file("threads", b"hello");
    // The share's address, to cross to the threads; it outlives them.
    let at = sh as usize;
    let url = &url;
    std::thread::scope(|scope| {
        for t in 0..2 {
            scope.spawn(move || {
                let c = curl_easy_init();
                assert_eq!(
                    pointer(c, ffi::CURLOPT_SHARE, at as *mut ffi::CURLSH),
                    CURLE_OK
                );
                pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
                function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
                for i in 0..EACH {
                    let line = format!("example.com\tFALSE\t/\tFALSE\t0\tt{t}_{i}\t1");
                    let line = std::ffi::CString::new(line).unwrap();
                    assert_eq!(
                        pointer(c, ffi::CURLOPT_COOKIELIST, line.as_ptr().cast_mut()),
                        CURLE_OK
                    );
                    // SAFETY: a live handle.
                    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
                }
                // SAFETY: a live handle, not used again.
                unsafe { curl_easy_cleanup(c) };
            });
        }
    });
    let c = curl_easy_init();
    assert_eq!(pointer(c, ffi::CURLOPT_SHARE, sh), CURLE_OK);
    let mut list: *mut ffi::curl_slist = ptr::null_mut();
    let mut count = 0;
    // SAFETY: a live handle, the list the info takes, walked to its end
    // and freed; then the handle and the share, not used again.
    unsafe {
        assert_eq!(
            curl_easy_getinfo(c, ffi::CURLINFO_COOKIELIST, &raw mut list),
            CURLE_OK
        );
        let mut at = list;
        while !at.is_null() {
            count += 1;
            at = (*at).next;
        }
        crate::strings::curl_slist_free_all(list);
        curl_easy_cleanup(c);
        assert_eq!(curl_share_cleanup(sh), ffi::CURLSHE_OK);
    }
    assert_eq!(count, 2 * EACH);
    std::fs::remove_file(path).unwrap();
}

/// The share answers each kind of data as C built like this one does,
/// refuses changes and its cleanup while a handle holds it, which a reset
/// keeps and a copy does not, and calls the lock functions for itself as
/// handles come and go.
#[test]
fn a_share_is_held_and_locked_as_in_c() {
    use crate::share::{curl_share_cleanup, curl_share_init, curl_share_setopt};
    let set = |sh, o, data: ffi::curl_lock_data| {
        // SAFETY: a live share and an int, as the option takes.
        unsafe { curl_share_setopt(sh, o, data.0 as c_int) }
    };
    let sh = curl_share_init();
    for (data, want) in [
        (ffi::CURL_LOCK_DATA_COOKIE, ffi::CURLSHE_OK),
        (ffi::CURL_LOCK_DATA_DNS, ffi::CURLSHE_OK),
        (ffi::CURL_LOCK_DATA_CONNECT, ffi::CURLSHE_OK),
        (ffi::CURL_LOCK_DATA_PSL, ffi::CURLSHE_OK),
        (ffi::CURL_LOCK_DATA_HSTS, ffi::CURLSHE_NOT_BUILT_IN),
        (ffi::CURL_LOCK_DATA_SSL_SESSION, ffi::CURLSHE_NOT_BUILT_IN),
        (ffi::CURL_LOCK_DATA_SHARE, ffi::CURLSHE_BAD_OPTION),
        (ffi::CURL_LOCK_DATA_LAST, ffi::CURLSHE_BAD_OPTION),
    ] {
        assert_eq!(set(sh, ffi::CURLSHOPT_SHARE, data), want, "{}", data.0);
    }
    assert_eq!(
        set(sh, ffi::CURLSHOPT_UNSHARE, ffi::CURL_LOCK_DATA_PSL),
        ffi::CURLSHE_BAD_OPTION
    );
    // SAFETY: a live share, and the functions its options take.
    unsafe {
        let lock: ffi::curl_lock_function = Some(record_lock);
        let unlock: ffi::curl_unlock_function = Some(record_unlock);
        assert_eq!(
            curl_share_setopt(sh, ffi::CURLSHOPT_LOCKFUNC, lock),
            ffi::CURLSHE_OK
        );
        assert_eq!(
            curl_share_setopt(sh, ffi::CURLSHOPT_UNLOCKFUNC, unlock),
            ffi::CURLSHE_OK
        );
    }
    let one = curl_easy_init();
    let two = curl_easy_init();
    assert_eq!(pointer(one, ffi::CURLOPT_SHARE, sh), CURLE_OK);
    assert_eq!(pointer(two, ffi::CURLOPT_SHARE, sh), CURLE_OK);
    let share = |c: *mut CURL| (true, ffi::CURL_LOCK_DATA_SHARE.0 as c_int, c as usize);
    let unshare = |c: *mut CURL| (false, ffi::CURL_LOCK_DATA_SHARE.0 as c_int, c as usize);
    assert_eq!(
        std::mem::take(&mut *LOCKS.lock().unwrap()),
        [share(one), unshare(one), share(two), unshare(two)]
    );

    // One jar for both.
    let line = c"example.com\tFALSE\t/\tFALSE\t0\ta\t1";
    assert_eq!(
        pointer(one, ffi::CURLOPT_COOKIELIST, line.as_ptr().cast_mut()),
        CURLE_OK
    );
    let mut list: *mut ffi::curl_slist = ptr::null_mut();
    // SAFETY: a live handle, and the list the info takes.
    let listed = unsafe {
        assert_eq!(
            curl_easy_getinfo(two, ffi::CURLINFO_COOKIELIST, &raw mut list),
            CURLE_OK
        );
        let text = CStr::from_ptr((*list).data).to_owned();
        crate::strings::curl_slist_free_all(list);
        text
    };
    assert_eq!(listed.as_c_str(), line);

    // Held: no changes, no cleanup, through a reset; a copy holds none.
    // SAFETY: live handles.
    unsafe { easy::curl_easy_reset(two) };
    // SAFETY: a live handle.
    let copy = unsafe { easy::curl_easy_duphandle(two) };
    assert_eq!(
        set(sh, ffi::CURLSHOPT_SHARE, ffi::CURL_LOCK_DATA_DNS),
        ffi::CURLSHE_IN_USE
    );
    // SAFETY: a live share.
    assert_eq!(unsafe { curl_share_cleanup(sh) }, ffi::CURLSHE_IN_USE);
    assert_eq!(
        pointer(one, ffi::CURLOPT_SHARE, ptr::null_mut::<c_void>()),
        CURLE_OK
    );
    // The one left holds it still.
    assert_eq!(
        set(sh, ffi::CURLSHOPT_SHARE, ffi::CURL_LOCK_DATA_DNS),
        ffi::CURLSHE_IN_USE
    );
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(two) };
    // The jar locked for each use of it, the flush at cleanup among them,
    // as C locks `CURL_LOCK_DATA_COOKIE`.
    let cookie = |c: *mut CURL| (true, ffi::CURL_LOCK_DATA_COOKIE.0 as c_int, c as usize);
    let uncookie = |c: *mut CURL| (false, ffi::CURL_LOCK_DATA_COOKIE.0 as c_int, c as usize);
    assert_eq!(
        std::mem::take(&mut *LOCKS.lock().unwrap()),
        [
            cookie(one),
            uncookie(one),
            cookie(two),
            uncookie(two),
            share(one),
            unshare(one),
            cookie(two),
            uncookie(two),
            share(two),
            unshare(two)
        ]
    );
    // SAFETY: a live share, held by none, the copy included; then no
    // share at all; then live handles, not used again.
    unsafe {
        assert_eq!(curl_share_cleanup(sh), ffi::CURLSHE_OK);
        assert_eq!(curl_share_cleanup(ptr::null_mut()), ffi::CURLSHE_INVALID);
        curl_easy_cleanup(one);
        curl_easy_cleanup(copy);
    }
    // Its connections closed under their lock (`Curl_cpool_destroy`).
    let null = ptr::null_mut();
    let connect = (true, ffi::CURL_LOCK_DATA_CONNECT.0 as c_int, 0);
    let unconnect = (false, ffi::CURL_LOCK_DATA_CONNECT.0 as c_int, 0);
    assert_eq!(
        std::mem::take(&mut *LOCKS.lock().unwrap()),
        [share(null), unshare(null), connect, unconnect]
    );
}

/// The proxy options reach the transfer's, checked as setopt.c checks
/// them.
#[test]
fn proxy_options_are_checked_as_in_c() {
    let c = curl_easy_init();
    assert_eq!(
        pointer(c, ffi::CURLOPT_PROXY, c"http://p:1".as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_NOPROXY, c"a,b".as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_PROXYPORT, 3128), CURLE_OK);
    assert_eq!(
        long(c, ffi::CURLOPT_PROXYTYPE, ffi::CURLPROXY_SOCKS5_HOSTNAME),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_HTTPPROXYTUNNEL, 2), CURLE_OK);
    options(c, |o| {
        assert_eq!(o.proxy.url.as_deref(), Some(&b"http://p:1"[..]));
        assert_eq!(o.proxy.no_proxy.as_deref(), Some(&b"a,b"[..]));
        assert_eq!(o.proxy.port.map(|p| p.get()), Some(3128));
        assert_eq!(o.proxy.kind, curl_core::options::ProxyType::Socks5Hostname);
        assert!(o.proxy.tunnel);
    });
    assert_eq!(
        long(c, ffi::CURLOPT_PROXYPORT, 65536),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(
        long(c, ffi::CURLOPT_PROXYPORT, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(long(c, ffi::CURLOPT_PROXYPORT, 0), CURLE_OK);
    assert_eq!(
        long(c, ffi::CURLOPT_PROXYTYPE, 9),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(
        long(c, ffi::CURLOPT_PROXYTYPE, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(
        long(c, ffi::CURLOPT_PROXYTYPE, ffi::CURLPROXY_HTTPS3),
        CURLE_NOT_BUILT_IN
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_PROXY, ptr::null_mut::<c_void>()),
        CURLE_OK
    );
    options(c, |o| {
        assert_eq!((o.proxy.url.as_deref(), o.proxy.port), (None, None));
        assert_eq!(o.proxy.kind, curl_core::options::ProxyType::Socks5Hostname);
    });
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_USED_PROXY), 0);
    use curl_core::options::ProxyType;
    for (v, want) in [
        (ffi::CURLPROXY_HTTP, ProxyType::Http),
        (ffi::CURLPROXY_HTTP_1_0, ProxyType::Http10),
        (ffi::CURLPROXY_HTTPS, ProxyType::Https),
        (ffi::CURLPROXY_HTTPS2, ProxyType::Https2),
        (ffi::CURLPROXY_SOCKS4, ProxyType::Socks4),
        (ffi::CURLPROXY_SOCKS5, ProxyType::Socks5),
        (ffi::CURLPROXY_SOCKS4A, ProxyType::Socks4a),
        (ffi::CURLPROXY_SOCKS5_HOSTNAME, ProxyType::Socks5Hostname),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_PROXYTYPE, v), CURLE_OK);
        assert_eq!(options(c, |o| o.proxy.kind), want, "{v}");
    }
    // The SOCKS5 methods: only those built in, and not none of them
    // with `CURLAUTH_ONLY`.
    let socks5 = |c| {
        options(c, |o| {
            let a = o.proxy.socks5_auth;
            [a.basic, a.gssapi, a.only]
        })
    };
    assert_eq!(socks5(c), [true, true, false], "C's default");
    let (basic, gssapi, only) = (
        ffi::CURLAUTH_BASIC,
        ffi::CURLAUTH_GSSAPI,
        ffi::CURLAUTH_ONLY,
    );
    for (mask, want) in [
        (0, [false; 3]),
        (basic, [true, false, false]),
        (gssapi, [false, true, false]),
        (basic | gssapi, [true, true, false]),
        (basic | only, [true, false, true]),
        (gssapi | only, [false, true, true]),
        (basic | gssapi | only, [true; 3]),
    ] {
        assert_eq!(
            long(c, ffi::CURLOPT_SOCKS5_AUTH, mask as c_long),
            CURLE_OK,
            "{mask:#x}"
        );
        assert_eq!(socks5(c), want, "{mask:#x}");
    }
    long(c, ffi::CURLOPT_SOCKS5_AUTH, basic as c_long);
    for (mask, code) in [
        (only, CURLE_BAD_FUNCTION_ARGUMENT),
        (ffi::CURLAUTH_DIGEST, CURLE_NOT_BUILT_IN),
        (basic | ffi::CURLAUTH_DIGEST, CURLE_NOT_BUILT_IN),
    ] {
        assert_eq!(
            long(c, ffi::CURLOPT_SOCKS5_AUTH, mask as c_long),
            code,
            "{mask:#x}"
        );
    }
    assert_eq!(socks5(c), [true, false, false], "unchanged");
    // The strings copied, the header list kept; NULL takes them away.
    pointer(c, ffi::CURLOPT_PRE_PROXY, c"socks4://q".as_ptr().cast_mut());
    pointer(c, ffi::CURLOPT_PROXYPASSWORD, c"pw".as_ptr().cast_mut());
    let mut list = ptr::null_mut();
    for line in [c"X-P: 1", c"X-Q: 2"] {
        // SAFETY: a list made here, and a C string.
        list = unsafe { crate::strings::curl_slist_append(list, line.as_ptr()) };
    }
    assert_eq!(pointer(c, ffi::CURLOPT_PROXYHEADER, list), CURLE_OK);
    let kept = |c| {
        options(c, |o| {
            (
                o.proxy.pre_proxy.clone(),
                o.proxy.password.clone(),
                o.proxy
                    .headers
                    .lines()
                    .map(<[u8]>::to_vec)
                    .collect::<Vec<_>>(),
            )
        })
    };
    assert_eq!(
        kept(c),
        (
            Some(b"socks4://q".to_vec()),
            Some(b"pw".to_vec()),
            vec![b"X-P: 1".to_vec(), b"X-Q: 2".to_vec()]
        )
    );
    for o in [
        ffi::CURLOPT_PRE_PROXY,
        ffi::CURLOPT_PROXYPASSWORD,
        ffi::CURLOPT_PROXYHEADER,
    ] {
        assert_eq!(pointer(c, o, ptr::null_mut::<c_char>()), CURLE_OK);
    }
    // SAFETY: the list made above, which the handle no longer keeps.
    unsafe { crate::strings::curl_slist_free_all(list) };
    assert_eq!(kept(c), (None, None, vec![]));
    // Only `CURLHEADER_SEPARATE`'s bit counts.
    let unified = |c| options(c, |o| o.proxy.unified_headers);
    for (v, want) in [
        (ffi::CURLHEADER_SEPARATE, false),
        (ffi::CURLHEADER_UNIFIED, true),
        (ffi::CURLHEADER_SEPARATE | 2, false),
        (2, true),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_HEADEROPT, v), CURLE_OK);
        assert_eq!(unified(c), want, "{v}");
    }
    // A client address turns the PROXY protocol on, and clearing it off.
    let haproxy = |c| options(c, |o| (o.proxy.haproxy, o.proxy.haproxy_client_ip.clone()));
    assert_eq!(
        pointer(
            c,
            ffi::CURLOPT_HAPROXY_CLIENT_IP,
            c"1.2.3.4".as_ptr().cast_mut()
        ),
        CURLE_OK
    );
    assert_eq!(haproxy(c), (true, Some(b"1.2.3.4".to_vec())));
    long(c, ffi::CURLOPT_HAPROXYPROTOCOL, 1);
    assert_eq!(
        pointer(c, ffi::CURLOPT_HAPROXY_CLIENT_IP, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    assert_eq!(haproxy(c), (false, None));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_PROXYUSERPWD` splits at the first colon and decodes each
/// part, refusing a zero byte, as setopt.c does; the proxy's methods are
/// read as `CURLOPT_HTTPAUTH`'s.
#[test]
fn proxy_credentials_are_decoded_as_in_c() {
    let c = curl_easy_init();
    let set = |s: &core::ffi::CStr| pointer(c, ffi::CURLOPT_PROXYUSERPWD, s.as_ptr().cast_mut());
    assert_eq!(set(c"a%3Ab:c:d%20"), CURLE_OK);
    options(c, |o| {
        assert_eq!(o.proxy.user.as_deref(), Some(&b"a:b"[..]));
        assert_eq!(o.proxy.password.as_deref(), Some(&b"c:d "[..]));
    });
    assert_eq!(set(c"user"), CURLE_OK);
    options(c, |o| {
        assert_eq!(
            (o.proxy.user.as_deref(), o.proxy.password.as_deref()),
            (Some(&b"user"[..]), None)
        )
    });
    assert_eq!(set(c"a:b%00"), ffi::CURLE_URL_MALFORMAT);
    assert_eq!(
        pointer(c, ffi::CURLOPT_PROXYUSERPWD, ptr::null_mut::<c_void>()),
        CURLE_OK
    );
    options(c, |o| {
        assert_eq!(
            (o.proxy.user.as_deref(), o.proxy.password.as_deref()),
            (None, None)
        )
    });
    assert_eq!(
        pointer(c, ffi::CURLOPT_PROXYUSERNAME, c"x%41".as_ptr().cast_mut()),
        CURLE_OK
    );
    options(c, |o| {
        assert_eq!(
            o.proxy.user.as_deref(),
            Some(&b"x%41"[..]),
            "taken as it is"
        )
    });
    assert_eq!(
        long(c, ffi::CURLOPT_PROXYAUTH, ffi::CURLAUTH_ANY as c_long),
        CURLE_OK
    );
    options(c, |o| {
        assert_eq!(o.proxy.auth.0, curl_core::options::AuthMethods::ANY)
    });
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_PROXYAUTH_AVAIL), 0);
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_PROXYAUTH_USED), 0);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// One request read whole from `peer`: its head and its body, as long as
/// `Content-Length` says or, chunked, to the end of its trailers. What
/// came before the peer closed, if it closed first.
fn read_request(peer: &mut std::net::TcpStream) -> Vec<u8> {
    use std::io::Read as _;
    let mut got = Vec::new();
    let mut buf = [0; 4096];
    let complete = |got: &[u8]| {
        let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
        let body = &got[end + 4..];
        if head.contains("transfer-encoding: chunked") {
            body.ends_with(b"\r\n\r\n")
                && (body.starts_with(b"0\r\n") || body.windows(5).any(|w| w == b"\r\n0\r\n"))
        } else {
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .map_or(0, |n| n.trim().parse::<usize>().unwrap());
            body.len() >= length
        }
    };
    while !complete(&got) {
        match peer.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    got
}

/// A server on a local port that answers one request per connection
/// with each of `replies` in turn, and gives back the requests: fewer,
/// if no client comes for ten seconds.
fn serve(replies: Vec<&'static [u8]>) -> (u16, std::thread::JoinHandle<Vec<Vec<u8>>>) {
    use std::io::Write as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for reply in replies {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut peer = loop {
                match listener.accept() {
                    Ok((peer, _)) => break peer,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() > deadline {
                            return requests;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            peer.set_nonblocking(false).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            requests.push(read_request(&mut peer));
            // A client that gave up may have gone.
            if let Err(e) = peer.write_all(reply) {
                let gone = [
                    std::io::ErrorKind::BrokenPipe,
                    std::io::ErrorKind::ConnectionReset,
                ];
                assert!(gone.contains(&e.kind()), "{e}");
            }
        }
        requests
    });
    (port, server)
}

fn text_of(p: *const c_char) -> String {
    assert!(!p.is_null());
    // SAFETY: getinfo gives a string that lives while the handle does.
    unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned()
}

/// The infos of HTTP transfers: the addresses, the methods the server
/// offered and the one used, the referer sent, the redirects followed,
/// and the request asking for every coding the handle undoes.
#[test]
fn infos_answer_from_an_http_transfer() {
    let (port, server) = serve(vec![
        b"HTTP/1.1 401 No\r\nWWW-Authenticate: Basic realm=\"x\"\r\n\
          Content-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    pointer(c, ffi::CURLOPT_USERPWD, c"u:p".as_ptr().cast_mut());
    long(c, ffi::CURLOPT_HTTPAUTH, ffi::CURLAUTH_ANY as c_long);
    pointer(c, ffi::CURLOPT_REFERER, c"http://r/".as_ptr().cast_mut());
    pointer(c, ffi::CURLOPT_ACCEPT_ENCODING, c"".as_ptr().cast_mut());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let requests = server.join().unwrap();
    let head = String::from_utf8(requests[1].clone()).unwrap();
    assert!(
        head.contains("\r\nAccept-Encoding: deflate, gzip, br, zstd\r\n"),
        "{head}"
    );
    assert!(head.contains("\r\nAuthorization: Basic dTpw\r\n"), "{head}");
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_RESPONSE_CODE), 200);
    for ip in [ffi::CURLINFO_PRIMARY_IP, ffi::CURLINFO_LOCAL_IP] {
        assert_eq!(text_of(info(c, ip)), "127.0.0.1", "{}", ip.0);
    }
    assert_eq!(
        info::<c_long>(c, ffi::CURLINFO_PRIMARY_PORT),
        c_long::from(port)
    );
    let basic = ffi::CURLAUTH_BASIC as c_long;
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_HTTPAUTH_AVAIL), basic);
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_HTTPAUTH_USED), basic);
    assert_eq!(text_of(info(c, ffi::CURLINFO_REFERER)), "http://r/");
    // The request sent again with credentials counts, as in C.
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_REDIRECT_COUNT), 1);

    // A POST sent again to where a 307 points, its fields read from
    // their start, with the URL it came from as its referer.
    let (port, server) = serve(vec![
        b"HTTP/1.1 307 Again\r\nLocation: /b\r\nContent-Length: 0\r\n\
          Connection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/a")).unwrap();
    let fields = c"abcdef";
    // SAFETY: a live handle.
    unsafe { easy::curl_easy_reset(c) };
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    pointer(c, ffi::CURLOPT_POSTFIELDS, fields.as_ptr().cast_mut());
    long(c, ffi::CURLOPT_FOLLOWLOCATION, 1);
    long(c, ffi::CURLOPT_AUTOREFERER, 1);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let requests = server.join().unwrap();
    let second = String::from_utf8(requests[1].clone()).unwrap();
    assert!(second.starts_with("POST /b HTTP/1.1\r\n"), "{second}");
    assert!(second.ends_with("\r\n\r\nabcdef"), "{second}");
    let from = format!("http://127.0.0.1:{port}/a");
    assert!(
        second.contains(&format!("\r\nReferer: {from}\r\n")),
        "{second}"
    );
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_REDIRECT_COUNT), 1);
    assert_eq!(text_of(info(c, ffi::CURLINFO_REFERER)), from);
    assert_eq!(text_of(info(c, ffi::CURLINFO_EFFECTIVE_METHOD)), "POST");
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// A method this build does not implement, asked with Basic, keeps
/// Basic from going at once: it waits for the server to ask, as in C;
/// asked alone, nothing is sent.
#[test]
fn unknown_auth_bits_hold_basic_back() {
    let challenge: &'static [u8] = b"HTTP/1.1 401 No\r\nWWW-Authenticate: Basic realm=\"x\"\r\n\
          Content-Length: 0\r\nConnection: close\r\n\r\n";
    let ok: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let unknown: core::ffi::c_ulong = 1 << 20;
    for (bits, replies, sent) in [
        (ffi::CURLAUTH_BASIC, vec![ok], vec![true]),
        (
            ffi::CURLAUTH_BASIC | unknown,
            vec![challenge, ok],
            vec![false, true],
        ),
        (unknown, vec![challenge], vec![false]),
    ] {
        let (port, server) = serve(replies);
        let c = curl_easy_init();
        let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
        long(c, ffi::CURLOPT_TIMEOUT, 10);
        pointer(c, ffi::CURLOPT_USERPWD, c"u:p".as_ptr().cast_mut());
        assert_eq!(long(c, ffi::CURLOPT_HTTPAUTH, bits as c_long), CURLE_OK);
        // SAFETY: a live handle.
        assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
        let requests = server.join().unwrap();
        let got: Vec<bool> = requests
            .iter()
            .map(|r| String::from_utf8_lossy(r).contains("\r\nAuthorization: Basic dTpw\r\n"))
            .collect();
        assert_eq!(got, sent, "{bits:#x}");
        // SAFETY: a live handle, not used again.
        unsafe { curl_easy_cleanup(c) };
    }
}

/// `lines` appended to `list`, which is returned: the same head once it
/// has one, as `curl_slist_append` keeps it.
fn append(mut list: *mut ffi::curl_slist, lines: &[&CStr]) -> *mut ffi::curl_slist {
    for line in lines {
        // SAFETY: a list made by the caller, or NULL, and a C string.
        list = unsafe { crate::strings::curl_slist_append(list, line.as_ptr()) };
    }
    list
}

/// The lines of `request` that start with `X-`.
fn x_lines(request: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(request)
        .split("\r\n")
        .filter(|l| l.starts_with("X-"))
        .map(str::to_owned)
        .collect()
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The application's header list is read as each transfer starts, not
/// copied when it is set: lines appended after `CURLOPT_HTTPHEADER`, as
/// WebKit appends them, go out, and so do those appended between two
/// transfers, and a copy of the handle reads the same list.
#[test]
fn header_lines_appended_after_the_option_are_sent() {
    let (port, server) = serve(vec![OK, OK, OK]);
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    let list = append(ptr::null_mut(), &[c"X-A: 1"]);
    assert_eq!(pointer(c, ffi::CURLOPT_HTTPHEADER, list), CURLE_OK);
    assert_eq!(append(list, &[c"X-B: 2", c"X-C: 3", c"X-D: 4"]), list);
    // SAFETY: a live handle, whose list lives through the transfer.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    append(list, &[c"X-E: 5"]);
    // SAFETY: as above.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    // SAFETY: a live handle.
    let copy = unsafe { easy::curl_easy_duphandle(c) };
    assert!(!copy.is_null());
    append(list, &[c"X-F: 6"]);
    // SAFETY: the copy, live, with the same list.
    assert_eq!(unsafe { curl_easy_perform(copy) }, CURLE_OK);
    let requests = server.join().unwrap();
    let four = ["X-A: 1", "X-B: 2", "X-C: 3", "X-D: 4"];
    assert_eq!(x_lines(&requests[0]), four);
    assert_eq!(x_lines(&requests[1])[4..], ["X-E: 5"]);
    assert_eq!(x_lines(&requests[2])[4..], ["X-E: 5", "X-F: 6"]);
    // SAFETY: live handles, not used again; then the list they kept.
    unsafe {
        curl_easy_cleanup(copy);
        curl_easy_cleanup(c);
        crate::strings::curl_slist_free_all(list);
    }
}

/// Appends a line to the list at `data` when a redirect's or a proxy's
/// demand for credentials comes, between the two requests it leads to.
unsafe extern "C" fn append_on_redirect(
    b: *mut c_char,
    size: usize,
    n: usize,
    data: *mut c_void,
) -> usize {
    // SAFETY: the header line, `size * n` bytes.
    let line = unsafe { core::slice::from_raw_parts(b.cast::<u8>(), size * n) };
    if line.starts_with(b"HTTP/1.1 302") || line.starts_with(b"HTTP/1.1 407") {
        // SAFETY: `data` is the list's head, which an append keeps.
        append(
            unsafe { *data.cast::<*mut ffi::curl_slist>() },
            &[c"X-Late: yes"],
        );
    }
    size * n
}

/// The header list is read again for each request of a transfer: a line
/// appended between a redirect's requests goes with the second, as C
/// sends it.
#[test]
fn header_lines_appended_during_a_redirect_go_with_the_next_request() {
    let (port, server) = serve(vec![
        b"HTTP/1.1 302 Moved\r\nLocation: /b\r\nContent-Length: 0\r\n\
          Connection: close\r\n\r\n",
        OK,
    ]);
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/a")).unwrap();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    long(c, ffi::CURLOPT_FOLLOWLOCATION, 1);
    let mut list = append(ptr::null_mut(), &[c"X-Early: yes"]);
    pointer(c, ffi::CURLOPT_HTTPHEADER, list);
    function(
        c,
        ffi::CURLOPT_HEADERFUNCTION,
        append_on_redirect as WriteFn as *const (),
    );
    pointer(c, ffi::CURLOPT_HEADERDATA, &raw mut list);
    // SAFETY: a live handle, whose list lives through the transfer.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let requests = server.join().unwrap();
    assert_eq!(x_lines(&requests[0]), ["X-Early: yes"]);
    assert_eq!(x_lines(&requests[1]), ["X-Early: yes", "X-Late: yes"]);
    // SAFETY: a live handle, not used again; then the list it kept.
    unsafe {
        curl_easy_cleanup(c);
        crate::strings::curl_slist_free_all(list);
    }
}

/// `CURLOPT_PROXYHEADER`'s list is read as each `CONNECT` is made: a line
/// appended after the option goes to the proxy, and one appended as the
/// proxy asks for credentials goes with the `CONNECT` that gives them.
#[test]
fn proxy_header_lines_appended_after_the_option_are_sent() {
    use std::io::Write as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let first = read_request(&mut peer);
        peer.write_all(
            b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: Basic realm=\"p\"\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .unwrap();
        let connect = read_request(&mut peer);
        peer.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        let get = read_request(&mut peer);
        peer.write_all(OK).unwrap();
        (first, connect, get)
    });
    let c = curl_easy_init();
    pointer(
        c,
        ffi::CURLOPT_URL,
        c"http://origin.invalid/".as_ptr().cast_mut(),
    );
    let proxy = std::ffi::CString::new(format!("http://127.0.0.1:{port}")).unwrap();
    pointer(c, ffi::CURLOPT_PROXY, proxy.as_ptr().cast_mut());
    long(c, ffi::CURLOPT_HTTPPROXYTUNNEL, 1);
    long(c, ffi::CURLOPT_HEADEROPT, ffi::CURLHEADER_SEPARATE);
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    pointer(c, ffi::CURLOPT_PROXYUSERPWD, c"u:p".as_ptr().cast_mut());
    long(c, ffi::CURLOPT_PROXYAUTH, ffi::CURLAUTH_ANY as c_long);
    let mut list = append(ptr::null_mut(), &[c"X-P: 1"]);
    pointer(c, ffi::CURLOPT_PROXYHEADER, list);
    append(list, &[c"X-Q: 2"]);
    function(
        c,
        ffi::CURLOPT_HEADERFUNCTION,
        append_on_redirect as WriteFn as *const (),
    );
    pointer(c, ffi::CURLOPT_HEADERDATA, &raw mut list);
    // SAFETY: a live handle, whose list lives through the transfer.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let (first, connect, get) = server.join().unwrap();
    assert!(first.starts_with(b"CONNECT origin.invalid:80 "));
    assert_eq!(x_lines(&first), ["X-P: 1", "X-Q: 2"]);
    let connect = String::from_utf8(connect).unwrap();
    assert!(
        connect.contains("\r\nProxy-Authorization: Basic dTpw\r\n"),
        "{connect}"
    );
    assert_eq!(
        x_lines(connect.as_bytes()),
        ["X-P: 1", "X-Q: 2", "X-Late: yes"]
    );
    assert!(x_lines(&get).is_empty(), "the proxy's alone");
    // SAFETY: a live handle, not used again; then the list it kept.
    unsafe {
        curl_easy_cleanup(c);
        crate::strings::curl_slist_free_all(list);
    }
}

/// `CURLOPT_CONNECT_TO` and `CURLOPT_RESOLVE` read the application's
/// list when it is used, not when it is set: an entry appended after the
/// option is taken. RESOLVE's is read once for each time it is set, as
/// the next transfer starts, so an entry appended after that transfer is
/// not, as in C.
#[test]
fn connect_to_and_resolve_entries_appended_after_the_option_are_used() {
    let (port, server) = serve(vec![OK, OK]);
    let c = curl_easy_init();
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    pointer(
        c,
        ffi::CURLOPT_URL,
        c"http://unreach.invalid:1/ct".as_ptr().cast_mut(),
    );
    let to = std::ffi::CString::new(format!("unreach.invalid:1:127.0.0.1:{port}")).unwrap();
    let list = append(ptr::null_mut(), &[c"nothere:9::"]);
    pointer(c, ffi::CURLOPT_CONNECT_TO, list);
    append(list, &[&to]);
    // SAFETY: a live handle, whose list lives through the transfer.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    pointer(c, ffi::CURLOPT_CONNECT_TO, ptr::null_mut::<c_char>());
    // SAFETY: the list made above, which the handle no longer keeps.
    unsafe { crate::strings::curl_slist_free_all(list) };

    let url = std::ffi::CString::new(format!("http://fake.invalid:{port}/rs")).unwrap();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    let entry = std::ffi::CString::new(format!("fake.invalid:{port}:127.0.0.1")).unwrap();
    let list = append(ptr::null_mut(), &[c"nothere:9:127.0.0.1"]);
    pointer(c, ffi::CURLOPT_RESOLVE, list);
    append(list, &[&entry]);
    // SAFETY: as above.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let url = std::ffi::CString::new(format!("http://fake2.invalid:{port}/rs2")).unwrap();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    let entry = std::ffi::CString::new(format!("fake2.invalid:{port}:127.0.0.1")).unwrap();
    append(list, &[&entry]);
    let code = {
        // SAFETY: as above.
        unsafe { curl_easy_perform(c) }
    };
    // The name is left to the system's resolver, which may answer it;
    // what counts is that the entry was not read.
    assert_ne!(code, CURLE_OK, "read once per setting");
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(b"GET /ct HTTP/1.1\r\nHost: unreach.invalid:1\r\n"));
    assert!(requests[1].starts_with(b"GET /rs HTTP/1.1\r\n"));
    // SAFETY: a live handle, not used again; then the list it kept.
    unsafe {
        curl_easy_cleanup(c);
        crate::strings::curl_slist_free_all(list);
    }
}

/// The trailer function's lines end a chunked body, and its abort ends
/// the transfer as `add_last_chunk` ends it.
#[test]
fn the_trailer_function_ends_a_chunked_body() {
    let run = |answer: c_int| {
        let (port, server) = serve(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
        let mut feed = Feed {
            left: b"hello".to_vec(),
            answer: None,
        };
        let mut trailing = Trailing {
            lines: vec![c"X-T: 1", c"X-U: 2"],
            answer,
        };
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
        long(c, ffi::CURLOPT_TIMEOUT, 10);
        long(c, ffi::CURLOPT_UPLOAD, 1);
        // The server sends no 100: wait for it no longer than needed.
        long(c, ffi::CURLOPT_EXPECT_100_TIMEOUT_MS, 1);
        function(c, ffi::CURLOPT_READFUNCTION, read as ReadFn as *const ());
        pointer(c, ffi::CURLOPT_READDATA, &raw mut feed);
        function(
            c,
            ffi::CURLOPT_TRAILERFUNCTION,
            trailers as TrailerFn as *const (),
        );
        pointer(c, ffi::CURLOPT_TRAILERDATA, &raw mut trailing);
        // SAFETY: a live handle, then not used again.
        let code = unsafe { curl_easy_perform(c) };
        // SAFETY: as above.
        unsafe { curl_easy_cleanup(c) };
        if code != CURLE_OK {
            // Unblock the server, which waits for a connection still.
            std::net::TcpStream::connect(("127.0.0.1", port)).ok();
        }
        let request = server.join().unwrap().remove(0);
        (code, String::from_utf8(request).unwrap())
    };
    let (code, request) = run(ffi::CURL_TRAILERFUNC_OK);
    assert_eq!(code, CURLE_OK);
    assert!(
        request.ends_with("\r\n\r\n5\r\nhello\r\n0\r\nX-T: 1\r\nX-U: 2\r\n\r\n"),
        "{request}"
    );
    let (code, request) = run(ffi::CURL_TRAILERFUNC_ABORT);
    assert_eq!(code, CURLE_ABORTED_BY_CALLBACK);
    assert!(!request.contains("X-T"), "{request}");
}

/// Appends `Transfer-Encoding: chunked` to the list at `data` as the
/// connection is first tried: after the transfer started, before its
/// request is built.
unsafe extern "C" fn chunked_on_trying(
    _: *mut CURL,
    kind: ffi::curl_infotype,
    ptr: *mut c_char,
    n: usize,
    data: *mut c_void,
) -> c_int {
    // SAFETY: the shim's `n` bytes.
    let text = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), n) };
    if kind == ffi::CURLINFO_TEXT && text.starts_with(b"  Trying") {
        // SAFETY: `data` is the list's head, which an append keeps.
        append(
            unsafe { *data.cast::<*mut ffi::curl_slist>() },
            &[c"Transfer-Encoding: chunked"],
        );
    }
    0
}

/// A POST from the read function is sent chunked, and read to its end
/// whatever `CURLOPT_POSTFIELDSIZE` said, if its request is asked chunked
/// when it is built: the C build sends all 20 bytes when the line is
/// appended after the transfer started (`set_reader`, `http_req_set_TE`).
#[test]
fn a_post_asked_chunked_as_its_request_is_built_reads_to_the_end() {
    let (port, server) = serve(vec![OK]);
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    let mut feed = Feed {
        left: b"0123456789abcdefghij".to_vec(),
        answer: None,
    };
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    long(c, ffi::CURLOPT_EXPECT_100_TIMEOUT_MS, 1);
    long(c, ffi::CURLOPT_POST, 1);
    long(c, ffi::CURLOPT_POSTFIELDSIZE, 5);
    function(c, ffi::CURLOPT_READFUNCTION, read as ReadFn as *const ());
    pointer(c, ffi::CURLOPT_READDATA, &raw mut feed);
    let mut list = append(ptr::null_mut(), &[c"X-A: 1"]);
    pointer(c, ffi::CURLOPT_HTTPHEADER, list);
    long(c, ffi::CURLOPT_VERBOSE, 1);
    function(
        c,
        ffi::CURLOPT_DEBUGFUNCTION,
        chunked_on_trying as DebugFn as *const (),
    );
    pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut list);
    // SAFETY: a live handle, whose list lives through the transfer.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let request = String::from_utf8(server.join().unwrap().remove(0)).unwrap();
    assert!(
        request.contains("\r\nTransfer-Encoding: chunked\r\n")
            && !request.contains("Content-Length")
            && request.ends_with("\r\n\r\n14\r\n0123456789abcdefghij\r\n0\r\n\r\n"),
        "{request}"
    );
    // SAFETY: a live handle, not used again; then the list it kept.
    unsafe {
        curl_easy_cleanup(c);
        crate::strings::curl_slist_free_all(list);
    }
}

/// `CURLOPT_POSTFIELDS` asked chunked keep their size: as many bytes as
/// `CURLOPT_POSTFIELDSIZE` says go, in one chunk, and the size, being
/// small, adds no `Expect: 100-continue`, as the C build sends them
/// (`set_buf`, `addexpect`).
#[test]
fn post_fields_asked_chunked_keep_their_size() {
    let (port, server) = serve(vec![OK]);
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    let mut fields = *b"0123456789abcdefghij";
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    long(c, ffi::CURLOPT_EXPECT_100_TIMEOUT_MS, 1);
    pointer(c, ffi::CURLOPT_POSTFIELDS, fields.as_mut_ptr());
    long(c, ffi::CURLOPT_POSTFIELDSIZE, 5);
    let list = append(ptr::null_mut(), &[c"Transfer-Encoding: chunked"]);
    pointer(c, ffi::CURLOPT_HTTPHEADER, list);
    // SAFETY: a live handle, whose list and fields live through the
    // transfer.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let request = String::from_utf8(server.join().unwrap().remove(0)).unwrap();
    assert!(
        request.contains("\r\nTransfer-Encoding: chunked\r\n")
            && !request.contains("Expect")
            && request.ends_with("\r\n\r\n5\r\n01234\r\n0\r\n\r\n"),
        "{request}"
    );
    // SAFETY: a live handle, not used again; then the list it kept.
    unsafe {
        curl_easy_cleanup(c);
        crate::strings::curl_slist_free_all(list);
    }
}

/// What a debug function saw sent of the body.
unsafe extern "C" fn data_out(
    _: *mut CURL,
    kind: ffi::curl_infotype,
    ptr: *mut c_char,
    n: usize,
    data: *mut c_void,
) -> c_int {
    if kind == ffi::CURLINFO_DATA_OUT {
        // SAFETY: the test passes a `Vec` of pieces, and the shim `n`
        // bytes.
        unsafe {
            let pieces = &mut *data.cast::<Vec<Vec<u8>>>();
            pieces.push(core::slice::from_raw_parts(ptr.cast::<u8>(), n).to_vec());
        }
    }
    0
}

/// `CURLOPT_POSTFIELDS` are read where they are, `CURLOPT_POSTFIELDSIZE`
/// of them, piece by piece, and from their start again after a rewind.
#[test]
fn post_fields_are_read_in_place_and_rewound() {
    let fields = c"abcdefghijklmnop";
    let mut pieces: Vec<Vec<u8>> = Vec::new();
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_URL, c"script://a".as_ptr().cast_mut());
    long(c, ffi::CURLOPT_TIMEOUT, 5);
    pointer(c, ffi::CURLOPT_POSTFIELDS, fields.as_ptr().cast_mut());
    // Fewer than there are: what is past them is not read.
    long(c, ffi::CURLOPT_POSTFIELDSIZE, 6);
    long(c, ffi::CURLOPT_VERBOSE, 1);
    function(
        c,
        ffi::CURLOPT_DEBUGFUNCTION,
        data_out as DebugFn as *const (),
    );
    pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut pieces);
    options(c, |o| {
        o.script = Some(
            Script::new(vec![
                Piece::Send(2),
                Piece::Send(2),
                Piece::Rewind,
                Piece::Send(4),
                Piece::SendAll,
            ])
            .unwrap(),
        );
    });
    // SAFETY: a live handle, then not used again.
    let code = unsafe { curl_easy_perform(c) };
    // SAFETY: as above.
    unsafe { curl_easy_cleanup(c) };
    assert_eq!(code, CURLE_OK);
    assert_eq!(pieces, [&b"ab"[..], b"cd", b"abcd", b"ef"]);
}

/// A SOCKS5 proxy's failure is reported as its `CURLproxycode`, and an
/// HTTP proxy's refusal of a tunnel by its code.
#[test]
fn proxy_failures_are_reported_as_in_c() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let mut greeting = [0; 3];
        peer.read_exact(&mut greeting).unwrap();
        // A SOCKS4 version where SOCKS5's belongs.
        peer.write_all(&[4, 0]).unwrap();
        greeting
    });
    let c = curl_easy_init();
    let proxy = std::ffi::CString::new(format!("socks5://127.0.0.1:{port}")).unwrap();
    pointer(
        c,
        ffi::CURLOPT_URL,
        c"http://127.0.0.1:1/".as_ptr().cast_mut(),
    );
    pointer(c, ffi::CURLOPT_PROXY, proxy.as_ptr().cast_mut());
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_PROXY);
    assert_eq!(server.join().unwrap()[0], 5);
    assert_eq!(
        info::<c_long>(c, ffi::CURLINFO_PROXY_ERROR),
        ffi::CURLPX_BAD_VERSION.0 as c_long
    );
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_HTTP_CONNECTCODE), 0);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };

    let (port, server) = serve(vec![
        b"HTTP/1.1 403 No\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ]);
    let c = curl_easy_init();
    let proxy = std::ffi::CString::new(format!("http://127.0.0.1:{port}")).unwrap();
    pointer(
        c,
        ffi::CURLOPT_URL,
        c"http://127.0.0.1:1/".as_ptr().cast_mut(),
    );
    pointer(c, ffi::CURLOPT_PROXY, proxy.as_ptr().cast_mut());
    long(c, ffi::CURLOPT_HTTPPROXYTUNNEL, 1);
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_COULDNT_CONNECT);
    let request = server.join().unwrap().remove(0);
    assert!(request.starts_with(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n"));
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_HTTP_CONNECTCODE), 403);
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_PROXY_ERROR), 0);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

unsafe extern "C" fn lock_into(
    _: *mut CURL,
    data: ffi::curl_lock_data,
    _: ffi::curl_lock_access,
    user: *mut c_void,
) {
    // SAFETY: the test passes its record as the share's user data.
    let seen = unsafe { &*user.cast::<std::sync::Mutex<Vec<c_int>>>() };
    seen.lock().unwrap().push(data.0 as c_int);
}

/// A lock function set alone is called for what is shared, as
/// `Curl_share_lock` calls it, though the share itself is locked only
/// with both functions set (`share_lock_acquire`); the connections are
/// locked at cleanup only when they are shared.
#[test]
fn a_lock_function_alone_locks_what_is_shared() {
    use crate::share::{curl_share_cleanup, curl_share_init, curl_share_setopt};
    let seen = std::sync::Mutex::new(Vec::<c_int>::new());
    let sh = curl_share_init();
    // SAFETY: a live share, an int, a lock function and its data, as the
    // options take.
    unsafe {
        let cookie = ffi::CURL_LOCK_DATA_COOKIE.0 as c_int;
        assert_eq!(
            curl_share_setopt(sh, ffi::CURLSHOPT_SHARE, cookie),
            ffi::CURLSHE_OK
        );
        let lock: ffi::curl_lock_function = Some(lock_into);
        assert_eq!(
            curl_share_setopt(sh, ffi::CURLSHOPT_LOCKFUNC, lock),
            ffi::CURLSHE_OK
        );
        let user = (&raw const seen).cast_mut().cast::<c_void>();
        assert_eq!(
            curl_share_setopt(sh, ffi::CURLSHOPT_USERDATA, user),
            ffi::CURLSHE_OK
        );
    }
    let c = curl_easy_init();
    assert_eq!(pointer(c, ffi::CURLOPT_SHARE, sh), CURLE_OK);
    let line = c"example.com\tFALSE\t/\tFALSE\t0\ta\t1";
    assert_eq!(
        pointer(c, ffi::CURLOPT_COOKIELIST, line.as_ptr().cast_mut()),
        CURLE_OK
    );
    let cookie = ffi::CURL_LOCK_DATA_COOKIE.0 as c_int;
    assert_eq!(std::mem::take(&mut *seen.lock().unwrap()), [cookie]);
    // SAFETY: a live handle, not used again; then the share, held by
    // none.
    unsafe {
        curl_easy_cleanup(c);
        assert_eq!(curl_share_cleanup(sh), ffi::CURLSHE_OK);
    }
    let calls = std::mem::take(&mut *seen.lock().unwrap());
    assert!(calls.iter().all(|&d| d == cookie), "{calls:?}");
}

/// What libtest 751 pays for each of its thousand handles, made, given a
/// URL and VERBOSE, and added to a multi, stays within a budget: no more
/// than C's 3,081 bytes (its `Curl_easy`, 3,056, and the URL), half the
/// 6,000 the test allows. Each hot option every handle carries eats into
/// it; an option most transfers never set belongs in a group made when it
/// is set (`curl_core::options::Cold`).
#[cfg(feature = "debug-hooks")]
#[test]
fn a_handle_costs_no_more_than_cs() {
    use curl_alloc::track::measure;
    const HANDLES: usize = 1000;
    const URL: &CStr = c"https://www.example.com/";
    let m = curl_multi_init();
    let mut handles = Vec::with_capacity(HANDLES);
    let ((), made) = measure(|| {
        for _ in 0..HANDLES {
            let c = curl_easy_init();
            assert!(!c.is_null());
            assert_eq!(
                pointer(c, ffi::CURLOPT_URL, URL.as_ptr().cast_mut()),
                CURLE_OK
            );
            assert_eq!(long(c, ffi::CURLOPT_VERBOSE, 1), CURLE_OK);
            handles.push(c);
        }
    });
    let ((), added) = measure(|| {
        for &c in &handles {
            // SAFETY: a live multi and handle.
            assert_eq!(unsafe { curl_multi_add_handle(m, c) }, CURLM_OK);
        }
    });
    let per = |bytes: i64| bytes / HANDLES as i64;
    let (made_bytes, held) = (per(made.bytes), per(made.bytes + added.bytes));
    assert!(made_bytes <= 2_112, "a new handle holds {made_bytes} bytes");
    assert!(held <= 3_081, "an added handle holds {held} bytes");
    // The `Easy`, the shim's handle, the write adapter and its count, the
    // URL; then the slot, and the multi's tables as they grow.
    assert_eq!(made.allocations, 5 * HANDLES as u64);
    assert!(
        added.allocations <= (HANDLES + HANDLES / 10) as u64,
        "{} allocations",
        added.allocations
    );
    for c in handles {
        // SAFETY: a live handle, not used again.
        unsafe { curl_easy_cleanup(c) };
    }
    // SAFETY: a live multi, not used again.
    assert_eq!(unsafe { curl_multi_cleanup(m) }, CURLM_OK);
}

/// Clearing a string or list option of a group never made allocates
/// nothing, as C's setopt frees nothing and copies nothing for a NULL:
/// the group is made only by a value. Clearing one in a group made
/// still clears it.
#[cfg(feature = "debug-hooks")]
#[test]
fn clearing_an_option_makes_no_group() {
    use curl_alloc::track::measure;
    let cleared = [
        ffi::CURLOPT_USERPWD,
        ffi::CURLOPT_USERNAME,
        ffi::CURLOPT_PASSWORD,
        ffi::CURLOPT_XOAUTH2_BEARER,
        ffi::CURLOPT_PROXY,
        ffi::CURLOPT_PROXYUSERPWD,
        ffi::CURLOPT_PROXYUSERNAME,
        ffi::CURLOPT_PROXYPASSWORD,
        ffi::CURLOPT_PRE_PROXY,
        ffi::CURLOPT_NOPROXY,
        ffi::CURLOPT_HAPROXY_CLIENT_IP,
        ffi::CURLOPT_PROXYHEADER,
        ffi::CURLOPT_NETRC_FILE,
        ffi::CURLOPT_COOKIE,
        ffi::CURLOPT_COOKIEFILE,
    ];
    let c = curl_easy_init();
    for option in cleared {
        let (code, cost) = measure(|| pointer(c, option, ptr::null_mut::<c_char>()));
        assert_eq!(code, CURLE_OK, "{option:?}");
        assert_eq!(cost.allocations, 0, "{option:?} made its group");
    }
    pointer(c, ffi::CURLOPT_PROXY, c"http://p".as_ptr().cast_mut());
    pointer(
        c,
        ffi::CURLOPT_HAPROXY_CLIENT_IP,
        c"1.2.3.4".as_ptr().cast_mut(),
    );
    assert!(options(c, |o| o.proxy.haproxy));
    pointer(c, ffi::CURLOPT_PROXY, ptr::null_mut::<c_char>());
    pointer(c, ffi::CURLOPT_HAPROXY_CLIENT_IP, ptr::null_mut::<c_char>());
    assert_eq!(options(c, |o| o.proxy.url.clone()), None);
    assert_eq!(options(c, |o| o.proxy.haproxy_client_ip.clone()), None);
    assert!(!options(c, |o| o.proxy.haproxy), "the protocol is off");
    // SAFETY: a live handle, not used again.
    // `CURLOPT_COOKIEJAR` turns the jar on whatever it names, as C makes
    // its cookie engine.
    let c = curl_easy_init();
    let (code, cost) = measure(|| pointer(c, ffi::CURLOPT_COOKIEJAR, ptr::null_mut::<c_char>()));
    assert_eq!((code, cost.allocations), (CURLE_OK, 1));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_COOKIELIST` "FLUSH" replaces a jar named long making the
/// allocations it makes for one named short, as C copies no name: std's
/// rename copied each name of 384 bytes or more, the jar's and the one it
/// is written under first, with an allocation that cannot fail, which
/// aborted a torture run.
#[cfg(feature = "debug-hooks")]
#[test]
fn flushes_a_jar_named_long_without_copying_the_name() {
    use curl_alloc::track::measure;
    let dir = std::env::temp_dir().join(format!("curl-shim-long-jar-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let flush = |name: &str| {
        let mut path = format!("{}/", dir.to_str().unwrap());
        while path.len() + name.len() < 400 && name == "long" {
            path.push_str("./");
        }
        path.push_str(name);
        std::fs::write(&path, b"old").unwrap();
        let jar = std::ffi::CString::new(path.as_str()).unwrap();
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_COOKIEJAR, jar.as_ptr().cast_mut());
        // A reload of no file starts the jar.
        pointer(c, ffi::CURLOPT_COOKIEFILE, c"".as_ptr().cast_mut());
        pointer(c, ffi::CURLOPT_COOKIELIST, c"RELOAD".as_ptr().cast_mut());
        let cookie = c".a.com\tTRUE\t/\tFALSE\t0\tname\tvalue";
        pointer(c, ffi::CURLOPT_COOKIELIST, cookie.as_ptr().cast_mut());
        let (set, cost) =
            measure(|| pointer(c, ffi::CURLOPT_COOKIELIST, c"FLUSH".as_ptr().cast_mut()));
        assert_eq!(set, CURLE_OK);
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("\tname\tvalue"), "{name}: {written:?}");
        // SAFETY: a live handle, not used again.
        unsafe { curl_easy_cleanup(c) };
        (path.len(), cost.allocations)
    };
    let (short_len, short) = flush("short");
    let (long_len, long) = flush("long");
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(short_len < 384 && long_len >= 400);
    assert_eq!(long, short, "a long name cost more allocations");
}
