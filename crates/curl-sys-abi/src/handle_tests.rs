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
use curl_core::options::{
    HttpVersion, Method, Options, Progress, Resume, ResumeOffset, UploadSource,
};
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
        (ffi::CURLOPT_PIPEWAIT, |o| o.http.pipewait),
        (ffi::CURLOPT_UNRESTRICTED_AUTH, |o| o.http.unrestricted_auth),
        (ffi::CURLOPT_FILETIME, |o| o.filetime),
        (ffi::CURLOPT_CRLF, |o| o.crlf),
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
    let target = |c| options(c, |o| o.http.custom.target.clone());
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

/// RTSP's strings are copied, and NULL unsets each; a session id set is
/// the application's, from no server's origin.
#[test]
fn rtsp_strings_are_kept() {
    let c = curl_easy_init();
    let kept = |c| {
        options(c, |o| {
            (
                o.small.rtsp_session.as_ref().map(|s| s.id().to_vec()),
                o.small.rtsp_stream_uri.clone(),
                o.small.rtsp_transport.clone(),
            )
        })
    };
    let mut id = *b"s1\0";
    let mut uri = *b"rtsp://h/x\0";
    let mut transport = *b"RTP/AVP\0";
    for (o, p) in [
        (ffi::CURLOPT_RTSP_SESSION_ID, id.as_mut_ptr()),
        (ffi::CURLOPT_RTSP_STREAM_URI, uri.as_mut_ptr()),
        (ffi::CURLOPT_RTSP_TRANSPORT, transport.as_mut_ptr()),
    ] {
        assert_eq!(pointer(c, o, p), CURLE_OK);
    }
    id[0] = b'X';
    uri[0] = b'X';
    transport[0] = b'X';
    std::hint::black_box((&id, &uri, &transport));
    assert_eq!(
        kept(c),
        (
            Some(b"s1".to_vec()),
            Some(b"rtsp://h/x".to_vec()),
            Some(b"RTP/AVP".to_vec())
        )
    );
    let null = ptr::null_mut::<c_char>();
    for o in [
        ffi::CURLOPT_RTSP_SESSION_ID,
        ffi::CURLOPT_RTSP_STREAM_URI,
        ffi::CURLOPT_RTSP_TRANSPORT,
    ] {
        assert_eq!(pointer(c, o, null), CURLE_OK);
    }
    assert_eq!(kept(c), (None, None, None));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// The TLS options as setopt.c takes them: a CA file of NULL is none
/// (not the build's default), a blob without bytes refused; the version
/// range as `Curl_setopt_SSLVERSION` checks it. Two differ from C
/// (DIVERGENCE.md): a `CURL_BLOB_NOCOPY` blob is copied, where C keeps
/// the application's pointer, and a newest version of SSL 2 or 3 is
/// refused, where C takes it and fails the handshake.
#[test]
fn tls_options_are_kept_as_c_keeps_them() {
    use curl_core::options::{CaCache, CaSetting, SslOptions, TlsMaxVersion, TlsMinVersion};
    let c = curl_easy_init();
    let ca = |c, want: CaSetting| options(c, |o| o.tls.options.ca_file == want);
    assert!(ca(c, CaSetting::Default));
    let mut file = *b"ca.pem\0";
    assert_eq!(pointer(c, ffi::CURLOPT_CAINFO, file.as_mut_ptr()), CURLE_OK);
    assert!(ca(c, CaSetting::Given(b"ca.pem".to_vec())));
    let null = ptr::null_mut::<c_char>();
    assert_eq!(pointer(c, ffi::CURLOPT_CAINFO, null), CURLE_OK);
    assert!(ca(c, CaSetting::Unset));
    assert_eq!(pointer(c, ffi::CURLOPT_CAPATH, null), CURLE_OK);
    assert!(options(c, |o| o.tls.options.ca_path == CaSetting::Unset));

    let mut pem = *b"PEM";
    let mut blob = ffi::curl_blob {
        data: pem.as_mut_ptr().cast(),
        len: pem.len(),
        flags: ffi::CURL_BLOB_NOCOPY as c_uint,
    };
    assert_eq!(
        pointer(c, ffi::CURLOPT_CAINFO_BLOB, &raw mut blob),
        CURLE_OK
    );
    pem[0] = b'X';
    std::hint::black_box(&pem);
    let kept = |c| options(c, |o| o.tls.options.ca_blob.clone());
    assert_eq!(kept(c), Some(b"PEM".to_vec()));
    blob.len = 0;
    assert_eq!(
        pointer(c, ffi::CURLOPT_CAINFO_BLOB, &raw mut blob),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    blob.len = 3;
    blob.data = ptr::null_mut();
    assert_eq!(
        pointer(c, ffi::CURLOPT_CAINFO_BLOB, &raw mut blob),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    let none = ptr::null_mut::<ffi::curl_blob>();
    assert_eq!(pointer(c, ffi::CURLOPT_CAINFO_BLOB, none), CURLE_OK);
    assert_eq!(kept(c), None);

    let versions = |c| {
        options(c, |o| {
            (o.tls.options.min_version, o.tls.options.max_version)
        })
    };
    for (value, want) in [
        (
            ffi::CURL_SSLVERSION_TLSv1_1 | ffi::CURL_SSLVERSION_MAX_TLSv1_2,
            Some((TlsMinVersion::Tls1_1, TlsMaxVersion::Tls1_2)),
        ),
        (
            ffi::CURL_SSLVERSION_DEFAULT | ffi::CURL_SSLVERSION_MAX_DEFAULT,
            Some((TlsMinVersion::Tls1_2, TlsMaxVersion::Default)),
        ),
        (
            ffi::CURL_SSLVERSION_TLSv1,
            Some((TlsMinVersion::Tls1, TlsMaxVersion::None)),
        ),
        (
            ffi::CURL_SSLVERSION_TLSv1_3,
            Some((TlsMinVersion::Tls1_3, TlsMaxVersion::None)),
        ),
        (
            ffi::CURL_SSLVERSION_TLSv1_0 | ffi::CURL_SSLVERSION_MAX_TLSv1_0,
            Some((TlsMinVersion::Tls1_0, TlsMaxVersion::Tls1_0)),
        ),
        (
            ffi::CURL_SSLVERSION_TLSv1_0 | ffi::CURL_SSLVERSION_MAX_TLSv1_1,
            Some((TlsMinVersion::Tls1_0, TlsMaxVersion::Tls1_1)),
        ),
        (
            ffi::CURL_SSLVERSION_TLSv1_2 | ffi::CURL_SSLVERSION_MAX_TLSv1_3,
            Some((TlsMinVersion::Tls1_2, TlsMaxVersion::Tls1_3)),
        ),
        (ffi::CURL_SSLVERSION_SSLv3, None),
        (ffi::CURL_SSLVERSION_SSLv2, None),
        (ffi::CURL_SSLVERSION_LAST, None),
        (ffi::CURL_SSLVERSION_MAX_LAST, None),
        // C takes these, and fails the handshake.
        (2 << 16, None),
        (3 << 16, None),
        (-1, None),
    ] {
        let before = versions(c);
        let code = long(c, ffi::CURLOPT_SSLVERSION, value);
        match want {
            Some(v) => {
                assert_eq!(code, CURLE_OK, "{value:#x}");
                assert_eq!(versions(c), v, "{value:#x}");
            }
            None => {
                assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT, "{value:#x}");
                assert_eq!(versions(c), before, "{value:#x}");
            }
        }
    }
    assert_eq!(long(c, ffi::CURLOPT_SSL_OPTIONS, 0x111), CURLE_OK);
    assert_eq!(
        options(c, |o| o.tls.options.ssl_options),
        SslOptions::NATIVE_CA | SslOptions::ALLOW_BEAST
    );
    assert_eq!(long(c, ffi::CURLOPT_SSL_ENABLE_ALPN, 0), CURLE_OK);
    assert!(!options(c, |o| o.tls.options.alpn));
    // A day unless set; -1 for ever, 0 off, past `INT_MAX` taken as it,
    // below -1 refused and the setting kept (`value_range`).
    let cache = |c| options(c, |o| o.tls.options.ca_cache);
    assert_eq!(cache(c), CaCache::For(Duration::from_secs(86400)));
    for (value, want) in [
        (-1, CaCache::Forever),
        (0, CaCache::Off),
        (60, CaCache::For(Duration::from_secs(60))),
        (
            c_long::MAX,
            CaCache::For(Duration::from_secs(c_int::MAX as u64)),
        ),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_CA_CACHE_TIMEOUT, value), CURLE_OK);
        assert_eq!(cache(c), want, "{value}");
    }
    assert_eq!(
        long(c, ffi::CURLOPT_CA_CACHE_TIMEOUT, -2),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(
        cache(c),
        CaCache::For(Duration::from_secs(c_int::MAX as u64)),
        "unchanged"
    );
    // The lists, each copied into its own option.
    type Field = fn(&curl_core::options::TlsOptions) -> &Option<Vec<u8>>;
    let lists: [(CURLoption, &[u8], Field); 4] = [
        (ffi::CURLOPT_SSL_EC_CURVES, b"X25519\0", |t| &t.curves),
        (ffi::CURLOPT_SSL_CIPHER_LIST, b"AES128-SHA\0", |t| {
            &t.ciphers
        }),
        (
            ffi::CURLOPT_TLS13_CIPHERS,
            b"TLS_AES_128_GCM_SHA256\0",
            |t| &t.tls13_ciphers,
        ),
        (ffi::CURLOPT_SSL_SIGNATURE_ALGORITHMS, b"ed25519\0", |t| {
            &t.signature_algorithms
        }),
    ];
    for (option, list, field) in lists {
        let mut list = list.to_vec();
        assert_eq!(pointer(c, option, list.as_mut_ptr()), CURLE_OK);
        assert_eq!(
            options(c, |o| field(&o.tls.options).clone()),
            Some(list[..list.len() - 1].to_vec())
        );
    }
    // The build's CA defaults, whatever was set.
    let given = |i| {
        let mut p: *const c_char = ptr::null();
        // SAFETY: a live handle, and a value of the info's type.
        assert_eq!(unsafe { curl_easy_getinfo(c, i, &raw mut p) }, CURLE_OK);
        p
    };
    let (file, path) = crate::version::ca_defaults();
    // C's CMake build looks for none on Windows (`CURL_CA_BUNDLE` and
    // `CURL_CA_PATH` unset).
    assert_eq!(
        !file.is_null() || !path.is_null(),
        cfg!(not(windows)),
        "the build has a default"
    );
    assert_eq!(given(ffi::CURLINFO_CAINFO), file);
    assert_eq!(given(ffi::CURLINFO_CAPATH), path);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// The strings that say who the client is and how its peer is checked
/// past the chain are copied; NULL takes each away (`Curl_setstropt`).
#[test]
fn the_tls_check_and_identity_strings_are_copied() {
    use curl_core::options::TlsOptions;
    let c = curl_easy_init();
    type Field = fn(&TlsOptions) -> Option<Vec<u8>>;
    let fields: [(CURLoption, Field); 9] = [
        (ffi::CURLOPT_CRLFILE, |t| t.crl_file.clone()),
        (ffi::CURLOPT_PINNEDPUBLICKEY, |t| t.pinned_key.clone()),
        (ffi::CURLOPT_SSLCERT, |t| t.cert.clone()),
        (ffi::CURLOPT_SSLCERTTYPE, |t| t.cert_type.clone()),
        (ffi::CURLOPT_SSLKEY, |t| t.key.clone()),
        (ffi::CURLOPT_SSLKEYTYPE, |t| t.key_type.clone()),
        (ffi::CURLOPT_KEYPASSWD, |t| t.key_password.clone()),
        (ffi::CURLOPT_SSLENGINE, |t| t.engine.clone()),
        (ffi::CURLOPT_ISSUERCERT, |t| t.issuer_cert.clone()),
    ];
    for (o, field) in fields {
        let mut given = *b"given\0";
        assert_eq!(pointer(c, o, given.as_mut_ptr()), CURLE_OK, "{}", o.0);
        given[0] = b'X';
        std::hint::black_box(&given);
        assert_eq!(
            options(c, |opts| field(&opts.tls.options)),
            Some(b"given".to_vec()),
            "{}",
            o.0
        );
        assert_eq!(pointer(c, o, ptr::null_mut::<c_char>()), CURLE_OK);
        assert_eq!(options(c, |opts| field(&opts.tls.options)), None, "{}", o.0);
    }
    // The certificate and key in memory, copied as `CAINFO_BLOB` is.
    type Blob = fn(&TlsOptions) -> Option<Vec<u8>>;
    let blobs: [(CURLoption, Blob); 3] = [
        (ffi::CURLOPT_SSLCERT_BLOB, |t| t.cert_blob.clone()),
        (ffi::CURLOPT_SSLKEY_BLOB, |t| t.key_blob.clone()),
        (ffi::CURLOPT_ISSUERCERT_BLOB, |t| t.issuer_cert_blob.clone()),
    ];
    for (o, field) in blobs {
        let mut pem = *b"PEM";
        let mut blob = ffi::curl_blob {
            data: pem.as_mut_ptr().cast(),
            len: pem.len(),
            flags: ffi::CURL_BLOB_COPY as c_uint,
        };
        assert_eq!(pointer(c, o, &raw mut blob), CURLE_OK, "{}", o.0);
        pem[0] = b'X';
        std::hint::black_box(&pem);
        assert_eq!(
            options(c, |opts| field(&opts.tls.options)),
            Some(b"PEM".to_vec())
        );
        assert_eq!(pointer(c, o, ptr::null_mut::<ffi::curl_blob>()), CURLE_OK);
        assert_eq!(options(c, |opts| field(&opts.tls.options)), None, "{}", o.0);
    }
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_SSL_SESSIONID_CACHE` keeps and resumes TLS sessions unless set
/// to 0, as C reads it.
#[test]
fn the_session_cache_is_off_only_with_0() {
    let c = curl_easy_init();
    let cache = |c| options(c, |o| o.tls.options.session_cache);
    assert!(cache(c), "on by default");
    assert_eq!(long(c, ffi::CURLOPT_SSL_SESSIONID_CACHE, 0), CURLE_OK);
    assert!(!cache(c));
    assert_eq!(long(c, ffi::CURLOPT_SSL_SESSIONID_CACHE, 2), CURLE_OK);
    assert!(cache(c));
    assert_eq!(long(c, ffi::CURLOPT_SSL_SESSIONID_CACHE, 0), CURLE_OK);
    assert!(!cache(c), "off again");
    // SAFETY: the handle made above, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_SSL_VERIFYSTATUS` asks for the stapled status with any value
/// but 0, `CURLOPT_SSLENGINE_DEFAULT` for the engine as the default only
/// with 1, as C reads them; `CURLINFO_SSL_ENGINES` lists OpenSSL's, its
/// built-in `dynamic` among them, in a list the application frees.
#[test]
fn the_engines_are_listed_and_one_made_the_default_with_1() {
    let c = curl_easy_init();
    let status = |c| options(c, |o| o.tls.options.verify_status);
    assert_eq!(long(c, ffi::CURLOPT_SSL_VERIFYSTATUS, 2), CURLE_OK);
    assert!(status(c));
    assert_eq!(long(c, ffi::CURLOPT_SSL_VERIFYSTATUS, 0), CURLE_OK);
    assert!(!status(c));
    let default = |c| options(c, |o| o.tls.options.engine_default);
    assert_eq!(long(c, ffi::CURLOPT_SSLENGINE_DEFAULT, 2), CURLE_OK);
    assert!(!default(c));
    assert_eq!(long(c, ffi::CURLOPT_SSLENGINE_DEFAULT, 1), CURLE_OK);
    assert!(default(c));
    assert_eq!(long(c, ffi::CURLOPT_SSLENGINE_DEFAULT, 0), CURLE_OK);
    assert!(!default(c));
    let list = info::<*mut ffi::curl_slist>(c, ffi::CURLINFO_SSL_ENGINES);
    let mut ids = Vec::new();
    let mut node = list;
    while !node.is_null() {
        // SAFETY: a node of the list the call made, its data a C string.
        let n = unsafe { &*node };
        // SAFETY: as above.
        ids.push(
            unsafe { core::ffi::CStr::from_ptr(n.data) }
                .to_bytes()
                .to_vec(),
        );
        node = n.next;
    }
    // SAFETY: the list the call made, freed once.
    unsafe { crate::strings::curl_slist_free_all(list) };
    assert!(ids.iter().any(|id| id == b"dynamic"), "{ids:?}");
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_CERTINFO` asks for the chain; `CURLINFO_CERTINFO` answers
/// the handle's `struct curl_certinfo`, empty before any is reported.
#[test]
fn the_chain_is_asked_for_and_answered_empty_before_any() {
    let c = curl_easy_init();
    assert!(!options(c, |o| o.tls.certinfo));
    assert_eq!(long(c, ffi::CURLOPT_CERTINFO, 1), CURLE_OK);
    assert!(options(c, |o| o.tls.certinfo));
    let view = info::<*mut ffi::curl_certinfo>(c, ffi::CURLINFO_CERTINFO);
    assert!(!view.is_null());
    // SAFETY: the handle's, alive while it is.
    let view = unsafe { &*view };
    assert_eq!(view.num_of_certs, 0);
    assert!(view.certinfo.is_null());
    assert_eq!(long(c, ffi::CURLOPT_CERTINFO, 0), CURLE_OK);
    assert!(!options(c, |o| o.tls.certinfo));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `curl_global_sslset` knows OpenSSL alone, by id or by name in any
/// case, and lists it.
#[test]
fn the_one_tls_library_is_openssl() {
    let mut avail: *mut *const ffi::curl_ssl_backend = ptr::null_mut();
    // SAFETY: a valid name and list pointer.
    let set = unsafe {
        crate::root::curl_global_sslset(ffi::CURLSSLBACKEND_OPENSSL, ptr::null(), &raw mut avail)
    };
    assert_eq!(set, ffi::CURLSSLSET_OK);
    // SAFETY: the list ends with NULL, each entry a static backend.
    let names: Vec<_> = unsafe {
        let mut names = Vec::new();
        let mut p = avail;
        while !(*p).is_null() {
            names.push(((**p).id.0, CStr::from_ptr((**p).name).to_bytes().to_vec()));
            p = p.add(1);
        }
        names
    };
    assert_eq!(names, [(1, b"openssl".to_vec())]);
    // SAFETY: valid names; no list asked.
    unsafe {
        let by_name =
            |id, name: &CStr| crate::root::curl_global_sslset(id, name.as_ptr(), ptr::null_mut());
        assert_eq!(
            by_name(ffi::curl_sslbackend(99), c"OpenSSL"),
            ffi::CURLSSLSET_OK
        );
        assert_eq!(
            by_name(ffi::curl_sslbackend(99), c"gnutls"),
            ffi::CURLSSLSET_UNKNOWN_BACKEND
        );
        let none =
            crate::root::curl_global_sslset(ffi::curl_sslbackend(99), ptr::null(), ptr::null_mut());
        assert_eq!(none, ffi::CURLSSLSET_UNKNOWN_BACKEND);
    }
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
    let speeds = |c| options(c, |o| (o.flow.max_recv_speed, o.flow.max_send_speed));
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
                o.http.custom.referer.clone(),
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
    // Negotiate kept, as the build claims SPNEGO; C strips it where not.
    assert!(curl_core::version::version().claims("SPNEGO"));
    assert_eq!(auth(c), M::ANY);
    // And reports it as C's bit.
    assert_eq!(
        crate::getinfo::auth_mask(M::NEGOTIATE, crate::getinfo::spnego()),
        4
    );
    assert_eq!(
        crate::getinfo::auth_mask(auth(c), true),
        1 | 2 | 4 | 64 | 128
    );
    // Negotiate reads as C's bit only where claimed; unclaimed, as no
    // method at all.
    assert_eq!(
        crate::getinfo::auth_mask(M::NEGOTIATE | M::BASIC, true),
        4 | 1
    );
    assert_eq!(crate::getinfo::auth_mask(M::NEGOTIATE | M::BASIC, false), 1);
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
    // A `long` of 64 bits: Windows' has 32.
    #[cfg(all(target_pointer_width = "64", not(windows)))]
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
    assert_eq!(version(c), HttpVersion::Any);
    for (v, want) in [
        (ffi::CURL_HTTP_VERSION_1_1, HttpVersion::Http11),
        (ffi::CURL_HTTP_VERSION_2_0, HttpVersion::Http2),
        (ffi::CURL_HTTP_VERSION_2TLS, HttpVersion::Http2Tls),
        (
            ffi::CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE,
            HttpVersion::Http2Prior,
        ),
        (ffi::CURL_HTTP_VERSION_3, HttpVersion::Http3),
        (ffi::CURL_HTTP_VERSION_3ONLY, HttpVersion::Http3Only),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_HTTP_VERSION, v), CURLE_OK, "{v}");
        assert_eq!(version(c), want);
    }
    for (v, code) in [
        (
            ffi::CURL_HTTP_VERSION_3ONLY + 1,
            ffi::CURLE_UNSUPPORTED_PROTOCOL,
        ),
        (-1, CURLE_BAD_FUNCTION_ARGUMENT),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_HTTP_VERSION, v), code, "{v}");
    }
    assert_eq!(version(c), HttpVersion::Http3Only);
    // A stream's weight is 1 to 256; others leave it, and a dependency is
    // taken and not kept.
    let weight = |c| options(c, |o| o.http.stream_weight.map(|w| w.get()));
    for (n, want) in [
        (256, Some(256)),
        (0, Some(256)),
        (257, Some(256)),
        (1, Some(1)),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_STREAM_WEIGHT, n), CURLE_OK, "{n}");
        assert_eq!(weight(c), want, "{n}");
    }
    for o in [ffi::CURLOPT_STREAM_DEPENDS, ffi::CURLOPT_STREAM_DEPENDS_E] {
        assert_eq!(pointer(c, o, ptr::null_mut::<c_void>()), CURLE_OK);
    }
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// Every string option refuses a string longer than C takes, or is not
/// built: none takes it (lib1911). The four lib1911 lets pass are left
/// out here too.
#[test]
fn no_string_option_takes_an_over_long_string() {
    let c = curl_easy_init();
    let mut long = vec![b'A'; 8_000_001];
    long.push(0);
    let mut row = ptr::null();
    let mut seen = 0;
    loop {
        row = crate::easyoption::curl_easy_option_next(row);
        // SAFETY: a row of the static table, or NULL at its end.
        let Some(o) = (unsafe { row.as_ref() }) else {
            break;
        };
        if o.r#type != ffi::CURLOT_STRING {
            continue;
        }
        // SAFETY: the table's names are static C strings.
        let name = unsafe { CStr::from_ptr(o.name) };
        if [
            c"PROXY_TLSAUTH_TYPE",
            c"TLSAUTH_TYPE",
            c"RANDOM_FILE",
            c"EGDSOCKET",
        ]
        .contains(&name)
        {
            continue;
        }
        seen += 1;
        let code = pointer(c, o.id, long.as_mut_ptr());
        assert!(
            [
                CURLE_BAD_FUNCTION_ARGUMENT,
                ffi::CURLE_UNKNOWN_OPTION,
                ffi::CURLE_NOT_BUILT_IN,
                ffi::CURLE_UNSUPPORTED_PROTOCOL,
            ]
            .contains(&code),
            "{name:?} took it: {code:?}"
        );
    }
    assert!(seen > 50, "only {seen} string options");
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
        #[allow(clippy::useless_conversion, reason = "a long is 32 bits on Windows")]
        let bad = curl_off_t::from(bad);
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

/// No body is a value of its own, as C's `opt_no_body`: a setopt that
/// sets a method without saying so leaves it, and it makes the request a
/// HEAD whatever that method is; one that says so clears it. C's tool
/// sets `CURLOPT_UPLOAD` to 0 after `CURLOPT_NOBODY` for every transfer.
#[test]
fn no_body_outlasts_a_method_that_does_not_clear_it() {
    let c = curl_easy_init();
    let method = |c| options(c, |o| o.method);
    assert_eq!(long(c, ffi::CURLOPT_NOBODY, 1), CURLE_OK);
    assert_eq!(long(c, ffi::CURLOPT_UPLOAD, 0), CURLE_OK);
    assert_eq!(method(c), Method::Head, "curl -I");
    let fields = c"a=b";
    assert_eq!(
        pointer(c, ffi::CURLOPT_POSTFIELDS, fields.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(method(c), Method::Head);
    // Without it again, the request is the method set meanwhile.
    assert_eq!(long(c, ffi::CURLOPT_NOBODY, 0), CURLE_OK);
    assert_eq!(method(c), Method::Post);
    for clears in [ffi::CURLOPT_POST, ffi::CURLOPT_HTTPGET, ffi::CURLOPT_UPLOAD] {
        assert_eq!(long(c, ffi::CURLOPT_NOBODY, 1), CURLE_OK);
        assert_eq!(long(c, clears, 1), CURLE_OK);
        assert_ne!(method(c), Method::Head, "{clears:?}");
    }
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
            o.flow.low_speed.map(|l| (l.limit.get(), l.time.get()))
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
    let max = |c| options(c, |o| o.flow.max_filesize.map(|m| m.get()));
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
    assert_eq!(resume(c), Some(Resume::At(ResumeOffset::new(9).unwrap())));
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
        Some(Resume::At(ResumeOffset::new(1 << 40).unwrap()))
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
    // Read as an `unsigned long`, past `UINT_MAX` refused where a `long`
    // reaches it, a negative among them; Windows' 32 bits all fit, -1 as
    // `UINT_MAX`, as C's cast takes it.
    #[cfg(not(windows))]
    for bad in [-1, c_long::from(u32::MAX) + 1] {
        assert_eq!(
            long(c, ffi::CURLOPT_ADDRESS_SCOPE, bad),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    #[cfg(windows)]
    {
        assert_eq!(long(c, ffi::CURLOPT_ADDRESS_SCOPE, -1), CURLE_OK);
        assert_eq!(scope(c), Some(u32::MAX));
        assert_eq!(long(c, ffi::CURLOPT_ADDRESS_SCOPE, 7), CURLE_OK);
    }
    assert_eq!(scope(c), Some(7));
    #[cfg(not(windows))]
    let most = c_long::from(u32::MAX);
    #[cfg(windows)]
    let most = c_long::MAX;
    assert_eq!(long(c, ffi::CURLOPT_ADDRESS_SCOPE, most), CURLE_OK);
    assert_eq!(scope(c), Some(u32::try_from(most).unwrap()));
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
    let upkeep = |c| options(c, |o| o.limits.reuse.upkeep.0);
    assert_eq!(upkeep(c), std::time::Duration::from_secs(60), "C's default");
    assert_eq!(long(c, ffi::CURLOPT_UPKEEP_INTERVAL_MS, 1500), CURLE_OK);
    assert_eq!(upkeep(c), std::time::Duration::from_millis(1500));
    assert_eq!(long(c, ffi::CURLOPT_UPKEEP_INTERVAL_MS, 0), CURLE_OK);
    assert_eq!(upkeep(c), std::time::Duration::ZERO);
    assert_eq!(
        long(c, ffi::CURLOPT_UPKEEP_INTERVAL_MS, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(upkeep(c), std::time::Duration::ZERO);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// The redirect, wait and condition options, checked as setopt.c checks
/// them: refused out of range, clamped where C clamps.
#[test]
fn http_ranges_are_checked_as_in_c() {
    use curl_core::options::{Condition, Follow, PostRedir, TimeCondition};
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
    let redirects = |c| options(c, |o| o.http.max_redirects.get());
    assert_eq!(redirects(c), Some(30), "C's default");
    for (v, want) in [
        (-1, None),
        (0, Some(0)),
        (5, Some(5)),
        (0x8000, Some(0x7fff)),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_MAXREDIRS, v), CURLE_OK);
        assert_eq!(redirects(c), want, "{v}");
    }
    assert_eq!(long(c, ffi::CURLOPT_MAXREDIRS, -2), bad);
    assert_eq!(redirects(c), Some(0x7fff), "unchanged");
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
    let wait = |c| options(c, |o| o.http.continue_wait.get());
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

/// The resolver library's options are kept where c-ares answers names,
/// and not built in where the threaded resolver does, as C's build
/// without c-ares answers.
#[test]
fn the_resolver_library_options_are_kept_with_c_ares_alone() {
    let c = curl_easy_init();
    let values = [
        (ffi::CURLOPT_DNS_SERVERS, c"127.0.0.1"),
        (ffi::CURLOPT_DNS_INTERFACE, c"lo"),
        (ffi::CURLOPT_DNS_LOCAL_IP4, c"127.0.0.2"),
        (ffi::CURLOPT_DNS_LOCAL_IP6, c"::1"),
    ];
    let set = values.map(|(o, v)| pointer(c, o, v.as_ptr().cast_mut()));
    let threaded = cfg!(feature = "threaded-resolver");
    let code = if threaded {
        ffi::CURLE_NOT_BUILT_IN
    } else {
        CURLE_OK
    };
    assert_eq!(set, [code; 4]);
    let kept = options(c, |o| {
        [
            o.dns.servers.clone(),
            o.dns.interface.clone(),
            o.dns.local_ip4.clone(),
            o.dns.local_ip6.clone(),
        ]
    });
    let want = values.map(|(_, v)| (!threaded).then(|| v.to_bytes().to_vec()));
    assert_eq!(kept, want);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// The scheme options set what a URL and a redirect may use: a refused
/// list keeps the one before, NULL brings back the default, and the
/// deprecated masks take C's bits.
#[test]
fn scheme_options_reach_the_transfer() {
    use curl_core::options::{ColdGroup, Protocols, Schemes};
    let c = curl_easy_init();
    let schemes = |c| options(c, |o| (o.schemes.allowed, o.schemes.redirect));
    let defaults = (Schemes::NONE.allowed, Schemes::NONE.redirect);
    assert_eq!(schemes(c), defaults);
    let file = Protocols::of(&["file"]).unwrap();
    let http = Protocols::of(&["http"]).unwrap();
    for (o, list, want) in [
        (ffi::CURLOPT_PROTOCOLS_STR, c"file", CURLE_OK),
        (ffi::CURLOPT_REDIR_PROTOCOLS_STR, c"HTTP", CURLE_OK),
        (
            ffi::CURLOPT_PROTOCOLS_STR,
            c"smb",
            ffi::CURLE_UNSUPPORTED_PROTOCOL,
        ),
        (
            ffi::CURLOPT_REDIR_PROTOCOLS_STR,
            c",",
            CURLE_BAD_FUNCTION_ARGUMENT,
        ),
    ] {
        assert_eq!(pointer(c, o, list.as_ptr().cast_mut()), want, "{list:?}");
    }
    assert_eq!(schemes(c), (file, http));
    let null = ptr::null_mut::<c_char>();
    assert_eq!(pointer(c, ffi::CURLOPT_PROTOCOLS_STR, null), CURLE_OK);
    assert_eq!(schemes(c), (Protocols::ALL, http));
    assert_eq!(pointer(c, ffi::CURLOPT_REDIR_PROTOCOLS_STR, null), CURLE_OK);
    assert_eq!(schemes(c), defaults);
    assert_eq!(
        long(c, ffi::CURLOPT_PROTOCOLS, ffi::CURLPROTO_FILE),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_REDIR_PROTOCOLS, 0), CURLE_OK);
    assert_eq!(schemes(c), (file, Protocols::NONE));
    // An http URL is then refused before anything connects.
    let url = c"http://127.0.0.1:1/";
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    // SAFETY: a live handle.
    let performed = unsafe { curl_easy_perform(c) };
    assert_eq!(performed, ffi::CURLE_UNSUPPORTED_PROTOCOL);
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
                o.http.custom.method.clone(),
                k.send.clone(),
                k.files.iter().map(<[u8]>::to_vec).collect::<Vec<_>>(),
                k.save_to().map(<[u8]>::to_vec),
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
    let urls = |c| {
        // SAFETY: a live handle.
        let curlu = unsafe { easy::handle(c) }
            .expect("a live handle")
            .set
            .get()
            .curlu;
        let o = options(c, |o| (o.url().is_some(), o.shared_url().is_some()));
        (o, curlu.is_null())
    };
    assert_eq!(urls(c), ((false, false), false), "in the URL's place");
    assert_eq!(pointer(c, ffi::CURLOPT_CURLU, null), CURLE_OK);
    assert_eq!(urls(c), ((false, false), true));
    // SAFETY: made above, and the handle no longer names it.
    unsafe { crate::url::curl_url_cleanup(u) };
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    assert!(
        !jar_path.exists(),
        "no jar is written once its name is gone"
    );
}

/// `CURLOPT_CURLU` keeps the pointer it is given and reads nothing
/// through it until a transfer starts, as C's `set.uh`: libtest 1521
/// passes the address of a local that is no URL handle and never
/// performs. A copy of the handle keeps the pointer, a reset forgets it.
#[test]
fn a_url_handle_is_not_read_until_a_transfer_starts() {
    // Small values, which a reference count read from them would change
    // without overflowing; room past a URL handle's size, wherever in it
    // the count lies.
    let mut object = [7usize; 128];
    assert!(size_of_val(&object) > 4 * size_of::<curl_core::url::UrlCell>());
    let p = (&raw mut object).cast::<c_void>();
    let c = curl_easy_init();
    assert_eq!(pointer(c, ffi::CURLOPT_CURLU, p), CURLE_OK);
    assert_eq!(object, [7; 128], "nothing written through the pointer");
    // SAFETY: a live handle.
    let d = unsafe { easy::curl_easy_duphandle(c) };
    assert!(!d.is_null());
    assert_eq!(object, [7; 128], "nothing written through the copy's");
    for h in [c, d] {
        // SAFETY: a live handle.
        let easy = unsafe { easy::handle(h) }.expect("a live handle");
        assert_eq!(easy.set.get().curlu, p.cast::<ffi::CURLU>().cast_const());
    }
    // SAFETY: a live handle.
    unsafe { crate::easy::curl_easy_reset(d) };
    // SAFETY: as above.
    let easy = unsafe { easy::handle(d) }.expect("a live handle");
    assert!(easy.set.get().curlu.is_null(), "a reset forgets it");
    // SAFETY: live handles, not used again.
    unsafe {
        curl_easy_cleanup(d);
        curl_easy_cleanup(c);
    }
    assert_eq!(object, [7; 128], "nothing freed through it");
}

/// Setting `CURLOPT_CURLU`, even to NULL, forgets the URL the last
/// transfer reported: `CURLINFO_EFFECTIVE_URL` is empty until the next
/// starts, as C frees `state.url`.
#[test]
fn a_url_handle_set_forgets_the_effective_url() {
    let (path, url) = file("curlu-effective", b"x");
    let effective = |c| {
        let url = info::<*const c_char>(c, ffi::CURLINFO_EFFECTIVE_URL);
        // SAFETY: getinfo gives a string that lives while the handle does.
        unsafe { CStr::from_ptr(url) }.to_owned()
    };
    let u = crate::url::curl_url();
    let c = curl_easy_init();
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    for given in [u, ptr::null_mut()] {
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        // SAFETY: a live handle.
        assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
        assert_eq!(effective(c), url);
        assert_eq!(pointer(c, ffi::CURLOPT_CURLU, given), CURLE_OK);
        assert_eq!(effective(c), c"", "{given:?}");
        // The URL set after it is the next transfer's, if none is.
        pointer(c, ffi::CURLOPT_CURLU, ptr::null_mut::<c_void>());
    }
    // SAFETY: live handles, not used again.
    unsafe {
        curl_easy_cleanup(c);
        crate::url::curl_url_cleanup(u);
    }
    std::fs::remove_file(path).unwrap();

    // Set from the transfer's own write function, it forgets the URL of
    // the transfer under way, which no later request sets again.
    unsafe extern "C" fn forgetting(
        _: *mut c_char,
        size: usize,
        n: usize,
        c: *mut c_void,
    ) -> usize {
        // SAFETY: the handle, live while its transfer runs.
        let set =
            unsafe { curl_easy_setopt(c.cast(), ffi::CURLOPT_CURLU, ptr::null_mut::<c_void>()) };
        assert_eq!(set, CURLE_OK);
        size * n
    }
    let (path, url) = file("curlu-effective-cb", b"x");
    let c = curl_easy_init();
    function(
        c,
        ffi::CURLOPT_WRITEFUNCTION,
        forgetting as WriteFn as *const (),
    );
    pointer(c, ffi::CURLOPT_WRITEDATA, c);
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    assert_eq!(effective(c), c"", "set from a callback");
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    std::fs::remove_file(path).unwrap();
}

/// A refused `CURLOPT_URL` leaves the URL set before it as the one
/// reported, as C's setopt points `state.url` at `STRING_SET_URL`
/// whether the new string was taken or not: none if none was set, and
/// after a transfer the URL set, not the one the transfer ended at.
#[test]
fn a_url_refused_leaves_the_last_one_set_as_the_effective_url() {
    let effective = |c| {
        let url = info::<*const c_char>(c, ffi::CURLINFO_EFFECTIVE_URL);
        // SAFETY: getinfo gives a string that lives while the handle does.
        unsafe { CStr::from_ptr(url) }.to_owned()
    };
    let long_url = {
        let mut text = b"http://127.0.0.1/".to_vec();
        // One past `CURL_MAX_INPUT_LENGTH`.
        text.resize(8_000_001, b'a');
        std::ffi::CString::new(text).unwrap()
    };
    let refused = |c| {
        let set = pointer(c, ffi::CURLOPT_URL, long_url.as_ptr().cast_mut());
        assert_eq!(set, CURLE_BAD_FUNCTION_ARGUMENT);
    };
    let c = curl_easy_init();
    refused(c);
    assert_eq!(effective(c), c"", "none set");
    pointer(
        c,
        ffi::CURLOPT_URL,
        c"http://127.0.0.1:1/a".as_ptr().cast_mut(),
    );
    refused(c);
    assert_eq!(effective(c), c"http://127.0.0.1:1/a", "before a transfer");

    // After a transfer that went elsewhere, the URL set, not the one
    // the transfer ended at.
    let (port, server) = serve(vec![
        b"HTTP/1.1 302 There\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]);
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/a")).unwrap();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    long(c, ffi::CURLOPT_FOLLOWLOCATION, 1);
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    server.join().unwrap();
    let there = format!("http://127.0.0.1:{port}/b");
    assert_eq!(effective(c).to_str().unwrap(), there);
    refused(c);
    assert_eq!(effective(c), url, "after a transfer");

    // After a transfer from a URL handle, its URL, which C's transfer
    // keeps as the text one (`Curl_pretransfer`).
    let (path, file_url) = file("url-refused-curlu", b"x");
    let u = crate::url::curl_url();
    // SAFETY: a live URL handle and a C string.
    let rc = unsafe { crate::url::curl_url_set(u, ffi::CURLUPART_URL, file_url.as_ptr(), 0) };
    assert_eq!(rc, ffi::CURLUE_OK);
    assert_eq!(pointer(c, ffi::CURLOPT_CURLU, u), CURLE_OK);
    // SAFETY: a live handle, its URL handle live through the transfer.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    refused(c);
    assert_eq!(effective(c), file_url, "after a URL handle's transfer");
    // SAFETY: live handles, not used again.
    unsafe {
        curl_easy_cleanup(c);
        crate::url::curl_url_cleanup(u);
    }
    std::fs::remove_file(path).unwrap();
}

/// `CURLOPT_URL` is the URL reported until a transfer starts, as C's
/// setopt points `state.url` at it: without its credentials, as getinfo
/// reads it back, or its error if it does not read back; after a
/// transfer, in place of that transfer's; NULL reports none; and set from
/// a transfer's callback, in place of the URL under way.
#[test]
fn a_url_set_is_the_effective_url_until_a_transfer_starts() {
    let effective = |c| {
        let mut url: *const c_char = c"untouched".as_ptr();
        // SAFETY: a live handle, and a string pointer for the info.
        let code = unsafe { curl_easy_getinfo(c, ffi::CURLINFO_EFFECTIVE_URL, &mut url) };
        // SAFETY: getinfo gives NULL or a string that lives while the
        // handle does.
        let text = (!url.is_null()).then(|| unsafe { CStr::from_ptr(url) }.to_owned());
        (code, text)
    };
    let shown = |text: &CStr| (CURLE_OK, Some(text.to_owned()));
    let set = |c, url: &CStr| pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    let c = curl_easy_init();
    assert_eq!(set(c, c"http://user:secret@127.0.0.1:1/a"), CURLE_OK);
    assert_eq!(effective(c), shown(c"http://127.0.0.1:1/a"));
    assert_eq!(set(c, c"http://[invalid/"), CURLE_OK);
    assert_eq!(effective(c), (ffi::CURLE_URL_MALFORMAT, None));
    // Read back as getinfo is asked, `CURLOPT_PATH_AS_IS` as it is then.
    assert_eq!(set(c, c"http://127.0.0.1:1/a/../b"), CURLE_OK);
    assert_eq!(effective(c), shown(c"http://127.0.0.1:1/b"));
    assert_eq!(long(c, ffi::CURLOPT_PATH_AS_IS, 1), CURLE_OK);
    assert_eq!(effective(c), shown(c"http://127.0.0.1:1/a/../b"));
    assert_eq!(long(c, ffi::CURLOPT_PATH_AS_IS, 0), CURLE_OK);
    // SAFETY: a live handle.
    unsafe { crate::easy::curl_easy_reset(c) };
    assert_eq!(effective(c), shown(c""), "after a reset");
    let (path, url) = file("url-effective", b"x");
    let (then_path, then) = file("url-effective-then", b"x");
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    assert_eq!(set(c, &url), CURLE_OK);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    assert_eq!(set(c, &then), CURLE_OK);
    assert_eq!(effective(c), shown(&then), "after a transfer");
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    assert_eq!(effective(c), shown(c""), "none");

    // Set from the transfer's own write function, it is reported in
    // place of the URL under way, which no later request sets again.
    struct Swap {
        c: *mut CURL,
        to: *const c_char,
    }
    unsafe extern "C" fn swapping(_: *mut c_char, size: usize, n: usize, s: *mut c_void) -> usize {
        // SAFETY: a `Swap` live through the transfer.
        let s = unsafe { &*s.cast::<Swap>() };
        // SAFETY: the handle, live while its transfer runs, and a string.
        let set = unsafe { curl_easy_setopt(s.c, ffi::CURLOPT_URL, s.to) };
        assert_eq!(set, CURLE_OK);
        size * n
    }
    let mut swap = Swap {
        c,
        to: then.as_ptr(),
    };
    function(
        c,
        ffi::CURLOPT_WRITEFUNCTION,
        swapping as WriteFn as *const (),
    );
    pointer(c, ffi::CURLOPT_WRITEDATA, &raw mut swap);
    assert_eq!(set(c, &url), CURLE_OK);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    assert_eq!(effective(c), shown(&then), "set from a callback");
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    assert_eq!(set(c, &url), CURLE_OK);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    // SAFETY: a live handle.
    unsafe { crate::easy::curl_easy_reset(c) };
    assert_eq!(effective(c), shown(c""), "after a transfer and a reset");
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    for path in [path, then_path] {
        std::fs::remove_file(path).unwrap();
    }
}

/// A handle holds only the pointer `CURLOPT_CURLU` gave it, never the
/// URL handle itself: after a transfer, after a copy of the handle, and
/// after one added and taken out unstarted, the application's
/// `curl_url_cleanup` frees it at once, as C's does.
#[cfg(feature = "debug-hooks")]
#[test]
fn a_url_handle_is_freed_by_its_cleanup_alone() {
    use curl_alloc::track::measure;
    let (path, url) = file("curlu-freed", b"x");
    let c = curl_easy_init();
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    let fresh = || {
        let u = crate::url::curl_url();
        // SAFETY: a live URL handle and a C string.
        let rc = unsafe { crate::url::curl_url_set(u, ffi::CURLUPART_URL, url.as_ptr(), 0) };
        assert_eq!(rc, ffi::CURLUE_OK);
        assert_eq!(pointer(c, ffi::CURLOPT_CURLU, u), CURLE_OK);
        u
    };
    let freed = |u, what: &str| {
        // SAFETY: a live URL handle, which the handle no longer reads.
        let ((), m) = measure(|| unsafe { crate::url::curl_url_cleanup(u) });
        assert!(
            m.bytes < 0,
            "{what}: the URL handle is freed ({} bytes)",
            m.bytes
        );
    };
    let u = fresh();
    // SAFETY: a live handle, its URL handle live through the transfer.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    freed(u, "after a transfer");

    let u = fresh();
    // SAFETY: as above.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    // SAFETY: a live handle.
    let d = unsafe { easy::curl_easy_duphandle(c) };
    assert!(!d.is_null());
    freed(u, "after a copy of the handle");

    let u = fresh();
    let multi = curl_multi_init();
    // SAFETY: a live multi and handle.
    unsafe {
        assert_eq!(curl_multi_add_handle(multi, c), CURLM_OK);
        assert_eq!(curl_multi_remove_handle(multi, c), CURLM_OK);
    }
    freed(u, "after an unstarted transfer");
    // SAFETY: live handles, not used again.
    unsafe {
        assert_eq!(curl_multi_cleanup(multi), CURLM_OK);
        curl_easy_cleanup(d);
        curl_easy_cleanup(c);
    }
    std::fs::remove_file(path).unwrap();
}

/// A URL handle changed after it is set is read as it is when the
/// transfer starts: by perform, and by a multi when it first drives the
/// transfer, not when it is added (`Curl_pretransfer`).
#[test]
fn a_url_handle_is_read_as_the_transfer_starts() {
    let (first_path, first) = file("curlu-first", b"first");
    let (then_path, then) = file("curlu-then", b"then");
    let u = crate::url::curl_url();
    let set_url = |url: &CStr| {
        // SAFETY: a live URL handle and a C string.
        let rc = unsafe { crate::url::curl_url_set(u, ffi::CURLUPART_URL, url.as_ptr(), 0) };
        assert_eq!(rc, ffi::CURLUE_OK);
    };
    let effective = |c| {
        let url = info::<*const c_char>(c, ffi::CURLINFO_EFFECTIVE_URL);
        // SAFETY: getinfo gives a string that lives while the handle does.
        unsafe { CStr::from_ptr(url) }.to_owned()
    };
    let c = curl_easy_init();
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    set_url(&first);
    assert_eq!(pointer(c, ffi::CURLOPT_CURLU, u), CURLE_OK);
    set_url(&then);
    // SAFETY: a live handle, its URL handle live through the transfer.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    assert_eq!(effective(c), then);

    set_url(&first);
    let multi = curl_multi_init();
    // SAFETY: a live multi and handle, the URL handle live through the
    // transfer, then both let go of.
    unsafe {
        assert_eq!(curl_multi_add_handle(multi, c), CURLM_OK);
        set_url(&then);
        let mut running = 1;
        let mut rounds = 0;
        while running > 0 {
            assert_eq!(curl_multi_perform(multi, &raw mut running), CURLM_OK);
            rounds += 1;
            assert!(rounds < 100, "the transfer never ends");
        }
        assert_eq!(effective(c), then);
        assert_eq!(curl_multi_remove_handle(multi, c), CURLM_OK);
    }
    // Another URL handle, set once the transfer is added and before it
    // starts, is the one it reads.
    let other = crate::url::curl_url();
    // SAFETY: a live URL handle and a C string.
    let rc = unsafe { crate::url::curl_url_set(other, ffi::CURLUPART_URL, first.as_ptr(), 0) };
    assert_eq!(rc, ffi::CURLUE_OK);
    // SAFETY: as above.
    unsafe {
        assert_eq!(curl_multi_add_handle(multi, c), CURLM_OK);
        assert_eq!(pointer(c, ffi::CURLOPT_CURLU, other), CURLE_OK);
        let mut running = 1;
        let mut rounds = 0;
        while running > 0 {
            assert_eq!(curl_multi_perform(multi, &raw mut running), CURLM_OK);
            rounds += 1;
            assert!(rounds < 100, "the transfer never ends");
        }
        let mut queued = 0;
        let msg = curl_multi_info_read(multi, &raw mut queued);
        assert!(!msg.is_null());
        assert_eq!((*msg).data.result, CURLE_OK);
        assert_eq!(effective(c), first);
        assert_eq!(curl_multi_remove_handle(multi, c), CURLM_OK);
        assert_eq!(curl_multi_cleanup(multi), CURLM_OK);
        curl_easy_cleanup(c);
        crate::url::curl_url_cleanup(other);
        crate::url::curl_url_cleanup(u);
    }
    for path in [first_path, then_path] {
        std::fs::remove_file(path).unwrap();
    }
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
    // RTSP's sequence numbers are the handle's: below 0 is refused, past
    // `INT_MAX` taken as it.
    let cseq = |c, info| {
        let mut v: c_long = -1;
        // SAFETY: a live handle and a `long` to write.
        assert_eq!(unsafe { curl_easy_getinfo(c, info, &raw mut v) }, CURLE_OK);
        v
    };
    assert_eq!(long(c, ffi::CURLOPT_RTSP_CLIENT_CSEQ, 7), CURLE_OK);
    assert_eq!(cseq(c, ffi::CURLINFO_RTSP_CLIENT_CSEQ), 7);
    // Where a `long` reaches past `INT_MAX`: Windows' does not.
    #[cfg(not(windows))]
    {
        assert_eq!(
            long(c, ffi::CURLOPT_RTSP_SERVER_CSEQ, c_long::from(i32::MAX) + 1),
            CURLE_OK
        );
        assert_eq!(
            cseq(c, ffi::CURLINFO_RTSP_SERVER_CSEQ),
            c_long::from(i32::MAX)
        );
    }
    assert_eq!(
        long(c, ffi::CURLOPT_RTSP_CLIENT_CSEQ, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(cseq(c, ffi::CURLINFO_RTSP_CLIENT_CSEQ), 7);
    assert_eq!(cseq(c, ffi::CURLINFO_RTSP_CSEQ_RECV), 0);
    // A request of C's eleven, counted from 1.
    let request = |c| options(c, |o| o.small.rtsp_request);
    assert_eq!(long(c, ffi::CURLOPT_RTSP_REQUEST, 11), CURLE_OK);
    assert_eq!(request(c), curl_core::options::RtspRequest::Receive);
    for bad in [0, 12, -1] {
        assert_eq!(
            long(c, ffi::CURLOPT_RTSP_REQUEST, bad),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    assert_eq!(request(c), curl_core::options::RtspRequest::Receive);
    // TFTP's block size is brought within its bounds; below 0 is refused.
    let blksize = |c| options(c, |o| o.small.tftp_blksize.map(|b| b.get()));
    assert_eq!(long(c, ffi::CURLOPT_TFTP_BLKSIZE, 7), CURLE_OK);
    assert_eq!(blksize(c), Some(8));
    assert_eq!(long(c, ffi::CURLOPT_TFTP_BLKSIZE, 100_000), CURLE_OK);
    assert_eq!(blksize(c), Some(65464));
    assert_eq!(
        long(c, ffi::CURLOPT_TFTP_BLKSIZE, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(blksize(c), Some(65464));
    assert_eq!(long(c, ffi::CURLOPT_TFTP_NO_OPTIONS, 1), CURLE_OK);
    assert!(options(c, |o| o.small.tftp_no_options));
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

/// The URL a refused transfer reports is the one given, read back as
/// C's `effective_url` reads it: without its credentials whatever its
/// scheme, and withheld, NULL and the parse's error, when it does not
/// read back at all (lib1990).
#[test]
fn a_refused_url_is_reported_without_its_credentials() {
    let c = curl_easy_init();
    let effective = |c| {
        let mut url: *const c_char = c"untouched".as_ptr();
        // SAFETY: a live handle, and a string pointer for the info.
        let code = unsafe { curl_easy_getinfo(c, ffi::CURLINFO_EFFECTIVE_URL, &mut url) };
        // SAFETY: getinfo gives NULL or a string that lives while the
        // handle does.
        let text = (!url.is_null()).then(|| unsafe { CStr::from_ptr(url) }.to_owned());
        (code, text)
    };
    let set = |c, url: &CStr| pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    assert_eq!(set(c, c"http://user:secret@[invalid/"), CURLE_OK);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_URL_MALFORMAT);
    assert_eq!(effective(c), (ffi::CURLE_URL_MALFORMAT, None));
    assert_eq!(set(c, c"nosuch://user:secret@example.com/x"), CURLE_OK);
    // SAFETY: a live handle.
    let performed = unsafe { curl_easy_perform(c) };
    assert_eq!(performed, ffi::CURLE_UNSUPPORTED_PROTOCOL);
    assert_eq!(
        effective(c),
        (CURLE_OK, Some(c"nosuch://example.com/x".to_owned()))
    );
    // A URL handle may allow spaces; getinfo's reading back does not.
    let u = crate::url::curl_url();
    let spaced = c"http://127.0.0.1:1/ /with/ space";
    // SAFETY: a live URL handle and a C string.
    let set_u = unsafe {
        crate::url::curl_url_set(
            u,
            ffi::CURLUPART_URL,
            spaced.as_ptr(),
            ffi::CURLU_ALLOW_SPACE as _,
        )
    };
    assert_eq!(set_u, ffi::CURLUE_OK);
    assert_eq!(pointer(c, ffi::CURLOPT_CURLU, u), CURLE_OK);
    // SAFETY: a live handle.
    let performed = unsafe { curl_easy_perform(c) };
    assert_eq!(performed, ffi::CURLE_COULDNT_CONNECT);
    assert_eq!(effective(c), (ffi::CURLE_URL_MALFORMAT, None));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    // SAFETY: a live URL handle the easy handle no longer uses.
    unsafe { crate::url::curl_url_cleanup(u) };
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
    assert!(info::<*const c_char>(c, ffi::CURLINFO_SCHEME).is_null());
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
    // The scheme's name, one string for every handle, as C's tool
    // compares its address (`proto_token`).
    let scheme = info::<*const c_char>(c, ffi::CURLINFO_SCHEME);
    // SAFETY: getinfo gives a string that lives as long as the process.
    assert_eq!(unsafe { CStr::from_ptr(scheme) }, c"file");
    assert_eq!(info::<*const c_char>(c, ffi::CURLINFO_SCHEME), scheme);
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
    // No FTP transfer, no entry path.
    assert!(info::<*const c_char>(c, ffi::CURLINFO_FTP_ENTRY_PATH).is_null());
    // An info not answered yet, and one of no type.
    let mut v: c_long = 0;
    // SAFETY: a live handle and a `long` to write.
    unsafe {
        let mut id: *const c_char = c"x".as_ptr();
        assert_eq!(
            curl_easy_getinfo(c, ffi::CURLINFO_RTSP_SESSION_ID, &raw mut id),
            CURLE_OK
        );
        assert!(id.is_null(), "no session yet");
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
                    #[cfg(unix)]
                    assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
                    #[cfg(windows)]
                    assert_eq!(libc::pipe(fds.as_mut_ptr(), 64, libc::O_BINARY), 0);
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
    // The UCRT's `fseek` takes a pipe's stream back without complaint,
    // so the rewind goes, as C's `fseek` there goes.
    #[cfg(windows)]
    assert_eq!(failed, (CURLE_OK, 0, String::new()));
    #[cfg(unix)]
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

/// A stream the read and seek functions share: the seek's answer, the
/// offsets it was asked for, and how many reads there were.
struct Stream {
    feed: Feed,
    answer: c_int,
    asked: Vec<(curl_off_t, c_int)>,
    reads: u32,
}

unsafe extern "C" fn stream_read(
    buf: *mut c_char,
    size: usize,
    n: usize,
    data: *mut c_void,
) -> usize {
    // SAFETY: the test passes a `Stream`, whose `Feed` comes first.
    let s = unsafe { &mut *data.cast::<Stream>() };
    s.reads += 1;
    // SAFETY: as `read` is called.
    unsafe { read(buf, size, n, (&raw mut s.feed).cast()) }
}

unsafe extern "C" fn stream_seek(data: *mut c_void, offset: curl_off_t, origin: c_int) -> c_int {
    // SAFETY: the test passes a `Stream`.
    let s = unsafe { &mut *data.cast::<Stream>() };
    s.asked.push((offset, origin));
    if s.answer == ffi::CURL_SEEKFUNC_OK {
        s.feed.left.drain(..usize::try_from(offset).unwrap());
    }
    s.answer
}

/// A body resumed is moved to its point by the seek function: one that
/// cannot seek, or no seek function, has the bytes before read instead,
/// so that the bytes after the point are the ones sent, and any other
/// answer fails the transfer (`ftp_state_ul_setup`). With no seek
/// function C seeks nothing and reads nothing before the point, and sends
/// the stream's first bytes as the ones after it (DIVERGENCE.md).
#[test]
fn a_resumed_body_asks_the_seek_function() {
    let run = |answer: Option<c_int>| {
        let mut s = Stream {
            feed: Feed {
                left: (0..100u8).collect(),
                answer: None,
            },
            answer: answer.unwrap_or(-1),
            asked: Vec::new(),
            reads: 0,
        };
        let mut buf = [0 as c_char; 256];
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, c"script://a".as_ptr().cast_mut());
        long(c, ffi::CURLOPT_UPLOAD, 1);
        long(c, ffi::CURLOPT_TIMEOUT, 5);
        pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
        options(c, |o| {
            o.script = Some(Script::new(vec![Piece::Resume(60), Piece::SendAll]).unwrap());
        });
        type StreamRead = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;
        function(
            c,
            ffi::CURLOPT_READFUNCTION,
            stream_read as StreamRead as *const (),
        );
        pointer(c, ffi::CURLOPT_READDATA, &raw mut s);
        if answer.is_some() {
            function(
                c,
                ffi::CURLOPT_SEEKFUNCTION,
                stream_seek as SeekFn as *const (),
            );
            pointer(c, ffi::CURLOPT_SEEKDATA, &raw mut s);
        }
        // SAFETY: a live handle, then not used again.
        let code = unsafe { curl_easy_perform(c) };
        let sent = info::<curl_off_t>(c, ffi::CURLINFO_SIZE_UPLOAD_T);
        // SAFETY: as above.
        unsafe { curl_easy_cleanup(c) };
        // SAFETY: the shim ends what it writes with a zero byte.
        let why = unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_str()
            .unwrap()
            .to_owned();
        (code, why, s.asked, s.reads, s.feed.left.len(), sent)
    };
    let set = libc::SEEK_SET;
    // Moved: the reads give the rest, then the end.
    assert_eq!(
        run(Some(ffi::CURL_SEEKFUNC_OK)),
        (CURLE_OK, String::new(), vec![(60, set)], 2, 0, 40)
    );
    // Read to the point, then the rest, then the end.
    assert_eq!(
        run(Some(ffi::CURL_SEEKFUNC_CANTSEEK)),
        (CURLE_OK, String::new(), vec![(60, set)], 3, 0, 40)
    );
    assert_eq!(run(None), (CURLE_OK, String::new(), vec![], 3, 0, 40));
    let failed = (
        ffi::CURLE_FTP_COULDNT_USE_REST,
        "Could not seek stream".to_owned(),
        vec![(60, set)],
        0,
        100,
        0,
    );
    assert_eq!(run(Some(ffi::CURL_SEEKFUNC_FAIL)), failed);
    assert_eq!(run(Some(7)), failed);
}

/// The null device, a file that is not regular.
#[cfg(unix)]
const DEV_NULL: &std::ffi::CStr = c"/dev/null";
#[cfg(windows)]
const DEV_NULL: &std::ffi::CStr = c"NUL";

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
                What::DevNull => curl_mime_filedata(p, DEV_NULL.as_ptr()),
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

/// A part's read function pausing after its headers, in the fill that
/// gave them, is not called again until the transfer is unpaused: the
/// pause is kept in the part and given by the next read
/// (`lastreadstatus`), as the reference build does.
#[test]
fn a_part_s_pause_after_its_headers_holds_until_unpaused() {
    #[derive(Default)]
    struct Calls {
        /// What the transfer had been unpaused for, at each call.
        seen: Vec<bool>,
        unpaused: bool,
    }
    unsafe extern "C" fn read(buf: *mut c_char, _: usize, _: usize, data: *mut c_void) -> usize {
        // SAFETY: the test passes a `Calls`, and room for one byte.
        let calls = unsafe { &mut *data.cast::<Calls>() };
        calls.seen.push(calls.unpaused);
        match calls.seen.len() {
            1 => ffi::CURL_READFUNC_PAUSE as usize,
            2 => {
                // SAFETY: as above.
                unsafe { *buf = b'B' as c_char };
                1
            }
            _ => 0,
        }
    }
    use crate::mime::{curl_mime_addpart, curl_mime_data_cb, curl_mime_free, curl_mime_init};
    for size in [-1, 1] {
        let mut calls = Calls::default();
        let c = curl_easy_init();
        // SAFETY: live handles, a tree and its part, freed after the handle;
        // `calls` outlives them.
        unsafe {
            let m = curl_mime_init(c);
            let p = curl_mime_addpart(m);
            assert_eq!(
                curl_mime_data_cb(p, size, Some(read), None, None, (&raw mut calls).cast()),
                CURLE_OK
            );
            pointer(c, ffi::CURLOPT_URL, c"script://a".as_ptr().cast_mut());
            pointer(c, ffi::CURLOPT_MIMEPOST, m);
            options(c, |o| {
                o.script = Some(Script::new(vec![Piece::SendAll]).unwrap());
            });
            let multi = curl_multi_init();
            assert_eq!(curl_multi_add_handle(multi, c), CURLM_OK);
            let mut running = 1;
            let mut rounds = 0;
            while running > 0 {
                assert_eq!(curl_multi_perform(multi, &raw mut running), CURLM_OK);
                rounds += 1;
                assert!(rounds < 1000, "the transfer never ends");
                if !calls.seen.is_empty() && !calls.unpaused && rounds >= 5 {
                    calls.unpaused = true;
                    assert_eq!(curl_easy_pause(c, ffi::CURLPAUSE_CONT), CURLE_OK);
                }
            }
            let mut queued = 0;
            let msg = curl_multi_info_read(multi, &raw mut queued);
            assert_eq!((*msg).data.result, CURLE_OK);
            assert_eq!(curl_multi_remove_handle(multi, c), CURLM_OK);
            curl_easy_cleanup(c);
            curl_mime_free(m);
            assert_eq!(curl_multi_cleanup(multi), CURLM_OK);
        }
        let want: &[bool] = if size < 0 {
            &[false, true, true]
        } else {
            &[false, true]
        };
        assert_eq!(calls.seen, want, "size {size}");
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

/// A DNS server that answers every query late, 200 ms after it is asked,
/// with no answer of the type asked (`NOERROR`, no records), for the
/// tests' lifetime: named as `CURLOPT_DNS_SERVERS` names it.
#[cfg(feature = "c-ares")]
fn late_dns_server() -> &'static CStr {
    static SERVER: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    SERVER.get_or_init(|| {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let at = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf) {
                let Some(question) = buf.get(12..n) else {
                    continue;
                };
                // The header with the question's id, a response, no answer.
                let mut reply = vec![buf[0], buf[1], 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
                reply.extend_from_slice(question);
                let late = socket.try_clone().unwrap();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(200));
                    let _sent = late.send_to(&reply, peer);
                });
            }
        });
        std::ffi::CString::new(at.to_string()).unwrap()
    })
}

/// A handle tracing DNS to `debug`, with `seen` its data, to a name the
/// resolver answers itself and a port that refuses. Over c-ares its HTTPS
/// record is asked of a server that answers late, so that the record is
/// still out at the start's look and taken after it, whatever the host's
/// own resolver would answer and however soon. The threaded build, as C's
/// built without c-ares, has no servers to set and asks no record, which
/// is then known at once.
#[cfg(feature = "c-ares")]
fn refused_tracing_dns(debug: DebugFn, seen: &mut Seen) -> *mut CURL {
    let c = curl_easy_init();
    pointer(
        c,
        ffi::CURLOPT_URL,
        c"https://localhost:1/".as_ptr().cast_mut(),
    );
    let servers = late_dns_server().as_ptr().cast_mut();
    let set = if cfg!(feature = "threaded-resolver") {
        ffi::CURLE_NOT_BUILT_IN
    } else {
        ffi::CURLE_OK
    };
    assert_eq!(pointer(c, ffi::CURLOPT_DNS_SERVERS, servers), set);
    let components = curl_core::components::Components::new().unwrap();
    components.configure(b"dns");
    // SAFETY: a live handle.
    let easy = unsafe { crate::easy::handle(c) }.unwrap();
    let set = easy.with_home(|e| match e {
        crate::easy::HomeRef::Detached(e) => e.set_components(Some(components)),
        _ => unreachable!("in no multi"),
    });
    assert!(set.is_ok());
    long(c, ffi::CURLOPT_VERBOSE, 1);
    function(c, ffi::CURLOPT_DEBUGFUNCTION, debug as *const ());
    pointer(c, ffi::CURLOPT_DEBUGDATA, ptr::from_mut(seen));
    c
}

/// The lines `seen` was told of resolves' records.
#[cfg(feature = "c-ares")]
fn asyncs_seen(seen: &Seen) -> Vec<&str> {
    seen.texts
        .iter()
        .map(String::as_str)
        .filter(|t| t.ends_with(" async\n"))
        .collect()
}

/// Cleanup and reset tell the debug function of each resolve's record the
/// handle still keeps, as C's `Curl_close` and `curl_easy_reset` do before
/// they stop tracing: C's tool says `[DNS] [1] shutdown async` for
/// `https://localhost:1/` as the transfer is done, and `[DNS] [1] destroy
/// async` as the handle goes. A handle reset in its multi is told as that
/// multi's transfer, which a debug function asking it for its response
/// code finds.
#[cfg(feature = "c-ares")]
#[test]
fn cleanup_and_reset_tell_the_debug_function_of_the_resolves_let_go() {
    let (shut, destroyed) = ("[DNS] [1] shutdown async\n", "[DNS] [1] destroy async\n");
    let mut seen = Seen::default();
    let c = refused_tracing_dns(debug_count, &mut seen);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_COULDNT_CONNECT);
    assert_eq!(asyncs_seen(&seen), [shut]);
    // SAFETY: a live handle, then not used again.
    unsafe { curl_easy_cleanup(c) };
    assert_eq!(asyncs_seen(&seen), [shut, destroyed]);

    let mut seen = Seen::default();
    let c = refused_tracing_dns(debug_count, &mut seen);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_COULDNT_CONNECT);
    // SAFETY: a live handle.
    unsafe { crate::easy::curl_easy_reset(c) };
    assert_eq!(asyncs_seen(&seen), [shut, destroyed]);
    // SAFETY: a live handle, then not used again.
    unsafe { curl_easy_cleanup(c) };
    assert_eq!(asyncs_seen(&seen), [shut, destroyed], "nothing left");

    let mut seen = Seen::default();
    let c = refused_tracing_dns(debug_asking, &mut seen);
    let multi = curl_multi_init();
    // SAFETY: a live multi and handle, the handle reset while added and
    // the transfer done, then both let go of.
    unsafe {
        assert_eq!(curl_multi_add_handle(multi, c), CURLM_OK);
        let mut running = 1;
        let mut rounds = 0;
        while running > 0 {
            assert_eq!(curl_multi_perform(multi, &raw mut running), CURLM_OK);
            let waited = curl_multi_wait(multi, ptr::null_mut(), 0, 100, ptr::null_mut());
            assert_eq!(waited, CURLM_OK);
            rounds += 1;
            assert!(rounds < 100, "the transfer never ends");
        }
        assert_eq!(asyncs_seen(&seen), [shut]);
        crate::easy::curl_easy_reset(c);
        assert_eq!(asyncs_seen(&seen), [shut, destroyed]);
        assert_eq!(curl_multi_remove_handle(multi, c), CURLM_OK);
        curl_easy_cleanup(c);
        assert_eq!(curl_multi_cleanup(multi), CURLM_OK);
    }
}

/// A debug function told of the records a handle on its own lets go of,
/// as it is cleaned up or reset outside any transfer, reaches the handle
/// whole, as C's does: asked there for the last connect's error, it is
/// answered with the refused connect's, as C's c-ares and threaded builds
/// answer (`CURLINFO_OS_ERRNO`, `ECONNREFUSED`).
#[cfg(feature = "c-ares")]
#[test]
fn the_records_a_lone_handle_lets_go_of_are_told_with_the_handle_reachable() {
    let destroyed = "[DNS] [1] destroy async\n";
    let refused = if cfg!(target_vendor = "apple") {
        61
    } else {
        111
    };
    let asked = format!("getinfo 0, errno {refused}\n");
    for reset in [false, true] {
        let mut seen = Seen::default();
        let c = refused_tracing_dns(debug_asking_errno, &mut seen);
        // SAFETY: a live handle.
        assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_COULDNT_CONNECT);
        if reset {
            // SAFETY: a live handle.
            unsafe { crate::easy::curl_easy_reset(c) };
        }
        // SAFETY: a live handle, then not used again.
        unsafe { curl_easy_cleanup(c) };
        let at = seen.texts.iter().position(|t| t == destroyed);
        let at = at.unwrap_or_else(|| panic!("{:#?}", seen.texts));
        assert_eq!(
            seen.texts.get(at + 1).map(String::as_str),
            Some(asked.as_str()),
            "{:#?}",
            seen.texts
        );
    }
}

/// A reset from the transfer's own callback is refused, as C's gate
/// refuses it (`curl_easy_reset` may not recurse): under
/// `curl_easy_perform` and in a multi alike, the handle keeps its options,
/// its URL among them. C's threaded build refuses one from the header
/// function both ways.
#[cfg(feature = "c-ares")]
#[test]
fn a_reset_from_the_transfer_s_own_callback_is_refused() {
    let mut seen = Seen::default();
    let c = refused_tracing_dns(debug_resetting, &mut seen);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_COULDNT_CONNECT);
    // Its URL kept: refused again, not malformed.
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_COULDNT_CONNECT);
    let multi = curl_multi_init();
    // SAFETY: a live multi and handle, the handle run in the multi, then
    // on its own again, then both let go of.
    unsafe {
        assert_eq!(curl_multi_add_handle(multi, c), CURLM_OK);
        let mut running = 1;
        let mut rounds = 0;
        while running > 0 {
            assert_eq!(curl_multi_perform(multi, &raw mut running), CURLM_OK);
            let waited = curl_multi_wait(multi, ptr::null_mut(), 0, 100, ptr::null_mut());
            assert_eq!(waited, CURLM_OK);
            rounds += 1;
            assert!(rounds < 100, "the transfer never ends");
        }
        assert_eq!(curl_multi_remove_handle(multi, c), CURLM_OK);
        assert_eq!(curl_easy_perform(c), ffi::CURLE_COULDNT_CONNECT);
        curl_easy_cleanup(c);
        assert_eq!(curl_multi_cleanup(multi), CURLM_OK);
    }
}

/// A debug function that, as it is told a record is destroyed, asks for
/// the handle's last connect error, and keeps what it was answered.
#[cfg(feature = "c-ares")]
unsafe extern "C" fn debug_asking_errno(
    h: *mut CURL,
    kind: ffi::curl_infotype,
    ptr: *mut c_char,
    n: usize,
    data: *mut c_void,
) -> c_int {
    // SAFETY: as `debug_count` is called.
    let r = unsafe { debug_count(h, kind, ptr, n, data) };
    // SAFETY: the test passes a `Seen`.
    let s = unsafe { &mut *data.cast::<Seen>() };
    if kind == ffi::CURLINFO_TEXT
        && s.texts
            .last()
            .is_some_and(|t| t.ends_with(" destroy async\n"))
    {
        let mut errno: c_long = -1;
        // SAFETY: a live handle, and a long to the info.
        let asked = unsafe { curl_easy_getinfo(h, ffi::CURLINFO_OS_ERRNO, &raw mut errno) };
        s.texts
            .push(format!("getinfo {}, errno {errno}\n", asked.0));
    }
    r
}

/// A debug function that, as it is told text, resets the handle.
#[cfg(feature = "c-ares")]
unsafe extern "C" fn debug_resetting(
    h: *mut CURL,
    kind: ffi::curl_infotype,
    ptr: *mut c_char,
    n: usize,
    data: *mut c_void,
) -> c_int {
    // SAFETY: a live handle.
    unsafe { crate::easy::curl_easy_reset(h) };
    // SAFETY: as `debug_count` is called.
    unsafe { debug_count(h, kind, ptr, n, data) }
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
        // Windows opens no directory as a stream (`fopen`).
        if cfg!(windows) {
            format!(
                "WARNING: failed to open cookie file \"{}\"\n",
                dir_name.to_str().unwrap()
            )
        } else {
            format!(
                "WARNING: cookie filename points to a directory: \"{}\"\n",
                dir_name.to_str().unwrap()
            )
        },
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
        let t = timer as TimerFn as *mut c_void;
        let n = notify as NotifyFn as *mut c_void;
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
            CURLM_OK
        );
        // Multiplexing on or off, and the streams a server may open: none,
        // or more than an int holds, is 100; the dropped pipelining
        // options are taken.
        let limits = |m| *crate::multi::multi(m).core_mut().conn_limits_mut();
        assert!(limits(m).multiplex, "on by default");
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_PIPELINING, 0 as c_long),
            CURLM_OK
        );
        assert!(!limits(m).multiplex);
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_PIPELINING, ffi::CURLPIPE_MULTIPLEX),
            CURLM_OK
        );
        assert!(limits(m).multiplex);
        for (n, want) in [
            (7, 7),
            (0, 100),
            (-1, 100),
            (1 << 31, 100),
            (i32::MAX as c_long, i32::MAX as u32),
        ] {
            let streams = ffi::CURLMOPT_MAX_CONCURRENT_STREAMS;
            assert_eq!(curl_multi_setopt(m, streams, n as c_long), CURLM_OK);
            assert_eq!(limits(m).max_streams.get(), want, "{n}");
        }
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_MAX_PIPELINE_LENGTH, 5 as c_long),
            CURLM_OK
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
/// Unix only: the descriptors are a Unix socket pair's.
#[cfg(unix)]
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
// Unix only: the descriptors are a Unix socket pair's.
#[cfg(all(unix, feature = "debug-hooks"))]
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
        // Connected and the request sent, the transfer waits to read. The
        // threaded resolver's wake is the multi's own, listed first while
        // a transfer is alive, as C's admin handle is.
        let wake = u32::from(cfg!(feature = "threaded-resolver"));
        let mut peer = None;
        let mut waits = [ffi::curl_waitfd {
            fd: -1,
            events: 0,
            revents: 0,
        }; 2];
        for _ in 0..100 {
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
            assert_eq!(
                crate::multi::curl_multi_waitfds(m, waits.as_mut_ptr(), 2, &raw mut sockets),
                CURLM_OK
            );
            if peer.is_none() {
                peer = listener.accept().ok();
            }
            let reading = waits[wake as usize].events == ffi::CURL_WAIT_POLLIN as i16;
            if sockets == 1 + wake && peer.is_some() && reading {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!((running, sockets), (1, 1 + wake), "waiting on its socket");
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
    // Unix's bitmap, or Winsock's list.
    #[cfg(unix)]
    type FdSet = libc::fd_set;
    #[cfg(windows)]
    type FdSet = ffi::fd_set;
    let fdset = |read: &mut FdSet, write: &mut FdSet| {
        let mut max: c_int = 7;
        // SAFETY: a live multi and the caller's sets.
        let rc = unsafe {
            #[cfg(unix)]
            {
                libc::FD_ZERO(read);
                libc::FD_ZERO(write);
            }
            #[cfg(windows)]
            {
                read.fd_count = 0;
                write.fd_count = 0;
            }
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
    #[cfg(unix)]
    unsafe {
        assert!(libc::FD_ISSET(1000, &write));
        assert!(!libc::FD_ISSET(1000, &read));
    }
    // Winsock's sets list their sockets.
    #[cfg(windows)]
    assert_eq!(
        (&write.fd_array[..write.fd_count as usize], read.fd_count),
        (&[1000][..], 0)
    );
    assert_eq!(count(ptr::null_mut(), 0), (CURLM_OK, 1));
    let mut entries = [curl_waitfd {
        fd: ffi::CURL_SOCKET_BAD,
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
    assert_eq!(entries[1].fd, ffi::CURL_SOCKET_BAD, "untouched");
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
    calls: Vec<(*mut CURL, ffi::curl_socket_t, c_int, *mut c_void)>,
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
        let f = f.map_or(ptr::null_mut(), |f| f as *mut c_void);
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
        let f = f.map_or(ptr::null_mut(), |f| f as *mut c_void);
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

/// lib758's end: a connection whose shutdown waits keeps its socket
/// registered as its transfer is done and taken out, no socket function
/// called; `curl_multi_cleanup` closes it, and the socket function hears
/// REMOVE with the multi's internal handle, non-NULL and not the
/// transfer's, as C passes its admin handle.
#[test]
fn a_closing_connection_s_socket_is_removed_by_the_internal_handle() {
    use crate::ffi::{CURL_POLL_IN, CURL_POLL_OUT, CURL_POLL_REMOVE, CURL_SOCKET_TIMEOUT};
    use crate::multi::{ShimMulti, curl_multi_socket_action};
    use curl_core::conn::Linger;
    use curl_core::conn::io::{Conversation, FakeNet, Peer};
    use curl_core::time::ManualClock;

    let clock = ManualClock::new().unwrap();
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let talk = Conversation::new(reply, false).late_replies();
    let net = FakeNet::new(clock)
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk);
    let shim = ShimMulti::boxed_with(Box::new(net)).unwrap();
    // SAFETY: the multi just made; no call is under way on it.
    unsafe { shim.as_ref().core_mut() }.linger_connections(Some(Linger::UntilPeer));
    let m: *mut CURLM = shim.as_ptr().cast();
    let mut log = SocketLog {
        m,
        calls: Vec::new(),
        abort: false,
    };
    let me: *mut c_void = ptr::from_mut(&mut log).cast();
    let c = curl_easy_init();
    let url = c"http://127.0.0.1:1/";
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_FORBID_REUSE, 1), CURLE_OK);
    let mut running_now: c_int = -1;
    // SAFETY: a live multi and handle; the log outlives them.
    unsafe {
        let f: ffi::curl_socket_callback = Some(socket_fn);
        let f = f.map_or(ptr::null_mut(), |f| f as *mut c_void);
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_SOCKETFUNCTION, f),
            CURLM_OK
        );
        assert_eq!(curl_multi_setopt(m, ffi::CURLMOPT_SOCKETDATA, me), CURLM_OK);
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        let rc = curl_multi_socket_action(m, CURL_SOCKET_TIMEOUT, 0, &raw mut running_now);
        assert_eq!(rc, CURLM_OK);
        for _ in 0..5 {
            if running_now == 0 {
                break;
            }
            let rc = curl_multi_socket_action(m, 1000, 0, &raw mut running_now);
            assert_eq!(rc, CURLM_OK);
        }
        assert_eq!(running_now, 0, "done");
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        curl_easy_cleanup(c);
    }
    assert_eq!(
        log.calls,
        [
            (c, 1000, CURL_POLL_OUT, ptr::null_mut()),
            (c, 1000, CURL_POLL_IN, me),
        ],
        "kept registered: no REMOVE as the transfer goes"
    );
    // SAFETY: the multi made above, done with.
    unsafe {
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
    assert_eq!(log.calls.len(), 3);
    let (admin, fd, what, socketp) = log.calls[2];
    assert_eq!((fd, what, socketp), (1000, CURL_POLL_REMOVE, me));
    assert!(!admin.is_null() && admin != c, "the internal handle");
}

/// Without a `CURLOPT_CONNECT_ONLY` connection there is nothing to read
/// or write: `CURLE_UNSUPPORTED_PROTOCOL`, nothing moved; a missing count
/// or buffer is a bad argument (`curl_easy_recv`, `curl_easy_send`).
#[test]
fn recv_and_send_need_a_connect_only_connection() {
    use crate::easy::{curl_easy_recv, curl_easy_send};
    let c = curl_easy_init();
    let mut errbuf = [0u8; 256];
    assert_eq!(
        pointer(c, ffi::CURLOPT_ERRORBUFFER, errbuf.as_mut_ptr()),
        CURLE_OK
    );
    let mut buf = [0u8; 4];
    let mut n = 9;
    // SAFETY: a live handle, a buffer of 4 bytes and a count to write.
    unsafe {
        assert_eq!(
            curl_easy_recv(c, buf.as_mut_ptr().cast(), 4, &raw mut n),
            ffi::CURLE_UNSUPPORTED_PROTOCOL
        );
        assert_eq!(n, 0);
        let said = CStr::from_bytes_until_nul(&errbuf).unwrap();
        assert_eq!(said, c"CONNECT_ONLY is required");
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
        (ffi::CURL_LOCK_DATA_HSTS, ffi::CURLSHE_OK),
        (ffi::CURL_LOCK_DATA_SSL_SESSION, ffi::CURLSHE_OK),
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
        let lock = lock.map_or(ptr::null_mut(), |f| f as *mut c_void);
        let unlock: ffi::curl_unlock_function = Some(record_unlock);
        let unlock = unlock.map_or(ptr::null_mut(), |f| f as *mut c_void);
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
    // The one left holds it still: for an option the core has no say in,
    // and for its cleanup.
    assert_eq!(
        set(sh, ffi::CURLSHOPT_SHARE, ffi::CURL_LOCK_DATA_DNS),
        ffi::CURLSHE_IN_USE
    );
    // SAFETY: a live share and a pointer, as the option takes; then a live
    // share.
    unsafe {
        assert_eq!(
            curl_share_setopt(sh, ffi::CURLSHOPT_USERDATA, ptr::null_mut::<c_void>()),
            ffi::CURLSHE_IN_USE
        );
        assert_eq!(curl_share_cleanup(sh), ffi::CURLSHE_IN_USE);
    }
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
    // An HTTP/3 proxy is built in, as with C's `USE_PROXY_HTTP3`.
    assert_eq!(
        long(c, ffi::CURLOPT_PROXYTYPE, ffi::CURLPROXY_HTTPS3),
        CURLE_OK
    );
    options(c, |o| {
        assert_eq!(o.proxy.kind, curl_core::options::ProxyType::Https3);
    });
    assert_eq!(
        long(c, ffi::CURLOPT_PROXYTYPE, ffi::CURLPROXY_SOCKS5_HOSTNAME),
        CURLE_OK
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

/// The service names are kept as given, a SOCKS5 GSS-API service being
/// the proxy's; delegation and NEC's switch are a GSS-API build's, and
/// unknown elsewhere, as a C build without GSS-API has them.
#[test]
fn gss_options_are_read_as_c() {
    let c = curl_easy_init();
    let services = |c| options(c, |o| (o.login.service.clone(), o.proxy.service.clone()));
    assert_eq!(services(c), (None, None));
    assert_eq!(
        pointer(c, ffi::CURLOPT_SERVICE_NAME, c"imap".as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(
        pointer(
            c,
            ffi::CURLOPT_PROXY_SERVICE_NAME,
            c"HTTP".as_ptr().cast_mut()
        ),
        CURLE_OK
    );
    assert_eq!(
        services(c),
        (Some(b"imap".to_vec()), Some(b"HTTP".to_vec()))
    );
    assert_eq!(
        pointer(
            c,
            ffi::CURLOPT_SOCKS5_GSSAPI_SERVICE,
            c"rcmd/host".as_ptr().cast_mut()
        ),
        CURLE_OK
    );
    assert_eq!(
        services(c),
        (Some(b"imap".to_vec()), Some(b"rcmd/host".to_vec())),
        "the proxy's, as its alias"
    );
    pointer(c, ffi::CURLOPT_SERVICE_NAME, ptr::null_mut::<c_char>());
    pointer(
        c,
        ffi::CURLOPT_PROXY_SERVICE_NAME,
        ptr::null_mut::<c_char>(),
    );
    assert_eq!(services(c), (None, None));
    let gssapi = curl_core::version::version().claims("GSS-API");
    let code = if gssapi {
        CURLE_OK
    } else {
        CURLE_UNKNOWN_OPTION
    };
    assert_eq!(
        long(
            c,
            ffi::CURLOPT_GSSAPI_DELEGATION,
            ffi::CURLGSSAPI_DELEGATION_FLAG
        ),
        code
    );
    assert_eq!(options(c, |o| o.login.delegation.always), gssapi);
    assert_eq!(long(c, ffi::CURLOPT_SOCKS5_GSSAPI_NEC, 1), code);
    assert_eq!(options(c, |o| o.proxy.socks5_gssapi_nec), gssapi);
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
        use curl_core::options::AuthMethods as M;
        // Negotiate kept, as the build claims SPNEGO.
        assert_eq!(o.proxy.auth.0, M::ANY)
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

/// `CURLMINFO_XFERS_CURRENT`, `RUNNING`, `PENDING`, `DONE` and `ADDED`
/// of multi `m`, each with its code.
fn census_of(m: *mut CURLM) -> [(ffi::CURLMcode, curl_off_t); 5] {
    [
        ffi::CURLMINFO_XFERS_CURRENT,
        ffi::CURLMINFO_XFERS_RUNNING,
        ffi::CURLMINFO_XFERS_PENDING,
        ffi::CURLMINFO_XFERS_DONE,
        ffi::CURLMINFO_XFERS_ADDED,
    ]
    .map(|info| {
        let mut value = -2;
        // SAFETY: the test's live multi, and a value to write.
        let code = unsafe { curl_multi_get_offt(m, info, &raw mut value) };
        (code, value)
    })
}

/// What `census_of` gives when every call succeeds.
fn census(values: [curl_off_t; 5]) -> [(ffi::CURLMcode, curl_off_t); 5] {
    values.map(|v| (CURLM_OK, v))
}

/// The multi a write or timer callback samples, and what it saw.
#[derive(Default)]
struct Sampled {
    multi: usize,
    seen: Vec<[(ffi::CURLMcode, curl_off_t); 5]>,
}

/// Samples the multi's counts from inside a transfer's write callback.
unsafe extern "C" fn sample_write(
    _: *mut c_char,
    size: usize,
    n: usize,
    data: *mut c_void,
) -> usize {
    // SAFETY: `data` is the test's `Sampled`, which outlives the transfers.
    let s = unsafe { &mut *data.cast::<Sampled>() };
    s.seen.push(census_of(s.multi as *mut CURLM));
    size * n
}

/// Samples the multi's counts from inside its timer callback.
unsafe extern "C" fn sample_timer(m: *mut CURLM, _: c_long, data: *mut c_void) -> c_int {
    // SAFETY: as above.
    let s = unsafe { &mut *data.cast::<Sampled>() };
    s.seen.push(census_of(m));
    0
}

/// Under a host limit of one, of three transfers to one host one runs
/// and two wait: `CURLMINFO_XFERS_RUNNING` counts the one and
/// `CURLMINFO_XFERS_PENDING` the two, while `curl_multi_perform` reports
/// all three running. The counts read the same from a write callback and
/// the timer callback, as C's `curl_multi_get_offt` may recurse.
#[test]
fn the_multi_counts_running_and_waiting_transfers_apart() {
    const HELLO: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    let (port, server) = serve(vec![HELLO, HELLO, HELLO]);
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    let m = curl_multi_init();
    let mut writes = Sampled {
        multi: m as usize,
        ..Sampled::default()
    };
    let mut timers = Sampled::default();
    // SAFETY: the live multi, and data that outlives it.
    unsafe {
        let limit = ffi::CURLMOPT_MAX_HOST_CONNECTIONS;
        assert_eq!(curl_multi_setopt(m, limit, 1 as c_long), CURLM_OK);
        let t = sample_timer as TimerFn as *mut c_void;
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_TIMERFUNCTION, t),
            CURLM_OK
        );
        let data = (&raw mut timers).cast::<c_void>();
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_TIMERDATA, data),
            CURLM_OK
        );
    }
    let handles = [(); 3].map(|()| {
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        function(
            c,
            ffi::CURLOPT_WRITEFUNCTION,
            sample_write as WriteFn as *const (),
        );
        pointer(c, ffi::CURLOPT_WRITEDATA, &raw mut writes);
        long(c, ffi::CURLOPT_TIMEOUT, 10);
        // SAFETY: live handles.
        assert_eq!(unsafe { curl_multi_add_handle(m, c) }, CURLM_OK);
        c
    });
    assert_eq!(
        census_of(m),
        census([3, 3, 0, 0, 3]),
        "none waits before a perform"
    );
    let mut running = 0;
    // SAFETY: the live multi.
    assert_eq!(unsafe { curl_multi_perform(m, &raw mut running) }, CURLM_OK);
    assert_eq!(running, 3, "the waiting ones run, to perform");
    assert_eq!(census_of(m), census([3, 1, 2, 0, 3]));
    while running > 0 {
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                curl_multi_wait(m, ptr::null_mut(), 0, 1000, ptr::null_mut()),
                CURLM_OK
            );
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
        }
    }
    assert_eq!(census_of(m), census([3, 0, 0, 3, 3]));
    // How many of the rest wait while one writes depends on when the
    // server answers; each writer runs and those before it are done.
    assert_eq!(writes.seen.len(), 3);
    for (i, seen) in (0..).zip(&writes.seen) {
        let [current, working, pending, done, added] = seen.map(|(code, v)| {
            assert_eq!(code, CURLM_OK, "{seen:?}");
            v
        });
        assert_eq!((current, done, added), (3, i, 3), "{seen:?}");
        assert!(working >= 1, "{seen:?}");
        assert_eq!(working + pending, 3 - i, "{seen:?}");
    }
    assert!(!timers.seen.is_empty());
    let last = timers.seen.last().unwrap();
    assert_eq!(*last, census([3, 0, 0, 3, 3]), "{:?}", timers.seen);
    assert!(
        timers
            .seen
            .iter()
            .flatten()
            .all(|&(code, _)| code == CURLM_OK),
        "{:?}",
        timers.seen
    );
    assert_eq!(server.join().unwrap().len(), 3);
    // SAFETY: live handles, not used again.
    unsafe {
        for c in handles {
            assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
            curl_easy_cleanup(c);
        }
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
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

/// The handle and what its header function heard: each line with the
/// methods `CURLINFO_HTTPAUTH_AVAIL` gave as it was delivered.
struct AuthAvail {
    c: *mut CURL,
    lines: Vec<(String, c_long)>,
}

unsafe extern "C" fn auth_avail(
    ptr: *mut c_char,
    size: usize,
    n: usize,
    data: *mut c_void,
) -> usize {
    // SAFETY: the test passes `AuthAvail` and the shim `size * n` bytes.
    let (a, b) = unsafe {
        (
            &mut *data.cast::<AuthAvail>(),
            core::slice::from_raw_parts(ptr.cast::<u8>(), size * n),
        )
    };
    let avail: c_long = info(a.c, ffi::CURLINFO_HTTPAUTH_AVAIL);
    a.lines
        .push((String::from_utf8(b.to_vec()).unwrap(), avail));
    size * n
}

/// A challenge's methods are available to the header function from the
/// line that offers them on, as C reads them before it delivers the line
/// (`Curl_http_input_auth`): WebKit's curl backend asks at the head's end.
#[test]
fn a_challenge_is_available_to_the_header_function_as_its_line_arrives() {
    let (port, server) = serve(vec![
        b"HTTP/1.1 401 No\r\nWWW-Authenticate: Basic realm=\"r\"\r\n\
          Content-Length: 0\r\nConnection: close\r\n\r\n",
    ]);
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    let mut heard = AuthAvail {
        c,
        lines: Vec::new(),
    };
    function(
        c,
        ffi::CURLOPT_HEADERFUNCTION,
        auth_avail as WriteFn as *const (),
    );
    pointer(c, ffi::CURLOPT_HEADERDATA, &raw mut heard);
    // SAFETY: a live handle, whose header data lives through the transfer.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    server.join().unwrap();
    let basic = c_long::try_from(ffi::CURLAUTH_BASIC).unwrap();
    let avail: Vec<_> = heard.lines.iter().map(|(_, a)| *a).collect();
    assert_eq!(avail, [0, basic, basic, basic, basic], "{:?}", heard.lines);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
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

/// A debug function that sets `CURLOPT_CUSTOMREQUEST` to PATCH when the
/// switch to GET after a redirect is traced, as `api.c` lets a callback
/// set options (`easy_setopt` may recurse).
unsafe extern "C" fn patch_on_stick(
    h: *mut CURL,
    kind: ffi::curl_infotype,
    ptr: *mut c_char,
    n: usize,
    _: *mut c_void,
) -> c_int {
    // SAFETY: the shim's `n` bytes.
    let text = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), n) };
    if kind == ffi::CURLINFO_TEXT && text.starts_with(b"Stick to DELETE instead of GET") {
        let patch = c"PATCH";
        assert_eq!(
            pointer(h, ffi::CURLOPT_CUSTOMREQUEST, patch.as_ptr().cast_mut()),
            CURLE_OK
        );
    }
    0
}

/// A custom method the debug function sets while a 303's "Stick to
/// DELETE instead of GET" is traced is the one the next request sends:
/// the C build sends `PATCH /b` (`http_switch_to_get` leaves the option
/// where it is while it traces).
#[test]
fn a_custom_method_set_from_the_debug_function_on_a_redirect_stands() {
    let (port, server) = serve(vec![
        b"HTTP/1.1 303 See Other\r\nLocation: /b\r\nContent-Length: 0\r\n\
          Connection: close\r\n\r\n",
        OK,
    ]);
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/a")).unwrap();
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    long(c, ffi::CURLOPT_FOLLOWLOCATION, 1);
    pointer(c, ffi::CURLOPT_CUSTOMREQUEST, c"DELETE".as_ptr().cast_mut());
    long(c, ffi::CURLOPT_VERBOSE, 1);
    function(
        c,
        ffi::CURLOPT_DEBUGFUNCTION,
        patch_on_stick as DebugFn as *const (),
    );
    // SAFETY: a live handle, then not used again.
    let code = unsafe { curl_easy_perform(c) };
    // SAFETY: as above.
    unsafe { curl_easy_cleanup(c) };
    assert_eq!(code, CURLE_OK);
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with(b"DELETE /a "));
    let second = String::from_utf8_lossy(&requests[1]);
    assert!(second.starts_with("PATCH /b "), "{second}");
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

/// A refused connect's error number: the C library's, or Winsock's
/// (`WSAECONNREFUSED`), as `SOCKERRNO` reads it.
#[cfg(unix)]
const ECONNREFUSED: c_long = libc::ECONNREFUSED as c_long;
#[cfg(windows)]
const ECONNREFUSED: c_long = 10061;
/// A reset connection's (`WSAECONNRESET`).
#[cfg(unix)]
const ECONNRESET: c_long = libc::ECONNRESET as c_long;
#[cfg(windows)]
const ECONNRESET: c_long = 10054;

/// `CURLINFO_OS_ERRNO` is the number of the last socket call that failed:
/// a connect refused, a receive the peer reset; kept by a reset of the
/// handle, and 0 again once its next transfer starts (`easy_perform`).
#[test]
fn the_os_errno_is_the_last_socket_failure_s() {
    let c = curl_easy_init();
    long(c, ffi::CURLOPT_TIMEOUT, 10);
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_OS_ERRNO), 0);
    // Port 1, which no unprivileged test can bind: a port picked free and
    // let go can be taken by a test running beside this one.
    let url = std::ffi::CString::new("http://127.0.0.1:1/").unwrap();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_COULDNT_CONNECT);
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_OS_ERRNO), ECONNREFUSED);

    // A peer that closes with the request unread resets the connection.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut some = [0; 1];
        peer.peek(&mut some).unwrap();
        drop(peer);
    });
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_RECV_ERROR);
    server.join().unwrap();
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_OS_ERRNO), ECONNRESET);
    // A reset leaves it: C keeps it in the handle's state, not its info.
    // SAFETY: a live handle.
    unsafe { easy::curl_easy_reset(c) };
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_OS_ERRNO), ECONNRESET);
    long(c, ffi::CURLOPT_TIMEOUT, 10);

    let (port, server) = serve(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]);
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    server.join().unwrap();
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_OS_ERRNO), 0);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
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
        // Held open until the client lets go: closed with bytes unread,
        // Windows resets the connection, and the reset can come before
        // the client reads the answer.
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _ = peer.read(&mut [0; 16]);
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

/// The lock functions' calls with their access: `(access, data)`, the
/// access none for an unlock. Kept in what the share is given.
type AccessCalls = std::sync::Mutex<Vec<(Option<c_int>, c_int)>>;

unsafe extern "C" fn access_lock(
    _: *mut CURL,
    data: ffi::curl_lock_data,
    access: ffi::curl_lock_access,
    user: *mut c_void,
) {
    // SAFETY: the test's calls, alive as long as the share.
    let calls = unsafe { &*user.cast::<AccessCalls>() };
    calls
        .lock()
        .unwrap()
        .push((Some(access.0 as c_int), data.0 as c_int));
}

unsafe extern "C" fn access_unlock(_: *mut CURL, data: ffi::curl_lock_data, user: *mut c_void) {
    // SAFETY: as in `access_lock`.
    let calls = unsafe { &*user.cast::<AccessCalls>() };
    calls.lock().unwrap().push((None, data.0 as c_int));
}

/// A server on this machine answering each connection with `reply`.
fn answering(reply: &'static [u8]) -> u16 {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut got = Vec::new();
            let mut chunk = [0; 1024];
            while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(n) if n > 0 => got.extend_from_slice(&chunk[..n]),
                    _ => break,
                }
            }
            let _gone = stream.write_all(reply);
        }
    });
    port
}

/// Which lock calls a share keeping the public suffix list, the cookies
/// and the HSTS cache makes around two transfers, as the C build makes
/// them: `SHARED`, with `SINGLE` where a list is looked for, nested in the
/// cookies' use; the HSTS cache `SINGLE` around its file alone.
#[test]
fn the_lock_functions_are_told_of_the_list_and_the_cache_as_in_c() {
    use crate::share::{curl_share_cleanup, curl_share_init, curl_share_setopt};
    const COOKIE: c_int = ffi::CURL_LOCK_DATA_COOKIE.0 as c_int;
    const PSL: c_int = ffi::CURL_LOCK_DATA_PSL.0 as c_int;
    const HSTS: c_int = ffi::CURL_LOCK_DATA_HSTS.0 as c_int;
    const SHARED: Option<c_int> = Some(ffi::CURL_LOCK_ACCESS_SHARED.0 as c_int);
    const SINGLE: Option<c_int> = Some(ffi::CURL_LOCK_ACCESS_SINGLE.0 as c_int);
    let port = answering(
        b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; domain=localhost\r\n\
          Content-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let file = std::env::temp_dir().join(format!("curl-abi-share-{}", std::process::id()));
    std::fs::write(&file, "kept.example \"unlimited\"\n").unwrap();
    let name = std::ffi::CString::new(file.to_str().unwrap()).unwrap();
    let url = std::ffi::CString::new(format!("http://localhost:{port}/")).unwrap();
    let calls = AccessCalls::default();
    let sh = curl_share_init();
    // SAFETY: a live share, then ints, the functions and data the options
    // take, the data outliving the share.
    unsafe {
        for data in [
            ffi::CURL_LOCK_DATA_COOKIE,
            ffi::CURL_LOCK_DATA_PSL,
            ffi::CURL_LOCK_DATA_HSTS,
        ] {
            let on = curl_share_setopt(sh, ffi::CURLSHOPT_SHARE, data.0 as c_int);
            assert_eq!(on, ffi::CURLSHE_OK);
        }
        let lock: ffi::curl_lock_function = Some(access_lock);
        let lock = lock.map_or(ptr::null_mut(), |f| f as *mut c_void);
        let unlock: ffi::curl_unlock_function = Some(access_unlock);
        let unlock = unlock.map_or(ptr::null_mut(), |f| f as *mut c_void);
        curl_share_setopt(sh, ffi::CURLSHOPT_LOCKFUNC, lock);
        curl_share_setopt(sh, ffi::CURLSHOPT_UNLOCKFUNC, unlock);
        let user = (&raw const calls).cast_mut().cast::<c_void>();
        curl_share_setopt(sh, ffi::CURLSHOPT_USERDATA, user);
    }
    let c = curl_easy_init();
    assert_eq!(
        pointer(c, ffi::CURLOPT_HSTS, name.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(pointer(c, ffi::CURLOPT_SHARE, sh), CURLE_OK);
    assert_eq!(
        pointer(c, ffi::CURLOPT_COOKIEFILE, c"".as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    let of = |kind: c_int, all: &[(Option<c_int>, c_int)]| -> Vec<Option<c_int>> {
        all.iter().filter(|c| c.1 == kind).map(|c| c.0).collect()
    };
    let take = || std::mem::take(&mut *calls.lock().unwrap());
    take();
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let first = take();
    assert_eq!(of(HSTS, &first), [SINGLE, None], "around the file");
    assert_eq!(
        of(PSL, &first),
        [SHARED, None, SINGLE, None, SHARED, None],
        "looked for"
    );
    // Nested in the use of the cookies that stores the one with a domain.
    let opened = first.iter().position(|c| c.1 == PSL).unwrap();
    assert_eq!(first[opened - 1], (SINGLE, COOKIE));
    assert_eq!(first[opened + 6], (None, COOKIE));
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let second = take();
    assert_eq!(of(HSTS, &second), [SINGLE, None], "at each transfer");
    assert_eq!(of(PSL, &second), [SHARED, None], "kept");
    // SAFETY: a live handle, not used again; then the share, held by none.
    unsafe {
        curl_easy_cleanup(c);
        assert_eq!(of(HSTS, &take()), []);
        assert_eq!(curl_share_cleanup(sh), ffi::CURLSHE_OK);
    }
    std::fs::remove_file(&file).unwrap();
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
        let lock = lock.map_or(ptr::null_mut(), |f| f as *mut c_void);
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

/// A name to save the jar under turns a jar on as it is set, not at each
/// transfer: once the jar has gone, by leaving a share that keeps cookies or
/// by `CURLOPT_COOKIEFILE` NULL, a transfer has none until the name is set
/// again or a cookie file named, as the C build does.
#[test]
fn a_jar_gone_is_not_brought_back_by_its_name() {
    use crate::share::{curl_share_cleanup, curl_share_init, curl_share_setopt};
    const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nContent-Length: 0\r\n\
                           Connection: close\r\n\r\n";
    let dir = std::env::temp_dir().join(format!("curl-jar-gone-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sh = curl_share_init();
    // SAFETY: a live share and an int, as the option takes.
    let kept = unsafe {
        curl_share_setopt(
            sh,
            ffi::CURLSHOPT_SHARE,
            ffi::CURL_LOCK_DATA_COOKIE.0 as c_int,
        )
    };
    assert_eq!(kept, ffi::CURLSHE_OK);
    let leave = |c| {
        assert_eq!(pointer(c, ffi::CURLOPT_SHARE, sh), CURLE_OK);
        assert_eq!(
            pointer(c, ffi::CURLOPT_SHARE, ptr::null_mut::<c_void>()),
            CURLE_OK
        );
    };
    let name = |c, jar: &std::ffi::CString| {
        assert_eq!(
            pointer(c, ffi::CURLOPT_COOKIEJAR, jar.as_ptr().cast_mut()),
            CURLE_OK
        );
    };
    type Between<'a> = &'a dyn Fn(*mut CURL, &std::ffi::CString);
    let cases: [(&str, bool, Between); 5] = [
        ("named", true, &|_, _| {}),
        ("left a share", false, &|c, _| leave(c)),
        ("forgotten", false, &|c, _| {
            let none = ptr::null_mut::<c_char>();
            assert_eq!(pointer(c, ffi::CURLOPT_COOKIEFILE, none), CURLE_OK);
        }),
        ("named again", true, &|c, jar| {
            leave(c);
            name(c, jar);
        }),
        ("a file after", true, &|c, _| {
            leave(c);
            pointer(c, ffi::CURLOPT_COOKIEFILE, c"".as_ptr().cast_mut());
        }),
    ];
    for (what, kept, between) in cases {
        let (port, server) = serve(vec![REPLY]);
        let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
        let path = dir.join(what.replace(' ', "-"));
        let jar = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
        long(c, ffi::CURLOPT_TIMEOUT, 10);
        name(c, &jar);
        between(c, &jar);
        // SAFETY: a live handle.
        assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK, "{what}");
        server.join().unwrap();
        let mut list: *mut ffi::curl_slist = ptr::null_mut();
        // SAFETY: a live handle, and where the option's list goes.
        let got = unsafe { curl_easy_getinfo(c, ffi::CURLINFO_COOKIELIST, &raw mut list) };
        assert_eq!(got, CURLE_OK);
        assert_eq!(!list.is_null(), kept, "{what}: the jar's cookies");
        // SAFETY: the list just given, and then a live handle, not used again.
        unsafe {
            crate::strings::curl_slist_free_all(list);
            curl_easy_cleanup(c);
        }
        assert_eq!(path.exists(), kept, "{what}: the file written at cleanup");
    }
    // SAFETY: a live share, held by none.
    assert_eq!(unsafe { curl_share_cleanup(sh) }, ffi::CURLSHE_OK);
    std::fs::remove_dir_all(&dir).unwrap();
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
    // `held` is the budget, from C. `made` is a tripwire inside it, to
    // raise with a reason when a field earns its place (DESIGN.md): RTSP's
    // state on the handle and its interleave function on the shim are made
    // when first set, a pointer each until then, as is the list of its
    // resolves' records (C's `state.async`). `CURLOPT_CURLU`'s pointer is
    // kept on the shim as given, as C keeps `set.uh`. Which jar and which
    // HSTS cache the handle uses are one value each (`JarUse`, `HstsUse`),
    // a tag beside the box of its own.
    assert!(made_bytes <= 2_152, "a new handle holds {made_bytes} bytes");
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
/// the group is made only by a value. A size or speed limit set to 0,
/// none, makes nothing either. Clearing one in a group made still
/// clears it.
#[cfg(feature = "debug-hooks")]
#[test]
fn clearing_an_option_makes_no_group() {
    use curl_alloc::track::measure;
    // Every handle made is cleaned up.
    let ((), held) = measure(|| {
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
            ffi::CURLOPT_SERVICE_NAME,
            ffi::CURLOPT_PROXY_SERVICE_NAME,
            ffi::CURLOPT_SOCKS5_GSSAPI_SERVICE,
            ffi::CURLOPT_PROXYHEADER,
            ffi::CURLOPT_NETRC_FILE,
            ffi::CURLOPT_COOKIE,
            ffi::CURLOPT_COOKIEFILE,
            ffi::CURLOPT_REFERER,
            ffi::CURLOPT_CUSTOMREQUEST,
            ffi::CURLOPT_REQUEST_TARGET,
        ];
        let c = curl_easy_init();
        for option in cleared {
            let (code, cost) = measure(|| pointer(c, option, ptr::null_mut::<c_char>()));
            assert_eq!(code, CURLE_OK, "{option:?}");
            assert_eq!(cost.allocations, 0, "{option:?} made its group");
        }
        let longs = [
            ffi::CURLOPT_LOW_SPEED_LIMIT,
            ffi::CURLOPT_LOW_SPEED_TIME,
            ffi::CURLOPT_MAXFILESIZE,
        ];
        for option in longs {
            let (code, cost) = measure(|| long(c, option, 0));
            assert_eq!((code, cost.allocations), (CURLE_OK, 0), "{option:?}");
        }
        let offs = [
            ffi::CURLOPT_MAXFILESIZE_LARGE,
            ffi::CURLOPT_MAX_RECV_SPEED_LARGE,
            ffi::CURLOPT_MAX_SEND_SPEED_LARGE,
        ];
        for option in offs {
            let (code, cost) = measure(|| off(c, option, 0));
            assert_eq!((code, cost.allocations), (CURLE_OK, 0), "{option:?}");
        }
        // A limit set makes the group, once; 0 then clears it.
        let (code, cost) = measure(|| off(c, ffi::CURLOPT_MAX_RECV_SPEED_LARGE, 1000));
        assert_eq!((code, cost.allocations), (CURLE_OK, 1));
        let (code, cost) = measure(|| off(c, ffi::CURLOPT_MAXFILESIZE_LARGE, 5));
        assert_eq!((code, cost.allocations), (CURLE_OK, 0));
        off(c, ffi::CURLOPT_MAX_RECV_SPEED_LARGE, 0);
        assert_eq!(options(c, |o| o.flow.max_recv_speed), None);
        assert_eq!(
            options(c, |o| o.flow.max_filesize.map(|n| n.get())),
            Some(5)
        );
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
        unsafe { curl_easy_cleanup(c) };
        // `CURLOPT_COOKIEJAR` turns the jar on whatever it names, as C makes
        // its cookie engine.
        let c = curl_easy_init();
        let (code, cost) =
            measure(|| pointer(c, ffi::CURLOPT_COOKIEJAR, ptr::null_mut::<c_char>()));
        assert_eq!((code, cost.allocations), (CURLE_OK, 1));
        // SAFETY: a live handle, not used again.
        unsafe { curl_easy_cleanup(c) };
    });
    assert_eq!(held.bytes, 0, "a handle left alive");
}

/// `CURLOPT_COOKIELIST` "FLUSH" replaces a jar named long making the
/// allocations it makes for one named short, as C copies no name: std's
/// rename copied each name of 384 bytes or more, the jar's and the one it
/// is written under first, with an allocation that cannot fail, which
/// aborted a torture run. Unix only: on Windows every name is turned to
/// UTF-16 in memory of its own to be opened, whatever its length.
#[cfg(all(unix, feature = "debug-hooks"))]
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

/// `curl_global_trace` changes what every handle traces, those made
/// before it, their copies and those reset among them, as C's process-wide
/// levels do. Tried on a component nothing traces yet, as the setting is
/// the process's and other tests run beside this one.
/// With `CURL_DEBUG` set, a debug build applies it at the first
/// `curl_global_init` and after each `curl_global_trace`, over what that
/// asked (`Curl_trc_opt`). Checked in a process of its own, the variable
/// set there.
#[cfg(feature = "debug-hooks")]
#[test]
fn a_debug_build_takes_curl_debug_last() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "handle_tests::curl_debug_applied", "--ignored"])
        .env("CURL_DEBUG", "threads")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("1 passed"), "the test ran: {stdout}");
}

#[cfg(feature = "debug-hooks")]
#[test]
#[ignore = "run by a_debug_build_takes_curl_debug_last, CURL_DEBUG set"]
fn curl_debug_applied() {
    use curl_core::components::Component;
    let threads = || crate::root::components().traces(Component::Threads);
    assert!(!threads(), "nothing read before the library starts");
    assert_eq!(crate::root::curl_global_init(0), CURLE_OK);
    assert!(threads(), "read as the library starts");
    // SAFETY: a C string.
    unsafe { crate::root::curl_global_trace(c"-threads".as_ptr()) };
    assert!(threads(), "read again over what the application asked");
    crate::root::curl_global_cleanup();
}

/// `curl_global_init` initialises OpenSSL as C's does (`ossl_init`),
/// reading the configuration `OPENSSL_CONF` names then: the file, which
/// lets the library fetch no algorithm, is emptied after the call, and
/// signing still fails. Checked in a process of its own.
#[test]
fn the_global_init_reads_openssl_s_configuration() {
    let path = std::env::temp_dir().join(format!("curl-sys-abi-{}.cnf", std::process::id()));
    std::fs::write(
        &path,
        "openssl_conf = init\n\
         [init]\n\
         alg_section = algorithms\n\
         [algorithms]\n\
         default_properties = \"provider=none\"\n",
    )
    .unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "handle_tests::openssl_configured", "--ignored"])
        .env("OPENSSL_CONF", &path)
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("1 passed"), "the test ran: {stdout}");
}

#[test]
#[ignore = "run by the_global_init_reads_openssl_s_configuration, OPENSSL_CONF set"]
fn openssl_configured() {
    use curl_core::libraries::{Ed25519, Ed25519Error};
    let path = std::env::var_os("OPENSSL_CONF").unwrap();
    assert_eq!(crate::root::curl_global_init(0), CURLE_OK);
    std::fs::write(&path, "").unwrap();
    assert_eq!(
        curl_openssl::ED25519.sign(&[1; 32], b"message"),
        Err(Ed25519Error::Failed)
    );
    crate::root::curl_global_cleanup();
}

#[test]
fn the_global_trace_reaches_every_handle() {
    use curl_core::components::Component;
    let threads = |c: *mut CURL| {
        // SAFETY: a live handle.
        let easy = unsafe { easy::handle(c) }.expect("a live handle");
        easy.with_easy(|e| match e {
            easy::EasyRef::Easy(e) => e.components().is_some_and(|c| c.traces(Component::Threads)),
            easy::EasyRef::Frame(..) => unreachable!("in no multi"),
        })
        .unwrap()
    };
    let c = curl_easy_init();
    assert!(!threads(c));
    // SAFETY: a C string.
    let set = unsafe { crate::root::curl_global_trace(c"THREADS".as_ptr()) };
    assert_eq!(set, CURLE_OK);
    assert!(threads(c));
    // SAFETY: a live handle.
    let d = unsafe { easy::curl_easy_duphandle(c) };
    // SAFETY: a live handle.
    unsafe { easy::curl_easy_reset(c) };
    assert!(threads(c) && threads(d));
    // NULL changes nothing.
    // SAFETY: NULL is allowed.
    let set = unsafe { crate::root::curl_global_trace(ptr::null()) };
    assert_eq!(set, CURLE_OK);
    let e = curl_easy_init();
    assert!(threads(e));
    // SAFETY: a C string.
    unsafe { crate::root::curl_global_trace(c"-threads".as_ptr()) };
    assert!(!threads(c) && !threads(d) && !threads(e));
    // SAFETY: live handles, not used again.
    unsafe {
        curl_easy_cleanup(c);
        curl_easy_cleanup(d);
        curl_easy_cleanup(e);
    }
}

/// A perform that cannot add its handle to its own multi for want of
/// memory fails with CURLE_OUT_OF_MEMORY, as C's `easy_perform` does.
#[cfg(feature = "debug-hooks")]
#[test]
fn a_perform_out_of_memory_adding_its_handle_says_so() {
    use curl_alloc::track::fail_once_after_here;
    // A port nothing listens on: refused at once.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    let c = curl_easy_init();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    // The first perform makes the handle's own multi, which it keeps: the
    // next one's first allocation is its handle's place in that multi.
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_COULDNT_CONNECT);
    // SAFETY: a live handle.
    let (code, refused) = fail_once_after_here(0, || unsafe { curl_easy_perform(c) });
    assert!(refused);
    assert_eq!(code, ffi::CURLE_OUT_OF_MEMORY);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// What a test's socket functions saw, and what its configurer answers.
/// These tests open, connect and close their sockets with libc's calls,
/// so they run on Unix only.
#[cfg(unix)]
#[derive(Default)]
struct SocketsSeen {
    /// The family, type, protocol and address length each open was asked
    /// for, and the descriptor it gave.
    opened: Vec<[c_int; 5]>,
    set: Vec<c_int>,
    closed: Vec<c_int>,
    answer: c_int,
    /// The port the opener points the address to, if not 0; the port the
    /// connecting configurer connects to.
    port: u16,
}

#[cfg(unix)]
unsafe extern "C" fn opener(
    data: *mut c_void,
    purpose: ffi::curlsocktype,
    address: *mut ffi::curl_sockaddr,
) -> ffi::curl_socket_t {
    // SAFETY: the test's data is a `SocketsSeen`; the address is live.
    let seen = unsafe { &mut *data.cast::<SocketsSeen>() };
    if seen.port != 0 {
        // SAFETY: the address is live, with room for its family's; the
        // port is at the same place in both.
        unsafe {
            let at = ptr::addr_of_mut!((*address).addr).cast::<libc::sockaddr_in>();
            (*at).sin_port = seen.port.to_be();
        }
    }
    // SAFETY: as above.
    let a = unsafe { &*address };
    assert_eq!(purpose, ffi::CURLSOCKTYPE_IPCXN);
    // SAFETY: the type and protocol asked for, as C's opener would.
    let fd = unsafe { libc::socket(a.family, a.socktype, a.protocol) };
    let addrlen = c_int::try_from(a.addrlen).unwrap();
    seen.opened
        .push([a.family, a.socktype, a.protocol, addrlen, fd]);
    fd
}

#[cfg(unix)]
unsafe extern "C" fn sockopt(
    data: *mut c_void,
    fd: ffi::curl_socket_t,
    _: ffi::curlsocktype,
) -> c_int {
    // SAFETY: the test's data is a `SocketsSeen`.
    let seen = unsafe { &mut *data.cast::<SocketsSeen>() };
    seen.set.push(fd);
    seen.answer
}

/// A configurer that connects the socket itself, to the port of its
/// data on this host, and says so.
#[cfg(unix)]
unsafe extern "C" fn connecting_sockopt(
    data: *mut c_void,
    fd: ffi::curl_socket_t,
    _: ffi::curlsocktype,
) -> c_int {
    // SAFETY: the test's data is a `SocketsSeen`.
    let seen = unsafe { &mut *data.cast::<SocketsSeen>() };
    seen.set.push(fd);
    let to = libc::sockaddr_in {
        #[cfg(target_vendor = "apple")]
        sin_len: 0,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: seen.port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
        },
        sin_zero: [0; 8],
    };
    let len = libc::socklen_t::try_from(size_of::<libc::sockaddr_in>()).unwrap();
    // SAFETY: the opener's socket is blocking, so the connect is made
    // before it returns; the address lives through the call.
    let rc = unsafe { libc::connect(fd, (&raw const to).cast(), len) };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    ffi::CURL_SOCKOPT_ALREADY_CONNECTED
}

#[cfg(unix)]
unsafe extern "C" fn closer(data: *mut c_void, fd: ffi::curl_socket_t) -> c_int {
    // SAFETY: the test's data is a `SocketsSeen`.
    let seen = unsafe { &mut *data.cast::<SocketsSeen>() };
    seen.closed.push(fd);
    // SAFETY: the closer owns the descriptor.
    unsafe { libc::close(fd) }
}

/// The socket functions are called with their data and with what C
/// gives them: the opener a close-on-exec TCP stream for the address's
/// family; a configurer's failure aborts the transfer, its socket closed
/// through the closer. A copy calls them with the data it was copied
/// with; a reset forgets them.
#[cfg(unix)]
#[test]
fn socket_functions_are_called_as_c_calls_them() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = std::ffi::CString::new(format!(
        "http://127.0.0.1:{}/",
        listener.local_addr().unwrap().port()
    ))
    .unwrap();
    let mut seen = SocketsSeen {
        answer: ffi::CURL_SOCKOPT_ERROR,
        ..SocketsSeen::default()
    };
    let c = curl_easy_init();
    let data: *mut SocketsSeen = &raw mut seen;
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    let o = opener as *const ();
    assert_eq!(function(c, ffi::CURLOPT_OPENSOCKETFUNCTION, o), CURLE_OK);
    assert_eq!(pointer(c, ffi::CURLOPT_OPENSOCKETDATA, data), CURLE_OK);
    let s = sockopt as *const ();
    assert_eq!(function(c, ffi::CURLOPT_SOCKOPTFUNCTION, s), CURLE_OK);
    assert_eq!(pointer(c, ffi::CURLOPT_SOCKOPTDATA, data), CURLE_OK);
    let x = closer as *const ();
    assert_eq!(function(c, ffi::CURLOPT_CLOSESOCKETFUNCTION, x), CURLE_OK);
    assert_eq!(pointer(c, ffi::CURLOPT_CLOSESOCKETDATA, data), CURLE_OK);
    // SAFETY: a live handle.
    let dup = unsafe { crate::easy::curl_easy_duphandle(c) };
    assert!(!dup.is_null());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_ABORTED_BY_CALLBACK);
    // The type C opens with: close-on-exec asked of it where the system
    // can be asked (`SOCK_CLOEXEC`), set after on macOS.
    #[cfg(target_os = "linux")]
    let stream = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    #[cfg(target_vendor = "apple")]
    let stream = libc::SOCK_STREAM;
    let fd = seen.opened[0][4];
    assert_eq!(
        seen.opened,
        [[libc::AF_INET, stream, libc::IPPROTO_TCP, 16, fd]]
    );
    assert_eq!((&seen.set[..], &seen.closed[..]), (&[fd][..], &[fd][..]));
    // The original's data changes; the copy keeps what it was made with.
    let mut other = SocketsSeen::default();
    let elsewhere: *mut SocketsSeen = &raw mut other;
    assert_eq!(pointer(c, ffi::CURLOPT_OPENSOCKETDATA, elsewhere), CURLE_OK);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(dup) }, CURLE_ABORTED_BY_CALLBACK);
    assert_eq!(
        (seen.opened.len(), seen.set.len(), seen.closed.len()),
        (2, 2, 2)
    );
    assert!(other.opened.is_empty());
    // A port nothing listens on, which the reset handle is refused at: port
    // 1, which no unprivileged test can bind, where a port picked free and
    // let go can be taken by a test running beside this one.
    let refused = std::ffi::CString::new("http://127.0.0.1:1/").unwrap();
    // SAFETY: live handles.
    unsafe {
        crate::easy::curl_easy_reset(dup);
        assert_eq!(
            pointer(dup, ffi::CURLOPT_URL, refused.as_ptr().cast_mut()),
            CURLE_OK
        );
        // Data alone brings back no function.
        assert_eq!(pointer(dup, ffi::CURLOPT_OPENSOCKETDATA, data), CURLE_OK);
        assert_eq!(curl_easy_perform(dup), ffi::CURLE_COULDNT_CONNECT);
    }
    assert_eq!(seen.opened.len(), 2, "a reset handle opens its own");
    // SAFETY: live handles, not used again.
    unsafe {
        curl_easy_cleanup(dup);
        curl_easy_cleanup(c);
    }
}

#[cfg(unix)]
const SERVED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// A handle performing a GET of `url` with the socket functions `hooks`
/// set, each with its data `seen`.
#[cfg(unix)]
fn perform_hooked(
    url: &str,
    hooks: &[(CURLoption, CURLoption, *const ())],
    seen: &mut SocketsSeen,
) -> CURLcode {
    let url = std::ffi::CString::new(url).unwrap();
    let c = curl_easy_init();
    let data: *mut SocketsSeen = seen;
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    let w = sink as WriteFn as *const ();
    assert_eq!(function(c, ffi::CURLOPT_WRITEFUNCTION, w), CURLE_OK);
    for &(f, d, hook) in hooks {
        assert_eq!(function(c, f, hook), CURLE_OK);
        assert_eq!(pointer(c, d, data), CURLE_OK);
    }
    // SAFETY: a live handle, not used again.
    unsafe {
        let code = curl_easy_perform(c);
        curl_easy_cleanup(c);
        code
    }
}

/// Each socket function is called set alone, as C calls whichever is
/// set; one set to NULL on a new handle makes nothing to keep. A
/// configurer's `CURL_SOCKOPT_OK` connects as usual; its
/// `CURL_SOCKOPT_ALREADY_CONNECTED` skips the connect it made itself
/// (`cf_socket_open`).
#[cfg(unix)]
#[test]
fn each_socket_function_is_called_alone() {
    let c = curl_easy_init();
    assert_eq!(
        function(c, ffi::CURLOPT_OPENSOCKETFUNCTION, ptr::null()),
        CURLE_OK
    );
    assert!(
        options(c, |o| o.sockets.made_mut().is_none()),
        "none set: no group"
    );
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    let (port, server) = serve(vec![SERVED; 4]);
    let url = format!("http://127.0.0.1:{port}/");
    let hooks = [
        (
            ffi::CURLOPT_OPENSOCKETFUNCTION,
            ffi::CURLOPT_OPENSOCKETDATA,
            opener as *const (),
        ),
        (
            ffi::CURLOPT_SOCKOPTFUNCTION,
            ffi::CURLOPT_SOCKOPTDATA,
            sockopt as *const (),
        ),
        (
            ffi::CURLOPT_CLOSESOCKETFUNCTION,
            ffi::CURLOPT_CLOSESOCKETDATA,
            closer as *const (),
        ),
    ];
    for (i, hook) in hooks.iter().enumerate() {
        let mut seen = SocketsSeen {
            answer: ffi::CURL_SOCKOPT_OK,
            ..SocketsSeen::default()
        };
        assert_eq!(perform_hooked(&url, &[*hook], &mut seen), CURLE_OK);
        let mut want = [0; 3];
        want[i] = 1;
        let calls = [seen.opened.len(), seen.set.len(), seen.closed.len()];
        assert_eq!(calls, want, "hook {i}");
    }
    let mut seen = SocketsSeen {
        port,
        ..SocketsSeen::default()
    };
    let connecting = (
        ffi::CURLOPT_SOCKOPTFUNCTION,
        ffi::CURLOPT_SOCKOPTDATA,
        connecting_sockopt as *const (),
    );
    // The opener's blocking socket, which the configurer connects.
    let code = perform_hooked(&url, &[hooks[0], connecting], &mut seen);
    assert_eq!(code, CURLE_OK);
    assert_eq!(seen.set, [seen.opened[0][4]]);
    assert_eq!(server.join().unwrap().len(), 4, "each reached the server");
}

/// An opener may point the address elsewhere, of either family, and the
/// socket connects there (`socket_open` hands it `ctx->addr`).
#[cfg(unix)]
#[test]
fn an_opener_may_change_the_port() {
    // A port nothing listens on, which the URL names.
    let unused = |at: &str| {
        let l = std::net::TcpListener::bind(at).unwrap();
        l.local_addr().unwrap().port()
    };
    let (port, server) = serve(vec![SERVED]);
    let mut seen = SocketsSeen {
        port,
        ..SocketsSeen::default()
    };
    let hook = (
        ffi::CURLOPT_OPENSOCKETFUNCTION,
        ffi::CURLOPT_OPENSOCKETDATA,
        opener as *const (),
    );
    let url = format!("http://127.0.0.1:{}/", unused("127.0.0.1:0"));
    assert_eq!(perform_hooked(&url, &[hook], &mut seen), CURLE_OK);
    assert_eq!(server.join().unwrap().len(), 1);
    let Ok(v6) = std::net::TcpListener::bind("[::1]:0") else {
        return;
    };
    let port = v6.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        use std::io::Write as _;
        let (mut peer, _) = v6.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let request = read_request(&mut peer);
        peer.write_all(SERVED).unwrap();
        request
    });
    let mut seen = SocketsSeen {
        port,
        ..SocketsSeen::default()
    };
    let url = format!("http://[::1]:{}/", unused("[::1]:0"));
    assert_eq!(perform_hooked(&url, &[hook], &mut seen), CURLE_OK);
    assert_eq!(seen.opened[0][0], libc::AF_INET6);
    assert!(server.join().unwrap().starts_with(b"GET / HTTP/1.1\r\n"));
}

/// The keepalive times and count are held to C's range: negative is
/// refused, past `INT_MAX` is `INT_MAX`; a TCP option at its default
/// makes no group, as most handles set none.
#[test]
fn tcp_options_are_held_to_c_s_range() {
    use curl_core::options::KeepAlive;
    let c = curl_easy_init();
    for o in [
        ffi::CURLOPT_TCP_KEEPIDLE,
        ffi::CURLOPT_TCP_KEEPINTVL,
        ffi::CURLOPT_TCP_KEEPCNT,
    ] {
        assert_eq!(long(c, o, -1), CURLE_BAD_FUNCTION_ARGUMENT);
    }
    assert_eq!(long(c, ffi::CURLOPT_TCP_NODELAY, 1), CURLE_OK);
    assert_eq!(long(c, ffi::CURLOPT_TCP_KEEPALIVE, 0), CURLE_OK);
    assert!(
        options(c, |o| o.sockets.made_mut().is_none()),
        "defaults: no group"
    );
    assert_eq!(long(c, ffi::CURLOPT_TCP_KEEPIDLE, c_long::MAX), CURLE_OK);
    assert_eq!(long(c, ffi::CURLOPT_TCP_KEEPINTVL, 7), CURLE_OK);
    assert_eq!(long(c, ffi::CURLOPT_TCP_KEEPCNT, 3), CURLE_OK);
    assert_eq!(long(c, ffi::CURLOPT_TCP_KEEPALIVE, 2), CURLE_OK);
    assert_eq!(long(c, ffi::CURLOPT_TCP_NODELAY, 0), CURLE_OK);
    #[cfg(not(windows))]
    assert_eq!(long(c, ffi::CURLOPT_TCP_FASTOPEN, 1), CURLE_OK);
    // Refused where C cannot connect with data.
    #[cfg(windows)]
    assert_eq!(
        long(c, ffi::CURLOPT_TCP_FASTOPEN, 1),
        ffi::CURLE_NOT_BUILT_IN
    );
    let max = Duration::from_secs(i32::MAX.unsigned_abs().into());
    options(c, |o| {
        let s = o.sockets.made_mut().expect("made by a value set");
        assert_eq!(
            s.keepalive,
            KeepAlive {
                on: true,
                idle: max,
                interval: Duration::from_secs(7),
                count: 3,
            }
        );
        assert!(!s.nodelay && s.fastopen == cfg!(not(windows)));
    });
    // 0 is in the range.
    for o in [
        ffi::CURLOPT_TCP_KEEPIDLE,
        ffi::CURLOPT_TCP_KEEPINTVL,
        ffi::CURLOPT_TCP_KEEPCNT,
    ] {
        assert_eq!(long(c, o, 0), CURLE_OK);
    }
    options(c, |o| {
        let k = o.sockets.made_mut().expect("made").keepalive;
        assert_eq!(
            (k.idle, k.interval, k.count),
            (Duration::ZERO, Duration::ZERO, 0)
        );
    });
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// An interface is read for its syntax as it is set, empty unsetting it,
/// and the local port and range are held to the ports
/// (`setstropt_interface`, `CURLOPT_LOCALPORT`).
#[test]
fn a_local_end_is_read_as_c_reads_it() {
    use curl_core::options::{Interface, LocalBind};
    let c = curl_easy_init();
    let set = |text: &CStr| pointer(c, ffi::CURLOPT_INTERFACE, text.as_ptr().cast_mut());
    for bad in [c"if!", c"host!", c"ifhost!eth0", c"ifhost!eth0!"] {
        assert_eq!(set(bad), CURLE_BAD_FUNCTION_ARGUMENT, "{bad:?}");
    }
    assert!(
        options(c, |o| o.sockets.made_mut().is_none()),
        "nothing refused is kept"
    );
    for range in [ffi::CURLOPT_LOCALPORT, ffi::CURLOPT_LOCALPORTRANGE] {
        assert_eq!(long(c, range, -1), CURLE_BAD_FUNCTION_ARGUMENT);
        assert_eq!(long(c, range, 65536), CURLE_BAD_FUNCTION_ARGUMENT);
    }
    assert_eq!(set(c"ifhost!eth0!10.0.0.1"), CURLE_OK);
    assert_eq!(long(c, ffi::CURLOPT_LOCALPORT, 65535), CURLE_OK);
    assert_eq!(long(c, ffi::CURLOPT_LOCALPORTRANGE, 3), CURLE_OK);
    options(c, |o| {
        let s = o.sockets.made_mut().expect("made by a value set");
        assert_eq!(
            s.local,
            LocalBind {
                interface: Some(Interface::InterfaceHost {
                    interface: b"eth0".to_vec(),
                    host: b"10.0.0.1".to_vec(),
                }),
                port: 65535,
                port_range: 3,
            }
        );
    });
    assert_eq!(set(c""), CURLE_OK);
    options(c, |o| {
        assert_eq!(o.sockets.made_mut().expect("made").local.interface, None);
    });
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLMOPT_RESOLVE_THREADS_MAX` is taken by a build with the threaded
/// resolver, which refuses 0, negative and past `UINT32_MAX`; another
/// build takes any. `CURLMOPT_QUICK_EXIT` and `CURLOPT_QUICK_EXIT` are
/// taken by either.
#[test]
fn the_resolver_s_options_are_the_build_s() {
    let m = curl_multi_init();
    let set = |o, n: c_long| {
        // SAFETY: a live multi and a `long` option.
        unsafe { curl_multi_setopt(m, o, n) }
    };
    let refused = match cfg!(feature = "threaded-resolver") {
        true => ffi::CURLM_BAD_FUNCTION_ARGUMENT,
        false => CURLM_OK,
    };
    for (n, code) in [(0, refused), (-1, refused), (1, CURLM_OK), (5, CURLM_OK)] {
        assert_eq!(set(ffi::CURLMOPT_RESOLVE_THREADS_MAX, n), code, "{n}");
    }
    // Where a `long` reaches past `u32::MAX`: Windows' does not.
    #[cfg(not(windows))]
    for (n, code) in [
        (c_long::from(u32::MAX), CURLM_OK),
        (c_long::from(u32::MAX) + 1, refused),
    ] {
        assert_eq!(set(ffi::CURLMOPT_RESOLVE_THREADS_MAX, n), code, "{n}");
    }
    assert_eq!(set(ffi::CURLMOPT_QUICK_EXIT, 1), CURLM_OK);
    assert_eq!(set(ffi::CURLMOPT_QUICK_EXIT, 0), CURLM_OK);
    let c = curl_easy_init();
    let quick = || {
        // SAFETY: a live handle.
        let easy = unsafe { crate::easy::handle(c) }.unwrap();
        easy.with_options(|o| o.quick_exit).unwrap()
    };
    assert!(!quick());
    assert_eq!(long(c, ffi::CURLOPT_QUICK_EXIT, 1), CURLE_OK);
    assert!(quick());
    assert_eq!(long(c, ffi::CURLOPT_QUICK_EXIT, 0), CURLE_OK);
    assert!(!quick());
    // SAFETY: live handles, cleaned up once.
    unsafe {
        curl_easy_cleanup(c);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
}

/// `CURLHSTS_READONLYFILE` keeps the HSTS file from being written as the
/// handle goes, and enabling again without it lets it be. C tests the
/// flag but never sets it, so writes the file back (DIVERGENCE.md).
#[test]
fn a_read_only_hsts_file_is_not_written() {
    let path = std::env::temp_dir().join(format!("curl-abi-hsts-ro-{}", std::process::id()));
    let text = "# kept as it is\n";
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    for (bits, written) in [
        (ffi::CURLHSTS_ENABLE | ffi::CURLHSTS_READONLYFILE, false),
        (ffi::CURLHSTS_ENABLE, true),
    ] {
        std::fs::write(&path, text).unwrap();
        let c = curl_easy_init();
        assert_eq!(long(c, ffi::CURLOPT_HSTS_CTRL, bits), CURLE_OK);
        assert_eq!(
            pointer(c, ffi::CURLOPT_HSTS, name.as_ptr().cast_mut()),
            CURLE_OK
        );
        // SAFETY: a live handle, not used again.
        unsafe { curl_easy_cleanup(c) };
        let now = std::fs::read_to_string(&path).unwrap();
        assert_eq!(now != text, written, "{bits}: {now}");
    }
    std::fs::remove_file(&path).unwrap();
}

/// The HSTS reader a copy of the handle calls as it is made is handed the
/// copy, as C's `curl_easy_duphandle` hands it `outcurl`, and so are the
/// copy's transfers, after the original is gone.
#[test]
fn a_copy_s_hsts_reader_is_handed_the_copy() {
    unsafe extern "C" fn read(
        easy: *mut CURL,
        _e: *mut ffi::curl_hstsentry,
        data: *mut c_void,
    ) -> ffi::CURLSTScode {
        // SAFETY: the test's vector, alive through the calls.
        unsafe { &mut *data.cast::<Vec<usize>>() }.push(easy as usize);
        ffi::CURLSTS_DONE
    }
    let mut seen: Vec<usize> = Vec::new();
    let c = curl_easy_init();
    let f: ffi::curl_hstsread_callback = Some(read);
    assert_eq!(
        long(c, ffi::CURLOPT_HSTS_CTRL, ffi::CURLHSTS_ENABLE),
        CURLE_OK
    );
    // SAFETY: a function of the option's type.
    let fp = unsafe { core::mem::transmute::<ffi::curl_hstsread_callback, *mut c_void>(f) };
    assert_eq!(pointer(c, ffi::CURLOPT_HSTSREADFUNCTION, fp), CURLE_OK);
    let data: *mut Vec<usize> = &mut seen;
    assert_eq!(pointer(c, ffi::CURLOPT_HSTSREADDATA, data), CURLE_OK);
    // SAFETY: a live handle.
    let d = unsafe { easy::curl_easy_duphandle(c) };
    assert!(!d.is_null());
    assert_eq!(seen, [d as usize]);
    // The copy's transfers call through the copy, the original gone.
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(d, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(d) }, ffi::CURLE_COULDNT_CONNECT);
    assert_eq!(seen, [d as usize, d as usize]);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(d) };
}

/// `CURLOPT_ALTSVC_CTRL` refuses no bits at all; with
/// `CURLALTSVC_READONLYFILE` the file `CURLOPT_ALTSVC` names is read and
/// not written as the handle goes, and without it, it is.
#[test]
fn alt_svc_options_read_and_write_the_file() {
    let c = curl_easy_init();
    assert_eq!(
        long(c, ffi::CURLOPT_ALTSVC_CTRL, 0),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    let path = std::env::temp_dir().join(format!("curl-abi-altsvc-{}", std::process::id()));
    let text = "h1 a.example 443 h1 b.example 443 \"20991231 00:00:00\" 0 0\n";
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    for (bits, written) in [
        (ffi::CURLALTSVC_H1 | ffi::CURLALTSVC_READONLYFILE, false),
        (ffi::CURLALTSVC_H1, true),
    ] {
        std::fs::write(&path, text).unwrap();
        let c = curl_easy_init();
        assert_eq!(long(c, ffi::CURLOPT_ALTSVC_CTRL, bits), CURLE_OK);
        assert_eq!(
            pointer(c, ffi::CURLOPT_ALTSVC, name.as_ptr().cast_mut()),
            CURLE_OK
        );
        // SAFETY: a live handle, not used again.
        unsafe { curl_easy_cleanup(c) };
        let now = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            now.starts_with("# Your alt-svc cache."),
            written,
            "{bits}: {now}"
        );
        // The entry read survives the write.
        assert!(now.contains("h1 a.example 443 h1 b.example 443"), "{now}");
    }
    std::fs::remove_file(&path).unwrap();
}

/// `CURLOPT_CONNECT_ONLY` takes 0, 1 and 2; a perform with it connects
/// and stops, the socket told by `CURLINFO_ACTIVESOCKET` and
/// `CURLINFO_LASTSOCKET`, and `curl_easy_send` and `curl_easy_recv` talk
/// on it.
#[test]
fn a_connect_only_perform_leaves_the_connection_to_the_handle() {
    use crate::easy::{curl_easy_recv, curl_easy_send};
    let c = curl_easy_init();
    for (n, code) in [
        (3, CURLE_BAD_FUNCTION_ARGUMENT),
        (-1, CURLE_BAD_FUNCTION_ARGUMENT),
        (2, CURLE_OK),
        (0, CURLE_OK),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_CONNECT_ONLY, n), code, "{n}");
    }
    let (port, server) = serve(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]);
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_CONNECT_ONLY, 1), CURLE_OK);
    let mut active: ffi::curl_socket_t = 0;
    let mut last: c_long = 0;
    // SAFETY: a live handle, and pointers to values of the infos' types.
    unsafe {
        assert_eq!(
            curl_easy_getinfo(c, ffi::CURLINFO_ACTIVESOCKET, &raw mut active),
            CURLE_OK
        );
        assert_eq!(active, ffi::CURL_SOCKET_BAD, "none before a transfer");
        assert_eq!(curl_easy_perform(c), CURLE_OK);
        assert_eq!(
            curl_easy_getinfo(c, ffi::CURLINFO_ACTIVESOCKET, &raw mut active),
            CURLE_OK
        );
        assert_eq!(
            curl_easy_getinfo(c, ffi::CURLINFO_LASTSOCKET, &raw mut last),
            CURLE_OK
        );
    }
    assert_ne!(active, ffi::CURL_SOCKET_BAD);
    // The last socket is the active one, cast to a `long` as C casts it.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let as_long = active as c_long;
    assert_eq!(as_long, last);
    let request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    let mut n = 0;
    // SAFETY: a live handle, the request's bytes and a count to write.
    let sent = unsafe { curl_easy_send(c, request.as_ptr().cast(), request.len(), &raw mut n) };
    assert_eq!((sent, n), (CURLE_OK, request.len()));
    let mut got = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !got.ends_with(b"ok") && std::time::Instant::now() < deadline {
        let mut buf = [0u8; 64];
        // SAFETY: a live handle, a buffer of 64 bytes and a count to write.
        match unsafe { curl_easy_recv(c, buf.as_mut_ptr().cast(), buf.len(), &raw mut n) } {
            CURLE_OK => got.extend_from_slice(&buf[..n]),
            ffi::CURLE_AGAIN => std::thread::sleep(Duration::from_millis(5)),
            code => panic!("{code:?}"),
        }
    }
    assert!(
        got.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "{}",
        String::from_utf8_lossy(&got)
    );
    assert_eq!(server.join().unwrap(), [request.to_vec()]);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// An entry an HSTS write function was given: its name, `namelen`, date,
/// reach, index and the number of entries.
type HstsWritten = (Vec<u8>, usize, Vec<u8>, bool, usize, usize);

/// What the HSTS functions of a test do and saw.
struct HstsSeen {
    /// The entries to give, last first, each a name, a date and whether
    /// its subdomains are included; then `last` is answered.
    give: Vec<(Vec<u8>, Vec<u8>, bool)>,
    last: ffi::CURLSTScode,
    /// Each entry written: its name, `namelen`, date, reach and index.
    written: Vec<HstsWritten>,
    /// What the write function answers each call, in turn.
    answers: Vec<ffi::CURLSTScode>,
}

impl Default for HstsSeen {
    fn default() -> Self {
        HstsSeen {
            give: Vec::new(),
            last: ffi::CURLSTS_DONE,
            written: Vec::new(),
            answers: Vec::new(),
        }
    }
}

unsafe extern "C" fn hsts_give(
    _easy: *mut CURL,
    e: *mut ffi::curl_hstsentry,
    data: *mut c_void,
) -> ffi::CURLSTScode {
    // SAFETY: the test's state and the entry lent, alive through the call.
    let (seen, e) = unsafe { (&mut *data.cast::<HstsSeen>(), &mut *e) };
    let Some((name, date, subdomains)) = seen.give.pop() else {
        return seen.last;
    };
    // SAFETY: the name has room for `namelen` bytes and its NUL, and the
    // test gives no more.
    let room = unsafe { core::slice::from_raw_parts_mut(e.name.cast::<u8>(), e.namelen + 1) };
    room[..name.len()].copy_from_slice(&name);
    for (to, b) in e.expire.iter_mut().zip(date) {
        *to = b as c_char;
    }
    e.set_includeSubDomains(subdomains);
    ffi::CURLSTS_OK
}

unsafe extern "C" fn hsts_take(
    _easy: *mut CURL,
    e: *mut ffi::curl_hstsentry,
    i: *mut ffi::curl_index,
    data: *mut c_void,
) -> ffi::CURLSTScode {
    // SAFETY: the test's state, the entry and the index lent, alive
    // through the call.
    let (seen, e, i) = unsafe { (&mut *data.cast::<HstsSeen>(), &*e, &*i) };
    // SAFETY: the name holds `namelen` bytes.
    let name = unsafe { core::slice::from_raw_parts(e.name.cast::<u8>(), e.namelen) };
    let date = e
        .expire
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| u8::from_ne_bytes(b.to_ne_bytes()))
        .collect();
    seen.written.push((
        name.to_vec(),
        e.namelen,
        date,
        e.includeSubDomains(),
        i.index,
        i.total,
    ));
    if seen.answers.is_empty() {
        ffi::CURLSTS_OK
    } else {
        seen.answers.remove(0)
    }
}

/// A handle with the HSTS cache on, reading and writing it through the
/// test's functions with `seen`, and a URL to a port nothing listens on:
/// port 1, which no unprivileged test can bind, where a port picked free
/// and let go can be taken by a test running beside it.
fn hsts_handle(seen: &mut HstsSeen) -> (*mut CURL, std::ffi::CString) {
    let url = std::ffi::CString::new("http://127.0.0.1:1/").unwrap();
    let c = curl_easy_init();
    assert_eq!(
        long(c, ffi::CURLOPT_HSTS_CTRL, ffi::CURLHSTS_ENABLE),
        CURLE_OK
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    let give: ffi::curl_hstsread_callback = Some(hsts_give);
    let take: ffi::curl_hstswrite_callback = Some(hsts_take);
    // SAFETY: functions of the options' types.
    let (give, take) = unsafe {
        (
            core::mem::transmute::<ffi::curl_hstsread_callback, *mut c_void>(give),
            core::mem::transmute::<ffi::curl_hstswrite_callback, *mut c_void>(take),
        )
    };
    let data: *mut HstsSeen = seen;
    for (option, p) in [
        (ffi::CURLOPT_HSTSREADFUNCTION, give),
        (ffi::CURLOPT_HSTSREADDATA, data.cast()),
        (ffi::CURLOPT_HSTSWRITEFUNCTION, take),
        (ffi::CURLOPT_HSTSWRITEDATA, data.cast()),
    ] {
        assert_eq!(pointer(c, option, p), CURLE_OK);
    }
    (c, url)
}

/// The read function's entries are taken, a name as long as C allows
/// among them, and given to the write function as the handle goes, with
/// their places, until it says to stop.
#[test]
fn hsts_functions_read_and_write_the_cache() {
    let long = vec![b'a'; 2048];
    let mut seen = HstsSeen {
        give: vec![
            (b"b.example".to_vec(), b"".to_vec(), true),
            (long.clone(), b"20991231 00:00:00".to_vec(), false),
        ],
        last: ffi::CURLSTS_DONE,
        ..HstsSeen::default()
    };
    let (c, _url) = hsts_handle(&mut seen);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, ffi::CURLE_COULDNT_CONNECT);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    assert_eq!(
        seen.written,
        [
            (
                long.clone(),
                2048,
                b"20991231 00:00:00".to_vec(),
                false,
                0,
                2
            ),
            (b"b.example".to_vec(), 9, b"unlimited".to_vec(), true, 1, 2),
        ]
    );
    // A write function that says it is done is called no more.
    let mut seen = HstsSeen {
        give: vec![
            (b"b.example".to_vec(), b"".to_vec(), false),
            (b"a.example".to_vec(), b"".to_vec(), false),
        ],
        last: ffi::CURLSTS_DONE,
        answers: vec![ffi::CURLSTS_DONE],
        ..HstsSeen::default()
    };
    let (c, _url) = hsts_handle(&mut seen);
    // SAFETY: as above.
    unsafe {
        assert_eq!(curl_easy_perform(c), ffi::CURLE_COULDNT_CONNECT);
        curl_easy_cleanup(c);
    }
    assert_eq!(seen.written.len(), 1);
}

/// A read function that fails the transfer aborts it; one that gives no
/// name, a name filling its room to the last byte, or a date filling
/// its, is a bad argument.
#[test]
fn hsts_read_function_errors_fail_the_transfer() {
    let full_name = vec![b'n'; 2049];
    let full_date = vec![b'1'; 18];
    let cases = [
        (vec![], ffi::CURLSTS_FAIL, ffi::CURLE_ABORTED_BY_CALLBACK),
        (
            vec![(b"".to_vec(), b"".to_vec(), false)],
            ffi::CURLSTS_DONE,
            CURLE_BAD_FUNCTION_ARGUMENT,
        ),
        (
            vec![(full_name, b"".to_vec(), false)],
            ffi::CURLSTS_DONE,
            CURLE_BAD_FUNCTION_ARGUMENT,
        ),
        (
            vec![(b"x".to_vec(), full_date, false)],
            ffi::CURLSTS_DONE,
            CURLE_BAD_FUNCTION_ARGUMENT,
        ),
    ];
    for (give, last, code) in cases {
        let mut seen = HstsSeen {
            give,
            last,
            ..HstsSeen::default()
        };
        let (c, _url) = hsts_handle(&mut seen);
        // SAFETY: a live handle, not used again.
        unsafe {
            assert_eq!(curl_easy_perform(c), code);
            curl_easy_cleanup(c);
        }
    }
}

/// Escaping and unescaping as C's `lib/escape.c`: letters, digits and
/// `-._~` kept, every other byte `%XX` in capitals; a zero length reads
/// to the NUL, a negative one or NULL gives NULL; unescaping takes any
/// byte, says the length, and leaves a `%` not followed by two hex digits.
#[test]
fn strings_escape_and_unescape_as_c_does() {
    use crate::root::curl_free;
    use crate::strings::{curl_easy_escape, curl_easy_unescape, curl_escape, curl_unescape};
    let text = |p: *mut c_char| {
        assert!(!p.is_null());
        // SAFETY: a C string the library made, freed once read.
        let s = unsafe { CStr::from_ptr(p) }.to_bytes().to_vec();
        // SAFETY: as above.
        unsafe { curl_free(p.cast()) };
        s
    };
    // SAFETY: C strings and lengths within them.
    unsafe {
        assert_eq!(
            text(curl_easy_escape(ptr::null_mut(), c"a b/~é".as_ptr(), 0)),
            b"a%20b%2F~%C3%A9"
        );
        assert_eq!(text(curl_escape(b"a\0b".as_ptr().cast(), 3)), b"a%00b");
        assert_eq!(text(curl_escape(c"".as_ptr(), 0)), b"");
        assert!(curl_escape(c"x".as_ptr(), -1).is_null());
        assert!(curl_escape(ptr::null(), 0).is_null());
        let mut n: c_int = -1;
        let p = curl_easy_unescape(ptr::null_mut(), c"a%20b%00c%4".as_ptr(), 0, &raw mut n);
        assert_eq!(n, 7);
        // SAFETY: the decoded bytes and their NUL.
        let decoded = core::slice::from_raw_parts(p.cast::<u8>(), 8).to_vec();
        curl_free(p.cast());
        assert_eq!(decoded, b"a b\0c%4\0");
        assert_eq!(text(curl_unescape(c"%41%4a%gg%".as_ptr(), 0)), b"AJ%gg%");
        assert!(curl_unescape(c"x".as_ptr(), -1).is_null());
    }
}

/// `curl_multi_get_handles` gives the handles in the order they joined,
/// then NULL; `curl_multi_socket_all` runs them as a perform does, and
/// `curl_multi_socket` as `curl_multi_socket_action`; `curl_easy_upkeep`
/// has nothing to do, and refuses NULL.
#[test]
fn multi_handles_and_old_socket_calls() {
    use crate::easy::curl_easy_upkeep;
    use crate::multi::{curl_multi_get_handles, curl_multi_socket, curl_multi_socket_all};
    use crate::root::curl_free;
    let m = curl_multi_init();
    let (a, b) = (curl_easy_init(), curl_easy_init());
    // SAFETY: a live multi and handles, and an `int` to write.
    unsafe {
        let empty = curl_multi_get_handles(m);
        assert!((*empty).is_null());
        curl_free(empty.cast());
        assert_eq!(curl_multi_add_handle(m, b), CURLM_OK);
        assert_eq!(curl_multi_add_handle(m, a), CURLM_OK);
        let list = curl_multi_get_handles(m);
        assert_eq!([*list, *list.add(1), *list.add(2)], [b, a, ptr::null_mut()]);
        curl_free(list.cast());
        let mut running: c_int = -1;
        // Neither has a URL: both fail at once, as in a perform.
        assert_eq!(curl_multi_socket_all(m, &raw mut running), CURLM_OK);
        assert_eq!(running, 0);
        running = -1;
        assert_eq!(
            curl_multi_socket(m, ffi::CURL_SOCKET_TIMEOUT, &raw mut running),
            CURLM_OK
        );
        assert_eq!(running, 0);
        assert_eq!(curl_easy_upkeep(a), CURLE_OK);
        assert_eq!(
            curl_easy_upkeep(ptr::null_mut()),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
        assert!(curl_multi_get_handles(ptr::null_mut()).is_null());
        for h in [a, b] {
            assert_eq!(curl_multi_remove_handle(m, h), CURLM_OK);
            curl_easy_cleanup(h);
        }
        curl_multi_cleanup(m);
    }
}

/// SMTP's options reach the handle: the sender and the submitter as
/// strings, the recipients as the application's list, walked again as
/// each mail is sent, and whether refused ones are let pass.
#[test]
fn the_mail_options_reach_the_handle() {
    let c = curl_easy_init();
    let mail = |c| {
        options(c, |o| {
            let l = &o.line;
            let rcpt: Vec<_> = l.mail_rcpt.iter().map(<[u8]>::to_vec).collect();
            (
                l.mail_from.clone(),
                rcpt,
                l.mail_rcpt_allowfails,
                l.mail_auth.clone(),
            )
        })
    };
    assert_eq!(mail(c), (None, vec![], false, None));
    let from = c"<f@a>";
    let auth = c"u@b";
    assert_eq!(
        pointer(c, ffi::CURLOPT_MAIL_FROM, from.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_MAIL_AUTH, auth.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_MAIL_RCPT_ALLOWFAILS, 2), CURLE_OK);
    let mut list = ptr::null_mut();
    for line in [c"r@c", c"s@d"] {
        // SAFETY: a list made here, and a C string.
        list = unsafe { crate::strings::curl_slist_append(list, line.as_ptr()) };
    }
    assert_eq!(pointer(c, ffi::CURLOPT_MAIL_RCPT, list), CURLE_OK);
    let rcpt = vec![b"r@c".to_vec(), b"s@d".to_vec()];
    assert_eq!(
        mail(c),
        (Some(b"<f@a>".to_vec()), rcpt, true, Some(b"u@b".to_vec()))
    );
    assert_eq!(long(c, ffi::CURLOPT_MAIL_RCPT_ALLOWFAILS, 0), CURLE_OK);
    assert_eq!(
        pointer(c, ffi::CURLOPT_MAIL_RCPT, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    // SAFETY: the list made above, which the handle no longer keeps.
    unsafe { crate::strings::curl_slist_free_all(list) };
    for o in [ffi::CURLOPT_MAIL_FROM, ffi::CURLOPT_MAIL_AUTH] {
        assert_eq!(pointer(c, o, ptr::null_mut::<c_char>()), CURLE_OK);
    }
    assert_eq!(mail(c), (None, vec![], false, None));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// The wildcard download's options: the switch, and an adapter for each
/// function set, its data kept beside it; a copy of the handle has them,
/// and a reset drops them (`Curl_init_userdefined`).
#[test]
fn the_wildcard_options_are_kept_copied_and_reset() {
    unsafe extern "C" fn begin(_: *const c_void, _: *mut c_void, _: c_int) -> c_long {
        0
    }
    unsafe extern "C" fn end(_: *mut c_void) -> c_long {
        0
    }
    unsafe extern "C" fn matches(_: *mut c_void, _: *const c_char, _: *const c_char) -> c_int {
        0
    }
    type Begin = unsafe extern "C" fn(*const c_void, *mut c_void, c_int) -> c_long;
    type End = unsafe extern "C" fn(*mut c_void) -> c_long;
    type Matches = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> c_int;
    let installed = |c| {
        options(c, |o| {
            let ftp = &o.line.ftp;
            [
                ftp.wildcard,
                ftp.chunk_begin.is_some(),
                ftp.chunk_end.is_some(),
                ftp.fnmatch.is_some(),
            ]
        })
    };
    let c = curl_easy_init();
    assert_eq!(installed(c), [false; 4]);
    assert_eq!(long(c, ffi::CURLOPT_WILDCARDMATCH, 1), CURLE_OK);
    assert_eq!(installed(c), [true, false, false, false]);
    let mut chunk = 0u8;
    let mut matching = 0u8;
    assert_eq!(
        pointer(c, ffi::CURLOPT_CHUNK_DATA, &raw mut chunk),
        CURLE_OK
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_FNMATCH_DATA, &raw mut matching),
        CURLE_OK
    );
    let fs = [
        (ffi::CURLOPT_CHUNK_BGN_FUNCTION, begin as Begin as *const ()),
        (ffi::CURLOPT_CHUNK_END_FUNCTION, end as End as *const ()),
        (
            ffi::CURLOPT_FNMATCH_FUNCTION,
            matches as Matches as *const (),
        ),
    ];
    for (o, f) in fs {
        assert_eq!(function(c, o, f), CURLE_OK);
    }
    assert_eq!(installed(c), [true; 4]);
    // SAFETY: a live handle.
    let d = unsafe { easy::curl_easy_duphandle(c) };
    assert!(!d.is_null());
    assert_eq!(installed(d), [true; 4]);
    // SAFETY: both live handles.
    let (kept, copied) = unsafe { (easy::handle(c), easy::handle(d)) };
    let (kept, copied) = (kept.unwrap().wildcard(), copied.unwrap().wildcard());
    assert_eq!(copied.chunk_data, (&raw mut chunk).cast::<c_void>());
    assert_eq!(copied.fnmatch_data, kept.fnmatch_data);
    assert_eq!(
        function(d, ffi::CURLOPT_CHUNK_END_FUNCTION, ptr::null()),
        CURLE_OK
    );
    assert_eq!(installed(d), [true, true, false, true]);
    assert_eq!(installed(c), [true; 4]);
    // SAFETY: a live handle.
    unsafe { easy::curl_easy_reset(c) };
    assert_eq!(installed(c), [false; 4]);
    // SAFETY: a live handle.
    let reset = unsafe { easy::handle(c) }.unwrap().wildcard();
    assert!(reset.chunk_data.is_null() && reset.fnmatch.is_none());
    // SAFETY: live handles, not used again.
    unsafe {
        curl_easy_cleanup(c);
        curl_easy_cleanup(d);
    }
}

/// RTSP's interleave function and data: an adapter while a function is
/// set, the data kept beside it; a copy of the handle has them, its own
/// adapter calling for it, and a reset drops them. RTSP's numbers are
/// the handle's, kept through a reset and not copied.
#[test]
fn the_interleave_options_are_kept_copied_and_reset() {
    unsafe extern "C" fn rtp(_: *mut c_char, _: usize, n: usize, _: *mut c_void) -> usize {
        n
    }
    let installed = |c| options(c, |o| o.small.interleave.is_some());
    let c = curl_easy_init();
    assert!(!installed(c));
    let mut data = 0u8;
    assert_eq!(
        pointer(c, ffi::CURLOPT_INTERLEAVEDATA, &raw mut data),
        CURLE_OK
    );
    assert!(!installed(c), "data alone sends RTP to the write function");
    assert_eq!(
        function(
            c,
            ffi::CURLOPT_INTERLEAVEFUNCTION,
            rtp as WriteFn as *const ()
        ),
        CURLE_OK
    );
    assert!(installed(c));
    assert_eq!(long(c, ffi::CURLOPT_RTSP_CLIENT_CSEQ, 9), CURLE_OK);
    // SAFETY: a live handle.
    let d = unsafe { easy::curl_easy_duphandle(c) };
    assert!(!d.is_null());
    assert!(installed(d));
    // SAFETY: both live handles.
    let (kept, copied) = unsafe { (easy::handle(c), easy::handle(d)) };
    let (kept, copied) = (kept.unwrap(), copied.unwrap());
    assert_eq!(copied.interleave().data, (&raw mut data).cast::<c_void>());
    assert!(copied.interleave().function.is_some());
    assert_eq!(
        copied.rtsp().ok().map(|r| r.next_client_cseq()),
        Some(0),
        "not copied"
    );
    assert_eq!(
        function(d, ffi::CURLOPT_INTERLEAVEFUNCTION, ptr::null()),
        CURLE_OK
    );
    assert!(!installed(d));
    assert!(installed(c));
    // SAFETY: a live handle.
    unsafe { easy::curl_easy_reset(c) };
    assert!(!installed(c));
    let reset = kept.interleave();
    assert!(reset.data.is_null() && reset.function.is_none());
    assert_eq!(
        kept.rtsp().ok().map(|r| r.next_client_cseq()),
        Some(9),
        "kept"
    );
    // SAFETY: live handles, not used again.
    unsafe {
        curl_easy_cleanup(c);
        curl_easy_cleanup(d);
    }
}

/// A WebSocket a perform only connected is the handle's through C's
/// calls: frames received with what they are, `curl_ws_meta` empty
/// outside a callback, and frames of each kind sent as the flags say.
#[test]
fn a_websocket_only_connected_talks_through_the_c_calls() {
    use crate::ffi::{CURLWS_BINARY, CURLWS_CLOSE, CURLWS_OFFSET, CURLWS_PING, CURLWS_TEXT};
    use crate::ws::{curl_ws_meta, curl_ws_recv, curl_ws_send};
    use std::io::{Read as _, Write as _};
    // The text frame's head and payload, three empty frames, then two
    // bytes sent raw.
    const SENT: usize = 6 + 3 + 3 * 6 + 2;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _request = read_request(&mut peer);
        peer.write_all(
            b"HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\
\x81\x03txt\x82\x02bi",
        )
        .unwrap();
        let mut got = vec![0u8; SENT];
        peer.read_exact(&mut got).unwrap();
        got
    });
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("ws://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_CONNECT_ONLY, 2), CURLE_OK);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let recv = |want: usize| {
        let mut buf = [0u8; 16];
        let mut n = 0;
        let mut meta: *const ffi::curl_ws_frame = ptr::null();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            // SAFETY: a live handle, a buffer of its length, and where
            // the count and the frame go.
            let got = unsafe {
                curl_ws_recv(
                    c,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    &raw mut n,
                    &raw mut meta,
                )
            };
            if got == CURLE_OK {
                break;
            }
            assert_eq!(got, ffi::CURLE_AGAIN);
            assert!(std::time::Instant::now() < deadline, "no frame came");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(n, want);
        assert!(!meta.is_null());
        // SAFETY: the handle's frame, valid until its next call.
        let frame = unsafe { *meta };
        (
            buf[..n].to_vec(),
            frame.flags,
            frame.offset,
            frame.bytesleft,
            frame.len,
        )
    };
    assert_eq!(recv(3), (b"txt".to_vec(), CURLWS_TEXT, 0, 0, 3));
    assert_eq!(recv(2), (b"bi".to_vec(), CURLWS_BINARY, 0, 0, 2));
    // SAFETY: a live handle.
    assert!(unsafe { curl_ws_meta(c) }.is_null(), "outside a callback");
    let send = |bytes: &[u8], fragsize: ffi::curl_off_t, flags: c_int| {
        let mut n = 0;
        // SAFETY: a live handle, the bytes and where their count goes.
        let sent = unsafe {
            curl_ws_send(
                c,
                bytes.as_ptr().cast(),
                bytes.len(),
                &raw mut n,
                fragsize,
                flags as c_uint,
            )
        };
        (sent, n)
    };
    assert_eq!(send(b"", 3, CURLWS_TEXT | CURLWS_OFFSET), (CURLE_OK, 0));
    assert_eq!(send(b"abc", 0, CURLWS_TEXT), (CURLE_OK, 3));
    for flags in [CURLWS_BINARY, CURLWS_PING, CURLWS_CLOSE] {
        assert_eq!(send(b"", 0, flags), (CURLE_OK, 0), "{flags:x}");
    }
    // Raw, the bytes go as they are, with neither a size nor flags, and
    // never from no buffer.
    assert_eq!(
        long(c, ffi::CURLOPT_WS_OPTIONS, ffi::CURLWS_RAW_MODE),
        CURLE_OK
    );
    let mut n = 0;
    // SAFETY: a live handle, no buffer, and where the count goes.
    let null = unsafe { curl_ws_send(c, ptr::null(), 0, &raw mut n, 0, 0) };
    assert_eq!(null, CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(send(b"x", 1, 0).0, CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(send(b"x", 0, CURLWS_TEXT).0, CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(send(b"xy", 0, 0), (CURLE_OK, 2));
    let got = server.join().unwrap();
    assert_eq!(&got[SENT - 2..], b"xy");
    let heads: Vec<[u8; 2]> = [0, 9, 15, 21]
        .iter()
        .map(|&at| [got[at], got[at + 1]])
        .collect();
    assert_eq!(
        heads,
        [[0x81, 0x83], [0x82, 0x80], [0x89, 0x80], [0x88, 0x80]]
    );
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
}

/// What the debug function that calls back into its handle saw.
#[derive(Default)]
struct AsksBack {
    socket: ffi::curl_socket_t,
    code: Option<CURLcode>,
    lines: Vec<Vec<u8>>,
}

/// A debug function asking its handle for the socket of the connection the
/// call that traces is on.
unsafe extern "C" fn debug_asks_back(
    c: *mut CURL,
    _: ffi::curl_infotype,
    data: *mut c_char,
    size: usize,
    user: *mut c_void,
) -> c_int {
    // SAFETY: the test's own, for the length of the call.
    let asks = unsafe { &mut *user.cast::<AsksBack>() };
    // SAFETY: the bytes it was given.
    let line = unsafe { core::slice::from_raw_parts(data.cast::<u8>(), size) };
    asks.lines.push(line.to_vec());
    // SAFETY: a live handle, and a pointer to a value of the info's type.
    let code = unsafe { curl_easy_getinfo(c, ffi::CURLINFO_ACTIVESOCKET, &raw mut asks.socket) };
    asks.code = Some(code);
    0
}

/// A WebSocket only connected whose server closes: the receive gets
/// nothing, and says so in the verbose output as C's `curl_ws_recv` does.
#[test]
fn a_websocket_closed_under_a_receive_says_so() {
    use crate::ws::curl_ws_recv;
    use std::io::Write as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _request = read_request(&mut peer);
        peer.write_all(
            b"HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
    });
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("ws://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_CONNECT_ONLY, 2), CURLE_OK);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    server.join().unwrap();
    let mut asks = AsksBack::default();
    assert_eq!(pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut asks), CURLE_OK);
    assert_eq!(
        function(
            c,
            ffi::CURLOPT_DEBUGFUNCTION,
            debug_asks_back as DebugFn as *const ()
        ),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_VERBOSE, 1), CURLE_OK);
    let mut buf = [0u8; 16];
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let got = loop {
        let mut n = 0;
        let mut meta: *const ffi::curl_ws_frame = ptr::null();
        // SAFETY: a live handle, a buffer of its length, and where the
        // count and the frame go.
        let got = unsafe {
            curl_ws_recv(
                c,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &raw mut n,
                &raw mut meta,
            )
        };
        if got != ffi::CURLE_AGAIN {
            break got;
        }
        assert!(std::time::Instant::now() < deadline, "no end came");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(got, ffi::CURLE_GOT_NOTHING);
    let lines: Vec<String> = asks
        .lines
        .iter()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    assert!(
        lines
            .iter()
            .any(|l| l == "[WS] connection expectedly closed?\n"),
        "{lines:?}"
    );
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
}

/// A debug function told what a call on a connection traces may call back
/// into its handle, as C's may: it is answered, of the connection the
/// call is on, which the handle keeps for its next call.
#[test]
fn a_debug_function_calls_back_during_a_call_on_a_connection() {
    use crate::easy::curl_easy_send;
    use crate::ws::curl_ws_recv;
    let (port, server) = serve(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]);
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_CONNECT_ONLY, 1), CURLE_OK);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let mut asks = AsksBack::default();
    assert_eq!(pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut asks), CURLE_OK);
    assert_eq!(
        function(
            c,
            ffi::CURLOPT_DEBUGFUNCTION,
            debug_asks_back as DebugFn as *const (),
        ),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_VERBOSE, 1), CURLE_OK);
    let (mut buf, mut n) = ([0u8; 8], 0);
    let mut meta: *const ffi::curl_ws_frame = ptr::null();
    // The connection is not a WebSocket's, which the call says, on it.
    // SAFETY: a live handle, a buffer of its length, where the count and
    // the frame go.
    let got = unsafe {
        curl_ws_recv(
            c,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &raw mut n,
            &raw mut meta,
        )
    };
    assert_eq!(got, CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(
        asks.lines,
        [b"[WS] connection is not setup for websocket\n".to_vec()]
    );
    assert_eq!(asks.code, Some(CURLE_OK));
    assert_ne!(
        asks.socket,
        ffi::CURL_SOCKET_BAD,
        "the connection is known during the call"
    );
    let request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    // SAFETY: a live handle, the request's bytes and a count to write.
    let sent = unsafe { curl_easy_send(c, request.as_ptr().cast(), request.len(), &raw mut n) };
    assert_eq!((sent, n), (CURLE_OK, request.len()), "still the handle's");
    assert_eq!(server.join().unwrap(), [request.to_vec()]);
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
}

/// `curl_ws_send`'s arguments that can be no frame trace C's lines and
/// answer C's codes, as the C build does them: the connection is looked for
/// first, so one that is gone says that; no flags or length is read while
/// a frame is under way, which goes on, its lines naming them as given.
#[test]
fn a_ws_send_of_no_frame_says_c_s_lines() {
    use crate::ffi::{CURLWS_BINARY, CURLWS_OFFSET, CURLWS_TEXT};
    use crate::ws::curl_ws_send;
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _request = read_request(&mut peer);
        peer.write_all(
            b"HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
        let mut got = vec![0u8; 8 + 2 + 7 + 7 + 7];
        peer.read_exact(&mut got).unwrap();
    });
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("ws://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_CONNECT_ONLY, 2), CURLE_OK);
    let components = curl_core::components::Components::new().unwrap();
    components.configure(b"ws");
    // SAFETY: a live handle.
    let easy = unsafe { crate::easy::handle(c) }.unwrap();
    let set = easy.with_home(|e| match e {
        crate::easy::HomeRef::Detached(e) => e.set_components(Some(components)),
        _ => unreachable!("in no multi"),
    });
    assert!(set.is_ok());
    let mut asks = AsksBack::default();
    assert_eq!(long(c, ffi::CURLOPT_VERBOSE, 1), CURLE_OK);
    assert_eq!(pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut asks), CURLE_OK);
    assert_eq!(
        function(
            c,
            ffi::CURLOPT_DEBUGFUNCTION,
            debug_asks_back as DebugFn as *const (),
        ),
        CURLE_OK
    );
    let send = |bytes: *const u8, len: usize, fragsize: ffi::curl_off_t, flags: c_int| {
        let mut n = 0;
        // SAFETY: a live handle, the bytes and where their count goes.
        let sent =
            unsafe { curl_ws_send(c, bytes.cast(), len, &raw mut n, fragsize, flags as c_uint) };
        (sent, n)
    };
    let bad = CURLWS_TEXT | CURLWS_BINARY;
    let x = b"x".as_ptr();
    let said = |asks: &mut AsksBack| -> Vec<String> {
        std::mem::take(&mut asks.lines)
            .iter()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .filter(|l| !l.contains("WS-ENC") && !l.contains("flushed"))
            .filter(|l| l.starts_with("[WS]") || l.starts_with("Failed") || l.starts_with("cannot"))
            .collect()
    };
    let start = |flags: c_int, len: ffi::curl_off_t| {
        // SAFETY: a live handle.
        unsafe { crate::ws::curl_ws_start_frame(c, flags as c_uint, len) }
    };
    // Nothing a frame's start asks is read before the connection is found.
    assert_eq!(start(bad, 1), ffi::CURLE_SEND_ERROR);
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_start_frame(flags=3, frame_len=1\n",
            "[WS] No associated connection\n",
        ]
    );
    assert_eq!(send(x, 1, 0, bad).0, ffi::CURLE_UNSUPPORTED_PROTOCOL);
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=1, fragsize=0, flags=3), raw=0\n",
            "Failed to get last socket used for connection #-1\n",
        ]
    );
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    said(&mut asks);
    assert_eq!(start(bad, 1), ffi::CURLE_SEND_ERROR, "not taken up");
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_start_frame(flags=3, frame_len=1\n",
            "[WS] No associated connection\n",
        ]
    );
    assert_eq!(
        send(ptr::null(), 5, 0, CURLWS_TEXT).0,
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=5, fragsize=0, flags=1), raw=0\n",
            "[WS] buffer is NULL when buflen is not\n",
        ]
    );
    assert_eq!(send(x, 1, 0, bad).0, CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=1, fragsize=0, flags=3), raw=0\n",
            "[WS] unknown flags: 3\n",
            "[WS] curl_ws_send(), error writing frame head 43\n",
            "[WS] curl_ws_send(len=1, fragsize=0, flags=3, raw=0) -> 43, 0\n",
        ]
    );
    assert_eq!(
        send(x, 1, -1, CURLWS_TEXT | CURLWS_OFFSET).0,
        ffi::CURLE_SEND_ERROR
    );
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=1, fragsize=-1, flags=21), raw=0\n",
            "[WS] starting new frame with negative payload length -1\n",
            "[WS] curl_ws_send(), error writing frame head 55\n",
            "[WS] curl_ws_send(len=1, fragsize=-1, flags=21, raw=0) -> 55, 0\n",
        ]
    );
    // Both bad, the length is found first.
    assert_eq!(send(x, 1, -1, bad | CURLWS_OFFSET).0, ffi::CURLE_SEND_ERROR);
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=1, fragsize=-1, flags=23), raw=0\n",
            "[WS] starting new frame with negative payload length -1\n",
            "[WS] curl_ws_send(), error writing frame head 55\n",
            "[WS] curl_ws_send(len=1, fragsize=-1, flags=23, raw=0) -> 55, 0\n",
        ]
    );
    // With no `CURLWS_OFFSET` the size is not read, and the lines name it.
    assert_eq!(send(x, 1, 7, CURLWS_TEXT), (CURLE_OK, 1));
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=1, fragsize=7, flags=1), raw=0\n",
            "[WS] curl_ws_send(len=1, fragsize=7, flags=1, raw=0) -> 0, 1\n",
        ]
    );
    assert_eq!(send(x, 1, -5, CURLWS_BINARY), (CURLE_OK, 1));
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=1, fragsize=-5, flags=2), raw=0\n",
            "[WS] curl_ws_send(len=1, fragsize=-5, flags=2, raw=0) -> 0, 1\n",
        ]
    );
    // What a frame's start asks is read where its head would be written.
    assert_eq!(start(bad, 1), CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_start_frame(flags=3, frame_len=1\n",
            "[WS] unknown flags: 3\n",
            "[WS] curl_start_frame(), error adding frame head 43\n",
        ]
    );
    assert_eq!(start(bad, -1), ffi::CURLE_SEND_ERROR);
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_start_frame(flags=3, frame_len=-1\n",
            "[WS] starting new frame with negative payload length -1\n",
            "[WS] curl_start_frame(), error adding frame head 55\n",
        ]
    );
    // A frame of 4 under way: two bytes now, its head with them, and more.
    let ab = b"ab".as_ptr();
    assert_eq!(send(ab, 2, 4, CURLWS_TEXT | CURLWS_OFFSET), (CURLE_OK, 2));
    said(&mut asks);
    assert_eq!(send(x, 1, 0, bad), (CURLE_OK, 1), "flags not read");
    assert_eq!(send(x, 1, -1, CURLWS_OFFSET), (CURLE_OK, 1), "nor the size");
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=1, fragsize=0, flags=3), raw=0\n",
            "[WS] curl_ws_send(len=1, fragsize=0, flags=3, raw=0) -> 0, 1\n",
            "[WS] curl_ws_send(len=1, fragsize=-1, flags=20), raw=0\n",
            "[WS] curl_ws_send(len=1, fragsize=-1, flags=20, raw=0) -> 0, 1\n",
        ]
    );
    // Bytes past the frame's end: what went is told with `CURLE_AGAIN`.
    let frame_of_one = (CURLWS_TEXT | CURLWS_OFFSET, 1);
    assert_eq!(
        send(ab, 2, frame_of_one.1, frame_of_one.0),
        (ffi::CURLE_AGAIN, 1)
    );
    assert_eq!(
        said(&mut asks).last().map(String::as_str),
        Some("[WS] curl_ws_send(len=2, fragsize=1, flags=21, raw=0) -> 81, 1\n")
    );
    // Raw, each refusal names the arguments as given.
    assert_eq!(
        long(c, ffi::CURLOPT_WS_OPTIONS, ffi::CURLWS_RAW_MODE),
        CURLE_OK
    );
    assert_eq!(start(bad, 1), ffi::CURLE_FAILED_INIT);
    assert_eq!(
        said(&mut asks),
        ["cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled\n"]
    );
    let refused = send(ptr::null(), 0, 0, 0).0;
    assert_eq!(refused, CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=0, fragsize=0, flags=0), raw=1\n",
            "[WS] buffer is NULL in raw mode\n",
        ]
    );
    // SAFETY: a live handle, the byte, and no count.
    let refused = unsafe { curl_ws_send(c, x.cast(), 1, ptr::null_mut(), 0, 0) };
    assert_eq!(refused, CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=1, fragsize=0, flags=0), raw=1\n",
            "[WS] sent is NULL in raw mode\n",
        ]
    );
    assert_eq!(send(x, 1, 1, 0).0, CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=1, fragsize=1, flags=0), raw=1\n",
            "[WS] fragsize and flags must be zero in raw mode\n",
        ]
    );
    assert_eq!(send(x, 1, 0, CURLWS_TEXT).0, CURLE_BAD_FUNCTION_ARGUMENT);
    assert_eq!(
        said(&mut asks),
        [
            "[WS] curl_ws_send(len=1, fragsize=0, flags=1), raw=1\n",
            "[WS] fragsize and flags must be zero in raw mode\n",
        ]
    );
    server.join().unwrap();
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
}

/// A connection that dies as a send of no frame sends the pong waiting
/// fails with the write, not the flags, and says C's line on leaving.
#[test]
fn a_ws_send_of_no_frame_says_why_if_the_flush_before_it_fails() {
    use crate::ffi::{CURLWS_BINARY, CURLWS_TEXT};
    use crate::ws::{curl_ws_recv, curl_ws_send};
    use std::io::Write as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (hang_up, hung_up) = std::sync::mpsc::channel::<()>();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _request = read_request(&mut peer);
        peer.write_all(
            b"HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
        peer.write_all(b"\x81\x02hi\x89\x01p").unwrap();
        hung_up.recv().unwrap();
        #[cfg(unix)]
        let set = {
            use std::os::fd::AsRawFd as _;
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: an open socket, and the option's type and size.
            unsafe {
                libc::setsockopt(
                    peer.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&raw const linger).cast(),
                    core::mem::size_of::<libc::linger>() as libc::socklen_t,
                )
            }
        };
        #[cfg(windows)]
        let set = {
            use std::os::windows::io::AsRawSocket as _;
            use windows_sys::Win32::Networking::WinSock::{
                LINGER, SO_LINGER, SOL_SOCKET, setsockopt,
            };
            let linger = LINGER {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: an open socket, and the option's type and size.
            unsafe {
                setsockopt(
                    peer.as_raw_socket() as usize,
                    SOL_SOCKET,
                    SO_LINGER,
                    (&raw const linger).cast(),
                    core::mem::size_of::<LINGER>() as i32,
                )
            }
        };
        assert_eq!(set, 0);
    });
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("ws://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_CONNECT_ONLY, 2), CURLE_OK);
    let components = curl_core::components::Components::new().unwrap();
    components.configure(b"ws");
    // SAFETY: a live handle.
    let easy = unsafe { crate::easy::handle(c) }.unwrap();
    let set = easy.with_home(|e| match e {
        crate::easy::HomeRef::Detached(e) => e.set_components(Some(components)),
        _ => unreachable!("in no multi"),
    });
    assert!(set.is_ok());
    let mut seen = Seen::default();
    long(c, ffi::CURLOPT_VERBOSE, 1);
    pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut seen);
    function(
        c,
        ffi::CURLOPT_DEBUGFUNCTION,
        debug_count as DebugFn as *const (),
    );
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let mut buf = [0u8; 8];
    let (mut n, mut meta) = (0, ptr::null());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    // The text frame, then the ping behind it, whose pong waits: it is not
    // sent while a receive finds nothing more.
    loop {
        // SAFETY: a live handle, the buffer, and where its results go.
        let got = unsafe {
            curl_ws_recv(
                c,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &raw mut n,
                &raw mut meta,
            )
        };
        if got == ffi::CURLE_AGAIN && seen.texts.iter().any(|t| t.contains("auto PONG")) {
            break;
        }
        assert!(got == CURLE_OK || got == ffi::CURLE_AGAIN, "{got:?}");
        assert!(std::time::Instant::now() < deadline);
    }
    hang_up.send(()).unwrap();
    server.join().unwrap();
    // The reset must have arrived for the send to fail: the kernel's
    // loopback delivers it as the server's socket closes.
    seen.texts.clear();
    let mut went = 0;
    let bad = (CURLWS_TEXT | CURLWS_BINARY) as c_uint;
    // SAFETY: a live handle, the byte, and where its count goes.
    let sent = unsafe { curl_ws_send(c, b"x".as_ptr().cast(), 1, &raw mut went, 0, bad) };
    assert_eq!(sent, ffi::CURLE_SEND_ERROR);
    let lines: Vec<&str> = seen
        .texts
        .iter()
        .map(String::as_str)
        .filter(|l| l.starts_with("[WS] curl_ws") || l.contains("flush") || l.contains("unknown"))
        .collect();
    assert_eq!(
        lines,
        [
            "[WS] curl_ws_send(len=1, fragsize=0, flags=3), raw=0\n",
            "[WS] flush, write error 55\n",
            "[WS] curl_ws_send(len=1, fragsize=0, flags=3, raw=0) -> 55, 0\n",
        ]
    );
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
}

/// A debug function that turns `CURLOPT_VERBOSE` off hears no more of the
/// call it is in, though that call's lines were held until it ended: C
/// asks before each line.
#[test]
fn a_debug_function_turning_verbose_off_hears_no_more_of_the_call() {
    use std::io::{Read as _, Write as _};
    unsafe extern "C" fn stops(
        c: *mut CURL,
        _: ffi::curl_infotype,
        ptr: *mut c_char,
        n: usize,
        user: *mut c_void,
    ) -> c_int {
        // SAFETY: the test passes its list, and the shim `n` bytes.
        let (heard, line) = unsafe {
            (
                &mut *user.cast::<Vec<String>>(),
                core::slice::from_raw_parts(ptr.cast::<u8>(), n),
            )
        };
        heard.push(String::from_utf8_lossy(line).into_owned());
        long(c, ffi::CURLOPT_VERBOSE, 0);
        0
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut head = Vec::new();
        let mut one = [0u8];
        while !head.ends_with(b"\r\n\r\n") {
            peer.read_exact(&mut one).unwrap();
            head.push(one[0]);
        }
        peer.write_all(
            b"HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
        let mut got = vec![0u8; 6 + 2];
        peer.read_exact(&mut got).unwrap();
    });
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("ws://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_CONNECT_ONLY, 2), CURLE_OK);
    let components = curl_core::components::Components::new().unwrap();
    components.configure(b"ws");
    // SAFETY: a live handle.
    let easy = unsafe { crate::easy::handle(c) }.unwrap();
    let set = easy.with_home(|e| match e {
        crate::easy::HomeRef::Detached(e) => e.set_components(Some(components)),
        _ => unreachable!("in no multi"),
    });
    assert!(set.is_ok());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let mut heard: Vec<String> = Vec::new();
    pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut heard);
    function(c, ffi::CURLOPT_DEBUGFUNCTION, stops as DebugFn as *const ());
    assert_eq!(long(c, ffi::CURLOPT_VERBOSE, 1), CURLE_OK);
    let mut n = 0;
    // SAFETY: a live handle, the bytes and where their count goes.
    let sent = unsafe {
        crate::ws::curl_ws_send(
            c,
            b"ab".as_ptr().cast(),
            2,
            &raw mut n,
            0,
            1 as core::ffi::c_uint,
        )
    };
    assert_eq!((sent, n), (CURLE_OK, 2));
    assert_eq!(
        heard,
        ["[WS] curl_ws_send(len=2, fragsize=0, flags=1), raw=0\n"]
    );
    server.join().unwrap();
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLINFO_TLS_SSL_PTR` on a connection a perform only made, the handle
/// out of its multi: NULL as the transfer let it go, the session once a
/// send took it up, as C's `data->conn` makes it.
#[test]
fn a_detached_connection_shows_its_ssl_pointer_once_taken_up() {
    use crate::easy::curl_easy_send;
    use curl_core::libraries::{Libraries, Library, SharedLibraries};
    use curl_core::tls::fake::{FINISHED, FakeTls, HELLO, WELCOME};
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut hello = vec![0u8; HELLO.len()];
        peer.read_exact(&mut hello).unwrap();
        peer.write_all(WELCOME).unwrap();
        let mut finished = vec![0u8; FINISHED.len()];
        peer.read_exact(&mut finished).unwrap();
        let mut rest = Vec::new();
        let _until_closed = peer.read_to_end(&mut rest);
    });
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    let c = curl_easy_init();
    // SAFETY: a live handle.
    let easy = unsafe { crate::easy::handle(c) }.unwrap();
    let set = easy.with_home(|e| match e {
        crate::easy::HomeRef::Detached(e) => e.set_libraries(libraries),
        _ => unreachable!("in no multi"),
    });
    assert!(set.is_ok());
    let url = std::ffi::CString::new(format!("https://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_CONNECT_ONLY, 1), CURLE_OK);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let ssl = || {
        let mut tsi: *mut ffi::curl_tlssessioninfo = ptr::null_mut();
        // SAFETY: a live handle, and a pointer to the info's type.
        let code = unsafe { curl_easy_getinfo(c, ffi::CURLINFO_TLS_SSL_PTR, &raw mut tsi) };
        assert_eq!(code, CURLE_OK);
        // SAFETY: the handle's own, valid until its next call.
        unsafe { (*tsi).internals }
    };
    assert!(ssl().is_null(), "no call took it up");
    let mut n = 0;
    // SAFETY: a live handle, the byte and a count to write.
    let sent = unsafe { curl_easy_send(c, b"x".as_ptr().cast(), 1, &raw mut n) };
    assert_eq!((sent, n), (CURLE_OK, 1));
    assert!(!ssl().is_null(), "taken up");
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
    server.join().unwrap();
}

/// CURLOPT_WS_OPTIONS sets raw mode and no auto-pong by their bits, any
/// other bit ignored.
#[test]
fn ws_options_are_read_by_their_bits() {
    let c = curl_easy_init();
    let raw = ffi::CURLWS_RAW_MODE;
    let no_pong = ffi::CURLWS_NOAUTOPONG;
    for (n, want) in [
        (raw, (true, false)),
        (no_pong, (false, true)),
        (raw | no_pong, (true, true)),
        (0x100, (false, false)),
    ] {
        assert_eq!(long(c, ffi::CURLOPT_WS_OPTIONS, n), CURLE_OK);
        assert_eq!(options(c, |o| (o.ws.raw, o.ws.no_auto_pong)), want, "{n:x}");
    }
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
}

/// What the echoing write function saw: the frames' flags, as
/// `curl_ws_meta` said them, and what its sends answered.
#[derive(Default)]
struct Echo {
    handle: usize,
    flags: Vec<c_int>,
    sent: Vec<CURLcode>,
}

/// A write function that sends each frame it is given back, from inside
/// the callback (`curl_ws_send` there).
unsafe extern "C" fn echo(ptr: *mut c_char, size: usize, n: usize, data: *mut c_void) -> usize {
    use crate::ws::{curl_ws_meta, curl_ws_send};
    // SAFETY: the test gave its `Echo`, alive for the transfer.
    let echo = unsafe { &mut *data.cast::<Echo>() };
    let c = echo.handle as *mut CURL;
    // SAFETY: inside the handle's own write callback.
    let meta = unsafe { curl_ws_meta(c) };
    assert!(!meta.is_null(), "meta inside the callback");
    // SAFETY: the handle's frame, valid during the callback.
    let flags = unsafe { (*meta).flags };
    echo.flags.push(flags);
    let mut sent = 0;
    // SAFETY: the bytes given, and where their count goes.
    let code = unsafe { curl_ws_send(c, ptr.cast(), size * n, &raw mut sent, 0, flags as c_uint) };
    echo.sent.push(code);
    size * n
}

/// In callback mode the write function sends on the transfer's own
/// WebSocket from inside the callback, `curl_ws_meta` naming each frame.
#[test]
fn a_write_callback_echoes_frames_on_its_own_websocket() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _request = read_request(&mut peer);
        peer.write_all(
            b"HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\
\x81\x02hi",
        )
        .unwrap();
        let mut got = vec![0u8; 8];
        peer.read_exact(&mut got).unwrap();
        got
    });
    let c = curl_easy_init();
    let mut seen = Echo {
        handle: c as usize,
        ..Echo::default()
    };
    let url = std::ffi::CString::new(format!("ws://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(
        function(c, ffi::CURLOPT_WRITEFUNCTION, echo as WriteFn as *const ()),
        CURLE_OK
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_WRITEDATA, (&raw mut seen).cast::<c_void>()),
        CURLE_OK
    );
    // SAFETY: a live handle; the server closes after the echo.
    let _done = unsafe { curl_easy_perform(c) };
    let got = server.join().unwrap();
    assert_eq!(
        (seen.flags, seen.sent),
        (vec![ffi::CURLWS_TEXT], vec![CURLE_OK])
    );
    assert_eq!(got[..2], [0x81, 0x82]);
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
}

/// A frame's fields, as `curl_ws_meta` gave them: its age, flags,
/// offset, what is left and its length.
type FrameFields = (c_int, c_int, curl_off_t, curl_off_t, usize);

/// What the read function was told of the WebSocket's frame as it first
/// read: whether `curl_ws_meta` gave one, and its fields.
#[derive(Default)]
struct FirstRead {
    handle: usize,
    reads: usize,
    meta: Option<Option<FrameFields>>,
}

/// A read function that uploads "up" once, keeping what `curl_ws_meta`
/// said as it first read.
unsafe extern "C" fn first_read(
    ptr: *mut c_char,
    _size: usize,
    _n: usize,
    data: *mut c_void,
) -> usize {
    use crate::ws::curl_ws_meta;
    // SAFETY: the test gave its `FirstRead`, alive for the transfer.
    let seen = unsafe { &mut *data.cast::<FirstRead>() };
    seen.reads += 1;
    if seen.reads > 1 {
        return 0;
    }
    // SAFETY: inside the handle's own read callback.
    let meta = unsafe { curl_ws_meta(seen.handle as *mut CURL) };
    seen.meta = Some(
        // SAFETY: the handle's frame, valid during the callback.
        unsafe { meta.as_ref() }.map(|m| (m.age, m.flags, m.offset, m.bytesleft, m.len)),
    );
    // SAFETY: the buffer has room for what a read may give, more than 2.
    unsafe { ptr::copy_nonoverlapping(b"up".as_ptr(), ptr.cast::<u8>(), 2) };
    2
}

/// Before any frame came, `curl_ws_meta` gives a frame of all zero, as
/// C gives its frame made zeroed, not none.
#[test]
fn the_websocket_s_frame_is_zero_before_the_first() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _request = read_request(&mut peer);
        peer.write_all(
            b"HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
        // The frame of "up": its head, its mask and its payload.
        let mut got = vec![0u8; 8];
        peer.read_exact(&mut got).unwrap();
        got
    });
    let c = curl_easy_init();
    let mut seen = FirstRead {
        handle: c as usize,
        ..FirstRead::default()
    };
    let url = std::ffi::CString::new(format!("ws://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_UPLOAD, 1), CURLE_OK);
    assert_eq!(
        function(
            c,
            ffi::CURLOPT_READFUNCTION,
            first_read as WriteFn as *const ()
        ),
        CURLE_OK
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_READDATA, (&raw mut seen).cast::<c_void>()),
        CURLE_OK
    );
    // SAFETY: a live handle; the server closes once it has the frame.
    let _done = unsafe { curl_easy_perform(c) };
    let got = server.join().unwrap();
    assert_eq!(got[0], 0x82, "the upload went as a frame");
    assert_eq!(seen.meta, Some(Some((0, 0, 0, 0, 0))));
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
}

/// What a read function that starts its frame was told.
#[derive(Default)]
struct StartsFrame {
    handle: usize,
    reads: usize,
    started: Option<CURLcode>,
}

/// A read function that starts a text frame of 2, then gives its payload,
/// "up", once.
unsafe extern "C" fn starts_frame(
    ptr: *mut c_char,
    _size: usize,
    _n: usize,
    data: *mut c_void,
) -> usize {
    // SAFETY: the test gave its `StartsFrame`, alive for the transfer.
    let seen = unsafe { &mut *data.cast::<StartsFrame>() };
    seen.reads += 1;
    if seen.reads > 1 {
        return 0;
    }
    // SAFETY: inside the handle's own read callback.
    let started = unsafe {
        crate::ws::curl_ws_start_frame(seen.handle as *mut CURL, ffi::CURLWS_TEXT as c_uint, 2)
    };
    seen.started = Some(started);
    // SAFETY: the buffer has room for what a read may give, more than 2.
    unsafe { ptr::copy_nonoverlapping(b"up".as_ptr(), ptr.cast::<u8>(), 2) };
    2
}

/// A frame started from inside the read function is the frame its bytes
/// go as: text, not the binary frame a read makes by itself
/// (`curl_ws_start_frame`).
#[test]
fn a_frame_started_in_the_read_function_is_the_one_sent() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _request = read_request(&mut peer);
        peer.write_all(
            b"HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
        // The frame of "up": its head, its mask and its payload.
        let mut got = vec![0u8; 8];
        peer.read_exact(&mut got).unwrap();
        got
    });
    let c = curl_easy_init();
    let mut seen = StartsFrame {
        handle: c as usize,
        ..StartsFrame::default()
    };
    let url = std::ffi::CString::new(format!("ws://127.0.0.1:{port}/")).unwrap();
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(long(c, ffi::CURLOPT_UPLOAD, 1), CURLE_OK);
    assert_eq!(
        function(
            c,
            ffi::CURLOPT_READFUNCTION,
            starts_frame as WriteFn as *const ()
        ),
        CURLE_OK
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_READDATA, (&raw mut seen).cast::<c_void>()),
        CURLE_OK
    );
    // SAFETY: a live handle; the server closes once it has the frame.
    let _done = unsafe { curl_easy_perform(c) };
    let got = server.join().unwrap();
    assert_eq!(seen.started, Some(CURLE_OK));
    assert_eq!(got[..2], [0x81, 0x82], "a text frame of 2, masked");
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
}

/// Raw, a send needs its buffer, which C says once it found the
/// connection: without one, that is what fails the send, raw or not.
#[test]
fn a_raw_send_needs_a_buffer() {
    use crate::ws::curl_ws_send;
    let send = |c: *mut CURL| {
        let mut n = 0;
        // SAFETY: a live handle, no bytes, and where their count goes.
        unsafe { curl_ws_send(c, ptr::null(), 0, &raw mut n, 0, 0) }
    };
    let c = curl_easy_init();
    assert_eq!(send(c), ffi::CURLE_SEND_ERROR, "no connection");
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
    let c = curl_easy_init();
    let mut buf = [0u8; ffi::CURL_ERROR_SIZE as usize];
    assert_eq!(
        pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr()),
        CURLE_OK
    );
    assert_eq!(
        long(c, ffi::CURLOPT_WS_OPTIONS, ffi::CURLWS_RAW_MODE),
        CURLE_OK
    );
    assert_eq!(send(c), ffi::CURLE_SEND_ERROR, "no connection, raw");
    let said = CStr::from_bytes_until_nul(&buf).unwrap();
    assert_eq!(said.to_bytes(), b"[WS] No associated connection");
    // SAFETY: a handle no call uses any more.
    unsafe { curl_easy_cleanup(c) };
}

/// TELNET's input is the read callback's once the application sets it or
/// its data, none before; TELNET's options are the application's list;
/// TFTP's are kept, and setting none leaves their group cold.
#[test]
fn telnet_and_tftp_options_reach_the_transfer() {
    let has_input = |c| options(c, |o| o.small.made_mut().is_some_and(|s| s.input.is_some()));
    let cold = |c| options(c, |o| o.small.made_mut().is_none());
    let c = curl_easy_init();
    assert!(!has_input(c) && cold(c));
    assert_eq!(long(c, ffi::CURLOPT_TFTP_NO_OPTIONS, 0), CURLE_OK);
    assert!(cold(c), "nothing set makes nothing");
    let mut data = 0u8;
    assert_eq!(pointer(c, ffi::CURLOPT_READDATA, &mut data), CURLE_OK);
    assert!(has_input(c));
    assert_eq!(long(c, ffi::CURLOPT_TFTP_NO_OPTIONS, 1), CURLE_OK);
    assert_eq!(long(c, ffi::CURLOPT_TFTP_NO_OPTIONS, 0), CURLE_OK);
    assert!(!options(c, |o| o.small.made_mut().unwrap().tftp_no_options));
    let mut list = ptr::null_mut();
    for line in [c"TTYPE=vt100", c"WS=80x24"] {
        // SAFETY: a list made here, and a C string.
        list = unsafe { crate::strings::curl_slist_append(list, line.as_ptr()) };
    }
    assert_eq!(pointer(c, ffi::CURLOPT_TELNETOPTIONS, list), CURLE_OK);
    let lines = options(c, |o| {
        o.small
            .made_mut()
            .unwrap()
            .telnet
            .iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>()
    });
    assert_eq!(lines, [b"TTYPE=vt100".to_vec(), b"WS=80x24".to_vec()]);
    assert_eq!(
        pointer(c, ffi::CURLOPT_TELNETOPTIONS, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    // SAFETY: the list made above, which the handle no longer keeps.
    unsafe { crate::strings::curl_slist_free_all(list) };
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    let c = curl_easy_init();
    assert_eq!(
        function(c, ffi::CURLOPT_READFUNCTION, read as *const ()),
        CURLE_OK
    );
    assert!(has_input(c));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// `CURLOPT_SHARE` is refused while the handle holds a connection and
/// taken while it does not, as the C build answers each of these
/// (`setopt_share`): added and not run, waiting for room, once out of its
/// multi; a connection only made is the handle's once it has sent on it.
#[test]
fn a_share_is_refused_while_the_handle_holds_a_connection() {
    use crate::easy::curl_easy_send;
    use crate::share::{curl_share_cleanup, curl_share_init};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = std::ffi::CString::new(format!("http://127.0.0.1:{port}/")).unwrap();
    let sh = curl_share_init();
    let none = ptr::null_mut::<c_void>();
    let made = || {
        let c = curl_easy_init();
        assert_eq!(
            pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
            CURLE_OK
        );
        c
    };
    // SAFETY: live handles, a live multi, and values of the options' types.
    unsafe {
        let m = curl_multi_init();
        let c = made();
        let mut seen = Seen::default();
        long(c, ffi::CURLOPT_VERBOSE, 1);
        function(
            c,
            ffi::CURLOPT_DEBUGFUNCTION,
            debug_count as DebugFn as *const (),
        );
        pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut seen);
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        assert_eq!(pointer(c, ffi::CURLOPT_SHARE, sh), CURLE_OK, "not run");
        assert_eq!(pointer(c, ffi::CURLOPT_SHARE, none), CURLE_OK);
        let mut running = 0;
        assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
        assert_eq!(
            pointer(c, ffi::CURLOPT_SHARE, sh),
            CURLE_BAD_FUNCTION_ARGUMENT,
            "running"
        );
        let said = |seen: &Seen| {
            let line = "Cannot change share object while in use\n";
            seen.texts.iter().filter(|t| *t == line).count()
        };
        assert_eq!(said(&seen), 1, "{:?}", seen.texts);
        let line = "setopt 0x2774 got bad argument\n";
        assert_eq!(
            seen.texts.iter().filter(|t| *t == line).count(),
            1,
            "{:?}",
            seen.texts
        );
        assert_eq!(
            pointer(c, ffi::CURLOPT_SHARE, none),
            CURLE_BAD_FUNCTION_ARGUMENT,
            "leaving it, running"
        );
        assert_eq!(said(&seen), 2, "{:?}", seen.texts);
        long(c, ffi::CURLOPT_VERBOSE, 0);
        assert_eq!(
            pointer(c, ffi::CURLOPT_SHARE, sh),
            CURLE_BAD_FUNCTION_ARGUMENT,
            "running, not verbose"
        );
        assert_eq!(said(&seen), 2, "only a verbose handle is told");
        long(c, ffi::CURLOPT_VERBOSE, 1);
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        assert_eq!(pointer(c, ffi::CURLOPT_SHARE, sh), CURLE_OK, "removed");
        assert_eq!(pointer(c, ffi::CURLOPT_SHARE, none), CURLE_OK);
        curl_easy_cleanup(c);

        // Over, its message unread, the connection has gone back.
        let (served, server) = serve(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]);
        let over = std::ffi::CString::new(format!("http://127.0.0.1:{served}/")).unwrap();
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, over.as_ptr().cast_mut());
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
            if running == 0 {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pointer(c, ffi::CURLOPT_SHARE, sh), CURLE_OK, "over");
        assert_eq!(pointer(c, ffi::CURLOPT_SHARE, none), CURLE_OK);
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        curl_easy_cleanup(c);
        server.join().unwrap();

        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_MAX_TOTAL_CONNECTIONS, 1 as c_long),
            CURLM_OK
        );
        let (one, two) = (made(), made());
        assert_eq!(curl_multi_add_handle(m, one), CURLM_OK);
        assert_eq!(curl_multi_add_handle(m, two), CURLM_OK);
        assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
        assert_eq!(
            pointer(one, ffi::CURLOPT_SHARE, sh),
            CURLE_BAD_FUNCTION_ARGUMENT,
            "connected"
        );
        let mut waiting = Seen::default();
        long(two, ffi::CURLOPT_VERBOSE, 1);
        function(
            two,
            ffi::CURLOPT_DEBUGFUNCTION,
            debug_count as DebugFn as *const (),
        );
        pointer(two, ffi::CURLOPT_DEBUGDATA, &raw mut waiting);
        assert_eq!(pointer(two, ffi::CURLOPT_SHARE, sh), CURLE_OK, "waiting");
        assert_eq!(said(&waiting), 0, "{:?}", waiting.texts);
        assert_eq!(pointer(two, ffi::CURLOPT_SHARE, none), CURLE_OK);
        assert_eq!(curl_multi_remove_handle(m, one), CURLM_OK);
        assert_eq!(curl_multi_remove_handle(m, two), CURLM_OK);
        curl_easy_cleanup(one);
        curl_easy_cleanup(two);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);

        let c = made();
        assert_eq!(long(c, ffi::CURLOPT_CONNECT_ONLY, 1), CURLE_OK);
        assert_eq!(curl_easy_perform(c), CURLE_OK);
        let mut made_only = Seen::default();
        long(c, ffi::CURLOPT_VERBOSE, 1);
        function(
            c,
            ffi::CURLOPT_DEBUGFUNCTION,
            debug_count as DebugFn as *const (),
        );
        pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut made_only);
        assert_eq!(pointer(c, ffi::CURLOPT_SHARE, sh), CURLE_OK, "only made");
        assert_eq!(pointer(c, ffi::CURLOPT_SHARE, none), CURLE_OK);
        assert_eq!(said(&made_only), 0, "{:?}", made_only.texts);
        let mut n = 0;
        assert_eq!(
            curl_easy_send(c, c"x".as_ptr().cast(), 1, &raw mut n),
            CURLE_OK
        );
        assert_eq!(
            pointer(c, ffi::CURLOPT_SHARE, sh),
            CURLE_BAD_FUNCTION_ARGUMENT,
            "sent on"
        );
        assert_eq!(said(&made_only), 1, "{:?}", made_only.texts);
        curl_easy_cleanup(c);
        assert_eq!(curl_share_cleanup(sh), ffi::CURLSHE_OK);
    }
}

/// From a callback, `CURLOPT_SHARE` is refused though the transfer has no
/// connection yet, where C takes it: its `Easy` is the step's to use.
#[test]
fn a_callback_cannot_change_the_share() {
    use crate::share::{curl_share_cleanup, curl_share_init};
    struct Asked {
        sh: *mut ffi::CURLSH,
        answer: Option<ffi::CURLcode>,
        said_setopt: bool,
    }
    unsafe extern "C" fn asks(
        c: *mut CURL,
        _: ffi::curl_infotype,
        data: *mut c_char,
        size: usize,
        user: *mut c_void,
    ) -> c_int {
        // SAFETY: the test passes its record as the debug data.
        let asked = unsafe { &mut *user.cast::<Asked>() };
        // SAFETY: the `size` bytes the library gives at `data`.
        let line = unsafe { core::slice::from_raw_parts(data.cast::<u8>(), size) };
        // As the `.netrc` is read: in C, before the transfer has a connection.
        if asked.answer.is_none() && line.starts_with(b"Could not find host") {
            asked.answer = Some(pointer(c, ffi::CURLOPT_SHARE, asked.sh));
        }
        asked.said_setopt |= line.starts_with(b"setopt ");
        0
    }
    let sh = curl_share_init();
    let mut asked = Asked {
        sh,
        answer: None,
        said_setopt: false,
    };
    let c = curl_easy_init();
    let url = c"file:///nonexistent/curl-shim-share";
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    long(c, ffi::CURLOPT_VERBOSE, 1);
    long(c, ffi::CURLOPT_NETRC, ffi::CURL_NETRC_OPTIONAL);
    pointer(c, ffi::CURLOPT_NETRC_FILE, c"/dev/null".as_ptr().cast_mut());
    function(c, ffi::CURLOPT_DEBUGFUNCTION, asks as DebugFn as *const ());
    pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut asked);
    // SAFETY: a live handle, then it and the share, not used again.
    unsafe {
        curl_easy_perform(c);
        curl_easy_cleanup(c);
        assert_eq!(asked.answer, Some(CURLE_BAD_FUNCTION_ARGUMENT));
        assert!(!asked.said_setopt, "this refusal is ours: C has no line");
        assert_eq!(curl_share_cleanup(sh), ffi::CURLSHE_OK);
    }
}

/// A bad argument to any option adds C's `failf` line: to ERRORBUFFER if no
/// reason is kept yet, which a reset does not change, and to a verbose
/// handle's trace every time. Other refusals say nothing. The answers are
/// the ones a C program gave against the C library.
#[test]
fn a_bad_argument_says_which_option_as_in_c() {
    unsafe extern "C" fn lines(
        _: *mut CURL,
        kind: ffi::curl_infotype,
        data: *mut c_char,
        size: usize,
        user: *mut c_void,
    ) -> c_int {
        if kind == ffi::CURLINFO_TEXT {
            // SAFETY: the `size` bytes the library gives at `data`.
            let line = unsafe { core::slice::from_raw_parts(data.cast::<u8>(), size) };
            // SAFETY: the test passes its list as the debug data.
            let seen = unsafe { &mut *user.cast::<Vec<String>>() };
            seen.push(String::from_utf8_lossy(line).into_owned());
        }
        0
    }
    let text = |buf: &[c_char; ffi::CURL_ERROR_SIZE as usize]| {
        // SAFETY: the library keeps it terminated; it starts zeroed.
        let t = unsafe { CStr::from_ptr(buf.as_ptr()) };
        t.to_str().unwrap().to_owned()
    };
    let mut buf = [0 as c_char; ffi::CURL_ERROR_SIZE as usize];
    let bad = CURLE_BAD_FUNCTION_ARGUMENT;
    let (altsvc, sslversion) = (ffi::CURLOPT_ALTSVC_CTRL, ffi::CURLOPT_SSLVERSION);

    // Without a buffer nothing is kept, so the first a buffer could hear
    // is written; the next does not replace it.
    let c = curl_easy_init();
    assert_eq!(long(c, altsvc, 0), bad);
    pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
    assert_eq!(text(&buf), "");
    assert_eq!(long(c, sslversion, 99999), bad);
    assert_eq!(text(&buf), "setopt 0x20 got bad argument");
    assert_eq!(long(c, altsvc, 0), bad);
    assert_eq!(text(&buf), "setopt 0x20 got bad argument");
    // A reset leaves that a reason was given.
    // SAFETY: a live handle.
    unsafe { crate::easy::curl_easy_reset(c) };
    pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
    buf[0] = 0;
    assert_eq!(long(c, altsvc, 0), bad);
    assert_eq!(text(&buf), "", "a reason was already given");
    // A transfer starts over: its reason replaces the option's, and stays
    // over the next bad argument.
    let url = c"nosuch://x/";
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    // SAFETY: a live handle.
    let performed = unsafe { curl_easy_perform(c) };
    assert_eq!(performed, ffi::CURLE_UNSUPPORTED_PROTOCOL);
    let failed = text(&buf);
    assert!(failed.starts_with("Protocol"), "{failed}");
    assert_eq!(long(c, sslversion, 99999), bad);
    assert_eq!(text(&buf), failed);
    // A transfer that gave no reason leaves room for the next.
    let (empty, url) = file("empty", b"");
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    assert_eq!(text(&buf), "");
    assert_eq!(long(c, altsvc, 0), bad);
    assert_eq!(text(&buf), "setopt 0x11e got bad argument");
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    std::fs::remove_file(empty).unwrap();

    // Each one is traced, and only a bad argument; not to a quiet handle.
    let mut seen: Vec<String> = Vec::new();
    let c = curl_easy_init();
    function(c, ffi::CURLOPT_DEBUGFUNCTION, lines as DebugFn as *const ());
    pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut seen);
    assert_eq!(long(c, altsvc, 0), bad);
    assert!(seen.is_empty(), "{seen:?}");
    long(c, ffi::CURLOPT_VERBOSE, 1);
    assert_eq!(long(c, altsvc, 0), bad);
    assert_eq!(long(c, sslversion, 99999), bad);
    assert_eq!(
        long(c, ffi::CURLOPT_HTTP_VERSION, 99),
        ffi::CURLE_UNSUPPORTED_PROTOCOL
    );
    assert_eq!(
        seen,
        [
            "setopt 0x11e got bad argument\n",
            "setopt 0x20 got bad argument\n"
        ]
    );
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// The same from a transfer's own callback, where the handle is reached
/// through the multi's frame. It is no reason the callback gave: one that
/// then fails still has the transfer's own line traced.
#[test]
fn a_bad_argument_in_a_callback_is_told_as_in_c() {
    unsafe extern "C" fn fails(_: *mut c_char, _: usize, _: usize, user: *mut c_void) -> usize {
        long(user.cast(), ffi::CURLOPT_ALTSVC_CTRL, 0);
        ffi::CURL_WRITEFUNC_ERROR as usize
    }
    unsafe extern "C" fn lines(
        _: *mut CURL,
        kind: ffi::curl_infotype,
        data: *mut c_char,
        size: usize,
        user: *mut c_void,
    ) -> c_int {
        if kind == ffi::CURLINFO_TEXT {
            // SAFETY: the `size` bytes the library gives at `data`.
            let line = unsafe { core::slice::from_raw_parts(data.cast::<u8>(), size) };
            // SAFETY: the test passes its list as the debug data.
            let seen = unsafe { &mut *user.cast::<Vec<String>>() };
            seen.push(String::from_utf8_lossy(line).into_owned());
        }
        0
    }
    unsafe extern "C" fn write(_: *mut c_char, size: usize, n: usize, user: *mut c_void) -> usize {
        long(user.cast(), ffi::CURLOPT_ALTSVC_CTRL, 0);
        size * n
    }
    let path = std::env::temp_dir().join(format!("curl-setopt-frame-{}", std::process::id()));
    std::fs::write(&path, "x").unwrap();
    let url = std::ffi::CString::new(format!("file://{}", path.display())).unwrap();
    let mut buf = [0 as c_char; ffi::CURL_ERROR_SIZE as usize];
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, write as WriteFn as *const ());
    pointer(c, ffi::CURLOPT_WRITEDATA, c);
    // SAFETY: a live handle, not used again; the buffer is the library's
    // to keep terminated.
    unsafe {
        assert_eq!(curl_easy_perform(c), CURLE_OK);
        let said = CStr::from_ptr(buf.as_ptr());
        assert_eq!(said.to_bytes(), b"setopt 0x11e got bad argument");
        curl_easy_cleanup(c);
    }
    let mut seen: Vec<String> = Vec::new();
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, fails as WriteFn as *const ());
    pointer(c, ffi::CURLOPT_WRITEDATA, c);
    long(c, ffi::CURLOPT_VERBOSE, 1);
    function(c, ffi::CURLOPT_DEBUGFUNCTION, lines as DebugFn as *const ());
    pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut seen);
    // SAFETY: a live handle, not used again; the buffer is the library's
    // to keep terminated.
    unsafe {
        assert_eq!(curl_easy_perform(c), ffi::CURLE_WRITE_ERROR);
        let said = CStr::from_ptr(buf.as_ptr());
        assert_eq!(said.to_bytes(), b"setopt 0x11e got bad argument");
        curl_easy_cleanup(c);
    }
    let of = |text: &str| seen.iter().filter(|l| l.starts_with(text)).count();
    assert_eq!(of("setopt 0x11e got bad argument"), 1, "{seen:?}");
    assert_eq!(
        of("client returned ERROR on write of 1 bytes"),
        1,
        "{seen:?}"
    );
    std::fs::remove_file(&path).unwrap();
}

/// What the debug function saw of the probes it was called for.
#[cfg(feature = "debug-hooks")]
struct ProbeSeen {
    master: *mut CURL,
    /// A multi the transfer does not run in, which its gate lets through:
    /// its own says the call is recursive before it looks at the handle.
    other: *mut CURLM,
    handles: Vec<usize>,
    removed: Vec<ffi::CURLMcode>,
    added: Vec<ffi::CURLMcode>,
    asked: Vec<CURLcode>,
    /// What asking about the master said from inside a probe's callback,
    /// which reaches it through what that callback was lent.
    master_asked: Vec<CURLcode>,
}

#[cfg(feature = "debug-hooks")]
unsafe extern "C" fn debug_probe(
    h: *mut CURL,
    _: ffi::curl_infotype,
    _: *mut c_char,
    _: usize,
    data: *mut c_void,
) -> c_int {
    // SAFETY: the `ProbeSeen` the test set, alive across its run.
    let seen = unsafe { &mut *data.cast::<ProbeSeen>() };
    if h != seen.master && !seen.handles.contains(&(h as usize)) {
        seen.handles.push(h as usize);
        let mut code: c_long = -1;
        // SAFETY: as a debug function may be called with, and what C says
        // to them for a handle of its own is what is checked.
        unsafe {
            seen.removed.push(curl_multi_remove_handle(seen.other, h));
            seen.added.push(curl_multi_add_handle(seen.other, h));
            seen.asked.push(curl_easy_getinfo(
                h,
                ffi::CURLINFO_RESPONSE_CODE,
                &raw mut code,
            ));
            seen.master_asked.push(curl_easy_getinfo(
                seen.master,
                ffi::CURLINFO_RESPONSE_CODE,
                &raw mut code,
            ));
        }
    }
    0
}

/// A probe calls the master's debug function with a handle of its own,
/// one the application may not add, remove or ask about, and that goes
/// with the transfer, though from its callback the master may be asked
/// about, as getinfo may recurse; `curl_multi_get_handles` lists the
/// application's. Each posts its query, never what the read function gives
/// (`doh_probe_run` sets `CURLOPT_POSTFIELDS`).
#[cfg(feature = "debug-hooks")]
#[test]
fn a_probes_handle_is_the_multis() {
    use crate::multi::curl_multi_get_handles;
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (told, heard) = std::sync::mpsc::channel();
    // The server: what a name is answered with, for either query, once
    // the request's body is in.
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut got = [0u8; 2048];
            let whole = |r: &[u8]| {
                let Some(end) = r.windows(4).position(|w| w == b"\r\n\r\n") else {
                    return false;
                };
                let head = String::from_utf8_lossy(&r[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .map_or(0, |n| n.trim().parse::<usize>().unwrap());
                r.len() >= end + 4 + length
            };
            while !whole(&request) {
                let n = s.read(&mut got).unwrap();
                assert!(n > 0, "the request ends early");
                request.extend_from_slice(&got[..n]);
            }
            let _sent = told.send(request);
            let mut body = vec![0, 0, 0x81, 0x83, 0, 0, 0, 0, 0, 0, 0, 0];
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            body.splice(0..0, head.bytes());
            s.write_all(&body).unwrap();
        }
    });
    let doh = std::ffi::CString::new(format!("http://127.0.0.1:{port}/dns")).unwrap();
    let m = curl_multi_init();
    let c = curl_easy_init();
    let mut seen = ProbeSeen {
        master: c,
        other: curl_multi_init(),
        handles: Vec::new(),
        removed: Vec::new(),
        added: Vec::new(),
        asked: Vec::new(),
        master_asked: Vec::new(),
    };
    pointer(c, ffi::CURLOPT_URL, c"http://nx.test/".as_ptr().cast_mut());
    pointer(c, ffi::CURLOPT_DOH_URL, doh.as_ptr().cast_mut());
    long(c, ffi::CURLOPT_VERBOSE, 1);
    function(
        c,
        ffi::CURLOPT_DEBUGFUNCTION,
        debug_probe as DebugFn as *const (),
    );
    pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut seen);
    // SAFETY: live handles, and a multi's list freed as it is read.
    unsafe {
        // Its lines are only said where DoH's trace is on (`doh_probe_run`).
        assert_eq!(crate::root::curl_global_trace(c"doh".as_ptr()), CURLE_OK);
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        let (mut running, mut rounds) = (1, 0);
        let mut listed = 0;
        while running > 0 {
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
            let list = curl_multi_get_handles(m);
            let mut n = 0;
            while !(*list.add(n)).is_null() {
                assert_eq!(*list.add(n), c, "the application's alone");
                n += 1;
            }
            listed = listed.max(n);
            crate::root::curl_free(list.cast());
            std::thread::sleep(std::time::Duration::from_millis(1));
            rounds += 1;
            assert!(rounds < 5000, "the transfer never ends");
        }
        assert_eq!(listed, 1);
        let mut queued = 0;
        let msg = curl_multi_info_read(m, &raw mut queued);
        assert_eq!((*msg).data.result, ffi::CURLE_COULDNT_RESOLVE_HOST);
        assert_eq!(queued, 0, "the probes left no message");
        assert!(curl_multi_info_read(m, &raw mut queued).is_null());
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
        assert_eq!(curl_multi_cleanup(seen.other), CURLM_OK);
        curl_easy_cleanup(c);
    }
    assert_eq!(seen.handles.len(), 2, "one for each query");
    let requests: Vec<Vec<u8>> = heard.try_iter().collect();
    assert_eq!(requests.len(), 2);
    for r in requests {
        let shown = String::from_utf8_lossy(&r);
        assert!(r.starts_with(b"POST /dns "), "{shown}");
        assert!(
            r.windows(9).any(|w| w == b"\x02nx\x04test\x00"),
            "the query is posted: {shown}"
        );
    }
    assert!(
        seen.removed
            .iter()
            .all(|&r| r == ffi::CURLM_BAD_EASY_HANDLE)
    );
    assert!(seen.added.iter().all(|&r| r == ffi::CURLM_BAD_EASY_HANDLE));
    assert!(
        seen.asked
            .iter()
            .all(|&r| r == ffi::CURLE_BAD_FUNCTION_ARGUMENT)
    );
    assert_eq!(
        seen.master_asked,
        [CURLE_OK, CURLE_OK],
        "getinfo may recurse"
    );
}
