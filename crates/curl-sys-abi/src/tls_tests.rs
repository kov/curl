//! The application's hands on OpenSSL through the C ABI, as a C program
//! uses them against a TLS server on a loopback socket (lib1587,
//! lib758): the `SSL_CTX` function, the `SSL_CTX` and `SSL` getinfo
//! hands out, and a verify callback that asks to be retried.

#![allow(unsafe_code)]
#![allow(
    clippy::multiple_unsafe_ops_per_block,
    reason = "one contract covers each test's sequence of calls"
)]

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use std::io::{Read, Write as _};
use std::net::TcpListener;
use std::thread::JoinHandle;

use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::{X509, X509Name};
use openssl_sys::{SSL, SSL_CTX, X509_STORE_CTX};

use crate::easy::{curl_easy_cleanup, curl_easy_duphandle, curl_easy_init, curl_easy_pause};
use crate::ffi::{
    self, CURL, CURLE_ABORTED_BY_CALLBACK, CURLE_OK, CURLE_SSL_CERTPROBLEM, CURLINFO, CURLM_OK,
    CURLcode, curl_tlssessioninfo,
};
use crate::getinfo::curl_easy_getinfo;
use crate::multi::{
    curl_multi_add_handle, curl_multi_cleanup, curl_multi_info_read, curl_multi_init,
    curl_multi_perform, curl_multi_remove_handle, curl_multi_wait,
};
use crate::setopt::curl_easy_setopt;

unsafe extern "C" {
    fn SSL_CTX_set_cert_verify_callback(
        ctx: *mut SSL_CTX,
        cb: Option<unsafe extern "C" fn(*mut X509_STORE_CTX, *mut c_void) -> c_int>,
        arg: *mut c_void,
    );
}

/// `SSL_set_retry_verify`, a macro of OpenSSL 3.0's.
///
/// # Safety
///
/// `ssl` is an `SSL` under verification.
unsafe fn set_retry_verify(ssl: *mut SSL) -> c_int {
    const SSL_CTRL_SET_RETRY_VERIFY: c_int = 136;
    // SAFETY: as the caller guarantees; the command takes no pointer.
    c_int::from(
        unsafe { openssl_sys::SSL_ctrl(ssl, SSL_CTRL_SET_RETRY_VERIFY, 0, ptr::null_mut()) } > 0,
    )
}

/// A server for one connection on loopback, with a certificate of its
/// own, answering one GET with `ok`; it ends when the client does.
fn serve() -> (u16, JoinHandle<()>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "localhost")
        .unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_certificate(&cert.build()).unwrap();
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let Ok(mut tls) = acceptor.accept(tcp) else {
            return;
        };
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        while matches!(tls.read(&mut buf), Ok(n) if n > 0) {}
    });
    (port, server)
}

/// What the callbacks saw.
struct Seen {
    /// The function's calls, with the handle and context each was given.
    calls: Vec<(*mut CURL, *mut c_void)>,
    /// The `SSL_CTX` and `SSL` getinfo gave inside the function.
    in_function: Vec<(*mut c_void, *mut c_void)>,
    /// The same, in the write callback, with the `SSL`'s own context.
    in_write: Vec<(*mut c_void, *mut c_void, *mut c_void)>,
    /// What the function answers.
    answer: CURLcode,
    /// It installs the verify callback that asks to be retried.
    retry: bool,
    /// The verify callback's calls.
    verifies: c_int,
}

impl Default for Seen {
    fn default() -> Seen {
        Seen {
            calls: Vec::new(),
            in_function: Vec::new(),
            in_write: Vec::new(),
            answer: CURLE_OK,
            retry: false,
            verifies: 0,
        }
    }
}

/// What `CURLINFO_TLS_SESSION` or `CURLINFO_TLS_SSL_PTR` hands out: its
/// result, the backend and the pointer.
fn session_info(c: *mut CURL, info: CURLINFO) -> (CURLcode, c_int, *mut c_void) {
    let mut tsi: *mut curl_tlssessioninfo = ptr::null_mut();
    // SAFETY: a live handle, and a pointer for the struct's address.
    let r = unsafe { curl_easy_getinfo(c, info, &raw mut tsi) };
    // SAFETY: the handle's own struct, alive with it.
    let t = unsafe { *tsi };
    (r, t.backend.0, t.internals)
}

/// The verify callback lib758 installs: it asks to be retried the first
/// time, and passes once the test says the verification is done.
unsafe extern "C" fn retried_verify(store: *mut X509_STORE_CTX, arg: *mut c_void) -> c_int {
    // SAFETY: `arg` is the test's `Seen`, alive through the transfer.
    let seen = unsafe { &mut *arg.cast::<Seen>() };
    seen.verifies += 1;
    if seen.verifies > 1 {
        return 1;
    }
    // SAFETY: the store of the `SSL` being verified, which keeps it at
    // OpenSSL's index.
    let ssl = unsafe {
        openssl_sys::X509_STORE_CTX_get_ex_data(
            store,
            openssl_sys::SSL_get_ex_data_X509_STORE_CTX_idx(),
        )
    };
    // SAFETY: the `SSL` under verification.
    unsafe { set_retry_verify(ssl.cast()) }
}

unsafe extern "C" fn ctx_function(
    curl: *mut CURL,
    ctx: *mut c_void,
    data: *mut c_void,
) -> CURLcode {
    // SAFETY: the test's `Seen`, alive through the transfer.
    let seen = unsafe { &mut *data.cast::<Seen>() };
    seen.calls.push((curl, ctx));
    let (r1, _, session) = session_info(curl, ffi::CURLINFO_TLS_SESSION);
    let (r2, _, ssl) = session_info(curl, ffi::CURLINFO_TLS_SSL_PTR);
    assert_eq!((r1, r2), (CURLE_OK, CURLE_OK));
    seen.in_function.push((session, ssl));
    // It is an `SSL_CTX`, which OpenSSL reads and sets.
    // SAFETY: the `SSL_CTX` the transfer's connection is made with.
    unsafe {
        let options = openssl_sys::SSL_CTX_get_options(ctx.cast());
        openssl_sys::SSL_CTX_set_options(ctx.cast(), options);
    }
    if seen.retry {
        // SAFETY: as above, and a callback of OpenSSL's type given the
        // test's `Seen`.
        unsafe { SSL_CTX_set_cert_verify_callback(ctx.cast(), Some(retried_verify), data) };
    }
    seen.answer
}

unsafe extern "C" fn write_cb(_: *mut c_char, size: usize, n: usize, data: *mut c_void) -> usize {
    // SAFETY: the pair of the test's `Seen` and the handle, alive through
    // the transfer.
    let (seen, curl) = unsafe { *data.cast::<(*mut Seen, *mut CURL)>() };
    // SAFETY: as above.
    let seen = unsafe { &mut *seen };
    let (_, _, ctx) = session_info(curl, ffi::CURLINFO_TLS_SESSION);
    let (_, _, ssl) = session_info(curl, ffi::CURLINFO_TLS_SSL_PTR);
    let own = if ssl.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the connection's `SSL`.
        unsafe { openssl_sys::SSL_get_SSL_CTX(ssl.cast()) }.cast()
    };
    seen.in_write.push((ctx, ssl, own));
    size * n
}

/// A handle for `https://localhost:<port>/`, not verifying the peer,
/// with the `SSL_CTX` function given `seen`, and the write callback.
fn handle(port: u16, seen: *mut Seen, pair: *mut (*mut Seen, *mut CURL)) -> *mut CURL {
    let c = curl_easy_init();
    let url = std::ffi::CString::new(format!("https://localhost:{port}/")).unwrap();
    // SAFETY: a live handle, and options of their types.
    unsafe {
        assert_eq!(
            curl_easy_setopt(c, ffi::CURLOPT_URL, url.as_ptr()),
            CURLE_OK
        );
        assert_eq!(
            curl_easy_setopt(c, ffi::CURLOPT_SSL_VERIFYPEER, 0 as c_long),
            CURLE_OK
        );
        assert_eq!(
            curl_easy_setopt(c, ffi::CURLOPT_SSL_VERIFYHOST, 0 as c_long),
            CURLE_OK
        );
        let f =
            ctx_function as unsafe extern "C" fn(*mut CURL, *mut c_void, *mut c_void) -> CURLcode;
        assert_eq!(
            curl_easy_setopt(c, ffi::CURLOPT_SSL_CTX_FUNCTION, f),
            CURLE_OK
        );
        assert_eq!(
            curl_easy_setopt(c, ffi::CURLOPT_SSL_CTX_DATA, seen.cast::<c_void>()),
            CURLE_OK
        );
        let w = write_cb as unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;
        assert_eq!(curl_easy_setopt(c, ffi::CURLOPT_WRITEFUNCTION, w), CURLE_OK);
        (*pair).1 = c;
        assert_eq!(
            curl_easy_setopt(c, ffi::CURLOPT_WRITEDATA, pair.cast::<c_void>()),
            CURLE_OK
        );
    }
    c
}

/// Before and after a transfer, and with no connection, getinfo names
/// OpenSSL and hands out NULL (`curl_tlssessioninfo`); during it, the
/// function is given the connection's `SSL_CTX`, which the transfer
/// reaches inside it while its `SSL` is not yet made; the write callback
/// reaches the same `SSL_CTX` and the connection's `SSL`, made of it.
#[test]
fn the_ssl_ctx_function_and_getinfo_hand_out_the_connection_s_objects() {
    let (port, server) = serve();
    let mut seen = Seen::default();
    let mut pair: (*mut Seen, *mut CURL) = (&raw mut seen, ptr::null_mut());
    let c = handle(port, &raw mut seen, &raw mut pair);
    let openssl = ffi::CURLSSLBACKEND_OPENSSL.0;
    for info in [ffi::CURLINFO_TLS_SSL_PTR, ffi::CURLINFO_TLS_SESSION] {
        assert_eq!(session_info(c, info), (CURLE_OK, openssl, ptr::null_mut()));
    }
    // SAFETY: a live handle.
    assert_eq!(unsafe { crate::easy::curl_easy_perform(c) }, CURLE_OK);
    for info in [ffi::CURLINFO_TLS_SSL_PTR, ffi::CURLINFO_TLS_SESSION] {
        assert_eq!(session_info(c, info), (CURLE_OK, openssl, ptr::null_mut()));
    }
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
    server.join().unwrap();
    let [(curl, ctx)] = seen.calls[..] else {
        panic!("{} calls", seen.calls.len());
    };
    assert_eq!(curl, c);
    assert!(!ctx.is_null());
    assert_eq!(seen.in_function, [(ctx, ptr::null_mut())]);
    assert!(!seen.in_write.is_empty());
    for &(session, ssl, own) in &seen.in_write {
        assert_eq!(session, ctx);
        assert!(!ssl.is_null());
        assert_eq!(own, ctx, "the SSL is made of the context");
    }
}

/// The function's error code fails the transfer with that code, said as
/// C says it; a code no transfer ends with is an abort (DIVERGENCE.md).
#[test]
fn the_ssl_ctx_function_s_code_fails_the_transfer() {
    for (answer, result) in [
        (CURLE_SSL_CERTPROBLEM, CURLE_SSL_CERTPROBLEM),
        (CURLcode(1000), CURLE_ABORTED_BY_CALLBACK),
    ] {
        let (port, server) = serve();
        let mut seen = Seen {
            answer,
            ..Seen::default()
        };
        let mut pair: (*mut Seen, *mut CURL) = (&raw mut seen, ptr::null_mut());
        let c = handle(port, &raw mut seen, &raw mut pair);
        let mut errbuf = [0 as c_char; ffi::CURL_ERROR_SIZE as usize];
        // SAFETY: a live handle and a buffer of C's size, alive through it.
        unsafe {
            assert_eq!(
                curl_easy_setopt(c, ffi::CURLOPT_ERRORBUFFER, errbuf.as_mut_ptr()),
                CURLE_OK
            );
            assert_eq!(crate::easy::curl_easy_perform(c), result);
            curl_easy_cleanup(c);
        }
        server.join().unwrap();
        // SAFETY: a C string the transfer wrote.
        let why = unsafe { CStr::from_ptr(errbuf.as_ptr()) };
        assert_eq!(why, c"error signaled by SSL ctx callback");
        assert!(seen.in_write.is_empty());
    }
}

/// A copy of the handle calls the function with the copy, not the
/// handle it was copied from: run while that one is still alive, so a
/// copy calling through it fails here rather than reading freed memory.
#[test]
fn a_copy_s_ssl_ctx_function_is_given_the_copy() {
    let (port, server) = serve();
    let mut seen = Seen::default();
    let mut pair: (*mut Seen, *mut CURL) = (&raw mut seen, ptr::null_mut());
    let pair = &raw mut pair;
    let c = handle(port, &raw mut seen, pair);
    // SAFETY: a live handle; the copy's write data is the same pair,
    // given the copy.
    let dup = unsafe { curl_easy_duphandle(c) };
    // SAFETY: the pair, which no callback reaches meanwhile.
    unsafe { (*pair).1 = dup };
    // SAFETY: live handles, each not used again after its cleanup.
    unsafe {
        assert_eq!(crate::easy::curl_easy_perform(dup), CURLE_OK);
        curl_easy_cleanup(c);
        curl_easy_cleanup(dup);
    }
    server.join().unwrap();
    assert_eq!(seen.calls.len(), 1);
    assert_eq!(seen.calls[0].0, dup);
}

/// Whether the function `data_function` was last given NULL data.
static GIVEN_NULL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

unsafe extern "C" fn data_function(_: *mut CURL, _: *mut c_void, data: *mut c_void) -> CURLcode {
    GIVEN_NULL.store(data.is_null(), std::sync::atomic::Ordering::Relaxed);
    CURLE_OK
}

/// A reset handle forgets the function's data with the function: one
/// set after is given NULL, as `Curl_init_userdefined` leaves it.
#[test]
fn a_reset_forgets_the_ssl_ctx_data() {
    let (port, server) = serve();
    let mut seen = Seen::default();
    let mut pair: (*mut Seen, *mut CURL) = (&raw mut seen, ptr::null_mut());
    let c = handle(port, &raw mut seen, &raw mut pair);
    let url = std::ffi::CString::new(format!("https://localhost:{port}/")).unwrap();
    let f = data_function as unsafe extern "C" fn(*mut CURL, *mut c_void, *mut c_void) -> CURLcode;
    // SAFETY: a live handle, and options of their types.
    unsafe {
        crate::easy::curl_easy_reset(c);
        assert_eq!(
            curl_easy_setopt(c, ffi::CURLOPT_URL, url.as_ptr()),
            CURLE_OK
        );
        assert_eq!(
            curl_easy_setopt(c, ffi::CURLOPT_SSL_VERIFYPEER, 0 as c_long),
            CURLE_OK
        );
        assert_eq!(
            curl_easy_setopt(c, ffi::CURLOPT_SSL_CTX_FUNCTION, f),
            CURLE_OK
        );
        let w = write_cb as unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;
        assert_eq!(curl_easy_setopt(c, ffi::CURLOPT_WRITEFUNCTION, w), CURLE_OK);
        assert_eq!(
            curl_easy_setopt(c, ffi::CURLOPT_WRITEDATA, (&raw mut pair).cast::<c_void>()),
            CURLE_OK
        );
        assert_eq!(crate::easy::curl_easy_perform(c), CURLE_OK);
        curl_easy_cleanup(c);
    }
    server.join().unwrap();
    assert!(GIVEN_NULL.load(std::sync::atomic::Ordering::Relaxed));
    assert!(seen.calls.is_empty(), "the old function was called");
}

/// A verify callback that asks to be retried (lib758) pauses the
/// transfer's receiving: however often the multi runs, the handshake is
/// not moved on and the callback is not called again; once the
/// application unpauses the transfer, the handshake runs the callback
/// again and the transfer ends.
#[test]
fn a_retried_verify_waits_for_the_application_to_unpause() {
    let (port, server) = serve();
    let mut seen = Seen {
        retry: true,
        ..Seen::default()
    };
    let seen = &raw mut seen;
    let mut pair: (*mut Seen, *mut CURL) = (seen, ptr::null_mut());
    let c = handle(port, seen, &raw mut pair);
    let m = curl_multi_init();
    let mut running: c_int = 1;
    // SAFETY: a live multi and handle; `seen` is read between calls, while
    // no callback runs.
    unsafe {
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        let mut turns = 0;
        // Until the verify callback has run, which the transfer's
        // callbacks note through `seen`.
        loop {
            if (*seen).verifies > 0 {
                break;
            }
            turns += 1;
            assert!(turns < 1000, "the verify callback never ran");
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
            assert_eq!(
                curl_multi_wait(m, ptr::null_mut(), 0, 10, ptr::null_mut()),
                CURLM_OK
            );
        }
        for _ in 0..20 {
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
            assert_eq!(
                curl_multi_wait(m, ptr::null_mut(), 0, 5, ptr::null_mut()),
                CURLM_OK
            );
        }
        assert_eq!((*seen).verifies, 1, "the handshake went on while paused");
        assert_eq!(running, 1);
        assert_eq!(curl_easy_pause(c, ffi::CURLPAUSE_CONT), CURLE_OK);
        let mut turns = 0;
        while running > 0 {
            turns += 1;
            assert!(turns < 1000, "the transfer never ended");
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
            assert_eq!(
                curl_multi_wait(m, ptr::null_mut(), 0, 10, ptr::null_mut()),
                CURLM_OK
            );
        }
        let mut left = 0;
        let msg = curl_multi_info_read(m, &raw mut left);
        assert!(!msg.is_null());
        assert_eq!((*msg).data.result, CURLE_OK);
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        curl_easy_cleanup(c);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
        server.join().unwrap();
        assert_eq!((*seen).verifies, 2);
        assert!(!(*seen).in_write.is_empty());
    }
}
