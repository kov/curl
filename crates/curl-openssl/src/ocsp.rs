//! The peer's certificate status, stapled to its handshake by OCSP
//! (`CURLOPT_SSL_VERIFYSTATUS`, openssl.c's `verifystatus`): asked for as
//! the session is made, checked after the chain is: a response there,
//! successful, signed by the chain, naming the peer's certificate, still
//! current, and saying it is good.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int, c_long};
use core::ptr::{self, NonNull};

use curl_core::error::ErrorKind;
use curl_core::tls::TlsCx;
use openssl_sys::{SSL, SSL_CTX, X509};

use crate::x509::{Text, c_text};

// SAFETY: the declarations are `ocsp.h`'s; the library exports them.
unsafe extern "C" {
    fn OCSP_response_status_str(s: c_long) -> *const c_char;
    fn OCSP_cert_status_str(s: c_long) -> *const c_char;
    fn OCSP_crl_reason_str(s: c_long) -> *const c_char;
}

/// Ask the peer to staple its certificate's status
/// (`SSL_set_tlsext_status_type`), as `ossl_init_ssl` does when the
/// transfer checks it.
pub(crate) fn request(ssl: NonNull<SSL>) {
    // SAFETY: the session's SSL, before its handshake.
    unsafe {
        openssl_sys::SSL_set_tlsext_status_type(ssl.as_ptr(), openssl_sys::TLSEXT_STATUSTYPE_ocsp)
    };
}

/// The library's static text for a code, or none.
///
/// # Safety
///
/// `f` returns null or a static C string for any code.
unsafe fn named(f: unsafe extern "C" fn(c_long) -> *const c_char, code: c_int) -> Text<'static> {
    // SAFETY: as the caller says.
    let text = unsafe { f(c_long::from(code)) };
    // SAFETY: as above.
    let text = unsafe { c_text(text) };
    Text(text.unwrap_or(b""))
}

/// Check the status the peer stapled (`verifystatus`): 91 for each way it
/// falls short, said as C says it.
pub(crate) fn check(
    ssl: NonNull<SSL>,
    ctx: NonNull<SSL_CTX>,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let fail = |io: &mut TlsCx<'_>, why: core::fmt::Arguments<'_>| {
        io.fail(ErrorKind::SslInvalidcertstatus, why)
    };
    let s = ssl.as_ptr();
    let mut status: *mut u8 = ptr::null_mut();
    // SAFETY: the session's SSL, its handshake done; the response is its
    // own, alive while it is.
    let len = unsafe { openssl_sys::SSL_get_tlsext_status_ocsp_resp(s, &mut status) };
    if status.is_null() {
        return Err(fail(io, format_args!("No OCSP response received")));
    }
    let mut p = status.cast_const();
    // SAFETY: `len` bytes at `p`, the SSL's; the response read is this
    // function's to free.
    let rsp = unsafe { openssl_sys::d2i_OCSP_RESPONSE(ptr::null_mut(), &mut p, len) };
    let Some(rsp) = NonNull::new(rsp) else {
        return Err(fail(io, format_args!("Invalid OCSP response")));
    };
    let result = response(rsp, s, ctx, io);
    // SAFETY: the response read, freed once.
    unsafe { openssl_sys::OCSP_RESPONSE_free(rsp.as_ptr()) };
    result
}

/// The rest of the check, on the response read.
fn response(
    rsp: NonNull<openssl_sys::OCSP_RESPONSE>,
    s: *mut SSL,
    ctx: NonNull<SSL_CTX>,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let fail = |io: &mut TlsCx<'_>, why: core::fmt::Arguments<'_>| {
        io.fail(ErrorKind::SslInvalidcertstatus, why)
    };
    // SAFETY: the response.
    let code = unsafe { openssl_sys::OCSP_response_status(rsp.as_ptr()) };
    if code != openssl_sys::OCSP_RESPONSE_STATUS_SUCCESSFUL {
        // SAFETY: the library's text for any code.
        let name = unsafe { named(OCSP_response_status_str, code) };
        return Err(fail(
            io,
            format_args!("Invalid OCSP response status: {name} ({code})"),
        ));
    }
    // SAFETY: the response; the basic response is this function's to free.
    let br = unsafe { openssl_sys::OCSP_response_get1_basic(rsp.as_ptr()) };
    let Some(br) = NonNull::new(br) else {
        return Err(fail(io, format_args!("Invalid OCSP response")));
    };
    let result = basic(br, s, ctx, io);
    // SAFETY: the basic response, freed once.
    unsafe { openssl_sys::OCSP_BASICRESP_free(br.as_ptr()) };
    result
}

/// The basic response's signature, the certificate it names and what it
/// says of it.
fn basic(
    br: NonNull<openssl_sys::OCSP_BASICRESP>,
    s: *mut SSL,
    ctx: NonNull<SSL_CTX>,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let fail = |io: &mut TlsCx<'_>, why: core::fmt::Arguments<'_>| {
        io.fail(ErrorKind::SslInvalidcertstatus, why)
    };
    // SAFETY: the SSL; the chain is its own, alive while it is.
    let chain = unsafe { openssl_sys::SSL_get0_verified_chain(s) };
    if chain.is_null() {
        return Err(fail(
            io,
            format_args!("Could not get peer certificate chain"),
        ));
    }
    // SAFETY: the context; its store is its own.
    let store = unsafe { openssl_sys::SSL_CTX_get_cert_store(ctx.as_ptr()) };
    // SAFETY: the basic response, the chain and the store.
    if unsafe { openssl_sys::OCSP_basic_verify(br.as_ptr(), chain, store, 0) } <= 0 {
        return Err(fail(io, format_args!("OCSP response verification failed")));
    }
    // SAFETY: the SSL; a reference to the certificate, freed below.
    let cert = unsafe { openssl_sys::SSL_get1_peer_certificate(s) };
    if cert.is_null() {
        return Err(fail(io, format_args!("Error getting peer certificate")));
    }
    let stack = chain.cast::<openssl_sys::OPENSSL_STACK>();
    let mut id = ptr::null_mut();
    // SAFETY: a stack of certificates.
    let n = unsafe { openssl_sys::OPENSSL_sk_num(stack) };
    for i in 0..n.max(0) {
        // SAFETY: an entry of the stack, a certificate.
        let issuer = unsafe { openssl_sys::OPENSSL_sk_value(stack, i) }.cast::<X509>();
        // SAFETY: two certificates.
        if unsafe { openssl_sys::X509_check_issued(issuer, cert) } == openssl_sys::X509_V_OK {
            // SAFETY: the library's static SHA-1 (a lookup key, RFC 5019,
            // not a verifier).
            let sha1 = unsafe { openssl_sys::EVP_sha1() };
            // SAFETY: the digest and the two certificates; the id is this
            // function's to free.
            id = unsafe { openssl_sys::OCSP_cert_to_id(sha1, cert, issuer) };
            break;
        }
    }
    // SAFETY: the reference taken above, given back once.
    unsafe { openssl_sys::X509_free(cert) };
    if id.is_null() {
        return Err(fail(io, format_args!("Error computing OCSP ID")));
    }
    let (mut status, mut reason) = (0, 0);
    let mut rev = ptr::null_mut();
    let mut thisupd = ptr::null_mut();
    let mut nextupd = ptr::null_mut();
    // SAFETY: the basic response and the id; what it finds is the
    // response's own.
    let found = unsafe {
        openssl_sys::OCSP_resp_find_status(
            br.as_ptr(),
            id,
            &mut status,
            &mut reason,
            &mut rev,
            &mut thisupd,
            &mut nextupd,
        )
    };
    // SAFETY: the id made above, freed once.
    unsafe { openssl_sys::OCSP_CERTID_free(id) };
    if found != 1 {
        return Err(fail(
            io,
            format_args!("Could not find certificate ID in OCSP response"),
        ));
    }
    // Five minutes of clock skew allowed, and no limit on how old the
    // response's issue may be.
    // SAFETY: the response's times.
    if unsafe { openssl_sys::OCSP_check_validity(thisupd, nextupd, 300, -1) } == 0 {
        return Err(fail(io, format_args!("OCSP response has expired")));
    }
    // SAFETY: the library's text for any code.
    let name = unsafe { named(OCSP_cert_status_str, status) };
    io.info(format_args!("SSL certificate status: {name} ({status})"));
    match status {
        openssl_sys::V_OCSP_CERTSTATUS_GOOD => Ok(()),
        openssl_sys::V_OCSP_CERTSTATUS_REVOKED => {
            // SAFETY: as above.
            let why = unsafe { named(OCSP_crl_reason_str, reason) };
            Err(fail(
                io,
                format_args!("SSL certificate revocation reason: {why} ({reason})"),
            ))
        }
        _ => Err(ErrorKind::SslInvalidcertstatus),
    }
}
