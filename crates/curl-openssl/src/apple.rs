//! A peer OpenSSL did not verify, verified by Apple's SecTrust against the
//! system's trust settings (`USE_APPLE_SECTRUST`: `lib/vtls/apple.c`'s
//! `Curl_vtls_apple_verify`, with `openssl.c`'s `ossl_apple_verify`
//! handing it the chain).

#![allow(unsafe_code)]

use core::ffi::{c_char, c_long, c_uchar, c_void};
use core::ptr::{self, NonNull};

use curl_alloc::TryVec as _;
use curl_core::error::ErrorKind;
use curl_core::tls::TlsCx;
use openssl_sys::{SSL, X509};

use crate::x509::Text;

type CFTypeRef = *const c_void;
type CFIndex = isize;
type OSStatus = i32;
type Boolean = u8;

/// `kCFStringEncodingUTF8`.
const UTF8: u32 = 0x0800_0100;
/// `kSecRevocationUseAnyAvailableMethod` and
/// `kSecRevocationRequirePositiveResponse`.
const REVOCATION_ANY: usize = 3;
const REVOCATION_REQUIRE_POSITIVE: usize = 8;
/// `errSecIncompleteCertRevocationCheck`: SecTrust could not tell whether
/// a certificate is revoked.
const INCOMPLETE_REVOCATION_CHECK: CFIndex = -67635;

#[repr(C)]
struct CFArrayCallBacks {
    _private: [u8; 0],
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeArrayCallBacks: CFArrayCallBacks;
    fn CFRelease(cf: CFTypeRef);
    fn CFArrayCreateMutable(
        allocator: CFTypeRef,
        capacity: CFIndex,
        callbacks: *const CFArrayCallBacks,
    ) -> *mut c_void;
    fn CFArrayAppendValue(array: *mut c_void, value: CFTypeRef);
    fn CFDataCreate(allocator: CFTypeRef, bytes: *const c_uchar, length: CFIndex) -> CFTypeRef;
    fn CFStringCreateWithCString(
        allocator: CFTypeRef,
        text: *const c_char,
        encoding: u32,
    ) -> CFTypeRef;
    fn CFStringGetLength(string: CFTypeRef) -> CFIndex;
    fn CFStringGetMaximumSizeForEncoding(length: CFIndex, encoding: u32) -> CFIndex;
    fn CFStringGetCString(
        string: CFTypeRef,
        buffer: *mut c_char,
        size: CFIndex,
        encoding: u32,
    ) -> Boolean;
    fn CFErrorGetCode(error: CFTypeRef) -> CFIndex;
    fn CFErrorCopyDescription(error: CFTypeRef) -> CFTypeRef;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecPolicyCreateSSL(server: Boolean, hostname: CFTypeRef) -> CFTypeRef;
    fn SecPolicyCreateRevocation(flags: usize) -> CFTypeRef;
    fn SecCertificateCreateWithData(allocator: CFTypeRef, data: CFTypeRef) -> CFTypeRef;
    fn SecTrustCreateWithCertificates(
        certificates: CFTypeRef,
        policies: CFTypeRef,
        trust: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecTrustSetOCSPResponse(trust: CFTypeRef, response: CFTypeRef) -> OSStatus;
    fn SecTrustEvaluateWithError(trust: CFTypeRef, error: *mut CFTypeRef) -> bool;
}

/// A Core Foundation object of ours, released as it goes.
struct Owned(CFTypeRef);

impl Owned {
    /// What a `Create` or `Copy` call returned, or none if it failed.
    fn of(made: CFTypeRef) -> Option<Owned> {
        (!made.is_null()).then(|| Owned(made))
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: an object a `Create` or `Copy` call gave us, released
        // once, here.
        unsafe { CFRelease(self.0) };
    }
}

/// A DER encoding OpenSSL made, freed with it.
struct Der(*mut u8, usize);

impl Drop for Der {
    fn drop(&mut self) {
        // SAFETY: what `i2d_X509` allocated, freed once (`OPENSSL_free`).
        unsafe { openssl_sys::CRYPTO_free(self.0.cast(), c"".as_ptr(), 0) };
    }
}

/// The certificate at `i` of `stack`, in DER (`ossl_chain_get_der`).
///
/// # Safety
/// `stack` is the session's peer chain, alive for the call.
unsafe fn der_at(stack: *mut openssl_sys::OPENSSL_STACK, i: usize) -> Result<Der, ErrorKind> {
    let index = i32::try_from(i).map_err(|_| ErrorKind::TooLarge)?;
    // SAFETY: as the caller says; an index below the count.
    let cert = unsafe { openssl_sys::OPENSSL_sk_value(stack, index) }.cast::<X509>();
    if cert.is_null() {
        return Err(ErrorKind::FailedInit);
    }
    let mut der: *mut u8 = ptr::null_mut();
    // SAFETY: the certificate; OpenSSL allocates the encoding and points
    // `der` at it.
    let len = unsafe { openssl_sys::i2d_X509(cert, &mut der) };
    let len = usize::try_from(len).map_err(|_| ErrorKind::FailedInit)?;
    if der.is_null() {
        return Err(ErrorKind::FailedInit);
    }
    Ok(Der(der, len))
}

/// What a session's peer came to by SecTrust (`ossl_apple_verify`): the
/// peer's chain checked, its name too if `host`, its revocation unless
/// `no_revoke`, with the status the server stapled. A resumed session has
/// no chain: its peer is trusted if its session came from one SecTrust
/// verified (`from_verified`). `Ok(true)` if SecTrust trusts it.
///
/// # Safety
/// `ssl` is the session's, its handshake done.
pub(crate) unsafe fn verify(
    ssl: NonNull<SSL>,
    host: Option<&[u8]>,
    no_revoke: bool,
    verify_status: bool,
    reused: bool,
    from_verified: bool,
    io: &mut TlsCx<'_>,
) -> Result<bool, ErrorKind> {
    // SAFETY: the session's SSL; the chain is its own.
    let stack = unsafe { openssl_sys::SSL_get_peer_cert_chain(ssl.as_ptr()) };
    let stack = stack.cast::<openssl_sys::OPENSSL_STACK>();
    let count = if stack.is_null() {
        0
    } else {
        // SAFETY: the chain, alive with the session.
        usize::try_from(unsafe { openssl_sys::OPENSSL_sk_num(stack) }).unwrap_or(0)
    };
    // C's caller asks only when the peer is to be verified, so the chain
    // is wanted.
    if count == 0 {
        if !reused {
            return Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("SSL: could not get peer certificate chain"),
            ));
        }
        io.trace(format_args!(
            "session reused, sectrust_session={}",
            u8::from(from_verified)
        ));
        return Ok(from_verified);
    }
    let mut ocsp: *mut u8 = ptr::null_mut();
    let mut ocsp_len: c_long = 0;
    if !reused {
        // SAFETY: the session's SSL; the response is its own, alive while
        // it is.
        ocsp_len = unsafe { openssl_sys::SSL_get_tlsext_status_ocsp_resp(ssl.as_ptr(), &mut ocsp) };
    }
    let ocsp: &[u8] = match usize::try_from(ocsp_len) {
        // SAFETY: `n` bytes at `ocsp`, the SSL's.
        Ok(n) if n > 0 && !ocsp.is_null() => unsafe { core::slice::from_raw_parts(ocsp, n) },
        _ => &[],
    };
    let require_ocsp = !reused && verify_status;
    // SAFETY: the chain, `count` long, alive for the call.
    let result = unsafe { evaluate(stack, count, host, no_revoke, ocsp, require_ocsp, io) };
    match result {
        Ok(()) => Ok(true),
        Err(ErrorKind::PeerFailedVerification) => Ok(false),
        Err(kind) => Err(kind),
    }
}

/// `Curl_vtls_apple_verify`: the chain's `count` certificates, the SSL
/// policy for `host` (any name if none), the revocation policy unless
/// `no_revoke`, the stapled `ocsp` response, and SecTrust's verdict.
///
/// # Safety
/// `stack` is a chain of at least `count` certificates, alive for the call.
unsafe fn evaluate(
    stack: *mut openssl_sys::OPENSSL_STACK,
    count: usize,
    host: Option<&[u8]>,
    no_revoke: bool,
    ocsp: &[u8],
    require_ocsp: bool,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let oom = ErrorKind::OutOfMemory;
    let host_str = match host {
        Some(host) => {
            // C hands the name as a C string: it ends at a NUL.
            let host = host.split(|&b| b == 0).next().unwrap_or_default();
            let mut z = Vec::new();
            z.try_reserve_exact(host.len() + 1).map_err(|_| oom)?;
            z.try_extend_from_slice(host).map_err(|_| oom)?;
            z.try_push(0).map_err(|_| oom)?;
            // SAFETY: a NUL-terminated string, read for the call.
            let made = unsafe { CFStringCreateWithCString(ptr::null(), z.as_ptr().cast(), UTF8) };
            Some(Owned::of(made).ok_or(oom)?)
        }
        None => None,
    };
    // SAFETY: no allocator, room for two, the callbacks that retain what
    // is added.
    let policies =
        unsafe { CFArrayCreateMutable(ptr::null(), 2, &raw const kCFTypeArrayCallBacks) };
    let policies = Owned::of(policies).ok_or(oom)?;
    let host_ref = host_str.as_ref().map_or(ptr::null(), |h| h.0);
    // SAFETY: a server's policy, for the name if any.
    let ssl_policy = Owned::of(unsafe { SecPolicyCreateSSL(1, host_ref) }).ok_or(oom)?;
    // SAFETY: the array, which retains the policy added.
    unsafe { CFArrayAppendValue(policies.0.cast_mut(), ssl_policy.0) };
    drop(ssl_policy);
    if !no_revoke {
        // trustd may also ask CRLs and OCSP whether a certificate is
        // revoked; one it already knows to be fails without this.
        let mut flags = REVOCATION_ANY;
        if require_ocsp {
            flags |= REVOCATION_REQUIRE_POSITIVE;
        }
        // SAFETY: flags of the revocation policy.
        let revocation = Owned::of(unsafe { SecPolicyCreateRevocation(flags) }).ok_or(oom)?;
        // SAFETY: as above.
        unsafe { CFArrayAppendValue(policies.0.cast_mut(), revocation.0) };
    }
    // SAFETY: as for `policies`, room for the chain.
    let certs = unsafe {
        CFArrayCreateMutable(
            ptr::null(),
            CFIndex::try_from(count).map_err(|_| oom)?,
            &raw const kCFTypeArrayCallBacks,
        )
    };
    let certs = Owned::of(certs).ok_or(oom)?;
    for i in 0..count {
        // SAFETY: as the caller says; `i` below the count.
        let der = unsafe { der_at(stack, i) }?;
        let len = CFIndex::try_from(der.1).map_err(|_| oom)?;
        // SAFETY: `der.1` bytes at `der.0`, copied into the data.
        let data = Owned::of(unsafe { CFDataCreate(ptr::null(), der.0, len) }).ok_or(oom)?;
        drop(der);
        // SAFETY: the certificate's DER as data.
        let cert = Owned::of(unsafe { SecCertificateCreateWithData(ptr::null(), data.0) });
        let cert = cert.ok_or(oom)?;
        // SAFETY: the array, which retains the certificate added.
        unsafe { CFArrayAppendValue(certs.0.cast_mut(), cert.0) };
    }
    let mut trust: CFTypeRef = ptr::null();
    // SAFETY: the certificates and policies, and where SecTrust puts the
    // trust object it makes.
    let status = unsafe { SecTrustCreateWithCertificates(certs.0, policies.0, &mut trust) };
    let trust = Owned::of(trust);
    let trust = match trust {
        Some(trust) if status == 0 => trust,
        _ => {
            return Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("Apple SecTrust: failed to create validation trust"),
            ));
        }
    };
    if !ocsp.is_empty() {
        let len = CFIndex::try_from(ocsp.len()).map_err(|_| oom)?;
        // SAFETY: the response's bytes, copied into the data.
        let data = Owned::of(unsafe { CFDataCreate(ptr::null(), ocsp.as_ptr(), len) });
        let data = data.ok_or(oom)?;
        // SAFETY: the trust object and the response.
        let status = unsafe { SecTrustSetOCSPResponse(trust.0, data.0) };
        if status != 0 {
            return Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("Apple SecTrust: failed to set OCSP response: {status}"),
            ));
        }
    }
    let mut error: CFTypeRef = ptr::null();
    // SAFETY: the trust object, and where SecTrust puts an error it makes.
    let trusted = unsafe { SecTrustEvaluateWithError(trust.0, &mut error) };
    let mut result = if trusted {
        Ok(())
    } else {
        Err(ErrorKind::PeerFailedVerification)
    };
    if let Some(error) = Owned::of(error) {
        // SAFETY: the error SecTrust made.
        let code = unsafe { CFErrorGetCode(error.0) };
        // SAFETY: as above; a description of our own, or none.
        let described = Owned::of(unsafe { CFErrorCopyDescription(error.0) });
        let text = described.as_ref().and_then(|d| string_of(d.0));
        match &text {
            Some(text) => io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("Apple SecTrust failure {code}: {}", Text(text)),
            ),
            None => io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("Apple SecTrust failure {code}"),
            ),
        };
        if code == INCOMPLETE_REVOCATION_CHECK {
            result = Err(ErrorKind::SslInvalidcertstatus);
        }
    }
    result
}

/// A Core Foundation string's text in UTF-8, as C copies it: into a buffer
/// of the encoding's largest size for its length, which a string as large
/// as that does not fit with its NUL. None if it does not convert.
fn string_of(string: CFTypeRef) -> Option<Vec<u8>> {
    // SAFETY: a string of ours, alive for the call.
    let len = unsafe { CFStringGetLength(string) };
    // SAFETY: a function of no state.
    let size = unsafe { CFStringGetMaximumSizeForEncoding(len, UTF8) };
    let room = usize::try_from(size).ok()?.checked_add(1)?;
    let mut buffer: Vec<u8> = Vec::new();
    buffer.try_reserve_exact(room).ok()?;
    buffer.try_resize(room, 0).ok()?;
    // SAFETY: the string, and `size` bytes of room at the buffer's start,
    // which has one more.
    let ok = unsafe { CFStringGetCString(string, buffer.as_mut_ptr().cast(), size, UTF8) };
    if ok == 0 {
        return None;
    }
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    buffer.truncate(end);
    Some(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A description converts whole, as C's copy holds it.
    #[test]
    fn a_string_converts_as_c_copies_it() {
        let text = c"“self signed” certificate";
        // SAFETY: a C string, read for the call.
        let s = Owned::of(unsafe { CFStringCreateWithCString(ptr::null(), text.as_ptr(), UTF8) })
            .unwrap();
        assert_eq!(string_of(s.0).as_deref(), Some(text.to_bytes()));
    }

    /// A call that made nothing gives nothing to release: SecTrust leaves
    /// no error when it trusts the peer, and Core Foundation traps on a
    /// release of none.
    #[test]
    fn nothing_made_is_not_released() {
        assert!(Owned::of(ptr::null()).is_none());
    }
}
