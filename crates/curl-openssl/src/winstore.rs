//! Windows' certificate stores, ROOT and CA, read into the store a
//! session trusts (`ossl_windows_load_anchors`, `ossl_win_load_store`):
//! the system's own store, as C's build reads it on Windows where the
//! transfer asks for it (`CURLSSLOPT_NATIVE_CA`) or the build makes it the
//! default. Which of their certificates are taken is `native`'s choice,
//! from what the system says of each.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_long};
use core::fmt;
use core::ptr::{self, NonNull};
use core::slice;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::error::ErrorKind;
use curl_core::tls::TlsCx;
use openssl_sys::X509_STORE;
use windows_sys::Win32::Foundation::{CRYPT_E_NOT_FOUND, FILETIME, GetLastError};
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CTL_USAGE, CertCloseStore,
    CertEnumCertificatesInStore, CertFreeCertificateContext, CertGetEnhancedKeyUsage,
    CertGetIntendedKeyUsage, CertGetNameStringA, CertOpenSystemStoreA,
};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

use crate::native::{self, KeyUsage, Uses};
use crate::x509::Text;

/// The stores read, in C's order: trusted roots, then intermediates.
const STORES: [&CStr; 2] = [c"ROOT", c"CA"];

/// Add the certificates C would take of Windows' stores to `store`.
/// Whether any store added one; an error only for memory that ran out.
pub(crate) fn load(store: NonNull<X509_STORE>, io: &mut TlsCx<'_>) -> Result<bool, ErrorKind> {
    let mut added = false;
    for name in STORES {
        let shown = Text(name.to_bytes());
        if load_store(store, name, io)? {
            io.trace(format_args!(
                "added trust anchors from Windows {shown} store"
            ));
            added = true;
        } else {
            io.info(format_args!(
                "error importing Windows {shown} store, continuing anyway"
            ));
        }
    }
    Ok(added)
}

/// A file time as one number, ordered as `CompareFileTime` orders them.
fn file_time(t: FILETIME) -> u64 {
    (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
}

/// The store `name` of the system's, open; closed as it goes.
struct Store(*mut core::ffi::c_void);

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: opened by `CertOpenSystemStoreA`, closed once, after the
        // last of its certificates is given back. C ignores the result.
        unsafe { CertCloseStore(self.0, 0) };
    }
}

/// The certificates of the store `name` C would take, added to `store`
/// (`ossl_win_load_store`): whether one was.
fn load_store(
    store: NonNull<X509_STORE>,
    name: &CStr,
    io: &mut TlsCx<'_>,
) -> Result<bool, ErrorKind> {
    // SAFETY: no provider, and a C string naming the store.
    let opened = unsafe { CertOpenSystemStoreA(0, name.as_ptr().cast()) };
    if opened.is_null() {
        return Ok(false);
    }
    let opened = Store(opened);
    let mut added = false;
    let mut total = 0usize;
    let mut imported = 0usize;
    // The uses' answer, grown as a certificate's needs more, kept across
    // them as C keeps it; in words, for the pointers it holds.
    let mut usage: Vec<u64> = Vec::new();
    let mut result = Ok(());
    let mut context: *const CERT_CONTEXT = ptr::null();
    loop {
        // SAFETY: the store, and the certificate before, which the call
        // gives back.
        context = unsafe { CertEnumCertificatesInStore(opened.0, context) };
        if context.is_null() {
            break;
        }
        total += 1;
        io.debug_info(format_args!("{}", Checking(context)));
        // SAFETY: a certificate of the store, alive until the next call.
        let cert = unsafe { &*context };
        if cert.pbCertEncoded.is_null() {
            continue;
        }
        let mut now = FILETIME::default();
        // SAFETY: a place to write the time to.
        unsafe { GetSystemTimeAsFileTime(&mut now) };
        // SAFETY: the certificate's information, alive while it is.
        let info = unsafe { &*cert.pCertInfo };
        let (before, after) = (file_time(info.NotBefore), file_time(info.NotAfter));
        if !native::valid_at(before, after, file_time(now)) {
            continue;
        }
        if !native::signs_certificates(key_usage(cert)) {
            continue;
        }
        match uses(cert, &mut usage) {
            Ok(uses) if native::serves(uses) => {}
            Ok(_) => continue,
            Err(OutOfMemory) => {
                io.fail(
                    ErrorKind::OutOfMemory,
                    format_args!("SSL: Out of memory allocating for OID list"),
                );
                result = Err(ErrorKind::OutOfMemory);
                break;
            }
        }
        let mut der = cert.pbCertEncoded.cast_const();
        let len = c_long::try_from(cert.cbCertEncoded).unwrap_or(c_long::MAX);
        // SAFETY: the certificate's encoding, `len` bytes, alive until the
        // next call; the certificate read is this one's to free.
        let x509 = unsafe { openssl_sys::d2i_X509(ptr::null_mut(), &mut der, len) };
        if x509.is_null() {
            continue;
        }
        // Refused as a duplicate, which Windows allows and OpenSSL does
        // not: left out.
        // SAFETY: the store, which takes its own reference.
        if unsafe { openssl_sys::X509_STORE_add_cert(store.as_ptr(), x509) } == 1 {
            imported += 1;
            io.debug_info(format_args!("SSL: Imported cert"));
            added = true;
        }
        // SAFETY: the reference read above, given back once.
        unsafe { openssl_sys::X509_free(x509) };
    }
    if !context.is_null() {
        // SAFETY: the certificate the loop stopped at, given back once.
        unsafe { CertFreeCertificateContext(context) };
    }
    drop(opened);
    io.trace(format_args!(
        "ossl_win_load_store() found: {total} imported: {imported} certs in {}.",
        Text(name.to_bytes())
    ));
    result.map(|()| added)
}

/// What `cert`'s key usage extension says.
fn key_usage(cert: &CERT_CONTEXT) -> KeyUsage {
    let mut bits = [0u8; 2];
    // SAFETY: the certificate's encoding and information, and a buffer of
    // the length given.
    let has = unsafe {
        CertGetIntendedKeyUsage(
            cert.dwCertEncodingType,
            cert.pCertInfo,
            bits.as_mut_ptr(),
            2,
        )
    };
    if has != 0 {
        return KeyUsage::Says(bits[0]);
    }
    // SAFETY: the thread's last error, which the call above set.
    if unsafe { GetLastError() } != 0 {
        KeyUsage::Unreadable
    } else {
        KeyUsage::Absent
    }
}

/// What the system says `cert` may be used for, its answer read into
/// `usage`, grown as needed: memory run out growing it is the error.
fn uses(cert: &CERT_CONTEXT, usage: &mut Vec<u64>) -> Result<Uses, OutOfMemory> {
    let mut size: u32 = 0;
    // SAFETY: the certificate, and a place for the size of the answer.
    let sized = unsafe { CertGetEnhancedKeyUsage(cert, 0, ptr::null_mut(), &mut size) };
    if sized == 0 || size == 0 {
        return Ok(Uses::Unsaid);
    }
    let words = (size as usize).div_ceil(8);
    if usage.len() < words {
        usage.try_resize(words, 0)?;
    }
    let answer = usage.as_mut_ptr().cast::<CTL_USAGE>();
    // SAFETY: the certificate, and a buffer of at least `size` bytes,
    // aligned for the answer, which points into itself.
    if unsafe { CertGetEnhancedKeyUsage(cert, 0, answer, &mut size) } == 0 {
        return Ok(Uses::Unreadable);
    }
    // SAFETY: the answer the call wrote.
    let answer = unsafe { &*answer };
    if answer.cUsageIdentifier == 0 {
        // SAFETY: the thread's last error, which the call above set.
        let why = unsafe { GetLastError() };
        // The error is an `HRESULT`'s bits.
        return Ok(if why == CRYPT_E_NOT_FOUND as u32 {
            Uses::Every
        } else {
            Uses::None
        });
    }
    // SAFETY: the answer's object ids, as many as it counts, in the
    // buffer, alive while it is.
    let oids = unsafe {
        slice::from_raw_parts(
            answer.rgpszUsageIdentifier,
            answer.cUsageIdentifier as usize,
        )
    };
    let oids = oids.iter().map(|&oid| {
        // SAFETY: each a C string in the buffer, as above.
        unsafe { CStr::from_ptr(oid.cast()) }.to_bytes()
    });
    Ok(Uses::Named {
        server_auth: native::names_server_auth(oids),
    })
}

/// The line C's debug build says of each certificate as it reads it:
/// its display name, as the system's code page has it.
struct Checking(*const CERT_CONTEXT);

impl fmt::Display for Checking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut name = [0u8; 256];
        // SAFETY: the certificate, alive while the line is made; the name
        // is written within the buffer named, ended by a zero byte.
        let len = unsafe {
            CertGetNameStringA(
                self.0,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                ptr::null(),
                name.as_mut_ptr(),
                256,
            )
        };
        if len == 0 {
            return f.write_str("SSL: unknown cert name");
        }
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        write!(f, "SSL: Checking cert \"{}\"", Text(&name[..end]))
    }
}
