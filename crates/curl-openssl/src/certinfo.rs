//! The peer's chain as a transfer that asks for it reports it
//! (`ossl_certchain`): each certificate's names, version, serial,
//! algorithms, extensions, dates, public key, signature and PEM, as
//! `label:value` lines worded and ordered as openssl.c's.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int};
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::error::ErrorKind;
use curl_core::report::{CertInfo, MAX_CERTS};
use curl_core::tls::TlsIo;
use openssl_sys::{EVP_PKEY, SSL, X509};

use crate::ffi;
use crate::x509::MemBio;

/// Report the peer's chain, if the transfer asked for it. A chain that
/// cannot be had, or is longer than C allows, fails the handshake; one
/// that cannot be kept fails it as out of memory, nothing reported.
pub(crate) fn report(ssl: NonNull<SSL>, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
    if !io.wants_certinfo() {
        return Ok(());
    }
    // SAFETY: the session's SSL; the chain is its own, alive while it is.
    let chain = unsafe { openssl_sys::SSL_get_peer_cert_chain(ssl.as_ptr()) };
    if chain.is_null() {
        return Err(ErrorKind::SslConnectError);
    }
    let stack = chain.cast::<openssl_sys::OPENSSL_STACK>();
    // SAFETY: a stack of certificates.
    let n = unsafe { openssl_sys::OPENSSL_sk_num(stack) };
    let count = usize::try_from(n).unwrap_or(0);
    if count > MAX_CERTS {
        return Err(io.fail(
            ErrorKind::SslConnectError,
            format_args!("{n} certificates is more than allowed ({MAX_CERTS})"),
        ));
    }
    let made = (|| {
        let mut info = CertInfo::new(count)?;
        let mut mem = MemBio::new().ok_or(OutOfMemory)?;
        for i in 0..count {
            // SAFETY: an entry of the stack, a certificate, the chain's.
            let x = unsafe { openssl_sys::OPENSSL_sk_value(stack, i as c_int) }.cast::<X509>();
            let Some(x) = NonNull::new(x) else { continue };
            certificate(&mut info, i, x, &mut mem, io)?;
        }
        Ok(info)
    })();
    match made {
        Ok(info) => io.set_certinfo(Some(info)),
        Err(OutOfMemory) => {
            io.set_certinfo(None)?;
            Err(ErrorKind::OutOfMemory)
        }
    }
}

/// What `mem` holds, as certificate `i`'s `label`, `mem` emptied after
/// (`push_certinfo`).
fn push(info: &mut CertInfo, i: usize, label: &[u8], mem: &mut MemBio) -> Result<(), OutOfMemory> {
    let pushed = info.push(i, label, mem.bytes());
    mem.reset();
    pushed
}

/// `text` written to `mem`, as `BIO_printf` would.
fn print(mem: &MemBio, text: &[u8]) {
    let Ok(len) = c_int::try_from(text.len()) else {
        return;
    };
    // SAFETY: the BIO, and `len` bytes at `text`.
    unsafe { openssl_sys::BIO_write(mem.as_ptr(), text.as_ptr().cast(), len) };
}

/// The bytes of an ASN.1 string, the library's, alive while it is.
///
/// # Safety
///
/// `s` is null or an ASN.1 string alive for `'a`.
unsafe fn asn1_bytes<'a>(s: *const openssl_sys::ASN1_STRING) -> &'a [u8] {
    if s.is_null() {
        return &[];
    }
    // SAFETY: as the caller says.
    let data = unsafe { openssl_sys::ASN1_STRING_get0_data(s) };
    // SAFETY: as above.
    let len = unsafe { openssl_sys::ASN1_STRING_length(s) };
    match usize::try_from(len) {
        // SAFETY: the string's `len` bytes.
        Ok(len) if len > 0 && !data.is_null() => unsafe { core::slice::from_raw_parts(data, len) },
        _ => &[],
    }
}

/// Bytes as lowercase hex, each followed by `after` (`%02x`).
fn hex(bytes: &[u8], after: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = Vec::new();
    s.try_reserve_exact(bytes.len() * (2 + after.len()))
        .map_err(|_| OutOfMemory)?;
    for &b in bytes {
        s.try_push(DIGITS[usize::from(b >> 4)])?;
        s.try_push(DIGITS[usize::from(b & 15)])?;
        s.try_extend_from_slice(after)?;
    }
    Ok(s)
}

/// One certificate's lines.
fn certificate(
    info: &mut CertInfo,
    i: usize,
    x: NonNull<X509>,
    mem: &mut MemBio,
    io: &mut TlsIo<'_>,
) -> Result<(), OutOfMemory> {
    let x = x.as_ptr();
    // SAFETY: the certificate; its names are its own.
    let subject = unsafe { openssl_sys::X509_get_subject_name(x) };
    // SAFETY: the BIO and the name.
    unsafe { ffi::X509_NAME_print_ex(mem.as_ptr(), subject, 0, ffi::XN_FLAG_ONELINE) };
    push(info, i, b"Subject", mem)?;
    // SAFETY: as above.
    let issuer = unsafe { openssl_sys::X509_get_issuer_name(x) };
    // SAFETY: as above.
    unsafe { ffi::X509_NAME_print_ex(mem.as_ptr(), issuer, 0, ffi::XN_FLAG_ONELINE) };
    push(info, i, b"Issuer", mem)?;

    // SAFETY: the certificate.
    let version = unsafe { openssl_sys::X509_get_version(x) };
    let text = curl_alloc::try_format(format_args!("{:x}", version as u64))?;
    print(mem, text.as_bytes());
    push(info, i, b"Version", mem)?;

    // SAFETY: the certificate; its serial is its own.
    let serial = unsafe { openssl_sys::X509_get_serialNumber(x) }
        .cast_const()
        .cast();
    // SAFETY: as above.
    if unsafe { openssl_sys::ASN1_STRING_type(serial) } == ffi::V_ASN1_NEG_INTEGER {
        print(mem, b"-");
    }
    // SAFETY: as above, alive while the certificate is.
    print(mem, &hex(unsafe { asn1_bytes(serial) }, b"")?);
    push(info, i, b"Serial Number", mem)?;

    let mut sig: *const openssl_sys::ASN1_BIT_STRING = ptr::null();
    let mut alg: *const openssl_sys::X509_ALGOR = ptr::null();
    // SAFETY: the certificate; what it gives is its own.
    unsafe { openssl_sys::X509_get0_signature(&mut sig, &mut alg, x) };
    if !alg.is_null() {
        let mut oid: *const openssl_sys::ASN1_OBJECT = ptr::null();
        // SAFETY: the algorithm, the certificate's.
        unsafe { openssl_sys::X509_ALGOR_get0(&mut oid, ptr::null_mut(), ptr::null_mut(), alg) };
        // SAFETY: the BIO and the object, or null, which prints `NULL`.
        unsafe { ffi::i2a_ASN1_OBJECT(mem.as_ptr(), oid) };
        push(info, i, b"Signature Algorithm", mem)?;
    }
    // SAFETY: the certificate; its key is its own.
    let xpubkey = unsafe { ffi::X509_get_X509_PUBKEY(x) };
    if !xpubkey.is_null() {
        let mut oid: *mut openssl_sys::ASN1_OBJECT = ptr::null_mut();
        // SAFETY: the key; the object is its own.
        unsafe {
            ffi::X509_PUBKEY_get0_param(
                &mut oid,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                xpubkey,
            )
        };
        if !oid.is_null() {
            // SAFETY: the BIO and the object.
            unsafe { ffi::i2a_ASN1_OBJECT(mem.as_ptr(), oid) };
            push(info, i, b"Public Key Algorithm", mem)?;
        }
    }
    extensions(info, i, x)?;

    // SAFETY: the certificate; its dates are its own.
    let start = unsafe { ffi::X509_get0_notBefore(x) };
    // SAFETY: the BIO and the date.
    unsafe { openssl_sys::ASN1_TIME_print(mem.as_ptr(), start) };
    push(info, i, b"Start date", mem)?;
    // SAFETY: as above.
    let expire = unsafe { ffi::X509_get0_notAfter(x) };
    // SAFETY: as above.
    unsafe { openssl_sys::ASN1_TIME_print(mem.as_ptr(), expire) };
    push(info, i, b"Expire date", mem)?;

    // SAFETY: the certificate; a reference to its key, freed below.
    let pubkey = unsafe { openssl_sys::X509_get_pubkey(x) };
    if pubkey.is_null() {
        io.info(format_args!("   Unable to load public key"));
    } else {
        let shown = public_key(info, i, pubkey, mem);
        // SAFETY: the reference taken above, given back once.
        unsafe { openssl_sys::EVP_PKEY_free(pubkey) };
        shown?;
    }

    if !sig.is_null() {
        // SAFETY: the signature, the certificate's.
        print(mem, &hex(unsafe { asn1_bytes(sig.cast()) }, b":")?);
        push(info, i, b"Signature", mem)?;
    }
    // SAFETY: the BIO and the certificate.
    unsafe { openssl_sys::PEM_write_bio_X509(mem.as_ptr(), x) };
    push(info, i, b"Cert", mem)
}

/// Each extension as its name and what the library prints of it
/// (`X509V3_ext`).
fn extensions(info: &mut CertInfo, i: usize, x: *mut X509) -> Result<(), OutOfMemory> {
    // SAFETY: the certificate; the stack is its own.
    let exts = unsafe { openssl_sys::X509_get0_extensions(x) }.cast::<openssl_sys::OPENSSL_STACK>();
    if exts.is_null() {
        return Ok(());
    }
    // SAFETY: a stack of extensions.
    let n = unsafe { openssl_sys::OPENSSL_sk_num(exts) };
    for e in 0..n.max(0) {
        // SAFETY: an entry of the stack, an extension.
        let ext =
            unsafe { openssl_sys::OPENSSL_sk_value(exts, e) }.cast::<openssl_sys::X509_EXTENSION>();
        // As C, an extension whose BIO cannot be made ends them, and no
        // error is made of it.
        let Some(mut out) = MemBio::new() else {
            return Ok(());
        };
        // SAFETY: the extension; its object is its own.
        let obj = unsafe { openssl_sys::X509_EXTENSION_get_object(ext) };
        let mut name = [0u8; 128];
        // SAFETY: room for 128 bytes, the library ending what it writes
        // within them with a zero byte.
        unsafe { ffi::i2t_ASN1_OBJECT(name.as_mut_ptr().cast::<c_char>(), 128, obj) };
        let name = until_zero(&name);
        // SAFETY: the BIO and the extension.
        if unsafe { openssl_sys::X509V3_EXT_print(out.as_ptr(), ext, 0, 0) } == 0 {
            // SAFETY: the extension; its data is its own.
            let data = unsafe { openssl_sys::X509_EXTENSION_get_data(ext) };
            // SAFETY: the BIO and the data.
            unsafe { ffi::ASN1_STRING_print(out.as_ptr(), data.cast_const().cast()) };
        }
        push(info, i, name, &mut out)?;
    }
    Ok(())
}

fn until_zero(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|&b| b == 0)
        .map_or(bytes, |n| &bytes[..n])
}

/// An RSA, DSA or DH key's numbers (`get_pkey_rsa`, `get_pkey_dsa`,
/// `get_pkey_dh`); nothing for another.
fn public_key(
    info: &mut CertInfo,
    i: usize,
    key: *mut EVP_PKEY,
    mem: &mut MemBio,
) -> Result<(), OutOfMemory> {
    // SAFETY: the key.
    let (kind, params): (&str, &[(&[u8], &str)]) = match unsafe { openssl_sys::EVP_PKEY_id(key) } {
        openssl_sys::EVP_PKEY_RSA => ("rsa", &[(b"n\0", "n"), (b"e\0", "e")]),
        openssl_sys::EVP_PKEY_DSA => (
            "dsa",
            &[
                (b"p\0", "p"),
                (b"q\0", "q"),
                (b"g\0", "g"),
                (b"pub\0", "pub_key"),
            ],
        ),
        openssl_sys::EVP_PKEY_DH => (
            "dh",
            &[
                (b"p\0", "p"),
                (b"q\0", "q"),
                (b"g\0", "g"),
                (b"pub\0", "pub_key"),
            ],
        ),
        _ => return Ok(()),
    };
    let mut first = true;
    for (param, shown) in params {
        let mut bn: *mut openssl_sys::BIGNUM = ptr::null_mut();
        // SAFETY: the key and a parameter's name as a C string; the
        // number, if any, is this function's to free.
        unsafe { openssl_sys::EVP_PKEY_get_bn_param(key, param.as_ptr().cast(), &mut bn) };
        if first && kind == "rsa" {
            let bits = if bn.is_null() {
                0
            } else {
                // SAFETY: the number.
                unsafe { openssl_sys::BN_num_bits(bn) }
            };
            let text = curl_alloc::try_format(format_args!("{bits}"));
            let pushed = text.map(|t| {
                print(mem, t.as_bytes());
                push(info, i, b"RSA Public Key", mem)
            });
            if let Err(e) | Ok(Err(e)) = pushed {
                // SAFETY: the number, or null, freed once.
                unsafe { openssl_sys::BN_free(bn) };
                return Err(e);
            }
        }
        first = false;
        if !bn.is_null() {
            // SAFETY: the BIO and the number.
            unsafe { ffi::BN_print(mem.as_ptr(), bn) };
        }
        // SAFETY: the number, or null, freed once.
        unsafe { openssl_sys::BN_free(bn) };
        let label = curl_alloc::try_format(format_args!("{kind}({shown})"))?;
        push(info, i, label.as_bytes(), mem)?;
    }
    Ok(())
}
