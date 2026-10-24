//! The client's certificate and key, loaded into the session's context
//! as openssl.c's `client_cert` loads them: PEM (a chain), DER, PKCS#12,
//! from a file or from memory, the key from its own file or the
//! certificate's, a password handed to OpenSSL by `passwd_callback`; a
//! certificate or key of an engine or a provider is refused as C refuses
//! it when none is set.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr::{self, NonNull};

use curl_core::error::ErrorKind;
use curl_core::options::TlsOptions;
use curl_core::tls::TlsIo;
use openssl_sys::{EVP_PKEY, SSL_CTX, X509};

use crate::engine::{Crypto, Wanted};
use crate::ffi;
use crate::ssl::{error_lib, error_reason};
use crate::x509::{ErrText, MemBio, Text, c_string};

/// What a certificate or key file holds (`ossl_do_file_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileType {
    Pem,
    /// DER (`SSL_FILETYPE_ASN1`).
    Asn1,
    Engine,
    Pkcs12,
    Provider,
}

/// The type a `CURLOPT_SSLCERTTYPE` or `CURLOPT_SSLKEYTYPE` names, PEM
/// for none, in any case; none for one unknown.
fn file_type(name: Option<&[u8]>) -> Option<FileType> {
    let Some(name) = name.filter(|n| !n.is_empty()) else {
        return Some(FileType::Pem);
    };
    [
        (&b"PEM"[..], FileType::Pem),
        (b"DER", FileType::Asn1),
        (b"PROV", FileType::Provider),
        (b"ENG", FileType::Engine),
        (b"P12", FileType::Pkcs12),
    ]
    .into_iter()
    .find(|(n, _)| n.eq_ignore_ascii_case(name))
    .map(|(_, t)| t)
}

/// What OpenSSL asks of a password, given the one the transfer has
/// (`passwd_callback`): it, if it fits the room, else none.
///
/// # Safety
///
/// `buf` has room for `num` bytes; `password` is null or a C string.
unsafe extern "C" fn passwd_callback(
    buf: *mut c_char,
    num: c_int,
    encrypting: c_int,
    password: *mut c_void,
) -> c_int {
    if encrypting != 0 || num < 0 || password.is_null() {
        return 0;
    }
    // SAFETY: a C string, as the caller says.
    let text = unsafe { core::ffi::CStr::from_ptr(password.cast()) }.to_bytes_with_nul();
    let klen = text.len() - 1;
    match c_int::try_from(klen) {
        Ok(k) if num > k => {
            // SAFETY: `klen + 1` bytes fit the `num` of room, and the
            // password is not in the buffer.
            unsafe { ptr::copy_nonoverlapping(text.as_ptr(), buf.cast::<u8>(), klen + 1) };
            k
        }
        _ => 0,
    }
}

/// The password as the context hands it to OpenSSL: null for none.
fn password_ptr(password: Option<&Vec<u8>>) -> *mut c_void {
    password.map_or(ptr::null_mut(), |p| p.as_ptr().cast_mut().cast())
}

/// A BIO reading `blob`, which outlives it; none if it cannot be made.
fn blob_bio(blob: &[u8]) -> Option<MemBio> {
    let len = c_int::try_from(blob.len()).ok()?;
    // SAFETY: a BIO reading `blob`, freed before `blob` goes, as the
    // caller keeps it.
    let bio = unsafe { openssl_sys::BIO_new_mem_buf(blob.as_ptr().cast(), len) };
    NonNull::new(bio).map(MemBio::adopt)
}

/// A certificate of the blob, DER or PEM, made the context's
/// (`use_certificate_blob`): 1 if it was.
fn use_certificate_blob(
    ctx: NonNull<SSL_CTX>,
    blob: &[u8],
    kind: FileType,
    password: *mut c_void,
) -> c_int {
    // Without a BIO the blob is not used, which C says as for one it
    // could not read.
    let Some(bio) = blob_bio(blob) else {
        return 0;
    };
    let x = match kind {
        // SAFETY: the BIO; no certificate to reuse.
        FileType::Asn1 => unsafe { openssl_sys::d2i_X509_bio(bio.as_ptr(), ptr::null_mut()) },
        // SAFETY: as above, with C's callback and the password it reads.
        FileType::Pem => unsafe {
            openssl_sys::PEM_read_bio_X509(
                bio.as_ptr(),
                ptr::null_mut(),
                Some(passwd_callback),
                password,
            )
        },
        _ => return 0,
    };
    if x.is_null() {
        return 0;
    }
    // SAFETY: the context, which takes its own reference to `x`.
    let ret = unsafe { openssl_sys::SSL_CTX_use_certificate(ctx.as_ptr(), x) };
    // SAFETY: the reference the read made, given back once.
    unsafe { openssl_sys::X509_free(x) };
    ret
}

/// A key of the blob, PEM or DER, made the context's
/// (`use_privatekey_blob`): 1 if it was.
fn use_privatekey_blob(
    ctx: NonNull<SSL_CTX>,
    blob: &[u8],
    kind: FileType,
    password: *mut c_void,
) -> c_int {
    // Without a BIO the blob is not used, which C says as for one it
    // could not read.
    let Some(bio) = blob_bio(blob) else {
        return 0;
    };
    let key: *mut EVP_PKEY = match kind {
        // SAFETY: the BIO, with C's callback and the password it reads.
        FileType::Pem => unsafe {
            openssl_sys::PEM_read_bio_PrivateKey(
                bio.as_ptr(),
                ptr::null_mut(),
                Some(passwd_callback),
                password,
            )
        },
        // SAFETY: the BIO; no key to reuse.
        FileType::Asn1 => unsafe { ffi::d2i_PrivateKey_bio(bio.as_ptr(), ptr::null_mut()) },
        _ => return 0,
    };
    if key.is_null() {
        return 0;
    }
    // SAFETY: the context, which takes its own reference to the key.
    let ret = unsafe { openssl_sys::SSL_CTX_use_PrivateKey(ctx.as_ptr(), key) };
    // SAFETY: the reference the read made, given back once.
    unsafe { openssl_sys::EVP_PKEY_free(key) };
    ret
}

/// The PEM chain of the blob made the context's: its first certificate,
/// the rest as the chain sent with it (`use_certificate_chain_blob`,
/// as `SSL_CTX_use_certificate_chain_file` reads a file): 1 if it was.
fn use_certificate_chain_blob(ctx: NonNull<SSL_CTX>, blob: &[u8], password: *mut c_void) -> c_int {
    // Without a BIO the blob is not used, which C says as for one it
    // could not read.
    let Some(bio) = blob_bio(blob) else {
        return 0;
    };
    // SAFETY: the thread's error queue.
    unsafe { openssl_sys::ERR_clear_error() };
    // SAFETY: the BIO, with C's callback and the password it reads.
    let x = unsafe {
        ffi::PEM_read_bio_X509_AUX(
            bio.as_ptr(),
            ptr::null_mut(),
            Some(passwd_callback),
            password,
        )
    };
    if x.is_null() {
        return 0;
    }
    let c = ctx.as_ptr();
    // SAFETY: the context, which takes its own reference to `x`.
    let mut ret = unsafe { openssl_sys::SSL_CTX_use_certificate(c, x) };
    // SAFETY: the thread's error queue, looked at.
    if unsafe { ffi::ERR_peek_error() } != 0 {
        ret = 0;
    }
    if ret != 0 {
        ret = chain_rest(c, &bio, password);
    }
    // SAFETY: the reference the read made, given back once.
    unsafe { openssl_sys::X509_free(x) };
    ret
}

/// The certificates after the first of `bio`, the context's chain; 1 if
/// they were, and the read ended where the text did.
fn chain_rest(c: *mut SSL_CTX, bio: &MemBio, password: *mut c_void) -> c_int {
    // SAFETY: the context (`SSL_CTX_clear_chain_certs`), no pointer.
    if unsafe { openssl_sys::SSL_CTX_ctrl(c, ffi::SSL_CTRL_CHAIN, 0, ptr::null_mut()) } == 0 {
        return 0;
    }
    loop {
        // SAFETY: the BIO, with C's callback and the password it reads.
        let ca = unsafe {
            openssl_sys::PEM_read_bio_X509(
                bio.as_ptr(),
                ptr::null_mut(),
                Some(passwd_callback),
                password,
            )
        };
        if ca.is_null() {
            break;
        }
        // SAFETY: the context, which takes `ca` over if it adds it
        // (`SSL_CTX_add0_chain_cert`).
        if unsafe { openssl_sys::SSL_CTX_ctrl(c, ffi::SSL_CTRL_CHAIN_CERT, 0, ca.cast()) } == 0 {
            // SAFETY: not taken: given back once.
            unsafe { openssl_sys::X509_free(ca) };
            return 0;
        }
    }
    // SAFETY: the thread's error queue, looked at.
    let err = unsafe { openssl_sys::ERR_peek_last_error() };
    if error_lib(err) == ffi::ERR_LIB_PEM && error_reason(err) == ffi::PEM_R_NO_START_LINE {
        // SAFETY: the thread's error queue.
        unsafe { openssl_sys::ERR_clear_error() };
        1
    } else {
        0
    }
}

/// A file BIO reading `name`, or none if it cannot be opened.
fn file_bio(name: &[u8]) -> Result<Option<MemBio>, ErrorKind> {
    // SAFETY: the library's static file method.
    let method = unsafe { openssl_sys::BIO_s_file() };
    // SAFETY: a BIO of that method, owned below.
    let bio = unsafe { openssl_sys::BIO_new(method) };
    let Some(bio) = NonNull::new(bio).map(MemBio::adopt) else {
        return Err(ErrorKind::OutOfMemory);
    };
    let c = c_string(name)?;
    // SAFETY: the BIO and a C string alive for the call
    // (`BIO_read_filename`), which opens the file to read and closes it
    // with the BIO.
    let opened = unsafe {
        openssl_sys::BIO_ctrl(
            bio.as_ptr(),
            ffi::BIO_C_SET_FILENAME,
            ffi::BIO_CLOSE_FP_READ,
            c.as_ptr().cast_mut().cast(),
        )
    };
    Ok((opened > 0).then_some(bio))
}

/// A PKCS#12 file or blob's certificate, key and CAs, made the context's
/// (`pkcs12load`): the failure said, if any.
fn pkcs12_load(
    ctx: NonNull<SSL_CTX>,
    blob: Option<&[u8]>,
    file: Option<&[u8]>,
    password: Option<&Vec<u8>>,
    io: &mut TlsIo<'_>,
) -> Result<(), ErrorKind> {
    let shown = Text(file.unwrap_or(b"(null)"));
    let bio = match blob {
        Some(blob) => match blob_bio(blob) {
            Some(bio) => bio,
            None => {
                let e = ErrText::last();
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!("BIO_new_mem_buf NULL, OpenSSL error {e}"),
                ));
            }
        },
        None => match file_bio(file.unwrap_or_default()) {
            Ok(Some(bio)) => bio,
            Ok(None) => {
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!("could not open PKCS12 file '{shown}'"),
                ));
            }
            Err(_) => {
                let e = ErrText::last();
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!("BIO_new return NULL, OpenSSL error {e}"),
                ));
            }
        },
    };
    // SAFETY: the BIO; no structure to reuse.
    let p12 = unsafe { ffi::d2i_PKCS12_bio(bio.as_ptr(), ptr::null_mut()) };
    drop(bio);
    if p12.is_null() {
        let what = if blob.is_some() {
            Text(b"(memory blob)")
        } else {
            Text(file.unwrap_or(b"(null)"))
        };
        return Err(io.fail(
            ErrorKind::SslCertproblem,
            format_args!("error reading PKCS12 file '{what}'"),
        ));
    }
    let mut key: *mut EVP_PKEY = ptr::null_mut();
    let mut x509: *mut X509 = ptr::null_mut();
    let mut ca: *mut openssl_sys::stack_st_X509 = ptr::null_mut();
    let pass = password.map_or(ptr::null(), |p| p.as_ptr().cast());
    // SAFETY: the structure read, and the password as a C string or
    // null; what it gives is this function's to free.
    let parsed = unsafe { openssl_sys::PKCS12_parse(p12, pass, &mut key, &mut x509, &mut ca) };
    // SAFETY: the structure read, freed once.
    unsafe { openssl_sys::PKCS12_free(p12) };
    if parsed == 0 {
        let e = ErrText::last();
        return Err(io.fail(
            ErrorKind::SslCertproblem,
            format_args!("could not parse PKCS12 file, check password, OpenSSL error {e}"),
        ));
    }
    let result = pkcs12_use(ctx, key, x509, ca, shown, io);
    // SAFETY: what the parse gave, each freed once; the stack's
    // certificates with it.
    unsafe { openssl_sys::EVP_PKEY_free(key) };
    // SAFETY: as above.
    unsafe { openssl_sys::X509_free(x509) };
    if !ca.is_null() {
        // SAFETY: as above.
        unsafe { openssl_sys::OPENSSL_sk_pop_free(ca.cast(), Some(free_x509)) };
    }
    result
}

unsafe extern "C" fn free_x509(x: *mut c_void) {
    // SAFETY: a certificate of the stack being freed.
    unsafe { openssl_sys::X509_free(x.cast()) };
}

/// The parsed certificate, key and CAs made the context's.
fn pkcs12_use(
    ctx: NonNull<SSL_CTX>,
    key: *mut EVP_PKEY,
    x509: *mut X509,
    ca: *mut openssl_sys::stack_st_X509,
    shown: Text<'_>,
    io: &mut TlsIo<'_>,
) -> Result<(), ErrorKind> {
    let c = ctx.as_ptr();
    // SAFETY: the context, which takes its own reference.
    if unsafe { openssl_sys::SSL_CTX_use_certificate(c, x509) } != 1 {
        let e = ErrText::last();
        return Err(io.fail(
            ErrorKind::SslCertproblem,
            format_args!("could not load PKCS12 client certificate, OpenSSL error {e}"),
        ));
    }
    // SAFETY: as above.
    if unsafe { openssl_sys::SSL_CTX_use_PrivateKey(c, key) } != 1 {
        return Err(io.fail(
            ErrorKind::SslCertproblem,
            format_args!("unable to use private key from PKCS12 file '{shown}'"),
        ));
    }
    // SAFETY: the context.
    if unsafe { openssl_sys::SSL_CTX_check_private_key(c) } == 0 {
        return Err(io.fail(
            ErrorKind::SslCertproblem,
            format_args!(
                "private key from PKCS12 file '{shown}' does not match certificate in same file"
            ),
        ));
    }
    if ca.is_null() {
        return Ok(());
    }
    let stack = ca.cast::<openssl_sys::OPENSSL_STACK>();
    // SAFETY: the stack of CAs the parse gave.
    while unsafe { openssl_sys::OPENSSL_sk_num(stack) } > 0 {
        // SAFETY: as above: its last certificate, now this function's.
        let x = unsafe { openssl_sys::OPENSSL_sk_pop(stack) }.cast::<X509>();
        // SAFETY: the context, which copies the CA's name.
        if unsafe { openssl_sys::SSL_CTX_add_client_CA(c, x) } == 0 {
            // SAFETY: not taken: freed once.
            unsafe { openssl_sys::X509_free(x) };
            return Err(io.fail(
                ErrorKind::SslCertproblem,
                format_args!("cannot add certificate to client CA list"),
            ));
        }
        // SAFETY: the context, which takes `x` over if it adds it.
        if unsafe { openssl_sys::SSL_CTX_add_extra_chain_cert(c, x) } == 0 {
            // SAFETY: not taken: freed once.
            unsafe { openssl_sys::X509_free(x) };
            return Err(io.fail(
                ErrorKind::SslCertproblem,
                format_args!("cannot add certificate to certificate chain"),
            ));
        }
    }
    Ok(())
}

/// An engine's or a provider's certificate or key made the context's
/// (`engineload`, `enginecheck`, `providerload`, `providercheck`). With
/// none of that kind selected, a PKCS#11 URI selects `pkcs11` as C does,
/// kept for the session if it had nothing selected. A provider's store
/// is read; loading from an engine is not built (no engine this build
/// meets can start), said as C's build without engines says it.
fn from_crypto(
    ctx: NonNull<SSL_CTX>,
    kind: FileType,
    wanted: Wanted,
    file: Option<&[u8]>,
    crypto: &mut Crypto,
    io: &mut TlsIo<'_>,
) -> Result<(), ErrorKind> {
    let engine = kind == FileType::Engine;
    let what = match wanted {
        Wanted::Certificate => "certificate",
        Wanted::PrivateKey => "private key",
    };
    let has = |c: &Crypto| {
        if engine {
            c.has_engine()
        } else {
            c.has_libctx()
        }
    };
    let pkcs11 = file.is_some_and(|f| f.len() >= 7 && f[..7].eq_ignore_ascii_case(b"pkcs11:"));
    let mut picked = None;
    if !has(crypto) && pkcs11 {
        let made = if engine {
            Crypto::select(b"pkcs11", io)
        } else {
            Crypto::select_provider(b"pkcs11", io)
        };
        let Ok(made) = made else {
            return Err(ErrorKind::SslCertproblem);
        };
        if crypto.is_empty() {
            *crypto = made;
        } else {
            picked = Some(made);
        }
    }
    let using = picked.as_ref().unwrap_or(crypto);
    let (name, short) = if engine {
        ("ENGINE", "engine")
    } else {
        ("PROVIDER", "provider")
    };
    if !has(using) {
        return Err(io.fail(
            ErrorKind::SslCertproblem,
            format_args!("crypto {short} not set, cannot load {what}"),
        ));
    }
    match (engine, file) {
        (false, Some(uri)) => using.use_from_store(ctx, uri, wanted, io),
        _ => Err(io.fail(
            ErrorKind::SslCertproblem,
            format_args!("SSL_FILETYPE_{name} not supported for {what}"),
        )),
    }
}

/// Load the client's certificate and key into `ctx` (`client_cert`), as
/// the options name them, if they name a certificate or its type; the
/// password, as a C string, is `password`, which the caller keeps alive
/// as long as the context, as OpenSSL keeps a pointer to it.
pub(crate) fn client_cert(
    ctx: NonNull<SSL_CTX>,
    options: &TlsOptions,
    password: Option<&Vec<u8>>,
    crypto: &mut Crypto,
    io: &mut TlsIo<'_>,
) -> Result<(), ErrorKind> {
    let cert_file = options.cert.as_deref();
    let cert_blob = options.cert_blob.as_deref();
    let cert_type = options.cert_type.as_deref();
    let mut kind = file_type(cert_type);
    if !(cert_file.is_some()
        || cert_blob.is_some()
        || matches!(kind, Some(FileType::Engine | FileType::Provider)))
    {
        return Ok(());
    }
    let c = ctx.as_ptr();
    let pass = password_ptr(password);
    if password.is_some() {
        // SAFETY: the context, and the password, which outlives it as the
        // caller keeps it.
        unsafe { ffi::SSL_CTX_set_default_passwd_cb_userdata(c, pass) };
        // SAFETY: the context, and a callback of OpenSSL's signature.
        unsafe { ffi::SSL_CTX_set_default_passwd_cb(c, Some(passwd_callback)) };
    }
    let from = Text(if cert_blob.is_some() {
        b"CURLOPT_SSLCERT_BLOB"
    } else {
        cert_file.unwrap_or_default()
    });
    let mut pkcs12_done = false;
    match kind {
        Some(FileType::Pem) => {
            let used = match cert_blob {
                Some(blob) => use_certificate_chain_blob(ctx, blob, pass),
                None => {
                    let name = c_string(cert_file.unwrap_or_default())?;
                    // SAFETY: the context, and a C string alive for the call.
                    unsafe {
                        openssl_sys::SSL_CTX_use_certificate_chain_file(c, name.as_ptr().cast())
                    }
                }
            };
            if used != 1 {
                let e = ErrText::last();
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!(
                        "could not load PEM client certificate from {from}, OpenSSL error {e}, \
                         (no key found, wrong passphrase, or wrong file format?)"
                    ),
                ));
            }
        }
        Some(FileType::Asn1) => {
            let used = match cert_blob {
                Some(blob) => use_certificate_blob(ctx, blob, FileType::Asn1, pass),
                None => {
                    let name = c_string(cert_file.unwrap_or_default())?;
                    // SAFETY: as above.
                    unsafe {
                        openssl_sys::SSL_CTX_use_certificate_file(
                            c,
                            name.as_ptr().cast(),
                            openssl_sys::SSL_FILETYPE_ASN1,
                        )
                    }
                }
            };
            if used != 1 {
                let e = ErrText::last();
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!(
                        "could not load ASN1 client certificate from {from}, OpenSSL error {e}, \
                         (no key found, wrong passphrase, or wrong file format?)"
                    ),
                ));
            }
        }
        Some(k @ (FileType::Engine | FileType::Provider)) => {
            // Without a name, C fails saying nothing.
            let Some(file) = cert_file else {
                return Err(ErrorKind::SslCertproblem);
            };
            from_crypto(ctx, k, Wanted::Certificate, Some(file), crypto, io)?;
        }
        Some(FileType::Pkcs12) => {
            pkcs12_load(ctx, cert_blob, cert_file, password, io)?;
            pkcs12_done = true;
        }
        None => {
            return Err(io.fail(
                ErrorKind::BadFunctionArgument,
                format_args!(
                    "not supported file type '{}' for certificate",
                    Text(cert_type.unwrap_or_default())
                ),
            ));
        }
    }
    let (key_file, key_blob) = match (options.key.as_deref(), options.key_blob.as_deref()) {
        (None, None) => (cert_file, cert_blob),
        given => {
            kind = file_type(options.key_type.as_deref());
            given
        }
    };
    match kind {
        Some(k @ (FileType::Pem | FileType::Asn1)) => {
            let used = match key_blob {
                Some(blob) => use_privatekey_blob(ctx, blob, k, pass),
                None => match key_file {
                    Some(file) => {
                        let name = c_string(file)?;
                        let t = if k == FileType::Pem {
                            openssl_sys::SSL_FILETYPE_PEM
                        } else {
                            openssl_sys::SSL_FILETYPE_ASN1
                        };
                        // SAFETY: the context, and a C string alive for
                        // the call.
                        unsafe {
                            openssl_sys::SSL_CTX_use_PrivateKey_file(c, name.as_ptr().cast(), t)
                        }
                    }
                    None => 0,
                },
            };
            if used != 1 {
                return Err(io.fail(
                    ErrorKind::BadFunctionArgument,
                    format_args!(
                        "unable to set private key file: '{}' type {}",
                        Text(key_file.unwrap_or(b"(memory blob)")),
                        Text(options.key_type.as_deref().unwrap_or(b"PEM"))
                    ),
                ));
            }
        }
        Some(k @ (FileType::Engine | FileType::Provider)) => {
            from_crypto(ctx, k, Wanted::PrivateKey, key_file, crypto, io)?;
        }
        Some(FileType::Pkcs12) => {
            if !pkcs12_done {
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!("file type P12 for private key not supported"),
                ));
            }
        }
        None => {
            return Err(io.fail(
                ErrorKind::BadFunctionArgument,
                format_args!("not supported file type for private key"),
            ));
        }
    }
    check_private_key(ctx, io)
}

/// The key set matches the certificate set, unless its method says it
/// cannot be checked (an RSA key's `RSA_METHOD_FLAG_NO_CHECK`).
fn check_private_key(ctx: NonNull<SSL_CTX>, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
    let c = ctx.as_ptr();
    // SAFETY: the context; an SSL made of it to read what it holds,
    // freed below.
    let ssl = unsafe { openssl_sys::SSL_new(c) };
    if ssl.is_null() {
        return Err(io.fail(
            ErrorKind::OutOfMemory,
            format_args!("unable to create an SSL structure"),
        ));
    }
    // SAFETY: the SSL; its certificate and key are its own, alive while
    // it is.
    let x509 = unsafe { openssl_sys::SSL_get_certificate(ssl) };
    // SAFETY: as above.
    let private = unsafe { openssl_sys::SSL_get_privatekey(ssl) };
    if !x509.is_null() {
        // SAFETY: the certificate; a reference to its key, freed below.
        let public = unsafe { openssl_sys::X509_get_pubkey(x509) };
        // SAFETY: the two keys; a DSA key's parameters copied, as C does.
        unsafe { openssl_sys::EVP_PKEY_copy_parameters(public, private) };
        // SAFETY: the reference taken above, given back once.
        unsafe { openssl_sys::EVP_PKEY_free(public) };
    }
    let mut check = true;
    // SAFETY: the SSL's key, looked at only if there is one.
    let rsa_key = !private.is_null()
        && unsafe { openssl_sys::EVP_PKEY_id(private) } == openssl_sys::EVP_PKEY_RSA;
    if rsa_key {
        // SAFETY: an RSA key; a reference to its RSA, freed below.
        let rsa = unsafe { openssl_sys::EVP_PKEY_get1_RSA(private) };
        // SAFETY: the RSA, or null, which has no flags.
        if !rsa.is_null() && unsafe { ffi::RSA_flags(rsa) } & ffi::RSA_METHOD_FLAG_NO_CHECK != 0 {
            check = false;
        }
        // SAFETY: the reference taken above, given back once.
        unsafe { openssl_sys::RSA_free(rsa) };
    }
    // SAFETY: made above, freed once.
    unsafe { openssl_sys::SSL_free(ssl) };
    // SAFETY: the context, its certificate and key set.
    if check && unsafe { openssl_sys::SSL_CTX_check_private_key(c) } == 0 {
        return Err(io.fail(
            ErrorKind::SslCertproblem,
            format_args!("Private key does not match the certificate public key"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_types_are_named_as_c_names_them() {
        for (name, want) in [
            (None, Some(FileType::Pem)),
            (Some(&b""[..]), Some(FileType::Pem)),
            (Some(b"pem"), Some(FileType::Pem)),
            (Some(b"DER"), Some(FileType::Asn1)),
            (Some(b"p12"), Some(FileType::Pkcs12)),
            (Some(b"Eng"), Some(FileType::Engine)),
            (Some(b"PROV"), Some(FileType::Provider)),
            (Some(b"PKCS12"), None),
        ] {
            assert_eq!(file_type(name), want, "{name:?}");
        }
    }

    #[test]
    fn the_password_is_handed_over_only_where_it_fits() {
        let pw = *b"secret\0";
        let mut buf = [0u8; 16];
        let p = pw.as_ptr().cast_mut().cast();
        // SAFETY: a buffer of 16 bytes and a C string.
        let n = unsafe { passwd_callback(buf.as_mut_ptr().cast(), 16, 0, p) };
        assert_eq!(n, 6);
        assert_eq!(&buf[..7], b"secret\0");
        // SAFETY: as above: room for 6 bytes is too little for 7.
        let n = unsafe { passwd_callback(buf.as_mut_ptr().cast(), 6, 0, p) };
        assert_eq!(n, 0);
        // SAFETY: as above, no password.
        let n = unsafe { passwd_callback(buf.as_mut_ptr().cast(), 16, 0, ptr::null_mut()) };
        assert_eq!(n, 0);
        // SAFETY: as above, asked to encrypt.
        let n = unsafe { passwd_callback(buf.as_mut_ptr().cast(), 16, 1, p) };
        assert_eq!(n, 0);
    }
}
