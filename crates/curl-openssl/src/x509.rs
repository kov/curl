//! Certificates: the store a session trusts (`ossl_populate_x509_store`,
//! `ossl_load_trust_anchors`), and the peer's certificate checked once the
//! handshake is done (`Curl_ossl_check_peer_cert`, `ossl_verifyhost`), with
//! the lines C traces about it.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use core::fmt;
use core::ptr::{self, NonNull};
use std::net::{Ipv4Addr, Ipv6Addr};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};
use curl_core::error::ErrorKind;
use curl_core::options::SslOptions;
use curl_core::tls::{TlsIdentity, TlsIo, TlsPeerKind, TlsShared};
use openssl_sys::{BIO, SSL, SSL_CTX, X509, X509_STORE};

use crate::cache::{self, StoreCache};
use crate::ffi;
use crate::hostcheck;

/// A certificate this crate holds a reference to, freed as it goes.
pub(crate) struct Cert(NonNull<X509>);

impl Cert {
    pub(crate) fn as_ptr(&self) -> *mut X509 {
        self.0.as_ptr()
    }
}

impl Drop for Cert {
    fn drop(&mut self) {
        // SAFETY: a reference the library gave this crate, freed once.
        unsafe { openssl_sys::X509_free(self.0.as_ptr()) };
    }
}

/// A BIO this crate made, a memory one unless adopted, freed as it goes.
pub(crate) struct MemBio(NonNull<BIO>);

impl MemBio {
    pub(crate) fn new() -> Option<MemBio> {
        // SAFETY: the library's own, static, memory method.
        let method = unsafe { openssl_sys::BIO_s_mem() };
        // SAFETY: a BIO of that method, owned by the `MemBio`.
        NonNull::new(unsafe { openssl_sys::BIO_new(method) }).map(MemBio)
    }

    /// A BIO of another method this crate made, owned from now on.
    pub(crate) fn adopt(bio: NonNull<BIO>) -> MemBio {
        MemBio(bio)
    }

    pub(crate) fn as_ptr(&self) -> *mut BIO {
        self.0.as_ptr()
    }

    /// What was written to it, as long as it is not written to again.
    pub(crate) fn bytes(&self) -> &[u8] {
        let mut data: *mut c_char = ptr::null_mut();
        // SAFETY: a memory BIO, which says where its bytes are.
        let len = unsafe { openssl_sys::BIO_get_mem_data(self.0.as_ptr(), &mut data) };
        match usize::try_from(len) {
            // SAFETY: `len` bytes at `data`, the BIO's, alive while it is
            // and not written to, which `&self` keeps.
            Ok(len) if len > 0 && !data.is_null() => unsafe {
                core::slice::from_raw_parts(data.cast::<u8>(), len)
            },
            _ => &[],
        }
    }

    /// Empty it (`BIO_reset`).
    pub(crate) fn reset(&mut self) {
        /// `BIO_CTRL_RESET`.
        const BIO_CTRL_RESET: c_int = 1;
        // SAFETY: a memory BIO, which a reset empties.
        unsafe { openssl_sys::BIO_ctrl(self.0.as_ptr(), BIO_CTRL_RESET, 0, ptr::null_mut()) };
    }
}

impl Drop for MemBio {
    fn drop(&mut self) {
        // SAFETY: made by `BIO_new`, freed once.
        unsafe { ffi::BIO_free(self.0.as_ptr()) };
    }
}

/// Bytes as text in a line, as C's `%s` prints them.
pub(crate) struct Text<'a>(pub(crate) &'a [u8]);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            for &b in chunk.invalid() {
                // The byte as it is would be the terminal's to show; text
                // here is Rust's, so the byte is written as Latin-1.
                write!(f, "{}", char::from(b))?;
            }
        }
        Ok(())
    }
}

/// The host as the URL names it, which C's messages about the
/// certificate's names say (`user_hostname`): an IPv6 address in
/// brackets.
struct Shown<'a>(&'a [u8], TlsPeerKind);

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.1 {
            TlsPeerKind::Ipv6 => write!(f, "[{}]", Text(self.0)),
            TlsPeerKind::Name | TlsPeerKind::Ipv4 => Text(self.0).fmt(f),
        }
    }
}

/// `bytes`, ended by a zero byte, for a call that takes a C string: cut
/// at a zero byte inside, where C would see its end.
pub(crate) fn c_string(bytes: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let mut c = Vec::new();
    c.try_reserve_exact(end + 1)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    c.try_extend_from_slice(&bytes[..end])
        .map_err(|_| ErrorKind::OutOfMemory)?;
    c.try_push(0).map_err(|_| ErrorKind::OutOfMemory)?;
    Ok(c)
}

/// A reference to a store of certificates to trust, freed as it goes.
pub(crate) struct Store(NonNull<X509_STORE>);

// SAFETY: OpenSSL counts a store's references atomically and locks it as
// it is used, so a store may be shared and freed from any thread; this
// crate changes a store only as it loads it, before it is shared.
unsafe impl Send for Store {}

impl Store {
    /// Another reference to the store of `ctx`.
    fn of(ctx: NonNull<SSL_CTX>) -> Option<Store> {
        // SAFETY: the session's context, alive while it is.
        let store = NonNull::new(unsafe { openssl_sys::SSL_CTX_get_cert_store(ctx.as_ptr()) })?;
        Store::up(store)
    }

    /// Another reference to the same store.
    fn another(&self) -> Option<Store> {
        Store::up(self.0)
    }

    /// Another reference to `store`, if the library could count it.
    fn up(store: NonNull<X509_STORE>) -> Option<Store> {
        // SAFETY: a store alive while this runs: a context's, or one this
        // crate holds a reference to.
        (unsafe { ffi::X509_STORE_up_ref(store.as_ptr()) } == 1).then_some(Store(store))
    }

    /// Make it the store of `ctx`, which takes this reference over and
    /// frees the store it had.
    fn give_to(self, ctx: NonNull<SSL_CTX>) {
        let store = core::mem::ManuallyDrop::new(self);
        // SAFETY: the session's context, and a reference this crate
        // holds, which the context now owns.
        unsafe { openssl_sys::SSL_CTX_set_cert_store(ctx.as_ptr(), store.0.as_ptr()) };
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: a reference this crate took, given back once.
        unsafe { openssl_sys::X509_STORE_free(self.0.as_ptr()) };
    }
}

/// What this library keeps for a multi: the store its connections last
/// loaded.
pub(crate) type Kept = StoreCache<Store>;

/// Set the trust store of `ctx` up for a session with `identity`
/// (`Curl_ssl_setup_x509_store`): the store `shared` keeps for the
/// multi, if one serves it, and nothing is said; else one loaded, and
/// kept for the connections after if they may take it.
pub(crate) fn setup_store(
    ctx: NonNull<SSL_CTX>,
    identity: &TryArc<TlsIdentity>,
    shared: Option<&TlsShared>,
    io: &mut TlsIo<'_>,
) -> Result<(), ErrorKind> {
    let shared = shared.filter(|_| cache::cacheable(identity));
    let now = io.now();
    if let Some(shared) = shared {
        let kept = shared.with(Kept::default, |c| {
            c.get(identity, now).and_then(Store::another)
        });
        match kept {
            Ok(Some(Some(store))) => {
                store.give_to(ctx);
                return Ok(());
            }
            Ok(Some(None)) => {}
            // No room to keep a store, or the multi keeps another
            // library's: loaded as without the cache, as C goes without
            // it when it cannot make its entry.
            Err(OutOfMemory) | Ok(None) => {}
        }
    }
    populate_store(ctx, identity, io)?;
    if let Some(shared) = shared
        && let Some(store) = Store::of(ctx)
    {
        // Kept, or not kept as above: the transfer goes on either way.
        let (Ok(Some(()) | None) | Err(OutOfMemory)) =
            shared.with(Kept::default, |c| c.set(identity, now, store));
    }
    Ok(())
}

/// Load the trust store of `ctx` for a session with `identity`
/// (`ossl_populate_x509_store`).
fn populate_store(
    ctx: NonNull<SSL_CTX>,
    identity: &TlsIdentity,
    io: &mut TlsIo<'_>,
) -> Result<(), ErrorKind> {
    io.trace(format_args!("configuring OpenSSL's x509 trust store"));
    // SAFETY: the session's context, alive while it is.
    let store = unsafe { openssl_sys::SSL_CTX_get_cert_store(ctx.as_ptr()) };
    let Some(store) = NonNull::new(store) else {
        return Err(ErrorKind::OutOfMemory);
    };
    if !identity.verify_peer {
        io.info(format_args!("SSL Trust: peer verification disabled"));
        return Ok(());
    }
    io.info(format_args!("SSL Trust Anchors:"));
    load_trust_anchors(store, identity, io)?;
    let mut flags: c_ulong = 0;
    if let Some(crl) = &identity.options.crl_file {
        // The revocation list, which every certificate of the chain is
        // checked against.
        let c = c_string(crl)?;
        // SAFETY: the library's static file method.
        let method = unsafe { openssl_sys::X509_LOOKUP_file() };
        // SAFETY: the context's store, which owns the lookup it adds.
        let lookup = unsafe { openssl_sys::X509_STORE_add_lookup(store.as_ptr(), method) };
        let pem = openssl_sys::X509_FILETYPE_PEM;
        if lookup.is_null()
            // SAFETY: the store's lookup, and a C string alive for the call.
            || unsafe { openssl_sys::X509_load_crl_file(lookup, c.as_ptr().cast(), pem) } == 0
        {
            return Err(io.fail(
                ErrorKind::SslCrlBadfile,
                format_args!("error loading CRL file: {}", Text(crl)),
            ));
        }
        flags = openssl_sys::X509_V_FLAG_CRL_CHECK | openssl_sys::X509_V_FLAG_CRL_CHECK_ALL;
        io.info(format_args!(" CRLfile: {}", Text(crl)));
    }
    // Chains built from what the store trusts first, and a certificate
    // the store has trusted whatever issued it (C's comment: trusted
    // intermediates as anchors), unless asked not to.
    flags |= openssl_sys::X509_V_FLAG_TRUSTED_FIRST;
    if !identity
        .options
        .ssl_options
        .contains(SslOptions::NO_PARTIALCHAIN)
        && identity.options.crl_file.is_none()
    {
        flags |= openssl_sys::X509_V_FLAG_PARTIAL_CHAIN;
    }
    // SAFETY: the context's store. C ignores the result.
    unsafe { openssl_sys::X509_STORE_set_flags(store.as_ptr(), flags) };
    Ok(())
}

/// `ossl_load_trust_anchors`: the blob, the file and the directory the
/// identity names, the default ones among them.
fn load_trust_anchors(
    store: NonNull<X509_STORE>,
    identity: &TlsIdentity,
    io: &mut TlsIo<'_>,
) -> Result<(), ErrorKind> {
    let options = &identity.options;
    let mut empty = true;
    if let Some(blob) = &options.ca_blob {
        if let Err(kind) = load_from_memory(store, blob) {
            return Err(io.fail(
                kind,
                format_args!(
                    "error adding trust anchors from certificate blob: {}",
                    kind.number()
                ),
            ));
        }
        io.info(format_args!("  CA Blob from configuration"));
        empty = false;
    }
    // A blob takes the file's place.
    let file = if options.ca_blob.is_some() {
        None
    } else {
        identity.ca_file()
    };
    if let Some(file) = file {
        let c = c_string(file)?;
        // SAFETY: the store, and a C string alive for the call.
        if unsafe { ffi::X509_STORE_load_file(store.as_ptr(), c.as_ptr().cast()) } == 0 {
            if empty {
                return Err(io.fail(
                    ErrorKind::SslCacertBadfile,
                    format_args!("error adding trust anchors from file: {}", Text(file)),
                ));
            }
            io.info(format_args!(
                "error setting certificate file, continuing anyway"
            ));
        }
        io.info(format_args!("  CAfile: {}", Text(file)));
        empty = false;
    }
    if let Some(path) = identity.ca_path() {
        let c = c_string(path)?;
        // SAFETY: as above.
        if unsafe { ffi::X509_STORE_load_path(store.as_ptr(), c.as_ptr().cast()) } == 0 {
            if empty {
                return Err(io.fail(
                    ErrorKind::SslCacertBadfile,
                    format_args!("error adding trust anchors from path: {}", Text(path)),
                ));
            }
            io.info(format_args!(
                "error setting certificate path, continuing anyway"
            ));
        }
        io.info(format_args!("  CApath: {}", Text(path)));
        empty = false;
    }
    if empty {
        io.info(format_args!("  no trust anchors configured"));
    }
    Ok(())
}

/// Add each certificate and revocation list of the PEM text `blob` to
/// the store (`load_cacert_from_memory`): none found, or one refused, is
/// a bad file.
fn load_from_memory(store: NonNull<X509_STORE>, blob: &[u8]) -> Result<(), ErrorKind> {
    let len = c_int::try_from(blob.len()).map_err(|_| ErrorKind::SslCacertBadfile)?;
    // SAFETY: a BIO that reads `blob`, alive for this call alone, which
    // outlives the BIO freed below.
    let bio = unsafe { openssl_sys::BIO_new_mem_buf(blob.as_ptr().cast(), len) };
    let Some(bio) = NonNull::new(bio) else {
        return Err(ErrorKind::OutOfMemory);
    };
    let bio = MemBio(bio);
    // SAFETY: the BIO; no stack to add to, no password callback.
    let infos = unsafe {
        ffi::PEM_X509_INFO_read_bio(
            bio.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if infos.is_null() {
        return Err(ErrorKind::SslCacertBadfile);
    }
    let stack = infos.cast::<openssl_sys::OPENSSL_STACK>();
    let mut count = 0;
    // SAFETY: the stack the library made of `X509_INFO`s.
    let n = unsafe { openssl_sys::OPENSSL_sk_num(stack) };
    for i in 0..n {
        // SAFETY: an entry of the stack, the start of an `X509_INFO`.
        let info = unsafe { openssl_sys::OPENSSL_sk_value(stack, i) }.cast::<ffi::X509InfoHead>();
        // SAFETY: as above, read through the pointer the stack gives.
        let ffi::X509InfoHead { x509, crl } = unsafe { info.read() };
        if !x509.is_null() {
            // SAFETY: the store, and the entry's certificate, which the
            // store takes a reference to.
            if unsafe { openssl_sys::X509_STORE_add_cert(store.as_ptr(), x509) } == 0 {
                count = 0;
                break;
            }
            count += 1;
        }
        if !crl.is_null() {
            // SAFETY: as above, the entry's list.
            if unsafe { ffi::X509_STORE_add_crl(store.as_ptr(), crl) } == 0 {
                count = 0;
                break;
            }
            count += 1;
        }
    }
    // SAFETY: the stack and its entries, freed once.
    unsafe { openssl_sys::OPENSSL_sk_pop_free(stack, Some(free_info)) };
    if count > 0 {
        Ok(())
    } else {
        Err(ErrorKind::SslCacertBadfile)
    }
}

unsafe extern "C" fn free_info(info: *mut c_void) {
    // SAFETY: an `X509_INFO` of the stack being freed.
    unsafe { ffi::X509_INFO_free(info) };
}

/// The longest name C prints of a certificate (`MAX_CERT_NAME_LENGTH`),
/// with its zero byte.
const MAX_NAME: usize = 2048;

/// A certificate's name as one line (`x509_name_oneline`), into `bio`:
/// none if the library could not print it, or `TooLarge` if it does not
/// fit C's buffer.
fn name_line(name: *const openssl_sys::X509_NAME, bio: &mut MemBio) -> Result<(), ErrorKind> {
    bio.reset();
    // SAFETY: the certificate's name, and the BIO.
    let rc = unsafe { ffi::X509_NAME_print_ex(bio.as_ptr(), name, 0, ffi::NAME_FLAGS) };
    if rc == -1 {
        return Err(ErrorKind::OutOfMemory);
    }
    if bio.bytes().len() + 1 > MAX_NAME {
        return Err(ErrorKind::TooLarge);
    }
    Ok(())
}

/// The lines about the peer's certificate (`ossl_infof_cert`).
fn info_cert(cert: &Cert, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
    let Some(mut bio) = MemBio::new() else {
        let e = ErrText::last();
        return Err(io.fail(
            ErrorKind::OutOfMemory,
            format_args!("BIO_new return NULL, OpenSSL error {e}"),
        ));
    };
    io.info(format_args!("Server certificate:"));
    // SAFETY: the certificate, alive while `cert` is.
    let subject = unsafe { openssl_sys::X509_get_subject_name(cert.as_ptr()) };
    match name_line(subject, &mut bio) {
        Ok(()) => io.info(format_args!("  subject: {}", Text(bio.bytes()))),
        Err(_) => io.info(format_args!("  subject: [NONE]")),
    }
    for (label, time) in [
        // SAFETY: as above.
        ("start", unsafe { ffi::X509_get0_notBefore(cert.as_ptr()) }),
        // SAFETY: as above.
        ("expire", unsafe { ffi::X509_get0_notAfter(cert.as_ptr()) }),
    ] {
        bio.reset();
        // SAFETY: the BIO, and the certificate's time. C ignores the result.
        unsafe { openssl_sys::ASN1_TIME_print(bio.as_ptr(), time) };
        io.info(format_args!("  {label} date: {}", Text(bio.bytes())));
    }
    // SAFETY: as above.
    let issuer = unsafe { openssl_sys::X509_get_issuer_name(cert.as_ptr()) };
    name_line(issuer, &mut bio)?;
    io.info(format_args!("  issuer: {}", Text(bio.bytes())));
    Ok(())
}

/// The text of a C string the library returns, or none.
///
/// # Safety
/// `p` is null or a C string alive while the result is used.
unsafe fn c_text<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: as the caller says.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes())
}

/// A line for each certificate of the chain (`infof_certstack`): the
/// verified one if it verified, else the one the peer sent.
fn info_chain(ssl: NonNull<SSL>, io: &mut TlsIo<'_>) {
    // SAFETY: the session's SSL, its handshake done.
    let verified = unsafe { openssl_sys::SSL_get_verify_result(ssl.as_ptr()) };
    let chain = if verified == c_long::from(openssl_sys::X509_V_OK) {
        // SAFETY: as above; the chain is the SSL's, alive while it is.
        unsafe { openssl_sys::SSL_get0_verified_chain(ssl.as_ptr()) }
    } else {
        // SAFETY: as above.
        unsafe { openssl_sys::SSL_get_peer_cert_chain(ssl.as_ptr()) }
    };
    if chain.is_null() {
        return;
    }
    let stack = chain.cast::<openssl_sys::OPENSSL_STACK>();
    // SAFETY: a stack of certificates.
    let n = unsafe { openssl_sys::OPENSSL_sk_num(stack) };
    for level in 0..n {
        // SAFETY: an entry of the stack, a certificate.
        let cert = unsafe { openssl_sys::OPENSSL_sk_value(stack, level) }.cast::<X509>();
        if cert.is_null() {
            continue;
        }
        // SAFETY: the certificate's key, its own.
        let key = unsafe { ffi::X509_get0_pubkey(cert) };
        if key.is_null() {
            continue;
        }
        let mut alg: *const openssl_sys::X509_ALGOR = ptr::null();
        let mut obj: *const openssl_sys::ASN1_OBJECT = ptr::null();
        let mut algorithm = [0u8; 80];
        let mut group = [0u8; 80];
        // SAFETY: the certificate and its key, the chain's; what
        // they give is their own, alive while they are; text is written
        // within the buffer named, ended by a zero byte.
        unsafe { openssl_sys::X509_get0_signature(ptr::null_mut(), &mut alg, cert) };
        // SAFETY: as above.
        unsafe { openssl_sys::X509_ALGOR_get0(&mut obj, ptr::null_mut(), ptr::null_mut(), alg) };
        // SAFETY: as above.
        unsafe { openssl_sys::OBJ_obj2txt(algorithm.as_mut_ptr().cast(), 80, obj, 0) };
        // SAFETY: as above.
        let bits = unsafe { openssl_sys::EVP_PKEY_bits(key) };
        // SAFETY: as above.
        let sec_bits = unsafe { openssl_sys::EVP_PKEY_get_security_bits(key) };
        let room = group.as_mut_ptr().cast();
        // SAFETY: as above.
        let has_group = unsafe { ffi::EVP_PKEY_get_group_name(key, room, 80, ptr::null_mut()) };
        // SAFETY: as above.
        let type_name = unsafe { ffi::EVP_PKEY_get0_type_name(key) };
        // SAFETY: the key's text, or null.
        let type_name = unsafe { c_text(type_name) };
        let algorithm = until_zero(&algorithm);
        let group = until_zero(&group);
        let type_name = type_name.unwrap_or(b"?");
        let slash = if has_group == 0 { "" } else { "/" };
        let group = if has_group == 0 { &[][..] } else { group };
        io.info(format_args!(
            "  Certificate level {level}: Public key type {}{slash}{} ({bits}/{sec_bits} \
             Bits/secBits), signed using {}",
            Text(type_name),
            Text(group),
            Text(algorithm)
        ));
    }
}

/// The text of a buffer the library wrote a C string into.
fn until_zero(buf: &[u8]) -> &[u8] {
    &buf[..buf.iter().position(|&b| b == 0).unwrap_or(buf.len())]
}

/// `GEN_DNS`, `GEN_IPADD`.
const GEN_DNS: c_int = 2;
const GEN_IPADD: c_int = 7;

/// The certificate names the peer (`ossl_verifyhost`): a subject
/// alternative name of the peer's kind, or without any, the last common
/// name.
fn verify_host(
    cert: &Cert,
    host: &[u8],
    kind: TlsPeerKind,
    io: &mut TlsIo<'_>,
) -> Result<(), ErrorKind> {
    let mut v4 = [0u8; 4];
    let mut v6 = [0u8; 16];
    let target = match kind {
        TlsPeerKind::Ipv4 => {
            let a: Ipv4Addr = std::str::from_utf8(host)
                .ok()
                .and_then(|h| h.parse().ok())
                .ok_or(ErrorKind::PeerFailedVerification)?;
            v4 = a.octets();
            GEN_IPADD
        }
        TlsPeerKind::Ipv6 => {
            let a: Ipv6Addr = std::str::from_utf8(host)
                .ok()
                .and_then(|h| h.parse().ok())
                .ok_or(ErrorKind::PeerFailedVerification)?;
            v6 = a.octets();
            GEN_IPADD
        }
        TlsPeerKind::Name => GEN_DNS,
    };
    let address: &[u8] = match kind {
        TlsPeerKind::Ipv4 => &v4,
        TlsPeerKind::Ipv6 => &v6,
        TlsPeerKind::Name => &[],
    };
    let mut matched = false;
    let mut dns_name = false;
    let mut ip_address = false;
    // SAFETY: the certificate; the names it gives, freed below.
    let names = unsafe {
        openssl_sys::X509_get_ext_d2i(
            cert.as_ptr(),
            openssl_sys::NID_subject_alt_name,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if !names.is_null() {
        let stack = names.cast::<openssl_sys::OPENSSL_STACK>();
        // SAFETY: a stack of `GENERAL_NAME`s.
        let n = unsafe { openssl_sys::OPENSSL_sk_num(stack) };
        let mut i = 0;
        while i < n && !matched {
            // SAFETY: an entry of the stack, a `GENERAL_NAME`.
            let name = unsafe { openssl_sys::OPENSSL_sk_value(stack, i) };
            // SAFETY: as above, alive while the stack is, freed below.
            let name = unsafe { &*name.cast::<openssl_sys::GENERAL_NAME>() };
            i += 1;
            match name.type_ {
                GEN_DNS => dns_name = true,
                GEN_IPADD => ip_address = true,
                _ => {}
            }
            if name.type_ != target {
                continue;
            }
            // SAFETY: a DNS name or an address is an `ASN1_IA5STRING` or
            // an `ASN1_OCTET_STRING`, both `ASN1_STRING`s.
            let alt = unsafe { asn1_bytes(name.d.cast()) };
            match target {
                GEN_DNS => {
                    if !alt.contains(&0) && hostcheck::names(alt, host) {
                        matched = true;
                        io.info(format_args!(
                            "  subjectAltName: \"{}\" matches cert's \"{}\"",
                            Shown(host, kind),
                            Text(alt)
                        ));
                    }
                }
                _ => {
                    if alt == address {
                        matched = true;
                        io.info(format_args!(
                            "  subjectAltName: \"{}\" matches cert's IP address!",
                            Shown(host, kind)
                        ));
                    }
                }
            }
        }
        // SAFETY: the names the library gave, freed once.
        unsafe { ffi::GENERAL_NAMES_free(names) };
    }
    if matched {
        return Ok(());
    }
    if dns_name || ip_address {
        let what = match kind {
            TlsPeerKind::Name => "hostname",
            TlsPeerKind::Ipv4 => "IPv4 address",
            TlsPeerKind::Ipv6 => "IPv6 address",
        };
        let shown = Shown(host, kind);
        io.info(format_args!(
            " subjectAltName does not match {what} {shown}"
        ));
        return Err(io.fail(
            ErrorKind::PeerFailedVerification,
            format_args!(
                "SSL: no alternative certificate subject name matches target {what} '{shown}'"
            ),
        ));
    }
    common_name(cert, host, kind, io)
}

/// The bytes of an `ASN1_STRING`.
///
/// # Safety
/// `s` is an `ASN1_STRING` alive while the result is used.
unsafe fn asn1_bytes<'a>(s: *const openssl_sys::ASN1_STRING) -> &'a [u8] {
    // SAFETY: as the caller says.
    let data = unsafe { openssl_sys::ASN1_STRING_get0_data(s) };
    // SAFETY: as the caller says.
    let len = usize::try_from(unsafe { openssl_sys::ASN1_STRING_length(s) }).unwrap_or(0);
    if data.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: the string's `len` bytes, alive as the caller says.
        unsafe { core::slice::from_raw_parts(data, len) }
    }
}

/// The certificate's last common name names the host (`ossl_verifyhost`'s
/// fallback, for a certificate without alternative names).
fn common_name(
    cert: &Cert,
    host: &[u8],
    kind: TlsPeerKind,
    io: &mut TlsIo<'_>,
) -> Result<(), ErrorKind> {
    // SAFETY: the certificate's subject, its own.
    let name = unsafe { openssl_sys::X509_get_subject_name(cert.as_ptr()) };
    let mut last = -1;
    if !name.is_null() {
        loop {
            // SAFETY: the name, searched after the last entry found.
            let j = unsafe {
                openssl_sys::X509_NAME_get_index_by_NID(name, openssl_sys::NID_commonName, last)
            };
            if j < 0 {
                break;
            }
            last = j;
        }
    }
    let mut owned: *mut u8 = ptr::null_mut();
    let mut cn: Option<&[u8]> = None;
    let mut result = Ok(());
    if last >= 0 {
        // SAFETY: an entry of the name, the name's own.
        let entry = unsafe { openssl_sys::X509_NAME_get_entry(name, last) };
        // SAFETY: the entry's data, its own.
        let data = unsafe { openssl_sys::X509_NAME_ENTRY_get_data(entry) };
        if !data.is_null() {
            // SAFETY: the entry's string.
            if unsafe { openssl_sys::ASN1_STRING_type(data) } == openssl_sys::V_ASN1_UTF8STRING {
                // SAFETY: as above.
                cn = Some(unsafe { asn1_bytes(data) });
            } else {
                // SAFETY: the string, converted into memory the library
                // allocates, freed below.
                let n = unsafe { openssl_sys::ASN1_STRING_to_UTF8(&mut owned, data) };
                cn = match usize::try_from(n) {
                    Ok(n) if !owned.is_null() => {
                        // SAFETY: `n` bytes the library wrote at `owned`,
                        // freed only below, after the last use.
                        Some(unsafe { core::slice::from_raw_parts(owned, n) })
                    }
                    _ => Some(&[]),
                };
            }
            match cn {
                Some([]) => result = Err(ErrorKind::OutOfMemory),
                Some(c) if c.contains(&0) => {
                    result = Err(io.fail(
                        ErrorKind::PeerFailedVerification,
                        format_args!("SSL: illegal cert name field"),
                    ));
                }
                _ => {}
            }
        }
    }
    if result.is_ok() {
        result = match cn {
            None => Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("SSL: unable to obtain common name from peer certificate"),
            )),
            Some(c) if !hostcheck::names(c, host) => Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!(
                    "SSL: certificate subject name '{}' does not match target hostname '{}'",
                    Text(c),
                    Shown(host, kind)
                ),
            )),
            Some(c) => {
                io.info(format_args!(" common name: {} (matched)", Text(c)));
                Ok(())
            }
        };
    }
    if !owned.is_null() {
        // SAFETY: what `ASN1_STRING_to_UTF8` allocated, freed once
        // (`OPENSSL_free`).
        unsafe { openssl_sys::CRYPTO_free(owned.cast(), c"".as_ptr(), 0) };
    }
    result
}

/// Check the peer's certificate once the handshake is done
/// (`Curl_ossl_check_peer_cert`): the lines about it, its name if the
/// host is to be checked, then what OpenSSL made of its chain, which
/// fails the transfer only if the peer is to be verified. Gives the
/// verify result kept for `CURLINFO_SSL_VERIFYRESULT`.
pub(crate) fn check_peer(
    ssl: NonNull<SSL>,
    identity: &TlsIdentity,
    host: &[u8],
    kind: TlsPeerKind,
    io: &mut TlsIo<'_>,
) -> Result<c_long, ErrorKind> {
    // SAFETY: the session's SSL; a reference to the certificate, freed
    // as `cert` goes.
    let cert = NonNull::new(unsafe { openssl_sys::SSL_get1_peer_certificate(ssl.as_ptr()) });
    let Some(cert) = cert.map(Cert) else {
        if !(identity.verify_peer || identity.verify_host) && identity.options.pinned_key.is_none()
        {
            return Ok(1);
        }
        return Err(io.fail(
            ErrorKind::PeerFailedVerification,
            format_args!("SSL: could not get peer certificate"),
        ));
    };
    info_cert(&cert, io)?;
    info_chain(ssl, io);
    if identity.verify_host {
        verify_host(&cert, host, kind, io)?;
    }
    // SAFETY: the session's SSL.
    let verified = unsafe { openssl_sys::SSL_get_verify_result(ssl.as_ptr()) };
    io.info(format_args!("OpenSSL verify result: {verified:x}"));
    if verified == c_long::from(openssl_sys::X509_V_OK) {
        io.info(format_args!("SSL certificate verified via OpenSSL."));
    } else {
        if identity.verify_peer {
            // SAFETY: a function of no state, for any number.
            let why = unsafe { openssl_sys::X509_verify_cert_error_string(verified) };
            // SAFETY: the library's static text, or null.
            let why = unsafe { c_text(why) };
            return Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!(
                    "SSL certificate OpenSSL verify result: {} ({verified})",
                    Text(why.unwrap_or(b""))
                ),
            ));
        }
        io.info(format_args!(
            " SSL certificate verification failed, continuing anyway!"
        ));
    }
    if let Some(pinned) = &identity.options.pinned_key {
        // Checked whether the peer is verified or not
        // (`ossl_check_pinned_key`).
        let spki = public_key_der(&cert);
        if let Err(kind) = curl_core::tls::pin_peer_pubkey(io, pinned, &spki) {
            return Err(io.fail(
                kind,
                format_args!("SSL: public key does not match pinned public key"),
            ));
        }
    }
    Ok(verified)
}

/// The DER of the certificate's SubjectPublicKeyInfo
/// (`ossl_pkp_pin_peer_pubkey`): empty if it cannot be had, which
/// matches no pinned key, as C finds no match where it fails to make it.
fn public_key_der(cert: &Cert) -> Vec<u8> {
    // SAFETY: the certificate's key, its own, alive while `cert` is.
    let key = unsafe { ffi::X509_get_X509_PUBKEY(cert.as_ptr()) };
    // SAFETY: the key; no buffer: the length is asked.
    let len = unsafe { ffi::i2d_X509_PUBKEY(key, ptr::null_mut()) };
    let mut der = Vec::new();
    let Ok(n) = usize::try_from(len) else {
        return der;
    };
    if n == 0 || der.try_reserve_exact(n).is_err() {
        return der;
    }
    let mut at = der.as_mut_ptr();
    // SAFETY: room for the `n` bytes the library said it writes, at `at`,
    // which it moves past what it wrote.
    let wrote = unsafe { ffi::i2d_X509_PUBKEY(key, &mut at) };
    if wrote != len || at != der.as_mut_ptr().wrapping_add(n) {
        return Vec::new();
    }
    // SAFETY: the library wrote the `n` bytes.
    unsafe { der.set_len(n) };
    der
}

/// The text of one of the library's errors as C gives it in a failure
/// (`ossl_strerror`): the library's text, within what is left of C's 256
/// bytes once the version and `: ` are put before it (C returns the text
/// past them), or `Unknown error` (`No error` for none) where the
/// library has none.
pub(crate) struct ErrText {
    buf: [u8; 256],
    len: usize,
}

impl ErrText {
    pub(crate) fn of(error: c_ulong) -> ErrText {
        let mut t = ErrText {
            buf: [0; 256],
            len: 0,
        };
        let version = crate::sys::version_len();
        let room = if version < t.buf.len() - 2 {
            t.buf.len() - version - 2
        } else {
            t.buf.len()
        };
        // SAFETY: `room` bytes of the buffer, which the library ends with
        // a zero byte.
        unsafe { ffi::ERR_error_string_n(error, t.buf.as_mut_ptr().cast(), room) };
        t.len = until_zero(&t.buf[..room]).len();
        if t.len == 0 {
            let msg: &[u8] = if error == 0 {
                b"No error"
            } else {
                b"Unknown error"
            };
            t.buf[..msg.len()].copy_from_slice(msg);
            t.len = msg.len();
        }
        t
    }

    /// The earliest error the library has queued, taken off the queue.
    pub(crate) fn last() -> ErrText {
        // SAFETY: the thread's error queue.
        ErrText::of(unsafe { openssl_sys::ERR_get_error() })
    }
}

impl fmt::Display for ErrText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Text(&self.buf[..self.len]), f)
    }
}
