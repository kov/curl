//! What this crate calls of OpenSSL that openssl-sys does not declare,
//! as OpenSSL 3's headers declare it, or LibreSSL's where the build is
//! LibreSSL's (`cfg(libressl)`), and the values of the headers' macros it
//! uses, which are the same in both but where said.
//!
//! Over AWS-LC and BoringSSL (`cfg(boringssl_like)`), openssl-sys's
//! declarations are made from the fork's own headers, its macros'
//! values among them: what this crate calls is taken from there, so that
//! the compiler checks each call against the fork, and what OpenSSL and
//! LibreSSL have as macros over `SSL_CTX_ctrl`, which the forks make
//! functions of, is called through the functions below, each one call.

#![allow(unsafe_code)]
// The functions bear the names of the C calls they make.
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

use openssl_sys::{ASN1_STRING, BIO, SSL, SSL_CTX, SSL_SESSION, X509, X509_CRL};
// What this crate's own declarations name.
#[cfg(not(boringssl_like))]
use openssl_sys::{
    ASN1_OBJECT, ASN1_TIME, BIGNUM, EVP_PKEY, PKCS12, X509_ALGOR, X509_NAME, X509_STORE,
    pem_password_cb,
};

/// A certificate's public key with its algorithm (`X509_PUBKEY`), only
/// ever pointed to.
#[cfg(not(boringssl_like))]
pub(crate) enum X509Pubkey {}

/// `SSL_CTX_set_msg_callback`'s callback.
#[cfg(not(boringssl_like))]
pub(crate) type MsgCallback = unsafe extern "C" fn(
    write_p: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: usize,
    ssl: *mut SSL,
    arg: *mut c_void,
);

/// The start of `X509_INFO` (`x509.h`): what `PEM_X509_INFO_read_bio`
/// found in an entry, read through a pointer the library gives.
#[repr(C)]
pub(crate) struct X509InfoHead {
    pub(crate) x509: *mut X509,
    pub(crate) crl: *mut X509_CRL,
}

/// A packed error code of the library's error queue (C's `sslerr_t`):
/// an `unsigned long`, or the forks' `uint32_t`.
#[cfg(not(boringssl_like))]
pub(crate) type ErrCode = c_ulong;
#[cfg(boringssl_like)]
pub(crate) type ErrCode = u32;

// The calls both libraries have that openssl-sys declares for OpenSSL
// alone, or under OpenSSL 3's names: LibreSSL's stack is `_STACK`, its
// calls `sk_*`, and C's `SSL_get1_peer_certificate` is its
// `SSL_get_peer_certificate` (`openssl.h`'s `#ifndef HAVE_OPENSSL3`), as
// `EVP_PKEY_get_security_bits` is its `EVP_PKEY_security_bits`.
#[cfg(libressl)]
pub(crate) use libressl::*;
#[cfg(ossl3)]
pub(crate) use openssl_sys::{
    EVP_PKEY_get_security_bits, OPENSSL_STACK as Stack, OPENSSL_init_ssl, OPENSSL_sk_num as sk_num,
    OPENSSL_sk_pop as sk_pop, OPENSSL_sk_pop_free as sk_pop_free, OPENSSL_sk_value as sk_value,
    SSL_get0_verified_chain, SSL_get1_peer_certificate, SSL_is_init_finished, X509_get_version,
    X509_get0_extensions,
};
// The forks' own, the stack's calls under OpenSSL's names; the peer's
// certificate is `SSL_get1_peer_certificate` there too.
#[cfg(boringssl_like)]
pub(crate) use openssl_sys::{
    ASN1_STRING_print, BIO_free, BIO_get_shutdown, BIO_set_shutdown, BIO_up_ref, BN_print,
    DH_get0_key, DH_get0_pqg, DSA_get0_key, DSA_get0_pqg, ERR_error_string_n, ERR_peek_error,
    ERR_pop_to_mark, ERR_set_mark, EVP_PKEY_get0_DH, EVP_PKEY_get0_DSA, EVP_PKEY_get0_RSA,
    GENERAL_NAMES_free, OBJ_find_sigid_algs, OPENSSL_STACK as Stack, OPENSSL_init_ssl,
    OPENSSL_sk_pop as sk_pop, PEM_X509_INFO_read_bio, PEM_read_bio_X509_AUX, RSA_get0_key,
    SSL_CTX_set_default_passwd_cb, SSL_CTX_set_default_passwd_cb_userdata,
    SSL_CTX_set_msg_callback, SSL_alert_desc_string_long, SSL_is_init_finished, SSL_set0_rbio,
    SSL_set0_wbio, X509_INFO_free, X509_NAME_print_ex, X509_PUBKEY_get0_param, X509_STORE_add_crl,
    X509_STORE_load_locations, X509_STORE_up_ref, X509_get_X509_PUBKEY, X509_get_signature_nid,
    X509_get_version, X509_get0_extensions, X509_get0_notAfter, X509_get0_notBefore,
    d2i_PKCS12_bio, d2i_PrivateKey_bio, i2a_ASN1_OBJECT, i2d_X509_PUBKEY, i2t_ASN1_OBJECT,
};

/// `sk_pop_free`: the forks' takes the free function through a caller of
/// its own (`OPENSSL_sk_pop_free_ex`), which the header's macro passes.
///
/// # Safety
/// As `OPENSSL_sk_pop_free`'s: `stack` is a stack of what `free` frees.
#[cfg(boringssl_like)]
pub(crate) unsafe fn sk_pop_free(
    stack: *mut Stack,
    free: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    /// The caller the header's `sk_pop_free` gives
    /// (`sk_pop_free_call_free_func`): `free` on the element.
    unsafe extern "C" fn call_free(
        free: Option<unsafe extern "C" fn(*mut c_void)>,
        p: *mut c_void,
    ) {
        if let Some(free) = free {
            // SAFETY: an element of the stack, freed once by its free
            // function, as the caller of `sk_pop_free` says.
            unsafe { free(p) };
        }
    }
    // SAFETY: as the caller says.
    unsafe { openssl_sys::OPENSSL_sk_pop_free_ex(stack, Some(call_free), free) };
}

/// `SSL_is_init_finished`, a macro of LibreSSL's: the handshake is done
/// (`SSL_ST_OK`).
///
/// # Safety
/// `ssl` is an SSL.
#[cfg(libressl)]
pub(crate) unsafe fn SSL_is_init_finished(ssl: *const SSL) -> c_int {
    /// `SSL_ST_OK`.
    const SSL_ST_OK: c_int = 0x03;
    // SAFETY: as the caller says.
    c_int::from(unsafe { SSL_state(ssl) } == SSL_ST_OK)
}

#[cfg(libressl)]
mod libressl {
    use core::ffi::{c_int, c_long, c_void};

    pub(crate) use openssl_sys::{_STACK as Stack, sk_num, sk_pop, sk_pop_free, sk_value};
    use openssl_sys::{EVP_PKEY, SSL, X509};

    // SAFETY: each declaration is LibreSSL's header's, for a function the
    // library this crate links (3.4.1 or later, checked at build) exports.
    unsafe extern "C" {
        pub(crate) fn OPENSSL_init_ssl(opts: u64, settings: *const c_void) -> c_int;
        pub(crate) fn SSL_get0_verified_chain(ssl: *const SSL) -> *mut openssl_sys::stack_st_X509;
        #[link_name = "SSL_get_peer_certificate"]
        pub(crate) fn SSL_get1_peer_certificate(ssl: *const SSL) -> *mut X509;
        pub(crate) fn SSL_state(ssl: *const SSL) -> c_int;
        pub(crate) fn X509_get_version(x: *const X509) -> c_long;
        pub(crate) fn X509_get0_extensions(x: *const X509) -> *const c_void;
        #[link_name = "EVP_PKEY_security_bits"]
        pub(crate) fn EVP_PKEY_get_security_bits(key: *const EVP_PKEY) -> c_int;
    }
}

// SAFETY: each declaration is LibreSSL's header's, for a function its
// build (C's `#ifdef LIBRESSL_VERSION_NUMBER` branches) calls.
#[cfg(libressl)]
unsafe extern "C" {
    pub(crate) fn X509_STORE_load_locations(
        store: *mut X509_STORE,
        file: *const c_char,
        path: *const c_char,
    ) -> c_int;
    pub(crate) fn SSL_set_bio(s: *mut SSL, rbio: *mut BIO, wbio: *mut BIO);
    pub(crate) fn SSL_get_client_random(s: *const SSL, out: *mut u8, outlen: usize) -> usize;
    pub(crate) fn SSL_SESSION_get_master_key(
        session: *const openssl_sys::SSL_SESSION,
        out: *mut u8,
        outlen: usize,
    ) -> usize;
    pub(crate) fn EVP_PKEY_get0_RSA(key: *mut EVP_PKEY) -> *mut c_void;
    pub(crate) fn EVP_PKEY_get0_DSA(key: *mut EVP_PKEY) -> *mut c_void;
    pub(crate) fn EVP_PKEY_get0_DH(key: *mut EVP_PKEY) -> *mut c_void;
    pub(crate) fn RSA_get0_key(
        rsa: *const c_void,
        n: *mut *const BIGNUM,
        e: *mut *const BIGNUM,
        d: *mut *const BIGNUM,
    );
    pub(crate) fn DSA_get0_pqg(
        dsa: *const c_void,
        p: *mut *const BIGNUM,
        q: *mut *const BIGNUM,
        g: *mut *const BIGNUM,
    );
    pub(crate) fn DSA_get0_key(
        dsa: *const c_void,
        public: *mut *const BIGNUM,
        private: *mut *const BIGNUM,
    );
    pub(crate) fn DH_get0_pqg(
        dh: *const c_void,
        p: *mut *const BIGNUM,
        q: *mut *const BIGNUM,
        g: *mut *const BIGNUM,
    );
    pub(crate) fn DH_get0_key(
        dh: *const c_void,
        public: *mut *const BIGNUM,
        private: *mut *const BIGNUM,
    );
    pub(crate) fn OBJ_find_sigid_algs(sig: c_int, digest: *mut c_int, key: *mut c_int) -> c_int;
    pub(crate) fn X509_get_signature_nid(x: *const X509) -> c_int;
}

// SAFETY: each declaration is OpenSSL 3's header's, for a function the
// library this crate links (3.0 or later, checked at build) exports.
#[cfg(ossl3)]
unsafe extern "C" {
    pub(crate) fn X509_STORE_load_file(store: *mut X509_STORE, file: *const c_char) -> c_int;
    pub(crate) fn X509_STORE_load_path(store: *mut X509_STORE, path: *const c_char) -> c_int;
    pub(crate) fn EVP_PKEY_get_group_name(
        key: *const EVP_PKEY,
        name: *mut c_char,
        size: usize,
        len: *mut usize,
    ) -> c_int;
    pub(crate) fn EVP_PKEY_get0_type_name(key: *const EVP_PKEY) -> *const c_char;
    pub(crate) fn SSL_CTX_set_default_read_buffer_len(ctx: *mut SSL_CTX, len: usize);
    pub(crate) fn X509_get_signature_info(
        x: *mut X509,
        mdnid: *mut c_int,
        pknid: *mut c_int,
        secbits: *mut c_int,
        flags: *mut u32,
    ) -> c_int;
    pub(crate) fn EVP_PKEY_get_default_digest_name(
        key: *mut EVP_PKEY,
        mdname: *mut c_char,
        mdname_sz: usize,
    ) -> c_int;
    pub(crate) fn SSL_set0_rbio(s: *mut SSL, rbio: *mut BIO);
    pub(crate) fn SSL_set0_wbio(s: *mut SSL, wbio: *mut BIO);
    pub(crate) fn SSL_get_peer_signature_type_nid(s: *const SSL, nid: *mut c_int) -> c_int;
    #[cfg(ossl320)]
    pub(crate) fn SSL_get0_group_name(s: *mut SSL) -> *const c_char;
}

/// AWS-LC's, from 1.61.0 (`cfg(read_buffer_len)`).
#[cfg(all(awslc, read_buffer_len))]
pub(crate) use openssl_sys::SSL_CTX_set_default_read_buffer_len;

// SAFETY: each declaration is OpenSSL 3's header's, for a function the
// library this crate links exports, OpenSSL 3.0 or later or LibreSSL
// 3.4.1 or later, both checked at build.
#[cfg(not(boringssl_like))]
unsafe extern "C" {
    pub(crate) fn SSL_CTX_set_msg_callback(ctx: *mut SSL_CTX, cb: Option<MsgCallback>);
    pub(crate) fn X509_STORE_up_ref(store: *mut X509_STORE) -> c_int;
    pub(crate) fn X509_STORE_add_crl(store: *mut X509_STORE, crl: *mut X509_CRL) -> c_int;
    pub(crate) fn X509_NAME_print_ex(
        out: *mut BIO,
        name: *const X509_NAME,
        indent: c_int,
        flags: c_ulong,
    ) -> c_int;
    pub(crate) fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
    pub(crate) fn ERR_peek_error() -> c_ulong;
    pub(crate) fn SSL_alert_desc_string_long(value: c_int) -> *const c_char;
    pub(crate) fn X509_get0_pubkey(x: *const X509) -> *mut EVP_PKEY;
    pub(crate) fn X509_get_X509_PUBKEY(x: *const X509) -> *mut X509Pubkey;
    pub(crate) fn i2d_X509_PUBKEY(a: *const X509Pubkey, out: *mut *mut u8) -> c_int;
    pub(crate) fn X509_get0_notBefore(x: *const X509) -> *const ASN1_TIME;
    pub(crate) fn X509_get0_notAfter(x: *const X509) -> *const ASN1_TIME;
    pub(crate) fn GENERAL_NAMES_free(names: *mut c_void);
    pub(crate) fn SSL_get_early_data_status(s: *const SSL) -> c_int;
    #[cfg(not(libressl))]
    pub(crate) fn BIO_up_ref(bio: *mut BIO) -> c_int;
    pub(crate) fn BIO_free(bio: *mut BIO) -> c_int;
    pub(crate) fn PEM_X509_INFO_read_bio(
        bio: *mut BIO,
        stack: *mut c_void,
        cb: *mut c_void,
        u: *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn X509_INFO_free(info: *mut c_void);
    pub(crate) fn BIO_get_shutdown(bio: *mut BIO) -> c_int;
    pub(crate) fn SSL_CTX_set_default_passwd_cb(ctx: *mut SSL_CTX, cb: pem_password_cb);
    pub(crate) fn SSL_CTX_set_default_passwd_cb_userdata(ctx: *mut SSL_CTX, u: *mut c_void);
    pub(crate) fn PEM_read_bio_X509_AUX(
        bio: *mut BIO,
        out: *mut *mut X509,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> *mut X509;
    pub(crate) fn d2i_PrivateKey_bio(bio: *mut BIO, out: *mut *mut EVP_PKEY) -> *mut EVP_PKEY;
    pub(crate) fn d2i_PKCS12_bio(bio: *mut BIO, out: *mut *mut PKCS12) -> *mut PKCS12;
    pub(crate) fn BIO_set_shutdown(bio: *mut BIO, shut: c_int);
    pub(crate) fn i2a_ASN1_OBJECT(bio: *mut BIO, a: *const ASN1_OBJECT) -> c_int;
    pub(crate) fn ERR_set_mark() -> c_int;
    pub(crate) fn ERR_pop_to_mark() -> c_int;
    pub(crate) fn i2t_ASN1_OBJECT(buf: *mut c_char, len: c_int, a: *const ASN1_OBJECT) -> c_int;
    pub(crate) fn X509_PUBKEY_get0_param(
        ppkalg: *mut *mut ASN1_OBJECT,
        pk: *mut *const u8,
        ppklen: *mut c_int,
        pa: *mut *mut X509_ALGOR,
        public: *const X509Pubkey,
    ) -> c_int;
    pub(crate) fn ASN1_STRING_print(bio: *mut BIO, v: *const ASN1_STRING) -> c_int;
    pub(crate) fn BN_print(bio: *mut BIO, a: *const BIGNUM) -> c_int;
}

/// `BIO_C_SET_FILENAME` and the flags `BIO_read_filename` passes
/// (`bio.h`): the file opened to read, closed with the BIO. The values
/// below are the same in every library of the family but where said.
#[cfg(not(boringssl_like))]
pub(crate) const BIO_C_SET_FILENAME: c_int = 108;
#[cfg(not(boringssl_like))]
pub(crate) const BIO_CLOSE_FP_READ: c_long = 0x01 | 0x02;

/// `BIO_read_filename`: a file BIO opens `name` to read, closed with it;
/// above 0 if it did. A macro over `BIO_ctrl` of OpenSSL's, a function of
/// the forks'.
///
/// # Safety
/// `bio` is a file BIO, `name` a C string alive for the call.
pub(crate) unsafe fn BIO_read_filename(bio: *mut BIO, name: *const c_char) -> c_long {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says; the library reads the name.
    let opened = unsafe {
        openssl_sys::BIO_ctrl(
            bio,
            BIO_C_SET_FILENAME,
            BIO_CLOSE_FP_READ,
            name.cast_mut().cast(),
        )
    };
    #[cfg(boringssl_like)]
    // SAFETY: as the caller says.
    let opened = c_long::from(unsafe { openssl_sys::BIO_read_filename(bio, name) });
    opened
}

/// The `SSL_CTX_ctrl` commands of `SSL_CTX_clear_chain_certs` and
/// `SSL_CTX_add0_chain_cert` (`ssl.h`).
#[cfg(not(boringssl_like))]
pub(crate) const SSL_CTRL_CHAIN: c_int = 88;
#[cfg(not(boringssl_like))]
pub(crate) const SSL_EARLY_DATA_ACCEPTED: c_int = 2;
#[cfg(not(boringssl_like))]
pub(crate) const SSL_CTRL_CHAIN_CERT: c_int = 89;

/// `V_ASN1_NEG_INTEGER` (`asn1.h`): a negative serial's type.
pub(crate) const V_ASN1_NEG_INTEGER: c_int = 2 | 0x100;

/// `XN_FLAG_ONELINE` (`x509.h`): `ASN1_STRFLGS_RFC2253 |
/// ASN1_STRFLGS_ESC_QUOTE | XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_SPC_EQ |
/// XN_FLAG_FN_SN`.
pub(crate) const XN_FLAG_ONELINE: c_ulong = 0x317 | 8 | (2 << 16) | (1 << 23);

/// `BIO_TYPE_MEM` (`bio.h`): `1 | BIO_TYPE_SOURCE_SINK`.
pub(crate) const BIO_TYPE_MEM: c_int = 1 | 0x0400;

/// `SSL_ctrl` and `SSL_CTX_ctrl` commands (`ssl.h`), which the forks
/// have none of: see the functions below.
#[cfg(not(boringssl_like))]
mod ctrl {
    use core::ffi::{c_int, c_long};

    pub(crate) const SSL_CTRL_MODE: c_int = 33;
    pub(crate) const SSL_CTRL_SET_READ_AHEAD: c_int = 41;
    pub(crate) const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
    pub(crate) const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
    pub(crate) const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
    pub(crate) const SSL_CTRL_SET_GROUPS_LIST: c_int = 92;
    // LibreSSL takes no list of signature algorithms.
    #[cfg_attr(libressl, allow(dead_code, reason = "checked against the header only"))]
    pub(crate) const SSL_CTRL_SET_SIGALGS_LIST: c_int = 98;
    /// `SSL_get_negotiated_group`, before 3.2 named the group itself.
    #[cfg(all(ossl3, not(ossl320)))]
    pub(crate) const SSL_CTRL_GET_NEGOTIATED_GROUP: c_int = 134;
    /// `TLSEXT_NAMETYPE_host_name`.
    pub(crate) const TLSEXT_NAMETYPE_HOST_NAME: c_long = 0;
}
#[cfg(not(boringssl_like))]
pub(crate) use ctrl::*;

/// `ERR_LIB_SSL`, `ERR_LIB_PEM`, and the reasons C tells apart
/// (`sslerr.h`, `pemerr.h`), OpenSSL's and LibreSSL's numbers.
#[cfg(not(boringssl_like))]
mod reasons {
    use core::ffi::c_int;

    pub(crate) const ERR_LIB_SSL: c_int = 20;
    pub(crate) const SSL_R_CERTIFICATE_VERIFY_FAILED: c_int = 134;
    pub(crate) const SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED: c_int = 1045;
    pub(crate) const SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED: Option<c_int> = Some(1116);
    /// The reason C clears after a chain's last certificate.
    pub(crate) const ERR_LIB_PEM: c_int = 9;
    pub(crate) const PEM_R_NO_START_LINE: c_int = 108;
}
/// The forks' own numbers, from their headers.
#[cfg(boringssl_like)]
mod reasons {
    use core::ffi::c_int;

    // Unsigned in BoringSSL's headers, signed in AWS-LC's; small either way.
    pub(crate) const ERR_LIB_SSL: c_int = openssl_sys::ERR_LIB_SSL as c_int;
    pub(crate) const SSL_R_CERTIFICATE_VERIFY_FAILED: c_int =
        openssl_sys::SSL_R_CERTIFICATE_VERIFY_FAILED as c_int;
    pub(crate) const SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED: c_int =
        openssl_sys::SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED as c_int;
    pub(crate) const ERR_LIB_PEM: c_int = openssl_sys::ERR_LIB_PEM as c_int;
    pub(crate) const PEM_R_NO_START_LINE: c_int = openssl_sys::PEM_R_NO_START_LINE as c_int;
}
/// The forks' older name for it, which C's `openssl.h` maps it to without
/// OpenSSL 3: a reference of the caller's, as `SSL_get1_peer_certificate`'s.
#[cfg(boringssl_like)]
pub(crate) use openssl_sys::SSL_get_peer_certificate as SSL_get1_peer_certificate;
pub(crate) use reasons::*;
/// `SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED`, which the forks' headers do
/// not define: C's `#ifdef` leaves its case out.
#[cfg(boringssl_like)]
pub(crate) const SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED: Option<c_int> = None;

/// `OPENSSL_VERSION_STRING`: the version alone, `3.5.9`.
#[cfg(ossl3)]
pub(crate) const OPENSSL_VERSION_STRING: c_int = 6;
/// `OPENSSL_VERSION`: the library's version line, LibreSSL's
/// `LibreSSL 4.4.0`.
#[cfg(libressl)]
pub(crate) const OPENSSL_VERSION: c_int = 0;

// What OpenSSL and LibreSSL have as macros over `SSL_CTX_ctrl` and
// `SSL_ctrl`, C's calls, each one function: the command over OpenSSL and
// LibreSSL, the fork's function of the same name over AWS-LC and
// BoringSSL.

/// `SSL_CTX_set_min_proto_version`, `version` a protocol's number, or 0
/// for the oldest the library has.
///
/// # Safety
/// `ctx` is a context.
pub(crate) unsafe fn SSL_CTX_set_min_proto_version(ctx: *mut SSL_CTX, version: u16) -> c_int {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says; the command takes no pointer.
    let set = unsafe {
        openssl_sys::SSL_CTX_ctrl(
            ctx,
            SSL_CTRL_SET_MIN_PROTO_VERSION,
            c_long::from(version),
            core::ptr::null_mut(),
        )
    } as c_int;
    #[cfg(boringssl_like)]
    // SAFETY: as the caller says.
    let set = unsafe { openssl_sys::SSL_CTX_set_min_proto_version(ctx, version) };
    set
}

/// `SSL_CTX_set_max_proto_version`, 0 for the newest the library has.
///
/// # Safety
/// `ctx` is a context.
pub(crate) unsafe fn SSL_CTX_set_max_proto_version(ctx: *mut SSL_CTX, version: u16) -> c_int {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says; the command takes no pointer.
    let set = unsafe {
        openssl_sys::SSL_CTX_ctrl(
            ctx,
            SSL_CTRL_SET_MAX_PROTO_VERSION,
            c_long::from(version),
            core::ptr::null_mut(),
        )
    } as c_int;
    #[cfg(boringssl_like)]
    // SAFETY: as the caller says.
    let set = unsafe { openssl_sys::SSL_CTX_set_max_proto_version(ctx, version) };
    set
}

/// `SSL_CTX_set_read_ahead`: read records ahead.
///
/// # Safety
/// `ctx` is a context.
pub(crate) unsafe fn SSL_CTX_set_read_ahead(ctx: *mut SSL_CTX, yes: bool) {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says; the command takes no pointer.
    unsafe {
        openssl_sys::SSL_CTX_ctrl(
            ctx,
            SSL_CTRL_SET_READ_AHEAD,
            c_long::from(yes),
            core::ptr::null_mut(),
        )
    };
    #[cfg(boringssl_like)]
    // SAFETY: as the caller says.
    unsafe {
        openssl_sys::SSL_CTX_set_read_ahead(ctx, c_int::from(yes))
    };
}

/// `SSL_CTX_set_mode`: `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`, the one
/// mode C sets.
///
/// # Safety
/// `ctx` is a context.
pub(crate) unsafe fn SSL_CTX_set_mode_moving_write_buffer(ctx: *mut SSL_CTX) {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says; the command takes no pointer.
    unsafe {
        openssl_sys::SSL_CTX_ctrl(
            ctx,
            SSL_CTRL_MODE,
            openssl_sys::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER,
            core::ptr::null_mut(),
        )
    };
    #[cfg(boringssl_like)]
    // SAFETY: as the caller says.
    unsafe {
        openssl_sys::SSL_CTX_set_mode(ctx, openssl_sys::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER as u32)
    };
}

/// `SSL_CTX_set1_curves_list` (`SSL_CTX_set1_groups_list`): `list` a C
/// string, which the library copies.
///
/// # Safety
/// `ctx` is a context, `list` a C string alive for the call.
pub(crate) unsafe fn SSL_CTX_set1_curves_list(ctx: *mut SSL_CTX, list: *const c_char) -> c_int {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says; the library only reads the string.
    let set = unsafe {
        openssl_sys::SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, list.cast_mut().cast())
    } as c_int;
    #[cfg(boringssl_like)]
    // SAFETY: as the caller says.
    let set = unsafe { openssl_sys::SSL_CTX_set1_curves_list(ctx, list) };
    set
}

/// `SSL_CTX_set1_sigalgs_list`, as `SSL_CTX_set1_curves_list`.
///
/// # Safety
/// As `SSL_CTX_set1_curves_list`.
#[cfg(not(libressl))]
pub(crate) unsafe fn SSL_CTX_set1_sigalgs_list(ctx: *mut SSL_CTX, list: *const c_char) -> c_int {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says; the library only reads the string.
    let set = unsafe {
        openssl_sys::SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS_LIST, 0, list.cast_mut().cast())
    } as c_int;
    #[cfg(boringssl_like)]
    // SAFETY: as the caller says.
    let set = unsafe { openssl_sys::SSL_CTX_set1_sigalgs_list(ctx, list) };
    set
}

/// `SSL_set_tlsext_host_name`: `name` a C string, which the library
/// copies.
///
/// # Safety
/// `ssl` is an SSL, `name` a C string alive for the call.
pub(crate) unsafe fn SSL_set_tlsext_host_name(ssl: *mut SSL, name: *const c_char) -> c_int {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says; the library only reads the string.
    let set = unsafe {
        openssl_sys::SSL_ctrl(
            ssl,
            SSL_CTRL_SET_TLSEXT_HOSTNAME,
            TLSEXT_NAMETYPE_HOST_NAME,
            name.cast_mut().cast(),
        )
    } as c_int;
    #[cfg(boringssl_like)]
    // SAFETY: as the caller says.
    let set = unsafe { openssl_sys::SSL_set_tlsext_host_name(ssl, name) };
    set
}

/// The early data a session allows (`SSL_SESSION_get_max_early_data`);
/// none from the forks, whose build C makes without early data
/// (`HAVE_OPENSSL_EARLYDATA` unset).
///
/// # Safety
/// `session` is a session.
pub(crate) unsafe fn SSL_SESSION_get_max_early_data(session: *const SSL_SESSION) -> u32 {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says.
    let most = unsafe { openssl_sys::SSL_SESSION_get_max_early_data(session) };
    #[cfg(boringssl_like)]
    let most = {
        let _ = session;
        0
    };
    most
}

/// `SSL_CTX_clear_chain_certs`.
///
/// # Safety
/// `ctx` is a context.
pub(crate) unsafe fn SSL_CTX_clear_chain_certs(ctx: *mut SSL_CTX) -> c_int {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says; no certificate clears the chain.
    let done = unsafe { openssl_sys::SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 0, core::ptr::null_mut()) }
        as c_int;
    #[cfg(boringssl_like)]
    // SAFETY: as the caller says.
    let done = unsafe { openssl_sys::SSL_CTX_clear_chain_certs(ctx) };
    done
}

/// `SSL_CTX_add0_chain_cert`: the context takes the reference to `cert`
/// if it succeeds.
///
/// # Safety
/// `ctx` is a context, `cert` a certificate whose reference the caller
/// gives up on success.
pub(crate) unsafe fn SSL_CTX_add0_chain_cert(ctx: *mut SSL_CTX, cert: *mut X509) -> c_int {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says (`SSL_CTRL_CHAIN_CERT`, 0: add, not
    // add1).
    let done =
        unsafe { openssl_sys::SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 0, cert.cast()) } as c_int;
    #[cfg(boringssl_like)]
    // SAFETY: as the caller says.
    let done = unsafe { openssl_sys::SSL_CTX_add0_chain_cert(ctx, cert) };
    done
}

// The forks' calls whose C types differ from OpenSSL's, under the types
// this crate calls OpenSSL's with: a stack's count and index are `size_t`
// there (C's `numcert_t`), a memory BIO's length `ossl_ssize_t`, the ALPN
// list's `size_t`, the stapled response's `const uint8_t *`.

/// `sk_num`: how many entries `stack` holds.
///
/// # Safety
/// `stack` is a stack.
#[cfg(boringssl_like)]
pub(crate) unsafe fn sk_num(stack: *const Stack) -> c_int {
    // SAFETY: as the caller says.
    let n = unsafe { openssl_sys::OPENSSL_sk_num(stack) };
    // A stack this large is none the library could have made.
    c_int::try_from(n).expect("a stack's count fits an int")
}

/// `sk_value`: the entry at `i`, null past the end.
///
/// # Safety
/// `stack` is a stack.
#[cfg(boringssl_like)]
pub(crate) unsafe fn sk_value(stack: *const Stack, i: c_int) -> *mut c_void {
    let Ok(i) = usize::try_from(i) else {
        return core::ptr::null_mut();
    };
    // SAFETY: as the caller says.
    unsafe { openssl_sys::OPENSSL_sk_value(stack, i) }
}

/// A memory BIO reading `bytes`, which must outlive it; null if the
/// library could not make one, or `bytes` is longer than it takes.
///
/// # Safety
/// None beyond `bytes` outliving the BIO, whose reads it serves.
pub(crate) unsafe fn BIO_new_mem_buf(bytes: &[u8]) -> *mut BIO {
    #[cfg(not(boringssl_like))]
    let len = c_int::try_from(bytes.len());
    #[cfg(boringssl_like)]
    let len = isize::try_from(bytes.len());
    let Ok(len) = len else {
        return core::ptr::null_mut();
    };
    // SAFETY: `len` bytes at the pointer, alive as the caller says.
    unsafe { openssl_sys::BIO_new_mem_buf(bytes.as_ptr().cast(), len) }
}

/// `SSL_set_alpn_protos`: the list of protocols offered, wire-encoded,
/// which the library copies; 0 if it took it.
///
/// # Safety
/// `ssl` is an SSL.
pub(crate) unsafe fn SSL_set_alpn_protos(ssl: *mut SSL, protos: &[u8]) -> c_int {
    #[cfg(not(boringssl_like))]
    let len = u32::try_from(protos.len()).expect("a short list");
    #[cfg(boringssl_like)]
    let len = protos.len();
    // SAFETY: as the caller says, and `len` bytes at the pointer.
    unsafe { openssl_sys::SSL_set_alpn_protos(ssl, protos.as_ptr(), len) }
}

/// The OCSP response the peer stapled, the SSL's own while it lives:
/// none if it stapled none (AWS-LC's length is 0 then, OpenSSL's -1).
///
/// # Safety
/// `ssl` is an SSL; the bytes live while it does, unchanged.
#[cfg(not(no_ocsp))]
pub(crate) unsafe fn stapled_response<'a>(ssl: *mut SSL) -> Option<&'a [u8]> {
    #[cfg(not(boringssl_like))]
    let (status, len) = {
        let mut status: *mut u8 = core::ptr::null_mut();
        // SAFETY: as the caller says.
        let len = unsafe { openssl_sys::SSL_get_tlsext_status_ocsp_resp(ssl, &mut status) };
        (status.cast_const(), usize::try_from(len).ok())
    };
    #[cfg(boringssl_like)]
    let (status, len) = {
        let mut status: *const u8 = core::ptr::null();
        // SAFETY: as the caller says.
        let len = unsafe { openssl_sys::SSL_get_tlsext_status_ocsp_resp(ssl, &mut status) };
        (status, Some(len))
    };
    if status.is_null() {
        return None;
    }
    // SAFETY: `len` bytes at `status`, the SSL's, as the caller says.
    Some(unsafe { core::slice::from_raw_parts(status, len.unwrap_or(0)) })
}

/// The certificates and revocation lists of the PEM text `bio` reads, a
/// new stack of `X509_INFO`s (`PEM_X509_INFO_read_bio` with no stack to
/// add to and no password callback, as C calls it); null if none.
///
/// # Safety
/// `bio` is a BIO.
pub(crate) unsafe fn PEM_X509_INFO_read_bio_new(bio: *mut BIO) -> *mut Stack {
    #[cfg(not(boringssl_like))]
    // SAFETY: as the caller says; null asks for a new stack.
    let infos = unsafe {
        PEM_X509_INFO_read_bio(
            bio,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    #[cfg(boringssl_like)]
    // SAFETY: as above.
    let infos =
        unsafe { PEM_X509_INFO_read_bio(bio, core::ptr::null_mut(), None, core::ptr::null_mut()) };
    infos.cast()
}

/// What a subject alternative name holds:a DNS name's or an address's
/// string (`GENERAL_NAME`'s `d`, which openssl-sys makes a pointer of
/// OpenSSL's and a union of the forks').
pub(crate) fn general_name_string(name: &openssl_sys::GENERAL_NAME) -> *mut ASN1_STRING {
    #[cfg(not(boringssl_like))]
    let d = name.d.cast();
    // SAFETY: every member of the union is a pointer, read as the string
    // C reads a DNS name or an address as.
    #[cfg(boringssl_like)]
    let d = unsafe { name.d.ptr }.cast();
    d
}

/// The store's verification flags C sets (`x509_vfy.h`), as openssl-sys
/// types OpenSSL's: the forks' headers' values.
#[cfg(not(boringssl_like))]
pub(crate) use openssl_sys::{
    X509_V_FLAG_CRL_CHECK, X509_V_FLAG_CRL_CHECK_ALL, X509_V_FLAG_PARTIAL_CHAIN,
    X509_V_FLAG_TRUSTED_FIRST,
};
#[cfg(boringssl_like)]
mod flags {
    use core::ffi::c_ulong;

    pub(crate) const X509_V_FLAG_CRL_CHECK: c_ulong = openssl_sys::X509_V_FLAG_CRL_CHECK as _;
    pub(crate) const X509_V_FLAG_CRL_CHECK_ALL: c_ulong =
        openssl_sys::X509_V_FLAG_CRL_CHECK_ALL as _;
    pub(crate) const X509_V_FLAG_PARTIAL_CHAIN: c_ulong =
        openssl_sys::X509_V_FLAG_PARTIAL_CHAIN as _;
    pub(crate) const X509_V_FLAG_TRUSTED_FIRST: c_ulong =
        openssl_sys::X509_V_FLAG_TRUSTED_FIRST as _;
}
#[cfg(boringssl_like)]
pub(crate) use flags::*;

/// The flags C prints a certificate's names with (`x509_name_oneline`):
/// `XN_FLAG_SEP_SPLUS_SPC | (XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB &
/// ~XN_FLAG_SPC_EQ)`, which leaves `XN_FLAG_ONELINE`'s string flags but
/// the escaping of bytes above 127, its short field names, and the
/// `;+` separator in place of its own (whose bits are a subset of it).
pub(crate) const NAME_FLAGS: c_ulong = {
    const ASN1_STRFLGS_ESC_2253: c_ulong = 1;
    const ASN1_STRFLGS_ESC_CTRL: c_ulong = 2;
    const ASN1_STRFLGS_ESC_QUOTE: c_ulong = 8;
    const ASN1_STRFLGS_UTF8_CONVERT: c_ulong = 0x10;
    const ASN1_STRFLGS_DUMP_UNKNOWN: c_ulong = 0x100;
    const ASN1_STRFLGS_DUMP_DER: c_ulong = 0x200;
    const XN_FLAG_SEP_SPLUS_SPC: c_ulong = 3 << 16;
    const XN_FLAG_FN_SN: c_ulong = 0;
    XN_FLAG_SEP_SPLUS_SPC
        | ASN1_STRFLGS_ESC_2253
        | ASN1_STRFLGS_ESC_CTRL
        | ASN1_STRFLGS_ESC_QUOTE
        | ASN1_STRFLGS_UTF8_CONVERT
        | ASN1_STRFLGS_DUMP_UNKNOWN
        | ASN1_STRFLGS_DUMP_DER
        | XN_FLAG_FN_SN
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The macros' values, as OpenSSL 3's headers expand them, the same in
    /// every library of the family but where said.
    #[test]
    fn the_values_are_the_headers_expansions() {
        #[cfg(not(boringssl_like))]
        {
            assert_eq!(BIO_C_SET_FILENAME, 108);
            // `BIO_CLOSE | BIO_FP_READ`.
            assert_eq!(BIO_CLOSE_FP_READ, 0x03);
        }
        // `V_ASN1_INTEGER | V_ASN1_NEG`.
        assert_eq!(V_ASN1_NEG_INTEGER, 0x102);
        assert_eq!(XN_FLAG_ONELINE, 0x0082_031f);
        // `1 | BIO_TYPE_SOURCE_SINK`.
        assert_eq!(BIO_TYPE_MEM, 0x0401);
        #[cfg(not(boringssl_like))]
        {
            assert_eq!((SSL_CTRL_CHAIN, SSL_CTRL_CHAIN_CERT), (88, 89));
            assert_eq!((ERR_LIB_PEM, PEM_R_NO_START_LINE), (9, 108));
            assert_eq!(
                (
                    SSL_CTRL_MODE,
                    SSL_CTRL_SET_READ_AHEAD,
                    SSL_CTRL_SET_TLSEXT_HOSTNAME,
                    SSL_CTRL_SET_MIN_PROTO_VERSION,
                    SSL_CTRL_SET_MAX_PROTO_VERSION,
                    SSL_CTRL_SET_GROUPS_LIST,
                    SSL_CTRL_SET_SIGALGS_LIST,
                ),
                (33, 41, 55, 123, 124, 92, 98)
            );
            assert_eq!(TLSEXT_NAMETYPE_HOST_NAME, 0);
            assert_eq!(
                (
                    ERR_LIB_SSL,
                    SSL_R_CERTIFICATE_VERIFY_FAILED,
                    SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED,
                    SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED,
                ),
                (20, 134, 1045, Some(1116))
            );
        }
        #[cfg(ossl3)]
        assert_eq!(OPENSSL_VERSION_STRING, 6);
        #[cfg(libressl)]
        assert_eq!(OPENSSL_VERSION, 0);
        // C's expression over the headers' values: `XN_FLAG_SEP_SPLUS_SPC`
        // (0x30000) with `XN_FLAG_ONELINE` (0x82031f) less
        // `ASN1_STRFLGS_ESC_MSB` (4) and `XN_FLAG_SPC_EQ` (0x800000).
        assert_eq!(NAME_FLAGS, 0x3_0000 | (0x0082_031f & !4 & !0x0080_0000));
        assert_eq!(NAME_FLAGS, 0x0003_031b);
    }

    /// The values this crate keeps of its own are the forks' headers'
    /// too, and theirs differ from OpenSSL's where it takes theirs: the
    /// error queue's library and reasons.
    #[cfg(boringssl_like)]
    #[test]
    fn the_forks_values_are_their_headers() {
        assert_eq!(V_ASN1_NEG_INTEGER, openssl_sys::V_ASN1_NEG_INTEGER);
        assert_eq!(XN_FLAG_ONELINE, openssl_sys::XN_FLAG_ONELINE as c_ulong);
        assert_eq!(BIO_TYPE_MEM, openssl_sys::BIO_TYPE_MEM);
        assert_eq!(openssl_sys::TLSEXT_NAMETYPE_host_name, 0);
        // AWS-LC's and BoringSSL's numbering.
        assert_eq!(
            (ERR_LIB_SSL, SSL_R_CERTIFICATE_VERIFY_FAILED, ERR_LIB_PEM),
            (16, 125, 9)
        );
        assert_eq!(SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED, 1045);
        assert_eq!(SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED, None);
    }
}
