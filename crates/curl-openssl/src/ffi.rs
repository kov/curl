//! What this crate calls of OpenSSL that openssl-sys does not declare,
//! as OpenSSL 3's headers declare it, and the values of the headers'
//! macros it uses. Declarations only.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

use openssl_sys::{ASN1_TIME, BIO, EVP_PKEY, SSL, SSL_CTX, X509, X509_CRL, X509_NAME, X509_STORE};

/// A certificate's public key with its algorithm (`X509_PUBKEY`), only
/// ever pointed to.
pub(crate) enum X509Pubkey {}

/// `SSL_CTX_set_msg_callback`'s callback.
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

// SAFETY: each declaration is OpenSSL 3's header's, for a function the
// library this crate links (3.0 or later, checked at build) exports.
unsafe extern "C" {
    pub(crate) fn SSL_CTX_set_msg_callback(ctx: *mut SSL_CTX, cb: Option<MsgCallback>);
    pub(crate) fn X509_STORE_load_file(store: *mut X509_STORE, file: *const c_char) -> c_int;
    pub(crate) fn X509_STORE_load_path(store: *mut X509_STORE, path: *const c_char) -> c_int;
    pub(crate) fn X509_STORE_up_ref(store: *mut X509_STORE) -> c_int;
    pub(crate) fn X509_STORE_add_crl(store: *mut X509_STORE, crl: *mut X509_CRL) -> c_int;
    pub(crate) fn X509_NAME_print_ex(
        out: *mut BIO,
        name: *const X509_NAME,
        indent: c_int,
        flags: c_ulong,
    ) -> c_int;
    pub(crate) fn EVP_PKEY_get_group_name(
        key: *const EVP_PKEY,
        name: *mut c_char,
        size: usize,
        len: *mut usize,
    ) -> c_int;
    pub(crate) fn EVP_PKEY_get0_type_name(key: *const EVP_PKEY) -> *const c_char;
    pub(crate) fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
    pub(crate) fn ERR_peek_error() -> c_ulong;
    pub(crate) fn SSL_alert_desc_string_long(value: c_int) -> *const c_char;
    pub(crate) fn SSL_CTX_set_default_read_buffer_len(ctx: *mut SSL_CTX, len: usize);
    pub(crate) fn X509_get0_pubkey(x: *const X509) -> *mut EVP_PKEY;
    pub(crate) fn X509_get_X509_PUBKEY(x: *const X509) -> *mut X509Pubkey;
    pub(crate) fn i2d_X509_PUBKEY(a: *const X509Pubkey, out: *mut *mut u8) -> c_int;
    pub(crate) fn X509_get0_notBefore(x: *const X509) -> *const ASN1_TIME;
    pub(crate) fn X509_get0_notAfter(x: *const X509) -> *const ASN1_TIME;
    pub(crate) fn GENERAL_NAMES_free(names: *mut c_void);
    pub(crate) fn SSL_set0_rbio(s: *mut SSL, rbio: *mut BIO);
    pub(crate) fn SSL_set0_wbio(s: *mut SSL, wbio: *mut BIO);
    pub(crate) fn BIO_up_ref(bio: *mut BIO) -> c_int;
    pub(crate) fn BIO_free(bio: *mut BIO) -> c_int;
    pub(crate) fn SSL_get_peer_signature_type_nid(s: *const SSL, nid: *mut c_int) -> c_int;
    #[cfg(ossl320)]
    pub(crate) fn SSL_get0_group_name(s: *mut SSL) -> *const c_char;
    pub(crate) fn PEM_X509_INFO_read_bio(
        bio: *mut BIO,
        stack: *mut c_void,
        cb: *mut c_void,
        u: *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn X509_INFO_free(info: *mut c_void);
    pub(crate) fn BIO_get_shutdown(bio: *mut BIO) -> c_int;
    pub(crate) fn BIO_set_shutdown(bio: *mut BIO, shut: c_int);
}

/// `BIO_TYPE_MEM` (`bio.h`): `1 | BIO_TYPE_SOURCE_SINK`.
pub(crate) const BIO_TYPE_MEM: c_int = 1 | 0x0400;

/// `SSL_ctrl` and `SSL_CTX_ctrl` commands (`ssl.h`).
pub(crate) const SSL_CTRL_MODE: c_int = 33;
pub(crate) const SSL_CTRL_SET_READ_AHEAD: c_int = 41;
pub(crate) const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
pub(crate) const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
pub(crate) const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
pub(crate) const SSL_CTRL_SET_GROUPS_LIST: c_int = 92;
pub(crate) const SSL_CTRL_SET_SIGALGS_LIST: c_int = 98;
/// `SSL_get_negotiated_group`, before 3.2 named the group itself.
#[cfg(not(ossl320))]
pub(crate) const SSL_CTRL_GET_NEGOTIATED_GROUP: c_int = 134;
/// `TLSEXT_NAMETYPE_host_name`.
pub(crate) const TLSEXT_NAMETYPE_HOST_NAME: c_long = 0;

/// `ERR_LIB_SSL`, and the reasons C tells apart (`sslerr.h`).
pub(crate) const ERR_LIB_SSL: c_int = 20;
pub(crate) const SSL_R_CERTIFICATE_VERIFY_FAILED: c_int = 134;
pub(crate) const SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED: c_int = 1045;
pub(crate) const SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED: c_int = 1116;

/// `OPENSSL_VERSION_STRING`: the version alone, `3.5.9`.
pub(crate) const OPENSSL_VERSION_STRING: c_int = 6;

/// The flags C prints a certificate's names with (`x509_name_oneline`):
/// `XN_FLAG_SEP_SPLUS_SPC | (XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB &
/// ~XN_FLAG_SPC_EQ)`.
pub(crate) const NAME_FLAGS: c_ulong = {
    const ASN1_STRFLGS_ESC_2253: c_ulong = 1;
    const ASN1_STRFLGS_ESC_CTRL: c_ulong = 2;
    const ASN1_STRFLGS_ESC_MSB: c_ulong = 4;
    const ASN1_STRFLGS_ESC_QUOTE: c_ulong = 8;
    const ASN1_STRFLGS_UTF8_CONVERT: c_ulong = 0x10;
    const ASN1_STRFLGS_DUMP_UNKNOWN: c_ulong = 0x100;
    const ASN1_STRFLGS_DUMP_DER: c_ulong = 0x200;
    const ASN1_STRFLGS_RFC2253: c_ulong = ASN1_STRFLGS_ESC_2253
        | ASN1_STRFLGS_ESC_CTRL
        | ASN1_STRFLGS_ESC_MSB
        | ASN1_STRFLGS_UTF8_CONVERT
        | ASN1_STRFLGS_DUMP_UNKNOWN
        | ASN1_STRFLGS_DUMP_DER;
    const XN_FLAG_SEP_CPLUS_SPC: c_ulong = 2 << 16;
    const XN_FLAG_SEP_SPLUS_SPC: c_ulong = 3 << 16;
    const XN_FLAG_SPC_EQ: c_ulong = 1 << 23;
    const XN_FLAG_FN_SN: c_ulong = 0;
    const XN_FLAG_ONELINE: c_ulong = ASN1_STRFLGS_RFC2253
        | ASN1_STRFLGS_ESC_QUOTE
        | XN_FLAG_SEP_CPLUS_SPC
        | XN_FLAG_SPC_EQ
        | XN_FLAG_FN_SN;
    XN_FLAG_SEP_SPLUS_SPC | (XN_FLAG_ONELINE & !ASN1_STRFLGS_ESC_MSB & !XN_FLAG_SPC_EQ)
};
