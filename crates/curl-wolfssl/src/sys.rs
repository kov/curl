//! The parts of wolfSSL's `ssl.h`, `error-ssl.h`, `asn_public.h` and
//! wolfCrypt's `ed25519.h` the crate calls, declared as wolfSSL 5.9 has
//! them. Every object is the library's own, made and freed by its calls;
//! the constants declared here are compared with the headers' by the
//! crate's tests (`csrc/layout.c`), which also refuse a build of the
//! library configured otherwise than the binding follows.

#![allow(
    unsafe_code,
    non_camel_case_types,
    dead_code,
    clippy::upper_case_acronyms
)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_ushort, c_void};

/// An object of the library's, reached only through a pointer.
#[repr(C)]
pub(crate) struct Opaque {
    _private: [u8; 0],
}

pub(crate) type WOLFSSL = Opaque;
pub(crate) type WOLFSSL_CTX = Opaque;
pub(crate) type WOLFSSL_METHOD = Opaque;
pub(crate) type WOLFSSL_SESSION = Opaque;
pub(crate) type WOLFSSL_X509 = Opaque;
pub(crate) type WOLFSSL_X509_STORE = Opaque;
pub(crate) type WOLFSSL_BIO = Opaque;
pub(crate) type WOLFSSL_BIO_METHOD = Opaque;
pub(crate) type ed25519_key = Opaque;

pub(crate) type bio_write_cb =
    unsafe extern "C" fn(bio: *mut WOLFSSL_BIO, buf: *const c_char, len: c_int) -> c_int;
pub(crate) type bio_read_cb =
    unsafe extern "C" fn(bio: *mut WOLFSSL_BIO, buf: *mut c_char, len: c_int) -> c_int;
pub(crate) type bio_ctrl_cb = unsafe extern "C" fn(
    bio: *mut WOLFSSL_BIO,
    cmd: c_int,
    num: c_long,
    ptr: *mut c_void,
) -> c_long;
pub(crate) type bio_create_cb = unsafe extern "C" fn(bio: *mut WOLFSSL_BIO) -> c_int;
pub(crate) type new_session_cb =
    unsafe extern "C" fn(ssl: *mut WOLFSSL, session: *mut WOLFSSL_SESSION) -> c_int;
pub(crate) type verify_cb = unsafe extern "C" fn(ok: c_int, store: *mut c_void) -> c_int;

pub(crate) const WOLFSSL_SUCCESS: c_int = 1;
pub(crate) const WOLFSSL_ERROR_NONE: c_int = 0;
pub(crate) const WOLFSSL_ERROR_WANT_READ: c_int = 2;
pub(crate) const WOLFSSL_ERROR_WANT_WRITE: c_int = 3;
pub(crate) const WOLFSSL_ERROR_ZERO_RETURN: c_int = 6;
pub(crate) const WOLFSSL_ALPN_NOT_FOUND: c_int = -458;
pub(crate) const DOMAIN_NAME_MISMATCH: c_int = -322;
pub(crate) const ASN_NO_SIGNER_E: c_int = -188;
pub(crate) const ASN_AFTER_DATE_E: c_int = -151;
pub(crate) const ASN_BEFORE_DATE_E: c_int = -150;
pub(crate) const WOLFSSL_FILETYPE_PEM: c_int = 1;
pub(crate) const WOLFSSL_FILETYPE_ASN1: c_int = 2;
pub(crate) const WOLFSSL_VERIFY_NONE: c_int = 0;
pub(crate) const WOLFSSL_VERIFY_PEER: c_int = 1;
pub(crate) const WOLFSSL_SNI_HOST_NAME: u8 = 0;
pub(crate) const WOLFSSL_ALPN_CONTINUE_ON_MISMATCH: u8 = 2;
pub(crate) const WOLFSSL_LOAD_FLAG_IGNORE_ERR: u32 = 1;
pub(crate) const WOLFSSL_SENT_SHUTDOWN: c_int = 1;
pub(crate) const WOLFSSL_EARLY_DATA_REJECTED: c_int = 1;
pub(crate) const WOLFSSL_BIO_MEMORY: c_int = 4;
pub(crate) const WOLFSSL_BIO_FLAG_READ: c_int = 0x02;
pub(crate) const WOLFSSL_BIO_FLAG_WRITE: c_int = 0x04;
pub(crate) const WOLFSSL_BIO_FLAG_RETRY: c_int = 0x10;
pub(crate) const WOLFSSL_BIO_CTRL_EOF: c_int = 2;
pub(crate) const WOLFSSL_BIO_CTRL_GET_CLOSE: c_int = 8;
pub(crate) const WOLFSSL_BIO_CTRL_SET_CLOSE: c_int = 9;
pub(crate) const WOLFSSL_BIO_CTRL_FLUSH: c_int = 11;
pub(crate) const WOLFSSL_BIO_CTRL_DUP: c_int = 12;
pub(crate) const WOLFSSL_SSLV3: c_int = 0;
pub(crate) const WOLFSSL_TLSV1_2: c_int = 3;
pub(crate) const INVALID_DEVID: c_int = -2;
pub(crate) const ED25519_KEY_SIZE: usize = 32;
pub(crate) const ED25519_PUB_KEY_SIZE: usize = 32;
pub(crate) const ED25519_SIG_SIZE: usize = 64;

unsafe extern "C" {
    // The headers' values, from `csrc/layout.c`.
    pub(crate) static curl_wolfssl_values: [i64; 33];

    pub(crate) fn wolfSSL_Init() -> c_int;
    pub(crate) fn wolfSSL_Cleanup() -> c_int;
    pub(crate) fn wolfSSL_lib_version() -> *const c_char;
    pub(crate) fn wolfSSL_get_cipher_list(priority: c_int) -> *mut c_char;
    pub(crate) fn wolfSSL_ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: c_ulong);
    pub(crate) fn wolfSSL_ERR_clear_error();

    pub(crate) fn wolfTLS_client_method() -> *mut WOLFSSL_METHOD;
    pub(crate) fn wolfSSL_CTX_new(method: *mut WOLFSSL_METHOD) -> *mut WOLFSSL_CTX;
    pub(crate) fn wolfSSL_CTX_free(ctx: *mut WOLFSSL_CTX);
    pub(crate) fn wolfSSL_CTX_set_min_proto_version(ctx: *mut WOLFSSL_CTX, version: c_int)
    -> c_int;
    pub(crate) fn wolfSSL_CTX_set_max_proto_version(ctx: *mut WOLFSSL_CTX, version: c_int)
    -> c_int;
    pub(crate) fn wolfSSL_CTX_set_cipher_list(ctx: *mut WOLFSSL_CTX, list: *const c_char) -> c_int;
    pub(crate) fn wolfSSL_CTX_set1_groups_list(ctx: *mut WOLFSSL_CTX, list: *const c_char)
    -> c_int;
    pub(crate) fn wolfSSL_CTX_use_certificate_chain_buffer(
        ctx: *mut WOLFSSL_CTX,
        buf: *const u8,
        len: c_long,
    ) -> c_int;
    pub(crate) fn wolfSSL_CTX_use_certificate_chain_file(
        ctx: *mut WOLFSSL_CTX,
        file: *const c_char,
    ) -> c_int;
    pub(crate) fn wolfSSL_CTX_use_certificate_buffer(
        ctx: *mut WOLFSSL_CTX,
        buf: *const u8,
        len: c_long,
        format: c_int,
    ) -> c_int;
    pub(crate) fn wolfSSL_CTX_use_certificate_file(
        ctx: *mut WOLFSSL_CTX,
        file: *const c_char,
        format: c_int,
    ) -> c_int;
    pub(crate) fn wolfSSL_CTX_use_PrivateKey_buffer(
        ctx: *mut WOLFSSL_CTX,
        buf: *const u8,
        len: c_long,
        format: c_int,
    ) -> c_int;
    pub(crate) fn wolfSSL_CTX_use_PrivateKey_file(
        ctx: *mut WOLFSSL_CTX,
        file: *const c_char,
        format: c_int,
    ) -> c_int;
    pub(crate) fn wolfSSL_CTX_set_verify(
        ctx: *mut WOLFSSL_CTX,
        mode: c_int,
        verify: Option<verify_cb>,
    );
    pub(crate) fn wolfSSL_CTX_UseSNI(
        ctx: *mut WOLFSSL_CTX,
        kind: u8,
        data: *const c_void,
        size: c_ushort,
    ) -> c_int;
    pub(crate) fn wolfSSL_CTX_sess_set_new_cb(ctx: *mut WOLFSSL_CTX, cb: Option<new_session_cb>);
    pub(crate) fn wolfSSL_CTX_load_system_CA_certs(ctx: *mut WOLFSSL_CTX) -> c_int;
    pub(crate) fn wolfSSL_CTX_load_verify_buffer(
        ctx: *mut WOLFSSL_CTX,
        buf: *const u8,
        len: c_long,
        format: c_int,
    ) -> c_int;
    pub(crate) fn wolfSSL_CTX_load_verify_locations_ex(
        ctx: *mut WOLFSSL_CTX,
        file: *const c_char,
        path: *const c_char,
        flags: u32,
    ) -> c_int;
    pub(crate) fn wolfSSL_CTX_get_cert_store(ctx: *const WOLFSSL_CTX) -> *mut WOLFSSL_X509_STORE;
    pub(crate) fn wolfSSL_CTX_set_cert_store(ctx: *mut WOLFSSL_CTX, store: *mut WOLFSSL_X509_STORE);
    pub(crate) fn wolfSSL_X509_STORE_new() -> *mut WOLFSSL_X509_STORE;
    pub(crate) fn wolfSSL_X509_STORE_up_ref(store: *mut WOLFSSL_X509_STORE) -> c_int;
    pub(crate) fn wolfSSL_X509_STORE_free(store: *mut WOLFSSL_X509_STORE);

    pub(crate) fn wolfSSL_new(ctx: *mut WOLFSSL_CTX) -> *mut WOLFSSL;
    pub(crate) fn wolfSSL_free(ssl: *mut WOLFSSL);
    pub(crate) fn wolfSSL_set_app_data(ssl: *mut WOLFSSL, arg: *mut c_void) -> c_int;
    pub(crate) fn wolfSSL_get_app_data(ssl: *const WOLFSSL) -> *mut c_void;
    pub(crate) fn wolfSSL_d2i_SSL_SESSION(
        session: *mut *mut WOLFSSL_SESSION,
        p: *mut *const u8,
        len: c_long,
    ) -> *mut WOLFSSL_SESSION;
    pub(crate) fn wolfSSL_i2d_SSL_SESSION(session: *mut WOLFSSL_SESSION, p: *mut *mut u8) -> c_int;
    pub(crate) fn wolfSSL_SESSION_free(session: *mut WOLFSSL_SESSION);
    pub(crate) fn wolfSSL_SESSION_get_timeout(session: *const WOLFSSL_SESSION) -> c_long;
    pub(crate) fn wolfSSL_SESSION_get_max_early_data(session: *const WOLFSSL_SESSION) -> c_uint;
    pub(crate) fn wolfSSL_set_session(ssl: *mut WOLFSSL, session: *mut WOLFSSL_SESSION) -> c_int;
    pub(crate) fn wolfSSL_get_session(ssl: *const WOLFSSL) -> *mut WOLFSSL_SESSION;
    pub(crate) fn wolfSSL_get_version(ssl: *const WOLFSSL) -> *const c_char;
    pub(crate) fn wolfSSL_version(ssl: *mut WOLFSSL) -> c_int;
    pub(crate) fn wolfSSL_GetVersion(ssl: *const WOLFSSL) -> c_int;
    pub(crate) fn wolfSSL_get_cipher_name(ssl: *mut WOLFSSL) -> *const c_char;
    pub(crate) fn wolfSSL_set_max_early_data(ssl: *mut WOLFSSL, most: c_uint) -> c_int;
    pub(crate) fn wolfSSL_UseALPN(
        ssl: *mut WOLFSSL,
        list: *mut c_char,
        len: c_uint,
        options: u8,
    ) -> c_int;
    pub(crate) fn wolfSSL_ALPN_GetProtocol(
        ssl: *mut WOLFSSL,
        name: *mut *mut c_char,
        size: *mut c_ushort,
    ) -> c_int;
    pub(crate) fn wolfSSL_KeepArrays(ssl: *mut WOLFSSL);
    pub(crate) fn wolfSSL_FreeArrays(ssl: *mut WOLFSSL);
    pub(crate) fn wolfSSL_get_keys(
        ssl: *mut WOLFSSL,
        ms: *mut *mut u8,
        ms_len: *mut c_uint,
        sr: *mut *mut u8,
        sr_len: *mut c_uint,
        cr: *mut *mut u8,
        cr_len: *mut c_uint,
    ) -> c_int;
    pub(crate) fn wolfSSL_check_domain_name(ssl: *mut WOLFSSL, name: *const c_char) -> c_int;
    pub(crate) fn wolfSSL_set_bio(ssl: *mut WOLFSSL, rd: *mut WOLFSSL_BIO, wr: *mut WOLFSSL_BIO);
    pub(crate) fn wolfSSL_connect(ssl: *mut WOLFSSL) -> c_int;
    pub(crate) fn wolfSSL_get_error(ssl: *mut WOLFSSL, ret: c_int) -> c_int;
    pub(crate) fn wolfSSL_want_read(ssl: *mut WOLFSSL) -> c_int;
    pub(crate) fn wolfSSL_want_write(ssl: *mut WOLFSSL) -> c_int;
    pub(crate) fn wolfSSL_write_early_data(
        ssl: *mut WOLFSSL,
        data: *const c_void,
        len: c_int,
        written: *mut c_int,
    ) -> c_int;
    pub(crate) fn wolfSSL_get_early_data_status(ssl: *const WOLFSSL) -> c_int;
    pub(crate) fn wolfSSL_read(ssl: *mut WOLFSSL, buf: *mut c_void, len: c_int) -> c_int;
    pub(crate) fn wolfSSL_write(ssl: *mut WOLFSSL, buf: *const c_void, len: c_int) -> c_int;
    pub(crate) fn wolfSSL_shutdown(ssl: *mut WOLFSSL) -> c_int;
    pub(crate) fn wolfSSL_get_shutdown(ssl: *const WOLFSSL) -> c_int;
    pub(crate) fn wolfSSL_pending(ssl: *mut WOLFSSL) -> c_int;
    pub(crate) fn wolfSSL_get_peer_certificate(ssl: *mut WOLFSSL) -> *mut WOLFSSL_X509;
    pub(crate) fn wolfSSL_X509_get_der(x509: *mut WOLFSSL_X509, len: *mut c_int) -> *const u8;
    pub(crate) fn wolfSSL_X509_free(x509: *mut WOLFSSL_X509);
    pub(crate) fn wolfSSL_X509_check_ip_asc(
        x509: *mut WOLFSSL_X509,
        ip: *const c_char,
        flags: c_uint,
    ) -> c_int;

    pub(crate) fn wolfSSL_BIO_meth_new(kind: c_int, name: *const c_char)
    -> *mut WOLFSSL_BIO_METHOD;
    pub(crate) fn wolfSSL_BIO_meth_free(method: *mut WOLFSSL_BIO_METHOD);
    pub(crate) fn wolfSSL_BIO_meth_set_write(
        method: *mut WOLFSSL_BIO_METHOD,
        cb: Option<bio_write_cb>,
    ) -> c_int;
    pub(crate) fn wolfSSL_BIO_meth_set_read(
        method: *mut WOLFSSL_BIO_METHOD,
        cb: Option<bio_read_cb>,
    ) -> c_int;
    pub(crate) fn wolfSSL_BIO_meth_set_ctrl(
        method: *mut WOLFSSL_BIO_METHOD,
        cb: Option<bio_ctrl_cb>,
    ) -> c_int;
    pub(crate) fn wolfSSL_BIO_meth_set_create(
        method: *mut WOLFSSL_BIO_METHOD,
        cb: Option<bio_create_cb>,
    ) -> c_int;
    pub(crate) fn wolfSSL_BIO_new(method: *mut WOLFSSL_BIO_METHOD) -> *mut WOLFSSL_BIO;
    pub(crate) fn wolfSSL_BIO_set_data(bio: *mut WOLFSSL_BIO, data: *mut c_void);
    pub(crate) fn wolfSSL_BIO_get_data(bio: *mut WOLFSSL_BIO) -> *mut c_void;
    pub(crate) fn wolfSSL_BIO_set_shutdown(bio: *mut WOLFSSL_BIO, shut: c_int);
    pub(crate) fn wolfSSL_BIO_get_shutdown(bio: *mut WOLFSSL_BIO) -> c_int;
    pub(crate) fn wolfSSL_BIO_clear_retry_flags(bio: *mut WOLFSSL_BIO);
    pub(crate) fn wolfSSL_BIO_set_flags(bio: *mut WOLFSSL_BIO, flags: c_int);

    pub(crate) fn wc_ed25519_new(heap: *mut c_void, dev: c_int, rc: *mut c_int)
    -> *mut ed25519_key;
    pub(crate) fn wc_ed25519_delete(key: *mut ed25519_key, key_p: *mut *mut ed25519_key) -> c_int;
    pub(crate) fn wc_ed25519_import_private_only(
        private: *const u8,
        len: u32,
        key: *mut ed25519_key,
    ) -> c_int;
    pub(crate) fn wc_ed25519_make_public(key: *mut ed25519_key, public: *mut u8, len: u32)
    -> c_int;
    pub(crate) fn wc_ed25519_import_private_key(
        private: *const u8,
        private_len: u32,
        public: *const u8,
        public_len: u32,
        key: *mut ed25519_key,
    ) -> c_int;
    pub(crate) fn wc_ed25519_sign_msg(
        msg: *const u8,
        msg_len: u32,
        sig: *mut u8,
        sig_len: *mut u32,
        key: *mut ed25519_key,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values this file declares are the headers', in
    /// `csrc/layout.c`'s order: one out of step asks the library for
    /// something else.
    #[test]
    // Reads a table C defines, which Miri cannot.
    #[cfg_attr(miri, ignore)]
    fn the_declared_values_are_the_headers() {
        let ours: [i64; 33] = [
            WOLFSSL_SUCCESS as i64,
            WOLFSSL_ERROR_NONE as i64,
            WOLFSSL_ERROR_WANT_READ as i64,
            WOLFSSL_ERROR_WANT_WRITE as i64,
            WOLFSSL_ERROR_ZERO_RETURN as i64,
            WOLFSSL_ALPN_NOT_FOUND as i64,
            DOMAIN_NAME_MISMATCH as i64,
            ASN_NO_SIGNER_E as i64,
            ASN_AFTER_DATE_E as i64,
            ASN_BEFORE_DATE_E as i64,
            WOLFSSL_FILETYPE_PEM as i64,
            WOLFSSL_FILETYPE_ASN1 as i64,
            WOLFSSL_VERIFY_NONE as i64,
            WOLFSSL_VERIFY_PEER as i64,
            WOLFSSL_SNI_HOST_NAME as i64,
            WOLFSSL_ALPN_CONTINUE_ON_MISMATCH as i64,
            WOLFSSL_LOAD_FLAG_IGNORE_ERR as i64,
            WOLFSSL_SENT_SHUTDOWN as i64,
            WOLFSSL_EARLY_DATA_REJECTED as i64,
            WOLFSSL_BIO_MEMORY as i64,
            WOLFSSL_BIO_FLAG_READ as i64,
            WOLFSSL_BIO_FLAG_WRITE as i64,
            WOLFSSL_BIO_FLAG_RETRY as i64,
            WOLFSSL_BIO_CTRL_EOF as i64,
            WOLFSSL_BIO_CTRL_GET_CLOSE as i64,
            WOLFSSL_BIO_CTRL_SET_CLOSE as i64,
            WOLFSSL_BIO_CTRL_FLUSH as i64,
            WOLFSSL_BIO_CTRL_DUP as i64,
            WOLFSSL_SSLV3 as i64,
            WOLFSSL_TLSV1_2 as i64,
            INVALID_DEVID as i64,
            ED25519_KEY_SIZE as i64,
            ED25519_SIG_SIZE as i64,
        ];
        // SAFETY: a table of 33 numbers C defines, read only.
        let theirs = unsafe { &curl_wolfssl_values };
        for (i, (o, t)) in ours.iter().zip(theirs.iter()).enumerate() {
            assert_eq!(o, t, "entry {i} of csrc/layout.c");
        }
    }
}
