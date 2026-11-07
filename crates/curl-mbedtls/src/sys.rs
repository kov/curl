//! The parts of mbedTLS's `ssl.h`, `x509_crt.h`, `x509_crl.h`, `pk.h`,
//! `entropy.h`, `ctr_drbg.h`, `error.h`, `version.h` and PSA's `crypto.h`
//! the crate calls, declared as mbedTLS 3.2 to 3.6 have them.
//!
//! The library's objects are the caller's to allocate, at the size its
//! build's configuration gives them, and some of their fields are reached
//! only through the headers' inline functions: `csrc/layout.c` gives
//! those sizes and offsets as the headers have them (`Layout`), which the
//! binding reads as it runs, and the constants declared here, which the
//! tests compare with the headers'.

#![allow(unsafe_code, non_camel_case_types, dead_code)]

use core::ffi::{c_char, c_int, c_uint, c_void};

/// An object of the library's, of a size only its build knows: the
/// binding allocates `Layout`'s bytes for it and hands the library a
/// pointer of this type.
#[repr(C)]
pub(crate) struct Opaque {
    _private: [u8; 0],
}

pub(crate) type mbedtls_ssl_context = Opaque;
pub(crate) type mbedtls_ssl_config = Opaque;
pub(crate) type mbedtls_ssl_session = Opaque;
pub(crate) type mbedtls_x509_crt = Opaque;
pub(crate) type mbedtls_x509_crl = Opaque;
pub(crate) type mbedtls_x509_crt_profile = Opaque;
pub(crate) type mbedtls_pk_context = Opaque;
pub(crate) type mbedtls_entropy_context = Opaque;
pub(crate) type mbedtls_ctr_drbg_context = Opaque;

pub(crate) type mbedtls_ssl_send_t =
    unsafe extern "C" fn(ctx: *mut c_void, buf: *const u8, len: usize) -> c_int;
pub(crate) type mbedtls_ssl_recv_t =
    unsafe extern "C" fn(ctx: *mut c_void, buf: *mut u8, len: usize) -> c_int;
pub(crate) type mbedtls_ssl_recv_timeout_t =
    unsafe extern "C" fn(ctx: *mut c_void, buf: *mut u8, len: usize, timeout: u32) -> c_int;
pub(crate) type f_vrfy_t = unsafe extern "C" fn(
    p: *mut c_void,
    crt: *mut mbedtls_x509_crt,
    depth: c_int,
    flags: *mut u32,
) -> c_int;
pub(crate) type f_rng_t = unsafe extern "C" fn(p: *mut c_void, out: *mut u8, len: usize) -> c_int;
pub(crate) type f_entropy_t =
    unsafe extern "C" fn(p: *mut c_void, out: *mut u8, len: usize) -> c_int;

pub(crate) const MBEDTLS_ERR_SSL_WANT_READ: c_int = -0x6900;
pub(crate) const MBEDTLS_ERR_SSL_WANT_WRITE: c_int = -0x6880;
pub(crate) const MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET: c_int = -0x7B00;
pub(crate) const MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY: c_int = -0x7880;
pub(crate) const MBEDTLS_ERR_SSL_ALLOC_FAILED: c_int = -0x7F00;
pub(crate) const MBEDTLS_ERR_X509_CERT_VERIFY_FAILED: c_int = -0x2700;
pub(crate) const MBEDTLS_ERR_PK_TYPE_MISMATCH: c_int = -0x3F00;
pub(crate) const MBEDTLS_SSL_IS_CLIENT: c_int = 0;
pub(crate) const MBEDTLS_SSL_TRANSPORT_STREAM: c_int = 0;
pub(crate) const MBEDTLS_SSL_PRESET_DEFAULT: c_int = 0;
pub(crate) const MBEDTLS_SSL_VERIFY_REQUIRED: c_int = 2;
pub(crate) const MBEDTLS_SSL_RENEGOTIATION_ENABLED: c_int = 1;
pub(crate) const MBEDTLS_SSL_SESSION_TICKETS_DISABLED: c_int = 0;
pub(crate) const MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED: c_int = 1;
pub(crate) const MBEDTLS_SSL_VERSION_TLS1_2: c_int = 0x0303;
pub(crate) const MBEDTLS_SSL_VERSION_TLS1_3: c_int = 0x0304;
pub(crate) const MBEDTLS_X509_BADCERT_CN_MISMATCH: u32 = 0x04;
pub(crate) const MBEDTLS_PK_RSA: c_int = 1;
pub(crate) const MBEDTLS_PK_ECKEY: c_int = 2;
pub(crate) const MBEDTLS_CTR_DRBG_PR_ON: c_int = 1;
pub(crate) const PSA_SUCCESS: i32 = 0;
pub(crate) const MBEDTLS_MPI_MAX_SIZE: usize = 1024;
pub(crate) const MBEDTLS_ECP_MAX_BYTES: usize = 66;

/// The most bytes of DER a public key writes to (`PUB_DER_MAX_BYTES`):
/// an RSA key's or an EC key's, whichever is larger.
pub(crate) const PUB_DER_MAX_BYTES: usize = {
    let rsa = 38 + 2 * MBEDTLS_MPI_MAX_SIZE;
    let ecp = 30 + 2 * MBEDTLS_ECP_MAX_BYTES;
    if rsa > ecp { rsa } else { ecp }
};

unsafe extern "C" {
    pub(crate) fn psa_crypto_init() -> i32;
    pub(crate) fn mbedtls_psa_crypto_free();
    pub(crate) fn mbedtls_version_get_number() -> c_uint;
    pub(crate) fn mbedtls_strerror(errnum: c_int, buffer: *mut c_char, buflen: usize);

    pub(crate) fn mbedtls_entropy_init(ctx: *mut mbedtls_entropy_context);
    pub(crate) fn mbedtls_entropy_free(ctx: *mut mbedtls_entropy_context);
    pub(crate) fn mbedtls_entropy_func(data: *mut c_void, output: *mut u8, len: usize) -> c_int;
    pub(crate) fn mbedtls_ctr_drbg_init(ctx: *mut mbedtls_ctr_drbg_context);
    pub(crate) fn mbedtls_ctr_drbg_free(ctx: *mut mbedtls_ctr_drbg_context);
    pub(crate) fn mbedtls_ctr_drbg_seed(
        ctx: *mut mbedtls_ctr_drbg_context,
        f_entropy: f_entropy_t,
        p_entropy: *mut c_void,
        custom: *const u8,
        len: usize,
    ) -> c_int;
    pub(crate) fn mbedtls_ctr_drbg_set_prediction_resistance(
        ctx: *mut mbedtls_ctr_drbg_context,
        resistance: c_int,
    );
    pub(crate) fn mbedtls_ctr_drbg_random(p_rng: *mut c_void, output: *mut u8, len: usize)
    -> c_int;

    pub(crate) fn mbedtls_x509_crt_init(crt: *mut mbedtls_x509_crt);
    pub(crate) fn mbedtls_x509_crt_free(crt: *mut mbedtls_x509_crt);
    pub(crate) fn mbedtls_x509_crt_parse(
        chain: *mut mbedtls_x509_crt,
        buf: *const u8,
        buflen: usize,
    ) -> c_int;
    pub(crate) fn mbedtls_x509_crt_parse_der(
        chain: *mut mbedtls_x509_crt,
        buf: *const u8,
        buflen: usize,
    ) -> c_int;
    pub(crate) fn mbedtls_x509_crt_parse_file(
        chain: *mut mbedtls_x509_crt,
        path: *const c_char,
    ) -> c_int;
    pub(crate) fn mbedtls_x509_crt_parse_path(
        chain: *mut mbedtls_x509_crt,
        path: *const c_char,
    ) -> c_int;
    pub(crate) fn mbedtls_x509_crt_info(
        buf: *mut c_char,
        size: usize,
        prefix: *const c_char,
        crt: *const mbedtls_x509_crt,
    ) -> c_int;
    pub(crate) fn mbedtls_x509_crt_verify_info(
        buf: *mut c_char,
        size: usize,
        prefix: *const c_char,
        flags: u32,
    ) -> c_int;
    pub(crate) static mbedtls_x509_crt_profile_next: mbedtls_x509_crt_profile;

    pub(crate) fn mbedtls_x509_crl_init(crl: *mut mbedtls_x509_crl);
    pub(crate) fn mbedtls_x509_crl_free(crl: *mut mbedtls_x509_crl);
    pub(crate) fn mbedtls_x509_crl_parse_file(
        chain: *mut mbedtls_x509_crl,
        path: *const c_char,
    ) -> c_int;

    pub(crate) fn mbedtls_pk_init(ctx: *mut mbedtls_pk_context);
    pub(crate) fn mbedtls_pk_free(ctx: *mut mbedtls_pk_context);
    pub(crate) fn mbedtls_pk_parse_keyfile(
        ctx: *mut mbedtls_pk_context,
        path: *const c_char,
        password: *const c_char,
        f_rng: f_rng_t,
        p_rng: *mut c_void,
    ) -> c_int;
    pub(crate) fn mbedtls_pk_parse_key(
        ctx: *mut mbedtls_pk_context,
        key: *const u8,
        keylen: usize,
        pwd: *const u8,
        pwdlen: usize,
        f_rng: f_rng_t,
        p_rng: *mut c_void,
    ) -> c_int;
    pub(crate) fn mbedtls_pk_can_do(ctx: *const mbedtls_pk_context, kind: c_int) -> c_int;
    pub(crate) fn mbedtls_pk_write_pubkey_der(
        ctx: *const mbedtls_pk_context,
        buf: *mut u8,
        size: usize,
    ) -> c_int;

    pub(crate) fn mbedtls_ssl_config_init(conf: *mut mbedtls_ssl_config);
    pub(crate) fn mbedtls_ssl_config_free(conf: *mut mbedtls_ssl_config);
    pub(crate) fn mbedtls_ssl_config_defaults(
        conf: *mut mbedtls_ssl_config,
        endpoint: c_int,
        transport: c_int,
        preset: c_int,
    ) -> c_int;
    pub(crate) fn mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(
        conf: *mut mbedtls_ssl_config,
        signal: c_int,
    );
    pub(crate) fn mbedtls_ssl_conf_verify(
        conf: *mut mbedtls_ssl_config,
        f_vrfy: f_vrfy_t,
        p_vrfy: *mut c_void,
    );
    pub(crate) fn mbedtls_ssl_conf_authmode(conf: *mut mbedtls_ssl_config, authmode: c_int);
    pub(crate) fn mbedtls_ssl_conf_cert_profile(
        conf: *mut mbedtls_ssl_config,
        profile: *const mbedtls_x509_crt_profile,
    );
    pub(crate) fn mbedtls_ssl_conf_rng(
        conf: *mut mbedtls_ssl_config,
        f_rng: f_rng_t,
        p_rng: *mut c_void,
    );
    pub(crate) fn mbedtls_ssl_list_ciphersuites() -> *const c_int;
    pub(crate) fn mbedtls_ssl_get_ciphersuite_name(id: c_int) -> *const c_char;
    pub(crate) fn mbedtls_ssl_conf_ciphersuites(
        conf: *mut mbedtls_ssl_config,
        ciphersuites: *const c_int,
    );
    pub(crate) fn mbedtls_ssl_conf_renegotiation(
        conf: *mut mbedtls_ssl_config,
        renegotiation: c_int,
    );
    pub(crate) fn mbedtls_ssl_conf_session_tickets(
        conf: *mut mbedtls_ssl_config,
        use_tickets: c_int,
    );
    pub(crate) fn mbedtls_ssl_conf_ca_chain(
        conf: *mut mbedtls_ssl_config,
        ca_chain: *mut mbedtls_x509_crt,
        ca_crl: *mut mbedtls_x509_crl,
    );
    pub(crate) fn mbedtls_ssl_conf_own_cert(
        conf: *mut mbedtls_ssl_config,
        own_cert: *mut mbedtls_x509_crt,
        pk_key: *mut mbedtls_pk_context,
    ) -> c_int;
    pub(crate) fn mbedtls_ssl_conf_alpn_protocols(
        conf: *mut mbedtls_ssl_config,
        protos: *mut *const c_char,
    ) -> c_int;

    pub(crate) fn mbedtls_ssl_init(ssl: *mut mbedtls_ssl_context);
    pub(crate) fn mbedtls_ssl_free(ssl: *mut mbedtls_ssl_context);
    pub(crate) fn mbedtls_ssl_setup(
        ssl: *mut mbedtls_ssl_context,
        conf: *const mbedtls_ssl_config,
    ) -> c_int;
    pub(crate) fn mbedtls_ssl_set_bio(
        ssl: *mut mbedtls_ssl_context,
        p_bio: *mut c_void,
        f_send: Option<mbedtls_ssl_send_t>,
        f_recv: Option<mbedtls_ssl_recv_t>,
        f_recv_timeout: Option<mbedtls_ssl_recv_timeout_t>,
    );
    pub(crate) fn mbedtls_ssl_set_hostname(
        ssl: *mut mbedtls_ssl_context,
        hostname: *const c_char,
    ) -> c_int;
    pub(crate) fn mbedtls_ssl_handshake(ssl: *mut mbedtls_ssl_context) -> c_int;
    pub(crate) fn mbedtls_ssl_read(
        ssl: *mut mbedtls_ssl_context,
        buf: *mut u8,
        len: usize,
    ) -> c_int;
    pub(crate) fn mbedtls_ssl_write(
        ssl: *mut mbedtls_ssl_context,
        buf: *const u8,
        len: usize,
    ) -> c_int;
    pub(crate) fn mbedtls_ssl_close_notify(ssl: *mut mbedtls_ssl_context) -> c_int;
    pub(crate) fn mbedtls_ssl_get_bytes_avail(ssl: *const mbedtls_ssl_context) -> usize;
    pub(crate) fn mbedtls_ssl_get_ciphersuite_id_from_ssl(ssl: *const mbedtls_ssl_context)
    -> c_int;
    pub(crate) fn mbedtls_ssl_get_version(ssl: *const mbedtls_ssl_context) -> *const c_char;
    pub(crate) fn mbedtls_ssl_get_peer_cert(
        ssl: *const mbedtls_ssl_context,
    ) -> *const mbedtls_x509_crt;
    pub(crate) fn mbedtls_ssl_get_alpn_protocol(ssl: *const mbedtls_ssl_context) -> *const c_char;

    pub(crate) fn mbedtls_ssl_session_init(session: *mut mbedtls_ssl_session);
    pub(crate) fn mbedtls_ssl_session_free(session: *mut mbedtls_ssl_session);
    pub(crate) fn mbedtls_ssl_session_load(
        session: *mut mbedtls_ssl_session,
        buf: *const u8,
        len: usize,
    ) -> c_int;
    pub(crate) fn mbedtls_ssl_session_save(
        session: *const mbedtls_ssl_session,
        buf: *mut u8,
        buf_len: usize,
        olen: *mut usize,
    ) -> c_int;
    pub(crate) fn mbedtls_ssl_set_session(
        ssl: *mut mbedtls_ssl_context,
        session: *const mbedtls_ssl_session,
    ) -> c_int;
    pub(crate) fn mbedtls_ssl_get_session(
        ssl: *const mbedtls_ssl_context,
        session: *mut mbedtls_ssl_session,
    ) -> c_int;
}

// The headers' values and layouts, from `csrc/layout.c`.
unsafe extern "C" {
    pub(crate) static curl_mbedtls_values: [i64; VALUES_LEN];
    static curl_mbedtls_layout: [i64; LAYOUT_LEN];
}

/// How many values `csrc/layout.c` gives.
pub(crate) const VALUES_LEN: usize = 23;
/// How many sizes and offsets it gives.
const LAYOUT_LEN: usize = 23;

/// An object the library is handed room for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Object {
    SslContext,
    SslConfig,
    X509Crt,
    X509Crl,
    PkContext,
    SslSession,
    Entropy,
    CtrDrbg,
}

/// The fields the binding reaches itself, at their offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Field {
    /// `mbedtls_x509_crt`'s `raw.len`, `raw.p`, `next` and `pk`.
    CrtRawLen,
    CrtRawP,
    CrtNext,
    CrtPk,
    /// `mbedtls_ssl_config`'s version range, which the inline
    /// `mbedtls_ssl_conf_min_tls_version` and `..._max_...` set.
    ConfMinVersion,
    ConfMaxVersion,
    /// `mbedtls_ssl_context`'s version agreed, which the inline
    /// `mbedtls_ssl_get_version_number` reads.
    SslVersion,
}

/// The sizes and offsets of this build of the library, as its headers
/// have them.
pub(crate) struct Layout;

impl Layout {
    fn at(i: usize) -> usize {
        // SAFETY: a table of `LAYOUT_LEN` numbers C defines, read only.
        let table = unsafe { &curl_mbedtls_layout };
        usize::try_from(table[i]).expect("sizes and offsets are not negative")
    }

    /// The size and alignment of `o`.
    pub(crate) fn size(o: Object) -> (usize, usize) {
        let i = 2 * o as usize;
        (Layout::at(i), Layout::at(i + 1))
    }

    /// The offset of `f` in its object.
    pub(crate) fn offset(f: Field) -> usize {
        Layout::at(16 + f as usize)
    }
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
        let n = |v: usize| i64::try_from(v).expect("small");
        let ours: [i64; VALUES_LEN] = [
            MBEDTLS_ERR_SSL_WANT_READ.into(),
            MBEDTLS_ERR_SSL_WANT_WRITE.into(),
            MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET.into(),
            MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY.into(),
            MBEDTLS_ERR_SSL_ALLOC_FAILED.into(),
            MBEDTLS_ERR_X509_CERT_VERIFY_FAILED.into(),
            MBEDTLS_ERR_PK_TYPE_MISMATCH.into(),
            MBEDTLS_SSL_IS_CLIENT.into(),
            MBEDTLS_SSL_TRANSPORT_STREAM.into(),
            MBEDTLS_SSL_PRESET_DEFAULT.into(),
            MBEDTLS_SSL_VERIFY_REQUIRED.into(),
            MBEDTLS_SSL_RENEGOTIATION_ENABLED.into(),
            MBEDTLS_SSL_SESSION_TICKETS_DISABLED.into(),
            MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED.into(),
            MBEDTLS_SSL_VERSION_TLS1_2.into(),
            MBEDTLS_SSL_VERSION_TLS1_3.into(),
            MBEDTLS_X509_BADCERT_CN_MISMATCH.into(),
            MBEDTLS_PK_RSA.into(),
            MBEDTLS_PK_ECKEY.into(),
            MBEDTLS_CTR_DRBG_PR_ON.into(),
            PSA_SUCCESS.into(),
            n(MBEDTLS_MPI_MAX_SIZE),
            n(MBEDTLS_ECP_MAX_BYTES),
        ];
        // SAFETY: a table of `VALUES_LEN` numbers C defines, read only.
        let theirs = unsafe { &curl_mbedtls_values };
        for (i, (o, t)) in ours.iter().zip(theirs.iter()).enumerate() {
            assert_eq!(o, t, "entry {i} of csrc/layout.c");
        }
    }

    /// Every object has a size and an alignment the binding's room has;
    /// every field lies inside its object.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn the_layout_is_one_the_binding_can_hold() {
        for o in [
            Object::SslContext,
            Object::SslConfig,
            Object::X509Crt,
            Object::X509Crl,
            Object::PkContext,
            Object::SslSession,
            Object::Entropy,
            Object::CtrDrbg,
        ] {
            let (size, align) = Layout::size(o);
            assert!(
                size > 0 && align > 0 && align <= 16,
                "{o:?}: {size}, {align}"
            );
        }
        let crt = Layout::size(Object::X509Crt).0;
        for f in [
            Field::CrtRawLen,
            Field::CrtRawP,
            Field::CrtNext,
            Field::CrtPk,
        ] {
            assert!(Layout::offset(f) < crt, "{f:?}");
        }
        let conf = Layout::size(Object::SslConfig).0;
        assert!(Layout::offset(Field::ConfMinVersion) + 4 <= conf);
        assert!(Layout::offset(Field::ConfMaxVersion) + 4 <= conf);
        assert!(Layout::offset(Field::SslVersion) + 4 <= Layout::size(Object::SslContext).0);
    }
}
