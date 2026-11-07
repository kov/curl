//! The parts of GnuTLS's `gnutls.h`, `x509.h`, `abstract.h` and `ocsp.h`,
//! and of nettle's `eddsa.h`, the crate calls, declared as GnuTLS 3.6.5
//! and later have them. `csrc/layout.c` gives the headers' own values,
//! which the tests below compare with these.

#![allow(unsafe_code, non_camel_case_types, dead_code)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

#[repr(C)]
pub(crate) struct gnutls_session_int {
    _private: [u8; 0],
}
pub(crate) type gnutls_session_t = *mut gnutls_session_int;

#[repr(C)]
pub(crate) struct gnutls_certificate_credentials_st {
    _private: [u8; 0],
}
pub(crate) type gnutls_certificate_credentials_t = *mut gnutls_certificate_credentials_st;

#[repr(C)]
pub(crate) struct gnutls_x509_crt_int {
    _private: [u8; 0],
}
pub(crate) type gnutls_x509_crt_t = *mut gnutls_x509_crt_int;

#[repr(C)]
pub(crate) struct gnutls_pubkey_st {
    _private: [u8; 0],
}
pub(crate) type gnutls_pubkey_t = *mut gnutls_pubkey_st;

#[repr(C)]
pub(crate) struct gnutls_ocsp_resp_int {
    _private: [u8; 0],
}
pub(crate) type gnutls_ocsp_resp_t = *mut gnutls_ocsp_resp_int;

/// `gnutls_datum_t`: bytes and their count, as the library passes them.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct gnutls_datum_t {
    pub(crate) data: *mut u8,
    pub(crate) size: c_uint,
}

/// `time_t`, a `long` on the systems the crate builds for.
pub(crate) type time_t = c_long;

pub(crate) type gnutls_push_func =
    unsafe extern "C" fn(ptr: *mut c_void, buf: *const c_void, len: usize) -> isize;
pub(crate) type gnutls_pull_func =
    unsafe extern "C" fn(ptr: *mut c_void, buf: *mut c_void, len: usize) -> isize;
pub(crate) type gnutls_handshake_hook_func = unsafe extern "C" fn(
    session: gnutls_session_t,
    htype: c_uint,
    when: c_uint,
    incoming: c_uint,
    msg: *const gnutls_datum_t,
) -> c_int;
pub(crate) type gnutls_keylog_func = unsafe extern "C" fn(
    session: gnutls_session_t,
    label: *const c_char,
    secret: *const gnutls_datum_t,
) -> c_int;

pub(crate) const GNUTLS_E_SUCCESS: c_int = 0;
pub(crate) const GNUTLS_E_FATAL_ALERT_RECEIVED: c_int = -12;
pub(crate) const GNUTLS_E_WARNING_ALERT_RECEIVED: c_int = -16;
pub(crate) const GNUTLS_E_AGAIN: c_int = -28;
pub(crate) const GNUTLS_E_REHANDSHAKE: c_int = -37;
pub(crate) const GNUTLS_E_NO_CERTIFICATE_FOUND: c_int = -49;
pub(crate) const GNUTLS_E_SHORT_MEMORY_BUFFER: c_int = -51;
pub(crate) const GNUTLS_E_INTERRUPTED: c_int = -52;
pub(crate) const GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE: c_int = -56;

pub(crate) const GNUTLS_CLIENT: c_uint = 1 << 1;
pub(crate) const GNUTLS_FORCE_CLIENT_CERT: c_uint = 1 << 9;
pub(crate) const GNUTLS_ENABLE_EARLY_DATA: c_uint = 1 << 20;
pub(crate) const GNUTLS_NO_END_OF_EARLY_DATA: c_uint = 1 << 22;

pub(crate) const GNUTLS_CRD_CERTIFICATE: c_int = 1;
pub(crate) const GNUTLS_NAME_DNS: c_int = 1;
pub(crate) const GNUTLS_SHUT_RDWR: c_int = 0;
pub(crate) const GNUTLS_X509_FMT_DER: c_int = 0;
pub(crate) const GNUTLS_X509_FMT_PEM: c_int = 1;
pub(crate) const GNUTLS_ALPN_MANDATORY: c_uint = 1;
pub(crate) const GNUTLS_HANDSHAKE_ANY: c_uint = c_uint::MAX;
pub(crate) const GNUTLS_HANDSHAKE_NEW_SESSION_TICKET: c_uint = 4;
pub(crate) const GNUTLS_HOOK_POST: c_int = 1;
pub(crate) const GNUTLS_SFLAGS_EARLY_DATA: c_uint = 1 << 10;
pub(crate) const GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT: c_uint = 0;

pub(crate) const GNUTLS_CERT_INVALID: c_uint = 1 << 1;
pub(crate) const GNUTLS_CERT_SIGNER_NOT_FOUND: c_uint = 1 << 6;
pub(crate) const GNUTLS_CERT_INSECURE_ALGORITHM: c_uint = 1 << 8;
pub(crate) const GNUTLS_CERT_NOT_ACTIVATED: c_uint = 1 << 9;
pub(crate) const GNUTLS_CERT_EXPIRED: c_uint = 1 << 10;
pub(crate) const GNUTLS_CERT_INVALID_OCSP_STATUS: c_uint = 1 << 20;

pub(crate) const GNUTLS_SSL3: c_int = 1;
pub(crate) const GNUTLS_TLS1_0: c_int = 2;
pub(crate) const GNUTLS_TLS1_1: c_int = 3;
pub(crate) const GNUTLS_TLS1_2: c_int = 4;
pub(crate) const GNUTLS_TLS1_3: c_int = 5;

pub(crate) const GNUTLS_PKCS_PKCS12_3DES: c_uint = 1 << 1;
pub(crate) const GNUTLS_PKCS_PKCS12_ARCFOUR: c_uint = 1 << 2;
pub(crate) const GNUTLS_PKCS_PKCS12_RC2_40: c_uint = 1 << 3;
pub(crate) const GNUTLS_PKCS_PBES2_3DES: c_uint = 1 << 4;
pub(crate) const GNUTLS_PKCS_PBES2_AES_128: c_uint = 1 << 5;
pub(crate) const GNUTLS_PKCS_PBES2_AES_192: c_uint = 1 << 6;
pub(crate) const GNUTLS_PKCS_PBES2_AES_256: c_uint = 1 << 7;

pub(crate) const GNUTLS_OCSP_RESP_SUCCESSFUL: c_int = 0;
pub(crate) const GNUTLS_OCSP_CERT_GOOD: c_int = 0;
pub(crate) const GNUTLS_OCSP_CERT_REVOKED: c_int = 1;

/// `ED25519_KEY_SIZE` and `ED25519_SIGNATURE_SIZE`, nettle's.
pub(crate) const ED25519_KEY_SIZE: usize = 32;
pub(crate) const ED25519_SIGNATURE_SIZE: usize = 64;

/// `GNUTLS_OID_X520_COMMON_NAME`.
pub(crate) const GNUTLS_OID_X520_COMMON_NAME: &core::ffi::CStr = c"2.5.4.3";

unsafe extern "C" {
    pub(crate) fn gnutls_global_init() -> c_int;
    pub(crate) fn gnutls_global_deinit();
    pub(crate) fn gnutls_check_version(req_version: *const c_char) -> *const c_char;
    pub(crate) fn gnutls_strerror(error: c_int) -> *const c_char;
    pub(crate) fn gnutls_error_is_fatal(error: c_int) -> c_int;
    pub(crate) fn gnutls_alert_get(session: gnutls_session_t) -> c_int;
    pub(crate) fn gnutls_alert_get_name(alert: c_int) -> *const c_char;

    /// A variable holding the library's `free`, not a function.
    pub(crate) static gnutls_free: Option<unsafe extern "C" fn(*mut c_void)>;

    pub(crate) fn gnutls_certificate_allocate_credentials(
        res: *mut gnutls_certificate_credentials_t,
    ) -> c_int;
    pub(crate) fn gnutls_certificate_free_credentials(sc: gnutls_certificate_credentials_t);
    pub(crate) fn gnutls_certificate_set_x509_system_trust(
        cred: gnutls_certificate_credentials_t,
    ) -> c_int;
    pub(crate) fn gnutls_certificate_set_x509_trust_mem(
        res: gnutls_certificate_credentials_t,
        ca: *const gnutls_datum_t,
        format: c_int,
    ) -> c_int;
    pub(crate) fn gnutls_certificate_set_verify_flags(
        res: gnutls_certificate_credentials_t,
        flags: c_uint,
    );
    pub(crate) fn gnutls_certificate_set_x509_trust_file(
        cred: gnutls_certificate_credentials_t,
        cafile: *const c_char,
        format: c_int,
    ) -> c_int;
    pub(crate) fn gnutls_certificate_set_x509_trust_dir(
        cred: gnutls_certificate_credentials_t,
        ca_dir: *const c_char,
        format: c_int,
    ) -> c_int;
    pub(crate) fn gnutls_certificate_set_x509_crl_file(
        res: gnutls_certificate_credentials_t,
        crlfile: *const c_char,
        format: c_int,
    ) -> c_int;
    pub(crate) fn gnutls_certificate_set_x509_simple_pkcs12_file(
        res: gnutls_certificate_credentials_t,
        pkcs12file: *const c_char,
        format: c_int,
        password: *const c_char,
    ) -> c_int;
    pub(crate) fn gnutls_certificate_set_x509_key_file2(
        res: gnutls_certificate_credentials_t,
        certfile: *const c_char,
        keyfile: *const c_char,
        format: c_int,
        pass: *const c_char,
        flags: c_uint,
    ) -> c_int;

    pub(crate) fn gnutls_init(session: *mut gnutls_session_t, flags: c_uint) -> c_int;
    pub(crate) fn gnutls_deinit(session: gnutls_session_t);
    pub(crate) fn gnutls_server_name_set(
        session: gnutls_session_t,
        kind: c_int,
        name: *const c_void,
        name_length: usize,
    ) -> c_int;
    pub(crate) fn gnutls_set_default_priority(session: gnutls_session_t) -> c_int;
    pub(crate) fn gnutls_priority_set_direct(
        session: gnutls_session_t,
        priorities: *const c_char,
        err_pos: *mut *const c_char,
    ) -> c_int;
    pub(crate) fn gnutls_credentials_set(
        session: gnutls_session_t,
        kind: c_int,
        cred: *mut c_void,
    ) -> c_int;
    pub(crate) fn gnutls_ocsp_status_request_enable_client(
        session: gnutls_session_t,
        responder_id: *mut gnutls_datum_t,
        responder_id_size: usize,
        request_extensions: *mut gnutls_datum_t,
    ) -> c_int;
    pub(crate) fn gnutls_session_set_data(
        session: gnutls_session_t,
        session_data: *const c_void,
        session_data_size: usize,
    ) -> c_int;
    pub(crate) fn gnutls_session_get_data(
        session: gnutls_session_t,
        session_data: *mut c_void,
        session_data_size: *mut usize,
    ) -> c_int;
    pub(crate) fn gnutls_record_get_max_early_data_size(session: gnutls_session_t) -> usize;
    pub(crate) fn gnutls_session_set_ptr(session: gnutls_session_t, ptr: *mut c_void);
    pub(crate) fn gnutls_session_get_ptr(session: gnutls_session_t) -> *mut c_void;
    pub(crate) fn gnutls_session_set_keylog_function(
        session: gnutls_session_t,
        func: Option<gnutls_keylog_func>,
    );
    pub(crate) fn gnutls_session_get_random(
        session: gnutls_session_t,
        client: *mut gnutls_datum_t,
        server: *mut gnutls_datum_t,
    );
    pub(crate) fn gnutls_alpn_set_protocols(
        session: gnutls_session_t,
        protocols: *const gnutls_datum_t,
        protocols_size: c_uint,
        flags: c_uint,
    ) -> c_int;
    pub(crate) fn gnutls_alpn_get_selected_protocol(
        session: gnutls_session_t,
        protocol: *mut gnutls_datum_t,
    ) -> c_int;
    pub(crate) fn gnutls_handshake_set_hook_function(
        session: gnutls_session_t,
        htype: c_uint,
        when: c_int,
        func: Option<gnutls_handshake_hook_func>,
    );
    pub(crate) fn gnutls_transport_set_ptr(session: gnutls_session_t, ptr: *mut c_void);
    pub(crate) fn gnutls_transport_set_push_function(
        session: gnutls_session_t,
        push_func: Option<gnutls_push_func>,
    );
    pub(crate) fn gnutls_transport_set_pull_function(
        session: gnutls_session_t,
        pull_func: Option<gnutls_pull_func>,
    );
    pub(crate) fn gnutls_transport_set_errno(session: gnutls_session_t, err: c_int);
    pub(crate) fn gnutls_handshake(session: gnutls_session_t) -> c_int;
    pub(crate) fn gnutls_record_get_direction(session: gnutls_session_t) -> c_int;
    pub(crate) fn gnutls_record_send(
        session: gnutls_session_t,
        data: *const c_void,
        data_size: usize,
    ) -> isize;
    pub(crate) fn gnutls_record_recv(
        session: gnutls_session_t,
        data: *mut c_void,
        data_size: usize,
    ) -> isize;
    pub(crate) fn gnutls_record_send_early_data(
        session: gnutls_session_t,
        data: *const c_void,
        length: usize,
    ) -> isize;
    pub(crate) fn gnutls_record_check_pending(session: gnutls_session_t) -> usize;
    pub(crate) fn gnutls_bye(session: gnutls_session_t, how: c_int) -> c_int;
    pub(crate) fn gnutls_protocol_get_version(session: gnutls_session_t) -> c_int;
    pub(crate) fn gnutls_protocol_get_name(version: c_int) -> *const c_char;
    pub(crate) fn gnutls_kx_get(session: gnutls_session_t) -> c_int;
    pub(crate) fn gnutls_cipher_get(session: gnutls_session_t) -> c_int;
    pub(crate) fn gnutls_mac_get(session: gnutls_session_t) -> c_int;
    pub(crate) fn gnutls_cipher_suite_get_name(
        kx_algorithm: c_int,
        cipher_algorithm: c_int,
        mac_algorithm: c_int,
    ) -> *const c_char;
    pub(crate) fn gnutls_session_get_flags(session: gnutls_session_t) -> c_uint;
    pub(crate) fn gnutls_certificate_get_peers(
        session: gnutls_session_t,
        list_size: *mut c_uint,
    ) -> *const gnutls_datum_t;
    pub(crate) fn gnutls_certificate_verify_peers2(
        session: gnutls_session_t,
        status: *mut c_uint,
    ) -> c_int;
    pub(crate) fn gnutls_ocsp_status_request_get(
        session: gnutls_session_t,
        response: *mut gnutls_datum_t,
    ) -> c_int;

    pub(crate) fn gnutls_x509_crt_init(cert: *mut gnutls_x509_crt_t) -> c_int;
    pub(crate) fn gnutls_x509_crt_deinit(cert: gnutls_x509_crt_t);
    pub(crate) fn gnutls_x509_crt_import(
        cert: gnutls_x509_crt_t,
        data: *const gnutls_datum_t,
        format: c_int,
    ) -> c_int;
    pub(crate) fn gnutls_x509_crt_get_dn_by_oid(
        cert: gnutls_x509_crt_t,
        oid: *const c_char,
        indx: c_uint,
        raw_flag: c_uint,
        buf: *mut c_void,
        buf_size: *mut usize,
    ) -> c_int;
    pub(crate) fn gnutls_x509_crt_check_hostname(
        cert: gnutls_x509_crt_t,
        hostname: *const c_char,
    ) -> c_uint;
    pub(crate) fn gnutls_x509_crt_check_issuer(
        cert: gnutls_x509_crt_t,
        issuer: gnutls_x509_crt_t,
    ) -> c_uint;
    pub(crate) fn gnutls_x509_crt_get_expiration_time(cert: gnutls_x509_crt_t) -> time_t;
    pub(crate) fn gnutls_x509_crt_get_activation_time(cert: gnutls_x509_crt_t) -> time_t;
    pub(crate) fn gnutls_x509_crt_get_pk_algorithm(
        cert: gnutls_x509_crt_t,
        bits: *mut c_uint,
    ) -> c_int;
    pub(crate) fn gnutls_pk_algorithm_get_name(algorithm: c_int) -> *const c_char;
    pub(crate) fn gnutls_x509_crt_get_version(cert: gnutls_x509_crt_t) -> c_int;
    pub(crate) fn gnutls_x509_crt_get_dn2(
        cert: gnutls_x509_crt_t,
        dn: *mut gnutls_datum_t,
    ) -> c_int;
    pub(crate) fn gnutls_x509_crt_get_issuer_dn2(
        cert: gnutls_x509_crt_t,
        dn: *mut gnutls_datum_t,
    ) -> c_int;

    pub(crate) fn gnutls_pubkey_init(key: *mut gnutls_pubkey_t) -> c_int;
    pub(crate) fn gnutls_pubkey_deinit(key: gnutls_pubkey_t);
    pub(crate) fn gnutls_pubkey_import_x509(
        key: gnutls_pubkey_t,
        crt: gnutls_x509_crt_t,
        flags: c_uint,
    ) -> c_int;
    pub(crate) fn gnutls_pubkey_export(
        key: gnutls_pubkey_t,
        format: c_int,
        output_data: *mut c_void,
        output_data_size: *mut usize,
    ) -> c_int;

    pub(crate) fn gnutls_ocsp_resp_init(resp: *mut gnutls_ocsp_resp_t) -> c_int;
    pub(crate) fn gnutls_ocsp_resp_deinit(resp: gnutls_ocsp_resp_t);
    pub(crate) fn gnutls_ocsp_resp_import(
        resp: gnutls_ocsp_resp_t,
        data: *const gnutls_datum_t,
    ) -> c_int;
    pub(crate) fn gnutls_ocsp_resp_get_status(resp: gnutls_ocsp_resp_t) -> c_int;
    pub(crate) fn gnutls_ocsp_resp_check_crt(
        resp: gnutls_ocsp_resp_t,
        indx: c_uint,
        crt: gnutls_x509_crt_t,
    ) -> c_int;
    pub(crate) fn gnutls_ocsp_resp_get_single(
        resp: gnutls_ocsp_resp_t,
        indx: c_uint,
        digest: *mut c_int,
        issuer_name_hash: *mut gnutls_datum_t,
        issuer_key_hash: *mut gnutls_datum_t,
        serial_number: *mut gnutls_datum_t,
        cert_status: *mut c_uint,
        this_update: *mut time_t,
        next_update: *mut time_t,
        revocation_time: *mut time_t,
        revocation_reason: *mut c_uint,
    ) -> c_int;

    pub(crate) fn nettle_ed25519_sha512_public_key(pubkey: *mut u8, key: *const u8);
    pub(crate) fn nettle_ed25519_sha512_sign(
        pub_: *const u8,
        priv_: *const u8,
        length: usize,
        msg: *const u8,
        signature: *mut u8,
    );
}

// The headers' values, from `csrc/layout.c`, in the order the tests
// compare them.
unsafe extern "C" {
    pub(crate) static curl_gnutls_values: [i64; LAYOUT_LEN];
}

/// How many values `csrc/layout.c` gives.
pub(crate) const LAYOUT_LEN: usize = 52;

#[cfg(test)]
mod tests {
    use super::*;

    /// The values this file declares are the headers', in
    /// `csrc/layout.c`'s order: one out of step asks the library for
    /// something else.
    #[test]
    fn the_declared_values_are_the_headers() {
        let ours: [i64; LAYOUT_LEN] = [
            GNUTLS_E_SUCCESS.into(),
            GNUTLS_E_FATAL_ALERT_RECEIVED.into(),
            GNUTLS_E_WARNING_ALERT_RECEIVED.into(),
            GNUTLS_E_AGAIN.into(),
            GNUTLS_E_REHANDSHAKE.into(),
            GNUTLS_E_NO_CERTIFICATE_FOUND.into(),
            GNUTLS_E_SHORT_MEMORY_BUFFER.into(),
            GNUTLS_E_INTERRUPTED.into(),
            GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE.into(),
            GNUTLS_CLIENT.into(),
            GNUTLS_FORCE_CLIENT_CERT.into(),
            GNUTLS_ENABLE_EARLY_DATA.into(),
            GNUTLS_NO_END_OF_EARLY_DATA.into(),
            GNUTLS_CRD_CERTIFICATE.into(),
            GNUTLS_NAME_DNS.into(),
            GNUTLS_SHUT_RDWR.into(),
            GNUTLS_X509_FMT_DER.into(),
            GNUTLS_X509_FMT_PEM.into(),
            GNUTLS_ALPN_MANDATORY.into(),
            GNUTLS_HANDSHAKE_ANY.into(),
            GNUTLS_HANDSHAKE_NEW_SESSION_TICKET.into(),
            GNUTLS_HOOK_POST.into(),
            GNUTLS_SFLAGS_EARLY_DATA.into(),
            GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT.into(),
            GNUTLS_CERT_INVALID.into(),
            GNUTLS_CERT_SIGNER_NOT_FOUND.into(),
            GNUTLS_CERT_INSECURE_ALGORITHM.into(),
            GNUTLS_CERT_NOT_ACTIVATED.into(),
            GNUTLS_CERT_EXPIRED.into(),
            GNUTLS_CERT_INVALID_OCSP_STATUS.into(),
            GNUTLS_SSL3.into(),
            GNUTLS_TLS1_0.into(),
            GNUTLS_TLS1_1.into(),
            GNUTLS_TLS1_2.into(),
            GNUTLS_TLS1_3.into(),
            GNUTLS_PKCS_PKCS12_3DES.into(),
            GNUTLS_PKCS_PKCS12_ARCFOUR.into(),
            GNUTLS_PKCS_PKCS12_RC2_40.into(),
            GNUTLS_PKCS_PBES2_3DES.into(),
            GNUTLS_PKCS_PBES2_AES_128.into(),
            GNUTLS_PKCS_PBES2_AES_192.into(),
            GNUTLS_PKCS_PBES2_AES_256.into(),
            GNUTLS_OCSP_RESP_SUCCESSFUL.into(),
            GNUTLS_OCSP_CERT_GOOD.into(),
            GNUTLS_OCSP_CERT_REVOKED.into(),
            i64::try_from(ED25519_KEY_SIZE).expect("small"),
            i64::try_from(ED25519_SIGNATURE_SIZE).expect("small"),
            i64::try_from(size_of::<gnutls_datum_t>()).expect("small"),
            i64::try_from(core::mem::offset_of!(gnutls_datum_t, data)).expect("small"),
            i64::try_from(core::mem::offset_of!(gnutls_datum_t, size)).expect("small"),
            i64::try_from(size_of::<time_t>()).expect("small"),
            i64::try_from(size_of::<isize>()).expect("small"),
        ];
        // SAFETY: a table of `LAYOUT_LEN` numbers C defines, read only.
        let theirs = unsafe { &curl_gnutls_values };
        for (i, (o, t)) in ours.iter().zip(theirs.iter()).enumerate() {
            assert_eq!(o, t, "entry {i} of csrc/layout.c");
        }
        // SAFETY: the library's static text.
        let oid = unsafe { core::ffi::CStr::from_ptr(curl_gnutls_oid_cn) };
        assert_eq!(oid, GNUTLS_OID_X520_COMMON_NAME);
    }

    unsafe extern "C" {
        static curl_gnutls_oid_cn: *const c_char;
    }
}
