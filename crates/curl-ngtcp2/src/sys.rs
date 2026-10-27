//! The parts of ngtcp2.h, ngtcp2_crypto_ossl.h and nghttp3.h the
//! connection uses, declared as the headers have them (ngtcp2 1.25,
//! nghttp3 1.18). The structures the libraries are handed by version
//! are declared at the version named beside them.

#![allow(non_camel_case_types, dead_code)]

use core::ffi::{c_char, c_int, c_void};

use libc::{sockaddr, sockaddr_in, sockaddr_in6, socklen_t};

pub(crate) type ngtcp2_tstamp = u64;
pub(crate) type ngtcp2_duration = u64;
pub(crate) type ngtcp2_ssize = isize;
pub(crate) type nghttp3_ssize = isize;

pub(crate) const NGTCP2_MILLISECONDS: u64 = 1_000_000;
pub(crate) const NGTCP2_PROTO_VER_V1: u32 = 1;
pub(crate) const NGTCP2_MAX_CIDLEN: usize = 20;
pub(crate) const NGTCP2_STATELESS_RESET_TOKENLEN: usize = 16;
pub(crate) const NGTCP2_MAX_UDP_PAYLOAD_SIZE: usize = 1200;

pub(crate) const NGTCP2_PKT_INFO_VERSION: c_int = 1;
pub(crate) const NGTCP2_SETTINGS_VERSION: c_int = 4;
pub(crate) const NGTCP2_TRANSPORT_PARAMS_VERSION: c_int = 1;
pub(crate) const NGTCP2_CALLBACKS_VERSION: c_int = 5;

pub(crate) const NGTCP2_ERR_STREAM_DATA_BLOCKED: c_int = -208;
pub(crate) const NGTCP2_ERR_CRYPTO: c_int = -213;
pub(crate) const NGTCP2_ERR_STREAM_SHUT_WR: c_int = -219;
pub(crate) const NGTCP2_ERR_STREAM_NOT_FOUND: c_int = -220;
pub(crate) const NGTCP2_ERR_WRITE_MORE: c_int = -230;
pub(crate) const NGTCP2_ERR_DROP_CONN: c_int = -232;
pub(crate) const NGTCP2_ERR_IDLE_CLOSE: c_int = -238;
pub(crate) const NGTCP2_ERR_FATAL: c_int = -500;
pub(crate) const NGTCP2_ERR_NOMEM: c_int = -501;
pub(crate) const NGTCP2_ERR_CALLBACK_FAILURE: c_int = -502;

pub(crate) const NGTCP2_STREAM_DATA_FLAG_FIN: u32 = 0x01;
pub(crate) const NGTCP2_STREAM_CLOSE2_FLAG_RX_APP_ERROR_CODE_SET: u32 = 0x01;
pub(crate) const NGTCP2_WRITE_STREAM_FLAG_MORE: u32 = 0x01;
pub(crate) const NGTCP2_WRITE_STREAM_FLAG_FIN: u32 = 0x02;

/// `ngtcp2_encryption_level`'s 1-RTT.
pub(crate) const NGTCP2_ENCRYPTION_LEVEL_1RTT: c_int = 2;

#[repr(C)]
pub(crate) struct ngtcp2_conn {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct ngtcp2_crypto_ossl_ctx {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ngtcp2_cid {
    pub(crate) datalen: usize,
    pub(crate) data: [u8; NGTCP2_MAX_CIDLEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ngtcp2_addr {
    pub(crate) addr: *mut sockaddr,
    pub(crate) addrlen: socklen_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ngtcp2_path {
    pub(crate) local: ngtcp2_addr,
    pub(crate) remote: ngtcp2_addr,
    pub(crate) user_data: *mut c_void,
}

/// `NGTCP2_ALIGN(8)`.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct ngtcp2_pkt_info {
    pub(crate) ecn: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ngtcp2_vec {
    pub(crate) base: *mut u8,
    pub(crate) len: usize,
}

#[repr(C)]
pub(crate) struct ngtcp2_rand_ctx {
    pub(crate) native_handle: *mut c_void,
}

#[repr(C)]
pub(crate) struct ngtcp2_stateless_reset_token {
    pub(crate) data: [u8; NGTCP2_STATELESS_RESET_TOKENLEN],
}

#[repr(C)]
pub(crate) struct ngtcp2_preferred_addr {
    pub(crate) cid: ngtcp2_cid,
    pub(crate) ipv4: sockaddr_in,
    pub(crate) ipv6: sockaddr_in6,
    pub(crate) ipv4_present: u8,
    pub(crate) ipv6_present: u8,
    pub(crate) stateless_reset_token: [u8; NGTCP2_STATELESS_RESET_TOKENLEN],
}

#[repr(C)]
pub(crate) struct ngtcp2_version_info {
    pub(crate) chosen_version: u32,
    pub(crate) available_versions: *const u8,
    pub(crate) available_versionslen: usize,
}

/// At `NGTCP2_TRANSPORT_PARAMS_V1`.
#[repr(C)]
pub(crate) struct ngtcp2_transport_params {
    pub(crate) preferred_addr: ngtcp2_preferred_addr,
    pub(crate) original_dcid: ngtcp2_cid,
    pub(crate) initial_scid: ngtcp2_cid,
    pub(crate) retry_scid: ngtcp2_cid,
    pub(crate) initial_max_stream_data_bidi_local: u64,
    pub(crate) initial_max_stream_data_bidi_remote: u64,
    pub(crate) initial_max_stream_data_uni: u64,
    pub(crate) initial_max_data: u64,
    pub(crate) initial_max_streams_bidi: u64,
    pub(crate) initial_max_streams_uni: u64,
    pub(crate) max_idle_timeout: ngtcp2_duration,
    pub(crate) max_udp_payload_size: u64,
    pub(crate) active_connection_id_limit: u64,
    pub(crate) ack_delay_exponent: u64,
    pub(crate) max_ack_delay: ngtcp2_duration,
    pub(crate) max_datagram_frame_size: u64,
    pub(crate) stateless_reset_token_present: u8,
    pub(crate) disable_active_migration: u8,
    pub(crate) original_dcid_present: u8,
    pub(crate) initial_scid_present: u8,
    pub(crate) retry_scid_present: u8,
    pub(crate) preferred_addr_present: u8,
    pub(crate) stateless_reset_token: [u8; NGTCP2_STATELESS_RESET_TOKENLEN],
    pub(crate) grease_quic_bit: u8,
    pub(crate) version_info: ngtcp2_version_info,
    pub(crate) version_info_present: u8,
}

/// At `NGTCP2_SETTINGS_V4`.
#[repr(C)]
pub(crate) struct ngtcp2_settings {
    pub(crate) qlog_write: Option<unsafe extern "C" fn()>,
    pub(crate) cc_algo: c_int,
    pub(crate) initial_ts: ngtcp2_tstamp,
    pub(crate) initial_rtt: ngtcp2_duration,
    pub(crate) log_printf: Option<unsafe extern "C" fn()>,
    pub(crate) max_tx_udp_payload_size: usize,
    pub(crate) token: *const u8,
    pub(crate) tokenlen: usize,
    pub(crate) token_type: c_int,
    pub(crate) rand_ctx: ngtcp2_rand_ctx,
    pub(crate) max_window: u64,
    pub(crate) max_stream_window: u64,
    pub(crate) ack_thresh: usize,
    pub(crate) no_tx_udp_payload_size_shaping: u8,
    pub(crate) handshake_timeout: ngtcp2_duration,
    pub(crate) preferred_versions: *const u32,
    pub(crate) preferred_versionslen: usize,
    pub(crate) available_versions: *const u32,
    pub(crate) available_versionslen: usize,
    pub(crate) original_version: u32,
    pub(crate) no_pmtud: u8,
    pub(crate) initial_pkt_num: u32,
    pub(crate) pmtud_probes: *const u16,
    pub(crate) pmtud_probeslen: usize,
    pub(crate) glitch_ratelim_burst: u64,
    pub(crate) glitch_ratelim_rate: u64,
    pub(crate) log_write: Option<unsafe extern "C" fn()>,
}

#[repr(C)]
pub(crate) struct ngtcp2_ccerr {
    pub(crate) r#type: c_int,
    pub(crate) error_code: u64,
    pub(crate) frame_type: u64,
    pub(crate) reason: *const u8,
    pub(crate) reasonlen: usize,
}

/// A callback the connection does not set, whatever its type.
pub(crate) type Unset = Option<unsafe extern "C" fn()>;

/// A callback of ngtcp2's crypto library, set as it is declared.
pub(crate) type Crypto = Option<unsafe extern "C" fn()>;

pub(crate) type ngtcp2_handshake_completed =
    Option<unsafe extern "C" fn(conn: *mut ngtcp2_conn, user_data: *mut c_void) -> c_int>;
pub(crate) type ngtcp2_recv_stream_data = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        flags: u32,
        stream_id: i64,
        offset: u64,
        data: *const u8,
        datalen: usize,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub(crate) type ngtcp2_acked_stream_data_offset = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        stream_id: i64,
        offset: u64,
        datalen: u64,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub(crate) type ngtcp2_stream_close2 = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        flags: u32,
        stream_id: i64,
        rx_app_error_code: u64,
        tx_app_error_code: u64,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub(crate) type ngtcp2_stream_reset = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        stream_id: i64,
        final_size: u64,
        app_error_code: u64,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub(crate) type ngtcp2_stream_stop_sending = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        stream_id: i64,
        app_error_code: u64,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub(crate) type ngtcp2_extend_max_streams = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, max_streams: u64, user_data: *mut c_void) -> c_int,
>;
pub(crate) type ngtcp2_extend_max_stream_data = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        stream_id: i64,
        max_data: u64,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub(crate) type ngtcp2_rand =
    Option<unsafe extern "C" fn(dest: *mut u8, destlen: usize, rand_ctx: *const ngtcp2_rand_ctx)>;
pub(crate) type ngtcp2_get_new_connection_id2 = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        cid: *mut ngtcp2_cid,
        token: *mut ngtcp2_stateless_reset_token,
        cidlen: usize,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub(crate) type ngtcp2_recv_key = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, level: c_int, user_data: *mut c_void) -> c_int,
>;

/// At `NGTCP2_CALLBACKS_V5`.
#[repr(C)]
pub(crate) struct ngtcp2_callbacks {
    pub(crate) client_initial: Crypto,
    pub(crate) recv_client_initial: Unset,
    pub(crate) recv_crypto_data: Crypto,
    pub(crate) handshake_completed: ngtcp2_handshake_completed,
    pub(crate) recv_version_negotiation: Unset,
    pub(crate) encrypt: Crypto,
    pub(crate) decrypt: Crypto,
    pub(crate) hp_mask: Crypto,
    pub(crate) recv_stream_data: ngtcp2_recv_stream_data,
    pub(crate) acked_stream_data_offset: ngtcp2_acked_stream_data_offset,
    pub(crate) stream_open: Unset,
    pub(crate) stream_close: Unset,
    pub(crate) recv_stateless_reset: Unset,
    pub(crate) recv_retry: Crypto,
    pub(crate) extend_max_local_streams_bidi: ngtcp2_extend_max_streams,
    pub(crate) extend_max_local_streams_uni: Unset,
    pub(crate) rand: ngtcp2_rand,
    pub(crate) get_new_connection_id: Unset,
    pub(crate) remove_connection_id: Unset,
    pub(crate) update_key: Crypto,
    pub(crate) path_validation: Unset,
    pub(crate) select_preferred_addr: Unset,
    pub(crate) stream_reset: ngtcp2_stream_reset,
    pub(crate) extend_max_remote_streams_bidi: Unset,
    pub(crate) extend_max_remote_streams_uni: Unset,
    pub(crate) extend_max_stream_data: ngtcp2_extend_max_stream_data,
    pub(crate) dcid_status: Unset,
    pub(crate) handshake_confirmed: Unset,
    pub(crate) recv_new_token: Unset,
    pub(crate) delete_crypto_aead_ctx: Crypto,
    pub(crate) delete_crypto_cipher_ctx: Crypto,
    pub(crate) recv_datagram: Unset,
    pub(crate) ack_datagram: Unset,
    pub(crate) lost_datagram: Unset,
    pub(crate) get_path_challenge_data: Unset,
    pub(crate) stream_stop_sending: ngtcp2_stream_stop_sending,
    pub(crate) version_negotiation: Unset,
    pub(crate) recv_rx_key: ngtcp2_recv_key,
    pub(crate) recv_tx_key: Unset,
    pub(crate) tls_early_data_rejected: Unset,
    pub(crate) begin_path_validation: Unset,
    pub(crate) recv_stateless_reset2: Unset,
    pub(crate) get_new_connection_id2: ngtcp2_get_new_connection_id2,
    pub(crate) dcid_status2: Unset,
    pub(crate) get_path_challenge_data2: Crypto,
    pub(crate) recv_stop_sending: Unset,
    pub(crate) stream_close2: ngtcp2_stream_close2,
}

/// What ngtcp2's crypto library finds the connection by, the `SSL`'s
/// application data.
#[repr(C)]
pub(crate) struct ngtcp2_crypto_conn_ref {
    pub(crate) get_conn:
        Option<unsafe extern "C" fn(conn_ref: *mut ngtcp2_crypto_conn_ref) -> *mut ngtcp2_conn>,
    pub(crate) user_data: *mut c_void,
}

#[repr(C)]
pub(crate) struct ngtcp2_info {
    pub(crate) age: c_int,
    pub(crate) version_num: c_int,
    pub(crate) version_str: *const c_char,
}

unsafe extern "C" {
    pub(crate) fn ngtcp2_settings_default_versioned(version: c_int, settings: *mut ngtcp2_settings);
    pub(crate) fn ngtcp2_transport_params_default_versioned(
        version: c_int,
        params: *mut ngtcp2_transport_params,
    );
    pub(crate) fn ngtcp2_conn_client_new_versioned(
        pconn: *mut *mut ngtcp2_conn,
        dcid: *const ngtcp2_cid,
        scid: *const ngtcp2_cid,
        path: *const ngtcp2_path,
        client_chosen_version: u32,
        callbacks_version: c_int,
        callbacks: *const ngtcp2_callbacks,
        settings_version: c_int,
        settings: *const ngtcp2_settings,
        transport_params_version: c_int,
        params: *const ngtcp2_transport_params,
        mem: *const c_void,
        user_data: *mut c_void,
    ) -> c_int;
    pub(crate) fn ngtcp2_conn_del(conn: *mut ngtcp2_conn);
    pub(crate) fn ngtcp2_conn_read_pkt_versioned(
        conn: *mut ngtcp2_conn,
        path: *const ngtcp2_path,
        pkt_info_version: c_int,
        pi: *const ngtcp2_pkt_info,
        pkt: *const u8,
        pktlen: usize,
        ts: ngtcp2_tstamp,
    ) -> c_int;
    pub(crate) fn ngtcp2_conn_writev_stream_versioned(
        conn: *mut ngtcp2_conn,
        path: *mut ngtcp2_path,
        pkt_info_version: c_int,
        pi: *mut ngtcp2_pkt_info,
        dest: *mut u8,
        destlen: usize,
        pdatalen: *mut ngtcp2_ssize,
        flags: u32,
        stream_id: i64,
        datav: *const ngtcp2_vec,
        datavcnt: usize,
        ts: ngtcp2_tstamp,
    ) -> ngtcp2_ssize;
    pub(crate) fn ngtcp2_conn_write_connection_close_versioned(
        conn: *mut ngtcp2_conn,
        path: *mut ngtcp2_path,
        pkt_info_version: c_int,
        pi: *mut ngtcp2_pkt_info,
        dest: *mut u8,
        destlen: usize,
        ccerr: *const ngtcp2_ccerr,
        ts: ngtcp2_tstamp,
    ) -> ngtcp2_ssize;
    pub(crate) fn ngtcp2_conn_get_expiry(conn: *mut ngtcp2_conn) -> ngtcp2_tstamp;
    pub(crate) fn ngtcp2_conn_handle_expiry(conn: *mut ngtcp2_conn, ts: ngtcp2_tstamp) -> c_int;
    pub(crate) fn ngtcp2_conn_get_handshake_completed(conn: *mut ngtcp2_conn) -> c_int;
    pub(crate) fn ngtcp2_conn_in_draining_period(conn: *mut ngtcp2_conn) -> c_int;
    pub(crate) fn ngtcp2_conn_get_ccerr(conn: *mut ngtcp2_conn) -> *const ngtcp2_ccerr;
    pub(crate) fn ngtcp2_conn_get_remote_transport_params(
        conn: *mut ngtcp2_conn,
    ) -> *const ngtcp2_transport_params;
    pub(crate) fn ngtcp2_conn_get_max_tx_udp_payload_size(conn: *mut ngtcp2_conn) -> usize;
    pub(crate) fn ngtcp2_conn_get_path_max_tx_udp_payload_size(conn: *mut ngtcp2_conn) -> usize;
    pub(crate) fn ngtcp2_conn_get_send_quantum(conn: *mut ngtcp2_conn) -> usize;
    pub(crate) fn ngtcp2_conn_get_cwnd_left(conn: *mut ngtcp2_conn) -> u64;
    pub(crate) fn ngtcp2_conn_get_max_data_left(conn: *mut ngtcp2_conn) -> u64;
    pub(crate) fn ngtcp2_conn_update_pkt_tx_time(conn: *mut ngtcp2_conn, ts: ngtcp2_tstamp);
    pub(crate) fn ngtcp2_conn_set_keep_alive_timeout(
        conn: *mut ngtcp2_conn,
        timeout: ngtcp2_duration,
    );
    pub(crate) fn ngtcp2_conn_extend_max_stream_offset(
        conn: *mut ngtcp2_conn,
        stream_id: i64,
        datalen: u64,
    ) -> c_int;
    pub(crate) fn ngtcp2_conn_extend_max_offset(conn: *mut ngtcp2_conn, datalen: u64);
    pub(crate) fn ngtcp2_conn_open_bidi_stream(
        conn: *mut ngtcp2_conn,
        pstream_id: *mut i64,
        stream_user_data: *mut c_void,
    ) -> c_int;
    pub(crate) fn ngtcp2_conn_open_uni_stream(
        conn: *mut ngtcp2_conn,
        pstream_id: *mut i64,
        stream_user_data: *mut c_void,
    ) -> c_int;
    pub(crate) fn ngtcp2_conn_shutdown_stream(
        conn: *mut ngtcp2_conn,
        flags: u32,
        stream_id: i64,
        app_error_code: u64,
    ) -> c_int;
    pub(crate) fn ngtcp2_conn_shutdown_stream_read(
        conn: *mut ngtcp2_conn,
        flags: u32,
        stream_id: i64,
        app_error_code: u64,
    ) -> c_int;
    pub(crate) fn ngtcp2_conn_shutdown_stream_write(
        conn: *mut ngtcp2_conn,
        flags: u32,
        stream_id: i64,
        app_error_code: u64,
    ) -> c_int;
    pub(crate) fn ngtcp2_conn_get_streams_uni_left(conn: *mut ngtcp2_conn) -> u64;
    pub(crate) fn ngtcp2_conn_get_tls_alert(conn: *mut ngtcp2_conn) -> u8;
    pub(crate) fn ngtcp2_conn_get_tls_early_data_rejected2(conn: *const ngtcp2_conn) -> c_int;
    pub(crate) fn ngtcp2_conn_encode_0rtt_transport_params(
        conn: *mut ngtcp2_conn,
        dest: *mut u8,
        destlen: usize,
    ) -> ngtcp2_ssize;
    pub(crate) fn ngtcp2_conn_decode_and_set_0rtt_transport_params(
        conn: *mut ngtcp2_conn,
        data: *const u8,
        datalen: usize,
    ) -> c_int;
    pub(crate) fn ngtcp2_conn_set_tls_native_handle(
        conn: *mut ngtcp2_conn,
        tls_native_handle: *mut c_void,
    );
    pub(crate) fn ngtcp2_ccerr_default(ccerr: *mut ngtcp2_ccerr);
    pub(crate) fn ngtcp2_ccerr_set_liberr(
        ccerr: *mut ngtcp2_ccerr,
        liberr: c_int,
        reason: *const u8,
        reasonlen: usize,
    );
    pub(crate) fn ngtcp2_ccerr_set_tls_alert(
        ccerr: *mut ngtcp2_ccerr,
        tls_alert: u8,
        reason: *const u8,
        reasonlen: usize,
    );
    pub(crate) fn ngtcp2_ccerr_set_application_error(
        ccerr: *mut ngtcp2_ccerr,
        error_code: u64,
        reason: *const u8,
        reasonlen: usize,
    );
    pub(crate) fn ngtcp2_strerror(liberr: c_int) -> *const c_char;
    pub(crate) fn ngtcp2_version(least_version: c_int) -> *const ngtcp2_info;
}

unsafe extern "C" {
    pub(crate) fn ngtcp2_crypto_client_initial_cb();
    pub(crate) fn ngtcp2_crypto_recv_crypto_data_cb();
    pub(crate) fn ngtcp2_crypto_encrypt_cb();
    pub(crate) fn ngtcp2_crypto_decrypt_cb();
    pub(crate) fn ngtcp2_crypto_hp_mask_cb();
    pub(crate) fn ngtcp2_crypto_recv_retry_cb();
    pub(crate) fn ngtcp2_crypto_update_key_cb();
    pub(crate) fn ngtcp2_crypto_delete_crypto_aead_ctx_cb();
    pub(crate) fn ngtcp2_crypto_delete_crypto_cipher_ctx_cb();
    pub(crate) fn ngtcp2_crypto_get_path_challenge_data2_cb();
    pub(crate) fn ngtcp2_crypto_ossl_init() -> c_int;
    pub(crate) fn ngtcp2_crypto_ossl_ctx_new(
        pctx: *mut *mut ngtcp2_crypto_ossl_ctx,
        ssl: *mut c_void,
    ) -> c_int;
    pub(crate) fn ngtcp2_crypto_ossl_ctx_del(ctx: *mut ngtcp2_crypto_ossl_ctx);
    pub(crate) fn ngtcp2_crypto_ossl_configure_client_session(ssl: *mut c_void) -> c_int;
}

pub(crate) const NGHTTP3_SETTINGS_VERSION: c_int = 4;
pub(crate) const NGHTTP3_CALLBACKS_VERSION: c_int = 4;

pub(crate) const NGHTTP3_ERR_WOULDBLOCK: nghttp3_ssize = -103;
pub(crate) const NGHTTP3_ERR_STREAM_NOT_FOUND: c_int = -110;
pub(crate) const NGHTTP3_ERR_CONN_CLOSING: c_int = -111;
pub(crate) const NGHTTP3_ERR_H3_CLOSED_CRITICAL_STREAM: c_int = -605;
pub(crate) const NGHTTP3_ERR_FATAL: c_int = -900;
pub(crate) const NGHTTP3_ERR_NOMEM: c_int = -901;
pub(crate) const NGHTTP3_ERR_CALLBACK_FAILURE: c_int = -902;
pub(crate) const NGHTTP3_H3_NO_ERROR: u64 = 0x0100;
pub(crate) const NGHTTP3_NV_FLAG_NONE: u8 = 0;
pub(crate) const NGHTTP3_DATA_FLAG_EOF: u32 = 0x01;
pub(crate) const NGHTTP3_QPACK_TOKEN__STATUS: i32 = 11;

#[repr(C)]
pub(crate) struct nghttp3_conn {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct nghttp3_rcbuf {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct nghttp3_vec {
    pub(crate) base: *mut u8,
    pub(crate) len: usize,
}

#[repr(C)]
pub(crate) struct nghttp3_nv {
    pub(crate) name: *const u8,
    pub(crate) value: *const u8,
    pub(crate) namelen: usize,
    pub(crate) valuelen: usize,
    pub(crate) flags: u8,
}

/// At `NGHTTP3_SETTINGS_V4`.
#[repr(C)]
pub(crate) struct nghttp3_settings {
    pub(crate) max_field_section_size: u64,
    pub(crate) qpack_max_dtable_capacity: usize,
    pub(crate) qpack_encoder_max_dtable_capacity: usize,
    pub(crate) qpack_blocked_streams: usize,
    pub(crate) enable_connect_protocol: u8,
    pub(crate) h3_datagram: u8,
    pub(crate) origin_list: *const nghttp3_vec,
    pub(crate) glitch_ratelim_burst: u64,
    pub(crate) glitch_ratelim_rate: u64,
    pub(crate) qpack_indexing_strat: c_int,
}

pub(crate) type nghttp3_stream_cb = Option<
    unsafe extern "C" fn(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        n: u64,
        conn_user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub(crate) type nghttp3_recv_data = Option<
    unsafe extern "C" fn(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        data: *const u8,
        datalen: usize,
        conn_user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub(crate) type nghttp3_deferred_consume = Option<
    unsafe extern "C" fn(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        consumed: usize,
        conn_user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub(crate) type nghttp3_recv_header = Option<
    unsafe extern "C" fn(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        token: i32,
        name: *mut nghttp3_rcbuf,
        value: *mut nghttp3_rcbuf,
        flags: u8,
        conn_user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub(crate) type nghttp3_end_headers = Option<
    unsafe extern "C" fn(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        fin: c_int,
        conn_user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;

/// At `NGHTTP3_CALLBACKS_V4`.
#[repr(C)]
pub(crate) struct nghttp3_callbacks {
    pub(crate) acked_stream_data: nghttp3_stream_cb,
    pub(crate) stream_close: nghttp3_stream_cb,
    pub(crate) recv_data: nghttp3_recv_data,
    pub(crate) deferred_consume: nghttp3_deferred_consume,
    pub(crate) begin_headers: Unset,
    pub(crate) recv_header: nghttp3_recv_header,
    pub(crate) end_headers: nghttp3_end_headers,
    pub(crate) begin_trailers: Unset,
    pub(crate) recv_trailer: nghttp3_recv_header,
    pub(crate) end_trailers: Unset,
    pub(crate) stop_sending: nghttp3_stream_cb,
    pub(crate) end_stream: Unset,
    pub(crate) reset_stream: nghttp3_stream_cb,
    pub(crate) shutdown: Unset,
    pub(crate) recv_settings: Unset,
    pub(crate) recv_origin: Unset,
    pub(crate) end_origin: Unset,
    pub(crate) rand: Unset,
    pub(crate) recv_settings2: Unset,
    pub(crate) stream_close2: Unset,
}

pub(crate) type nghttp3_read_data_callback = Option<
    unsafe extern "C" fn(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        vec: *mut nghttp3_vec,
        veccnt: usize,
        pflags: *mut u32,
        conn_user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> nghttp3_ssize,
>;

#[repr(C)]
pub(crate) struct nghttp3_data_reader {
    pub(crate) read_data: nghttp3_read_data_callback,
}

#[repr(C)]
pub(crate) struct nghttp3_info {
    pub(crate) age: c_int,
    pub(crate) version_num: c_int,
    pub(crate) version_str: *const c_char,
}

unsafe extern "C" {
    pub(crate) fn nghttp3_settings_default_versioned(
        version: c_int,
        settings: *mut nghttp3_settings,
    );
    pub(crate) fn nghttp3_conn_client_new_versioned(
        pconn: *mut *mut nghttp3_conn,
        callbacks_version: c_int,
        callbacks: *const nghttp3_callbacks,
        settings_version: c_int,
        settings: *const nghttp3_settings,
        mem: *const c_void,
        conn_user_data: *mut c_void,
    ) -> c_int;
    pub(crate) fn nghttp3_conn_del(conn: *mut nghttp3_conn);
    pub(crate) fn nghttp3_conn_bind_control_stream(
        conn: *mut nghttp3_conn,
        stream_id: i64,
    ) -> c_int;
    pub(crate) fn nghttp3_conn_bind_qpack_streams(
        conn: *mut nghttp3_conn,
        qenc_stream_id: i64,
        qdec_stream_id: i64,
    ) -> c_int;
    pub(crate) fn nghttp3_conn_read_stream(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        src: *const u8,
        srclen: usize,
        fin: c_int,
    ) -> nghttp3_ssize;
    pub(crate) fn nghttp3_conn_writev_stream(
        conn: *mut nghttp3_conn,
        pstream_id: *mut i64,
        pfin: *mut c_int,
        vec: *mut nghttp3_vec,
        veccnt: usize,
    ) -> nghttp3_ssize;
    pub(crate) fn nghttp3_conn_add_write_offset(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        n: usize,
    ) -> c_int;
    pub(crate) fn nghttp3_conn_add_ack_offset(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        n: u64,
    ) -> c_int;
    pub(crate) fn nghttp3_conn_block_stream(conn: *mut nghttp3_conn, stream_id: i64);
    pub(crate) fn nghttp3_conn_unblock_stream(conn: *mut nghttp3_conn, stream_id: i64) -> c_int;
    pub(crate) fn nghttp3_conn_resume_stream(conn: *mut nghttp3_conn, stream_id: i64) -> c_int;
    pub(crate) fn nghttp3_conn_close_stream(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        app_error_code: u64,
    ) -> c_int;
    pub(crate) fn nghttp3_conn_shutdown_stream_read(
        conn: *mut nghttp3_conn,
        stream_id: i64,
    ) -> c_int;
    pub(crate) fn nghttp3_conn_shutdown_stream_write(conn: *mut nghttp3_conn, stream_id: i64);
    pub(crate) fn nghttp3_conn_submit_request(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        nva: *const nghttp3_nv,
        nvlen: usize,
        dr: *const nghttp3_data_reader,
        stream_user_data: *mut c_void,
    ) -> c_int;
    pub(crate) fn nghttp3_conn_set_stream_user_data(
        conn: *mut nghttp3_conn,
        stream_id: i64,
        stream_user_data: *mut c_void,
    ) -> c_int;
    pub(crate) fn nghttp3_rcbuf_get_buf(rcbuf: *const nghttp3_rcbuf) -> nghttp3_vec;
    pub(crate) fn nghttp3_strerror(liberr: c_int) -> *const c_char;
    pub(crate) fn nghttp3_err_infer_quic_app_error_code(liberr: c_int) -> u64;
    pub(crate) fn nghttp3_version(least_version: c_int) -> *const nghttp3_info;
}

unsafe extern "C" {
    /// OpenSSL's, from 3.5: whether a QUIC session sends early data.
    pub(crate) fn SSL_set_quic_tls_early_data_enabled(ssl: *mut c_void, enabled: c_int) -> c_int;
}

/// `SSL_set_app_data`, a macro over `SSL_set_ex_data`'s slot 0.
pub(crate) unsafe fn ssl_set_app_data(ssl: *mut c_void, data: *mut c_void) {
    unsafe extern "C" {
        fn SSL_set_ex_data(ssl: *mut c_void, idx: c_int, data: *mut c_void) -> c_int;
    }
    // SAFETY: as the caller says: a live SSL.
    unsafe { SSL_set_ex_data(ssl, 0, data) };
}
