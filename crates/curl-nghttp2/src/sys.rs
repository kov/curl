//! The parts of nghttp2.h the session uses, declared as the header has
//! them (nghttp2 1.61 or later: the `2` functions with `nghttp2_ssize`).

#![allow(non_camel_case_types, dead_code)]

use core::ffi::{c_char, c_int, c_void};

pub(crate) type nghttp2_ssize = isize;

#[repr(C)]
pub(crate) struct nghttp2_session {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct nghttp2_session_callbacks {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct nghttp2_option {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct nghttp2_priority_spec {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct nghttp2_nv {
    pub(crate) name: *mut u8,
    pub(crate) value: *mut u8,
    pub(crate) namelen: usize,
    pub(crate) valuelen: usize,
    pub(crate) flags: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct nghttp2_settings_entry {
    pub(crate) settings_id: i32,
    pub(crate) value: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct nghttp2_frame_hd {
    pub(crate) length: usize,
    pub(crate) stream_id: i32,
    pub(crate) r#type: u8,
    pub(crate) flags: u8,
    pub(crate) reserved: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct nghttp2_rst_stream {
    pub(crate) hd: nghttp2_frame_hd,
    pub(crate) error_code: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct nghttp2_goaway {
    pub(crate) hd: nghttp2_frame_hd,
    pub(crate) last_stream_id: i32,
    pub(crate) error_code: u32,
    pub(crate) opaque_data: *mut u8,
    pub(crate) opaque_data_len: usize,
    pub(crate) reserved: u8,
}

/// The frames the session reads, of which only these members are read;
/// the union is as large as the library's (its largest member, the
/// HEADERS frame, is smaller than the padding here).
#[repr(C)]
pub(crate) union nghttp2_frame {
    pub(crate) hd: nghttp2_frame_hd,
    pub(crate) rst_stream: nghttp2_rst_stream,
    pub(crate) goaway: nghttp2_goaway,
    _size: [u64; 16],
}

#[repr(C)]
pub(crate) union nghttp2_data_source {
    pub(crate) fd: c_int,
    pub(crate) ptr: *mut c_void,
}

pub(crate) type nghttp2_data_source_read_callback2 = Option<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        i32,
        *mut u8,
        usize,
        *mut u32,
        *mut nghttp2_data_source,
        *mut c_void,
    ) -> nghttp2_ssize,
>;

#[repr(C)]
pub(crate) struct nghttp2_data_provider2 {
    pub(crate) source: nghttp2_data_source,
    pub(crate) read_callback: nghttp2_data_source_read_callback2,
}

#[repr(C)]
pub(crate) struct nghttp2_info {
    pub(crate) age: c_int,
    pub(crate) version_num: c_int,
    pub(crate) version_str: *const c_char,
    pub(crate) proto_str: *const c_char,
}

pub(crate) const NGHTTP2_ERR_DEFERRED: c_int = -508;
pub(crate) const NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE: c_int = -521;
pub(crate) const NGHTTP2_ERR_NOMEM: c_int = -901;
pub(crate) const NGHTTP2_NV_FLAG_NONE: u8 = 0;
pub(crate) const NGHTTP2_DATA: u8 = 0;
pub(crate) const NGHTTP2_HEADERS: u8 = 0x01;
pub(crate) const NGHTTP2_RST_STREAM: u8 = 0x03;
pub(crate) const NGHTTP2_SETTINGS: u8 = 0x04;
pub(crate) const NGHTTP2_GOAWAY: u8 = 0x07;
pub(crate) const NGHTTP2_FLAG_END_STREAM: u8 = 0x01;
pub(crate) const NGHTTP2_FLAG_ACK: u8 = 0x01;
pub const NGHTTP2_SETTINGS_ENABLE_PUSH: i32 = 0x02;
pub const NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS: i32 = 0x03;
pub const NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE: i32 = 0x04;
pub(crate) const NGHTTP2_DATA_FLAG_EOF: u32 = 0x01;

type OnFrameRecv =
    Option<unsafe extern "C" fn(*mut nghttp2_session, *const nghttp2_frame, *mut c_void) -> c_int>;
type OnHeader = Option<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const nghttp2_frame,
        *const u8,
        usize,
        *const u8,
        usize,
        u8,
        *mut c_void,
    ) -> c_int,
>;
type OnDataChunk = Option<
    unsafe extern "C" fn(*mut nghttp2_session, u8, i32, *const u8, usize, *mut c_void) -> c_int,
>;
type OnStreamClose =
    Option<unsafe extern "C" fn(*mut nghttp2_session, i32, u32, *mut c_void) -> c_int>;

unsafe extern "C" {
    pub(crate) fn nghttp2_version(least_version: c_int) -> *const nghttp2_info;
    pub(crate) fn nghttp2_strerror(lib_error_code: c_int) -> *const c_char;
    pub(crate) fn nghttp2_http2_strerror(error_code: u32) -> *const c_char;

    pub(crate) fn nghttp2_session_callbacks_new(out: *mut *mut nghttp2_session_callbacks) -> c_int;
    pub(crate) fn nghttp2_session_callbacks_del(callbacks: *mut nghttp2_session_callbacks);
    pub(crate) fn nghttp2_session_callbacks_set_on_frame_recv_callback(
        cbs: *mut nghttp2_session_callbacks,
        cb: OnFrameRecv,
    );
    pub(crate) fn nghttp2_session_callbacks_set_on_header_callback(
        cbs: *mut nghttp2_session_callbacks,
        cb: OnHeader,
    );
    pub(crate) fn nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        cbs: *mut nghttp2_session_callbacks,
        cb: OnDataChunk,
    );
    pub(crate) fn nghttp2_session_callbacks_set_on_stream_close_callback(
        cbs: *mut nghttp2_session_callbacks,
        cb: OnStreamClose,
    );

    pub(crate) fn nghttp2_option_new(out: *mut *mut nghttp2_option) -> c_int;
    pub(crate) fn nghttp2_option_del(option: *mut nghttp2_option);
    pub(crate) fn nghttp2_option_set_no_auto_window_update(option: *mut nghttp2_option, val: c_int);
    pub(crate) fn nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation(
        option: *mut nghttp2_option,
        val: c_int,
    );

    pub(crate) fn nghttp2_session_client_new2(
        out: *mut *mut nghttp2_session,
        callbacks: *const nghttp2_session_callbacks,
        user_data: *mut c_void,
        option: *const nghttp2_option,
    ) -> c_int;
    pub(crate) fn nghttp2_session_server_new2(
        out: *mut *mut nghttp2_session,
        callbacks: *const nghttp2_session_callbacks,
        user_data: *mut c_void,
        option: *const nghttp2_option,
    ) -> c_int;
    pub(crate) fn nghttp2_session_del(session: *mut nghttp2_session);

    pub(crate) fn nghttp2_submit_settings(
        session: *mut nghttp2_session,
        flags: u8,
        iv: *const nghttp2_settings_entry,
        niv: usize,
    ) -> c_int;
    pub(crate) fn nghttp2_submit_request2(
        session: *mut nghttp2_session,
        pri_spec: *const nghttp2_priority_spec,
        nva: *const nghttp2_nv,
        nvlen: usize,
        data_prd: *const nghttp2_data_provider2,
        stream_user_data: *mut c_void,
    ) -> i32;
    pub(crate) fn nghttp2_submit_response2(
        session: *mut nghttp2_session,
        stream_id: i32,
        nva: *const nghttp2_nv,
        nvlen: usize,
        data_prd: *const nghttp2_data_provider2,
    ) -> c_int;
    pub(crate) fn nghttp2_submit_rst_stream(
        session: *mut nghttp2_session,
        flags: u8,
        stream_id: i32,
        error_code: u32,
    ) -> c_int;
    pub(crate) fn nghttp2_submit_goaway(
        session: *mut nghttp2_session,
        flags: u8,
        last_stream_id: i32,
        error_code: u32,
        opaque_data: *const u8,
        opaque_data_len: usize,
    ) -> c_int;

    pub(crate) fn nghttp2_session_mem_recv2(
        session: *mut nghttp2_session,
        input: *const u8,
        inlen: usize,
    ) -> nghttp2_ssize;
    pub(crate) fn nghttp2_session_mem_send2(
        session: *mut nghttp2_session,
        data_ptr: *mut *const u8,
    ) -> nghttp2_ssize;
    pub(crate) fn nghttp2_session_consume(
        session: *mut nghttp2_session,
        stream_id: i32,
        size: usize,
    ) -> c_int;
    pub(crate) fn nghttp2_session_resume_data(
        session: *mut nghttp2_session,
        stream_id: i32,
    ) -> c_int;
    pub(crate) fn nghttp2_session_want_read(session: *mut nghttp2_session) -> c_int;
    pub(crate) fn nghttp2_session_want_write(session: *mut nghttp2_session) -> c_int;
    pub(crate) fn nghttp2_session_get_remote_settings(
        session: *mut nghttp2_session,
        id: i32,
    ) -> u32;
}
