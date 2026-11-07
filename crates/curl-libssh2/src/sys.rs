//! The parts of libssh2's `libssh2.h` and `libssh2_sftp.h` the session
//! uses, declared as libssh2 1.11 has them (`libssh2_crypto_engine`).
//! `csrc/layout.c` gives the headers' own values and layouts, which the
//! crate's tests compare with these.

#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

#[repr(C)]
pub(crate) struct LIBSSH2_SESSION {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct LIBSSH2_CHANNEL {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct LIBSSH2_KNOWNHOSTS {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct LIBSSH2_AGENT {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct LIBSSH2_SFTP {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct LIBSSH2_SFTP_HANDLE {
    _private: [u8; 0],
}

/// `struct libssh2_knownhost`, which the header has whole.
#[repr(C)]
pub(crate) struct libssh2_knownhost {
    pub(crate) magic: c_uint,
    pub(crate) node: *mut c_void,
    pub(crate) name: *mut c_char,
    pub(crate) key: *mut c_char,
    pub(crate) typemask: c_int,
}

/// `struct libssh2_agent_publickey`, which the header has whole.
#[repr(C)]
pub(crate) struct libssh2_agent_publickey {
    pub(crate) magic: c_uint,
    pub(crate) node: *mut c_void,
    pub(crate) blob: *mut u8,
    pub(crate) blob_len: usize,
    pub(crate) comment: *mut c_char,
}

/// `LIBSSH2_SFTP_ATTRIBUTES`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct LIBSSH2_SFTP_ATTRIBUTES {
    pub(crate) flags: c_ulong,
    pub(crate) filesize: u64,
    pub(crate) uid: c_ulong,
    pub(crate) gid: c_ulong,
    pub(crate) permissions: c_ulong,
    pub(crate) atime: c_ulong,
    pub(crate) mtime: c_ulong,
}

/// `LIBSSH2_SFTP_STATVFS`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct LIBSSH2_SFTP_STATVFS {
    pub(crate) f_bsize: u64,
    pub(crate) f_frsize: u64,
    pub(crate) f_blocks: u64,
    pub(crate) f_bfree: u64,
    pub(crate) f_bavail: u64,
    pub(crate) f_files: u64,
    pub(crate) f_ffree: u64,
    pub(crate) f_favail: u64,
    pub(crate) f_fsid: u64,
    pub(crate) f_flag: u64,
    pub(crate) f_namemax: u64,
}

/// `LIBSSH2_USERAUTH_KBDINT_PROMPT`.
#[repr(C)]
pub(crate) struct LIBSSH2_USERAUTH_KBDINT_PROMPT {
    pub(crate) text: *mut u8,
    pub(crate) length: usize,
    pub(crate) echo: u8,
}

/// `LIBSSH2_USERAUTH_KBDINT_RESPONSE`.
#[repr(C)]
pub(crate) struct LIBSSH2_USERAUTH_KBDINT_RESPONSE {
    pub(crate) text: *mut c_char,
    pub(crate) length: c_uint,
}

/// `libssh2_struct_stat`: the system's `struct stat`; on Windows
/// `struct _stati64`, which with 64-bit times is the `_stat64` that is
/// libc's `stat` there.
pub(crate) type libssh2_struct_stat = libc::stat;

/// `libssh2_socket_t`: a descriptor, on Windows a Winsock `SOCKET`.
#[cfg(unix)]
pub(crate) type libssh2_socket_t = c_int;
#[cfg(windows)]
pub(crate) type libssh2_socket_t = usize;

/// `libssh2_cb_generic`, which a callback is cast to and from.
pub(crate) type libssh2_cb_generic = unsafe extern "C" fn();

/// `LIBSSH2_RECV_FUNC`.
pub(crate) type recv_func = unsafe extern "C" fn(
    socket: libssh2_socket_t,
    buffer: *mut c_void,
    length: usize,
    flags: c_int,
    abstract_: *mut *mut c_void,
) -> isize;

/// `LIBSSH2_SEND_FUNC`.
pub(crate) type send_func = unsafe extern "C" fn(
    socket: libssh2_socket_t,
    buffer: *const c_void,
    length: usize,
    flags: c_int,
    abstract_: *mut *mut c_void,
) -> isize;

/// `LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC`.
pub(crate) type kbdint_response_func = unsafe extern "C" fn(
    name: *const c_char,
    name_len: c_int,
    instruction: *const c_char,
    instruction_len: c_int,
    num_prompts: c_int,
    prompts: *const LIBSSH2_USERAUTH_KBDINT_PROMPT,
    responses: *mut LIBSSH2_USERAUTH_KBDINT_RESPONSE,
    abstract_: *mut *mut c_void,
);

// `LIBSSH2_ERROR_*`.
pub(crate) const LIBSSH2_ERROR_NONE: c_int = 0;
pub(crate) const LIBSSH2_ERROR_SOCKET_NONE: c_int = -1;
pub(crate) const LIBSSH2_ERROR_ALLOC: c_int = -6;
pub(crate) const LIBSSH2_ERROR_SOCKET_SEND: c_int = -7;
pub(crate) const LIBSSH2_ERROR_TIMEOUT: c_int = -9;
pub(crate) const LIBSSH2_ERROR_HOSTKEY_INIT: c_int = -10;
pub(crate) const LIBSSH2_ERROR_HOSTKEY_SIGN: c_int = -11;
pub(crate) const LIBSSH2_ERROR_PASSWORD_EXPIRED: c_int = -15;
pub(crate) const LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED: c_int = -18;
pub(crate) const LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED: c_int = -19;
pub(crate) const LIBSSH2_ERROR_SCP_PROTOCOL: c_int = -28;
pub(crate) const LIBSSH2_ERROR_SOCKET_TIMEOUT: c_int = -30;
pub(crate) const LIBSSH2_ERROR_SFTP_PROTOCOL: c_int = -31;
pub(crate) const LIBSSH2_ERROR_EAGAIN: c_int = -37;

// `libssh2_crypto_engine_t`.
pub(crate) const libssh2_no_crypto: c_int = 0;
pub(crate) const libssh2_openssl: c_int = 1;
pub(crate) const libssh2_gcrypt: c_int = 2;
pub(crate) const libssh2_mbedtls: c_int = 3;
pub(crate) const libssh2_wincng: c_int = 4;
pub(crate) const libssh2_os400qc3: c_int = 5;

/// `libssh2_session_disconnect`'s reason.
pub(crate) const SSH_DISCONNECT_BY_APPLICATION: c_int = 11;
pub(crate) const LIBSSH2_METHOD_HOSTKEY: c_int = 1;
pub(crate) const LIBSSH2_FLAG_COMPRESS: c_int = 2;
/// `libssh2_session_callback_set2`'s callbacks.
pub(crate) const LIBSSH2_CALLBACK_SEND: c_int = 5;
pub(crate) const LIBSSH2_CALLBACK_RECV: c_int = 6;
pub(crate) const LIBSSH2_SESSION_BLOCK_INBOUND: c_int = 0x0001;
pub(crate) const LIBSSH2_SESSION_BLOCK_OUTBOUND: c_int = 0x0002;
pub(crate) const LIBSSH2_HOSTKEY_HASH_MD5: c_int = 1;
pub(crate) const LIBSSH2_HOSTKEY_HASH_SHA256: c_int = 3;

// `LIBSSH2_HOSTKEY_TYPE_*`.
pub(crate) const LIBSSH2_HOSTKEY_TYPE_RSA: c_int = 1;
pub(crate) const LIBSSH2_HOSTKEY_TYPE_DSS: c_int = 2;
pub(crate) const LIBSSH2_HOSTKEY_TYPE_ECDSA_256: c_int = 3;
pub(crate) const LIBSSH2_HOSTKEY_TYPE_ECDSA_384: c_int = 4;
pub(crate) const LIBSSH2_HOSTKEY_TYPE_ECDSA_521: c_int = 5;
pub(crate) const LIBSSH2_HOSTKEY_TYPE_ED25519: c_int = 6;

// `LIBSSH2_KNOWNHOST_*`.
pub(crate) const LIBSSH2_KNOWNHOST_TYPE_PLAIN: c_int = 1;
pub(crate) const LIBSSH2_KNOWNHOST_KEYENC_RAW: c_int = 1 << 16;
pub(crate) const LIBSSH2_KNOWNHOST_KEYENC_BASE64: c_int = 2 << 16;
pub(crate) const LIBSSH2_KNOWNHOST_KEY_MASK: c_int = 15 << 18;
pub(crate) const LIBSSH2_KNOWNHOST_KEY_SHIFT: c_int = 18;
pub(crate) const LIBSSH2_KNOWNHOST_KEY_RSA1: c_int = 1 << 18;
pub(crate) const LIBSSH2_KNOWNHOST_KEY_SSHRSA: c_int = 2 << 18;
pub(crate) const LIBSSH2_KNOWNHOST_KEY_SSHDSS: c_int = 3 << 18;
pub(crate) const LIBSSH2_KNOWNHOST_KEY_ECDSA_256: c_int = 4 << 18;
pub(crate) const LIBSSH2_KNOWNHOST_KEY_ECDSA_384: c_int = 5 << 18;
pub(crate) const LIBSSH2_KNOWNHOST_KEY_ECDSA_521: c_int = 6 << 18;
pub(crate) const LIBSSH2_KNOWNHOST_KEY_ED25519: c_int = 7 << 18;
pub(crate) const LIBSSH2_KNOWNHOST_CHECK_MATCH: c_int = 0;
pub(crate) const LIBSSH2_KNOWNHOST_CHECK_MISMATCH: c_int = 1;
pub(crate) const LIBSSH2_KNOWNHOST_CHECK_NOTFOUND: c_int = 2;
pub(crate) const LIBSSH2_KNOWNHOST_CHECK_FAILURE: c_int = 3;
pub(crate) const LIBSSH2_KNOWNHOST_FILE_OPENSSH: c_int = 1;

// `libssh2_sftp.h`.
pub(crate) const LIBSSH2_SFTP_OPENFILE: c_int = 0;
pub(crate) const LIBSSH2_SFTP_OPENDIR: c_int = 1;
pub(crate) const LIBSSH2_SFTP_RENAME_OVERWRITE: c_long = 0x1;
pub(crate) const LIBSSH2_SFTP_RENAME_ATOMIC: c_long = 0x2;
pub(crate) const LIBSSH2_SFTP_RENAME_NATIVE: c_long = 0x4;
pub(crate) const LIBSSH2_SFTP_STAT: c_int = 0;
pub(crate) const LIBSSH2_SFTP_SETSTAT: c_int = 2;
pub(crate) const LIBSSH2_SFTP_SYMLINK: c_int = 0;
pub(crate) const LIBSSH2_SFTP_READLINK: c_int = 1;
pub(crate) const LIBSSH2_SFTP_REALPATH: c_int = 2;
pub(crate) const LIBSSH2_SFTP_ATTR_SIZE: c_ulong = 0x1;
pub(crate) const LIBSSH2_SFTP_ATTR_UIDGID: c_ulong = 0x2;
pub(crate) const LIBSSH2_SFTP_ATTR_PERMISSIONS: c_ulong = 0x4;
pub(crate) const LIBSSH2_SFTP_ATTR_ACMODTIME: c_ulong = 0x8;
pub(crate) const LIBSSH2_FXF_READ: c_ulong = 0x1;
pub(crate) const LIBSSH2_FXF_WRITE: c_ulong = 0x2;
pub(crate) const LIBSSH2_FXF_APPEND: c_ulong = 0x4;
pub(crate) const LIBSSH2_FXF_CREAT: c_ulong = 0x8;
pub(crate) const LIBSSH2_FXF_TRUNC: c_ulong = 0x10;

// Linked by the build script, under the name each platform gives it.
unsafe extern "C" {
    pub(crate) fn libssh2_init(flags: c_int) -> c_int;
    pub(crate) fn libssh2_version(req_version_num: c_int) -> *const c_char;
    pub(crate) fn libssh2_crypto_engine() -> c_int;

    pub(crate) fn libssh2_session_init_ex(
        my_alloc: *const c_void,
        my_free: *const c_void,
        my_realloc: *const c_void,
        abstract_: *mut c_void,
    ) -> *mut LIBSSH2_SESSION;
    pub(crate) fn libssh2_session_abstract(session: *mut LIBSSH2_SESSION) -> *mut *mut c_void;
    pub(crate) fn libssh2_session_callback_set2(
        session: *mut LIBSSH2_SESSION,
        cbtype: c_int,
        callback: Option<libssh2_cb_generic>,
    ) -> Option<libssh2_cb_generic>;
    pub(crate) fn libssh2_session_set_read_timeout(session: *mut LIBSSH2_SESSION, timeout: c_long);
    pub(crate) fn libssh2_session_flag(
        session: *mut LIBSSH2_SESSION,
        flag: c_int,
        value: c_int,
    ) -> c_int;
    pub(crate) fn libssh2_session_set_blocking(session: *mut LIBSSH2_SESSION, blocking: c_int);
    pub(crate) fn libssh2_session_handshake(
        session: *mut LIBSSH2_SESSION,
        sock: libssh2_socket_t,
    ) -> c_int;
    pub(crate) fn libssh2_session_last_error(
        session: *mut LIBSSH2_SESSION,
        errmsg: *mut *mut c_char,
        errmsg_len: *mut c_int,
        want_buf: c_int,
    ) -> c_int;
    pub(crate) fn libssh2_session_last_errno(session: *mut LIBSSH2_SESSION) -> c_int;
    pub(crate) fn libssh2_session_block_directions(session: *mut LIBSSH2_SESSION) -> c_int;
    pub(crate) fn libssh2_session_hostkey(
        session: *mut LIBSSH2_SESSION,
        len: *mut usize,
        kind: *mut c_int,
    ) -> *const c_char;
    pub(crate) fn libssh2_hostkey_hash(
        session: *mut LIBSSH2_SESSION,
        hash_type: c_int,
    ) -> *const c_char;
    pub(crate) fn libssh2_session_method_pref(
        session: *mut LIBSSH2_SESSION,
        method_type: c_int,
        prefs: *const c_char,
    ) -> c_int;
    pub(crate) fn libssh2_session_disconnect_ex(
        session: *mut LIBSSH2_SESSION,
        reason: c_int,
        description: *const c_char,
        lang: *const c_char,
    ) -> c_int;
    pub(crate) fn libssh2_session_free(session: *mut LIBSSH2_SESSION) -> c_int;

    pub(crate) fn libssh2_userauth_list(
        session: *mut LIBSSH2_SESSION,
        username: *const c_char,
        username_len: c_uint,
    ) -> *mut c_char;
    pub(crate) fn libssh2_userauth_authenticated(session: *mut LIBSSH2_SESSION) -> c_int;
    pub(crate) fn libssh2_userauth_publickey_fromfile_ex(
        session: *mut LIBSSH2_SESSION,
        username: *const c_char,
        username_len: c_uint,
        publickey: *const c_char,
        privatekey: *const c_char,
        passphrase: *const c_char,
    ) -> c_int;
    pub(crate) fn libssh2_userauth_password_ex(
        session: *mut LIBSSH2_SESSION,
        username: *const c_char,
        username_len: c_uint,
        password: *const c_char,
        password_len: c_uint,
        passwd_change_cb: *const c_void,
    ) -> c_int;
    pub(crate) fn libssh2_userauth_keyboard_interactive_ex(
        session: *mut LIBSSH2_SESSION,
        username: *const c_char,
        username_len: c_uint,
        response_callback: Option<kbdint_response_func>,
    ) -> c_int;

    pub(crate) fn libssh2_knownhost_init(session: *mut LIBSSH2_SESSION) -> *mut LIBSSH2_KNOWNHOSTS;
    pub(crate) fn libssh2_knownhost_readfile(
        hosts: *mut LIBSSH2_KNOWNHOSTS,
        filename: *const c_char,
        kind: c_int,
    ) -> c_int;
    pub(crate) fn libssh2_knownhost_get(
        hosts: *mut LIBSSH2_KNOWNHOSTS,
        store: *mut *mut libssh2_knownhost,
        prev: *mut libssh2_knownhost,
    ) -> c_int;
    pub(crate) fn libssh2_knownhost_checkp(
        hosts: *mut LIBSSH2_KNOWNHOSTS,
        host: *const c_char,
        port: c_int,
        key: *const c_char,
        keylen: usize,
        typemask: c_int,
        knownhost: *mut *mut libssh2_knownhost,
    ) -> c_int;
    pub(crate) fn libssh2_knownhost_del(
        hosts: *mut LIBSSH2_KNOWNHOSTS,
        entry: *mut libssh2_knownhost,
    ) -> c_int;
    pub(crate) fn libssh2_knownhost_addc(
        hosts: *mut LIBSSH2_KNOWNHOSTS,
        host: *const c_char,
        salt: *const c_char,
        key: *const c_char,
        keylen: usize,
        comment: *const c_char,
        commentlen: usize,
        typemask: c_int,
        store: *mut *mut libssh2_knownhost,
    ) -> c_int;
    pub(crate) fn libssh2_knownhost_writefile(
        hosts: *mut LIBSSH2_KNOWNHOSTS,
        filename: *const c_char,
        kind: c_int,
    ) -> c_int;
    pub(crate) fn libssh2_knownhost_free(hosts: *mut LIBSSH2_KNOWNHOSTS);

    pub(crate) fn libssh2_agent_init(session: *mut LIBSSH2_SESSION) -> *mut LIBSSH2_AGENT;
    pub(crate) fn libssh2_agent_connect(agent: *mut LIBSSH2_AGENT) -> c_int;
    pub(crate) fn libssh2_agent_list_identities(agent: *mut LIBSSH2_AGENT) -> c_int;
    pub(crate) fn libssh2_agent_get_identity(
        agent: *mut LIBSSH2_AGENT,
        store: *mut *mut libssh2_agent_publickey,
        prev: *mut libssh2_agent_publickey,
    ) -> c_int;
    pub(crate) fn libssh2_agent_userauth(
        agent: *mut LIBSSH2_AGENT,
        username: *const c_char,
        identity: *mut libssh2_agent_publickey,
    ) -> c_int;
    pub(crate) fn libssh2_agent_disconnect(agent: *mut LIBSSH2_AGENT) -> c_int;
    pub(crate) fn libssh2_agent_free(agent: *mut LIBSSH2_AGENT);

    pub(crate) fn libssh2_scp_recv2(
        session: *mut LIBSSH2_SESSION,
        path: *const c_char,
        sb: *mut libssh2_struct_stat,
    ) -> *mut LIBSSH2_CHANNEL;
    pub(crate) fn libssh2_scp_send64(
        session: *mut LIBSSH2_SESSION,
        path: *const c_char,
        mode: c_int,
        size: i64,
        mtime: libc::time_t,
        atime: libc::time_t,
    ) -> *mut LIBSSH2_CHANNEL;
    pub(crate) fn libssh2_channel_read_ex(
        channel: *mut LIBSSH2_CHANNEL,
        stream_id: c_int,
        buf: *mut c_char,
        buflen: usize,
    ) -> isize;
    pub(crate) fn libssh2_channel_write_ex(
        channel: *mut LIBSSH2_CHANNEL,
        stream_id: c_int,
        buf: *const c_char,
        buflen: usize,
    ) -> isize;
    pub(crate) fn libssh2_channel_send_eof(channel: *mut LIBSSH2_CHANNEL) -> c_int;
    pub(crate) fn libssh2_channel_wait_eof(channel: *mut LIBSSH2_CHANNEL) -> c_int;
    pub(crate) fn libssh2_channel_wait_closed(channel: *mut LIBSSH2_CHANNEL) -> c_int;
    pub(crate) fn libssh2_channel_free(channel: *mut LIBSSH2_CHANNEL) -> c_int;

    pub(crate) fn libssh2_sftp_init(session: *mut LIBSSH2_SESSION) -> *mut LIBSSH2_SFTP;
    pub(crate) fn libssh2_sftp_shutdown(sftp: *mut LIBSSH2_SFTP) -> c_int;
    pub(crate) fn libssh2_sftp_last_error(sftp: *mut LIBSSH2_SFTP) -> c_ulong;
    pub(crate) fn libssh2_sftp_open_ex(
        sftp: *mut LIBSSH2_SFTP,
        filename: *const c_char,
        filename_len: c_uint,
        flags: c_ulong,
        mode: c_long,
        open_type: c_int,
    ) -> *mut LIBSSH2_SFTP_HANDLE;
    pub(crate) fn libssh2_sftp_read(
        handle: *mut LIBSSH2_SFTP_HANDLE,
        buffer: *mut c_char,
        buffer_maxlen: usize,
    ) -> isize;
    pub(crate) fn libssh2_sftp_readdir_ex(
        handle: *mut LIBSSH2_SFTP_HANDLE,
        buffer: *mut c_char,
        buffer_maxlen: usize,
        longentry: *mut c_char,
        longentry_maxlen: usize,
        attrs: *mut LIBSSH2_SFTP_ATTRIBUTES,
    ) -> c_int;
    pub(crate) fn libssh2_sftp_write(
        handle: *mut LIBSSH2_SFTP_HANDLE,
        buffer: *const c_char,
        count: usize,
    ) -> isize;
    pub(crate) fn libssh2_sftp_close_handle(handle: *mut LIBSSH2_SFTP_HANDLE) -> c_int;
    pub(crate) fn libssh2_sftp_seek64(handle: *mut LIBSSH2_SFTP_HANDLE, offset: u64);
    pub(crate) fn libssh2_sftp_rename_ex(
        sftp: *mut LIBSSH2_SFTP,
        source_filename: *const c_char,
        source_filename_len: c_uint,
        dest_filename: *const c_char,
        dest_filename_len: c_uint,
        flags: c_long,
    ) -> c_int;
    pub(crate) fn libssh2_sftp_unlink_ex(
        sftp: *mut LIBSSH2_SFTP,
        filename: *const c_char,
        filename_len: c_uint,
    ) -> c_int;
    pub(crate) fn libssh2_sftp_statvfs(
        sftp: *mut LIBSSH2_SFTP,
        path: *const c_char,
        path_len: usize,
        st: *mut LIBSSH2_SFTP_STATVFS,
    ) -> c_int;
    pub(crate) fn libssh2_sftp_mkdir_ex(
        sftp: *mut LIBSSH2_SFTP,
        path: *const c_char,
        path_len: c_uint,
        mode: c_long,
    ) -> c_int;
    pub(crate) fn libssh2_sftp_rmdir_ex(
        sftp: *mut LIBSSH2_SFTP,
        path: *const c_char,
        path_len: c_uint,
    ) -> c_int;
    pub(crate) fn libssh2_sftp_stat_ex(
        sftp: *mut LIBSSH2_SFTP,
        path: *const c_char,
        path_len: c_uint,
        stat_type: c_int,
        attrs: *mut LIBSSH2_SFTP_ATTRIBUTES,
    ) -> c_int;
    pub(crate) fn libssh2_sftp_symlink_ex(
        sftp: *mut LIBSSH2_SFTP,
        path: *const c_char,
        path_len: c_uint,
        target: *mut c_char,
        target_len: c_uint,
        link_type: c_int,
    ) -> c_int;
}

// The headers' values and layouts, from `csrc/layout.c`, in the order
// the tests read them.
#[cfg(test)]
unsafe extern "C" {
    pub(crate) static curl_libssh2_values: [i64; LAYOUT_LEN];
}

#[cfg(test)]
pub(crate) const LAYOUT_LEN: usize = 104;
