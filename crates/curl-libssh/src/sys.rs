//! The parts of libssh's `libssh.h` and `sftp.h` the session uses,
//! declared as libssh 0.11 and later have them (the `sftp_aio` calls).
//! `csrc/layout.c` gives the header's own values and layouts, which the
//! crate's tests compare with these.

#![allow(non_camel_case_types, dead_code)]

use core::ffi::{c_char, c_int, c_uint, c_void};

#[repr(C)]
pub(crate) struct ssh_session_struct {
    _private: [u8; 0],
}
pub(crate) type ssh_session = *mut ssh_session_struct;

#[repr(C)]
pub(crate) struct ssh_key_struct {
    _private: [u8; 0],
}
pub(crate) type ssh_key = *mut ssh_key_struct;

#[repr(C)]
pub(crate) struct ssh_scp_struct {
    _private: [u8; 0],
}
pub(crate) type ssh_scp = *mut ssh_scp_struct;

#[repr(C)]
pub(crate) struct ssh_string_struct {
    _private: [u8; 0],
}
pub(crate) type ssh_string = *mut ssh_string_struct;

#[repr(C)]
pub(crate) struct sftp_session_struct {
    _private: [u8; 0],
}
pub(crate) type sftp_session = *mut sftp_session_struct;

#[repr(C)]
pub(crate) struct sftp_file_struct {
    _private: [u8; 0],
}
pub(crate) type sftp_file = *mut sftp_file_struct;

#[repr(C)]
pub(crate) struct sftp_dir_struct {
    _private: [u8; 0],
}
pub(crate) type sftp_dir = *mut sftp_dir_struct;

#[repr(C)]
pub(crate) struct sftp_aio_struct {
    _private: [u8; 0],
}
pub(crate) type sftp_aio = *mut sftp_aio_struct;

/// `struct sftp_attributes_struct`, which the header has whole.
#[repr(C)]
pub(crate) struct sftp_attributes_struct {
    pub(crate) name: *mut c_char,
    pub(crate) longname: *mut c_char,
    pub(crate) flags: u32,
    pub(crate) r#type: u8,
    pub(crate) size: u64,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) owner: *mut c_char,
    pub(crate) group: *mut c_char,
    pub(crate) permissions: u32,
    pub(crate) atime64: u64,
    pub(crate) atime: u32,
    pub(crate) atime_nseconds: u32,
    pub(crate) createtime: u64,
    pub(crate) createtime_nseconds: u32,
    pub(crate) mtime64: u64,
    pub(crate) mtime: u32,
    pub(crate) mtime_nseconds: u32,
    pub(crate) acl: ssh_string,
    pub(crate) extended_count: u32,
    pub(crate) extended_type: ssh_string,
    pub(crate) extended_data: ssh_string,
}
pub(crate) type sftp_attributes = *mut sftp_attributes_struct;

/// `struct ssh_knownhosts_entry`, which the header has whole.
#[repr(C)]
pub(crate) struct ssh_knownhosts_entry {
    pub(crate) hostname: *mut c_char,
    pub(crate) unparsed: *mut c_char,
    pub(crate) publickey: ssh_key,
    pub(crate) comment: *mut c_char,
}

/// `mode_t` on Linux.
pub(crate) type mode_t = c_uint;

// `SSH_OK`, `SSH_ERROR`, `SSH_AGAIN`.
pub(crate) const SSH_OK: c_int = 0;
pub(crate) const SSH_ERROR: c_int = -1;
pub(crate) const SSH_AGAIN: c_int = -2;

// `enum ssh_auth_e`.
pub(crate) const SSH_AUTH_SUCCESS: c_int = 0;
pub(crate) const SSH_AUTH_DENIED: c_int = 1;
pub(crate) const SSH_AUTH_PARTIAL: c_int = 2;
pub(crate) const SSH_AUTH_INFO: c_int = 3;
pub(crate) const SSH_AUTH_AGAIN: c_int = 4;
pub(crate) const SSH_AUTH_ERROR: c_int = -1;

// `enum ssh_options_e`.
pub(crate) const SSH_OPTIONS_HOST: c_int = 0;
pub(crate) const SSH_OPTIONS_PORT: c_int = 1;
pub(crate) const SSH_OPTIONS_FD: c_int = 3;
pub(crate) const SSH_OPTIONS_USER: c_int = 4;
pub(crate) const SSH_OPTIONS_KNOWNHOSTS: c_int = 8;
pub(crate) const SSH_OPTIONS_COMPRESSION: c_int = 22;
pub(crate) const SSH_OPTIONS_GLOBAL_KNOWNHOSTS: c_int = 35;

// `ssh_get_poll_flags`'s bits.
pub(crate) const SSH_READ_PENDING: c_int = 0x02;
pub(crate) const SSH_WRITE_PENDING: c_int = 0x08;

// `enum ssh_known_hosts_e`.
pub(crate) const SSH_KNOWN_HOSTS_ERROR: c_int = -2;
pub(crate) const SSH_KNOWN_HOSTS_NOT_FOUND: c_int = -1;
pub(crate) const SSH_KNOWN_HOSTS_UNKNOWN: c_int = 0;
pub(crate) const SSH_KNOWN_HOSTS_OK: c_int = 1;
pub(crate) const SSH_KNOWN_HOSTS_CHANGED: c_int = 2;
pub(crate) const SSH_KNOWN_HOSTS_OTHER: c_int = 3;

// `enum ssh_keytypes_e`, the ones curl names.
pub(crate) const SSH_KEYTYPE_DSS: c_int = 1;
pub(crate) const SSH_KEYTYPE_RSA: c_int = 2;
pub(crate) const SSH_KEYTYPE_RSA1: c_int = 3;
pub(crate) const SSH_KEYTYPE_ECDSA: c_int = 4;
pub(crate) const SSH_KEYTYPE_ED25519: c_int = 5;
pub(crate) const SSH_KEYTYPE_ECDSA_P256: c_int = 8;
pub(crate) const SSH_KEYTYPE_ECDSA_P384: c_int = 9;
pub(crate) const SSH_KEYTYPE_ECDSA_P521: c_int = 10;

// `enum ssh_publickey_hash_type`.
pub(crate) const SSH_PUBLICKEY_HASH_MD5: c_int = 1;
pub(crate) const SSH_PUBLICKEY_HASH_SHA256: c_int = 2;

// `enum ssh_scp_request_types` and the modes of `ssh_scp_new`.
pub(crate) const SSH_SCP_WRITE: c_int = 0;
pub(crate) const SSH_SCP_READ: c_int = 1;
pub(crate) const SSH_SCP_REQUEST_NEWFILE: c_int = 2;

// `open(2)`'s flags, as `sftp_open` takes them.
pub(crate) const O_RDONLY: c_int = 0;
pub(crate) const O_WRONLY: c_int = 1;
pub(crate) const O_CREAT: c_int = 0o100;
pub(crate) const O_TRUNC: c_int = 0o1000;
pub(crate) const O_APPEND: c_int = 0o2000;

// `SSH_FILEXFER_ATTR_*` read of what the server gave, and set by the changes.
pub(crate) const SSH_FILEXFER_ATTR_SIZE: u32 = 0x0000_0001;
pub(crate) const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x0000_0002;
pub(crate) const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x0000_0004;
pub(crate) const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x0000_0008;

#[link(name = "ssh")]
unsafe extern "C" {
    pub(crate) fn ssh_version(req_version: c_int) -> *const c_char;
    pub(crate) fn ssh_new() -> ssh_session;
    pub(crate) fn ssh_free(session: ssh_session);
    pub(crate) fn ssh_options_set(session: ssh_session, kind: c_int, value: *const c_void)
    -> c_int;
    pub(crate) fn ssh_options_parse_config(session: ssh_session, filename: *const c_char) -> c_int;
    pub(crate) fn ssh_set_blocking(session: ssh_session, blocking: c_int);
    pub(crate) fn ssh_get_poll_flags(session: ssh_session) -> c_int;
    pub(crate) fn ssh_get_error(error: *mut c_void) -> *const c_char;
    pub(crate) fn ssh_connect(session: ssh_session) -> c_int;
    pub(crate) fn ssh_disconnect(session: ssh_session);
    pub(crate) fn ssh_get_fd(session: ssh_session) -> c_int;
    pub(crate) fn ssh_get_server_publickey(session: ssh_session, key: *mut ssh_key) -> c_int;
    pub(crate) fn ssh_get_publickey_hash(
        key: ssh_key,
        kind: c_int,
        hash: *mut *mut u8,
        hlen: *mut usize,
    ) -> c_int;
    pub(crate) fn ssh_clean_pubkey_hash(hash: *mut *mut u8);
    pub(crate) fn ssh_pki_export_pubkey_base64(key: ssh_key, b64_key: *mut *mut c_char) -> c_int;
    pub(crate) fn ssh_key_type(key: ssh_key) -> c_int;
    pub(crate) fn ssh_key_free(key: ssh_key);
    pub(crate) fn ssh_session_get_known_hosts_entry(
        session: ssh_session,
        pentry: *mut *mut ssh_knownhosts_entry,
    ) -> c_int;
    pub(crate) fn ssh_knownhosts_entry_free(entry: *mut ssh_knownhosts_entry);
    pub(crate) fn ssh_session_update_known_hosts(session: ssh_session) -> c_int;
    pub(crate) fn ssh_pki_import_privkey_file(
        filename: *const c_char,
        passphrase: *const c_char,
        auth_fn: *const c_void,
        auth_data: *mut c_void,
        pkey: *mut ssh_key,
    ) -> c_int;
    pub(crate) fn ssh_pki_import_pubkey_file(filename: *const c_char, pkey: *mut ssh_key) -> c_int;
    pub(crate) fn ssh_userauth_none(session: ssh_session, username: *const c_char) -> c_int;
    pub(crate) fn ssh_userauth_list(session: ssh_session, username: *const c_char) -> c_int;
    pub(crate) fn ssh_userauth_try_publickey(
        session: ssh_session,
        username: *const c_char,
        pubkey: ssh_key,
    ) -> c_int;
    pub(crate) fn ssh_userauth_publickey(
        session: ssh_session,
        username: *const c_char,
        privkey: ssh_key,
    ) -> c_int;
    pub(crate) fn ssh_userauth_publickey_auto(
        session: ssh_session,
        username: *const c_char,
        passphrase: *const c_char,
    ) -> c_int;
    pub(crate) fn ssh_userauth_password(
        session: ssh_session,
        username: *const c_char,
        password: *const c_char,
    ) -> c_int;
    pub(crate) fn ssh_userauth_kbdint(
        session: ssh_session,
        user: *const c_char,
        submethods: *const c_char,
    ) -> c_int;
    pub(crate) fn ssh_userauth_kbdint_getnprompts(session: ssh_session) -> c_int;
    pub(crate) fn ssh_userauth_kbdint_setanswer(
        session: ssh_session,
        i: c_uint,
        answer: *const c_char,
    ) -> c_int;
    pub(crate) fn ssh_userauth_gssapi(session: ssh_session) -> c_int;
    pub(crate) fn ssh_string_free_char(s: *mut c_char);

    pub(crate) fn ssh_scp_new(
        session: ssh_session,
        mode: c_int,
        location: *const c_char,
    ) -> ssh_scp;
    pub(crate) fn ssh_scp_init(scp: ssh_scp) -> c_int;
    pub(crate) fn ssh_scp_push_file64(
        scp: ssh_scp,
        filename: *const c_char,
        size: u64,
        perms: c_int,
    ) -> c_int;
    pub(crate) fn ssh_scp_pull_request(scp: ssh_scp) -> c_int;
    pub(crate) fn ssh_scp_request_get_size64(scp: ssh_scp) -> u64;
    pub(crate) fn ssh_scp_read(scp: ssh_scp, buffer: *mut c_void, size: usize) -> c_int;
    pub(crate) fn ssh_scp_write(scp: ssh_scp, buffer: *const c_void, len: usize) -> c_int;
    pub(crate) fn ssh_scp_close(scp: ssh_scp) -> c_int;
    pub(crate) fn ssh_scp_free(scp: ssh_scp);

    pub(crate) fn sftp_new(session: ssh_session) -> sftp_session;
    pub(crate) fn sftp_free(sftp: sftp_session);
    pub(crate) fn sftp_init(sftp: sftp_session) -> c_int;
    pub(crate) fn sftp_get_error(sftp: sftp_session) -> c_int;
    pub(crate) fn sftp_canonicalize_path(sftp: sftp_session, path: *const c_char) -> *mut c_char;
    pub(crate) fn sftp_opendir(sftp: sftp_session, path: *const c_char) -> sftp_dir;
    pub(crate) fn sftp_readdir(sftp: sftp_session, dir: sftp_dir) -> sftp_attributes;
    pub(crate) fn sftp_dir_eof(dir: sftp_dir) -> c_int;
    pub(crate) fn sftp_closedir(dir: sftp_dir) -> c_int;
    pub(crate) fn sftp_stat(sftp: sftp_session, path: *const c_char) -> sftp_attributes;
    pub(crate) fn sftp_lstat(sftp: sftp_session, path: *const c_char) -> sftp_attributes;
    pub(crate) fn sftp_fstat(file: sftp_file) -> sftp_attributes;
    pub(crate) fn sftp_attributes_free(attrs: sftp_attributes);
    pub(crate) fn sftp_readlink(sftp: sftp_session, path: *const c_char) -> *mut c_char;
    pub(crate) fn sftp_setstat(
        sftp: sftp_session,
        file: *const c_char,
        attr: sftp_attributes,
    ) -> c_int;
    pub(crate) fn sftp_symlink(
        sftp: sftp_session,
        target: *const c_char,
        dest: *const c_char,
    ) -> c_int;
    pub(crate) fn sftp_mkdir(sftp: sftp_session, directory: *const c_char, mode: mode_t) -> c_int;
    pub(crate) fn sftp_rename(
        sftp: sftp_session,
        original: *const c_char,
        newname: *const c_char,
    ) -> c_int;
    pub(crate) fn sftp_rmdir(sftp: sftp_session, directory: *const c_char) -> c_int;
    pub(crate) fn sftp_unlink(sftp: sftp_session, file: *const c_char) -> c_int;
    pub(crate) fn sftp_open(
        sftp: sftp_session,
        file: *const c_char,
        accesstype: c_int,
        mode: mode_t,
    ) -> sftp_file;
    pub(crate) fn sftp_close(file: sftp_file) -> c_int;
    pub(crate) fn sftp_seek64(file: sftp_file, new_offset: u64) -> c_int;
    pub(crate) fn sftp_file_set_nonblocking(file: sftp_file);
    pub(crate) fn sftp_aio_begin_read(file: sftp_file, len: usize, aio: *mut sftp_aio) -> isize;
    pub(crate) fn sftp_aio_wait_read(
        aio: *mut sftp_aio,
        buf: *mut c_void,
        buf_size: usize,
    ) -> isize;
    pub(crate) fn sftp_aio_begin_write(
        file: sftp_file,
        buf: *const c_void,
        len: usize,
        aio: *mut sftp_aio,
    ) -> isize;
    pub(crate) fn sftp_aio_wait_write(aio: *mut sftp_aio) -> isize;
    pub(crate) fn sftp_aio_free(aio: sftp_aio);
}

unsafe extern "C" {
    /// The C library's, which frees what `ssh_pki_export_pubkey_base64`
    /// allocates.
    pub(crate) fn free(p: *mut c_void);
    #[cfg(test)]
    pub(crate) fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    pub(crate) fn close(fd: c_int) -> c_int;
}

// The headers' values and layouts, from `csrc/layout.c`, in the order
// the tests read them.
#[cfg(test)]
unsafe extern "C" {
    pub(crate) static curl_libssh_values: [i64; LAYOUT_LEN];
}

#[cfg(test)]
pub(crate) const LAYOUT_LEN: usize = 75;
