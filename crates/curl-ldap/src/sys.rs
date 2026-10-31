//! The parts of libldap's `ldap.h` and liblber's `lber.h` the session
//! uses, and the two calls of libldap's own the headers keep private
//! (`ldap_pvt_url_scheme2proto`, `ldap_init_fd`), declared as
//! `lib/openldap.c` declares them. `csrc/layout.c` gives the headers' own
//! values and layouts, which the crate's tests compare with these.

#![allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

pub(crate) type ber_len_t = c_ulong;
pub(crate) type ber_slen_t = c_long;
pub(crate) type ber_socket_t = c_int;

#[repr(C)]
pub(crate) struct LDAP {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct LDAPMessage {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct BerElement {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct Sockbuf {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct LDAPControl {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct berval {
    pub(crate) bv_len: ber_len_t,
    pub(crate) bv_val: *mut c_char,
}

#[repr(C)]
pub(crate) struct timeval {
    pub(crate) tv_sec: c_long,
    pub(crate) tv_usec: c_long,
}

#[repr(C)]
pub(crate) struct LDAPURLDesc {
    pub(crate) lud_next: *mut LDAPURLDesc,
    pub(crate) lud_scheme: *mut c_char,
    pub(crate) lud_host: *mut c_char,
    pub(crate) lud_port: c_int,
    pub(crate) lud_dn: *mut c_char,
    pub(crate) lud_attrs: *mut *mut c_char,
    pub(crate) lud_scope: c_int,
    pub(crate) lud_filter: *mut c_char,
    pub(crate) lud_exts: *mut *mut c_char,
    pub(crate) lud_crit_exts: c_int,
}

#[repr(C)]
pub(crate) struct LDAPAPIInfo {
    pub(crate) ldapai_info_version: c_int,
    pub(crate) ldapai_api_version: c_int,
    pub(crate) ldapai_protocol_version: c_int,
    pub(crate) ldapai_extensions: *mut *mut c_char,
    pub(crate) ldapai_vendor_name: *mut c_char,
    pub(crate) ldapai_vendor_version: c_int,
}

#[repr(C)]
pub(crate) struct Sockbuf_IO_Desc {
    pub(crate) sbiod_level: c_int,
    pub(crate) sbiod_sb: *mut Sockbuf,
    pub(crate) sbiod_io: *mut Sockbuf_IO,
    pub(crate) sbiod_pvt: *mut c_void,
    pub(crate) sbiod_next: *mut Sockbuf_IO_Desc,
}

#[repr(C)]
pub(crate) struct Sockbuf_IO {
    pub(crate) sbi_setup: unsafe extern "C" fn(*mut Sockbuf_IO_Desc, *mut c_void) -> c_int,
    pub(crate) sbi_remove: unsafe extern "C" fn(*mut Sockbuf_IO_Desc) -> c_int,
    pub(crate) sbi_ctrl: unsafe extern "C" fn(*mut Sockbuf_IO_Desc, c_int, *mut c_void) -> c_int,
    pub(crate) sbi_read:
        unsafe extern "C" fn(*mut Sockbuf_IO_Desc, *mut c_void, ber_len_t) -> ber_slen_t,
    pub(crate) sbi_write:
        unsafe extern "C" fn(*mut Sockbuf_IO_Desc, *mut c_void, ber_len_t) -> ber_slen_t,
    pub(crate) sbi_close: unsafe extern "C" fn(*mut Sockbuf_IO_Desc) -> c_int,
}

pub(crate) const LDAP_SUCCESS: c_int = 0x00;
pub(crate) const LDAP_OPT_SUCCESS: c_int = 0;
pub(crate) const LDAP_OPT_API_INFO: c_int = 0x0000;
pub(crate) const LDAP_OPT_REFERRALS: c_int = 0x0008;
pub(crate) const LDAP_OPT_PROTOCOL_VERSION: c_int = 0x0011;
pub(crate) const LDAP_OPT_SOCKBUF: c_int = 0x5008;
pub(crate) const LDAP_API_INFO_VERSION: c_int = 1;
pub(crate) const LDAP_MSG_ONE: c_int = 0x00;
pub(crate) const LDAP_RES_BIND: c_int = 0x61;
pub(crate) const LDAP_RES_SEARCH_ENTRY: c_int = 0x64;
pub(crate) const LDAP_RES_SEARCH_REFERENCE: c_int = 0x73;
pub(crate) const LDAP_RES_SEARCH_RESULT: c_int = 0x65;
pub(crate) const LDAP_RES_EXTENDED: c_int = 0x78;
pub(crate) const LBER_SB_OPT_DATA_READY: c_int = 8;
pub(crate) const LBER_SB_OPT_SET_MAX_INCOMING: c_int = 14;
pub(crate) const LBER_SBIOD_LEVEL_TRANSPORT: c_int = 20;
pub(crate) const LDAP_URL_SUCCESS: c_int = 0x00;
pub(crate) const LDAP_URL_ERR_MEM: c_int = 0x01;

#[link(name = "ldap")]
unsafe extern "C" {
    pub(crate) fn ldap_url_parse(url: *const c_char, ludpp: *mut *mut LDAPURLDesc) -> c_int;
    pub(crate) fn ldap_free_urldesc(ludp: *mut LDAPURLDesc);
    pub(crate) fn ldap_pvt_url_scheme2proto(scheme: *const c_char) -> c_int;
    pub(crate) fn ldap_init_fd(
        fd: ber_socket_t,
        proto: c_int,
        url: *const c_char,
        ld: *mut *mut LDAP,
    ) -> c_int;
    pub(crate) fn ldap_err2string(err: c_int) -> *mut c_char;
    pub(crate) fn ldap_set_option(ld: *mut LDAP, option: c_int, invalue: *const c_void) -> c_int;
    pub(crate) fn ldap_get_option(ld: *mut LDAP, option: c_int, outvalue: *mut c_void) -> c_int;
    pub(crate) fn ldap_sasl_bind(
        ld: *mut LDAP,
        dn: *const c_char,
        mechanism: *const c_char,
        cred: *mut berval,
        sctrls: *mut *mut LDAPControl,
        cctrls: *mut *mut LDAPControl,
        msgidp: *mut c_int,
    ) -> c_int;
    pub(crate) fn ldap_search_ext(
        ld: *mut LDAP,
        base: *const c_char,
        scope: c_int,
        filter: *const c_char,
        attrs: *mut *mut c_char,
        attrsonly: c_int,
        sctrls: *mut *mut LDAPControl,
        cctrls: *mut *mut LDAPControl,
        timeout: *mut timeval,
        sizelimit: c_int,
        msgidp: *mut c_int,
    ) -> c_int;
    pub(crate) fn ldap_start_tls(
        ld: *mut LDAP,
        sctrls: *mut *mut LDAPControl,
        cctrls: *mut *mut LDAPControl,
        msgidp: *mut c_int,
    ) -> c_int;
    pub(crate) fn ldap_result(
        ld: *mut LDAP,
        msgid: c_int,
        all: c_int,
        timeout: *mut timeval,
        result: *mut *mut LDAPMessage,
    ) -> c_int;
    pub(crate) fn ldap_msgtype(lm: *mut LDAPMessage) -> c_int;
    pub(crate) fn ldap_msgfree(lm: *mut LDAPMessage) -> c_int;
    pub(crate) fn ldap_parse_result(
        ld: *mut LDAP,
        res: *mut LDAPMessage,
        errcodep: *mut c_int,
        matcheddnp: *mut *mut c_char,
        diagmsgp: *mut *mut c_char,
        referralsp: *mut *mut *mut c_char,
        serverctrls: *mut *mut *mut LDAPControl,
        freeit: c_int,
    ) -> c_int;
    pub(crate) fn ldap_parse_sasl_bind_result(
        ld: *mut LDAP,
        res: *mut LDAPMessage,
        servercredp: *mut *mut berval,
        freeit: c_int,
    ) -> c_int;
    pub(crate) fn ldap_get_dn_ber(
        ld: *mut LDAP,
        e: *mut LDAPMessage,
        berout: *mut *mut BerElement,
        dn: *mut berval,
    ) -> c_int;
    pub(crate) fn ldap_get_attribute_ber(
        ld: *mut LDAP,
        e: *mut LDAPMessage,
        ber: *mut BerElement,
        attr: *mut berval,
        vals: *mut *mut berval,
    ) -> c_int;
    pub(crate) fn ldap_memfree(p: *mut c_void);
    pub(crate) fn ldap_abandon_ext(
        ld: *mut LDAP,
        msgid: c_int,
        sctrls: *mut *mut LDAPControl,
        cctrls: *mut *mut LDAPControl,
    ) -> c_int;
    pub(crate) fn ldap_unbind_ext(
        ld: *mut LDAP,
        sctrls: *mut *mut LDAPControl,
        cctrls: *mut *mut LDAPControl,
    ) -> c_int;
}

#[link(name = "lber")]
unsafe extern "C" {
    pub(crate) fn ber_sockbuf_ctrl(sb: *mut Sockbuf, opt: c_int, arg: *mut c_void) -> c_int;
    pub(crate) fn ber_sockbuf_add_io(
        sb: *mut Sockbuf,
        sbio: *mut Sockbuf_IO,
        layer: c_int,
        arg: *mut c_void,
    ) -> c_int;
    pub(crate) fn ber_free(ber: *mut BerElement, freebuf: c_int);
    pub(crate) fn ber_memfree(p: *mut c_void);
    pub(crate) fn ber_memvfree(vector: *mut *mut c_void);
    pub(crate) fn ber_bvfree(bv: *mut berval);
}

unsafe extern "C" {
    /// The C library's: where the calling thread's `errno` is, which a
    /// layer's read or write sets as the library expects.
    pub(crate) fn __errno_location() -> *mut c_int;
}

unsafe extern "C" {
    pub(crate) static curl_ldap_values: [i64; LAYOUT_LEN];
}

/// How many values and layouts `csrc/layout.c` gives.
pub(crate) const LAYOUT_LEN: usize = 55;
