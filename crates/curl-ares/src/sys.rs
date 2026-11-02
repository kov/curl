//! The functions of c-ares this crate calls, and the types they take.
#![allow(unsafe_code)]

use core::ffi::{c_char, c_int, c_uint, c_ushort, c_void};

/// `ares_channel_t`.
#[repr(C)]
pub struct Channel {
    _opaque: [u8; 0],
}

/// `ares_dns_record_t`.
#[repr(C)]
pub struct DnsRecord {
    _opaque: [u8; 0],
}

/// `ares_dns_rr_t`.
#[repr(C)]
pub struct DnsRr {
    _opaque: [u8; 0],
}

pub const SUCCESS: c_int = 0;
pub const ENODATA: c_int = 1;
pub const ENOTFOUND: c_int = 4;
pub const ENOMEM: c_int = 15;

pub const LIB_INIT_ALL: c_int = 1;
pub const OPT_SOCK_STATE_CB: c_int = 1 << 9;
pub const AI_NUMERICSERV: c_int = 1 << 3;
pub const GETSOCK_MAXNUM: usize = 16;
pub const SOCKET_BAD: c_int = -1;

pub const CLASS_IN: c_int = 1;
pub const REC_TYPE_HTTPS: c_int = 65;
pub const SECTION_ANSWER: c_int = 1;
pub const RR_HTTPS_PRIORITY: c_int = 65 * 100 + 1;
pub const RR_HTTPS_TARGET: c_int = 65 * 100 + 2;
pub const RR_HTTPS_PARAMS: c_int = 65 * 100 + 3;

pub type SockStateCb =
    unsafe extern "C" fn(data: *mut c_void, fd: c_int, readable: c_int, writable: c_int);
pub type AddrinfoCb =
    unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, ai: *mut Addrinfo);
pub type DnsrecCb = unsafe extern "C" fn(
    arg: *mut c_void,
    status: c_int,
    timeouts: usize,
    dnsrec: *const DnsRecord,
);

/// `struct ares_server_failover_options`.
#[repr(C)]
pub struct ServerFailover {
    pub retry_chance: c_ushort,
    pub retry_delay: usize,
}

/// `struct ares_options`: only what its mask names is read.
#[repr(C)]
pub struct Options {
    pub flags: c_int,
    pub timeout: c_int,
    pub tries: c_int,
    pub ndots: c_int,
    pub udp_port: c_ushort,
    pub tcp_port: c_ushort,
    pub socket_send_buffer_size: c_int,
    pub socket_receive_buffer_size: c_int,
    pub servers: *mut c_void,
    pub nservers: c_int,
    pub domains: *mut *mut c_char,
    pub ndomains: c_int,
    pub lookups: *mut c_char,
    pub sock_state_cb: Option<SockStateCb>,
    pub sock_state_cb_data: *mut c_void,
    pub sortlist: *mut c_void,
    pub nsort: c_int,
    pub ednspsz: c_int,
    pub resolvconf_path: *mut c_char,
    pub hosts_path: *mut c_char,
    pub udp_max_queries: c_int,
    pub maxtimeout: c_int,
    pub qcache_max_ttl: c_uint,
    pub evsys: c_int,
    pub server_failover_opts: ServerFailover,
}

/// `struct ares_addrinfo_hints`.
#[repr(C)]
pub struct Hints {
    pub ai_flags: c_int,
    pub ai_family: c_int,
    pub ai_socktype: c_int,
    pub ai_protocol: c_int,
}

/// `struct ares_addrinfo_node`.
#[repr(C)]
pub struct AddrinfoNode {
    pub ai_ttl: c_int,
    pub ai_flags: c_int,
    pub ai_family: c_int,
    pub ai_socktype: c_int,
    pub ai_protocol: c_int,
    pub ai_addrlen: c_uint,
    pub ai_addr: *const libc::sockaddr,
    pub ai_next: *const AddrinfoNode,
}

/// `struct ares_addrinfo`.
#[repr(C)]
pub struct Addrinfo {
    pub cnames: *mut c_void,
    pub nodes: *const AddrinfoNode,
    pub name: *mut c_char,
}

unsafe extern "C" {
    pub fn ares_library_init(flags: c_int) -> c_int;
    pub fn ares_version(version: *mut c_int) -> *const c_char;
    pub fn ares_strerror(code: c_int) -> *const c_char;
    pub fn ares_init_options(
        channel: *mut *mut Channel,
        options: *const Options,
        optmask: c_int,
    ) -> c_int;
    pub fn ares_destroy(channel: *mut Channel);
    pub fn ares_set_servers_ports_csv(channel: *mut Channel, servers: *const c_char) -> c_int;
    pub fn ares_get_servers_csv(channel: *const Channel) -> *mut c_char;
    pub fn ares_free_string(string: *mut c_void);
    pub fn ares_set_local_dev(channel: *mut Channel, name: *const c_char);
    pub fn ares_set_local_ip4(channel: *mut Channel, ip: c_uint);
    pub fn ares_set_local_ip6(channel: *mut Channel, ip: *const u8);
    pub fn ares_getaddrinfo(
        channel: *mut Channel,
        node: *const c_char,
        service: *const c_char,
        hints: *const Hints,
        callback: AddrinfoCb,
        arg: *mut c_void,
    );
    pub fn ares_freeaddrinfo(ai: *mut Addrinfo);
    pub fn ares_query_dnsrec(
        channel: *mut Channel,
        name: *const c_char,
        class: c_int,
        kind: c_int,
        callback: DnsrecCb,
        arg: *mut c_void,
        qid: *mut c_ushort,
    ) -> c_int;
    pub fn ares_getsock(channel: *const Channel, socks: *mut c_int, count: c_int) -> c_int;
    pub fn ares_process_fd(channel: *mut Channel, read: c_int, write: c_int);
    pub fn ares_timeout(
        channel: *const Channel,
        max: *const libc::timeval,
        out: *mut libc::timeval,
    ) -> *mut libc::timeval;
    pub fn ares_dns_record_rr_cnt(record: *const DnsRecord, section: c_int) -> usize;
    pub fn ares_dns_record_rr_get_const(
        record: *const DnsRecord,
        section: c_int,
        index: usize,
    ) -> *const DnsRr;
    pub fn ares_dns_rr_get_type(rr: *const DnsRr) -> c_int;
    pub fn ares_dns_rr_get_str(rr: *const DnsRr, key: c_int) -> *const c_char;
    pub fn ares_dns_rr_get_u16(rr: *const DnsRr, key: c_int) -> c_ushort;
    pub fn ares_dns_rr_get_opt_cnt(rr: *const DnsRr, key: c_int) -> usize;
    pub fn ares_dns_rr_get_opt(
        rr: *const DnsRr,
        key: c_int,
        index: usize,
        value: *mut *const u8,
        length: *mut usize,
    ) -> c_ushort;
}
