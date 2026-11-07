//! The functions of c-ares this crate calls, and the types they take.
#![allow(unsafe_code)]

use core::ffi::{c_char, c_int, c_uint, c_ushort, c_void};
use std::net::{Ipv4Addr, Ipv6Addr};

pub use platform::*;

/// `ares_socket_t`: a descriptor on Unix, a Winsock `SOCKET` on Windows,
/// as `curl_socket_t` is in C's build.
pub type AresSocket = curl_os::socket::RawSocket;

/// The system's socket types and numbers c-ares takes and hands back.
#[cfg(unix)]
mod platform {
    pub use libc::{
        AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM, sockaddr as Sockaddr, timeval as Timeval,
    };
    /// A `timeval`'s fields.
    pub type Seconds = libc::time_t;
    pub type Micros = libc::suseconds_t;

    /// `ARES_SOCKET_BAD`.
    pub const SOCKET_BAD: super::AresSocket = -1;

    /// The address of an `AF_INET` socket address.
    ///
    /// # Safety
    /// `sa` points to a `sockaddr_in`, alive for the call.
    pub unsafe fn v4(sa: *const Sockaddr) -> super::Ipv4Addr {
        // SAFETY: as the caller says.
        let sa = unsafe { &*sa.cast::<libc::sockaddr_in>() };
        super::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))
    }

    /// The address of an `AF_INET6` socket address.
    ///
    /// # Safety
    /// `sa` points to a `sockaddr_in6`, alive for the call.
    pub unsafe fn v6(sa: *const Sockaddr) -> super::Ipv6Addr {
        // SAFETY: as the caller says.
        let sa = unsafe { &*sa.cast::<libc::sockaddr_in6>() };
        super::Ipv6Addr::from(sa.sin6_addr.s6_addr)
    }
}

#[cfg(windows)]
mod platform {
    use core::ffi::c_int;
    use windows_sys::Win32::Networking::WinSock as ws;

    pub use ws::{SOCKADDR as Sockaddr, TIMEVAL as Timeval};
    /// A `timeval`'s fields, Winsock's `long`s.
    pub type Seconds = i32;
    pub type Micros = i32;

    pub const AF_INET: c_int = ws::AF_INET as c_int;
    pub const AF_INET6: c_int = ws::AF_INET6 as c_int;
    pub const SOCK_STREAM: c_int = ws::SOCK_STREAM;
    pub const SOCK_DGRAM: c_int = ws::SOCK_DGRAM;

    /// `ARES_SOCKET_BAD`, `INVALID_SOCKET`.
    pub const SOCKET_BAD: super::AresSocket = super::AresSocket::MAX;

    // `SOCKET` is pointer-sized; a `RawSocket` stands in for it only where
    // the two are one width, as on the 64-bit Windows the rewrite targets.
    const _: () = assert!(size_of::<super::AresSocket>() == size_of::<ws::SOCKET>());

    /// The address of an `AF_INET` socket address.
    ///
    /// # Safety
    /// `sa` points to a `SOCKADDR_IN`, alive for the call.
    pub unsafe fn v4(sa: *const Sockaddr) -> super::Ipv4Addr {
        // SAFETY: as the caller says.
        let sa = unsafe { &*sa.cast::<ws::SOCKADDR_IN>() };
        // SAFETY: every field of the union is the address's four bytes.
        let raw = unsafe { sa.sin_addr.S_un.S_addr };
        super::Ipv4Addr::from(u32::from_be(raw))
    }

    /// The address of an `AF_INET6` socket address.
    ///
    /// # Safety
    /// `sa` points to a `SOCKADDR_IN6`, alive for the call.
    pub unsafe fn v6(sa: *const Sockaddr) -> super::Ipv6Addr {
        // SAFETY: as the caller says.
        let sa = unsafe { &*sa.cast::<ws::SOCKADDR_IN6>() };
        // SAFETY: every field of the union is the address's sixteen bytes.
        let raw = unsafe { sa.sin6_addr.u.Byte };
        super::Ipv6Addr::from(raw)
    }
}

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

pub const CLASS_IN: c_int = 1;
pub const REC_TYPE_HTTPS: c_int = 65;
pub const SECTION_ANSWER: c_int = 1;
pub const RR_HTTPS_PRIORITY: c_int = 65 * 100 + 1;
pub const RR_HTTPS_TARGET: c_int = 65 * 100 + 2;
pub const RR_HTTPS_PARAMS: c_int = 65 * 100 + 3;

pub type SockStateCb =
    unsafe extern "C" fn(data: *mut c_void, fd: AresSocket, readable: c_int, writable: c_int);
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
    pub ai_addr: *const Sockaddr,
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
    pub fn ares_getsock(channel: *const Channel, socks: *mut AresSocket, count: c_int) -> c_int;
    pub fn ares_process_fd(channel: *mut Channel, read: AresSocket, write: AresSocket);
    pub fn ares_timeout(
        channel: *const Channel,
        max: *const Timeval,
        out: *mut Timeval,
    ) -> *mut Timeval;
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
    /// A message's bytes read into a record, for the tests to hand over
    /// as c-ares would.
    #[cfg(test)]
    pub fn ares_dns_parse(
        buf: *const u8,
        length: usize,
        flags: c_uint,
        record: *mut *mut DnsRecord,
    ) -> c_int;
    #[cfg(test)]
    pub fn ares_dns_record_destroy(record: *mut DnsRecord);
}
