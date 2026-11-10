//! The two calls of quiche's C API the crate makes, which its Rust API
//! lacks: a connection over an SSL made elsewhere, whose ownership passes
//! to quiche (`quiche_conn_new_with_tls`), and the library's version
//! (`quiche_version`). Everything else is quiche's Rust API.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_void};
use core::ptr::NonNull;
use std::net::SocketAddr;

unsafe extern "C" {
    /// quiche's `ffi` feature's: a connection made with `config` over
    /// `ssl`, which it frees as the connection drops, or at once if it
    /// cannot make one; `Box::into_raw` of the connection, or null. The
    /// config and the connection are quiche's Rust types, passed as
    /// pointers.
    fn quiche_conn_new_with_tls(
        scid: *const u8,
        scid_len: usize,
        odcid: *const u8,
        odcid_len: usize,
        local: *const libc::sockaddr,
        local_len: libc::socklen_t,
        peer: *const libc::sockaddr,
        peer_len: libc::socklen_t,
        config: *const c_void,
        ssl: *mut c_void,
        is_server: bool,
    ) -> *mut c_void;

    /// A static C string.
    fn quiche_version() -> *const c_char;
}

/// `addr` as the socket calls take it, and its length.
fn sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: all zero bytes are a `sockaddr_storage`, an unspecified
    // address.
    let mut storage: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: the storage is aligned for and larger than any
            // address, a `sockaddr_in` among them.
            unsafe { (&raw mut storage).cast::<libc::sockaddr_in>().write(sin) };
            core::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: a.scope_id(),
            };
            // SAFETY: as above, for a `sockaddr_in6`.
            unsafe { (&raw mut storage).cast::<libc::sockaddr_in6>().write(sin6) };
            core::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    let len = libc::socklen_t::try_from(len).expect("an address's length fits");
    (storage, len)
}

/// A client connection from `local` to `peer`, of source id `scid`,
/// with `config`, over `ssl`, which quiche owns from this call on
/// whatever comes of it: it frees it as the connection drops, or at once
/// if it makes none. None if it made none.
///
/// `ssl` is an OpenSSL-family SSL the TLS session gave up
/// (`QuicheTls::give_up_session`), whose session outlives the connection:
/// only OpenSSL's sessions are handed over, their kind checked as the
/// connection is made (`Connection::client`).
pub(crate) fn connect(
    scid: &[u8],
    local: SocketAddr,
    peer: SocketAddr,
    config: &quiche::Config,
    ssl: NonNull<c_void>,
) -> Option<Box<quiche::Connection>> {
    let (local, local_len) = sockaddr(local);
    let (peer, peer_len) = sockaddr(peer);
    // SAFETY: the id and the addresses are alive for the call, each of
    // the length given; quiche copies them. `config` is a live
    // `quiche::Config`, which quiche reads. `ssl` is an OpenSSL-family
    // SSL, as the kind its library gave the session says, which no one
    // else frees: the session gave it up, and keeps the context, callbacks
    // and BIO method it uses alive until after the connection is
    // dropped (the caller holds both, the connection dropped first).
    let conn = unsafe {
        quiche_conn_new_with_tls(
            scid.as_ptr(),
            scid.len(),
            core::ptr::null(),
            0,
            (&raw const local).cast(),
            local_len,
            (&raw const peer).cast(),
            peer_len,
            core::ptr::from_ref(config).cast(),
            ssl.as_ptr(),
            false,
        )
    };
    // SAFETY: quiche returns `Box::into_raw` of a `quiche::Connection` of
    // its default buffers, the type declared above, and lets go of it:
    // the box is the connection's only owner.
    NonNull::new(conn.cast::<quiche::Connection>())
        .map(|conn| unsafe { Box::from_raw(conn.as_ptr()) })
}

/// quiche's version, as it says it: `0.30.0`.
pub(crate) fn version() -> &'static str {
    // SAFETY: no arguments; it returns a static string.
    let version = unsafe { quiche_version() };
    // SAFETY: a NUL-terminated static C string, never null.
    let version = unsafe { CStr::from_ptr(version) };
    version.to_str().expect("quiche's version is ASCII")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]

    use super::*;

    /// An address is the socket calls' of its family, its port in
    /// network order and its length that family's.
    #[test]
    fn an_address_is_laid_out_as_its_family_s() {
        let (v4, len) = sockaddr("127.0.0.1:8443".parse().unwrap());
        assert_eq!(len as usize, core::mem::size_of::<libc::sockaddr_in>());
        // SAFETY: laid out as a `sockaddr_in` above.
        let sin = unsafe { &*(&raw const v4).cast::<libc::sockaddr_in>() };
        assert_eq!(i32::from(sin.sin_family), libc::AF_INET);
        assert_eq!(u16::from_be(sin.sin_port), 8443);
        assert_eq!(sin.sin_addr.s_addr.to_ne_bytes(), [127, 0, 0, 1]);
        let (v6, len) = sockaddr("[::1]:443".parse().unwrap());
        assert_eq!(len as usize, core::mem::size_of::<libc::sockaddr_in6>());
        // SAFETY: laid out as a `sockaddr_in6` above.
        let sin6 = unsafe { &*(&raw const v6).cast::<libc::sockaddr_in6>() };
        assert_eq!(i32::from(sin6.sin6_family), libc::AF_INET6);
        assert_eq!(u16::from_be(sin6.sin6_port), 443);
        assert_eq!(
            sin6.sin6_addr.s6_addr,
            std::net::Ipv6Addr::LOCALHOST.octets()
        );
    }
}
