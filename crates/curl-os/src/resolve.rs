//! Names resolved to addresses by the system's resolver (`getaddrinfo`),
//! as C's synchronous resolver asks it (`lib/vdns/hostip4.c`,
//! `hostip6.c`): blocking until it answers, its addresses in the order it
//! gives them, each once.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use curl_alloc::{OutOfMemory, TryVec as _};

/// Which addresses to ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Any,
    V4,
    V6,
}

/// Why a name gave no addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// No such name (`EAI_NONAME`).
    NotFound,
    /// The name has no addresses of the family asked for (`EAI_NODATA`).
    NoData,
    /// The resolver could not answer now (`EAI_AGAIN`).
    Again,
    OutOfMemory,
    /// Any other way it failed.
    Failed,
}

impl From<OutOfMemory> for Failure {
    fn from(OutOfMemory: OutOfMemory) -> Self {
        Failure::OutOfMemory
    }
}

/// The addresses of `name`, of `family`.
pub fn lookup(name: &[u8], family: Family) -> Result<Vec<IpAddr>, Failure> {
    let mut text = Vec::new();
    text.try_reserve_exact(name.len() + 1)
        .map_err(|_| Failure::OutOfMemory)?;
    text.try_extend_from_slice(name)?;
    text.try_push(0)?;
    // A name with a zero byte in it is no name.
    let text = CString::from_vec_with_nul(text).map_err(|_| Failure::NotFound)?;
    // SAFETY: `addrinfo` is plain data, for which all zeroes is the empty
    // hint `getaddrinfo` expects in the fields not set.
    let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
    hints.ai_family = match family {
        Family::Any => libc::AF_UNSPEC,
        Family::V4 => libc::AF_INET,
        Family::V6 => libc::AF_INET6,
    };
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut first: *mut libc::addrinfo = ptr::null_mut();
    // SAFETY: `text` is a C string and `hints` an addrinfo, both alive
    // through the call; `first` is where it writes the list.
    let rc =
        unsafe { libc::getaddrinfo(text.as_ptr(), ptr::null(), &raw const hints, &raw mut first) };
    if rc != 0 {
        return Err(failure(rc));
    }
    let list = List(first);
    let mut addrs: Vec<IpAddr> = Vec::new();
    let mut at = list.0;
    while !at.is_null() {
        // SAFETY: a node of the list `getaddrinfo` made, which `list`
        // keeps until it is dropped.
        let node = unsafe { &*at };
        if let Some(ip) = address(node)
            && !addrs.contains(&ip)
        {
            addrs.try_push(ip)?;
        }
        at = node.ai_next;
    }
    Ok(addrs)
}

/// What a failure `getaddrinfo` returned says. Only no such name and no
/// such data are answers (as C's `gai_negative` tells them apart), which
/// the caller keeps; the resolver failing now is not.
fn failure(rc: libc::c_int) -> Failure {
    match rc {
        libc::EAI_NONAME => Failure::NotFound,
        libc::EAI_NODATA => Failure::NoData,
        libc::EAI_AGAIN => Failure::Again,
        libc::EAI_MEMORY => Failure::OutOfMemory,
        _ => Failure::Failed,
    }
}

/// The address a node holds, if of a family known here.
fn address(node: &libc::addrinfo) -> Option<IpAddr> {
    let len = usize::try_from(node.ai_addrlen).ok()?;
    if node.ai_addr.is_null() {
        return None;
    }
    match node.ai_family {
        libc::AF_INET if len >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: an AF_INET address of a sockaddr_in's length, which
            // the list keeps; read unaligned, as nothing promises more.
            let sin = unsafe { ptr::read_unaligned(node.ai_addr.cast::<libc::sockaddr_in>()) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 if len >= mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: as above, for AF_INET6 and a sockaddr_in6.
            let sin6 = unsafe { ptr::read_unaligned(node.ai_addr.cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// The list `getaddrinfo` made, freed once.
struct List(*mut libc::addrinfo);

impl Drop for List {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the list `getaddrinfo` returned, freed only here.
            unsafe { libc::freeaddrinfo(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The loopback names resolve, by family as asked; a name that cannot
    /// exist does not.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's getaddrinfo takes no family")]
    fn looks_up_names_as_the_system_knows_them() {
        let v4 = lookup(b"127.0.0.1", Family::Any).unwrap();
        assert_eq!(v4, [IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        let v6 = lookup(b"::1", Family::V6).unwrap();
        assert_eq!(v6, [IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        assert!(lookup(b"::1", Family::V4).is_err());
        let localhost = lookup(b"localhost", Family::V4).unwrap();
        assert!(localhost.iter().all(IpAddr::is_ipv4), "{localhost:?}");
        assert!(!localhost.is_empty());
        let mut seen = localhost.clone();
        seen.dedup();
        assert_eq!(seen, localhost, "each once");
        assert!(lookup(b"nonexist.invalid", Family::Any).is_err());
        assert_eq!(lookup(b"bad\0name", Family::Any), Err(Failure::NotFound));
        assert!(lookup(b"", Family::Any).is_err());
    }

    /// Each of `getaddrinfo`'s failures says what it means.
    #[test]
    fn failures_say_why() {
        for (rc, why) in [
            (libc::EAI_NONAME, Failure::NotFound),
            (libc::EAI_NODATA, Failure::NoData),
            (libc::EAI_AGAIN, Failure::Again),
            (libc::EAI_MEMORY, Failure::OutOfMemory),
            (libc::EAI_FAIL, Failure::Failed),
            (libc::EAI_SYSTEM, Failure::Failed),
        ] {
            assert_eq!(failure(rc), why, "{rc}");
        }
    }

    /// A node's address is read only when it is as long as its family's.
    #[test]
    fn a_short_address_is_none() {
        let mut sin = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(Ipv4Addr::new(192, 0, 2, 1)).to_be(),
            },
            sin_zero: [0; 8],
        };
        let mut sin6 = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: Ipv6Addr::LOCALHOST.octets(),
            },
            sin6_scope_id: 0,
        };
        let node = |family, addr: *mut libc::sockaddr, len: usize| libc::addrinfo {
            ai_flags: 0,
            ai_family: family,
            ai_socktype: libc::SOCK_STREAM,
            ai_protocol: 0,
            ai_addrlen: libc::socklen_t::try_from(len).unwrap(),
            ai_addr: addr,
            ai_canonname: ptr::null_mut(),
            ai_next: ptr::null_mut(),
        };
        let v4 = (&raw mut sin).cast::<libc::sockaddr>();
        let v6 = (&raw mut sin6).cast::<libc::sockaddr>();
        let (len4, len6) = (
            mem::size_of::<libc::sockaddr_in>(),
            mem::size_of::<libc::sockaddr_in6>(),
        );
        assert_eq!(
            address(&node(libc::AF_INET, v4, len4)),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(address(&node(libc::AF_INET, v4, len4 - 1)), None);
        assert_eq!(
            address(&node(libc::AF_INET6, v6, len6)),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(address(&node(libc::AF_INET6, v6, len6 - 1)), None);
        assert_eq!(address(&node(libc::AF_INET, ptr::null_mut(), len4)), None);
        assert_eq!(address(&node(libc::AF_UNIX, v6, len6)), None);
    }
}
