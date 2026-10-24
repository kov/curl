//! The application's socket functions behind the core's socket handlers
//! (`CURLOPT_OPENSOCKETFUNCTION`, `CURLOPT_SOCKOPTFUNCTION`,
//! `CURLOPT_CLOSESOCKETFUNCTION` and their data, `lib/cf-socket.c`).
//!
//! The opener and the configurer read the function and data the
//! application set at the moment they call, through the handle, as the
//! other adapters do. The closer is kept by each connection the handle
//! makes and may close its sockets after the handle is gone, so it holds
//! the function and data it was made with, as C copies them onto the
//! connection (url.c's `fclosesocket`).

#![allow(unsafe_code)]

use core::ffi::{c_int, c_uint, c_void};
use core::ptr::NonNull;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use curl_alloc::{OutOfMemory, try_box};
use curl_core::conn::io::{Remote, Socket, SocketKey};
use curl_core::handler::{
    Configured, Handler, SocketCloser, SocketConfigurer, SocketOpener, SocketToSet,
};
use curl_core::multi::TransferCx;
use curl_core::options::Options;

use crate::callbacks::Adapter;
use crate::easy::ShimEasy;
use crate::ffi::{
    self, CURL_SOCKET_BAD, CURL_SOCKOPT_ALREADY_CONNECTED, CURL_SOCKOPT_OK, CURLSOCKTYPE_IPCXN,
    curl_closesocket_callback, curl_opensocket_callback, curl_sockopt_callback,
};

/// The application's socket functions and data, as setopt left them.
#[derive(Clone, Copy)]
pub(crate) struct CSockets {
    pub(crate) open: curl_opensocket_callback,
    pub(crate) open_data: *mut c_void,
    pub(crate) sockopt: curl_sockopt_callback,
    pub(crate) sockopt_data: *mut c_void,
    pub(crate) close: curl_closesocket_callback,
    pub(crate) close_data: *mut c_void,
}

impl CSockets {
    /// None set, as a new handle has (`Curl_init_userdefined`).
    pub(crate) const NONE: CSockets = CSockets {
        open: None,
        open_data: core::ptr::null_mut(),
        sockopt: None,
        sockopt_data: core::ptr::null_mut(),
        close: None,
        close_data: core::ptr::null_mut(),
    };
}

/// The handlers for `c` in `options`: an opener and a configurer that
/// call through `easy` while the application has the function set, and
/// a closer holding the function and data now set.
pub(crate) fn sync(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    c: &CSockets,
) -> Result<(), OutOfMemory> {
    let none = c.open.is_none() && c.sockopt.is_none() && c.close.is_none();
    let Some(sockets) = (match options.sockets.made_mut() {
        Some(made) => Some(made),
        None if none => None,
        None => Some(options.sockets.make_mut()?),
    }) else {
        return Ok(());
    };
    let open = match c.open {
        Some(_) => Some(Handler::socket_opener(Adapter(easy))?),
        None => None,
    };
    let configure = match c.sockopt {
        Some(_) => Some(Handler::socket_configurer(Adapter(easy))?),
        None => None,
    };
    let close = match c.close {
        Some(f) => Some(Handler::socket_closer(CCloser {
            f,
            data: c.close_data,
        })?),
        None => None,
    };
    sockets.open = open;
    sockets.configure = configure;
    sockets.close = close;
    Ok(())
}

/// What C hands an opener (`Curl_sockaddr_ex`): `curl_sockaddr`'s fields,
/// the address with room for any family.
#[repr(C)]
struct SockaddrEx {
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    addrlen: c_uint,
    addr: libc::sockaddr_storage,
}

const _: () = assert!(core::mem::offset_of!(SockaddrEx, addr) == 16);

impl SockaddrEx {
    /// A TCP stream to `to`, as C asks the opener for one: close-on-exec,
    /// never nonblocking (`cf_socket_open`).
    fn tcp(to: SocketAddr) -> SockaddrEx {
        // SAFETY: all-zero bytes are a valid `sockaddr_storage`.
        let mut addr: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
        let (family, len) = match to {
            SocketAddr::V4(v4) => {
                let sin = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(*v4.ip()).to_be(),
                    },
                    sin_zero: [0; 8],
                };
                // SAFETY: a `sockaddr_in` fits in the storage, which is
                // aligned for any address.
                unsafe { (&raw mut addr).cast::<libc::sockaddr_in>().write(sin) };
                (libc::AF_INET, size_of::<libc::sockaddr_in>())
            }
            SocketAddr::V6(v6) => {
                let sin6 = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo().to_be(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.ip().octets(),
                    },
                    sin6_scope_id: v6.scope_id(),
                };
                // SAFETY: as above, for a `sockaddr_in6`.
                unsafe { (&raw mut addr).cast::<libc::sockaddr_in6>().write(sin6) };
                (libc::AF_INET6, size_of::<libc::sockaddr_in6>())
            }
        };
        SockaddrEx {
            family,
            socktype: libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            protocol: libc::IPPROTO_TCP,
            addrlen: c_uint::try_from(len).expect("an address's size fits"),
            addr,
        }
    }

    /// A Unix stream to the socket at `path`, or of the abstract name
    /// `path` if `abstract_name`, as C asks the opener for one
    /// (`Curl_unix2addr`): no protocol, and the address's length its
    /// path's and the terminator's, or the zero before the name and the
    /// name's, after the family.
    fn unix(path: &[u8], abstract_name: bool) -> SockaddrEx {
        // SAFETY: all-zero bytes are a valid `sockaddr_un`.
        let mut un: libc::sockaddr_un = unsafe { core::mem::zeroed() };
        un.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let at = usize::from(abstract_name);
        // The setup refused a path too long for it.
        assert!(at + path.len() < un.sun_path.len(), "a Unix path fits");
        for (to, &b) in un.sun_path[at..].iter_mut().zip(path) {
            *to = b as libc::c_char;
        }
        let len = core::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;
        // SAFETY: all-zero bytes are a valid `sockaddr_storage`.
        let mut addr: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
        // SAFETY: a `sockaddr_un` fits in the storage, which is aligned
        // for any address.
        unsafe { (&raw mut addr).cast::<libc::sockaddr_un>().write(un) };
        SockaddrEx {
            family: libc::AF_UNIX,
            socktype: libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            protocol: 0,
            addrlen: c_uint::try_from(len).expect("an address's size fits"),
            addr,
        }
    }

    /// The address as the opener left it, if it is one of TCP's
    /// families.
    fn read(&self) -> Option<SocketAddr> {
        let p = (&raw const self.addr).cast::<u8>();
        match c_int::from(self.addr.ss_family) {
            libc::AF_INET => {
                // SAFETY: the storage holds a `sockaddr_in` by its family,
                // and is aligned for one.
                let sin = unsafe { p.cast::<libc::sockaddr_in>().read() };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                Some(SocketAddr::V4(SocketAddrV4::new(
                    ip,
                    u16::from_be(sin.sin_port),
                )))
            }
            libc::AF_INET6 => {
                // SAFETY: as above, a `sockaddr_in6`.
                let sin6 = unsafe { p.cast::<libc::sockaddr_in6>().read() };
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                    u16::from_be(sin6.sin6_port),
                    u32::from_be(sin6.sin6_flowinfo),
                    sin6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

impl SocketOpener for Adapter {
    /// The descriptor the application's opener returns, owned from then
    /// on, and the address it may have changed; `CURL_SOCKET_BAD` with
    /// the error number it left (`socket_open`).
    fn open(&self, cx: &mut TransferCx<'_>, address: &mut Remote) -> io::Result<Box<dyn Socket>> {
        let c = self.sockets();
        let Some(f) = c.open else {
            // Cleared since the transfer started: the system opens it,
            // as C does once its function is NULL.
            let socket = curl_core::conn::io::open_remote(
                address,
                curl_core::conn::io::Protocol::Tcp,
                false,
            )?;
            return Ok(try_box(socket).map_err(|_| io::ErrorKind::OutOfMemory)?);
        };
        let mut ex = match address {
            Remote::Inet(to) => SockaddrEx::tcp(*to),
            Remote::Unix(to) => SockaddrEx::unix(to.path(), to.is_abstract()),
        };
        let fd = self.call(cx, || {
            // SAFETY: the application's opener takes its data, the
            // purpose and the address, which lives through the call with
            // room for any family.
            unsafe {
                f(
                    c.open_data,
                    CURLSOCKTYPE_IPCXN,
                    (&raw mut ex).cast::<ffi::curl_sockaddr>(),
                )
            }
        });
        if fd == CURL_SOCKET_BAD {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the opener hands the descriptor over, open, as its
        // contract says; nothing else closes it.
        let socket = unsafe { curl_core::conn::io::adopt(fd) };
        // A Unix socket's address is not read back: it is connected to
        // as the options name it.
        if let (Remote::Inet(to), Some(changed)) = (&mut *address, ex.read()) {
            *to = changed;
        }
        Ok(try_box(socket).map_err(|_| io::ErrorKind::OutOfMemory)?)
    }
}

impl SocketConfigurer for Adapter {
    /// What the application's function answers: `CURL_SOCKOPT_OK`, the
    /// socket connected already, or anything else, a failure.
    fn configure(&self, cx: &mut TransferCx<'_>, socket: SocketToSet<'_>) -> Configured {
        let c = self.sockets();
        let Some(f) = c.sockopt else {
            return Configured::Ok;
        };
        let fd = socket.key().get();
        // SAFETY: the application's function takes its data, the socket
        // and the purpose.
        let answer = self.call(cx, || unsafe { f(c.sockopt_data, fd, CURLSOCKTYPE_IPCXN) });
        match answer {
            CURL_SOCKOPT_OK => Configured::Ok,
            CURL_SOCKOPT_ALREADY_CONNECTED => Configured::AlreadyConnected,
            _ => Configured::Abort,
        }
    }
}

impl Adapter {
    fn sockets(&self) -> CSockets {
        self.easy().sockets()
    }
}

/// The application's closer, as it was when a connection was made.
struct CCloser {
    f: unsafe extern "C" fn(*mut c_void, ffi::curl_socket_t) -> c_int,
    data: *mut c_void,
}

// SAFETY: the function and data are the application's, which C calls
// from whichever thread closes the connection, as here.
unsafe impl Send for CCloser {}
// SAFETY: as for `Send`; the closer holds nothing of its own to share.
unsafe impl Sync for CCloser {}

impl SocketCloser for CCloser {
    /// Its answer is not asked, as C ignores it (`socket_close`).
    fn close(&self, socket: SocketKey) {
        // SAFETY: the application's closer takes its data and the
        // descriptor it now owns.
        unsafe { (self.f)(self.data, socket.get()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An opener is handed a Unix socket's address as C hands it
    /// (`Curl_unix2addr`): no protocol, the path and its terminator, or a
    /// zero and the abstract name, and the length after the family.
    #[test]
    fn a_unix_address_is_handed_over_as_c_hands_it() {
        let at = core::mem::offset_of!(libc::sockaddr_un, sun_path);
        let path = SockaddrEx::unix(b"/tmp/s46.sock", false);
        assert_eq!(
            (path.family, path.protocol, path.addrlen as usize),
            (libc::AF_UNIX, 0, at + 14)
        );
        assert_eq!(path.socktype, libc::SOCK_STREAM | libc::SOCK_CLOEXEC);
        let abs = SockaddrEx::unix(b"s46abs", true);
        assert_eq!(abs.addrlen as usize, at + 7);
        // SAFETY: the storage holds the `sockaddr_un` written.
        let un = unsafe { (&raw const abs.addr).cast::<libc::sockaddr_un>().read() };
        #[allow(
            clippy::unnecessary_cast,
            reason = "`c_char` is signed on some targets"
        )]
        let name: Vec<u8> = un.sun_path[..8].iter().map(|&c| c as u8).collect();
        assert_eq!(name, b"\0s46abs\0");
        assert_eq!(abs.read(), None, "not read back as TCP's");
    }
}
