//! Nonblocking TCP sockets (`lib/cf-socket.c`). Opening, setting and
//! connecting are system calls of their own, in C's order; everything
//! after goes through a std `TcpStream`, which already sends with
//! `MSG_NOSIGNAL`. A receive or send a signal interrupts would block, as
//! C reads `EINTR` there; a connect it interrupts failed.

#![allow(unsafe_code)]

use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::num::{NonZeroU32, NonZeroUsize};
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

/// How a connect started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Connect {
    /// Connected already, as happens on loopback.
    Done,
    /// Under way: the socket polls writable once it is decided, and
    /// [`TcpSocket::take_error`] then says how.
    InProgress,
}

/// What a receive got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recv {
    Data(NonZeroUsize),
    /// The peer closed its side.
    Eof,
    WouldBlock,
}

/// What a send took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    Bytes(NonZeroUsize),
    WouldBlock,
}

/// A TCP socket: opened, then connecting or connected.
#[derive(Debug)]
pub struct TcpSocket(TcpStream);

/// The protocol a stream socket speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// `IPPROTO_TCP`, as curl opens its sockets.
    Tcp,
    /// Multipath TCP (`IPPROTO_MPTCP`), as the tool's `--mptcp` opens them.
    Mptcp,
}

/// An option set on a socket between its opening and its connect
/// (`cf_socket_open`, `do_connect`), each one `setsockopt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketOption {
    /// Small sends go out at once, Nagle's algorithm off (`TCP_NODELAY`).
    NoDelay,
    /// The kernel probes an idle connection (`SO_KEEPALIVE`).
    KeepAlive,
    /// Seconds idle before the first probe (`TCP_KEEPIDLE`).
    KeepIdle(i32),
    /// Seconds between probes (`TCP_KEEPINTVL`).
    KeepInterval(i32),
    /// Probes unanswered before the connection is dropped (`TCP_KEEPCNT`).
    KeepCount(i32),
    /// The connect is made with TCP Fast Open (`TCP_FASTOPEN_CONNECT`).
    FastOpenConnect,
    /// The type of service of what it sends: `IP_TOS` over IPv4,
    /// `IPV6_TCLASS` over IPv6, nothing over any other family.
    TypeOfService(i32),
    /// The priority of what it sends, a VLAN's (`SO_PRIORITY`).
    Priority(i32),
    /// A bind to an address leaves the port for the connect to choose
    /// (`IP_BIND_ADDRESS_NO_PORT`).
    BindAddressNoPort,
}

impl SocketOption {
    /// Its level, name and value, or none for the family.
    fn raw(self, family: libc::c_int) -> Option<(libc::c_int, libc::c_int, libc::c_int)> {
        let tcp = libc::IPPROTO_TCP;
        Some(match self {
            SocketOption::NoDelay => (tcp, libc::TCP_NODELAY, 1),
            SocketOption::KeepAlive => (libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1),
            SocketOption::KeepIdle(s) => (tcp, libc::TCP_KEEPIDLE, s),
            SocketOption::KeepInterval(s) => (tcp, libc::TCP_KEEPINTVL, s),
            SocketOption::KeepCount(n) => (tcp, libc::TCP_KEEPCNT, n),
            SocketOption::FastOpenConnect => (tcp, libc::TCP_FASTOPEN_CONNECT, 1),
            SocketOption::TypeOfService(tos) => match family {
                libc::AF_INET => (libc::IPPROTO_IP, libc::IP_TOS, tos),
                libc::AF_INET6 => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS, tos),
                _ => return None,
            },
            SocketOption::Priority(p) => (libc::SOL_SOCKET, libc::SO_PRIORITY, p),
            SocketOption::BindAddressNoPort => (libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT, 1),
        })
    }
}

/// Set `option` on the socket `fd`. The type of service is set for the
/// family the socket is bound to; on one of no family it sets nothing,
/// as the tool's `sockopt_callback` does.
pub fn set(fd: BorrowedFd<'_>, option: SocketOption) -> io::Result<()> {
    let family = match option {
        SocketOption::TypeOfService(_) => family(fd),
        _ => libc::AF_UNSPEC,
    };
    let Some((level, name, value)) = option.raw(family) else {
        return Ok(());
    };
    let len = libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("an int's size fits");
    // SAFETY: `value` is an int of the length given and lives through the
    // call; `fd` is an open descriptor for as long as it is borrowed.
    let rc =
        unsafe { libc::setsockopt(fd.as_raw_fd(), level, name, (&raw const value).cast(), len) };
    checked(rc)?;
    Ok(())
}

/// A system call's result `rc`, an error if it failed: negative, the
/// error in `errno`.
fn checked(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

/// The address family of the socket `fd`, `AF_UNSPEC` if it cannot be
/// told (`get_address_family`).
fn family(fd: BorrowedFd<'_>) -> libc::c_int {
    // SAFETY: all-zero bytes are a valid `sockaddr_storage`.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len =
        libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>()).expect("its size fits");
    // SAFETY: `storage` has room for any address, `len` says so, and both
    // live through the call; `fd` is open while borrowed.
    let rc = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&raw mut storage).cast::<libc::sockaddr>(),
            &raw mut len,
        )
    };
    if rc == 0 {
        libc::c_int::from(storage.ss_family)
    } else {
        libc::AF_UNSPEC
    }
}

/// Open a close-on-exec TCP stream socket of `addr`'s family, speaking
/// `protocol`, nonblocking if `nonblocking`: not connected yet.
pub fn open(addr: SocketAddr, protocol: Protocol, nonblocking: bool) -> io::Result<TcpSocket> {
    let family = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let mut kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    if nonblocking {
        kind |= libc::SOCK_NONBLOCK;
    }
    let protocol = match protocol {
        Protocol::Tcp => libc::IPPROTO_TCP,
        Protocol::Mptcp => libc::IPPROTO_MPTCP,
    };
    // SAFETY: `socket` takes no pointers; a negative result is an error.
    let fd = unsafe { libc::socket(family, kind, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and is owned by nothing else.
    Ok(TcpSocket(TcpStream::from(unsafe {
        OwnedFd::from_raw_fd(fd)
    })))
}

/// Open a close-on-exec Unix stream socket (`AF_UNIX`), nonblocking if
/// `nonblocking`: not connected yet. It is held as a TCP socket is, its
/// reads, writes and errors being the same calls; it has no local
/// address of TCP's families.
pub fn open_unix(nonblocking: bool) -> io::Result<TcpSocket> {
    let mut kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    if nonblocking {
        kind |= libc::SOCK_NONBLOCK;
    }
    // SAFETY: `socket` takes no pointers; a negative result is an error.
    let fd = unsafe { libc::socket(libc::AF_UNIX, kind, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and is owned by nothing else.
    Ok(TcpSocket(TcpStream::from(unsafe {
        OwnedFd::from_raw_fd(fd)
    })))
}

/// The room a Unix socket's address has for its path, its terminator or,
/// for an abstract name, the zero before it among it (`sun_path`).
pub const UNIX_PATH_ROOM: usize = {
    // SAFETY: all-zero bytes are a valid `sockaddr_un`.
    let un: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    std::mem::size_of_val(&un.sun_path)
};

/// The address of the Unix socket at `path`, or of the abstract name
/// `path` if `abstract_name`, as C writes it (`Curl_unix2addr`): the path
/// and its terminator, or a zero and the name, without one after. `None`
/// if it does not fit, or a path holds a zero byte.
fn unix_address(path: &[u8], abstract_name: bool) -> Option<SockAddr> {
    if path.len() >= UNIX_PATH_ROOM || (!abstract_name && path.contains(&0)) {
        return None;
    }
    // SAFETY: all-zero bytes are a valid `sockaddr_un`.
    let mut un: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    un.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let at = usize::from(abstract_name);
    for (to, &b) in un.sun_path[at..].iter_mut().zip(path) {
        *to = b as libc::c_char;
    }
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;
    // SAFETY: all-zero bytes are a valid `sockaddr_storage`.
    let mut raw: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    // SAFETY: `sockaddr_storage` is large enough and aligned for any
    // socket address, `sockaddr_un` among them.
    unsafe { (&raw mut raw).cast::<libc::sockaddr_un>().write(un) };
    Some(SockAddr {
        raw,
        len: libc::socklen_t::try_from(len).expect("a Unix socket address length fits"),
    })
}

/// The socket `fd`, which an application opened and gives up: closing
/// the `TcpSocket` closes it.
///
/// # Safety
///
/// `fd` is an open socket descriptor that nothing else owns or closes
/// while the `TcpSocket` lives.
pub unsafe fn adopt(fd: RawFd) -> TcpSocket {
    // SAFETY: as the caller guarantees.
    TcpSocket(TcpStream::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// A socket address as the kernel reads it.
struct SockAddr {
    raw: libc::sockaddr_storage,
    len: libc::socklen_t,
}

impl From<SocketAddr> for SockAddr {
    fn from(addr: SocketAddr) -> SockAddr {
        // SAFETY: all-zero bytes are a valid `sockaddr_storage`.
        let mut raw: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
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
                // SAFETY: `sockaddr_storage` is large enough and aligned
                // for any socket address, `sockaddr_in` among them.
                unsafe { (&raw mut raw).cast::<libc::sockaddr_in>().write(sin) };
                size_of::<libc::sockaddr_in>()
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
                // SAFETY: as above, for `sockaddr_in6`.
                unsafe { (&raw mut raw).cast::<libc::sockaddr_in6>().write(sin6) };
                size_of::<libc::sockaddr_in6>()
            }
        };
        SockAddr {
            raw,
            len: libc::socklen_t::try_from(len).expect("a socket address length fits"),
        }
    }
}

/// Whether the system has a working IPv6 stack: an IPv6 datagram socket
/// opens, and is closed at once (`Curl_probeipv6`). Only running out of
/// memory is an error; any other failure is no IPv6.
pub fn probe_ipv6() -> io::Result<bool> {
    // SAFETY: `socket` takes no pointer.
    let fd = match checked(unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) }) {
        Ok(fd) => fd,
        Err(err) => return probe_failed(err),
    };
    // SAFETY: `fd` was opened just now and nothing else holds it; it is
    // closed as the `OwnedFd` drops.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    Ok(true)
}

/// What the probe's socket failing to open with `err` means: running out
/// of memory is an error, anything else no IPv6.
fn probe_failed(err: io::Error) -> io::Result<bool> {
    match err.raw_os_error() {
        Some(libc::ENOMEM) => Err(err),
        _ => Ok(false),
    }
}

/// The index of the network interface named `name` (`if_nametoindex`),
/// or `None` if no interface has that name.
pub fn interface_index(name: &[u8]) -> Option<NonZeroU32> {
    // A name with a zero byte names no interface; one that does not fit
    // the kernel's limit, with its terminator, names none either.
    if name.contains(&0) || name.len() >= libc::IF_NAMESIZE {
        return None;
    }
    let mut c_name = [0u8; libc::IF_NAMESIZE];
    c_name[..name.len()].copy_from_slice(name);
    // SAFETY: `c_name` holds `name` and at least one zero after it, so it
    // is a C string, and it lives through the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr().cast()) };
    NonZeroU32::new(index)
}

/// The scope of the first interface that is up, is not loopback, and has
/// a link-local IPv6 address, for a link-local address given without one
/// (cf-socket.c's `get_scope_id`); `None` if there is none, or the list
/// cannot be had.
pub fn link_local_scope() -> Option<NonZeroU32> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `list` is a valid place for the list's head, which is freed
    // below with `freeifaddrs` and nowhere else.
    if unsafe { libc::getifaddrs(&raw mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut at = list;
    while !at.is_null() {
        // SAFETY: `at` is an entry of the list `getifaddrs` returned, not
        // yet freed.
        let entry = unsafe { &*at };
        at = entry.ifa_next;
        let flags = entry.ifa_flags;
        let up = flags & libc::IFF_UP as libc::c_uint != 0;
        let loopback = flags & libc::IFF_LOOPBACK as libc::c_uint != 0;
        if entry.ifa_addr.is_null() || !up || loopback {
            continue;
        }
        // SAFETY: a non-null `ifa_addr` points at a socket address, which
        // starts with its family.
        let family = unsafe { (*entry.ifa_addr).sa_family };
        if i32::from(family) != libc::AF_INET6 {
            continue;
        }
        // SAFETY: the family says the address is a `sockaddr_in6`, which
        // may be unaligned in the list.
        let sin6 = unsafe { entry.ifa_addr.cast::<libc::sockaddr_in6>().read_unaligned() };
        let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
        if ip.is_unicast_link_local()
            && let Some(scope) = NonZeroU32::new(sin6.sin6_scope_id)
        {
            found = Some(scope);
            break;
        }
    }
    // SAFETY: `list` is what `getifaddrs` returned, freed once, and no
    // entry of it is used after.
    unsafe { libc::freeifaddrs(list) };
    found
}

/// The system's numbers for the address families, as C's traces show
/// them.
pub const AF_INET: i32 = libc::AF_INET;
pub const AF_INET6: i32 = libc::AF_INET6;

/// The scope an IPv6 address is in, as an interface's address is matched
/// against the one connected to (`Curl_ipv6_scope`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6Scope {
    Global,
    LinkLocal,
    SiteLocal,
    UniqueLocal,
    /// The loopback address.
    NodeLocal,
}

/// The scope of `ip`; an IPv4 address's is global.
pub fn ipv6_scope(ip: IpAddr) -> Ipv6Scope {
    let IpAddr::V6(v6) = ip else {
        return Ipv6Scope::Global;
    };
    let b = v6.octets();
    if b[0] & 0xFE == 0xFC {
        return Ipv6Scope::UniqueLocal;
    }
    match u16::from_be_bytes([b[0], b[1]]) & 0xFFC0 {
        0xFE80 => Ipv6Scope::LinkLocal,
        0xFEC0 => Ipv6Scope::SiteLocal,
        0x0000 if b[1..15].iter().all(|&x| x == 0) && b[15] == 1 => Ipv6Scope::NodeLocal,
        _ => Ipv6Scope::Global,
    }
}

/// What the interface asked for has of the family a socket binds in
/// (`Curl_if2ip`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceAddress {
    /// No interface has the name, or the list cannot be had.
    NotFound,
    /// It has no address of the family, or none of the scope wanted.
    OtherFamily,
    /// Its address, and for IPv6 the address's scope id (0 for none).
    Found(IpAddr, u32),
}

/// The first address of the family IPv6 if `v6`, else IPv4, of the
/// interface named `name` (`Curl_if2ip`). An IPv6 one is taken only in
/// `remote_scope`, the scope of the address connected to, and, if
/// `scope_id` is not 0, with that scope id.
pub fn interface_address(
    name: &[u8],
    v6: bool,
    remote_scope: Ipv6Scope,
    scope_id: u32,
) -> InterfaceAddress {
    let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `list` is a valid place for the list's head, which is freed
    // below with `freeifaddrs` and nowhere else.
    if unsafe { libc::getifaddrs(&raw mut list) } < 0 {
        return InterfaceAddress::NotFound;
    }
    let mut found = InterfaceAddress::NotFound;
    let mut at = list;
    while !at.is_null() {
        // SAFETY: `at` is an entry of the list `getifaddrs` returned, not
        // yet freed.
        let entry = unsafe { &*at };
        at = entry.ifa_next;
        if entry.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: an entry's name is a C string the list owns.
        let named = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_bytes() == name;
        // SAFETY: a non-null `ifa_addr` points at a socket address, which
        // starts with its family.
        let of = libc::c_int::from(unsafe { (*entry.ifa_addr).sa_family });
        if of != family {
            if named && found == InterfaceAddress::NotFound {
                found = InterfaceAddress::OtherFamily;
            }
            continue;
        }
        if !named {
            continue;
        }
        if v6 {
            // SAFETY: the family says the address is a `sockaddr_in6`,
            // which may be unaligned in the list.
            let sin6 = unsafe { entry.ifa_addr.cast::<libc::sockaddr_in6>().read_unaligned() };
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr));
            // Only an address of the scope connected to, and of the scope
            // id asked for, if one is.
            let wrong_scope =
                ipv6_scope(ip) != remote_scope || (scope_id != 0 && sin6.sin6_scope_id != scope_id);
            if wrong_scope {
                if found == InterfaceAddress::NotFound {
                    found = InterfaceAddress::OtherFamily;
                }
                continue;
            }
            found = InterfaceAddress::Found(ip, sin6.sin6_scope_id);
        } else {
            // SAFETY: as above, for a `sockaddr_in`.
            let sin = unsafe { entry.ifa_addr.cast::<libc::sockaddr_in>().read_unaligned() };
            let ip = std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            found = InterfaceAddress::Found(IpAddr::V4(ip), 0);
        }
        break;
    }
    // SAFETY: `list` is what `getifaddrs` returned, freed once, and no
    // entry of it is used after.
    unsafe { libc::freeifaddrs(list) };
    found
}

impl TcpSocket {
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    /// Bind its local end to `addr`, before it connects.
    pub fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        let storage = SockAddr::from(addr);
        // SAFETY: `storage` holds a sockaddr of `addr`'s family, valid for
        // the length given, and lives through the call; the socket is open.
        let rc = unsafe {
            libc::bind(
                self.fd().as_raw_fd(),
                (&raw const storage.raw).cast::<libc::sockaddr>(),
                storage.len,
            )
        };
        checked(rc)?;
        Ok(())
    }

    /// Bind it to the network interface named `name`, which must not hold
    /// a zero byte and be shorter than 255 bytes (`SO_BINDTODEVICE`).
    pub fn bind_to_device(&self, name: &[u8]) -> io::Result<()> {
        let mut c_name = [0u8; 256];
        if name.contains(&0) || name.len() >= c_name.len() - 1 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        c_name[..name.len()].copy_from_slice(name);
        // With its terminator, as C gives it.
        let len = libc::socklen_t::try_from(name.len() + 1).expect("a short name's length fits");
        // SAFETY: `c_name` holds the name and a zero after it, `len` bytes
        // of it, and lives through the call; the socket is open.
        let rc = unsafe {
            libc::setsockopt(
                self.fd().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                c_name.as_ptr().cast(),
                len,
            )
        };
        checked(rc)?;
        Ok(())
    }

    /// Set `option` on it, as [`set`] does.
    pub fn set(&self, option: SocketOption) -> io::Result<()> {
        set(self.fd(), option)
    }

    /// Make it nonblocking, as `curlx_nonblock` does (`F_SETFL`).
    pub fn set_nonblocking(&self) -> io::Result<()> {
        let fd = self.fd().as_raw_fd();
        // SAFETY: `fcntl` with `F_GETFL` takes no pointer; `fd` is open.
        let flags = checked(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
        // SAFETY: as above, with `F_SETFL` and an int.
        checked(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
        Ok(())
    }

    /// Start connecting it to `addr`; the socket is nonblocking, so a
    /// connect not decided at once goes on in the background.
    pub fn connect(&self, addr: SocketAddr) -> io::Result<Connect> {
        let mut storage = SockAddr::from(addr);
        // SAFETY: `storage` holds a sockaddr of `addr`'s family, valid for
        // the length given, and lives through the call; the socket is open.
        let rc = unsafe {
            libc::connect(
                self.fd().as_raw_fd(),
                (&raw mut storage.raw).cast::<libc::sockaddr>(),
                storage.len,
            )
        };
        if rc == 0 {
            return Ok(Connect::Done);
        }
        connect_failed(io::Error::last_os_error())
    }

    /// Start connecting it, a Unix socket, to the one at `path`, or of
    /// the abstract name `path` if `abstract_name`: refused with `EINVAL`
    /// if the address cannot hold it (see [`UNIX_PATH_ROOM`]).
    pub fn connect_unix(&self, path: &[u8], abstract_name: bool) -> io::Result<Connect> {
        let Some(mut storage) = unix_address(path, abstract_name) else {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        };
        // SAFETY: `storage` holds a `sockaddr_un`, valid for the length
        // given, and lives through the call; the socket is open.
        let rc = unsafe {
            libc::connect(
                self.fd().as_raw_fd(),
                (&raw mut storage.raw).cast::<libc::sockaddr>(),
                storage.len,
            )
        };
        if rc == 0 {
            return Ok(Connect::Done);
        }
        connect_failed(io::Error::last_os_error())
    }

    /// The error that ended a connect in progress, once the socket polls
    /// writable; `None` if it connected (`SO_ERROR`).
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.0.take_error()
    }

    /// Receive into `buf`, which must not be empty: an empty read would
    /// look like the peer closing.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Recv> {
        assert!(!buf.is_empty(), "a receive needs room");
        received((&self.0).read(buf))
    }

    /// Send from `buf`, which must not be empty.
    pub fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        assert!(!buf.is_empty(), "a send needs bytes");
        sent((&self.0).write(buf))
    }

    /// Send nothing more; the peer reads the end of the stream.
    pub fn shutdown_send(&self) -> io::Result<()> {
        self.0.shutdown(Shutdown::Write)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    /// Let go of the descriptor without closing it: the caller closes
    /// it, as an application's own closer does.
    pub fn into_raw(self) -> RawFd {
        self.0.into_raw_fd()
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }
}

/// What a connect that did not connect at once means: in progress, or,
/// for any other error, failed (`socket_connect_result`). An `EINTR`
/// fails it, as C takes only `EINPROGRESS` and `EAGAIN` for under way.
fn connect_failed(err: io::Error) -> io::Result<Connect> {
    match err.raw_os_error() {
        Some(libc::EINPROGRESS | libc::EAGAIN) => Ok(Connect::InProgress),
        _ => Err(err),
    }
}

/// What a receive's result means: an `EAGAIN` or an `EINTR` would block
/// (`cf_socket_recv`).
fn received(got: io::Result<usize>) -> io::Result<Recv> {
    match got {
        Ok(n) => Ok(NonZeroUsize::new(n).map_or(Recv::Eof, Recv::Data)),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) => {
            Ok(Recv::WouldBlock)
        }
        Err(e) => Err(e),
    }
}

/// What a send's result means: an `EAGAIN`, an `EINTR` or an
/// `EINPROGRESS` would block (`cf_socket_send`).
fn sent(took: io::Result<usize>) -> io::Result<Sent> {
    match took {
        Ok(n) => {
            let n = NonZeroUsize::new(n).expect("a send of some bytes takes some");
            Ok(Sent::Bytes(n))
        }
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EAGAIN | libc::EINTR | libc::EINPROGRESS)
            ) =>
        {
            Ok(Sent::WouldBlock)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use std::net::{Ipv6Addr, TcpListener};
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use super::*;
    use crate::poll::{Events, PollFd, poll};

    /// Open a nonblocking socket, Nagle's algorithm off, and start
    /// connecting it to `addr`, as curl does by default.
    fn connect(addr: SocketAddr) -> io::Result<(TcpSocket, Connect)> {
        let s = open(addr, Protocol::Tcp, true)?;
        s.set(SocketOption::NoDelay)?;
        let state = s.connect(addr)?;
        Ok((s, state))
    }

    /// The int value of option `name` at `level` on `s`.
    fn option(s: &TcpSocket, level: libc::c_int, name: libc::c_int) -> libc::c_int {
        let mut value: libc::c_int = -1;
        let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap();
        // SAFETY: `value` is an int of the length given, and both live
        // through the call; `s` is open.
        let rc = unsafe {
            libc::getsockopt(
                s.fd().as_raw_fd(),
                level,
                name,
                (&raw mut value).cast(),
                &raw mut len,
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        value
    }

    /// Wait for `s` to be ready for `events`, for at most five seconds.
    fn ready(s: &TcpSocket, events: Events) -> Events {
        let mut fds = [PollFd::new(s.fd(), events)];
        assert_eq!(
            poll(&mut fds, Duration::from_secs(5)).unwrap(),
            1,
            "ready in time"
        );
        fds[0].revents()
    }

    /// Connected either at once or once it polls writable, with no error;
    /// the listener then has the peer.
    fn connected(listener: &TcpListener) -> (TcpSocket, TcpStream) {
        let (s, state) = connect(listener.local_addr().unwrap()).unwrap();
        if state == Connect::InProgress {
            assert!(ready(&s, Events::OUT).contains(Events::OUT));
        }
        assert!(s.take_error().unwrap().is_none());
        let (peer, from) = listener.accept().unwrap();
        assert_eq!(from, s.local_addr().unwrap());
        assert_eq!(s.peer_addr().unwrap(), listener.local_addr().unwrap());
        (s, peer)
    }

    /// IPv6 works here, as `connects_over_ipv4_and_ipv6` needs.
    #[test]
    #[cfg_attr(miri, ignore = "Miri opens TCP sockets only")]
    fn the_probe_finds_ipv6() {
        assert!(probe_ipv6().unwrap());
    }

    /// The probe's socket failing to open is no IPv6, whatever the
    /// reason, unless memory ran out (`Curl_probeipv6`, `socket_open`).
    #[test]
    fn a_failed_probe_is_no_ipv6_unless_memory_ran_out() {
        for errno in [libc::EAFNOSUPPORT, libc::EMFILE, libc::EACCES] {
            assert!(!probe_failed(os(errno)).unwrap(), "{errno}");
        }
        let err = probe_failed(os(libc::ENOMEM)).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOMEM));
    }

    /// A system call's failure `errno`, as std reports it.
    fn os(errno: libc::c_int) -> io::Error {
        io::Error::from_raw_os_error(errno)
    }

    /// A signal interrupting a receive or a send would block, as C reads
    /// `EINTR` there, and so does a send's `EINPROGRESS`; a connect it
    /// interrupts failed, as C takes only `EINPROGRESS` and `EAGAIN` for
    /// under way (`cf_socket_recv`, `cf_socket_send`,
    /// `socket_connect_result`).
    #[test]
    fn an_interrupted_call_reads_as_c_reads_it() {
        fn errno<T>(r: io::Result<T>) -> Result<T, Option<i32>> {
            r.map_err(|e| e.raw_os_error())
        }
        assert_eq!(errno(received(Err(os(libc::EINTR)))), Ok(Recv::WouldBlock));
        assert_eq!(errno(received(Err(os(libc::EAGAIN)))), Ok(Recv::WouldBlock));
        assert_eq!(
            errno(received(Err(os(libc::EINPROGRESS)))),
            Err(Some(libc::EINPROGRESS))
        );
        assert_eq!(
            errno(received(Err(os(libc::ECONNRESET)))),
            Err(Some(libc::ECONNRESET))
        );
        assert_eq!(errno(received(Ok(0))), Ok(Recv::Eof));
        assert_eq!(
            errno(received(Ok(3))),
            Ok(Recv::Data(NonZeroUsize::new(3).unwrap()))
        );
        for would_block in [libc::EINTR, libc::EAGAIN, libc::EINPROGRESS] {
            assert_eq!(errno(sent(Err(os(would_block)))), Ok(Sent::WouldBlock));
        }
        assert_eq!(errno(sent(Err(os(libc::EPIPE)))), Err(Some(libc::EPIPE)));
        assert_eq!(
            errno(sent(Ok(2))),
            Ok(Sent::Bytes(NonZeroUsize::new(2).unwrap()))
        );
        for under_way in [libc::EINPROGRESS, libc::EAGAIN] {
            assert_eq!(
                errno(connect_failed(os(under_way))),
                Ok(Connect::InProgress)
            );
        }
        assert_eq!(
            errno(connect_failed(os(libc::EINTR))),
            Err(Some(libc::EINTR))
        );
        assert_eq!(
            errno(connect_failed(os(libc::ECONNREFUSED))),
            Err(Some(libc::ECONNREFUSED))
        );
    }

    /// Each option reaches the kernel's socket as C sets it: Nagle's
    /// algorithm off, keepalive on with its times and count, the type of
    /// service for the socket's family, and the priority.
    #[test]
    #[cfg_attr(miri, ignore = "Miri sets few socket options")]
    fn a_socket_is_set_as_asked() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let s = open(addr, Protocol::Tcp, true).unwrap();
        let tcp = libc::IPPROTO_TCP;
        assert_eq!(option(&s, tcp, libc::TCP_NODELAY), 0, "Nagle on until set");
        for o in [
            SocketOption::NoDelay,
            SocketOption::KeepAlive,
            SocketOption::KeepIdle(30),
            SocketOption::KeepInterval(20),
            SocketOption::KeepCount(4),
            SocketOption::Priority(3),
            SocketOption::FastOpenConnect,
        ] {
            s.set(o).unwrap();
        }
        assert_eq!(option(&s, tcp, libc::TCP_NODELAY), 1);
        assert_eq!(option(&s, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 1);
        assert_eq!(option(&s, tcp, libc::TCP_KEEPIDLE), 30);
        assert_eq!(option(&s, tcp, libc::TCP_KEEPINTVL), 20);
        assert_eq!(option(&s, tcp, libc::TCP_KEEPCNT), 4);
        assert_eq!(option(&s, libc::SOL_SOCKET, libc::SO_PRIORITY), 3);
        assert_eq!(option(&s, tcp, libc::TCP_FASTOPEN_CONNECT), 1);
        // One the kernel refuses is an error, as C's `setsockopt` call
        // sees it: an idle time is at least a second.
        let refused = s.set(SocketOption::KeepIdle(0)).unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::EINVAL));
        assert_eq!(option(&s, tcp, libc::TCP_KEEPIDLE), 30, "left as it was");
        // The type of service needs the socket's family, which it has once
        // bound: a connect binds it.
        s.connect(addr).unwrap();
        s.set(SocketOption::TypeOfService(32)).unwrap();
        assert_eq!(option(&s, libc::IPPROTO_IP, libc::IP_TOS), 32);
        if let Ok(v6) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) {
            let at = v6.local_addr().unwrap();
            let s = open(at, Protocol::Tcp, true).unwrap();
            s.connect(at).unwrap();
            s.set(SocketOption::TypeOfService(32)).unwrap();
            assert_eq!(option(&s, libc::IPPROTO_IPV6, libc::IPV6_TCLASS), 32);
        }
    }

    /// A socket opened blocking, as an application's may be, is made
    /// nonblocking; one opened so is close-on-exec either way.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot read SO_PROTOCOL")]
    fn a_socket_is_made_nonblocking() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 1));
        let s = open(addr, Protocol::Tcp, false).unwrap();
        let flags = || {
            // SAFETY: `F_GETFL` takes no pointer; the socket is open.
            unsafe { libc::fcntl(s.fd().as_raw_fd(), libc::F_GETFL) }
        };
        assert_eq!(flags() & libc::O_NONBLOCK, 0);
        s.set_nonblocking().unwrap();
        assert_ne!(flags() & libc::O_NONBLOCK, 0);
        // Made so again, it stays so, as `curlx_nonblock` leaves it.
        s.set_nonblocking().unwrap();
        assert_ne!(flags() & libc::O_NONBLOCK, 0, "still nonblocking");
        // SAFETY: `F_GETFD` takes no pointer; the socket is open.
        let fd_flags = unsafe { libc::fcntl(s.fd().as_raw_fd(), libc::F_GETFD) };
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);
        assert_eq!(
            option(&s, libc::SOL_SOCKET, libc::SO_PROTOCOL),
            libc::IPPROTO_TCP
        );
    }

    /// An application's descriptor is the socket's from then on: it
    /// connects through it, and closing the socket closes it.
    #[test]
    fn an_adopted_descriptor_is_the_socket_s() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // SAFETY: `socket` takes no pointers.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);
        // SAFETY: `fd` was just opened here and is given up.
        let s = unsafe { adopt(fd) };
        assert_eq!(s.fd().as_raw_fd(), fd);
        s.set_nonblocking().unwrap();
        if s.connect(addr).unwrap() == Connect::InProgress {
            assert!(ready(&s, Events::OUT).contains(Events::OUT));
        }
        assert_eq!(s.peer_addr().unwrap(), addr);
        let (mut peer, _) = listener.accept().unwrap();
        drop(s);
        // Not by its number, which another test may be given meanwhile:
        // the peer sees the end.
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0, "closed");
    }

    /// Multipath TCP is the protocol asked for, where the kernel has it.
    #[test]
    #[cfg_attr(miri, ignore = "Miri opens TCP sockets only")]
    fn a_socket_may_speak_multipath_tcp() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 1));
        match open(addr, Protocol::Mptcp, true) {
            Ok(s) => assert_eq!(
                option(&s, libc::SOL_SOCKET, libc::SO_PROTOCOL),
                libc::IPPROTO_MPTCP
            ),
            // A kernel without it says so.
            Err(e) => assert!(
                matches!(
                    e.raw_os_error(),
                    Some(libc::EPROTONOSUPPORT | libc::EINVAL | libc::ENOPROTOOPT)
                ),
                "{e}"
            ),
        }
    }

    /// The type of service of a socket of no family yet sets nothing.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot name a socket pair")]
    fn the_type_of_service_needs_a_family() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        set(a.as_fd(), SocketOption::TypeOfService(32)).unwrap();
    }

    /// A socket let go of stays open until its new owner closes it.
    #[test]
    fn a_socket_let_go_of_stays_open() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (s, _peer) = connected(&listener);
        let fd = s.into_raw();
        // SAFETY: `fd` was let go of above and is owned by nothing else.
        let s = TcpSocket(TcpStream::from(unsafe { OwnedFd::from_raw_fd(fd) }));
        assert_eq!(s.fd().as_raw_fd(), fd);
        assert_eq!(s.peer_addr().unwrap(), listener.local_addr().unwrap());
    }

    #[test]
    fn connects_over_ipv4_and_ipv6() {
        connected(&TcpListener::bind("127.0.0.1:0").unwrap());
        if let Ok(v6) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) {
            connected(&v6);
        }
    }

    /// A loopback port held by a socket that is bound but never listens:
    /// connects to it are refused, and no other test can take it.
    fn refusing_port() -> (OwnedFd, SocketAddr) {
        // SAFETY: `socket` takes no pointers.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        // SAFETY: `fd` was just opened and is owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut addr = SockAddr::from(SocketAddr::from(([127, 0, 0, 1], 0)));
        // SAFETY: `addr` holds an IPv4 address of the length given and
        // lives through the call; `fd` is open.
        let rc = unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr.raw).cast(), addr.len) };
        assert_eq!(rc, 0);
        // SAFETY: `addr` has room for any address, its length says so, and
        // both live through the call; `fd` is open.
        let rc = unsafe {
            libc::getsockname(
                fd.as_raw_fd(),
                (&raw mut addr.raw).cast(),
                &raw mut addr.len,
            )
        };
        assert_eq!(rc, 0);
        // SAFETY: the socket is IPv4, so the kernel wrote a `sockaddr_in`.
        let sin = unsafe { (&raw const addr.raw).cast::<libc::sockaddr_in>().read() };
        (
            fd,
            SocketAddr::from(([127, 0, 0, 1], u16::from_be(sin.sin_port))),
        )
    }

    /// A port nobody listens on: refused at once, or once the connect in
    /// progress is decided.
    #[test]
    fn a_refused_connect_reports_why() {
        let (_held, addr) = refusing_port();
        let err = match connect(addr) {
            Err(e) => e,
            Ok((s, state)) => {
                assert_eq!(state, Connect::InProgress, "nothing listens there");
                assert!(!ready(&s, Events::OUT).is_empty());
                s.take_error().unwrap().expect("the connect failed")
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn receives_data_then_the_end_of_the_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (s, mut peer) = connected(&listener);
        let mut buf = [0u8; 16];
        assert_eq!(
            s.recv(&mut buf).unwrap(),
            Recv::WouldBlock,
            "nothing sent yet"
        );
        peer.write_all(b"hi").unwrap();
        drop(peer);
        assert!(ready(&s, Events::IN).contains(Events::IN));
        assert_eq!(
            s.recv(&mut buf).unwrap(),
            Recv::Data(NonZeroUsize::new(2).unwrap())
        );
        assert_eq!(&buf[..2], b"hi");
        // The end may arrive after the data.
        assert!(ready(&s, Events::IN).contains(Events::IN));
        assert_eq!(s.recv(&mut buf).unwrap(), Recv::Eof);
    }

    #[test]
    fn a_send_into_full_buffers_would_block() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (s, peer) = connected(&listener);
        let chunk = [7u8; 65536];
        let mut sent = 0usize;
        let blocked = loop {
            match s.send(&chunk).unwrap() {
                Sent::Bytes(n) => sent += n.get(),
                Sent::WouldBlock => break true,
            }
            if sent > 256 << 20 {
                break false;
            }
        };
        assert!(blocked, "the peer reads nothing, so the buffers fill");
        drop(peer);
    }

    #[test]
    fn a_shut_down_side_reads_as_the_end_at_the_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (s, mut peer) = connected(&listener);
        s.shutdown_send().unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(std::io::Read::read(&mut peer, &mut buf).unwrap(), 0);
    }

    /// Close `peer` with a reset rather than an orderly end.
    fn reset(peer: TcpStream) {
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let len = libc::socklen_t::try_from(size_of::<libc::linger>()).unwrap();
        // SAFETY: `linger` is a valid `SO_LINGER` value of the length given
        // and lives through the call; `peer` is open.
        let rc = unsafe {
            libc::setsockopt(
                peer.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&raw const linger).cast(),
                len,
            )
        };
        assert_eq!(rc, 0);
    }

    #[test]
    fn a_reset_connection_fails_both_ways() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (s, peer) = connected(&listener);
        reset(peer);
        assert!(ready(&s, Events::IN).contains(Events::IN));
        let mut buf = [0u8; 4];
        let err = s.recv(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        let err = s.send(b"x").unwrap_err();
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ),
            "{err}"
        );
    }

    /// An IPv6 address's scope reaches the kernel's socket address.
    #[test]
    fn the_scope_reaches_the_socket_address() {
        let ip = "fe80::1".parse().unwrap();
        let addr = SockAddr::from(SocketAddr::V6(std::net::SocketAddrV6::new(ip, 80, 0, 7)));
        assert_eq!(addr.len as usize, size_of::<libc::sockaddr_in6>());
        // SAFETY: an IPv6 address was written as a `sockaddr_in6`.
        let sin6 = unsafe { (&raw const addr.raw).cast::<libc::sockaddr_in6>().read() };
        assert_eq!(sin6.sin6_scope_id, 7);
        assert_eq!(u16::from_be(sin6.sin6_port), 80);
    }

    /// Interfaces are found by name; a name no interface has, or no
    /// interface could have, finds none.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot call if_nametoindex")]
    fn interfaces_are_found_by_name() {
        assert!(interface_index(b"lo").is_some(), "Linux has a loopback");
        assert_eq!(interface_index(b"nosuch-if0"), None);
        assert_eq!(interface_index(b""), None);
        assert_eq!(interface_index(b"lo\0"), None);
        assert_eq!(interface_index(&[b'a'; 64]), None);
        assert_eq!(interface_index(&[b'a'; libc::IF_NAMESIZE]), None);
    }

    /// The link-local fallback never picks the loopback interface.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot call getifaddrs")]
    fn the_link_local_scope_is_not_loopback_s() {
        if let Some(scope) = link_local_scope() {
            assert_ne!(Some(scope), interface_index(b"lo"));
        }
    }

    /// Set in the child process `descriptors_run_from_zero_to_the_limit`
    /// runs itself in.
    const CHILD: &str = "CURL_OS_NET_DESCRIPTOR_CHILD";

    /// A socket may be descriptor 0, and opening one past the descriptor
    /// limit is an error, not a crash. Run in a child process, as it
    /// closes stdin and lowers the limit.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot start a process")]
    fn descriptors_run_from_zero_to_the_limit() {
        if std::env::var_os(CHILD).is_some() {
            return in_child();
        }
        let name = "net::tests::descriptors_run_from_zero_to_the_limit";
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name, "--exact", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stdout}{stderr}");
        assert!(stdout.contains("1 passed"), "the child ran it: {stdout}");
    }

    fn in_child() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // SAFETY: nothing in this process reads stdin.
        assert_eq!(unsafe { libc::close(0) }, 0);
        let (s, _) = connect(addr).unwrap();
        assert_eq!(s.fd().as_raw_fd(), 0, "the lowest free descriptor");
        // SAFETY: `dup` of the open stdout; the copy is closed at once.
        let next = unsafe { libc::dup(1) };
        assert!(next > 0);
        // SAFETY: `next` was just opened here and is used by nothing else.
        assert_eq!(unsafe { libc::close(next) }, 0);
        // SAFETY: a zeroed `rlimit` is valid, and is filled in by the call.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `limit` is valid to write and lives through the call.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) };
        assert_eq!(rc, 0);
        limit.rlim_cur = libc::rlim_t::try_from(next).unwrap();
        // SAFETY: `limit` is valid and lives through the call.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) };
        assert_eq!(rc, 0);
        let err = connect(addr).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EMFILE));
        // No descriptor for the probe's socket is no IPv6, not an error.
        assert!(!probe_ipv6().unwrap());
        drop(s);
    }

    /// The scope given a link-local address is that of an interface that
    /// is up, is not loopback and has one, as the kernel lists them
    /// (`/proc/net/if_inet6`, `/sys/class/net/*/flags`); none without one.
    #[test]
    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore = "FFI")]
    fn a_link_local_address_takes_an_interface_s_scope() {
        let listed = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
        let mut scopes = Vec::new();
        for line in listed.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (addr, index, name) = (f[0], f[1], f[5]);
            let flags = std::fs::read_to_string(format!("/sys/class/net/{name}/flags")).unwrap();
            let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap();
            let up = flags & libc::IFF_UP as u32 != 0;
            let loopback = flags & libc::IFF_LOOPBACK as u32 != 0;
            let link_local = ["fe8", "fe9", "fea", "feb"]
                .iter()
                .any(|p| addr.starts_with(p));
            if link_local && up && !loopback {
                scopes.push(u32::from_str_radix(index, 16).unwrap());
            }
        }
        match link_local_scope() {
            Some(scope) => assert!(scopes.contains(&scope.get()), "{scope} of {scopes:?}"),
            None => assert!(scopes.is_empty(), "none of {scopes:?}"),
        }
    }

    /// An address's scope is C's: the unique-local, link-local and
    /// site-local prefixes, the loopback address, and global for any
    /// other and for IPv4.
    #[test]
    fn an_address_s_scope_is_c_s() {
        let scope = |a: &str| ipv6_scope(a.parse().unwrap());
        assert_eq!(scope("fc00::1"), Ipv6Scope::UniqueLocal);
        assert_eq!(scope("fdff::1"), Ipv6Scope::UniqueLocal);
        assert_eq!(scope("fe80::1"), Ipv6Scope::LinkLocal);
        assert_eq!(scope("febf::1"), Ipv6Scope::LinkLocal);
        assert_eq!(scope("fec0::1"), Ipv6Scope::SiteLocal);
        assert_eq!(scope("::1"), Ipv6Scope::NodeLocal);
        assert_eq!(scope("::2"), Ipv6Scope::Global);
        assert_eq!(scope("::"), Ipv6Scope::Global);
        assert_eq!(scope("2001:db8::1"), Ipv6Scope::Global);
        assert_eq!(scope("127.0.0.1"), Ipv6Scope::Global);
    }

    /// The loopback interface has the loopback addresses, each of its
    /// family; an IPv6 one only of the scope wanted; a name no interface
    /// has, none.
    #[test]
    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore = "FFI")]
    fn an_interface_s_address_is_of_the_family_and_scope_asked() {
        let lo = interface_address(b"lo", false, Ipv6Scope::Global, 0);
        assert_eq!(lo, InterfaceAddress::Found("127.0.0.1".parse().unwrap(), 0));
        let missing = interface_address(b"no-such-if0", false, Ipv6Scope::Global, 0);
        assert_eq!(missing, InterfaceAddress::NotFound);
        let has_v6 = std::fs::read_to_string("/proc/net/if_inet6")
            .unwrap_or_default()
            .lines()
            .any(|l| l.ends_with(" lo"));
        if has_v6 {
            let lo6 = interface_address(b"lo", true, Ipv6Scope::NodeLocal, 0);
            assert_eq!(lo6, InterfaceAddress::Found(Ipv6Addr::LOCALHOST.into(), 0));
            let global = interface_address(b"lo", true, Ipv6Scope::Global, 0);
            assert_eq!(global, InterfaceAddress::OtherFamily);
            let scoped = interface_address(b"lo", true, Ipv6Scope::NodeLocal, 77);
            assert_eq!(scoped, InterfaceAddress::OtherFamily);
        }
    }

    /// A socket bound before it connects connects from the address and
    /// port it was bound to; a port in use is refused; an interface no
    /// one has is no device.
    #[test]
    #[cfg_attr(miri, ignore = "FFI")]
    fn a_socket_binds_its_local_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = listener.local_addr().unwrap();
        let s = open(to, Protocol::Tcp, false).unwrap();
        s.set(SocketOption::BindAddressNoPort).unwrap();
        s.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        assert_eq!(s.connect(to).unwrap(), Connect::Done);
        let from = s.local_addr().unwrap();
        assert_eq!(from.ip(), to.ip());
        let taken = open(to, Protocol::Tcp, false).unwrap();
        let refused = taken.bind(from).unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::EADDRINUSE));
        let unknown = taken.bind_to_device(b"no-such-if0").unwrap_err();
        assert_eq!(unknown.raw_os_error(), Some(libc::ENODEV));
        let too_long = taken.bind_to_device(&[b'x'; 255]).unwrap_err();
        assert_eq!(too_long.raw_os_error(), Some(libc::EINVAL));
    }

    /// A Unix socket's address is its path and terminator, or a zero and
    /// the abstract name, after the family, as C sizes it; one that does
    /// not fit is none.
    #[test]
    fn a_unix_address_is_sized_as_c_sizes_it() {
        let at = std::mem::offset_of!(libc::sockaddr_un, sun_path);
        let path = unix_address(b"/tmp/s", false).unwrap();
        assert_eq!(path.len as usize, at + 7);
        let abs = unix_address(b"name", true).unwrap();
        assert_eq!(abs.len as usize, at + 5);
        // SAFETY: the storage holds the `sockaddr_un` written.
        let un = unsafe { (&raw const abs.raw).cast::<libc::sockaddr_un>().read() };
        assert_eq!(i32::from(un.sun_family), libc::AF_UNIX);
        #[allow(
            clippy::unnecessary_cast,
            reason = "`c_char` is signed on some targets"
        )]
        let name: Vec<u8> = un.sun_path[..6].iter().map(|&c| c as u8).collect();
        assert_eq!(name, b"\0name\0");
        assert!(unix_address(&[b'x'; UNIX_PATH_ROOM - 1], false).is_some());
        assert!(unix_address(&[b'x'; UNIX_PATH_ROOM], false).is_none());
        assert!(unix_address(&[b'x'; UNIX_PATH_ROOM], true).is_none());
        assert!(unix_address(b"a\0b", false).is_none());
    }

    /// A Unix socket connects to one listening at a path, and to one of
    /// an abstract name; to a path nothing listens at, it fails at once.
    #[test]
    #[cfg_attr(miri, ignore = "FFI")]
    fn a_unix_socket_connects_by_path_and_by_name() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener};
        let dir = std::env::temp_dir().join(format!("curl-os-uds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let s = open_unix(false).unwrap();
        let bytes = path.as_os_str().as_encoded_bytes();
        assert_eq!(s.connect_unix(bytes, false).unwrap(), Connect::Done);
        let (accepted, _) = listener.accept().unwrap();
        assert_eq!(
            s.send(b"hi").unwrap(),
            Sent::Bytes(NonZeroUsize::new(2).unwrap())
        );
        let mut got = [0; 2];
        std::io::Read::read_exact(&mut &accepted, &mut got).unwrap();
        assert_eq!(&got, b"hi");
        assert!(s.local_addr().is_err(), "no address of TCP's families");
        let name = format!("curl-os-uds-{}", std::process::id());
        let abs = UnixListener::bind_addr(&UnixAddr::from_abstract_name(&name).unwrap()).unwrap();
        let s = open_unix(false).unwrap();
        assert_eq!(
            s.connect_unix(name.as_bytes(), true).unwrap(),
            Connect::Done
        );
        abs.accept().unwrap();
        drop(listener);
        std::fs::remove_file(&path).unwrap();
        let refused = open_unix(true)
            .unwrap()
            .connect_unix(bytes, false)
            .unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::ENOENT));
        std::fs::remove_dir(&dir).unwrap();
    }
}
