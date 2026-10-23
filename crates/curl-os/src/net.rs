//! Nonblocking TCP sockets (`lib/cf-socket.c`). Opening and connecting
//! are system calls of their own; everything after goes through a std
//! `TcpStream`, which already sends with `MSG_NOSIGNAL`. A nonblocking
//! receive or send never sleeps, so no signal interrupts it.

#![allow(unsafe_code)]

use std::io::{self, Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::num::{NonZeroU32, NonZeroUsize};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};

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

/// A nonblocking TCP socket, connected or connecting.
#[derive(Debug)]
pub struct TcpSocket(TcpStream);

/// What a TCP socket is set to between its opening and its connect
/// (`cf_socket_open`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketOptions {
    /// Small sends go out at once, Nagle's algorithm off (`TCP_NODELAY`).
    pub nodelay: bool,
}

/// As curl sets a socket unless told otherwise: `TCP_NODELAY` on
/// (url.c's `Curl_init_userdefined`).
impl Default for SocketOptions {
    fn default() -> SocketOptions {
        SocketOptions { nodelay: true }
    }
}

/// Open a nonblocking, close-on-exec TCP socket, set it to `options`,
/// and start connecting it to `addr`.
pub fn connect(addr: SocketAddr, options: SocketOptions) -> io::Result<(TcpSocket, Connect)> {
    let family = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let kind = libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
    // SAFETY: `socket` takes no pointers; a negative result is an error.
    let fd = unsafe { libc::socket(family, kind, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and is owned by nothing else.
    let socket = TcpStream::from(unsafe { OwnedFd::from_raw_fd(fd) });
    if options.nodelay {
        // C only traces a failure (`tcpnodelay`): the socket works the
        // same, its small sends merely wait.
        let _ = socket.set_nodelay(true);
    }
    let mut storage = SockAddr::from(addr);
    // SAFETY: `storage` holds a sockaddr of `addr`'s family, valid for the
    // length given, and lives through the call; the socket is open.
    let rc = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&socket),
            (&raw mut storage.raw).cast::<libc::sockaddr>(),
            storage.len,
        )
    };
    let state = if rc == 0 {
        Connect::Done
    } else {
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // A nonblocking connect interrupted by a signal goes on in
            // the background, as one in progress does.
            Some(libc::EINPROGRESS | libc::EINTR) => Connect::InProgress,
            _ => return Err(err),
        }
    };
    Ok((TcpSocket(socket), state))
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

impl TcpSocket {
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
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
        match (&self.0).read(buf) {
            Ok(n) => Ok(NonZeroUsize::new(n).map_or(Recv::Eof, Recv::Data)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Recv::WouldBlock),
            Err(e) => Err(e),
        }
    }

    /// Send from `buf`, which must not be empty.
    pub fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        assert!(!buf.is_empty(), "a send needs bytes");
        match (&self.0).write(buf) {
            Ok(n) => {
                let n = NonZeroUsize::new(n).expect("a send of some bytes takes some");
                Ok(Sent::Bytes(n))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Sent::WouldBlock),
            Err(e) => Err(e),
        }
    }

    /// Send nothing more; the peer reads the end of the stream.
    pub fn shutdown_send(&self) -> io::Result<()> {
        self.0.shutdown(Shutdown::Write)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
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

    const NODELAY: SocketOptions = SocketOptions { nodelay: true };

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
        let (s, state) = connect(listener.local_addr().unwrap(), NODELAY).unwrap();
        if state == Connect::InProgress {
            assert!(ready(&s, Events::OUT).contains(Events::OUT));
        }
        assert!(s.take_error().unwrap().is_none());
        let (peer, from) = listener.accept().unwrap();
        assert_eq!(from, s.local_addr().unwrap());
        assert_eq!(s.peer_addr().unwrap(), listener.local_addr().unwrap());
        (s, peer)
    }

    /// The socket is set as asked before it connects: Nagle's algorithm
    /// off for `nodelay`, as C sets it by default, and left on without.
    #[test]
    fn a_socket_is_set_as_asked() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        for nodelay in [true, false] {
            let (s, _) = connect(addr, SocketOptions { nodelay }).unwrap();
            assert_eq!(s.0.nodelay().unwrap(), nodelay);
        }
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
        let err = match connect(addr, NODELAY) {
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
        let (s, _) = connect(addr, NODELAY).unwrap();
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
        let err = connect(addr, NODELAY).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EMFILE));
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
}
