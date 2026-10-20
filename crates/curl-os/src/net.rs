//! Nonblocking TCP sockets (`lib/cf-socket.c`). Opening and connecting
//! are system calls of their own; everything after goes through a std
//! `TcpStream`, which already sends with `MSG_NOSIGNAL`.

#![allow(unsafe_code)]

use std::io::{self, Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::num::NonZeroUsize;
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

/// Open a nonblocking, close-on-exec TCP socket and start connecting it
/// to `addr`.
pub fn connect(addr: SocketAddr) -> io::Result<(TcpSocket, Connect)> {
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
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut storage = SockAddr::from(addr);
    // SAFETY: `storage` holds a sockaddr of `addr`'s family, valid for the
    // length given, and lives through the call; `fd` is open.
    let rc = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
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
    Ok((TcpSocket(TcpStream::from(fd)), state))
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
        loop {
            match (&self.0).read(buf) {
                Ok(n) => return Ok(NonZeroUsize::new(n).map_or(Recv::Eof, Recv::Data)),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Recv::WouldBlock),
                Err(e) => return Err(e),
            }
        }
    }

    /// Send from `buf`, which must not be empty.
    pub fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        assert!(!buf.is_empty(), "a send needs bytes");
        loop {
            match (&self.0).write(buf) {
                Ok(n) => {
                    let n = NonZeroUsize::new(n).expect("a send of some bytes takes some");
                    return Ok(Sent::Bytes(n));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Sent::WouldBlock),
                Err(e) => return Err(e),
            }
        }
    }

    /// Send nothing more; the peer reads the end of the stream.
    pub fn shutdown_send(&self) -> io::Result<()> {
        self.0.shutdown(Shutdown::Write)
    }

    pub fn set_nodelay(&self, on: bool) -> io::Result<()> {
        self.0.set_nodelay(on)
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
    use std::net::{Ipv6Addr, TcpListener};
    use std::time::Duration;

    use super::*;
    use crate::poll::{Events, PollFd, poll};

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
        s.set_nodelay(true).unwrap();
        s.shutdown_send().unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(std::io::Read::read(&mut peer, &mut buf).unwrap(), 0);
    }
}
