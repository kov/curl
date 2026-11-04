//! Waking a waiting multi from another thread (`curl_multi_wakeup`,
//! `lib/socketpair.c`): an eventfd, as C makes one where the system has
//! it (`wakeup_eventfd`), written by those that wake and polled by the
//! waiting thread. It is nonblocking, so a wake never waits and a drain
//! stops once the count is read. On macOS, which has no eventfd, it is
//! C's pipe (`wakeup_pipe`); on Windows C's pair of loopback sockets.

#![allow(unsafe_code)]

use std::io;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

/// Shared between the waiting thread and those that wake it.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Waker(OwnedFd);

#[cfg(target_os = "linux")]
impl Waker {
    pub fn new() -> io::Result<Waker> {
        // SAFETY: `eventfd` takes no pointers; a negative result is an
        // error.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just opened and is owned by nothing else.
        Ok(Waker(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Make the next poll of [`Waker::fd`] report it readable
    /// (`Curl_wakeup_signal`): one added to the count. A count that cannot
    /// grow is a wake already pending, not an error.
    pub fn wake(&self) -> io::Result<()> {
        let one = 1u64.to_ne_bytes();
        loop {
            // SAFETY: the descriptor is open while `self` lives, and the
            // buffer is the 8 bytes an eventfd is written with.
            let n = unsafe { libc::write(self.0.as_raw_fd(), one.as_ptr().cast(), one.len()) };
            if n >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(()),
                _ => return Err(e),
            }
        }
    }

    /// Consume every pending wake (`Curl_wakeup_consume`): reading the
    /// count resets it.
    pub fn drain(&self) -> io::Result<()> {
        let mut count = [0u8; 8];
        loop {
            // SAFETY: as in `wake`; the buffer has room for the count.
            let n =
                unsafe { libc::read(self.0.as_raw_fd(), count.as_mut_ptr().cast(), count.len()) };
            if n >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(()),
                _ => return Err(e),
            }
        }
    }

    /// The descriptor to poll for reading.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// Shared between the waiting thread and those that wake it: on macOS a
/// pipe, as C makes one there (`wakeup_pipe`), both ends close-on-exec and
/// nonblocking. The waiting thread polls the reading end, those that wake
/// write a byte to the other.
#[cfg(target_vendor = "apple")]
#[derive(Debug)]
pub struct Waker {
    /// The end polled and drained (C's `socks[0]`).
    read: OwnedFd,
    /// The end written (C's `socks[1]`).
    write: OwnedFd,
}

#[cfg(target_vendor = "apple")]
impl Waker {
    /// A pipe, each end then made close-on-exec and nonblocking with
    /// `fcntl`, as C makes one without `pipe2`. A step failing closes
    /// both ends.
    pub fn new() -> io::Result<Waker> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` has room for the two descriptors `pipe` writes.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both were just opened and are owned by nothing else.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        for end in [read.as_fd(), write.as_fd()] {
            // SAFETY: `fcntl` with `F_SETFD` takes an int, no pointer; the
            // end is open.
            if unsafe { libc::fcntl(end.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        for end in [read.as_fd(), write.as_fd()] {
            // SAFETY: as above, `F_GETFL` and `F_SETFL` with an int.
            let flags = unsafe { libc::fcntl(end.as_raw_fd(), libc::F_GETFL) };
            // SAFETY: as above.
            if flags < 0
                || unsafe { libc::fcntl(end.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                    < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Waker { read, write })
    }

    /// Make the next poll of [`Waker::fd`] report it readable
    /// (`Curl_wakeup_signal`): one byte written. A pipe too full to take
    /// it is a wake already pending, not an error.
    pub fn wake(&self) -> io::Result<()> {
        let one = [1u8];
        loop {
            // SAFETY: the end is open while `self` lives, and the buffer
            // is the one byte written.
            let n = unsafe { libc::write(self.write.as_raw_fd(), one.as_ptr().cast(), one.len()) };
            if n >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(()),
                _ => return Err(e),
            }
        }
    }

    /// Consume every pending wake (`Curl_wakeup_consume` with `all`):
    /// read until nothing is left, or the other end is gone.
    pub fn drain(&self) -> io::Result<()> {
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: as in `wake`; the buffer has room for what is read.
            let n =
                unsafe { libc::read(self.read.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n == 0 {
                return Ok(());
            }
            if n > 0 {
                continue;
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(()),
                _ => return Err(e),
            }
        }
    }

    /// The descriptor to poll for reading.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.read.as_fd()
    }
}

/// Shared between the waiting thread and those that wake it: on Windows a
/// pair of connected loopback TCP sockets, as C makes one there
/// (`wakeup_inet`, for want of `eventfd`, `pipe` and `socketpair`). The
/// waiting thread polls one end, those that wake write a byte to the
/// other; both are nonblocking.
#[cfg(windows)]
#[derive(Debug)]
pub struct Waker {
    /// The end polled and drained (C's `socks[0]`, which connected).
    read: std::net::TcpStream,
    /// The end written (C's `socks[1]`, accepted).
    write: std::net::TcpStream,
}

#[cfg(windows)]
impl Waker {
    /// Make the pair as `wakeup_inet` does: a listener on the loopback
    /// address's port the system picks, held exclusively, a socket
    /// connected to it and the one accepted, and random bytes sent from
    /// the one to the other to check that they are the pair, read for at
    /// most a minute. Winsock must be started.
    pub fn new() -> io::Result<Waker> {
        use std::io::{Read as _, Write as _};
        use std::os::windows::io::{AsRawSocket as _, FromRawSocket as _};
        use std::time::Duration;

        use windows_sys::Win32::Networking::WinSock as ws;

        use crate::poll::{Events, PollFd, poll};
        use crate::socket::OwnedSocket;

        let last_error = || {
            // SAFETY: `WSAGetLastError` only reads the thread's error.
            io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() })
        };
        let open = || {
            // SAFETY: `socket` takes no pointers; `INVALID_SOCKET` is an
            // error.
            let s = unsafe { ws::socket(i32::from(ws::AF_INET), ws::SOCK_STREAM, ws::IPPROTO_TCP) };
            if s == ws::INVALID_SOCKET {
                return Err(last_error());
            }
            // SAFETY: `s` was just opened and is owned by nothing else.
            Ok(unsafe { OwnedSocket::from_raw_socket(s as u64) })
        };
        let checked = |rc: i32| {
            if rc == ws::SOCKET_ERROR {
                Err(last_error())
            } else {
                Ok(())
            }
        };
        let raw = |s: &OwnedSocket| s.as_raw_socket() as ws::SOCKET;
        let nonblocking = |s: ws::SOCKET| {
            let mut on = 1u32;
            // SAFETY: `on` is the `u_long` the request reads, alive through
            // the call; the socket is open.
            checked(unsafe { ws::ioctlsocket(s, ws::FIONBIO, &raw mut on) })
        };

        let listener = open()?;
        let exclusive = 1i32;
        let int = i32::try_from(size_of::<i32>()).expect("fits");
        // SAFETY: `exclusive` is an int of the length given, alive through
        // the call; the socket is open. C does not set `SO_REUSEADDR` here.
        checked(unsafe {
            ws::setsockopt(
                raw(&listener),
                ws::SOL_SOCKET,
                ws::SO_EXCLUSIVEADDRUSE,
                (&raw const exclusive).cast(),
                int,
            )
        })?;
        // SAFETY: all-zero bytes are a valid `SOCKADDR_IN`.
        let mut addr: ws::SOCKADDR_IN = unsafe { core::mem::zeroed() };
        addr.sin_family = ws::AF_INET;
        addr.sin_addr.S_un.S_addr = ws::INADDR_LOOPBACK.to_be();
        let mut len = i32::try_from(size_of::<ws::SOCKADDR_IN>()).expect("fits");
        let full = len;
        // SAFETY: `addr` is an IPv4 address of the length given, alive
        // through the call; the socket is open.
        checked(unsafe { ws::bind(raw(&listener), (&raw const addr).cast(), len) })?;
        // SAFETY: `addr` has room for the IPv4 address and `len` says so,
        // both alive through the call.
        checked(unsafe { ws::getsockname(raw(&listener), (&raw mut addr).cast(), &raw mut len) })?;
        if len < full {
            return Err(io::Error::from_raw_os_error(ws::WSAEINVAL));
        }
        // SAFETY: `listen` takes no pointers; the socket is open.
        checked(unsafe { ws::listen(raw(&listener), 1) })?;
        let read = open()?;
        // SAFETY: `addr` is the listener's address, of the length given,
        // alive through the call; the socket is open and blocking.
        checked(unsafe { ws::connect(raw(&read), (&raw const addr).cast(), full) })?;
        // A nonblocking accept, so as not to wait for ever.
        nonblocking(raw(&listener))?;
        {
            let mut fds = [PollFd::new(
                std::os::windows::io::AsSocket::as_socket(&listener),
                Events::IN,
            )];
            poll(&mut fds, Duration::from_secs(1))?;
        }
        // SAFETY: null asks for no peer address; the socket is open.
        let s = unsafe { ws::accept(raw(&listener), core::ptr::null_mut(), core::ptr::null_mut()) };
        if s == ws::INVALID_SOCKET {
            return Err(last_error());
        }
        // SAFETY: `s` was just accepted and is owned by nothing else.
        let write = std::net::TcpStream::from(unsafe { OwnedSocket::from_raw_socket(s as u64) });
        let read = std::net::TcpStream::from(read);

        let mut sent = [0u8; 9];
        crate::random::fill(&mut sent)?;
        // From the end connected to the one accepted, as C checks them.
        (&read).write_all(&sent)?;
        let start = crate::time::monotonic();
        let mut got = [0u8; 9];
        let mut have = 0;
        while have < got.len() {
            if crate::time::monotonic() - start > Duration::from_secs(60) {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let mut fds = [PollFd::new(
                std::os::windows::io::AsSocket::as_socket(&write),
                Events::IN,
            )];
            poll(&mut fds, Duration::from_secs(1))?;
            match (&write).read(&mut got[have..]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => have += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        if got != sent {
            return Err(io::ErrorKind::InvalidData.into());
        }
        nonblocking(read.as_raw_socket() as ws::SOCKET)?;
        nonblocking(write.as_raw_socket() as ws::SOCKET)?;
        Ok(Waker { read, write })
    }

    /// Make the next poll of [`Waker::fd`] report it readable
    /// (`Curl_wakeup_signal`): one byte written. A buffer too full to take
    /// it is a wake already pending, not an error.
    pub fn wake(&self) -> io::Result<()> {
        use std::io::Write as _;
        match (&self.write).write(&[1]) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Consume every pending wake (`Curl_wakeup_consume` with `all`):
    /// read until nothing is left, or the other end is gone.
    pub fn drain(&self) -> io::Result<()> {
        use std::io::Read as _;
        let mut buf = [0u8; 64];
        loop {
            match (&self.read).read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// The socket to poll for reading.
    pub fn fd(&self) -> crate::socket::BorrowedSocket<'_> {
        std::os::windows::io::AsSocket::as_socket(&self.read)
    }
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use std::time::Duration;

    use super::*;
    use crate::poll::{Events, PollFd, poll};

    fn woken(w: &Waker) -> bool {
        let mut fds = [PollFd::new(w.fd(), Events::IN)];
        poll(&mut fds, Duration::ZERO).unwrap() == 1
    }

    #[test]
    fn a_wake_is_seen_until_drained() {
        let w = Waker::new().unwrap();
        assert!(!woken(&w));
        w.wake().unwrap();
        w.wake().unwrap();
        assert!(woken(&w));
        w.drain().unwrap();
        assert!(!woken(&w), "every pending wake consumed at once");
    }

    /// One descriptor, an eventfd, as C's (`wakeup_eventfd`): a process
    /// short of descriptors still gets its waker, and the descriptors
    /// after it are numbered as C numbers them.
    #[test]
    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore = "Miri cannot read a descriptor's link")]
    fn the_waker_is_one_eventfd() {
        let w = Waker::new().unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&w.fd());
        let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
        assert_eq!(link.to_str(), Some("anon_inode:[eventfd]"));
        // SAFETY: `fcntl` on a descriptor `w` holds open.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_ne!(flags & libc::O_NONBLOCK, 0, "nonblocking");
        // SAFETY: as above.
        let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0, "closed on exec");
    }

    /// Two descriptors on macOS, a pipe's ends, as C's (`wakeup_pipe`):
    /// each nonblocking and closed on exec.
    #[test]
    #[cfg(target_vendor = "apple")]
    fn the_waker_is_a_pipe() {
        let w = Waker::new().unwrap();
        for end in [w.read.as_raw_fd(), w.write.as_raw_fd()] {
            // SAFETY: all zeroes is a valid `stat`, which `fstat` fills
            // for a descriptor `w` holds open.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            assert_eq!(unsafe { libc::fstat(end, &raw mut st) }, 0);
            assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFIFO, "a pipe");
            // SAFETY: `fcntl` on a descriptor `w` holds open.
            let flags = unsafe { libc::fcntl(end, libc::F_GETFL) };
            assert_ne!(flags & libc::O_NONBLOCK, 0, "nonblocking");
            // SAFETY: as above.
            let fd_flags = unsafe { libc::fcntl(end, libc::F_GETFD) };
            assert_ne!(fd_flags & libc::FD_CLOEXEC, 0, "closed on exec");
        }
    }

    /// A wake with one already pending past counting is no error, as C's
    /// "wakeup is already ongoing"; a drain with none pending is none
    /// (`Curl_wakeup_signal`, `Curl_wakeup_consume` on `EAGAIN`).
    #[test]
    #[cfg(target_os = "linux")]
    fn a_full_count_wakes_and_an_empty_one_drains() {
        use std::io::Write as _;
        let w = Waker::new().unwrap();
        w.drain().unwrap();
        assert!(!woken(&w));
        // The most an eventfd counts: one more would block.
        let mut count = std::fs::File::from(w.fd().try_clone_to_owned().unwrap());
        count.write_all(&(u64::MAX - 1).to_ne_bytes()).unwrap();
        w.wake().unwrap();
        assert!(woken(&w));
        w.drain().unwrap();
        assert!(!woken(&w));
        w.drain().unwrap();
    }

    #[test]
    fn many_wakes_drain_as_one() {
        let w = Waker::new().unwrap();
        // Far more than a socket buffer or a pipe would hold, one each: a
        // full pipe is a wake pending, not an error.
        for _ in 0..1_000_000 {
            w.wake().unwrap();
        }
        w.drain().unwrap();
        assert!(!woken(&w));
    }

    #[test]
    fn another_thread_wakes_a_waiting_one() {
        let w = Waker::new().unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(20));
                w.wake().unwrap();
            });
            let mut fds = [PollFd::new(w.fd(), Events::IN)];
            assert_eq!(poll(&mut fds, Duration::from_secs(10)).unwrap(), 1);
        });
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use std::time::Duration;

    use super::*;
    use crate::poll::{Events, PollFd, poll};

    fn started() {
        std::mem::forget(crate::net::Winsock::start().unwrap());
    }

    fn woken(w: &Waker) -> bool {
        let mut fds = [PollFd::new(w.fd(), Events::IN)];
        poll(&mut fds, Duration::ZERO).unwrap() == 1
    }

    #[test]
    fn a_wake_is_seen_until_drained() {
        started();
        let w = Waker::new().unwrap();
        assert!(!woken(&w));
        w.wake().unwrap();
        w.wake().unwrap();
        assert!(woken(&w));
        w.drain().unwrap();
        assert!(!woken(&w), "every pending wake consumed at once");
        w.drain().unwrap();
    }

    /// C's pair: the end polled is connected to the loopback address, to
    /// the end written, which was accepted.
    #[test]
    fn the_waker_is_a_loopback_pair() {
        started();
        let w = Waker::new().unwrap();
        let read = w.read.local_addr().unwrap();
        assert!(read.ip().is_loopback());
        assert_eq!(w.write.peer_addr().unwrap(), read);
        assert_eq!(w.read.peer_addr().unwrap(), w.write.local_addr().unwrap());
    }

    /// More wakes than the socket's buffers hold: those past it are wakes
    /// already pending, and one drain takes them all.
    #[test]
    fn many_wakes_drain_as_one() {
        started();
        let w = Waker::new().unwrap();
        for _ in 0..200_000 {
            w.wake().unwrap();
        }
        w.drain().unwrap();
        assert!(!woken(&w));
        w.wake().unwrap();
        assert!(woken(&w), "still wakes after its buffers filled");
    }

    #[test]
    fn another_thread_wakes_a_waiting_one() {
        started();
        let w = Waker::new().unwrap();
        let start = std::time::Instant::now();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(20));
                w.wake().unwrap();
            });
            let mut fds = [PollFd::new(w.fd(), Events::IN)];
            assert_eq!(poll(&mut fds, Duration::from_secs(10)).unwrap(), 1);
        });
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "woken, not timed out"
        );
    }
}
