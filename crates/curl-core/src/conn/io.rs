//! The engine's way to the network, and the fake that stands in for it in
//! tests. Only `conn` and `Multi::wait` call it.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::time::Duration;

use curl_alloc::{TryVec, try_box};

use crate::time::Instant;

pub use curl_os::net::Connect;
pub use curl_os::poll::{Events, PollFd};
pub use curl_os::wake::Waker;

/// A socket's number, as C hands it to the application (`curl_socket_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketKey(i32);

impl SocketKey {
    pub fn get(self) -> i32 {
        self.0
    }
}

/// A socket the network opened.
pub trait Socket: fmt::Debug {
    fn key(&self) -> SocketKey;

    /// How to learn whether it is ready: a descriptor to poll, or, for a
    /// socket that has none, what it is ready for now.
    fn readiness(&self) -> Readiness<'_>;

    /// The error that ended a connect in progress, once the socket is
    /// writable; `None` if it connected (`SO_ERROR`).
    fn take_error(&self) -> io::Result<Option<io::Error>>;

    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// How a socket's readiness is learned.
#[derive(Clone, Copy, Debug)]
pub enum Readiness<'a> {
    Poll(BorrowedFd<'a>),
    /// A socket without a descriptor knows what it is ready for now, and
    /// when it will be ready if it is not.
    Known {
        now: Events,
        later: Option<Instant>,
    },
}

/// A socket to watch in a poll, and what it was found ready for.
#[derive(Debug)]
pub struct SocketPoll<'a> {
    socket: &'a dyn Socket,
    events: Events,
    revents: Events,
}

impl<'a> SocketPoll<'a> {
    pub fn new(socket: &'a dyn Socket, events: Events) -> SocketPoll<'a> {
        SocketPoll {
            socket,
            events,
            revents: Events::NONE,
        }
    }

    pub fn revents(&self) -> Events {
        self.revents
    }
}

/// The network as the engine reaches it.
pub trait Net {
    /// Wait up to `timeout` for any of `sockets` or `fds` to be ready;
    /// with none, sleep. Returns how many have events; a signal ending the
    /// wait early counts as nothing ready.
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> io::Result<u32>;

    /// Open a TCP socket and start connecting it to `addr`.
    fn connect(&mut self, addr: SocketAddr) -> io::Result<(Box<dyn Socket>, Connect)>;

    /// Close a socket the network opened.
    fn close(&mut self, socket: Box<dyn Socket>);
}

impl Socket for curl_os::net::TcpSocket {
    fn key(&self) -> SocketKey {
        SocketKey(self.fd().as_raw_fd())
    }

    fn readiness(&self) -> Readiness<'_> {
        Readiness::Poll(self.fd())
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        curl_os::net::TcpSocket::take_error(self)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        curl_os::net::TcpSocket::local_addr(self)
    }
}

/// The operating system's network.
#[derive(Debug, Default)]
pub struct SystemNet;

impl Net for SystemNet {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> io::Result<u32> {
        poll_together(sockets, fds, timeout)
    }

    fn connect(&mut self, addr: SocketAddr) -> io::Result<(Box<dyn Socket>, Connect)> {
        let (socket, connect) = curl_os::net::connect(addr)?;
        let socket: Box<dyn Socket> = try_box(socket).map_err(|_| io::ErrorKind::OutOfMemory)?;
        Ok((socket, connect))
    }

    fn close(&mut self, socket: Box<dyn Socket>) {
        drop(socket);
    }
}

/// Poll `fds` and the sockets with descriptors in one call; sockets that
/// know their readiness count without one, and end the wait at once.
fn poll_together(
    sockets: &mut [SocketPoll<'_>],
    fds: &mut [PollFd<'_>],
    timeout: Duration,
) -> io::Result<u32> {
    let mut known = 0;
    for s in sockets.iter_mut() {
        if let Readiness::Known { now: ready, .. } = s.socket.readiness() {
            s.revents = [Events::IN, Events::PRI, Events::OUT]
                .into_iter()
                .filter(|&e| ready.contains(e) && s.events.contains(e))
                .fold(Events::NONE, |a, e| a | e);
            known += u32::from(!s.revents.is_empty());
        }
    }
    let timeout = if known > 0 { Duration::ZERO } else { timeout };
    if sockets.is_empty() {
        return curl_os::poll::poll(fds, timeout);
    }
    let mut all = Vec::new();
    all.try_reserve_exact(sockets.len() + fds.len())
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for s in sockets.iter() {
        if let Readiness::Poll(fd) = s.socket.readiness() {
            all.try_push(PollFd::new(fd, s.events)).expect("reserved");
        }
    }
    let polled_sockets = all.len();
    for fd in fds.iter() {
        all.try_push(*fd).expect("reserved");
    }
    let ready = curl_os::poll::poll(&mut all, timeout)?;
    let mut polled = all.iter();
    for s in sockets.iter_mut() {
        if let Readiness::Poll(_) = s.socket.readiness() {
            s.revents = polled.next().expect("one per socket polled").revents();
        }
    }
    for (mine, p) in fds.iter_mut().zip(&all[polled_sockets..]) {
        mine.copy_revents(p);
    }
    Ok(ready + known)
}

/// How a fake peer answers a connect.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// It accepts once the socket is polled.
    Accepts,
    /// It accepts once this much time has passed.
    AcceptsAfter(Duration),
    /// It refuses once the socket is polled (`ECONNREFUSED`).
    Refuses,
    /// It never answers.
    Silent,
}

/// A network where waiting takes no time: a poll that finds nothing ready
/// moves the clock on by its timeout instead of sleeping. Real descriptors
/// given to it, a waker's or the application's, are still polled. Connects
/// reach fake peers, by address; one to an address with no peer is
/// refused at once.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct FakeNet {
    clock: crate::time::ManualClock,
    peers: Vec<(SocketAddr, Peer)>,
    /// The sockets open, by number from `FIRST_FAKE`, each with whether
    /// its peer hung up: a closed number is handed out again, lowest
    /// first, as the kernel does.
    open: Vec<Option<HungUp>>,
}

/// Whether a fake socket's peer hung up, shared by the socket and its
/// network.
#[cfg(any(test, feature = "test-util"))]
type HungUp = curl_alloc::TryRc<std::cell::Cell<bool>>;

/// The first number a fake socket gets: past the descriptors a test
/// process has open, so that a fake one is never mistaken for them.
#[cfg(any(test, feature = "test-util"))]
const FIRST_FAKE: i32 = 1000;

#[cfg(any(test, feature = "test-util"))]
impl FakeNet {
    /// A network whose waits move `clock`.
    pub fn new(clock: crate::time::ManualClock) -> FakeNet {
        FakeNet {
            clock,
            peers: Vec::new(),
            open: Vec::new(),
        }
    }

    /// A peer at `addr`.
    pub fn with_peer(mut self, addr: SocketAddr, peer: Peer) -> FakeNet {
        self.peers
            .try_push((addr, peer))
            .expect("a test's peers fit");
        self
    }

    fn open_number(&mut self, hung_up: HungUp) -> io::Result<SocketKey> {
        let row = match self.open.iter().position(Option::is_none) {
            Some(row) => row,
            None => {
                self.open
                    .try_push(None)
                    .map_err(|_| io::ErrorKind::OutOfMemory)?;
                self.open.len() - 1
            }
        };
        self.open[row] = Some(hung_up);
        let n = i32::try_from(row).expect("a test opens few sockets");
        Ok(SocketKey(FIRST_FAKE + n))
    }

    /// The peer of socket `key` closes its side: the socket reads as
    /// ready, with nothing but the end to read.
    pub fn hang_up(&self, key: SocketKey) {
        let row = usize::try_from(key.0 - FIRST_FAKE).expect("a fake socket's number");
        self.open[row].as_ref().expect("an open socket").set(true);
    }

    /// How many fake sockets are open.
    pub fn open_sockets(&self) -> usize {
        self.open.iter().filter(|s| s.is_some()).count()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Net for FakeNet {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> io::Result<u32> {
        let ready = poll_together(sockets, fds, Duration::ZERO)?;
        if ready > 0 {
            return Ok(ready);
        }
        // Wait for the first fake socket to come ready, or the timeout.
        let now = crate::time::Clock::now(&self.clock);
        let soonest = sockets
            .iter()
            .filter_map(|s| match s.socket.readiness() {
                Readiness::Known { later, .. } => later,
                Readiness::Poll(_) => None,
            })
            .map(|at| at.since(now))
            .min();
        match soonest {
            Some(wait) if wait < timeout => {
                self.clock.advance(wait);
                poll_together(sockets, fds, Duration::ZERO)
            }
            _ => {
                self.clock.advance(timeout);
                Ok(0)
            }
        }
    }

    fn connect(&mut self, addr: SocketAddr) -> io::Result<(Box<dyn Socket>, Connect)> {
        let Some(&(_, peer)) = self.peers.iter().find(|(a, _)| *a == addr) else {
            return Err(io::Error::from_raw_os_error(libc_errno::ECONNREFUSED));
        };
        let hung_up = curl_alloc::TryRc::try_new(std::cell::Cell::new(false))
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let key = self.open_number(hung_up.clone())?;
        // The port the kernel would have picked.
        let port = 40000 + u16::try_from(key.0 - FIRST_FAKE).expect("a test opens few sockets");
        let local = match addr {
            SocketAddr::V4(_) => SocketAddr::from(([127, 0, 0, 1], port)),
            SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
        };
        let now = crate::time::Clock::now(&self.clock);
        let ready_at = match peer {
            Peer::AcceptsAfter(d) => Some(now.after(d)),
            Peer::Accepts | Peer::Refuses | Peer::Silent => None,
        };
        let clock = self.clock.clone();
        let socket = FakeSocket {
            key,
            peer,
            local,
            clock,
            ready_at,
            hung_up,
        };
        let socket: Box<dyn Socket> = try_box(socket).map_err(|_| io::ErrorKind::OutOfMemory)?;
        Ok((socket, Connect::InProgress))
    }

    fn close(&mut self, socket: Box<dyn Socket>) {
        let row = usize::try_from(socket.key().0 - FIRST_FAKE).expect("a fake socket's number");
        assert!(
            self.open[row].take().is_some(),
            "{:?} closed twice",
            socket.key()
        );
    }
}

/// A socket to a fake peer.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
struct FakeSocket {
    key: SocketKey,
    peer: Peer,
    local: SocketAddr,
    clock: crate::time::ManualClock,
    /// When a peer that answers late answers.
    ready_at: Option<Instant>,
    hung_up: HungUp,
}

#[cfg(any(test, feature = "test-util"))]
impl Socket for FakeSocket {
    fn key(&self) -> SocketKey {
        self.key
    }

    fn readiness(&self) -> Readiness<'_> {
        if self.hung_up.get() {
            return Readiness::Known {
                now: Events::IN | Events::OUT,
                later: None,
            };
        }
        let now = match (self.peer, self.ready_at) {
            (Peer::Accepts | Peer::Refuses, _) => Events::OUT,
            (Peer::AcceptsAfter(_), Some(at)) if crate::time::Clock::now(&self.clock) >= at => {
                Events::OUT
            }
            (Peer::AcceptsAfter(_) | Peer::Silent, _) => Events::NONE,
        };
        let later = self.ready_at.filter(|_| now.is_empty());
        Readiness::Known { now, later }
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        Ok(match self.peer {
            Peer::Refuses => Some(io::Error::from_raw_os_error(libc_errno::ECONNREFUSED)),
            Peer::Accepts | Peer::AcceptsAfter(_) | Peer::Silent => None,
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// The error numbers the fake gives, as Linux numbers them.
#[cfg(any(test, feature = "test-util"))]
mod libc_errno {
    pub(super) const ECONNREFUSED: i32 = 111;
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn the_system_network_polls_the_descriptors() {
        let (mut a, b) = UnixStream::pair().unwrap();
        let mut fds = [PollFd::new(b.as_fd(), Events::IN)];
        let none = &mut [];
        assert_eq!(
            SystemNet
                .poll(none, &mut fds, Duration::from_millis(1))
                .unwrap(),
            0
        );
        a.write_all(b"x").unwrap();
        assert_eq!(
            SystemNet
                .poll(none, &mut fds, Duration::from_secs(5))
                .unwrap(),
            1
        );
        assert!(fds[0].revents().contains(Events::IN));
    }

    /// A real socket and a descriptor polled together each get their own
    /// events back.
    #[test]
    fn sockets_and_descriptors_are_polled_together() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (socket, _) = SystemNet.connect(listener.local_addr().unwrap()).unwrap();
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"x").unwrap();
        let mut sockets = [SocketPoll::new(&*socket, Events::OUT)];
        let mut fds = [PollFd::new(b.as_fd(), Events::IN)];
        let ready = SystemNet
            .poll(&mut sockets, &mut fds, Duration::from_secs(5))
            .unwrap();
        assert!(ready >= 1);
        assert!(fds[0].revents().contains(Events::IN));
        // The connect is decided by now or soon; once it is, writable.
        let mut sockets = [SocketPoll::new(&*socket, Events::OUT)];
        SystemNet
            .poll(&mut sockets, &mut [], Duration::from_secs(5))
            .unwrap();
        assert!(sockets[0].revents().contains(Events::OUT));
        assert!(socket.take_error().unwrap().is_none());
        SystemNet.close(socket);
    }

    /// Fake sockets get the lowest free number, and a fake peer's answer
    /// shows once the socket is polled.
    #[test]
    fn fake_peers_answer_and_numbers_are_reused() {
        use crate::time::Clock as _;
        let clock = crate::time::ManualClock::new().unwrap();
        let at = |port| SocketAddr::from(([127, 0, 0, 1], port));
        let mut net = FakeNet::new(clock.clone())
            .with_peer(at(1), Peer::Accepts)
            .with_peer(at(2), Peer::Refuses)
            .with_peer(at(3), Peer::Silent);
        let err = net.connect(at(9)).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(111), "no peer: refused at once");
        let (a, _) = net.connect(at(1)).unwrap();
        let (b, _) = net.connect(at(2)).unwrap();
        let (c, _) = net.connect(at(3)).unwrap();
        assert_eq!(
            [a.key(), b.key(), c.key()].map(SocketKey::get),
            [1000, 1001, 1002]
        );
        let start = clock.now();
        let mut sockets = [
            SocketPoll::new(&*a, Events::OUT),
            SocketPoll::new(&*b, Events::OUT),
            SocketPoll::new(&*c, Events::OUT),
        ];
        let ready = net
            .poll(&mut sockets, &mut [], Duration::from_secs(5))
            .unwrap();
        assert_eq!(ready, 2);
        assert_eq!(
            sockets.each_ref().map(|s| s.revents()),
            [Events::OUT, Events::OUT, Events::NONE]
        );
        assert_eq!(clock.now(), start, "something was ready: no time passed");
        assert!(a.take_error().unwrap().is_none());
        let refused = b.take_error().unwrap().unwrap();
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
        let mut silent = [SocketPoll::new(&*c, Events::OUT)];
        assert_eq!(
            net.poll(&mut silent, &mut [], Duration::from_secs(5))
                .unwrap(),
            0
        );
        assert_eq!(clock.now().since(start), Duration::from_secs(5));
        net.close(b);
        let (d, _) = net.connect(at(1)).unwrap();
        assert_eq!(d.key().get(), 1001, "the lowest free number again");
        for s in [a, c, d] {
            net.close(s);
        }
    }
}
