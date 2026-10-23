//! The engine's way to the network, and the fake that stands in for it in
//! tests. Only `conn` and `Multi::wait` call it.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec, try_box};

use crate::handler::{Handler, SocketCloser};
use crate::time::Instant;

pub use curl_os::net::{Connect, Protocol, Recv, Sent, SocketOption, TcpSocket, adopt, open};
pub use curl_os::poll::{Events, PollFd};
pub use curl_os::resolve::{Failure as ResolveFailure, Family};
pub use curl_os::wake::Waker;

/// A socket's number, as C hands it to the application (`curl_socket_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketKey(i32);

impl SocketKey {
    /// No socket (`CURL_SOCKET_BAD`).
    pub(crate) const BAD: SocketKey = SocketKey(-1);

    /// The socket C calls `n`, as the application names it back.
    pub fn new(n: i32) -> SocketKey {
        SocketKey(n)
    }

    pub fn get(self) -> i32 {
        self.0
    }
}

/// A socket the network opened.
pub trait Socket: fmt::Debug + Send {
    fn key(&self) -> SocketKey;

    /// How to learn whether it is ready: a descriptor to poll, or, for a
    /// socket that has none, what it is ready for now.
    fn readiness(&self) -> Readiness<'_>;

    /// The error that ended a connect in progress, once the socket is
    /// writable; `None` if it connected (`SO_ERROR`).
    fn take_error(&self) -> io::Result<Option<io::Error>>;

    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Set `option` on it.
    fn set(&self, option: SocketOption) -> io::Result<()>;

    /// Make it nonblocking, as a socket the application opened may not be.
    fn set_nonblocking(&self) -> io::Result<()>;

    /// Start connecting it to `addr`.
    fn connect(&self, addr: SocketAddr) -> io::Result<Connect>;

    /// Receive into `buf`, which is not empty.
    fn recv(&self, buf: &mut [u8]) -> io::Result<Recv>;

    /// Send from `buf`, which is not empty.
    fn send(&self, buf: &[u8]) -> io::Result<Sent>;

    /// Let go of the descriptor without closing it, for the application's
    /// closer to close: its number.
    fn release(self: Box<Self>) -> SocketKey;
}

/// A socket open, and how it is to be closed: the closer the connection
/// it belongs to was made with. Only `Net::close` takes one; one dropped
/// unclosed is a bug, caught in debug builds.
pub struct Sock {
    /// None only as it closes.
    socket: Option<Box<dyn Socket>>,
    closer: Closer,
}

/// How a connection's sockets are closed: by the system, or by the
/// application's `SocketCloser` (`CURLOPT_CLOSESOCKETFUNCTION`), which C
/// keeps on the connection (url.c:1167) and calls whoever closes it.
#[derive(Clone, Debug, Default)]
pub enum Closer {
    #[default]
    System,
    Hook(Handler<dyn SocketCloser>),
}

impl Sock {
    pub(crate) fn new(socket: Box<dyn Socket>, closer: Closer) -> Sock {
        Sock {
            socket: Some(socket),
            closer,
        }
    }

    pub fn socket(&self) -> &dyn Socket {
        self.socket.as_deref().expect("open until closed")
    }

    pub fn key(&self) -> SocketKey {
        self.socket().key()
    }

    /// Close it: through the system with `close`, which takes the socket,
    /// or through the application's closer, given the number of the
    /// descriptor the socket let go of. What the closer says is not
    /// asked, as C ignores it (`socket_close`).
    pub fn close_with(mut self, close: impl FnOnce(Box<dyn Socket>)) {
        let socket = self.socket.take().expect("open until closed");
        match &self.closer {
            Closer::System => close(socket),
            Closer::Hook(closer) => closer.close(socket.release()),
        }
    }
}

impl fmt::Debug for Sock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sock")
            .field("socket", &self.socket)
            .field("closer", &self.closer)
            .finish()
    }
}

impl Drop for Sock {
    fn drop(&mut self) {
        debug_assert!(
            self.socket.is_none() || std::thread::panicking(),
            "{:?} was dropped, not closed",
            self.socket.as_ref().map(|s| s.key())
        );
    }
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

    /// Open a nonblocking TCP socket for `addr`'s family, not connected
    /// yet.
    fn open(&mut self, addr: SocketAddr) -> io::Result<Box<dyn Socket>>;

    /// Close a socket the network opened, through its closer.
    fn close(&mut self, socket: Sock);

    /// The addresses of `name`, of `family`, as the system's resolver
    /// finds them, waiting for its answer (C's synchronous resolver).
    fn resolve(&mut self, name: &[u8], family: Family) -> Result<Vec<IpAddr>, ResolveFailure>;

    /// The scope of the first local interface that is up, is not
    /// loopback and has a link-local IPv6 address, if any.
    fn link_local_scope(&mut self) -> Option<NonZeroU32>;

    /// Whether IPv6 works here, as a multi asks once as it is made
    /// (`Curl_probeipv6`): an error only if memory ran out. A network of
    /// the tests' has it unless it says otherwise.
    fn probe_ipv6(&mut self) -> Result<bool, OutOfMemory> {
        Ok(true)
    }
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

    fn set(&self, option: SocketOption) -> io::Result<()> {
        curl_os::net::TcpSocket::set(self, option)
    }

    fn set_nonblocking(&self) -> io::Result<()> {
        curl_os::net::TcpSocket::set_nonblocking(self)
    }

    fn connect(&self, addr: SocketAddr) -> io::Result<Connect> {
        curl_os::net::TcpSocket::connect(self, addr)
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<Recv> {
        curl_os::net::TcpSocket::recv(self, buf)
    }

    fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        curl_os::net::TcpSocket::send(self, buf)
    }

    fn release(self: Box<Self>) -> SocketKey {
        SocketKey(self.into_raw())
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

    fn open(&mut self, addr: SocketAddr) -> io::Result<Box<dyn Socket>> {
        let socket = curl_os::net::open(addr, Protocol::Tcp, true)?;
        Ok(try_box(socket).map_err(|_| io::ErrorKind::OutOfMemory)?)
    }

    fn close(&mut self, socket: Sock) {
        socket.close_with(drop);
    }

    fn resolve(&mut self, name: &[u8], family: Family) -> Result<Vec<IpAddr>, ResolveFailure> {
        curl_os::resolve::lookup(name, family)
    }

    fn link_local_scope(&mut self) -> Option<NonZeroU32> {
        curl_os::net::link_local_scope()
    }

    fn probe_ipv6(&mut self) -> Result<bool, OutOfMemory> {
        curl_os::net::probe_ipv6().map_err(|_| OutOfMemory)
    }
}

/// The entries a wait keeps on the stack (`NUM_POLLS_ON_STACK`).
pub(crate) const ON_STACK: usize = 10;

/// Poll `fds` and the sockets with descriptors in one call; sockets that
/// know their readiness count without one, and end the wait at once.
pub(crate) fn poll_together(
    sockets: &mut [SocketPoll<'_>],
    fds: &mut [PollFd<'_>],
    timeout: Duration,
) -> io::Result<u32> {
    let mut known = 0;
    for s in sockets.iter_mut() {
        if let Readiness::Known { now: ready, .. } = s.socket.readiness() {
            // An error, a hang-up or a bad descriptor is said unasked, as
            // `poll(2)` says it.
            let unasked = Events::ERR | Events::HUP | Events::NVAL;
            s.revents = [
                Events::IN,
                Events::RDNORM,
                Events::RDBAND,
                Events::PRI,
                Events::OUT,
            ]
            .into_iter()
            .filter(|&e| s.events.contains(e))
            .chain([Events::ERR, Events::HUP, Events::NVAL])
            .filter(|&e| ready.contains(e) && (s.events | unasked).contains(e))
            .fold(Events::NONE, |a, e| a | e);
            known += u32::from(!s.revents.is_empty());
        }
    }
    let timeout = if known > 0 { Duration::ZERO } else { timeout };
    // With no socket to poll, or one alone as a connect's check polls it,
    // no list is made.
    let mut to_poll = sockets
        .iter_mut()
        .filter_map(|s| match s.socket.readiness() {
            Readiness::Poll(fd) => Some((fd, s)),
            Readiness::Known { .. } => None,
        });
    match (to_poll.next(), to_poll.next()) {
        (None, _) => return Ok(curl_os::poll::poll(fds, timeout)? + known),
        (Some((fd, s)), None) if fds.is_empty() => {
            let mut one = [PollFd::new(fd, s.events)];
            let ready = curl_os::poll::poll(&mut one, timeout)?;
            s.revents = one[0].revents();
            return Ok(ready + known);
        }
        _ => {}
    }
    // As many as a wait keeps on the stack are polled from it, more from
    // memory of their own (`a_few_on_stack`).
    let polled = sockets.iter().filter_map(|s| match s.socket.readiness() {
        Readiness::Poll(fd) => Some(PollFd::new(fd, s.events)),
        Readiness::Known { .. } => None,
    });
    let polled_sockets = polled.clone().count();
    let n = polled_sockets + fds.len();
    let mut few;
    let mut more = Vec::new();
    let all: &mut [PollFd<'_>] = match polled.clone().next().or(fds.first().copied()) {
        Some(any) if n <= ON_STACK => {
            few = [any; ON_STACK];
            for (slot, fd) in few.iter_mut().zip(polled.chain(fds.iter().copied())) {
                *slot = fd;
            }
            &mut few[..n]
        }
        _ => {
            more.try_reserve_exact(n)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            for fd in polled.chain(fds.iter().copied()) {
                more.try_push(fd).expect("reserved");
            }
            &mut more
        }
    };
    let ready = curl_os::poll::poll(all, timeout)?;
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
    /// It refuses once this much time has passed.
    RefusesAfter(Duration),
    /// It never answers.
    Silent,
    /// It hangs up once the socket is polled, the socket saying no error
    /// (`SO_ERROR` 0).
    HangsUp,
}

/// What a fake peer says once connected, as the test suite's server
/// does: it reads what it is sent, and once that holds a request's head,
/// up to its blank line, it replies, then closes if told to. The test
/// keeps a clone to read what the peer was sent.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Debug)]
pub struct Conversation(curl_alloc::TryArc<std::sync::Mutex<Wire>>);

/// A fake connection's two directions, shared by its socket, its network
/// and the test.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
struct Wire {
    received: Vec<u8>,
    /// One reply for each request, in turn.
    replies: Vec<Vec<u8>>,
    /// Replies read whole.
    answered: usize,
    /// How much of the next reply was read.
    read: usize,
    /// The peer closes once its last reply is read.
    then_close: bool,
    /// The options its socket was set to, in order.
    options: [Option<SocketOption>; 8],
    /// Its socket was made nonblocking, after that many options.
    nonblocking_after: Option<usize>,
    /// The peer closes on a request it has no reply for, as a server
    /// closing an idle connection just as it is reused.
    hang_up_unanswered: bool,
    /// The peer closed, whatever it was saying.
    hung_up: bool,
    /// The peer answers each send with its next reply, not each
    /// request's head: a handshake whose messages have no blank line.
    per_send: bool,
    /// The sends it was given.
    sends: usize,
    /// Sends still to be refused as would-block, though the socket polls
    /// writable: a full send buffer that drains by the next poll.
    stalls: usize,
    /// The sends taken before the stalls start.
    stalls_after: usize,
    /// The most a send takes; the rest is left to the sender.
    takes: Option<std::num::NonZeroUsize>,
    /// Each reply arrives a poll after its request: its first read
    /// would block.
    late: bool,
    /// The reply due was read for once already, and would block.
    waited: bool,
    /// Sends past this many fail, the peer gone though nothing says so
    /// to a poll yet: a reset that arrives as the request goes.
    breaks_after: Option<usize>,
    /// After its last reply the peer sends without end, each read of it
    /// moving the clock on by this much: a peer faster than its reader.
    endless: Option<Duration>,
    /// The reads of the endless part so far.
    endless_reads: usize,
    /// The reads so far, and how much room the last one had.
    reads: usize,
    last_read_room: usize,
    /// How many of its replies the peer may give so far, if it waits
    /// for the test to let them go.
    allowed: Option<usize>,
}

/// The most reads of an endless reply before the test fails: a transfer
/// that never stops reading would otherwise hang it.
#[cfg(any(test, feature = "test-util"))]
const ENDLESS_READS: usize = 20_000;

#[cfg(any(test, feature = "test-util"))]
impl Wire {
    /// The peer has a request's head to answer with its next reply.
    fn answering(&self) -> bool {
        let asked = if self.per_send {
            self.sends
        } else {
            self.heads()
        };
        self.answered < self.replies.len()
            && asked > self.answered
            && self.allowed.is_none_or(|n| self.answered < n)
    }

    /// The request heads the peer was sent.
    fn heads(&self) -> usize {
        self.received
            .windows(4)
            .filter(|w| w == b"\r\n\r\n")
            .count()
    }

    /// The socket has something to read: reply bytes, or the end.
    fn readable(&self) -> bool {
        self.hung_up
            || self.answering()
            || (self.answered == self.replies.len() && (self.then_close || self.endless.is_some()))
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Conversation {
    /// A peer that replies `reply` to a request's head, then closes if
    /// `then_close`.
    pub fn new(reply: &[u8], then_close: bool) -> Conversation {
        Conversation::replies(&[reply], then_close)
    }

    /// A peer that replies to each request's head with the next of
    /// `replies`, then closes after the last if `then_close`.
    pub fn replies(replies: &[&[u8]], then_close: bool) -> Conversation {
        let mut wire = Wire {
            then_close,
            ..Wire::default()
        };
        // Room for the requests a test sends, made now so that sending
        // them allocates nothing the library would be charged for.
        wire.received
            .try_reserve(REQUESTS_ROOM)
            .expect("a test's requests fit");
        for reply in replies {
            let mut copy = Vec::new();
            copy.try_extend_from_slice(reply)
                .expect("a test's reply fits");
            wire.replies.try_push(copy).expect("a test's replies fit");
        }
        Conversation(
            curl_alloc::TryArc::try_new(std::sync::Mutex::new(wire)).expect("a test's peer fits"),
        )
    }

    /// The same peer, answering each send with its next reply.
    pub fn per_send(self) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .per_send = true;
        self
    }

    /// The same peer, its first `n` sends refused as would-block.
    pub fn stalling_sends(self, n: usize) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .stalls = n;
        self
    }

    /// The same peer, the `n` sends after its first `taken` refused as
    /// would-block: a send buffer that fills mid-conversation.
    pub fn stalling_sends_after(self, taken: usize, n: usize) -> Conversation {
        {
            let mut wire = self.0.lock().expect("no test panics holding the wire");
            wire.stalls = n;
            wire.stalls_after = taken;
        }
        self
    }

    /// The same peer, each send taking at most `n` bytes: a send buffer
    /// with little room.
    pub fn taking(self, n: std::num::NonZeroUsize) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .takes = Some(n);
        self
    }

    /// The same peer, each reply arriving only after the read that
    /// first looks for it: a peer slower than the request's sender.
    pub fn late_replies(self) -> Conversation {
        self.0.lock().expect("no test panics holding the wire").late = true;
        self
    }

    /// The same peer, giving no reply until the test lets it with
    /// `allow`: a peer that takes as long to answer as the test says.
    pub fn held(self) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .allowed = Some(0);
        self
    }

    /// Let a `held` peer give its first `n` replies.
    pub fn allow(&self, n: usize) {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .allowed = Some(n);
    }

    /// The same peer, gone after its first `n` sends: those past them
    /// fail as on a connection reset, though the socket never polls
    /// readable for it.
    pub fn breaking_after(self, n: usize) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .breaks_after = Some(n);
        self
    }

    /// The same peer, sending without end after its last reply, each
    /// read of that taking `per_read` of the clock: a peer that sends
    /// faster than it is read. Reading on and on fails the test.
    pub fn endless(self, per_read: Duration) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .endless = Some(per_read);
        self
    }

    /// How many reads the connection had, and how much room the last
    /// one had.
    pub fn reads(&self) -> (usize, usize) {
        let wire = self.0.lock().expect("no test panics holding the wire");
        (wire.reads, wire.last_read_room)
    }

    /// How many reads the endless part of the reply has had.
    pub fn endless_reads(&self) -> usize {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .endless_reads
    }

    /// The same peer, closing the connection when a request comes that
    /// it has no reply left for.
    pub fn hanging_up_unanswered(self) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .hang_up_unanswered = true;
        self
    }

    /// After how many options its socket was made nonblocking, if it
    /// was: a socket the network opens is nonblocking from the start.
    pub fn made_nonblocking_after(&self) -> Option<usize> {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .nonblocking_after
    }

    /// The options its socket was set to, in order.
    pub fn options(&self) -> Vec<SocketOption> {
        let wire = self.0.lock().expect("no test panics holding the wire");
        let mut set = Vec::new();
        for &option in wire.options.iter().flatten() {
            set.try_push(option).expect("a test's options fit");
        }
        set
    }

    /// What the peer was sent so far.
    pub fn received(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.try_extend_from_slice(
            &self
                .0
                .lock()
                .expect("no test panics holding the wire")
                .received,
        )
        .expect("a test's request fits");
        out
    }
}

/// A network where waiting takes no time: a poll that finds nothing ready
/// moves the clock on by its timeout instead of sleeping. Real descriptors
/// given to it, a waker's or the application's, are still polled. Connects
/// reach fake peers, by address; one to an address with no peer is
/// refused at once. A peer says what its next conversation scripts, or
/// nothing.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct FakeNet {
    clock: crate::time::ManualClock,
    peers: Vec<(SocketAddr, Peer)>,
    /// The names it knows, with their addresses in the order answered.
    names: Vec<(Vec<u8>, Vec<IpAddr>)>,
    /// The conversations to come, each for the next connection to its
    /// address.
    conversations: Vec<(SocketAddr, Conversation)>,
    /// The scope of its interface with a link-local address, if it has one.
    link_local: Option<NonZeroU32>,
    /// Whether IPv6 works, as a multi's probe finds.
    ipv6: bool,
    /// The sockets open, by number from `FIRST_FAKE`, each with its
    /// conversation: a closed number is handed out again, lowest first, as
    /// the kernel does.
    open: Vec<Option<Conversation>>,
}

/// The first number a fake socket gets: past the descriptors a test
/// process has open, so that a fake one is never mistaken for them.
#[cfg(any(test, feature = "test-util"))]
const FIRST_FAKE: i32 = 1000;

/// The sockets, and the bytes of requests, a fake holds without growing.
#[cfg(any(test, feature = "test-util"))]
const SOCKETS_ROOM: usize = 16;
#[cfg(any(test, feature = "test-util"))]
const REQUESTS_ROOM: usize = 4096;

#[cfg(any(test, feature = "test-util"))]
impl FakeNet {
    /// A network whose waits move `clock`.
    pub fn new(clock: crate::time::ManualClock) -> FakeNet {
        // The socket numbers a test uses, made now so that opening a
        // socket allocates nothing the library would be charged for.
        let mut open = Vec::new();
        open.try_reserve(SOCKETS_ROOM)
            .expect("a test's sockets fit");
        FakeNet {
            clock,
            peers: Vec::new(),
            names: Vec::new(),
            conversations: Vec::new(),
            link_local: None,
            ipv6: true,
            open,
        }
    }

    /// A system where IPv6 does not work: a multi's probe finds none.
    pub fn without_ipv6(mut self) -> FakeNet {
        self.ipv6 = false;
        self
    }

    /// An interface with a link-local address, in `scope`.
    pub fn with_link_local_scope(mut self, scope: NonZeroU32) -> FakeNet {
        self.link_local = Some(scope);
        self
    }

    /// The next connection to `addr` has `conversation`.
    pub fn with_conversation(mut self, addr: SocketAddr, conversation: Conversation) -> FakeNet {
        self.conversations
            .try_push((addr, conversation))
            .expect("a test's conversations fit");
        self
    }

    /// A peer at `addr`.
    /// `name` resolves to `addrs`; any name not given is not found.
    pub fn with_name(mut self, name: &str, addrs: &[IpAddr]) -> FakeNet {
        let (mut n, mut a) = (Vec::new(), Vec::new());
        n.try_extend_from_slice(name.as_bytes())
            .expect("a test's names fit");
        a.try_extend_from_slice(addrs).expect("a test's names fit");
        self.names.try_push((n, a)).expect("a test's names fit");
        self
    }

    pub fn with_peer(mut self, addr: SocketAddr, peer: Peer) -> FakeNet {
        self.peers
            .try_push((addr, peer))
            .expect("a test's peers fit");
        self
    }

    fn open_number(&mut self, wire: Conversation) -> io::Result<SocketKey> {
        let row = match self.open.iter().position(Option::is_none) {
            Some(row) => row,
            None => {
                self.open
                    .try_push(None)
                    .map_err(|_| io::ErrorKind::OutOfMemory)?;
                self.open.len() - 1
            }
        };
        self.open[row] = Some(wire);
        let n = i32::try_from(row).expect("a test opens few sockets");
        Ok(SocketKey(FIRST_FAKE + n))
    }

    /// The peer of socket `key` closes its side: the socket reads as
    /// ready, with nothing but the end to read.
    pub fn hang_up(&self, key: SocketKey) {
        let row = usize::try_from(key.0 - FIRST_FAKE).expect("a fake socket's number");
        self.open[row]
            .as_ref()
            .expect("an open socket")
            .0
            .lock()
            .expect("no test panics holding the wire")
            .hung_up = true;
    }

    /// The options the open socket `key` was set to, in order.
    pub fn socket_options(&self, key: SocketKey) -> Vec<SocketOption> {
        let row = usize::try_from(key.0 - FIRST_FAKE).expect("a fake socket's number");
        self.open[row].as_ref().expect("an open socket").options()
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

    /// A socket to the peer at `addr`, if there is one, whose next
    /// conversation it has; to an address without one, its connect is
    /// refused at once.
    fn open(&mut self, addr: SocketAddr) -> io::Result<Box<dyn Socket>> {
        let peer = self.peers.iter().find(|(a, _)| *a == addr).map(|&(_, p)| p);
        let wire = match self.conversations.iter().position(|(a, _)| *a == addr) {
            Some(at) if peer.is_some() => self.conversations.remove(at).1,
            _ => Conversation(
                curl_alloc::TryArc::try_new(std::sync::Mutex::new(Wire::default()))
                    .map_err(|_| io::ErrorKind::OutOfMemory)?,
            ),
        };
        let key = self.open_number(wire.clone())?;
        // The port the kernel would have picked.
        let port = 40000 + u16::try_from(key.0 - FIRST_FAKE).expect("a test opens few sockets");
        let local = match addr {
            SocketAddr::V4(_) => SocketAddr::from(([127, 0, 0, 1], port)),
            SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
        };
        let now = crate::time::Clock::now(&self.clock);
        let ready_at = match peer {
            Some(Peer::AcceptsAfter(d) | Peer::RefusesAfter(d)) => Some(now.after(d)),
            _ => None,
        };
        let socket = FakeSocket {
            key,
            peer,
            local,
            connected: std::sync::atomic::AtomicBool::new(false),
            opened_for: addr,
            clock: self.clock.clone(),
            ready_at,
            wire,
        };
        Ok(try_box(socket).map_err(|_| io::ErrorKind::OutOfMemory)?)
    }

    fn close(&mut self, socket: Sock) {
        let row = usize::try_from(socket.key().0 - FIRST_FAKE).expect("a fake socket's number");
        assert!(
            self.open[row].take().is_some(),
            "{:?} closed twice",
            socket.key()
        );
        socket.close_with(drop);
    }

    fn resolve(&mut self, name: &[u8], family: Family) -> Result<Vec<IpAddr>, ResolveFailure> {
        let (_, addrs) = self
            .names
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .ok_or(ResolveFailure::NotFound)?;
        let wanted = |a: &&IpAddr| match family {
            Family::Any => true,
            Family::V4 => a.is_ipv4(),
            Family::V6 => a.is_ipv6(),
        };
        let mut found = Vec::new();
        for &a in addrs.iter().filter(wanted) {
            found.try_push(a).map_err(|_| ResolveFailure::OutOfMemory)?;
        }
        if found.is_empty() {
            return Err(ResolveFailure::NoData);
        }
        Ok(found)
    }

    fn link_local_scope(&mut self) -> Option<NonZeroU32> {
        self.link_local
    }

    fn probe_ipv6(&mut self) -> Result<bool, OutOfMemory> {
        Ok(self.ipv6)
    }
}

/// A socket to a fake peer, or to none.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
struct FakeSocket {
    key: SocketKey,
    /// None where nothing is at the address: the connect is refused at
    /// once.
    peer: Option<Peer>,
    /// The address the kernel would bind it to as it connects.
    local: SocketAddr,
    /// Whether its connect started: only then is it bound.
    connected: std::sync::atomic::AtomicBool,
    opened_for: SocketAddr,
    clock: crate::time::ManualClock,
    /// When a peer that answers late answers.
    ready_at: Option<Instant>,
    wire: Conversation,
}

#[cfg(any(test, feature = "test-util"))]
impl FakeSocket {
    /// Its peer; nothing is heard from an address without one.
    fn peer(&self) -> Peer {
        self.peer.unwrap_or(Peer::Silent)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Socket for FakeSocket {
    fn key(&self) -> SocketKey {
        self.key
    }

    fn readiness(&self) -> Readiness<'_> {
        let wire = self.wire.0.lock().expect("no test panics holding the wire");
        if wire.hung_up {
            return Readiness::Known {
                now: Events::IN | Events::OUT,
                later: None,
            };
        }
        let mut now = match (self.peer(), self.ready_at) {
            (Peer::HangsUp, _) => {
                return Readiness::Known {
                    now: Events::OUT | Events::HUP,
                    later: None,
                };
            }
            (Peer::Accepts | Peer::Refuses, _) => Events::OUT,
            (Peer::AcceptsAfter(_) | Peer::RefusesAfter(_), Some(at))
                if crate::time::Clock::now(&self.clock) >= at =>
            {
                Events::OUT
            }
            (Peer::AcceptsAfter(_) | Peer::RefusesAfter(_) | Peer::Silent, _) => Events::NONE,
        };
        let refuses = matches!(self.peer(), Peer::Refuses | Peer::RefusesAfter(_));
        if now == Events::OUT && !refuses && wire.readable() {
            now = now | Events::IN;
        }
        if now == Events::OUT && refuses {
            // A refused connect polls in error, and hung up.
            now = now | Events::ERR | Events::HUP;
        }
        let later = self.ready_at.filter(|_| now.is_empty());
        Readiness::Known { now, later }
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        Ok(match self.peer() {
            Peer::Refuses | Peer::RefusesAfter(_) => {
                Some(io::Error::from_raw_os_error(libc_errno::ECONNREFUSED))
            }
            Peer::Accepts | Peer::AcceptsAfter(_) | Peer::Silent | Peer::HangsUp => None,
        })
    }

    /// Bound as its connect starts: unbound before, and after one
    /// refused at once.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        if self.connected.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(self.local);
        }
        Ok(match self.local {
            SocketAddr::V4(_) => SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
        })
    }

    fn set(&self, option: SocketOption) -> io::Result<()> {
        let mut wire = self.wire.0.lock().expect("no test panics holding the wire");
        let free = wire.options.iter_mut().find(|o| o.is_none());
        *free.expect("a test sets few options") = Some(option);
        Ok(())
    }

    fn set_nonblocking(&self) -> io::Result<()> {
        let mut wire = self.wire.0.lock().expect("no test panics holding the wire");
        wire.nonblocking_after = Some(wire.options.iter().flatten().count());
        Ok(())
    }

    /// Its peer is the one at the address it was opened for, which it
    /// must connect to.
    fn connect(&self, addr: SocketAddr) -> io::Result<Connect> {
        assert_eq!(
            addr, self.opened_for,
            "a fake socket connects where it was opened for"
        );
        if self.peer.is_none() {
            return Err(io::Error::from_raw_os_error(libc_errno::ECONNREFUSED));
        }
        self.connected
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(Connect::InProgress)
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<Recv> {
        assert!(!buf.is_empty(), "a receive needs room");
        let mut wire = self.wire.0.lock().expect("no test panics holding the wire");
        wire.reads += 1;
        wire.last_read_room = buf.len();
        if wire.hung_up || self.peer() == Peer::HangsUp {
            return Ok(Recv::Eof);
        }
        while wire.answered < wire.replies.len() {
            if !wire.answering() {
                return Ok(Recv::WouldBlock);
            }
            if wire.late && !wire.waited {
                wire.waited = true;
                return Ok(Recv::WouldBlock);
            }
            let left = &wire.replies[wire.answered][wire.read..];
            let n = left.len().min(buf.len());
            buf[..n].copy_from_slice(&left[..n]);
            wire.read += n;
            if wire.read == wire.replies[wire.answered].len() {
                // Read whole: an idle connection has nothing waiting.
                wire.answered += 1;
                wire.read = 0;
                wire.waited = false;
            }
            if let Some(got) = std::num::NonZeroUsize::new(n) {
                return Ok(Recv::Data(got));
            }
        }
        if let Some(per_read) = wire.endless {
            wire.endless_reads += 1;
            assert!(
                wire.endless_reads <= ENDLESS_READS,
                "the transfer never stopped reading"
            );
            buf.fill(b'x');
            self.clock.advance(per_read);
            let n = std::num::NonZeroUsize::new(buf.len()).expect("checked above");
            return Ok(Recv::Data(n));
        }
        Ok(if wire.then_close {
            Recv::Eof
        } else {
            Recv::WouldBlock
        })
    }

    fn release(self: Box<Self>) -> SocketKey {
        self.key
    }

    fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        let mut wire = self.wire.0.lock().expect("no test panics holding the wire");
        let n = std::num::NonZeroUsize::new(buf.len()).expect("a send needs bytes");
        let n = wire.takes.map_or(n, |most| n.min(most));
        let buf = &buf[..n.get()];
        if wire.hung_up || wire.breaks_after.is_some_and(|n| wire.sends >= n) {
            return Err(io::Error::from_raw_os_error(libc_errno::EPIPE));
        }
        if wire.stalls > 0 && wire.sends >= wire.stalls_after {
            wire.stalls -= 1;
            return Ok(Sent::WouldBlock);
        }
        wire.received
            .try_extend_from_slice(buf)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        wire.sends += 1;
        if wire.hang_up_unanswered
            && wire.answered == wire.replies.len()
            && wire.heads() > wire.answered
        {
            wire.hung_up = true;
        }
        Ok(Sent::Bytes(n))
    }
}

/// The error numbers the fake gives, as Linux numbers them.
#[cfg(any(test, feature = "test-util"))]
mod libc_errno {
    pub(super) const ECONNREFUSED: i32 = 111;
    pub(super) const EPIPE: i32 = 32;
}

/// A fake network the test reaches while the multi holds it.
#[cfg(test)]
pub(crate) struct SharedNet(pub(crate) std::sync::Arc<std::sync::Mutex<FakeNet>>);

#[cfg(test)]
impl Net for SharedNet {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> io::Result<u32> {
        self.0.lock().unwrap().poll(sockets, fds, timeout)
    }

    fn open(&mut self, addr: SocketAddr) -> io::Result<Box<dyn Socket>> {
        self.0.lock().unwrap().open(addr)
    }

    fn close(&mut self, socket: Sock) {
        self.0.lock().unwrap().close(socket);
    }

    fn resolve(&mut self, name: &[u8], family: Family) -> Result<Vec<IpAddr>, ResolveFailure> {
        self.0.lock().unwrap().resolve(name, family)
    }

    fn link_local_scope(&mut self) -> Option<NonZeroU32> {
        self.0.lock().unwrap().link_local_scope()
    }

    fn probe_ipv6(&mut self) -> Result<bool, OutOfMemory> {
        self.0.lock().unwrap().probe_ipv6()
    }
}

/// A socket opened on `net` for `at`, its connect started, for tests that
/// need one connecting.
#[cfg(test)]
pub(crate) fn dial(net: &mut dyn Net, at: SocketAddr) -> Box<dyn Socket> {
    let socket = net.open(at).expect("a test's socket opens");
    socket.connect(at).expect("a test's connect starts");
    socket
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;

    use super::*;

    /// The system's network resolves names with the system's resolver.
    #[test]
    fn the_system_resolves_names() {
        let addrs = SystemNet.resolve(b"localhost", Family::V4).unwrap();
        assert!(addrs.contains(&IpAddr::from([127, 0, 0, 1])), "{addrs:?}");
        assert!(SystemNet.resolve(b"nonexist.invalid", Family::Any).is_err());
    }

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
        let socket = dial(&mut SystemNet, listener.local_addr().unwrap());
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
        SystemNet.close(Sock::new(socket, Closer::System));
    }

    /// More sockets and descriptors than fit on the stack are polled all
    /// the same, each getting its own events back.
    #[test]
    fn more_than_fit_on_the_stack_are_polled() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let one = dial(&mut SystemNet, listener.local_addr().unwrap());
        let two = dial(&mut SystemNet, listener.local_addr().unwrap());
        let pairs: Vec<_> = (0..9).map(|_| UnixStream::pair().unwrap()).collect();
        (&pairs[8].0).write_all(b"x").unwrap();
        let mut sockets = [
            SocketPoll::new(&*one, Events::IN),
            SocketPoll::new(&*two, Events::IN),
        ];
        let mut fds: Vec<PollFd<'_>> = pairs
            .iter()
            .map(|(_, b)| PollFd::new(b.as_fd(), Events::IN))
            .collect();
        let ready = SystemNet
            .poll(&mut sockets, &mut fds, Duration::from_secs(5))
            .unwrap();
        assert_eq!(ready, 1);
        assert!(fds[8].revents().contains(Events::IN));
        assert!(fds[..8].iter().all(|f| f.revents().is_empty()));
        SystemNet.close(Sock::new(one, Closer::System));
        SystemNet.close(Sock::new(two, Closer::System));
    }

    /// A socket goes only through its closer: one dropped unclosed is a
    /// bug, caught in debug builds.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "was dropped, not closed"]
    fn a_dropped_socket_is_caught() {
        let clock = crate::time::ManualClock::new().unwrap();
        let at = SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(clock).with_peer(at, Peer::Accepts);
        drop(Sock::new(dial(&mut net, at), Closer::System));
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
        let nobody = net.open(at(9)).unwrap();
        let err = nobody.connect(at(9)).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(111), "no peer: refused at once");
        let unbound = SocketAddr::from(([0, 0, 0, 0], 0));
        assert_eq!(nobody.local_addr().unwrap(), unbound, "never bound");
        net.close(Sock::new(nobody, Closer::System));
        let a = net.open(at(1)).unwrap();
        assert_eq!(a.local_addr().unwrap(), unbound, "bound as it connects");
        assert_eq!(a.connect(at(1)).unwrap(), Connect::InProgress);
        assert_eq!(a.local_addr().unwrap(), at(40000));
        let (b, c) = (dial(&mut net, at(2)), dial(&mut net, at(3)));
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
        let refused = Events::OUT | Events::ERR | Events::HUP;
        assert_eq!(
            sockets.each_ref().map(|s| s.revents()),
            [Events::OUT, refused, Events::NONE]
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
        net.close(Sock::new(b, Closer::System));
        let d = dial(&mut net, at(1));
        assert_eq!(d.key().get(), 1001, "the lowest free number again");
        for s in [a, c, d] {
            net.close(Sock::new(s, Closer::System));
        }
    }

    /// A conversation waits for a connection to a peer: a socket to its
    /// address refused for want of one leaves it to the next.
    #[test]
    fn a_refused_socket_leaves_the_conversation() {
        let clock = crate::time::ManualClock::new().unwrap();
        let at = SocketAddr::from(([127, 0, 0, 1], 1));
        let talk = Conversation::new(b"", false);
        let mut net = FakeNet::new(clock).with_conversation(at, talk.clone());
        let refused = net.open(at).unwrap();
        assert!(refused.connect(at).is_err(), "no peer yet");
        net.close(Sock::new(refused, Closer::System));
        let mut net = net.with_peer(at, Peer::Accepts);
        let s = dial(&mut net, at);
        s.send(b"hi").unwrap();
        assert_eq!(talk.received(), b"hi");
        net.close(Sock::new(s, Closer::System));
    }

    /// The system's socket is set, and made nonblocking, through the
    /// library's view of it.
    #[test]
    fn a_system_socket_is_set_through_the_trait() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Blocking, as an application's opener may give it.
        let s: Box<dyn Socket> = Box::new(open(addr, Protocol::Tcp, false).unwrap());
        let Readiness::Poll(fd) = s.readiness() else {
            panic!("a system socket is polled");
        };
        let flags = || {
            let info =
                std::fs::read_to_string(format!("/proc/self/fdinfo/{}", s.key().get())).unwrap();
            let line = info.lines().find(|l| l.starts_with("flags:")).unwrap();
            u32::from_str_radix(line["flags:".len()..].trim(), 8).unwrap()
        };
        const O_NONBLOCK: u32 = 0o4000;
        assert_eq!(flags() & O_NONBLOCK, 0);
        s.set_nonblocking().unwrap();
        assert_ne!(flags() & O_NONBLOCK, 0);
        let view = std::net::TcpStream::from(fd.try_clone_to_owned().unwrap());
        assert!(!view.nodelay().unwrap());
        s.set(SocketOption::NoDelay).unwrap();
        assert!(view.nodelay().unwrap());
        // An idle time the kernel refuses is an error.
        assert!(s.set(SocketOption::KeepIdle(0)).is_err());
    }

    /// A fake socket keeps the options it was set to, in order.
    #[test]
    fn a_fake_socket_keeps_its_options() {
        let clock = crate::time::ManualClock::new().unwrap();
        let at = SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(clock).with_peer(at, Peer::Accepts);
        let s = net.open(at).unwrap();
        s.set(SocketOption::NoDelay).unwrap();
        s.set(SocketOption::KeepIdle(5)).unwrap();
        assert_eq!(
            net.socket_options(s.key()),
            [SocketOption::NoDelay, SocketOption::KeepIdle(5)]
        );
        net.close(Sock::new(s, Closer::System));
    }
}
