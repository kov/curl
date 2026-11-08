//! The engine's way to the network, and the fake that stands in for it in
//! tests. Only `conn` and `Multi::wait` call it.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryArc, TryVec, try_box};

use crate::handler::{Handler, SocketCloser};
use crate::time::Instant;

#[cfg(unix)]
pub use curl_os::net::IO_FAILED;
pub use curl_os::net::{
    AF_INET, AF_INET6, BATCH, Connect, Datagram, InterfaceAddress, Ipv6Scope, Protocol, Recv, SLOT,
    Sent, SocketOption, TOO_LARGE, TcpSocket, UdpSocket, Winsock, adopt, adopt_udp, ipv6_scope,
    open, open_udp,
};
pub use curl_os::poll::{Events, PollFd};
pub use curl_os::resolve::{Failure as ResolveFailure, Family};
pub use curl_os::socket::{BorrowedSocket, RawSocket};
pub use curl_os::wake::Waker;

/// What a socket carries: a stream (TCP's, or a Unix socket's), or
/// datagrams (UDP's, for QUIC), as C opens them `SOCK_STREAM` or
/// `SOCK_DGRAM` by the connection's transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SocketKind {
    #[default]
    Stream,
    Datagram,
}

/// A socket's number, as C hands it to the application (`curl_socket_t`):
/// a descriptor on Unix, a `SOCKET` on Windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketKey(RawSocket);

impl SocketKey {
    /// No socket (`CURL_SOCKET_BAD`: -1 on Unix, `INVALID_SOCKET` on
    /// Windows).
    #[cfg(unix)]
    pub(crate) const BAD: SocketKey = SocketKey(-1);
    #[cfg(windows)]
    pub(crate) const BAD: SocketKey = SocketKey(RawSocket::MAX);

    /// The socket C calls `n`, as the application names it back.
    pub fn new(n: RawSocket) -> SocketKey {
        SocketKey(n)
    }

    /// The number of `socket`, open.
    pub fn of(socket: BorrowedSocket<'_>) -> SocketKey {
        SocketKey(curl_os::socket::raw(socket))
    }

    pub fn get(self) -> RawSocket {
        self.0
    }
}

/// Where a socket connects: an address on the network, or a Unix socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Remote {
    Inet(SocketAddr),
    Unix(UnixPeer),
}

impl Remote {
    /// The address, for one on the network.
    pub fn inet(&self) -> Option<SocketAddr> {
        match self {
            Remote::Inet(a) => Some(*a),
            Remote::Unix(_) => None,
        }
    }

    /// The address as C's traces and infos show it (`ip_quadruple`'s
    /// `remote_ip`): an IP address, or a Unix socket's path as
    /// `unix_path` shows it.
    pub(crate) fn shown_ip(&self) -> crate::text::Text<SHOWN_IP_MAX> {
        let mut shown = crate::text::Text::new();
        match self {
            Remote::Inet(a) => {
                shown.push_fmt(format_args!("{}", a.ip()));
            }
            Remote::Unix(_) => shown.push_clipped(self.unix_path().unwrap_or_default()),
        }
        shown
    }

    /// The path a Unix socket's address shows, as C's traces and infos
    /// show it: at most the first `SHOWN_IP_MAX` bytes, as C prints it
    /// into a buffer the size of the longest IP address's text
    /// (`sockaddr2string` into `MAX_IPADR_LEN`); an abstract name's is
    /// empty, as its text starts with a zero byte.
    pub fn unix_path(&self) -> Option<&[u8]> {
        match self {
            Remote::Inet(_) => None,
            Remote::Unix(u) if u.is_abstract() => Some(b""),
            Remote::Unix(u) => Some(&u.path()[..u.path().len().min(SHOWN_IP_MAX)]),
        }
    }

    /// The port as C's traces show it: a Unix socket's is 0, and its
    /// infos say it has none (`CUR_IP_QUAD_HAS_PORTS`).
    pub fn port(&self) -> u16 {
        match self {
            Remote::Inet(a) => a.port(),
            Remote::Unix(_) => 0,
        }
    }
}

/// The longest address `Remote::shown_ip` shows: C's buffer for an
/// address's text less its terminating zero (`MAX_IPADR_LEN`, the size of
/// `"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"`), which holds any IP
/// address and cuts a Unix socket's path.
const SHOWN_IP_MAX: usize = 45;

/// A Unix socket connected to: the peer that names it, shared.
#[derive(Clone, Debug)]
pub struct UnixPeer(TryArc<super::Peer>);

impl UnixPeer {
    /// The Unix socket `peer` names, which must be one.
    pub(crate) fn of(peer: TryArc<super::Peer>) -> UnixPeer {
        assert!(peer.is_unix(), "a peer at a Unix socket");
        UnixPeer(peer)
    }

    /// The path, or the abstract name.
    pub fn path(&self) -> &[u8] {
        self.0.name()
    }

    /// Whether the name is in the abstract namespace.
    pub fn is_abstract(&self) -> bool {
        self.0.at() == super::PeerAt::AbstractUnix
    }
}

impl PartialEq for UnixPeer {
    fn eq(&self, other: &UnixPeer) -> bool {
        self.path() == other.path() && self.is_abstract() == other.is_abstract()
    }
}

impl Eq for UnixPeer {}

/// A socket the network opened.
pub trait Socket: fmt::Debug + Send {
    fn key(&self) -> SocketKey;

    /// How to learn whether it is ready: a descriptor to poll, or, for a
    /// socket that has none, what it is ready for now.
    fn readiness(&self) -> Readiness<'_>;

    /// Its descriptor, for a library that works on the socket itself; none
    /// for a socket that has none.
    fn descriptor(&self) -> Option<BorrowedSocket<'_>> {
        match self.readiness() {
            Readiness::Poll(fd) => Some(fd),
            Readiness::Known { .. } => None,
        }
    }

    /// The error that ended a connect in progress, once the socket is
    /// writable; `None` if it connected (`SO_ERROR`).
    fn take_error(&self) -> io::Result<Option<io::Error>>;

    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// The address of its peer, for one accepted, as the trace names it
    /// (`getpeername`); a socket of another kind has none to say.
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Set `option` on it.
    fn set(&self, option: SocketOption) -> io::Result<()>;

    /// Make it nonblocking, as a socket the application opened may not be.
    fn set_nonblocking(&self) -> io::Result<()>;

    /// Bind its local end to `addr`, before it connects.
    fn bind(&self, addr: SocketAddr) -> io::Result<()>;

    /// Bind it to the network interface named `name` (`SO_BINDTODEVICE`),
    /// which Linux alone has.
    #[cfg(target_os = "linux")]
    fn bind_to_device(&self, name: &[u8]) -> io::Result<()>;

    /// Start connecting it to `addr`.
    fn connect(&self, addr: &Remote) -> io::Result<Connect>;

    /// Receive into `buf`, which is not empty.
    fn recv(&self, buf: &mut [u8]) -> io::Result<Recv>;

    /// Send from `buf`, which is not empty.
    fn send(&self, buf: &[u8]) -> io::Result<Sent>;

    /// Send `buf`, which is not empty, as datagrams of `segment` bytes in
    /// one call, as a UDP socket does (`UdpSocket::send_segments`); a
    /// socket of another kind cannot.
    #[cfg(unix)]
    fn send_segments(&self, buf: &[u8], segment: usize) -> io::Result<usize> {
        let _ = (buf, segment);
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Receive datagrams into slots of `buf`, as a UDP socket does
    /// (`UdpSocket::recv_batch`); a socket of another kind cannot.
    #[cfg(unix)]
    fn recv_batch(&self, buf: &mut [u8], slot: usize, out: &mut [Datagram]) -> io::Result<usize> {
        let _ = (buf, slot, out);
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Send `buf` as one datagram to `to`, as an unconnected UDP socket
    /// does (`sendto`): how many bytes went. A socket of another kind
    /// cannot.
    fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        let _ = (buf, to);
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Receive one datagram into `buf`, which is not empty, and whom it
    /// came from, as an unconnected UDP socket does (`recvfrom`); none if
    /// none waits. A socket of another kind cannot.
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        let _ = buf;
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Listen on it, bound, for one connection to wait at most, as FTP's
    /// active data connection does (`listen`); a socket of another kind
    /// cannot.
    fn listen(&self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// The connection waiting on it, listening, accepted as a nonblocking
    /// socket; none if none waits (`accept4`).
    fn accept(&self) -> io::Result<Option<Box<dyn Socket>>> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Size its send buffer to what the system finds ideal now, if that
    /// is not `current`, the size set last: the size set, or `None` if
    /// none was (`win_update_sndbuf_size`). Only a TCP socket can.
    #[cfg(windows)]
    fn fit_send_buffer(&self, current: u32) -> Option<u32> {
        let _unused = current;
        None
    }

    /// Let go of the descriptor without closing it, for the application's
    /// closer to close: its number.
    fn release(self: Box<Self>) -> SocketKey;
}

/// A socket open, and how it is to be closed: the closer the connection
/// it belongs to was made with. Only `Net::close` takes one; one dropped
/// unclosed is a bug, and aborts.
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
        assert!(
            self.socket.is_none() || std::thread::panicking(),
            "{:?} was dropped, not closed",
            self.socket.as_ref().map(|s| s.key())
        );
    }
}

/// How a socket's readiness is learned.
#[derive(Clone, Copy, Debug)]
pub enum Readiness<'a> {
    Poll(BorrowedSocket<'a>),
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

    /// Add `events` to the entry of `polls` for `socket`, the newest
    /// first, if there is one (`cpfds_add_sock`'s folding): whether there
    /// was.
    pub fn fold(polls: &mut [SocketPoll<'_>], socket: &dyn Socket, events: Events) -> bool {
        let key = socket.key();
        match polls.iter_mut().rev().find(|p| p.socket.key() == key) {
            Some(p) => {
                p.events = p.events | events;
                true
            }
            None => false,
        }
    }
}

/// The transfer a resolve is for, which the multi runs again once its
/// answer comes (C's `mid` in each queued item); none for a setup that
/// no transfer drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Waiter(pub(crate) Option<crate::multi::TransferId>);

impl Waiter {
    /// No transfer.
    pub const NONE: Waiter = Waiter(None);
}

/// A resolve's start: the answer, where it is known at once, or the
/// resolve to wait for, and which families it queued as a query of their
/// own, IPv6's first, for a resolver that asks each family apart
/// (`async_thrdd_query`); neither for one that asks once for what the
/// resolve wants.
#[derive(Debug)]
pub enum Resolve {
    Answer(Vec<IpAddr>),
    Pending {
        resolve: Box<dyn Resolving>,
        v6: bool,
        v4: bool,
    },
}

/// One resolve a [`Resolver`] answers later, owned by what waits for it:
/// dropped, before or after its answer is taken, it ends, and its
/// resolver keeps nothing of it, its queries not yet asked taken back
/// and an answer that comes after dropped (`Curl_resolv_destroy`).
pub trait Resolving: Send + fmt::Debug {
    /// Its answer, once it has come, taken; none while it has not. Taken
    /// once: asked again, it is a bug.
    fn answer(&mut self) -> Option<Result<Vec<IpAddr>, ResolveFailure>>;

    /// What has come while it goes on (`Curl_resolv_get_ai`), for a
    /// resolver that answers each query as it can.
    fn partial(&mut self) -> Result<Option<Partial>, OutOfMemory> {
        Ok(None)
    }

    /// Its answer, waited for (C's `Curl_async_await`).
    fn wait(&mut self) -> Result<Vec<IpAddr>, ResolveFailure>;
}

/// What a resolve has found so far: every address of the queries that
/// answered, and whether AAAA's and A's are among them, though with no
/// address, or were never asked.
#[derive(Debug)]
pub struct Partial {
    pub addrs: Vec<IpAddr>,
    pub v6_answered: bool,
    pub v4_answered: bool,
}

/// A library that resolves names with a resolve of its own for each ask, the
/// transfer driving it as it drives its sockets (c-ares).
pub trait DnsLibrary: Send + Sync + fmt::Debug {
    /// Start a resolve, saying what C traces as it does.
    fn resolve(
        &self,
        ask: DnsAsk<'_>,
        say: &mut DnsSay<'_>,
    ) -> Result<Box<dyn DnsResolve>, DnsRefused>;
}

/// What is said of a resolve as it starts, in parts of a line.
pub type DnsSay<'a> = dyn FnMut(&[&[u8]]) + 'a;

/// What a transfer asks of a [`DnsLibrary`].
#[derive(Debug)]
pub struct DnsAsk<'a> {
    pub name: &'a [u8],
    pub port: u16,
    /// The addresses wanted; none for the name's HTTPS record.
    pub family: Option<Family>,
    /// For a connection over a stream, which the answer's hints say.
    pub stream: bool,
    pub options: &'a crate::options::DnsOptions,
    /// Where the sockets the resolve closes are told, for as long as it
    /// lives and as it goes.
    pub closed: &'a SocketsClosed,
}

/// The sockets a library closed, which a transfer may have been waiting
/// on, until the multi forgets them (`sock_state_cb`'s
/// `Curl_multi_will_close`). Shared by the transfer and its library's
/// resolves, so that one closing as it is dropped, wherever that is, is
/// told all the same.
#[derive(Clone, Debug)]
pub struct SocketsClosed(TryArc<std::sync::Mutex<Vec<SocketKey>>>);

impl SocketsClosed {
    pub fn new() -> Result<SocketsClosed, OutOfMemory> {
        Ok(SocketsClosed(TryArc::try_new(std::sync::Mutex::new(
            Vec::new(),
        ))?))
    }

    /// `key` closes, or has just closed.
    pub fn said(&self, key: SocketKey) -> Result<(), OutOfMemory> {
        self.0.lock().expect("no push panics").try_push(key)
    }

    /// Those closed since last taken, in their order.
    pub fn take(&self) -> Vec<SocketKey> {
        std::mem::take(&mut *self.0.lock().expect("no push panics"))
    }
}

/// Why a resolve did not start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsRefused {
    OutOfMemory,
    /// The library could not be set up (`CURLE_FAILED_INIT`).
    Init,
    /// A setting it takes is not one (`CURLE_BAD_FUNCTION_ARGUMENT`).
    BadOption(&'static str),
    /// An answer's record could not be read.
    BadRecord,
}

/// One resolve under way in a [`DnsLibrary`].
pub trait DnsResolve: Send + fmt::Debug {
    /// Process what is ready and what has timed out.
    fn perform(&mut self) -> Result<(), OutOfMemory>;
    /// The sockets it waits on, and for what.
    fn wants(&self) -> &[(Box<dyn Socket>, Events)];
    /// How soon `perform` is due at the latest, `within` at most.
    fn due(&self, within: Duration) -> Duration;
    /// What has come so far of a resolve of addresses.
    fn partial(&self) -> Result<Partial, OutOfMemory>;
    /// The queries still unanswered, and which have answered as C names them.
    fn ongoing(&self) -> (u32, &'static str);
    /// The answer of a resolve of addresses, once every query has one. A
    /// failure other than for memory is given again if asked again.
    fn answer(&mut self) -> Option<Result<Vec<IpAddr>, ResolveFailure>>;
    /// The answer of a resolve of an HTTPS record.
    fn record(&mut self) -> Option<crate::doh::RecordAnswer>;
    /// What it says of its failure beside the name, if anything.
    fn explain(&self) -> Option<&'static str>;
    /// Its status, as its trace numbers it.
    fn status(&self) -> i32;
}

/// What finds the addresses names stand for (C's resolver backends):
/// the system's, at once, or one that answers later, handing each such
/// resolve to what waits for it and telling the multi which transfers to
/// run again.
pub trait Resolver {
    /// Start finding the addresses of `family` that `name` stands for,
    /// for `waiter`.
    fn start(
        &mut self,
        name: &[u8],
        family: Family,
        waiter: Waiter,
    ) -> Result<Resolve, ResolveFailure>;

    /// The waiter of each resolve whose answer has come since last asked,
    /// told once (`Curl_async_thrdd_multi_process`). Told under the
    /// resolver's lock, if it has one: `each` drops no resolve.
    fn answered(&mut self, each: &mut dyn FnMut(Waiter));

    /// What an answer coming wakes, which the multi polls, for a resolver
    /// that answers later from elsewhere (C's `wakeup_internal`).
    fn waker(&self) -> Option<TryArc<Waker>>;

    /// What it says of `why` beside the name it could not resolve, if
    /// anything.
    fn explain(&self, why: ResolveFailure) -> Option<&'static str>;

    /// The settings of the threads it answers from, for a resolver that
    /// answers from a pool of them.
    fn pool(&self) -> Option<super::threaded::ResolverThreads> {
        None
    }

    /// How soon to ask again for answers whose queries wait for a thread
    /// that could not be started (`Curl_async_pollset`'s 100 ms), if any
    /// do.
    fn retry(&self) -> Option<Duration> {
        None
    }

    /// Whether a name's HTTPS record is asked of it, which it never
    /// answers, as C's threaded resolver is asked and resolves only
    /// addresses (`Curl_async_getaddrinfo`); not, for one that is never
    /// asked, as C's synchronous resolver is not.
    fn asked_for_records(&self) -> bool {
        false
    }
}

/// The system's resolver as C's synchronous one: `getaddrinfo`, its
/// answer waited for as it starts.
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn start(&mut self, name: &[u8], family: Family, _: Waiter) -> Result<Resolve, ResolveFailure> {
        curl_os::resolve::lookup(name, family).map(Resolve::Answer)
    }

    fn answered(&mut self, _: &mut dyn FnMut(Waiter)) {}

    fn waker(&self) -> Option<TryArc<Waker>> {
        None
    }

    fn explain(&self, why: ResolveFailure) -> Option<&'static str> {
        c_ares_explains(why)
    }
}

/// What the reference build's resolver, c-ares, says of a failure
/// (`ares_strerror`), which the resolvers that stand in for it say.
pub fn c_ares_explains(why: ResolveFailure) -> Option<&'static str> {
    match why {
        ResolveFailure::NotFound => Some("Domain name not found"),
        ResolveFailure::NoData => Some("DNS server returned answer with no data"),
        _ => None,
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

    /// Open a nonblocking socket of `kind` for `addr`'s family: a stream,
    /// TCP or Unix, or a UDP socket for datagrams; not connected yet.
    fn open(&mut self, addr: &Remote, kind: SocketKind) -> io::Result<Box<dyn Socket>>;

    /// Close a socket the network opened, through its closer.
    fn close(&mut self, socket: Sock);

    /// `f` given the network's resolver.
    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn Resolver));

    /// The scope of the first local interface that is up, is not
    /// loopback and has a link-local IPv6 address, if any.
    fn link_local_scope(&mut self) -> Option<NonZeroU32>;

    /// The address the interface named `name` has of the family IPv6 if
    /// `v6`, else IPv4; an IPv6 one only in `remote_scope`, and with the
    /// scope id `scope_id` unless that is 0 (`Curl_if2ip`).
    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: Ipv6Scope,
        scope_id: u32,
    ) -> InterfaceAddress;

    /// Whether IPv6 works here, as a multi asks once as it is made
    /// (`Curl_probeipv6`): an error only if memory ran out. A network of
    /// the tests' has it unless it says otherwise.
    fn probe_ipv6(&mut self) -> Result<bool, OutOfMemory> {
        Ok(true)
    }
}

impl Socket for curl_os::net::TcpSocket {
    fn key(&self) -> SocketKey {
        SocketKey::of(self.fd())
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

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        curl_os::net::TcpSocket::peer_addr(self)
    }

    fn set(&self, option: SocketOption) -> io::Result<()> {
        curl_os::net::TcpSocket::set(self, option)
    }

    fn set_nonblocking(&self) -> io::Result<()> {
        curl_os::net::TcpSocket::set_nonblocking(self)
    }

    fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        curl_os::net::TcpSocket::bind(self, addr)
    }

    #[cfg(target_os = "linux")]
    fn bind_to_device(&self, name: &[u8]) -> io::Result<()> {
        curl_os::net::TcpSocket::bind_to_device(self, name)
    }

    fn connect(&self, addr: &Remote) -> io::Result<Connect> {
        match addr {
            Remote::Inet(a) => curl_os::net::TcpSocket::connect(self, *a),
            Remote::Unix(u) => self.connect_unix(u.path(), u.is_abstract()),
        }
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<Recv> {
        curl_os::net::TcpSocket::recv(self, buf)
    }

    fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        curl_os::net::TcpSocket::send(self, buf)
    }

    fn listen(&self) -> io::Result<()> {
        curl_os::net::TcpSocket::listen(self, 1)
    }

    fn accept(&self) -> io::Result<Option<Box<dyn Socket>>> {
        let oom = |_| io::Error::from(io::ErrorKind::OutOfMemory);
        match curl_os::net::TcpSocket::accept(self)? {
            Some(s) => Ok(Some(try_box(s).map_err(oom)? as Box<dyn Socket>)),
            None => Ok(None),
        }
    }

    #[cfg(windows)]
    fn fit_send_buffer(&self, current: u32) -> Option<u32> {
        curl_os::net::TcpSocket::fit_send_buffer(self, current)
    }

    fn release(self: Box<Self>) -> SocketKey {
        SocketKey(self.into_raw())
    }
}

impl Socket for curl_os::net::UdpSocket {
    fn key(&self) -> SocketKey {
        SocketKey::of(self.fd())
    }

    fn readiness(&self) -> Readiness<'_> {
        Readiness::Poll(self.fd())
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        curl_os::net::UdpSocket::take_error(self)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        curl_os::net::UdpSocket::local_addr(self)
    }

    fn set(&self, option: SocketOption) -> io::Result<()> {
        curl_os::net::UdpSocket::set(self, option)
    }

    fn set_nonblocking(&self) -> io::Result<()> {
        curl_os::net::UdpSocket::set_nonblocking(self)
    }

    fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        curl_os::net::UdpSocket::bind(self, addr)
    }

    #[cfg(target_os = "linux")]
    fn bind_to_device(&self, name: &[u8]) -> io::Result<()> {
        curl_os::net::UdpSocket::bind_to_device(self, name)
    }

    /// A Unix socket carries no datagrams of QUIC's: no route asks.
    fn connect(&self, addr: &Remote) -> io::Result<Connect> {
        match addr {
            Remote::Inet(a) => curl_os::net::UdpSocket::connect(self, *a),
            Remote::Unix(_) => Err(io::Error::from(io::ErrorKind::InvalidInput)),
        }
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<Recv> {
        curl_os::net::UdpSocket::recv(self, buf)
    }

    fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        curl_os::net::UdpSocket::send(self, buf)
    }

    #[cfg(unix)]
    fn send_segments(&self, buf: &[u8], segment: usize) -> io::Result<usize> {
        curl_os::net::UdpSocket::send_segments(self, buf, segment)
    }

    #[cfg(unix)]
    fn recv_batch(&self, buf: &mut [u8], slot: usize, out: &mut [Datagram]) -> io::Result<usize> {
        curl_os::net::UdpSocket::recv_batch(self, buf, slot, out)
    }

    fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        curl_os::net::UdpSocket::send_to(self, buf, to)
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        curl_os::net::UdpSocket::recv_from(self, buf)
    }

    fn release(self: Box<Self>) -> SocketKey {
        SocketKey(self.into_raw())
    }
}

/// A close-on-exec socket of `kind` for `addr`, nonblocking if
/// `nonblocking`, as the system opens one when the application has no
/// opener: a stream speaking TCP, or a UDP socket for datagrams. A Unix
/// socket is a stream.
pub fn open_kind(
    addr: &Remote,
    kind: SocketKind,
    nonblocking: bool,
) -> io::Result<Box<dyn Socket>> {
    let oom = |_| io::Error::from(io::ErrorKind::OutOfMemory);
    match (addr, kind) {
        (Remote::Inet(a), SocketKind::Datagram) => {
            try_box(curl_os::net::open_udp(*a, nonblocking)?)
                .map_err(oom)
                .map(|s| s as Box<dyn Socket>)
        }
        _ => try_box(open_remote(addr, Protocol::Tcp, nonblocking)?)
            .map_err(oom)
            .map(|s| s as Box<dyn Socket>),
    }
}

/// A close-on-exec stream socket for `addr`'s family, speaking `protocol`
/// over TCP's, nonblocking if `nonblocking`: not connected yet. A Unix
/// socket speaks no protocol of TCP's (`CURL_SOCKET`'s, protocol 0).
pub fn open_remote(addr: &Remote, protocol: Protocol, nonblocking: bool) -> io::Result<TcpSocket> {
    match addr {
        Remote::Inet(a) => curl_os::net::open(*a, protocol, nonblocking),
        Remote::Unix(_) => curl_os::net::open_unix(nonblocking),
    }
}

/// The operating system's network, and its resolver: the system's,
/// answering as a resolve starts, or, in a build with the threaded
/// resolver, a pool of threads of the multi's own. It holds a Winsock
/// start for as long as it lives, last so that it ends after the
/// resolver; one the system refused is none, and each socket then fails
/// to open, saying so.
#[derive(Debug)]
pub struct SystemNet {
    threaded: Option<super::threaded::ThreadedResolver>,
    _winsock: Option<curl_os::net::Winsock>,
}

impl Default for SystemNet {
    fn default() -> SystemNet {
        SystemNet {
            threaded: None,
            _winsock: curl_os::net::Winsock::start().ok(),
        }
    }
}

impl SystemNet {
    /// The network a multi uses: in a build with the threaded resolver,
    /// with a pool of `threads`.
    pub fn for_multi(threads: super::threaded::Threads) -> io::Result<SystemNet> {
        let winsock = curl_os::net::Winsock::start().ok();
        #[cfg(feature = "threaded-resolver")]
        let threaded = {
            let debug = super::threaded::DebugVars::from_env();
            Some(super::threaded::ThreadedResolver::with_debug(
                threads, debug,
            )?)
        };
        #[cfg(not(feature = "threaded-resolver"))]
        let threaded = {
            let _unused = threads;
            None
        };
        Ok(SystemNet {
            threaded,
            _winsock: winsock,
        })
    }
}

impl Net for SystemNet {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> io::Result<u32> {
        poll_together(sockets, fds, timeout)
    }

    fn open(&mut self, addr: &Remote, kind: SocketKind) -> io::Result<Box<dyn Socket>> {
        open_kind(addr, kind, true)
    }

    fn close(&mut self, socket: Sock) {
        socket.close_with(drop);
    }

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn Resolver)) {
        match &mut self.threaded {
            Some(threaded) => f(threaded),
            None => f(&mut SystemResolver),
        }
    }

    fn link_local_scope(&mut self) -> Option<NonZeroU32> {
        curl_os::net::link_local_scope()
    }

    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: Ipv6Scope,
        scope_id: u32,
    ) -> InterfaceAddress {
        curl_os::net::interface_address(name, v6, remote_scope, scope_id)
    }

    fn probe_ipv6(&mut self) -> Result<bool, OutOfMemory> {
        curl_os::net::probe_ipv6().map_err(|_| OutOfMemory)
    }
}

/// The entries a wait keeps on the stack (`NUM_POLLS_ON_STACK`).
pub(crate) const ON_STACK: usize = 10;

/// What the system is asked of a socket wanted for `events`. On Windows
/// a socket wanted writable is asked for priority data too: a connect
/// refused there shows only as an exception, which C's
/// `SOCKET_WRITABLE` asks for (`POLLPRI`) and its multi's wait watches
/// (`FD_CONNECT`).
pub(crate) fn as_asked(events: Events) -> Events {
    #[cfg(windows)]
    if events.contains(Events::OUT) {
        return events | Events::PRI;
    }
    events
}

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
            let mut one = [PollFd::new(fd, as_asked(s.events))];
            let ready = curl_os::poll::poll(&mut one, timeout)?;
            s.revents = one[0].revents();
            return Ok(ready + known);
        }
        _ => {}
    }
    // As many as a wait keeps on the stack are polled from it, more from
    // memory of their own (`a_few_on_stack`).
    let polled = sockets.iter().filter_map(|s| match s.socket.readiness() {
        Readiness::Poll(fd) => Some(PollFd::new(fd, as_asked(s.events))),
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

/// What a scripted send does ([`Conversation::scripted_sends`]).
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptedSend {
    /// It takes at most this many bytes; none is a send that would block.
    Takes(usize),
    /// It fails, as on a connection the peer closed.
    Fails,
}

/// A fake connection's two directions, shared by its socket, its network
/// and the test.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
struct Wire {
    received: Vec<u8>,
    /// The ECN mark each datagram of its replies arrives with.
    ecn: u8,
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
    /// A hang-up is a reset: its reads fail (`ECONNRESET`).
    hang_up_resets: bool,
    /// The peer closed, whatever it was saying.
    hung_up: bool,
    /// Once its last reply is read, a read fails as on a connection the
    /// peer reset.
    resets: bool,
    /// The reset polls in error and hung up, as Linux polls it.
    reset_polls: bool,
    /// The reset is read once, as Linux reports it: after it the
    /// connection reads its end and sends fail (`EPIPE`).
    reset_once: bool,
    /// The peer answers each send with its next reply, not each
    /// request's head: a handshake whose messages have no blank line.
    per_send: bool,
    /// Its datagrams from the reply numbered first on come from this
    /// address, not the peer's.
    datagrams_from: Option<(usize, SocketAddr)>,
    /// The peer speaks first: its first reply is there before anything
    /// is sent, a line protocol's greeting, and each send after that ends
    /// a line with CRLF is answered with the next (a fake TLS handshake's
    /// last flight ends with a bare LF, and has no answer).
    greets: bool,
    /// The sends that ended with CRLF.
    lines: usize,
    /// The sends it was given.
    sends: usize,
    /// Sends still to be refused as would-block, though the socket polls
    /// writable: a full send buffer that drains by the next poll.
    stalls: usize,
    /// The sends taken before the stalls start.
    stalls_after: usize,
    /// The most a send takes; the rest is left to the sender.
    takes: Option<std::num::NonZeroUsize>,
    /// What each send in turn does, as the test scripts it; past the
    /// script, sends go as the rest of the peer says.
    script: Vec<ScriptedSend>,
    /// The bytes each scripted send was offered, one for each made: the
    /// next is the script's step after them.
    offered: Vec<usize>,
    /// The most a read gives; the rest waits for the next.
    gives: Option<std::num::NonZeroUsize>,
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
    /// What the endless part repeats, and how far into it the next read
    /// starts; `x` with no line end if nothing is given.
    endless_lines: Option<&'static [u8]>,
    endless_at: usize,
    /// The reads so far, and how much room the last one had.
    reads: usize,
    last_read_room: usize,
    /// How many of its replies the peer may give so far, if it waits
    /// for the test to let them go.
    allowed: Option<usize>,
    /// How many of its last replies the peer gives without being asked,
    /// each once the one before it is read.
    volunteers: usize,
}

/// The most reads of an endless reply before the test fails: a transfer
/// that never stops reading would otherwise hang it.
#[cfg(any(test, feature = "test-util"))]
const ENDLESS_READS: usize = 20_000;

#[cfg(any(test, feature = "test-util"))]
impl Wire {
    /// The peer has a request's head to answer with its next reply.
    fn answering(&self) -> bool {
        let asked = if self.greets {
            self.lines + 1
        } else if self.per_send {
            self.sends
        } else {
            self.heads()
        };
        let asked = if self.answered + self.volunteers >= self.replies.len() {
            asked.max(self.answered + 1)
        } else {
            asked
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
            || (self.answered == self.replies.len()
                && (self.then_close || self.resets || self.endless.is_some()))
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
            curl_alloc::TryArc::try_new(curl_alloc::track::untracked_mutex(wire))
                .expect("a test's peer fits"),
        )
    }

    /// The same peer, its datagrams from reply `first` on (counted from
    /// 0) coming from `from`.
    pub fn datagrams_from(self, first: usize, from: SocketAddr) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .datagrams_from = Some((first, from));
        self
    }

    /// The same peer, answering each send with its next reply.
    /// The same peer, each datagram of its replies arriving with the ECN
    /// mark `ecn`.
    pub fn with_ecn(self, ecn: u8) -> Conversation {
        self.0.lock().expect("no test panics holding the wire").ecn = ecn;
        self
    }

    pub fn per_send(self) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .per_send = true;
        self
    }

    /// The same peer, speaking first: a greeting before anything is
    /// sent, then a reply to each send that ends a line with CRLF, however
    /// the sends before it split the line.
    pub fn greeting(self) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .greets = true;
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

    /// The same peer, its sends doing what `script` says in turn: taking
    /// at most so many bytes, none as would-block, or failing as on a
    /// connection the peer closed (`EPIPE`).
    pub fn scripted_sends(self, script: &[ScriptedSend]) -> Conversation {
        {
            let mut wire = self.0.lock().expect("no test panics holding the wire");
            wire.script
                .try_extend_from_slice(script)
                .expect("a test's script fits");
            // Room for what each send is offered, made now.
            wire.offered
                .try_reserve(script.len())
                .expect("a test's script fits");
        }
        self
    }

    /// The scripted sends not yet made.
    pub fn script_left(&self) -> usize {
        let wire = self.0.lock().expect("no test panics holding the wire");
        wire.script.len() - wire.offered.len()
    }

    /// How many bytes each scripted send made so far was offered.
    pub fn offered(&self) -> Vec<usize> {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .offered
            .clone()
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

    /// The same peer, each read giving at most `n` bytes: a peer whose
    /// bytes come a few at a time, each read finding the next waiting.
    pub fn giving(self, n: std::num::NonZeroUsize) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .gives = Some(n);
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

    /// The same peer, giving its last `n` replies unasked, each once the
    /// one before it is read: a server that says more on its own, as a
    /// reply's line that comes late.
    pub fn volunteering(self, n: usize) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .volunteers = n;
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

    /// How many of its replies were read whole.
    pub fn answered(&self) -> usize {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .answered
    }

    /// The same peer, its endless part (`endless`) `line` over and over:
    /// whole lines, none of which ends a reply.
    pub fn endless_lines(self, line: &'static [u8]) -> Conversation {
        assert!(!line.is_empty(), "a line has bytes");
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .endless_lines = Some(line);
        self
    }

    /// How many reads the endless part of the reply has had.
    pub fn endless_reads(&self) -> usize {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .endless_reads
    }

    /// The same peer, resetting the connection once its last reply is
    /// read: the next read fails (`ECONNRESET`).
    pub fn resetting(self) -> Conversation {
        self.0
            .lock()
            .expect("no test panics holding the wire")
            .resets = true;
        self
    }

    /// The same peer, resetting as `resetting` does, the reset polled in
    /// error and hung up beside readable, as Linux polls a socket the
    /// peer reset.
    pub fn resetting_polled(self) -> Conversation {
        {
            let mut wire = self.0.lock().expect("no test panics holding the wire");
            wire.resets = true;
            wire.reset_polls = true;
        }
        self
    }

    /// The same peer, resetting as `resetting` does, the reset read once
    /// as Linux reads it: then the connection's end, and sends failing
    /// with `EPIPE`.
    pub fn resetting_once(self) -> Conversation {
        {
            let mut wire = self.0.lock().expect("no test panics holding the wire");
            wire.resets = true;
            wire.reset_once = true;
        }
        self
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

    /// The same, resetting it instead: the reads after fail.
    pub fn resetting_unanswered(self) -> Conversation {
        let mut wire = self.0.lock().expect("no test panics holding the wire");
        wire.hang_up_unanswered = true;
        wire.hang_up_resets = true;
        drop(wire);
        self
    }

    /// After how many options its socket was made nonblocking before its
    /// first send or read, if it was: a socket the network opens is
    /// nonblocking from the start, and the drain before a close comes too
    /// late.
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

/// The error number a fake lookup of an interface not there leaves.
#[cfg(any(test, feature = "test-util"))]
const NOT_FOUND_ERRNO: i32 = if cfg!(target_vendor = "apple") {
    // What macOS's `getifaddrs` leaves behind (`ENXIO`), which C says.
    6
} else {
    0
};

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
    peers: Vec<(Remote, Peer)>,
    /// What an address's datagrams meet, where the test gives them a peer
    /// apart from its streams': a QUIC peer gone, its TCP one there.
    datagram_peers: Vec<(Remote, Peer)>,
    /// The names it knows, with their addresses in the order answered.
    names: Vec<(Vec<u8>, Vec<IpAddr>)>,
    /// The names answered only once their test lets them, each with its
    /// gate; a resolve of one waits until then.
    late: Vec<(Vec<u8>, Late)>,
    /// The resolves waiting, shared with each one's own, which takes
    /// itself out as it is dropped.
    resolving: FakeResolves,
    /// The id the next resolve gets.
    next_resolve: u64,
    /// The conversations to come, each for the next connection to its
    /// address.
    conversations: Vec<(Remote, Conversation)>,
    /// The connections to come in, each to the next socket opened to
    /// listen on its address (port 0), from its peer's address, so long
    /// after it listens.
    incoming: Vec<(IpAddr, SocketAddr, Conversation, Duration)>,
    /// The scope of its interface with a link-local address, if it has one.
    link_local: Option<NonZeroU32>,
    /// Whether IPv6 works, as a multi's probe finds.
    ipv6: bool,
    /// The sockets open, by number from `FIRST_FAKE`, each with its
    /// conversation: a closed number is handed out again, lowest first, as
    /// the kernel does.
    open: Vec<Option<Conversation>>,
    /// Its interfaces' addresses, each with its name and scope id.
    interfaces: Vec<(Vec<u8>, IpAddr, u32)>,
    /// What a socket may bind to, shared by the sockets it opens; none
    /// where a test says nothing of it, so that opening a socket
    /// allocates nothing.
    binding: Option<curl_alloc::TryArc<Binding>>,
    /// Whether its resolver gives no reason for a failure, as the
    /// threaded resolver gives none, rather than c-ares's.
    no_reasons: bool,
    /// Whether its resolver is asked for a name's HTTPS record, which it
    /// never answers, as the threaded resolver is.
    records_asked: bool,
    /// How many of the sockets it opened were for datagrams.
    datagrams: u32,
    /// The family of a late name that answers before its gate opens, if
    /// one does, as the threaded resolver tells of each family as it
    /// answers: that family's addresses come first, the other's with the
    /// rest.
    first: Option<Family>,
}

/// The gate of a fake name answered late: its resolves wait until the
/// test lets the answer come.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Debug)]
pub struct Late(TryArc<std::sync::atomic::AtomicBool>);

#[cfg(any(test, feature = "test-util"))]
impl Late {
    pub fn new() -> Late {
        Late(TryArc::try_new(std::sync::atomic::AtomicBool::new(false)).expect("a test's gate"))
    }

    /// The answer comes now.
    pub fn release(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn released(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Default for Late {
    fn default() -> Late {
        Late::new()
    }
}

/// The fake's resolves waiting: each one's id, waiter and gate, and
/// whether its answer was told of.
#[cfg(any(test, feature = "test-util"))]
type FakeResolves = TryArc<std::sync::Mutex<Vec<FakeWaiting>>>;

#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
struct FakeWaiting {
    id: u64,
    waiter: Waiter,
    gate: Late,
    told: bool,
}

/// A fake resolve of a late name, its answer and what comes before it
/// found as it starts: the names a test gives do not change.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
struct FakeResolve {
    all: FakeResolves,
    id: u64,
    gate: Late,
    answer: Option<Result<Vec<IpAddr>, ResolveFailure>>,
    partial: Option<Partial>,
}

#[cfg(any(test, feature = "test-util"))]
impl FakeResolve {
    /// Its answer, its place among those waiting let go of.
    fn take(&mut self) -> Result<Vec<IpAddr>, ResolveFailure> {
        self.forget();
        self.answer
            .take()
            .expect("a resolve's answer is taken once")
    }

    fn forget(&self) {
        let id = self.id;
        lock_resolves(&self.all).retain(|w| w.id != id);
    }
}

#[cfg(any(test, feature = "test-util"))]
fn lock_resolves(all: &FakeResolves) -> std::sync::MutexGuard<'_, Vec<FakeWaiting>> {
    all.lock()
        .expect("no test panics holding the fake's resolves")
}

#[cfg(any(test, feature = "test-util"))]
impl Resolving for FakeResolve {
    fn answer(&mut self) -> Option<Result<Vec<IpAddr>, ResolveFailure>> {
        self.gate.released().then(|| self.take())
    }

    fn partial(&mut self) -> Result<Option<Partial>, OutOfMemory> {
        let Some(part) = &self.partial else {
            return Ok(None);
        };
        let mut addrs = Vec::new();
        addrs.try_extend_from_slice(&part.addrs)?;
        Ok(Some(Partial {
            addrs,
            v6_answered: part.v6_answered,
            v4_answered: part.v4_answered,
        }))
    }

    fn wait(&mut self) -> Result<Vec<IpAddr>, ResolveFailure> {
        self.take()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Drop for FakeResolve {
    fn drop(&mut self) {
        self.forget();
    }
}

/// What a fake socket may bind to.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Debug, Default)]
struct Binding {
    /// The interfaces a socket binds to by name.
    devices: Vec<Vec<u8>>,
    /// The local ports in use, which a bind is refused.
    in_use: Vec<u16>,
}

/// The first number a fake socket gets: past the descriptors a test
/// process has open, so that a fake one is never mistaken for them.
#[cfg(any(test, feature = "test-util"))]
const FIRST_FAKE: RawSocket = 1000;
/// The sockets, and the bytes of requests, a fake holds without growing:
/// room for a QUIC handshake and request in a tunnel, a few full
/// datagrams.
#[cfg(any(test, feature = "test-util"))]
const SOCKETS_ROOM: usize = 16;
#[cfg(any(test, feature = "test-util"))]
const REQUESTS_ROOM: usize = 16384;

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
            datagram_peers: Vec::new(),
            names: Vec::new(),
            late: Vec::new(),
            resolving: TryArc::try_new(curl_alloc::track::untracked_mutex(Vec::new()))
                .expect("a test's resolves fit"),
            next_resolve: 0,
            conversations: Vec::new(),
            incoming: Vec::new(),
            link_local: None,
            ipv6: true,
            open,
            interfaces: Vec::new(),
            binding: None,
            no_reasons: false,
            records_asked: false,
            datagrams: 0,
            first: None,
        }
    }

    /// An interface named `name` with the address `ip`, of scope id
    /// `scope` if IPv6.
    pub fn with_interface(mut self, name: &str, ip: IpAddr, scope: u32) -> FakeNet {
        let mut n = Vec::new();
        n.try_extend_from_slice(name.as_bytes())
            .expect("a test's names fit");
        self.interfaces
            .try_push((n, ip, scope))
            .expect("a test's interfaces fit");
        self
    }

    /// A socket may bind to the interface `name` by its name.
    pub fn with_device(self, name: &str) -> FakeNet {
        self.binding_with(|b| {
            let mut n = Vec::new();
            n.try_extend_from_slice(name.as_bytes())
                .expect("a test's names fit");
            b.devices.try_push(n).expect("a test's devices fit");
        })
    }

    /// The local port `port` is in use: a bind to it is refused.
    pub fn with_port_in_use(self, port: u16) -> FakeNet {
        self.binding_with(|b| b.in_use.try_push(port).expect("a test's ports fit"))
    }

    fn binding_with(mut self, change: impl FnOnce(&mut Binding)) -> FakeNet {
        let mut binding = self.binding.as_deref().cloned().unwrap_or_default();
        change(&mut binding);
        self.binding = Some(curl_alloc::TryArc::try_new(binding).expect("a test's binding fits"));
        self
    }

    /// `Curl_if2ip` over the interfaces it has; one not there leaves
    /// the error number the system's lookup leaves.
    fn interface_address_of(
        &self,
        name: &[u8],
        v6: bool,
        remote_scope: Ipv6Scope,
        scope_id: u32,
    ) -> InterfaceAddress {
        let mut found = InterfaceAddress::NotFound(NOT_FOUND_ERRNO);
        for &(ref n, ip, scope) in &self.interfaces {
            let named = n.as_slice() == name;
            if ip.is_ipv6() != v6 {
                if named && matches!(found, InterfaceAddress::NotFound(_)) {
                    found = InterfaceAddress::OtherFamily;
                }
                continue;
            }
            if !named {
                continue;
            }
            if v6 && (ipv6_scope(ip) != remote_scope || (scope_id != 0 && scope != scope_id)) {
                if matches!(found, InterfaceAddress::NotFound(_)) {
                    found = InterfaceAddress::OtherFamily;
                }
                continue;
            }
            return InterfaceAddress::Found(ip, scope);
        }
        found
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
    pub fn with_conversation(self, addr: SocketAddr, conversation: Conversation) -> FakeNet {
        self.with_conversation_at(Remote::Inet(addr), conversation)
    }

    /// `with_conversation`, at an address on the network or a Unix
    /// socket.
    pub(crate) fn with_conversation_at(
        mut self,
        addr: Remote,
        conversation: Conversation,
    ) -> FakeNet {
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

    /// `name` resolves to `addrs` once `late` lets it: until then, a
    /// resolve of it waits.
    /// Its resolver gives no reason for a failure, as the threaded
    /// resolver gives none.
    pub fn without_reasons(mut self) -> FakeNet {
        self.no_reasons = true;
        self
    }

    /// Its resolver is asked for a name's HTTPS record, and never
    /// answers, as the threaded resolver is.
    pub fn with_records_asked(mut self) -> FakeNet {
        self.records_asked = true;
        self
    }

    /// Its late names' AAAA answers come before their gates open.
    pub fn with_v6_first(mut self) -> FakeNet {
        self.first = Some(Family::V6);
        self
    }

    /// Its late names' A answers come before their gates open.
    pub fn with_v4_first(mut self) -> FakeNet {
        self.first = Some(Family::V4);
        self
    }

    pub fn with_late_name(mut self, name: &str, addrs: &[IpAddr], late: &Late) -> FakeNet {
        self = self.with_name(name, addrs);
        let mut n = Vec::new();
        n.try_extend_from_slice(name.as_bytes())
            .expect("a test's names fit");
        self.late
            .try_push((n, late.clone()))
            .expect("a test's names fit");
        self
    }

    /// How many resolves wait for their answer to be taken.
    #[cfg(test)]
    pub(crate) fn resolving(&self) -> usize {
        lock_resolves(&self.resolving).len()
    }

    /// The gate `name`'s answer waits for, if it is not open yet.
    fn gate(&self, name: &[u8]) -> Option<Late> {
        self.late
            .iter()
            .find(|(n, late)| n.eq_ignore_ascii_case(name) && !late.released())
            .map(|(_, late)| late.clone())
    }

    /// The addresses of `family` the test gave `name`.
    fn lookup(&self, name: &[u8], family: Family) -> Result<Vec<IpAddr>, ResolveFailure> {
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

    pub fn with_peer(self, addr: SocketAddr, peer: Peer) -> FakeNet {
        self.with_peer_at(Remote::Inet(addr), peer)
    }

    /// What datagrams to `addr` meet, apart from what its streams meet,
    /// which `with_peer` gives: the address needs that too.
    pub fn with_datagram_peer(mut self, addr: SocketAddr, peer: Peer) -> FakeNet {
        self.datagram_peers
            .try_push((Remote::Inet(addr), peer))
            .expect("a test's peers fit");
        self
    }

    /// A server that connects to the next socket opened to listen on
    /// `ip`, from `from`, `after` it listens, and then says `talk`: FTP's
    /// active data connection. The socket it connects as is numbered as
    /// the listening one opens, the next number after it.
    pub fn with_incoming(
        mut self,
        ip: IpAddr,
        from: SocketAddr,
        talk: &Conversation,
        after: Duration,
    ) -> FakeNet {
        self.incoming
            .try_push((ip, from, talk.clone(), after))
            .expect("a test's connections fit");
        self
    }

    /// `with_peer`, at an address on the network or a Unix socket.
    pub(crate) fn with_peer_at(mut self, addr: Remote, peer: Peer) -> FakeNet {
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
        let n = RawSocket::try_from(row).expect("a test opens few sockets");
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
    pub fn datagram_sockets(&self) -> u32 {
        self.datagrams
    }

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
    /// A socket for datagrams is counted, and carries its conversation as
    /// a stream's does, each send and receive a datagram's bytes.
    fn open(&mut self, addr: &Remote, kind: SocketKind) -> io::Result<Box<dyn Socket>> {
        if kind == SocketKind::Datagram {
            self.datagrams += 1;
        }
        let peer = self.peers.iter().find(|(a, _)| a == addr).map(|&(_, p)| p);
        let datagram_peer = self.datagram_peers.iter().find(|(a, _)| a == addr);
        let peer = match datagram_peer {
            Some(&(_, p)) if kind == SocketKind::Datagram && peer.is_some() => Some(p),
            _ => peer,
        };
        let wire = match self.conversations.iter().position(|(a, _)| a == addr) {
            Some(at) if peer.is_some() => self.conversations.remove(at).1,
            _ => Conversation(
                curl_alloc::TryArc::try_new(curl_alloc::track::untracked_mutex(Wire::default()))
                    .map_err(|_| io::ErrorKind::OutOfMemory)?,
            ),
        };
        let key = self.open_number(wire.clone())?;
        // A socket to listen with: a connection to come in is given its
        // number now, as it will be once accepted.
        let listens_on = match addr {
            Remote::Inet(at) if at.port() == 0 && kind == SocketKind::Stream => Some(at.ip()),
            _ => None,
        };
        let incoming = match listens_on.and_then(|ip| self.incoming.iter().position(|i| i.0 == ip))
        {
            Some(at) => {
                let (_, from, talk, after) = self.incoming.remove(at);
                let accepted = self.open_number(talk.clone())?;
                Some(Incoming {
                    key: accepted,
                    from,
                    talk,
                    after,
                    at: None,
                })
            }
            None => None,
        };
        // The port the kernel would have picked.
        let port = 40000 + u16::try_from(key.0 - FIRST_FAKE).expect("a test opens few sockets");
        // A Unix socket has no address of TCP's families.
        let local = match addr {
            Remote::Inet(SocketAddr::V4(_)) => Some(SocketAddr::from(([127, 0, 0, 1], port))),
            Remote::Inet(SocketAddr::V6(_)) => {
                Some(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)))
            }
            Remote::Unix(_) => None,
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
            binding: self.binding.clone(),
            bound: curl_alloc::track::untracked_mutex(None),
            connected: std::sync::atomic::AtomicBool::new(false),
            opened_for: addr.clone(),
            clock: self.clock.clone(),
            ready_at,
            wire,
            listening: std::sync::atomic::AtomicBool::new(false),
            incoming: curl_alloc::track::untracked_mutex(incoming),
            from: None,
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

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn Resolver)) {
        f(self);
    }

    fn link_local_scope(&mut self) -> Option<NonZeroU32> {
        self.link_local
    }

    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: crate::conn::io::Ipv6Scope,
        scope_id: u32,
    ) -> crate::conn::io::InterfaceAddress {
        self.interface_address_of(name, v6, remote_scope, scope_id)
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
    local: Option<SocketAddr>,
    binding: Option<curl_alloc::TryArc<Binding>>,
    /// What it was bound to before it connected.
    bound: std::sync::Mutex<Option<SocketAddr>>,
    /// Whether its connect started: only then is it bound.
    connected: std::sync::atomic::AtomicBool,
    opened_for: Remote,
    clock: crate::time::ManualClock,
    /// When a peer that answers late answers.
    ready_at: Option<Instant>,
    wire: Conversation,
    /// It listens.
    listening: std::sync::atomic::AtomicBool,
    /// The connection that comes in once it listens, until accepted.
    incoming: std::sync::Mutex<Option<Incoming>>,
    /// Where an accepted socket's peer connected from.
    from: Option<SocketAddr>,
}

/// A connection to come in to a fake listening socket: its number, its
/// peer's address and what it says.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
struct Incoming {
    key: SocketKey,
    from: SocketAddr,
    talk: Conversation,
    /// How long after the listen it comes, and when that is, once it
    /// listens.
    after: Duration,
    at: Option<Instant>,
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
        if self.listening.load(std::sync::atomic::Ordering::Relaxed) {
            // A connection waits to be accepted, comes later, or none comes.
            let at = self
                .incoming
                .lock()
                .expect("no test panics holding it")
                .as_ref()
                .and_then(|i| i.at);
            let now = crate::time::Clock::now(&self.clock);
            return match at {
                Some(at) if at <= now => Readiness::Known {
                    now: Events::IN,
                    later: None,
                },
                later => Readiness::Known {
                    now: Events::NONE,
                    later,
                },
            };
        }
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
            // A reset come polls in error and hung up beside readable,
            // as Linux polls a socket the peer reset.
            if wire.reset_polls && wire.resets && wire.answered == wire.replies.len() {
                now = now | Events::ERR | Events::HUP;
            }
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

    /// Bound as its connect starts, where it was bound to if it was, the
    /// kernel's port for a bind to none: unbound before, and after one
    /// refused at once, unless it was bound.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let bound = *self.bound.lock().expect("no test panics holding it");
        let Some(local) = self.local else {
            return Err(io::Error::from_raw_os_error(libc_errno::EINVAL));
        };
        if self.connected.load(std::sync::atomic::Ordering::Relaxed) {
            // What the bind left open, the connect chooses.
            return Ok(match bound {
                Some(at) => {
                    let ip = if at.ip().is_unspecified() {
                        local.ip()
                    } else {
                        at.ip()
                    };
                    let port = if at.port() == 0 {
                        local.port()
                    } else {
                        at.port()
                    };
                    SocketAddr::new(ip, port)
                }
                None => local,
            });
        }
        if let Some(at) = bound {
            // A bind to port 0 is given one, as the kernel picks.
            let port = if at.port() == 0 {
                local.port()
            } else {
                at.port()
            };
            return Ok(SocketAddr::new(at.ip(), port));
        }
        Ok(match local {
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
        if wire.sends == 0 && wire.reads == 0 {
            wire.nonblocking_after = Some(wire.options.iter().flatten().count());
        }
        Ok(())
    }

    /// Bound to a port in use, the bind is refused; and so is the bind of
    /// a socket that connected, which the connect bound.
    fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        if self.connected.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(io::Error::from_raw_os_error(libc_errno::EINVAL));
        }
        let in_use = self
            .binding
            .as_ref()
            .is_some_and(|b| addr.port() != 0 && b.in_use.contains(&addr.port()));
        if in_use {
            return Err(io::Error::from_raw_os_error(libc_errno::EADDRINUSE));
        }
        *self.bound.lock().expect("no test panics holding it") = Some(addr);
        Ok(())
    }

    /// Only an interface the network has as a device binds.
    #[cfg(target_os = "linux")]
    fn bind_to_device(&self, name: &[u8]) -> io::Result<()> {
        let known = self
            .binding
            .as_ref()
            .is_some_and(|b| b.devices.iter().any(|d| d.as_slice() == name));
        if known {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(libc_errno::ENODEV))
        }
    }

    /// Only a socket that was bound listens.
    fn listen(&self) -> io::Result<()> {
        if self
            .bound
            .lock()
            .expect("no test panics holding it")
            .is_none()
        {
            return Err(io::Error::from_raw_os_error(libc_errno::EINVAL));
        }
        self.listening
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let now = crate::time::Clock::now(&self.clock);
        if let Some(i) = self
            .incoming
            .lock()
            .expect("no test panics holding it")
            .as_mut()
        {
            i.at = Some(now.after(i.after));
        }
        Ok(())
    }

    /// The connection to come in, once it listens: connected, from its
    /// peer's address to the one it listens on.
    fn accept(&self) -> io::Result<Option<Box<dyn Socket>>> {
        if !self.listening.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(io::Error::from_raw_os_error(libc_errno::EINVAL));
        }
        let now = crate::time::Clock::now(&self.clock);
        let mut waiting = self.incoming.lock().expect("no test panics holding it");
        if !waiting
            .as_ref()
            .is_some_and(|i| i.at.is_some_and(|at| at <= now))
        {
            return Ok(None);
        }
        let incoming = waiting.take().expect("checked above");
        drop(waiting);
        let local = self.local_addr()?;
        let socket = FakeSocket {
            key: incoming.key,
            peer: Some(Peer::Accepts),
            local: Some(local),
            binding: None,
            bound: curl_alloc::track::untracked_mutex(None),
            connected: std::sync::atomic::AtomicBool::new(true),
            opened_for: Remote::Inet(incoming.from),
            clock: self.clock.clone(),
            ready_at: None,
            wire: incoming.talk,
            listening: std::sync::atomic::AtomicBool::new(false),
            incoming: curl_alloc::track::untracked_mutex(None),
            from: Some(incoming.from),
        };
        Ok(Some(
            try_box(socket).map_err(|_| io::ErrorKind::OutOfMemory)? as Box<dyn Socket>,
        ))
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.from
            .ok_or_else(|| io::Error::from_raw_os_error(libc_errno::ENOTCONN))
    }

    /// Its peer is the one at the address it was opened for, which it
    /// must connect to.
    fn connect(&self, addr: &Remote) -> io::Result<Connect> {
        assert_eq!(
            *addr, self.opened_for,
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
        if wire.hung_up && wire.hang_up_resets {
            return Err(io::Error::from_raw_os_error(libc_errno::ECONNRESET));
        }
        if wire.hung_up || self.peer() == Peer::HangsUp {
            return Ok(Recv::Eof);
        }
        // A refusal is read as the error it is, as a UDP socket reads the
        // ICMP error a datagram met (a stream's connect fails first).
        if matches!(self.peer(), Peer::Refuses)
            || matches!(self.peer(), Peer::RefusesAfter(_))
                && self
                    .ready_at
                    .is_some_and(|at| crate::time::Clock::now(&self.clock) >= at)
        {
            return Err(io::Error::from_raw_os_error(libc_errno::ECONNREFUSED));
        }
        // A peer that answers late says nothing before then.
        if self
            .ready_at
            .is_some_and(|at| crate::time::Clock::now(&self.clock) < at)
        {
            return Ok(Recv::WouldBlock);
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
            let most = wire.gives.map_or(buf.len(), |g| g.get().min(buf.len()));
            let n = left.len().min(most);
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
            match wire.endless_lines {
                Some(line) => {
                    for b in buf.iter_mut() {
                        *b = line[wire.endless_at];
                        wire.endless_at = (wire.endless_at + 1) % line.len();
                    }
                }
                None => buf.fill(b'x'),
            }
            self.clock.advance(per_read);
            let n = std::num::NonZeroUsize::new(buf.len()).expect("checked above");
            return Ok(Recv::Data(n));
        }
        if wire.resets {
            if wire.reset_once {
                wire.hung_up = true;
            }
            return Err(io::Error::from_raw_os_error(libc_errno::ECONNRESET));
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

    /// One send, as a stream's: the run is the peer's to cut.
    #[cfg(unix)]
    fn send_segments(&self, buf: &[u8], _segment: usize) -> io::Result<usize> {
        match self.send(buf)? {
            Sent::Bytes(n) => Ok(n.get()),
            Sent::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    /// A datagram to the address it was opened for, or the one its
    /// datagrams come from, as a stream's send.
    fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        let other = self
            .wire
            .0
            .lock()
            .expect("no test panics holding the wire")
            .datagrams_from
            .map(|(_, from)| from);
        assert!(
            Remote::Inet(to) == self.opened_for || Some(to) == other,
            "sent to its peer, not {to}"
        );
        match self.send(buf)? {
            Sent::Bytes(n) => Ok(n.get()),
            Sent::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    /// Each reply is a datagram from the address it was opened for, or
    /// from the one `Conversation::datagrams_from` names; what of one
    /// does not fit is lost, as a datagram's is.
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        let Remote::Inet(peer) = self.opened_for else {
            return Err(io::ErrorKind::Unsupported.into());
        };
        let from = {
            let wire = self.wire.0.lock().expect("no test panics holding the wire");
            match wire.datagrams_from {
                Some((first, from)) if wire.answered >= first => from,
                _ => peer,
            }
        };
        Ok(match self.recv(buf)? {
            Recv::Data(n) => {
                let mut wire = self.wire.0.lock().expect("no test panics holding the wire");
                if wire.read != 0 {
                    wire.answered += 1;
                    wire.read = 0;
                }
                Some((n.get(), from))
            }
            Recv::WouldBlock | Recv::Eof => None,
        })
    }

    /// Each reply the peer has ready is a datagram, none joined.
    #[cfg(unix)]
    fn recv_batch(&self, buf: &mut [u8], slot: usize, out: &mut [Datagram]) -> io::Result<usize> {
        let room = out.len().min(buf.len() / slot);
        let mut n = 0;
        while n < room {
            match self.recv(&mut buf[n * slot..(n + 1) * slot])? {
                Recv::Data(got) => {
                    let len = got.get();
                    let ecn = self
                        .wire
                        .0
                        .lock()
                        .expect("no test panics holding the wire")
                        .ecn;
                    out[n] = Datagram {
                        len,
                        segment: len,
                        ecn,
                        from: None,
                    };
                    n += 1;
                }
                Recv::WouldBlock | Recv::Eof => break,
            }
        }
        if n == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(n)
    }

    fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        let mut wire = self.wire.0.lock().expect("no test panics holding the wire");
        let n = std::num::NonZeroUsize::new(buf.len()).expect("a send needs bytes");
        let mut n = wire.takes.map_or(n, |most| n.min(most));
        if let Some(&step) = wire.script.get(wire.offered.len()) {
            assert!(
                wire.offered.len() < wire.offered.capacity(),
                "room for each scripted send"
            );
            wire.offered
                .try_push(buf.len())
                .expect("room for each scripted send");
            match step {
                ScriptedSend::Fails => return Err(io::Error::from_raw_os_error(libc_errno::EPIPE)),
                ScriptedSend::Takes(most) => match std::num::NonZeroUsize::new(most) {
                    Some(most) => n = n.min(most),
                    None => return Ok(Sent::WouldBlock),
                },
            }
        }
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
        if wire.received.ends_with(b"\r\n") {
            wire.lines += 1;
        }
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
#[cfg(all(target_os = "linux", any(test, feature = "test-util")))]
mod libc_errno {
    pub(super) const ECONNREFUSED: i32 = 111;
    pub(super) const EPIPE: i32 = 32;
    pub(super) const ECONNRESET: i32 = 104;
    pub(super) const EADDRINUSE: i32 = 98;
    pub(super) const EINVAL: i32 = 22;
    pub(super) const ENODEV: i32 = 19;
    pub(super) const ENOTCONN: i32 = 107;
}

/// The error numbers the fake gives, as macOS numbers them.
#[cfg(all(target_vendor = "apple", any(test, feature = "test-util")))]
mod libc_errno {
    pub(super) const ECONNREFUSED: i32 = 61;
    pub(super) const EPIPE: i32 = 32;
    pub(super) const ECONNRESET: i32 = 54;
    pub(super) const EADDRINUSE: i32 = 48;
    pub(super) const EINVAL: i32 = 22;
    pub(super) const ENOTCONN: i32 = 57;
}

/// The error numbers the fake gives, as Winsock numbers them; a send on
/// a connection shut is `WSAESHUTDOWN`, Windows' broken pipe.
#[cfg(all(windows, any(test, feature = "test-util")))]
mod libc_errno {
    pub(super) const ECONNREFUSED: i32 = 10061;
    pub(super) const EPIPE: i32 = 10058;
    pub(super) const ECONNRESET: i32 = 10054;
    pub(super) const EADDRINUSE: i32 = 10048;
    pub(super) const EINVAL: i32 = 10022;
    pub(super) const ENOTCONN: i32 = 10057;
}

#[cfg(any(test, feature = "test-util"))]
impl Resolver for FakeNet {
    fn start(
        &mut self,
        name: &[u8],
        family: Family,
        waiter: Waiter,
    ) -> Result<Resolve, ResolveFailure> {
        let Some(gate) = self.gate(name) else {
            return self.lookup(name, family).map(Resolve::Answer);
        };
        let oom = |OutOfMemory| ResolveFailure::OutOfMemory;
        let id = self.next_resolve;
        self.next_resolve += 1;
        let partial = match self.first {
            None => None,
            Some(first) => {
                let mut addrs = Vec::new();
                if let Some((_, all)) = self
                    .names
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(name))
                {
                    let v6 = first == Family::V6;
                    for a in all.iter().filter(|a| a.is_ipv6() == v6) {
                        addrs.try_push(*a).map_err(oom)?;
                    }
                }
                Some(Partial {
                    addrs,
                    v6_answered: first == Family::V6,
                    v4_answered: first == Family::V4,
                })
            }
        };
        let waiting = FakeWaiting {
            id,
            waiter,
            gate: gate.clone(),
            told: false,
        };
        lock_resolves(&self.resolving)
            .try_push(waiting)
            .map_err(oom)?;
        let resolve = FakeResolve {
            all: self.resolving.clone(),
            id,
            gate,
            answer: Some(self.lookup(name, family)),
            partial,
        };
        // Each family a query of its own, as the threaded resolver asks.
        Ok(Resolve::Pending {
            resolve: try_box(resolve).map_err(oom)?,
            v6: family != Family::V4,
            v4: family != Family::V6,
        })
    }

    fn answered(&mut self, each: &mut dyn FnMut(Waiter)) {
        for w in lock_resolves(&self.resolving).iter_mut() {
            if !w.told && w.gate.released() {
                w.told = true;
                each(w.waiter);
            }
        }
    }

    fn waker(&self) -> Option<TryArc<Waker>> {
        None
    }

    fn explain(&self, why: ResolveFailure) -> Option<&'static str> {
        c_ares_explains(why).filter(|_| !self.no_reasons)
    }

    fn asked_for_records(&self) -> bool {
        self.records_asked
    }
}

/// A tests' resolver whose every answer `F` gives as its resolve starts.
#[cfg(any(test, feature = "test-util"))]
pub struct AtOnce<F>(pub F);

#[cfg(any(test, feature = "test-util"))]
impl<F: FnMut(&[u8], Family) -> Result<Vec<IpAddr>, ResolveFailure>> Resolver for AtOnce<F> {
    fn start(&mut self, name: &[u8], family: Family, _: Waiter) -> Result<Resolve, ResolveFailure> {
        (self.0)(name, family).map(Resolve::Answer)
    }

    fn answered(&mut self, _: &mut dyn FnMut(Waiter)) {}

    fn waker(&self) -> Option<TryArc<Waker>> {
        None
    }

    fn explain(&self, why: ResolveFailure) -> Option<&'static str> {
        c_ares_explains(why)
    }
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

    fn open(&mut self, addr: &Remote, kind: SocketKind) -> io::Result<Box<dyn Socket>> {
        self.0.lock().unwrap().open(addr, kind)
    }

    fn close(&mut self, socket: Sock) {
        self.0.lock().unwrap().close(socket);
    }

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn Resolver)) {
        self.0.lock().unwrap().with_resolver(f);
    }

    fn link_local_scope(&mut self) -> Option<NonZeroU32> {
        self.0.lock().unwrap().link_local_scope()
    }

    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: crate::conn::io::Ipv6Scope,
        scope_id: u32,
    ) -> crate::conn::io::InterfaceAddress {
        self.0
            .lock()
            .unwrap()
            .interface_address(name, v6, remote_scope, scope_id)
    }

    fn probe_ipv6(&mut self) -> Result<bool, OutOfMemory> {
        self.0.lock().unwrap().probe_ipv6()
    }
}

/// One end of a connected pair of streams, for tests that poll a
/// descriptor of their own: a Unix socket's, or on Windows, which polls
/// sockets alone, a loopback TCP connection's.
#[cfg(all(test, unix))]
pub(crate) type PairEnd = std::os::unix::net::UnixStream;
#[cfg(all(test, windows))]
pub(crate) type PairEnd = std::net::TcpStream;

/// A connected pair of streams, written at one end and read at the other.
#[cfg(test)]
pub(crate) fn stream_pair() -> (PairEnd, PairEnd) {
    #[cfg(unix)]
    {
        PairEnd::pair().expect("a pair of sockets")
    }
    #[cfg(windows)]
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let a = PairEnd::connect(listener.local_addr().expect("bound")).expect("a connect");
        let (b, _) = crate::test_server::accept(&listener);
        (a, b)
    }
}

/// The socket `end` polls by.
#[cfg(test)]
pub(crate) fn pair_socket(end: &PairEnd) -> BorrowedSocket<'_> {
    curl_os::socket::AsSocket::borrow_socket(end)
}

/// A socket opened on `net` for `at`, its connect started, for tests that
/// need one connecting.
#[cfg(test)]
pub(crate) fn dial(net: &mut dyn Net, at: SocketAddr) -> Box<dyn Socket> {
    let at = Remote::Inet(at);
    let socket = net
        .open(&at, SocketKind::Stream)
        .expect("a test's socket opens");
    socket.connect(&at).expect("a test's connect starts");
    socket
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    /// A socket the system opened gives a library working on it, as
    /// libssh and libldap do, the descriptor it is polled by.
    #[test]
    fn a_system_socket_gives_its_descriptor() {
        // Winsock started for the socket, as a multi starts it, not left
        // to whichever test has it started meanwhile.
        let _winsock = Winsock::start().expect("Winsock");
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let s = curl_os::net::open(at, curl_os::net::Protocol::Tcp, true).unwrap();
        let polled = match s.readiness() {
            Readiness::Poll(fd) => curl_os::socket::raw(fd),
            Readiness::Known { .. } => panic!("a system socket is polled"),
        };
        let given = Socket::descriptor(&s).expect("a descriptor");
        assert_eq!(curl_os::socket::raw(given), polled);
    }

    /// The system's resolver, which stands in for the reference build's
    /// c-ares, gives c-ares's reasons, in any build.
    #[test]
    fn the_system_s_resolver_gives_c_ares_s_reasons() {
        let r = SystemResolver;
        assert_eq!(
            r.explain(ResolveFailure::NotFound),
            Some("Domain name not found")
        );
        assert_eq!(
            r.explain(ResolveFailure::NoData),
            Some("DNS server returned answer with no data")
        );
        assert_eq!(r.explain(ResolveFailure::Failed), None);
    }

    /// A multi's network resolves as the build chooses: with the threaded
    /// resolver, which lends a wake and gives no reason for a failure;
    /// else with the system's, which answers as it starts and gives
    /// c-ares's reason, as the reference build's does.
    #[test]
    fn a_multi_s_network_resolves_as_the_build_chooses() {
        let mut net = SystemNet::for_multi(super::super::threaded::Threads::EASY).unwrap();
        let mut seen = None;
        net.with_resolver(&mut |r| {
            seen = Some((
                r.waker().is_some(),
                r.explain(ResolveFailure::NotFound),
                r.explain(ResolveFailure::NoData),
                r.explain(ResolveFailure::Again),
            ));
        });
        let threaded = cfg!(feature = "threaded-resolver");
        let reasons = match threaded {
            true => (None, None),
            false => (
                Some("Domain name not found"),
                Some("DNS server returned answer with no data"),
            ),
        };
        assert_eq!(seen, Some((threaded, reasons.0, reasons.1, None)));
    }

    /// The system's network resolves names with the system's resolver.
    #[test]
    fn the_system_resolves_names() {
        let mut answers = Vec::new();
        SystemNet::default().with_resolver(&mut |r| {
            answers.push(r.start(b"localhost", Family::V4, Waiter::NONE));
            answers.push(r.start(b"nonexist.invalid", Family::Any, Waiter::NONE));
        });
        let Ok(Resolve::Answer(addrs)) = &answers[0] else {
            panic!("{answers:?}");
        };
        assert!(addrs.contains(&IpAddr::from([127, 0, 0, 1])), "{addrs:?}");
        assert!(answers[1].is_err(), "{answers:?}");
    }

    #[test]
    fn the_system_network_polls_the_descriptors() {
        let (mut a, b) = stream_pair();
        let mut fds = [PollFd::new(pair_socket(&b), Events::IN)];
        let none = &mut [];
        assert_eq!(
            SystemNet::default()
                .poll(none, &mut fds, Duration::from_millis(1))
                .unwrap(),
            0
        );
        a.write_all(b"x").unwrap();
        assert_eq!(
            SystemNet::default()
                .poll(none, &mut fds, Duration::from_secs(5))
                .unwrap(),
            1
        );
        assert!(fds[0].revents().contains(Events::IN));
    }

    /// A real socket bound listens and accepts a connection once one
    /// waits; a socket of another kind does neither.
    #[test]
    fn a_real_socket_listens_and_accepts() {
        let mut net = SystemNet::default();
        let any = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
        let socket = net.open(&Remote::Inet(any), SocketKind::Stream).unwrap();
        socket.bind(any).unwrap();
        socket.listen().unwrap();
        assert!(socket.accept().unwrap().is_none(), "none waits yet");
        let peer = std::net::TcpStream::connect(socket.local_addr().unwrap()).unwrap();
        let mut sockets = [SocketPoll::new(&*socket, Events::IN)];
        net.poll(&mut sockets, &mut [], Duration::from_secs(5))
            .unwrap();
        let accepted = socket.accept().unwrap().expect("the connection waiting");
        assert_eq!(accepted.peer_addr().unwrap(), peer.local_addr().unwrap());
        net.close(Sock::new(accepted, Closer::System));
        net.close(Sock::new(socket, Closer::System));
        let udp = net.open(&Remote::Inet(any), SocketKind::Datagram).unwrap();
        assert_eq!(udp.listen().unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            udp.accept().err().map(|e| e.kind()),
            Some(io::ErrorKind::Unsupported)
        );
        net.close(Sock::new(udp, Closer::System));
    }

    /// A real UDP socket, connected to no peer, sends a datagram to an
    /// address and reads one with its sender, none when none waits; a
    /// stream does neither.
    #[test]
    fn a_real_udp_socket_sends_to_and_receives_from() {
        let mut net = SystemNet::default();
        let any = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
        let peer = std::net::UdpSocket::bind(any).unwrap();
        let udp = net.open(&Remote::Inet(any), SocketKind::Datagram).unwrap();
        udp.bind(any).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(udp.recv_from(&mut buf).unwrap(), None, "none waits yet");
        assert_eq!(udp.send_to(b"ping", peer.local_addr().unwrap()).unwrap(), 4);
        let (n, from) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
        peer.send_to(b"pong!", from).unwrap();
        let mut sockets = [SocketPoll::new(&*udp, Events::IN)];
        net.poll(&mut sockets, &mut [], Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            udp.recv_from(&mut buf).unwrap(),
            Some((5, peer.local_addr().unwrap()))
        );
        assert_eq!(&buf[..5], b"pong!");
        net.close(Sock::new(udp, Closer::System));
        let stream = net.open(&Remote::Inet(any), SocketKind::Stream).unwrap();
        assert_eq!(
            stream.send_to(b"x", any).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            stream.recv_from(&mut buf).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        net.close(Sock::new(stream, Closer::System));
    }

    /// A real socket and a descriptor polled together each get their own
    /// events back.
    #[test]
    fn sockets_and_descriptors_are_polled_together() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = dial(&mut SystemNet::default(), listener.local_addr().unwrap());
        let (mut a, b) = stream_pair();
        a.write_all(b"x").unwrap();
        let mut sockets = [SocketPoll::new(&*socket, Events::OUT)];
        let mut fds = [PollFd::new(pair_socket(&b), Events::IN)];
        let ready = SystemNet::default()
            .poll(&mut sockets, &mut fds, Duration::from_secs(5))
            .unwrap();
        assert!(ready >= 1);
        assert!(fds[0].revents().contains(Events::IN));
        // The connect is decided by now or soon; once it is, writable.
        let mut sockets = [SocketPoll::new(&*socket, Events::OUT)];
        SystemNet::default()
            .poll(&mut sockets, &mut [], Duration::from_secs(5))
            .unwrap();
        assert!(sockets[0].revents().contains(Events::OUT));
        assert!(socket.take_error().unwrap().is_none());
        SystemNet::default().close(Sock::new(socket, Closer::System));
    }

    /// A connect refused on Windows shows only as an exception: a socket
    /// polled to take more is asked for that too, so the refusal ends the
    /// wait, and the socket's error says it.
    #[cfg(windows)]
    #[test]
    fn a_refused_connect_ends_a_wait_for_writable() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = closed.local_addr().unwrap();
        drop(closed);
        let mut net = SystemNet::default();
        let socket = net.open(&Remote::Inet(at), SocketKind::Stream).unwrap();
        // Refused at the first SYN, not after Windows' retries.
        socket.set(SocketOption::NoSynRetransmissions).unwrap();
        match socket.connect(&Remote::Inet(at)) {
            Ok(Connect::InProgress) => {}
            other => panic!("{other:?}"),
        }
        let mut sockets = [SocketPoll::new(&*socket, Events::OUT)];
        let ready = net
            .poll(&mut sockets, &mut [], Duration::from_secs(10))
            .unwrap();
        assert_eq!(ready, 1, "the refusal ends the wait");
        assert!(sockets[0].revents().contains(Events::PRI));
        let refused = socket.take_error().unwrap().expect("refused");
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
        net.close(Sock::new(socket, Closer::System));
    }

    /// More sockets and descriptors than fit on the stack are polled all
    /// the same, each getting its own events back.
    #[test]
    fn more_than_fit_on_the_stack_are_polled() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let one = dial(&mut SystemNet::default(), listener.local_addr().unwrap());
        let two = dial(&mut SystemNet::default(), listener.local_addr().unwrap());
        let pairs: Vec<_> = (0..9).map(|_| stream_pair()).collect();
        (&pairs[8].0).write_all(b"x").unwrap();
        let mut sockets = [
            SocketPoll::new(&*one, Events::IN),
            SocketPoll::new(&*two, Events::IN),
        ];
        let mut fds: Vec<PollFd<'_>> = pairs
            .iter()
            .map(|(_, b)| PollFd::new(pair_socket(b), Events::IN))
            .collect();
        let ready = SystemNet::default()
            .poll(&mut sockets, &mut fds, Duration::from_secs(5))
            .unwrap();
        assert_eq!(ready, 1);
        assert!(fds[8].revents().contains(Events::IN));
        assert!(fds[..8].iter().all(|f| f.revents().is_empty()));
        SystemNet::default().close(Sock::new(one, Closer::System));
        SystemNet::default().close(Sock::new(two, Closer::System));
    }

    /// A socket goes only through its closer: one dropped unclosed is a
    /// bug, caught in every build.
    #[test]
    #[should_panic = "was dropped, not closed"]
    fn a_dropped_socket_is_caught() {
        let clock = crate::time::ManualClock::new().unwrap();
        let at = SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(clock).with_peer(at, Peer::Accepts);
        drop(Sock::new(dial(&mut net, at), Closer::System));
    }

    /// A fake listening socket is readable only once its incoming
    /// connection is due, and accepts it then, from where it comes.
    #[test]
    fn a_fake_listener_is_ready_when_its_connection_comes() {
        use crate::time::Clock as _;
        let clock = crate::time::ManualClock::new().unwrap();
        let ip = IpAddr::from([127, 0, 0, 1]);
        let from = SocketAddr::from((ip, 20));
        let talk = Conversation::replies(&[b"x"], true);
        let after = Duration::from_millis(5);
        let mut net = FakeNet::new(clock.clone()).with_incoming(ip, from, &talk, after);
        let any = SocketAddr::from((ip, 0));
        let s = net.open(&Remote::Inet(any), SocketKind::Stream).unwrap();
        s.bind(any).unwrap();
        s.listen().unwrap();
        let due = clock.now().after(after);
        assert!(matches!(
            s.readiness(),
            Readiness::Known { now: Events::NONE, later: Some(at) } if at == due
        ));
        assert!(s.accept().unwrap().is_none(), "not yet");
        clock.advance(after);
        assert!(matches!(
            s.readiness(),
            Readiness::Known {
                now: Events::IN,
                later: None
            }
        ));
        let accepted = s.accept().unwrap().expect("due now");
        assert_eq!(accepted.peer_addr().unwrap(), from);
        net.close(Sock::new(accepted, Closer::System));
        net.close(Sock::new(s, Closer::System));
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
        let nobody = net.open(&Remote::Inet(at(9)), SocketKind::Stream).unwrap();
        let err = nobody.connect(&Remote::Inet(at(9))).unwrap_err();
        let refused = Some(libc_errno::ECONNREFUSED);
        assert_eq!(err.raw_os_error(), refused, "no peer: refused at once");
        let unbound = SocketAddr::from(([0, 0, 0, 0], 0));
        assert_eq!(nobody.local_addr().unwrap(), unbound, "never bound");
        net.close(Sock::new(nobody, Closer::System));
        let a = net.open(&Remote::Inet(at(1)), SocketKind::Stream).unwrap();
        assert_eq!(a.local_addr().unwrap(), unbound, "bound as it connects");
        assert_eq!(
            a.connect(&Remote::Inet(at(1))).unwrap(),
            Connect::InProgress
        );
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
        let refused = net.open(&Remote::Inet(at), SocketKind::Stream).unwrap();
        assert!(refused.connect(&Remote::Inet(at)).is_err(), "no peer yet");
        net.close(Sock::new(refused, Closer::System));
        let mut net = net.with_peer(at, Peer::Accepts);
        let s = dial(&mut net, at);
        s.send(b"hi").unwrap();
        assert_eq!(talk.received(), b"hi");
        net.close(Sock::new(s, Closer::System));
    }

    /// An endless reply of lines repeats its line whole, across reads.
    #[test]
    fn an_endless_reply_repeats_its_line_across_reads() {
        let clock = crate::time::ManualClock::new().unwrap();
        let at = SocketAddr::from(([127, 0, 0, 1], 1));
        let talk = Conversation::new(b"", false)
            .per_send()
            .endless(Duration::ZERO)
            .endless_lines(b"ab\r\n");
        let mut net = FakeNet::new(clock)
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone());
        let s = dial(&mut net, at);
        s.send(b"hi").unwrap();
        let mut got = Vec::new();
        for room in [6, 5] {
            let mut buf = vec![0; room];
            let Ok(Recv::Data(n)) = s.recv(&mut buf) else {
                panic!("the endless reply reads");
            };
            got.extend_from_slice(&buf[..n.get()]);
        }
        assert_eq!(got, b"ab\r\nab\r\nab\r\n"[..11]);
        assert_eq!(talk.endless_reads(), 2);
        net.close(Sock::new(s, Closer::System));
    }

    /// The system's socket is set, and made nonblocking, through the
    /// library's view of it, as Linux's `/proc` shows.
    #[cfg(target_os = "linux")]
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
        let s = net.open(&Remote::Inet(at), SocketKind::Stream).unwrap();
        s.set(SocketOption::NoDelay).unwrap();
        s.set(SocketOption::KeepIdle(5)).unwrap();
        assert_eq!(
            net.socket_options(s.key()),
            [SocketOption::NoDelay, SocketOption::KeepIdle(5)]
        );
        net.close(Sock::new(s, Closer::System));
    }
}
