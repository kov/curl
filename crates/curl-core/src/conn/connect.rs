//! Setting a connection up: the name resolved, then attempts raced to its
//! addresses until one connects (`lib/connect.c`, `cf-ip-happy.c`,
//! `cf-socket.c`), then, through a proxy that tunnels, the tunnel's
//! handshake over what connected (`cf-h1-proxy.c`).
//!
//! Each stage owns what the one before produced. A drive moves the machine
//! on by at most one event, which it returns for the transfer to trace:
//! the machine never reaches a transfer, so it can be driven while the
//! pool holding it is borrowed.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use std::num::NonZeroU32;

use curl_alloc::{OutOfMemory, TryRc, TryVec as _};

use super::dns::{Answer, DnsCache, Lookup};
use super::io::{Connect, Events, Family, Net, Recv, ResolveFailure, Sent, Socket, SocketPoll};
use super::{Conn, ConnNumber, RecvBuf, RecvFailed, Route, Tcp, Transport, Use};
use crate::options::IpVersion;
use crate::time::Instant;

/// A connection being set up.
#[derive(Debug)]
pub(crate) struct ConnectMachine {
    number: ConnNumber,
    route: Tcp,
    /// When the setup started (C's `conn->created`).
    created: Instant,
    stage: Stage,
    /// The setup was started over, for a proxy that closed the connection
    /// when asking for credentials (`retry_count`).
    redials: u8,
}

#[derive(Debug)]
enum Stage {
    /// The destination's name is to be resolved.
    Resolving,
    /// Attempts are made to the addresses it resolved to.
    Racing(Racing),
    /// Connected to the proxy, the tunnel's handshake is made.
    Tunnel(Dialed),
}

/// The most times a setup is started over (cf-setup.c's arbitrary 5).
const MAX_REDIALS: u8 = 5;

/// A connection to a proxy, over which a tunnel is being set up (the
/// chain below C's tunnel filter). The handshake's own bytes go through
/// it; what comes after them is kept for the tunnel's first reader.
#[derive(Debug)]
pub(crate) struct Dialed {
    remote: SocketAddr,
    socket: Box<dyn Socket>,
    connected_at: Instant,
    rx: RecvBuf,
}

impl Dialed {
    pub(crate) fn send(&self, bytes: &[u8]) -> io::Result<Sent> {
        self.socket.send(bytes)
    }

    /// Read up to `max` bytes behind what was received and not used.
    pub(crate) fn recv(&mut self, max: usize) -> Result<Recv, RecvFailed> {
        let room = self.rx.room(max).map_err(|_| RecvFailed::OutOfMemory)?;
        let got = self.socket.recv(room).map_err(RecvFailed::Os);
        let n = match got {
            Ok(Recv::Data(n)) => n.get(),
            Ok(Recv::Eof | Recv::WouldBlock) | Err(_) => 0,
        };
        self.rx.commit(max, n);
        got
    }

    /// What was received and not used.
    pub(crate) fn received(&self) -> &[u8] {
        self.rx.filled()
    }

    /// The first `n` bytes received were used.
    pub(crate) fn consume(&mut self, n: usize) {
        self.rx.consume(n);
    }
}

/// The most attempts running at once (`IP_HE_MAX_CONCURRENT_ATTEMPTS`).
const MAX_ATTEMPTS: usize = 6;

/// The attempts of a setup (C's `cf_ip_ballers`): each starts when the
/// one before has failed, or has run the happy eyeballs delay without
/// connecting, while an address is left.
#[derive(Debug)]
struct Racing {
    eyeballs: Eyeballs,
    /// The attempts running, oldest first.
    attempts: Vec<Attempt>,
    /// When the last attempt started.
    last_start: Option<Instant>,
}

/// What a drive needs beyond the network.
pub(crate) struct Setup<'a> {
    /// The answers kept from the setups before.
    pub(crate) dns: &'a mut DnsCache,
    /// A `*` entry answers for any name (C's `wildcard_resolve`).
    pub(crate) wildcard: bool,
    /// How long an answer is kept (`CURLOPT_DNS_CACHE_TIMEOUT`).
    pub(crate) max_age: Option<Duration>,
    /// The happy eyeballs delay (`CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`).
    pub(crate) delay: Duration,
}

/// Where a name's answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Found {
    /// Kept from a setup before.
    Cached,
    /// Resolved again: what was kept had gone stale.
    Stale,
    Resolved,
}

/// The attempts to make, over an answer (C's ballers): the families
/// alternate, IPv6 first, each in the answer's order.
#[derive(Debug)]
struct Eyeballs {
    answer: TryRc<Answer>,
    /// How many of each family's addresses were tried.
    v6: usize,
    v4: usize,
    last_v4: bool,
    /// The families attempts may use; both for an address the URL names.
    use_v6: bool,
    use_v4: bool,
}

impl Eyeballs {
    fn new(answer: TryRc<Answer>, ip: IpVersion) -> Eyeballs {
        let any = !answer.resolved() || ip == IpVersion::Any;
        Eyeballs {
            answer,
            v6: 0,
            v4: 0,
            last_v4: true,
            use_v6: any || ip == IpVersion::V6,
            use_v4: any || ip == IpVersion::V4,
        }
    }

    /// The `n`th address of IPv6 if `v6`, else of IPv4.
    fn nth(&self, v6: bool, n: usize) -> Option<IpAddr> {
        let usable = if v6 { self.use_v6 } else { self.use_v4 };
        let of = |a: &&IpAddr| a.is_ipv6() == v6;
        self.answer
            .addrs()
            .iter()
            .filter(of)
            .nth(n)
            .filter(|_| usable)
            .copied()
    }

    /// The address to try next, if one is left (`cf_ip_ballers_run`).
    fn next(&mut self) -> Option<IpAddr> {
        if (self.last_v4 || self.nth(false, self.v4).is_none())
            && let Some(a) = self.nth(true, self.v6)
        {
            self.v6 += 1;
            self.last_v4 = false;
            return Some(a);
        }
        let a = self.nth(false, self.v4)?;
        self.v4 += 1;
        self.last_v4 = true;
        Some(a)
    }

    /// Whether an address is left to try.
    fn more(&self) -> bool {
        self.nth(true, self.v6).is_some() || self.nth(false, self.v4).is_some()
    }
}

/// A socket connecting to one address.
#[derive(Debug)]
struct Attempt {
    remote: SocketAddr,
    socket: Box<dyn Socket>,
}

/// What a drive did.
#[derive(Debug)]
pub(crate) enum Drove {
    /// Still setting up: drive it again when `wants` comes.
    Connecting(ConnectMachine, Progress),
    /// The connection is up.
    Established(Conn),
}

/// Something a setup said, or nothing new.
#[derive(Debug)]
pub(crate) enum Progress {
    /// The name resolved: its answer is the machine's.
    Resolved(Found),
    /// An attempt started on `0`.
    Trying(SocketAddr),
    /// An attempt failed, and the setup goes on.
    Failed(Failure),
    /// Nothing until a socket is ready, or until `until`, when the next
    /// attempt is due (`EXPIRE_HAPPY_EYEBALLS`).
    Waiting { until: Option<Instant> },
    /// Connected to a proxy, through which a tunnel is to be made: its
    /// handshake goes over `Pool::dialed`.
    Dialed,
}

/// How an attempt failed.
#[derive(Debug)]
pub(crate) enum Failure {
    /// Connecting to `remote` failed at once, before any socket was
    /// polled.
    Immediate {
        remote: SocketAddr,
        error: io::Error,
    },
    /// The attempt to `remote` from `local` failed.
    Attempt {
        remote: SocketAddr,
        local: Option<SocketAddr>,
        error: io::Error,
    },
}

/// Why a setup failed; any socket it had is closed.
#[derive(Debug)]
pub(crate) enum ConnectError {
    /// The name has no address to try.
    Unresolved(Unresolved),
    /// The last attempt failed.
    Failed(Failure),
    /// Memory ran out: no failure of the peer's.
    OutOfMemory,
}

/// Why a name has no address to try.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unresolved {
    /// The resolver said so now.
    Resolver(ResolveFailure),
    /// It said so before, and the cache kept its word.
    Negative,
    /// None of the addresses found is of the family allowed.
    NoAddress,
}

impl ConnectMachine {
    pub(crate) fn new(number: ConnNumber, route: Tcp, created: Instant) -> ConnectMachine {
        ConnectMachine {
            number,
            route,
            created,
            stage: Stage::Resolving,
            redials: 0,
        }
    }

    pub(crate) fn number(&self) -> ConnNumber {
        self.number
    }

    pub(crate) fn route(&self) -> &Tcp {
        &self.route
    }

    /// The sockets of the attempts running.
    pub(crate) fn sockets(&self) -> impl Iterator<Item = &dyn Socket> {
        let (running, dialed) = match &self.stage {
            Stage::Resolving => (&[][..], None),
            Stage::Racing(r) => (&r.attempts[..], None),
            Stage::Tunnel(d) => (&[][..], Some(&*d.socket)),
        };
        running.iter().map(|a| &*a.socket).chain(dialed)
    }

    /// The addresses the name resolved to, once it has.
    pub(crate) fn answer(&self) -> Option<&TryRc<Answer>> {
        match &self.stage {
            Stage::Resolving | Stage::Tunnel(_) => None,
            Stage::Racing(r) => Some(&r.eyeballs.answer),
        }
    }

    /// The connection to the proxy, while the tunnel is set up.
    pub(crate) fn dialed(&mut self) -> &mut Dialed {
        match &mut self.stage {
            Stage::Tunnel(d) => d,
            Stage::Resolving | Stage::Racing(_) => panic!("no tunnel is set up"),
        }
    }

    /// The tunnel is up: the connection is.
    pub(crate) fn tunneled(self) -> Conn {
        let Stage::Tunnel(d) = self.stage else {
            panic!("no tunnel is set up");
        };
        let at = d.connected_at;
        Self::conn(
            self.number,
            self.route,
            self.created,
            d.socket,
            d.remote,
            at,
            d.rx,
        )
    }

    /// The proxy closed the connection as it asked for credentials: the
    /// setup starts over, from resolving its name (`cf_setup_connect`).
    /// False, and nothing done, if it was started over too often.
    pub(crate) fn redial(&mut self, net: &mut dyn Net) -> bool {
        if self.redials >= MAX_REDIALS {
            return false;
        }
        self.redials += 1;
        if let Stage::Tunnel(d) = std::mem::replace(&mut self.stage, Stage::Resolving) {
            net.close(d.socket);
        }
        true
    }

    /// Move the setup on by one event.
    pub(crate) fn drive(
        mut self,
        net: &mut dyn Net,
        now: Instant,
        setup: Setup<'_>,
    ) -> Result<Drove, ConnectError> {
        let delay = setup.delay;
        let r = match &mut self.stage {
            Stage::Resolving => {
                let (answer, found) = self.resolve(net, setup, now)?;
                let eyeballs = Eyeballs::new(answer, self.route.ip);
                if !eyeballs.more() {
                    return Err(ConnectError::Unresolved(Unresolved::NoAddress));
                }
                self.stage = Stage::Racing(Racing {
                    eyeballs,
                    attempts: Vec::new(),
                    last_start: None,
                });
                return Ok(Drove::Connecting(self, Progress::Resolved(found)));
            }
            Stage::Racing(r) => r,
            Stage::Tunnel(_) => unreachable!("a tunnel is driven by its handshake"),
        };
        // A running attempt that connected wins; one that failed is
        // dropped (`cf_ip_ballers_run`).
        for i in 0..r.attempts.len() {
            let a = &r.attempts[i];
            // Writable once the connect is decided, either way
            // (`SOCKET_WRITABLE(sock, 0)`).
            let mut watch = [SocketPoll::new(&*a.socket, Events::OUT)];
            let error = match net.poll(&mut watch, &mut [], Duration::ZERO) {
                Ok(_) if watch[0].revents().is_empty() => continue,
                Ok(_) => match a.socket.take_error() {
                    Ok(None) => {
                        let won = r.attempts.remove(i);
                        r.close_all(net);
                        if self.route.tunnels() {
                            // The connection is the proxy's; the tunnel
                            // through it is still to be made.
                            self.stage = Stage::Tunnel(Dialed {
                                remote: won.remote,
                                socket: won.socket,
                                connected_at: now,
                                rx: RecvBuf::default(),
                            });
                            return Ok(Drove::Connecting(self, Progress::Dialed));
                        }
                        let rx = RecvBuf::default();
                        let (number, route, created) = (self.number, self.route, self.created);
                        let conn =
                            Self::conn(number, route, created, won.socket, won.remote, now, rx);
                        return Ok(Drove::Established(conn));
                    }
                    Ok(Some(error)) | Err(error) => error,
                },
                Err(error) => error,
            };
            let failure = r.attempts.remove(i).fail(net, error)?;
            return r.failed(failure).map(|p| Drove::Connecting(self, p));
        }
        let due = r.last_start.is_none_or(|at| now >= at.after(delay)) || r.attempts.is_empty();
        if due && r.eyeballs.more() {
            if r.attempts.len() == MAX_ATTEMPTS {
                // The oldest makes room (`cf_ip_ballers_prune`).
                let oldest = r.attempts.remove(0);
                net.close(oldest.socket);
            }
            if r.attempts.try_reserve(1).is_err() {
                return Err(ConnectError::OutOfMemory);
            }
            let ip = r.eyeballs.next().expect("an address is left");
            let remote = SocketAddr::new(ip, self.route.destination().port());
            r.last_start = Some(now);
            return match net.connect(remote) {
                Ok((socket, Connect::InProgress | Connect::Done)) => {
                    r.attempts
                        .try_push(Attempt { remote, socket })
                        .expect("reserved");
                    Ok(Drove::Connecting(self, Progress::Trying(remote)))
                }
                Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
                    Err(ConnectError::OutOfMemory)
                }
                Err(error) => {
                    let failure = Failure::Immediate { remote, error };
                    r.failed(failure).map(|p| Drove::Connecting(self, p))
                }
            };
        }
        let until = r
            .last_start
            .filter(|_| r.eyeballs.more())
            .map(|at| at.after(delay));
        Ok(Drove::Connecting(self, Progress::Waiting { until }))
    }

    /// The peer's answer (`hostip_resolv`): what the cache keeps, or what
    /// the name stands for without asking a resolver, or what the system's
    /// resolver finds, then kept. That the name does not exist is kept
    /// too; that the resolver could not tell is not.
    fn resolve(
        &self,
        net: &mut dyn Net,
        setup: Setup<'_>,
        now: Instant,
    ) -> Result<(TryRc<Answer>, Found), ConnectError> {
        let peer = self.route.destination();
        let (name, port) = (peer.name(), peer.port());
        let family = match self.route.ip {
            IpVersion::Any => Family::Any,
            IpVersion::V4 => Family::V4,
            IpVersion::V6 => Family::V6,
        };
        let found = match setup
            .dns
            .lookup((name, port), family, setup.wildcard, setup.max_age, now)
        {
            Lookup::Found(answer) => return Ok((answer, Found::Cached)),
            Lookup::Negative => return Err(ConnectError::Unresolved(Unresolved::Negative)),
            Lookup::Stale => Found::Stale,
            Lookup::Missing => Found::Resolved,
        };
        let oom = |OutOfMemory| ConnectError::OutOfMemory;
        let answer = match shortcut(peer.shown(), name).map_err(oom)? {
            Some(answer) => answer,
            None => match net.resolve(name, family) {
                Ok(addrs) => Answer::of(name, addrs, family).map_err(oom)?,
                Err(ResolveFailure::OutOfMemory) => return Err(ConnectError::OutOfMemory),
                Err(why @ (ResolveFailure::NotFound | ResolveFailure::NoData)) => {
                    let none = Answer::of(name, Vec::new(), family).map_err(oom)?;
                    let none = TryRc::try_new(none).map_err(oom)?;
                    setup.dns.put(none, port, now, false).map_err(oom)?;
                    return Err(ConnectError::Unresolved(Unresolved::Resolver(why)));
                }
                Err(why) => return Err(ConnectError::Unresolved(Unresolved::Resolver(why))),
            },
        };
        let answer = TryRc::try_new(answer).map_err(oom)?;
        setup
            .dns
            .put(answer.clone(), port, now, false)
            .map_err(oom)?;
        Ok((answer, found))
    }

    /// The connection set up over `socket` to `remote`, found connected
    /// at `at`, with what was received over it and not used.
    fn conn(
        number: ConnNumber,
        route: Tcp,
        created: Instant,
        socket: Box<dyn Socket>,
        remote: SocketAddr,
        at: Instant,
        rx: RecvBuf,
    ) -> Conn {
        let local = socket.local_addr().ok();
        Conn {
            number,
            route: Route::Tcp(route),
            transport: Transport::Tcp(socket),
            remote: Some(remote),
            local,
            created,
            connected_at: at,
            use_: Use::Leased(NonZeroU32::MIN),
            rx,
            served: false,
            seen_version: None,
            close: false,
        }
    }

    /// End the setup, closing what it has open.
    pub(crate) fn close(self, net: &mut dyn Net) {
        match self.stage {
            Stage::Resolving => {}
            Stage::Racing(mut r) => r.close_all(net),
            Stage::Tunnel(d) => net.close(d.socket),
        }
    }
}

impl Racing {
    fn close_all(&mut self, net: &mut dyn Net) {
        for a in self.attempts.drain(..) {
            net.close(a.socket);
        }
    }

    /// An attempt failed: the setup goes on while an attempt runs or an
    /// address is left, and fails with it otherwise.
    fn failed(&self, failure: Failure) -> Result<Progress, ConnectError> {
        if !self.attempts.is_empty() || self.eyeballs.more() {
            Ok(Progress::Failed(failure))
        } else {
            Err(ConnectError::Failed(failure))
        }
    }
}

impl Attempt {
    /// The attempt failed with `error`: its socket is closed, its local
    /// address read first, as C reads it for the trace.
    fn fail(self, net: &mut dyn Net, error: io::Error) -> Result<Failure, ConnectError> {
        let local = self.socket.local_addr().ok();
        net.close(self.socket);
        if error.kind() == io::ErrorKind::OutOfMemory {
            return Err(ConnectError::OutOfMemory);
        }
        Ok(Failure::Attempt {
            remote: self.remote,
            local,
            error,
        })
    }
}

/// The addresses `host`, as the URL names it, stands for without asking
/// a resolver (`hostip_resolv_start`'s shortcuts): an address itself, or
/// the loopback addresses for `localhost` and the names under it (RFC
/// 6761). None for any other name, which a resolver must find. The answer
/// is for `name`, the host without brackets.
fn shortcut(host: &[u8], name: &[u8]) -> Result<Option<Answer>, OutOfMemory> {
    let mut addrs = Vec::new();
    if let Some(ip) = literal(host) {
        addrs.try_push(ip)?;
    } else if is_localhost(host) {
        addrs.try_push(IpAddr::V6(Ipv6Addr::LOCALHOST))?;
        addrs.try_push(IpAddr::V4(Ipv4Addr::LOCALHOST))?;
    } else {
        return Ok(None);
    }
    Answer::new(name, addrs).map(Some)
}

/// `localhost`, or a name under it, with or without the root's dot, in
/// any case.
fn is_localhost(host: &[u8]) -> bool {
    let host = host.strip_suffix(b".").unwrap_or(host);
    let tail = b".localhost";
    host.eq_ignore_ascii_case(b"localhost")
        || (host.len() > tail.len() && host[host.len() - tail.len()..].eq_ignore_ascii_case(tail))
}

/// `host` as an address if it is one, as the URL holds it: an IPv4
/// address dotted, an IPv6 one in brackets.
fn literal(host: &[u8]) -> Option<IpAddr> {
    let text = std::str::from_utf8(host).ok()?;
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        return inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    text.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::io::{FakeNet, Peer as FakePeer};
    use crate::conn::{Peer, Scheme};
    use crate::options::IpVersion;
    use crate::time::{Clock as _, ManualClock};

    /// What a race did, in milliseconds from its start.
    #[derive(Debug, PartialEq, Eq)]
    struct Raced {
        v4_starts: Vec<u64>,
        v6_starts: Vec<u64>,
        most_running: usize,
        failed_at: u64,
    }

    /// Race a name that resolved to `addrs`, each refusing `fail_ms`
    /// after its attempt starts, with a happy eyeballs delay of `he_ms`;
    /// the clock moves a millisecond whenever the setup waits.
    fn race(addrs: &[&str], ip: IpVersion, he_ms: u64, fail_ms: u64) -> Raced {
        let clock = ManualClock::new().unwrap();
        let start = clock.now();
        let addrs: Vec<IpAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
        let mut net = FakeNet::new(clock.clone());
        for &a in &addrs {
            let peer = FakePeer::RefusesAfter(Duration::from_millis(fail_ms));
            net = net.with_peer(SocketAddr::new(a, 123), peer);
        }
        let scheme = Scheme {
            name: "http",
            reuse: true,
        };
        let peer = Peer::new(scheme, b"abc.test".to_vec(), 123, None);
        let route = Tcp {
            origin: TryRc::try_new(peer).unwrap(),
            via: None,
            ip,
            proxy: None,
        };
        let mut m = ConnectMachine::new(ConnNumber(0), route, start);
        m.stage = Stage::Racing(Racing {
            eyeballs: Eyeballs::new(
                TryRc::try_new(Answer::new(b"abc.test", addrs).unwrap()).unwrap(),
                ip,
            ),
            attempts: Vec::new(),
            last_start: None,
        });
        let mut raced = Raced {
            v4_starts: Vec::new(),
            v6_starts: Vec::new(),
            most_running: 0,
            failed_at: 0,
        };
        let he = Duration::from_millis(he_ms);
        for _ in 0..5000 {
            let ms = u64::try_from(clock.now().since(start).as_millis()).unwrap();
            let setup = Setup {
                dns: &mut DnsCache::default(),
                wildcard: false,
                max_age: Some(Duration::from_secs(60)),
                delay: he,
            };
            match m.drive(&mut net, clock.now(), setup) {
                Ok(Drove::Connecting(next, progress)) => {
                    m = next;
                    raced.most_running = raced.most_running.max(m.sockets().count());
                    match progress {
                        Progress::Trying(SocketAddr::V4(_)) => raced.v4_starts.push(ms),
                        Progress::Trying(SocketAddr::V6(_)) => raced.v6_starts.push(ms),
                        Progress::Failed(_) => {}
                        Progress::Waiting { .. } => clock.advance(Duration::from_millis(1)),
                        Progress::Resolved(_) => unreachable!("resolved already"),
                        Progress::Dialed => unreachable!("no proxy"),
                    }
                }
                Ok(Drove::Established(conn)) => panic!("{conn:?}"),
                Err(ConnectError::Failed(_)) => {
                    raced.failed_at = ms;
                    assert_eq!(net.open_sockets(), 0, "every attempt closed");
                    return raced;
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        panic!("no end: {raced:?}");
    }

    /// The attempt that connects wins, and the others are closed.
    #[test]
    fn the_winner_closes_the_other_attempts() {
        let clock = ManualClock::new().unwrap();
        let (silent, up) = ("[::1]:5".parse().unwrap(), "127.0.0.1:5".parse().unwrap());
        let mut net = FakeNet::new(clock.clone())
            .with_peer(silent, FakePeer::Silent)
            .with_peer(up, FakePeer::AcceptsAfter(Duration::from_millis(10)));
        let scheme = Scheme {
            name: "http",
            reuse: true,
        };
        let peer = Peer::new(scheme, b"localhost".to_vec(), 5, None);
        let route = Tcp {
            origin: TryRc::try_new(peer).unwrap(),
            via: None,
            ip: IpVersion::Any,
            proxy: None,
        };
        let mut m = ConnectMachine::new(ConnNumber(0), route, clock.now());
        let he = Duration::from_millis(200);
        let mut dns = DnsCache::default();
        let conn = loop {
            let setup = Setup {
                dns: &mut dns,
                wildcard: false,
                max_age: Some(Duration::from_secs(60)),
                delay: he,
            };
            match m.drive(&mut net, clock.now(), setup).unwrap() {
                Drove::Connecting(next, progress) => {
                    m = next;
                    if let Progress::Waiting { .. } = progress {
                        clock.advance(Duration::from_millis(1));
                    }
                }
                Drove::Established(conn) => break conn,
            }
        };
        assert_eq!(conn.remote, Some(up));
        assert_eq!(net.open_sockets(), 1, "the winner's alone");
        let Transport::Tcp(socket) = conn.transport else {
            panic!("over the network");
        };
        net.close(socket);
    }

    /// Unit 2600's cases: how many attempts of each family start, and
    /// when, how many run at once, and when the setup fails. The next
    /// attempt starts once the delay has passed since the last one
    /// started, or once none runs; six run at most, the oldest making
    /// room.
    #[test]
    fn attempts_race_as_unit_2600_has_them() {
        use IpVersion::{Any, V4, V6};
        let raced = |v4: &[u64], v6: &[u64], most_running, failed_at| Raced {
            v4_starts: v4.to_vec(),
            v6_starts: v6.to_vec(),
            most_running,
            failed_at,
        };
        // 1 and 2: IPv4 alone; the second starts on the delay.
        assert_eq!(
            race(&["192.0.2.1"], Any, 150, 250),
            raced(&[0], &[], 1, 250)
        );
        let two = ["192.0.2.1", "192.0.2.2"];
        assert_eq!(race(&two, Any, 150, 250), raced(&[0, 150], &[], 2, 400));
        // 3 and 4: IPv6 alone.
        assert_eq!(race(&["::1"], Any, 150, 250), raced(&[], &[0], 1, 250));
        assert_eq!(
            race(&["::1", "::2"], Any, 150, 250),
            raced(&[], &[0, 150], 2, 400)
        );
        // 5 and 6: IPv6 first, whatever the order; IPv4 on the delay.
        let mixed = raced(&[150], &[0], 2, 400);
        assert_eq!(race(&["192.0.2.1", "::1"], Any, 150, 250), mixed);
        assert_eq!(race(&["::1", "192.0.2.1"], Any, 150, 250), mixed);
        // 7 and 8: one family only, over its whole time.
        assert_eq!(
            race(&["192.0.2.1", "::1"], V4, 150, 500),
            raced(&[0], &[], 1, 500)
        );
        assert_eq!(
            race(&["::1", "192.0.2.1"], V6, 150, 500),
            raced(&[], &[0], 1, 500)
        );
        // 9: the families alternate while both have addresses.
        let four = ["::1", "192.0.2.1", "::2", "::3"];
        assert_eq!(
            race(&four, Any, 50, 400),
            raced(&[50], &[0, 100, 150], 4, 550)
        );
        // 10: six at most, the oldest discarded for the seventh.
        let nine = [
            "::1",
            "192.0.2.1",
            "::2",
            "::3",
            "::4",
            "::5",
            "::6",
            "::7",
            "::8",
        ];
        let v6 = [0, 40, 60, 80, 100, 120, 140, 160];
        assert_eq!(race(&nine, Any, 20, 500), raced(&[20], &v6, 6, 660));
    }

    /// The names C answers itself: `localhost` and the names under it.
    #[test]
    fn localhost_names_are_loopback() {
        for name in [
            &b"localhost"[..],
            b"LocalHost.",
            b"a.localhost",
            b"A.B.LOCALHOST.",
        ] {
            assert!(is_localhost(name), "{name:?}");
        }
        for name in [
            &b"localhost.."[..],
            b".localhost",
            b"xlocalhost",
            b"localhost.com",
        ] {
            assert!(!is_localhost(name), "{name:?}");
        }
        let answer = shortcut(b"localhost", b"localhost").unwrap().unwrap();
        let loopback = [
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ];
        assert_eq!((answer.addrs(), answer.resolved()), (&loopback[..], true));
        let answer = shortcut(b"[::1]", b"::1").unwrap().unwrap();
        assert_eq!((answer.addrs(), answer.resolved()), (&loopback[..1], false));
        assert_eq!(answer.name(), b"::1");
        assert!(shortcut(b"example.com", b"example.com").unwrap().is_none());
    }

    /// Attempts alternate the families, IPv6 first, each family in the
    /// answer's order; `IpVersion` limits a name's, not an address's.
    #[test]
    fn eyeballs_alternate_the_families() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let addrs = ["1.1.1.1", "::1", "2.2.2.2", "3.3.3.3", "::2"].map(ip);
        let answer = || TryRc::try_new(Answer::new(b"a.test", addrs.to_vec()).unwrap()).unwrap();
        let order = |mut e: Eyeballs| std::iter::from_fn(move || e.next()).collect::<Vec<_>>();
        let all = ["::1", "1.1.1.1", "::2", "2.2.2.2", "3.3.3.3"].map(ip);
        assert_eq!(order(Eyeballs::new(answer(), IpVersion::Any)), all);
        assert_eq!(
            order(Eyeballs::new(answer(), IpVersion::V4)),
            ["1.1.1.1", "2.2.2.2", "3.3.3.3"].map(ip)
        );
        assert_eq!(
            order(Eyeballs::new(answer(), IpVersion::V6)),
            ["::1", "::2"].map(ip)
        );
        let literal =
            TryRc::try_new(Answer::new(b"1.1.1.1", vec![ip("1.1.1.1")]).unwrap()).unwrap();
        assert_eq!(
            order(Eyeballs::new(literal, IpVersion::V6)),
            [ip("1.1.1.1")]
        );
        let mut e = Eyeballs::new(answer(), IpVersion::V6);
        assert!(e.more());
        e.next();
        e.next();
        assert!(!e.more());
    }

    #[test]
    fn literals_are_addresses() {
        assert_eq!(literal(b"127.0.0.1"), Some(IpAddr::from([127, 0, 0, 1])));
        assert_eq!(literal(b"[::1]"), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(literal(b"::1"), None, "the URL keeps the brackets");
        assert_eq!(literal(b"[127.0.0.1]"), None);
        assert_eq!(literal(b"example.com"), None);
        assert_eq!(literal(b"localhost"), None);
    }
}
