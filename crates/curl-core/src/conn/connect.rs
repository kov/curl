//! Setting a connection up: the name resolved, then attempts raced to its
//! addresses until one connects (`lib/connect.c`, `cf-ip-happy.c`,
//! `cf-socket.c`).
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

use super::io::{Connect, Events, Net, Socket, SocketPoll};
use super::{Conn, ConnNumber, Peer, RecvBuf, Route, Transport, Use};
use crate::options::IpVersion;
use crate::time::Instant;

/// A connection being set up.
#[derive(Debug)]
pub(crate) struct ConnectMachine {
    number: ConnNumber,
    peer: TryRc<Peer>,
    ip: IpVersion,
    /// When the setup started (C's `conn->created`).
    created: Instant,
    stage: Stage,
}

#[derive(Debug)]
enum Stage {
    /// The destination's name is to be resolved.
    Resolving,
    /// Attempts are made to the addresses it resolved to.
    Racing(Racing),
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

/// The addresses a name stands for, in the order the resolver gave them
/// (C's `Curl_dns_entry`).
#[derive(Debug)]
pub(crate) enum Answer {
    /// The name was an address: nothing was resolved to report, or
    /// allocated.
    Literal([IpAddr; 1]),
    Resolved(Vec<IpAddr>),
}

impl Answer {
    pub(crate) fn addrs(&self) -> &[IpAddr] {
        match self {
            Answer::Literal(a) => a,
            Answer::Resolved(addrs) => addrs,
        }
    }

    /// Whether the name was resolved, rather than an address itself.
    pub(crate) fn resolved(&self) -> bool {
        matches!(self, Answer::Resolved(_))
    }
}

/// The attempts to make, over an answer (C's ballers): the families
/// alternate, IPv6 first, each in the answer's order.
#[derive(Debug)]
struct Eyeballs {
    answer: Answer,
    /// How many of each family's addresses were tried.
    v6: usize,
    v4: usize,
    last_v4: bool,
    /// The families attempts may use; both for an address the URL names.
    use_v6: bool,
    use_v4: bool,
}

impl Eyeballs {
    fn new(answer: Answer, ip: IpVersion) -> Eyeballs {
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
    Resolved,
    /// An attempt started on `0`.
    Trying(SocketAddr),
    /// An attempt failed, and the setup goes on.
    Failed(Failure),
    /// Nothing until a socket is ready, or until `until`, when the next
    /// attempt is due (`EXPIRE_HAPPY_EYEBALLS`).
    Waiting { until: Option<Instant> },
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
    /// The name has no address this build can find.
    Unresolved,
    /// The last attempt failed.
    Failed(Failure),
    /// Memory ran out: no failure of the peer's.
    OutOfMemory,
}

impl ConnectMachine {
    pub(crate) fn new(
        number: ConnNumber,
        peer: TryRc<Peer>,
        ip: IpVersion,
        created: Instant,
    ) -> ConnectMachine {
        ConnectMachine {
            number,
            peer,
            ip,
            created,
            stage: Stage::Resolving,
        }
    }

    pub(crate) fn number(&self) -> ConnNumber {
        self.number
    }

    /// The sockets of the attempts running.
    pub(crate) fn sockets(&self) -> impl Iterator<Item = &dyn Socket> {
        let running = match &self.stage {
            Stage::Resolving => &[][..],
            Stage::Racing(r) => &r.attempts[..],
        };
        running.iter().map(|a| &*a.socket)
    }

    /// The addresses the name resolved to, once it has.
    pub(crate) fn answer(&self) -> Option<&Answer> {
        match &self.stage {
            Stage::Resolving => None,
            Stage::Racing(r) => Some(&r.eyeballs.answer),
        }
    }

    /// Move the setup on by one event; `delay` is the happy eyeballs
    /// delay (`CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`).
    pub(crate) fn drive(
        mut self,
        net: &mut dyn Net,
        now: Instant,
        delay: Duration,
    ) -> Result<Drove, ConnectError> {
        let r = match &mut self.stage {
            Stage::Resolving => {
                let answer = resolve(self.peer.shown())
                    .map_err(|OutOfMemory| ConnectError::OutOfMemory)?
                    .ok_or(ConnectError::Unresolved)?;
                let eyeballs = Eyeballs::new(answer, self.ip);
                if !eyeballs.more() {
                    return Err(ConnectError::Unresolved);
                }
                self.stage = Stage::Racing(Racing {
                    eyeballs,
                    attempts: Vec::new(),
                    last_start: None,
                });
                return Ok(Drove::Connecting(self, Progress::Resolved));
            }
            Stage::Racing(r) => r,
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
                        return Ok(Drove::Established(self.established(won, now)));
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
            let remote = SocketAddr::new(ip, self.peer.port());
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

    /// The connection `won` set up, found connected at `now`.
    fn established(self, won: Attempt, now: Instant) -> Conn {
        let local = won.socket.local_addr().ok();
        Conn {
            number: self.number,
            route: Route::Tcp(self.peer, self.ip),
            transport: Transport::Tcp(won.socket),
            remote: Some(won.remote),
            local,
            created: self.created,
            connected_at: now,
            use_: Use::Leased(NonZeroU32::MIN),
            rx: RecvBuf::default(),
            served: false,
            close: false,
        }
    }

    /// End the setup, closing what it has open.
    pub(crate) fn close(self, net: &mut dyn Net) {
        match self.stage {
            Stage::Resolving => {}
            Stage::Racing(mut r) => r.close_all(net),
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
/// a resolver (`Curl_resolv`'s shortcuts): an address itself, or the
/// loopback addresses for `localhost` and the names under it (RFC 6761).
/// None for any other name, until a resolver lands.
fn resolve(host: &[u8]) -> Result<Option<Answer>, OutOfMemory> {
    if let Some(ip) = literal(host) {
        return Ok(Some(Answer::Literal([ip])));
    }
    if !is_localhost(host) {
        return Ok(None);
    }
    let mut addrs = Vec::new();
    addrs.try_push(IpAddr::V6(Ipv6Addr::LOCALHOST))?;
    addrs.try_push(IpAddr::V4(Ipv4Addr::LOCALHOST))?;
    Ok(Some(Answer::Resolved(addrs)))
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
    use crate::conn::Scheme;
    use crate::conn::io::{FakeNet, Peer as FakePeer};
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
        let mut m = ConnectMachine::new(ConnNumber(0), TryRc::try_new(peer).unwrap(), ip, start);
        m.stage = Stage::Racing(Racing {
            eyeballs: Eyeballs::new(Answer::Resolved(addrs), ip),
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
            match m.drive(&mut net, clock.now(), he) {
                Ok(Drove::Connecting(next, progress)) => {
                    m = next;
                    raced.most_running = raced.most_running.max(m.sockets().count());
                    match progress {
                        Progress::Trying(SocketAddr::V4(_)) => raced.v4_starts.push(ms),
                        Progress::Trying(SocketAddr::V6(_)) => raced.v6_starts.push(ms),
                        Progress::Failed(_) => {}
                        Progress::Waiting { .. } => clock.advance(Duration::from_millis(1)),
                        Progress::Resolved => unreachable!("resolved already"),
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
        let peer = TryRc::try_new(peer).unwrap();
        let mut m = ConnectMachine::new(ConnNumber(0), peer, IpVersion::Any, clock.now());
        let he = Duration::from_millis(200);
        let conn = loop {
            match m.drive(&mut net, clock.now(), he).unwrap() {
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
        let answer = resolve(b"localhost").unwrap().unwrap();
        let loopback = [
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ];
        assert_eq!((answer.addrs(), answer.resolved()), (&loopback[..], true));
        let answer = resolve(b"[::1]").unwrap().unwrap();
        assert_eq!((answer.addrs(), answer.resolved()), (&loopback[..1], false));
        assert!(resolve(b"example.com").unwrap().is_none());
    }

    /// Attempts alternate the families, IPv6 first, each family in the
    /// answer's order; `IpVersion` limits a name's, not an address's.
    #[test]
    fn eyeballs_alternate_the_families() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let addrs = ["1.1.1.1", "::1", "2.2.2.2", "3.3.3.3", "::2"].map(ip);
        let answer = || Answer::Resolved(addrs.to_vec());
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
        let literal = Answer::Literal([ip("1.1.1.1")]);
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
