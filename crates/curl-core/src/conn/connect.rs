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
    /// The next attempt is to start.
    Resolved(Eyeballs),
    /// An attempt is connecting to an address.
    Racing(Eyeballs, Attempt),
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
    /// An attempt failed, and another address is left to try.
    Failed(Failure),
    /// Nothing until the socket is ready.
    Waiting,
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

    /// The socket of the attempt under way, if one is.
    pub(crate) fn socket(&self) -> Option<&dyn Socket> {
        match &self.stage {
            Stage::Resolving | Stage::Resolved(_) => None,
            Stage::Racing(_, a) => Some(&*a.socket),
        }
    }

    /// The addresses the name resolved to, once it has.
    pub(crate) fn answer(&self) -> Option<&Answer> {
        match &self.stage {
            Stage::Resolving => None,
            Stage::Resolved(e) | Stage::Racing(e, _) => Some(&e.answer),
        }
    }

    /// Move the setup on by one event.
    pub(crate) fn drive(self, net: &mut dyn Net, now: Instant) -> Result<Drove, ConnectError> {
        let ConnectMachine {
            number,
            peer,
            ip,
            created,
            stage,
        } = self;
        let next = |peer, stage, progress| {
            let m = ConnectMachine {
                number,
                peer,
                ip,
                created,
                stage,
            };
            Ok(Drove::Connecting(m, progress))
        };
        match stage {
            Stage::Resolving => {
                let answer = resolve(peer.shown())
                    .map_err(|OutOfMemory| ConnectError::OutOfMemory)?
                    .ok_or(ConnectError::Unresolved)?;
                let eyeballs = Eyeballs::new(answer, ip);
                if !eyeballs.more() {
                    return Err(ConnectError::Unresolved);
                }
                next(peer, Stage::Resolved(eyeballs), Progress::Resolved)
            }
            Stage::Resolved(mut eyeballs) => {
                let ip = eyeballs.next().expect("an address is left");
                let remote = SocketAddr::new(ip, peer.port());
                match net.connect(remote) {
                    Ok((socket, Connect::InProgress | Connect::Done)) => {
                        let stage = Stage::Racing(eyeballs, Attempt { remote, socket });
                        next(peer, stage, Progress::Trying(remote))
                    }
                    Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
                        Err(ConnectError::OutOfMemory)
                    }
                    Err(error) => {
                        let failure = Failure::Immediate { remote, error };
                        if eyeballs.more() {
                            next(peer, Stage::Resolved(eyeballs), Progress::Failed(failure))
                        } else {
                            Err(ConnectError::Failed(failure))
                        }
                    }
                }
            }
            Stage::Racing(eyeballs, a) => {
                // Writable once the connect is decided, either way
                // (`SOCKET_WRITABLE(sock, 0)`).
                let mut watch = [SocketPoll::new(&*a.socket, Events::OUT)];
                let polled = net
                    .poll(&mut watch, &mut [], std::time::Duration::ZERO)
                    .map(|_| !watch[0].revents().is_empty());
                let error = match polled {
                    Ok(false) => {
                        return next(peer, Stage::Racing(eyeballs, a), Progress::Waiting);
                    }
                    Ok(true) => match a.socket.take_error() {
                        Ok(None) => {
                            let local = a.socket.local_addr().ok();
                            return Ok(Drove::Established(Conn {
                                number,
                                route: Route::Tcp(peer, ip),
                                transport: Transport::Tcp(a.socket),
                                remote: Some(a.remote),
                                local,
                                created,
                                connected_at: now,
                                use_: Use::Leased(NonZeroU32::MIN),
                                rx: RecvBuf::default(),
                                served: false,
                                close: false,
                            }));
                        }
                        Ok(Some(error)) | Err(error) => error,
                    },
                    Err(error) => error,
                };
                let failure = a.fail(net, error)?;
                if eyeballs.more() {
                    next(peer, Stage::Resolved(eyeballs), Progress::Failed(failure))
                } else {
                    Err(ConnectError::Failed(failure))
                }
            }
        }
    }

    /// End the setup, closing what it has open.
    pub(crate) fn close(self, net: &mut dyn Net) {
        match self.stage {
            Stage::Resolving | Stage::Resolved(_) => {}
            Stage::Racing(_, a) => net.close(a.socket),
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
