//! Setting a connection up: the name resolved, then attempts raced to its
//! addresses until one connects (`lib/connect.c`, `cf-ip-happy.c`,
//! `cf-socket.c`), then the handshakes the route and the transfer ask for
//! over what connected (SOCKS's, an HTTP proxy's tunnel, the PROXY
//! protocol's line), which the transfer makes.
//!
//! Each stage owns what the one before produced. A drive moves the machine
//! on by at most one event, tracing its attempts as C's filters do and
//! returning the event for the transfer, through a context (`ConnCx`)
//! that reaches the network, the names kept and the transfer's trace,
//! never the pool: the machine is driven in its lease.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use std::num::NonZeroU32;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};

use super::bind::{BindFailed, bind_local};
use super::chain::SetupPoint;
#[cfg(test)]
use super::dns::DnsCache;
use super::dns::{Answer, Lookup, Names};
use super::io::{
    Closer, Connect, Events, Family, Net, Queued, Remote, Resolve, ResolveFailure, ResolveId, Sock,
    Socket, SocketKind, SocketOption, SocketPoll, UnixPeer, Waiter,
};
#[cfg(test)]
use super::layer::LayerCx;
use super::layer::{LayerAnswer, LayerQuery};
use super::quic::{Quic, QuicCx};
use super::shutdown::ConnSettings;
use super::{Conn, ConnNumber, Peer, Route, Stream, Tcp, Transport, Use};
use crate::components::Component;
use crate::error::ErrorKind;
use crate::handler::Configured;
use crate::options::{IpVersion, KeepAlive, Sockets};
use crate::time::Instant;
use crate::trace::{Ip, OsError};

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
    /// What closes each socket it opens: the creating transfer's.
    closer: Closer,
    /// What the connection keeps of the creating transfer's settings.
    settings: ConnSettings,
}

#[derive(Debug)]
enum Stage {
    /// The destination's name is to be resolved, or its resolve waits
    /// for the resolver's answer.
    Resolving(Option<Pending>),
    /// Attempts are made to the addresses it resolved to.
    Racing(Racing),
    /// Connected to the first hop, the handshakes over it are made.
    Dialed(Dialed),
}

/// The most times a setup is started over (cf-setup.c's arbitrary 5).
const MAX_REDIALS: u8 = 5;

/// A connection to its first hop, over which its handshakes are being
/// made (the chain below C's SOCKS, tunnel and HAPROXY filters). The
/// handshakes' own bytes go through its stream; what comes after them is
/// kept for the connection's first reader.
#[derive(Debug)]
pub(crate) struct Dialed {
    remote: Remote,
    stream: Stream,
    connected_at: Instant,
    /// The addresses raced to reach the proxy, raced again on a redial.
    answer: Addresses,
    /// The destination's addresses, for a SOCKS proxy that is not to
    /// resolve its name, and where they came from; or that there are none.
    target: Option<Result<(TryArc<Answer>, Came), ()>>,
    /// A SOCKS5 proxy on the way authenticated the user.
    socks5_authenticated: bool,
    /// The handshakes made over it so far.
    made: Made,
    /// The PROXY protocol's line is to be sent over it, decided once the
    /// proxies' handshakes are made, as C reads the option once as its
    /// setup reaches that stage (`cf_setup_add_haproxy`); `None` before.
    preface: Option<bool>,
    /// The QUIC connection to an HTTP/3 proxy, its handshake done, until
    /// the tunnel's `CONNECT` takes it over.
    quic: Option<Box<Quic>>,
}

/// The handshakes made over a dialed connection, each once, in
/// cf-setup.c's order: SOCKS's and the tunnel's stay in C's chain as
/// filters that pass the bytes (`[H1-PROXY][SOCKS][TCP]`); the PROXY
/// line's filter goes once the chain is connected; the origin's TLS stays
/// as the layer on top (`[SSL][TCP]`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Made(u8);

impl Made {
    pub(crate) const SOCKS: Made = Made(1);
    pub(crate) const TUNNEL: Made = Made(2);
    pub(crate) const PREFACE: Made = Made(4);
    pub(crate) const TLS: Made = Made(8);
    /// An HTTPS proxy's TLS, which stays as a layer below what follows
    /// (`[SSL-PROXY][TCP]`).
    pub(crate) const PROXY_TLS: Made = Made(16);
    /// The tunnel is a stream of an HTTP/2 session with the proxy
    /// (`[H2-PROXY]`), made with `TUNNEL`.
    pub(crate) const H2_TUNNEL: Made = Made(32);
    /// The tunnel is a stream of a QUIC connection to an HTTP/3 proxy
    /// (`[H3-PROXY]`), made with `TUNNEL`.
    pub(crate) const H3_TUNNEL: Made = Made(64);
    /// The origin's QUIC connection through a CONNECT-UDP tunnel
    /// (`[HTTP/3][CAPSULE]`), in place of its TLS.
    pub(crate) const QUIC: Made = Made(128);

    pub(crate) fn has(self, which: Made) -> bool {
        self.0 & which.0 != 0
    }
}

impl std::ops::BitOr for Made {
    type Output = Made;

    fn bitor(self, other: Made) -> Made {
        Made(self.0 | other.0)
    }
}

impl Dialed {
    /// The handshakes made over it so far.
    pub(crate) fn made(&self) -> Made {
        self.made
    }

    /// The handshake `which` is made.
    pub(crate) fn mark_made(&mut self, which: Made) {
        self.made.0 |= which.0;
    }

    /// A SOCKS5 proxy on the way authenticated the user, which the
    /// connection keeps (`bits.socks5_authenticated`).
    pub(crate) fn socks5_authenticated(&mut self) {
        self.socks5_authenticated = true;
    }

    /// The connection to the proxy, which the handshake's bytes go over.
    pub(crate) fn stream(&mut self) -> &mut Stream {
        &mut self.stream
    }

    /// The addresses of the destination, resolved here.
    pub(crate) fn target(&self) -> Option<&Result<(TryArc<Answer>, Came), ()>> {
        self.target.as_ref()
    }

    /// The QUIC connection to an HTTP/3 proxy, for the tunnel's
    /// `CONNECT` to take; or the origin's, made through a CONNECT-UDP
    /// tunnel, for the connection's session.
    pub(crate) fn take_quic(&mut self) -> Option<Box<Quic>> {
        self.quic.take()
    }

    /// The origin's QUIC connection, its handshake made through the
    /// tunnel, held for the connection it is the session of.
    pub(crate) fn put_quic(&mut self, quic: Box<Quic>) {
        assert!(self.quic.is_none(), "one QUIC connection is held");
        self.quic = Some(quic);
    }

    /// The proxy's address, and the connection's end here.
    pub(crate) fn ends(&self) -> (Remote, Option<SocketAddr>) {
        (self.remote.clone(), self.stream.local_addr())
    }
}

/// The most attempts running at once (`IP_HE_MAX_CONCURRENT_ATTEMPTS`).
pub(crate) const MAX_ATTEMPTS: usize = 6;

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

/// What a drive reaches while it works, as C's connection filters reach
/// the transfer they connect for: the time and the transfer's trace
/// (`LayerCx`), the network, and the names kept. A transfer's step
/// gives one over its own context (`DriveCx`); it is an argument, never
/// stored.
pub(crate) trait ConnCx: QuicCx {
    fn net(&mut self) -> &mut dyn Net;

    /// What a QUIC attempt is made with, if the transfer has an HTTP/3
    /// library.
    fn quic_making(&mut self) -> Result<Option<QuicMaking>, OutOfMemory>;

    /// The answers kept from the setups before: the multi's, or its
    /// share's.
    fn names(&mut self) -> Names<'_>;

    /// IPv6 works here, as the multi's probe found (`ipv6works`).
    fn ipv6_works(&self) -> bool;

    /// Every resolve of IPv6 addresses alone fails, as the debug build's
    /// `CURL_DBG_RESOLV_FAIL_IPV6` asks.
    fn fails_ipv6_resolves(&self) -> bool;

    /// The transfer the setup's resolves are for, which the multi runs
    /// again when one is answered.
    fn waiter(&self) -> Waiter;

    /// A socket for `address`: the application's opener's, which may
    /// change the address, or else the network's (`socket_open`).
    fn open_socket(&mut self, address: &mut Remote, kind: SocketKind) -> Opened;

    /// The socket set by the application's configurer, if it has one,
    /// before it connects.
    fn configure_socket(&mut self, socket: &dyn Socket) -> Configured;

    /// Why the transfer fails, kept if nothing said so before (`failf`).
    fn fail(&mut self, reason: std::fmt::Arguments<'_>);

    /// Let go of the reason kept, as the race starts an attempt or ends
    /// (`Curl_reset_fail`): what an attempt said is not why the transfer
    /// fails.
    fn reset_fail(&mut self);

    /// Tell the application a resolve starts, if it asked to hear of
    /// it: it may stop it (`Curl_resolv_announce_start`).
    fn announce_resolve(&mut self) -> Result<(), ConnectError>;
}

/// What a QUIC attempt is made with: the transfer's libraries, what its
/// TLS library keeps across the multi's connections, and how long the
/// handshake may take (`quic_settings`).
pub(crate) struct QuicMaking {
    pub(crate) libraries: crate::libraries::SharedLibraries,
    pub(crate) shared: crate::tls::TlsShared,
    pub(crate) handshake_timeout: Duration,
    /// The multi's clock, which the connection keeps.
    pub(crate) clock: crate::time::SharedClock,
    /// The transfer makes requests over it, which early data may carry
    /// (not `bits.connect_only`).
    pub(crate) requests: bool,
}

/// A socket opened for an attempt, or why none was, and whether the
/// application opened it: one it did is made nonblocking once set, as
/// C cannot know how it was opened.
pub(crate) struct Opened {
    pub(crate) socket: io::Result<Box<dyn Socket>>,
    pub(crate) by_application: bool,
}

/// What each socket an attempt opens is set to (`tcpnodelay`,
/// `tcpkeepalive`, `do_connect`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct SocketSetup {
    pub(crate) nodelay: bool,
    pub(crate) keepalive: KeepAlive,
    pub(crate) fastopen: bool,
}

impl SocketSetup {
    /// Nothing set at all, for the tests of the machine.
    #[cfg(test)]
    pub(crate) const PLAIN: SocketSetup = SocketSetup {
        nodelay: false,
        keepalive: KeepAlive::DEFAULT,
        fastopen: false,
    };

    pub(crate) fn of(sockets: &Sockets) -> SocketSetup {
        SocketSetup {
            nodelay: sockets.nodelay,
            keepalive: sockets.keepalive,
            fastopen: sockets.fastopen,
        }
    }
}

/// A drive's context with nothing to trace: a network, a cache of names
/// and the time, for the tests of the machine and the pool.
#[cfg(test)]
pub(crate) struct Plain<'a> {
    pub(crate) net: &'a mut dyn Net,
    pub(crate) dns: &'a mut DnsCache,
    pub(crate) now: Instant,
}

#[cfg(test)]
impl LayerCx for Plain<'_> {
    fn now(&self) -> Instant {
        self.now
    }

    fn of(&mut self, _: crate::components::Component, _: std::fmt::Arguments<'_>) {}

    fn info(&mut self, _: std::fmt::Arguments<'_>) {}
}

#[cfg(test)]
impl QuicCx for Plain<'_> {
    fn take_room(&mut self) -> Result<Vec<u8>, OutOfMemory> {
        Ok(vec![0; super::quic::RECV_ROOM])
    }

    fn give_room(&mut self, _: Vec<u8>) {}
}

#[cfg(test)]
impl ConnCx for Plain<'_> {
    fn net(&mut self) -> &mut dyn Net {
        self.net
    }

    /// It has no HTTP/3 library.
    fn quic_making(&mut self) -> Result<Option<QuicMaking>, OutOfMemory> {
        Ok(None)
    }

    fn names(&mut self) -> Names<'_> {
        Names::Own(self.dns)
    }

    fn ipv6_works(&self) -> bool {
        true
    }

    fn fails_ipv6_resolves(&self) -> bool {
        false
    }

    fn waiter(&self) -> Waiter {
        Waiter::NONE
    }

    fn open_socket(&mut self, address: &mut Remote, kind: SocketKind) -> Opened {
        Opened {
            socket: self.net.open(address, kind),
            by_application: false,
        }
    }

    fn configure_socket(&mut self, _: &dyn Socket) -> Configured {
        Configured::Ok
    }

    fn fail(&mut self, _: std::fmt::Arguments<'_>) {}

    fn reset_fail(&mut self) {}

    fn announce_resolve(&mut self) -> Result<(), ConnectError> {
        Ok(())
    }
}

/// What a drive needs beyond its context: the settings of the transfer
/// it is driven for.
#[derive(Clone, Copy)]
pub(crate) struct Setup {
    /// A `*` entry answers for any name (C's `wildcard_resolve`).
    pub(crate) wildcard: bool,
    /// How long an answer is kept (`CURLOPT_DNS_CACHE_TIMEOUT`).
    pub(crate) max_age: Option<Duration>,
    /// The happy eyeballs delay (`CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`).
    pub(crate) delay: Duration,
    /// The IPv6 scope connections are made in, whatever the peer's
    /// (`CURLOPT_ADDRESS_SCOPE`).
    pub(crate) scope: Option<NonZeroU32>,
    /// What each socket is set to before it connects.
    pub(crate) socket: SocketSetup,
    /// The transfer sends the PROXY protocol's line over a connection it
    /// makes (`CURLOPT_HAPROXYPROTOCOL`): the connection is open only
    /// once it is sent.
    pub(crate) haproxy: bool,
    /// A layer of the tests' to put on the connection once it is up.
    #[cfg(test)]
    pub(crate) layer: Option<fn() -> Box<dyn super::layer::Layer>>,
    /// The tests' layer whose shutdown waits, put on as `layer` is.
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) linger: Option<super::layer::Linger>,
}

/// Where a name's answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Found {
    /// Kept from a setup before.
    Cached,
    /// Resolved again: what was kept had gone stale.
    Stale(Asked),
    Resolved(Asked),
}

/// Where a lookup's answer came from, all a setup keeps of its `Found`
/// (a byte, where a `Found` would grow the setup's slot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Came {
    Cached,
    Stale,
    Resolved,
}

impl From<Found> for Came {
    fn from(found: Found) -> Came {
        match found {
            Found::Cached => Came::Cached,
            Found::Stale(_) => Came::Stale,
            Found::Resolved(_) => Came::Resolved,
        }
    }
}

/// What answered a name the cache did not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Asked {
    /// The name is an address, or `localhost`: no resolver was asked.
    Shortcut,
    /// A resolver, which queued its queries as `.0` says, if it did.
    Resolver(Option<Queued>),
}

/// What a setup's attempts connect to: the addresses a name resolved to,
/// or the Unix socket the route's first hop is, its one address
/// (`Curl_unix2addr`). A pointer's size, as the setup's slot holds it.
#[derive(Clone, Debug)]
enum Addresses {
    Resolved(TryArc<Answer>),
    Unix,
}

/// An address an attempt is made to.
enum Candidate {
    Ip(IpAddr),
    /// The route's Unix socket.
    Unix,
}

/// The attempts to make, over an answer (C's ballers): the families
/// alternate, IPv6 first, each in the answer's order. A Unix socket's one
/// address is tried once.
#[derive(Debug)]
struct Eyeballs {
    answer: Addresses,
    /// How many of each family's addresses were tried.
    v6: usize,
    v4: usize,
    last_v4: bool,
    /// The families attempts may use; both for an address the URL names.
    use_v6: bool,
    use_v4: bool,
}

impl Eyeballs {
    fn new(answer: Addresses, ip: IpVersion) -> Eyeballs {
        let any = match &answer {
            Addresses::Resolved(a) => !a.resolved() || ip == IpVersion::Any,
            Addresses::Unix => true,
        };
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
        let Addresses::Resolved(answer) = &self.answer else {
            return None;
        };
        let usable = if v6 { self.use_v6 } else { self.use_v4 };
        let of = |a: &&IpAddr| a.is_ipv6() == v6;
        answer
            .addrs()
            .iter()
            .filter(of)
            .nth(n)
            .filter(|_| usable)
            .copied()
    }

    /// The address to try next, if one is left (`cf_ip_ballers_run`).
    fn next(&mut self) -> Option<Candidate> {
        if let Addresses::Unix = self.answer {
            // Counted among IPv4's, as C's family is not IPv6's.
            let left = self.v4 == 0;
            self.v4 = 1;
            return left.then_some(Candidate::Unix);
        }
        if (self.last_v4 || self.nth(false, self.v4).is_none())
            && let Some(a) = self.nth(true, self.v6)
        {
            self.v6 += 1;
            self.last_v4 = false;
            return Some(Candidate::Ip(a));
        }
        let a = self.nth(false, self.v4)?;
        self.v4 += 1;
        self.last_v4 = true;
        Some(Candidate::Ip(a))
    }

    /// Whether an address is left to try.
    fn more(&self) -> bool {
        match &self.answer {
            Addresses::Unix => self.v4 == 0,
            Addresses::Resolved(_) => {
                self.nth(true, self.v6).is_some() || self.nth(false, self.v4).is_some()
            }
        }
    }
}

/// A socket connecting to one address, and over it, for a route dialed
/// over QUIC, the QUIC connection whose handshake decides it (C's
/// `cf_ip_attempt` with its QUIC filter).
#[derive(Debug)]
struct Attempt {
    remote: Remote,
    socket: Sock,
    quic: Option<Box<Quic>>,
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
    /// An attempt started on `remote`. Its socket connected `at_once`, or
    /// its connect is in progress, to be polled when the transfer is next
    /// run, as C polls it (`cf_tcp_connect` returns at once on
    /// `EINPROGRESS`); the next attempt is due at `until`, as `Waiting`
    /// has it.
    Trying {
        #[cfg_attr(
            not(test),
            expect(dead_code, reason = "the race's tests tell the families by it")
        )]
        remote: Remote,
        at_once: bool,
        until: Option<Instant>,
    },
    /// An attempt failed, traced as it went, and the setup goes on.
    Failed,
    /// Nothing until a socket is ready, or until `until`, when the next
    /// attempt is due (`EXPIRE_HAPPY_EYEBALLS`).
    Waiting { until: Option<Instant> },
    /// Nothing until the resolver answers, or until `retry`, when
    /// queries waiting for a thread that could not be started are tried
    /// again (`EXPIRE_ASYNC_NAME`).
    Resolving { retry: Option<Instant> },
    /// Connected to the first hop, over which handshakes are to be made
    /// (`ConnLease::dialed`).
    Dialed,
}

/// Why a setup failed; any socket it had is closed.
#[derive(Debug)]
pub(crate) enum ConnectError {
    /// The name has no address to try.
    Unresolved(Unresolved),
    /// The last attempt failed, with its error if the system gave one
    /// (a QUIC handshake's failure is none), as `.1` says it. The
    /// transfer took the error's number from the drive's context as each
    /// attempt failed (`LayerCx::socket_failed`); the machine's tests,
    /// which have no transfer, read it here.
    Failed(
        #[cfg_attr(not(test), expect(dead_code, reason = "read by the tests"))] Option<io::Error>,
        ErrorKind,
    ),
    /// The application stopped a resolve as it started.
    Aborted,
    /// Memory ran out: no failure of the peer's.
    OutOfMemory,
}

/// Why a name has no address to try.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unresolved {
    /// The resolver said so now, having queued its queries as `queued`
    /// says, if it did, and what it says of why, if anything.
    Resolver {
        why: ResolveFailure,
        queued: Option<Queued>,
        explained: Option<&'static str>,
    },
    /// It said so before, and the cache kept its word.
    Negative,
    /// None of the addresses found, as `.0` says they were, is of the
    /// family allowed.
    NoAddress(Found),
    /// Only IPv6 addresses are allowed, and IPv6 does not work here: no
    /// resolver is asked (`can_resolve_dns_queries`).
    NoIpv6,
    /// Only IPv6 addresses are asked for, and the debug build fails every
    /// such resolve before the cache is looked in (`hostip_resolv`).
    DebugFailIpv6,
    /// A Unix socket's path is too long for its address
    /// (`Curl_unix2addr`'s `CURLE_TOO_LARGE`).
    UnixPathTooLong,
    /// The name is under `.onion`, which is never resolved (RFC 7686).
    Onion,
}

impl ConnectMachine {
    /// The setup of connection `number` over `route`, whose sockets close
    /// through `closer`.
    pub(crate) fn new(
        number: ConnNumber,
        route: Tcp,
        created: Instant,
        closer: Closer,
        settings: ConnSettings,
    ) -> ConnectMachine {
        ConnectMachine {
            number,
            route,
            created,
            stage: Stage::Resolving(None),
            redials: 0,
            closer,
            settings,
        }
    }

    /// A second attempt of the same setup over `route`, another way of
    /// dialing, racing the addresses `answer` holds, which the first
    /// resolved (C's HTTPS connect filter's second baller, below the
    /// name's filter that holds its answer).
    pub(crate) fn racing(
        number: ConnNumber,
        route: Tcp,
        created: Instant,
        closer: Closer,
        settings: ConnSettings,
        answer: TryArc<Answer>,
    ) -> ConnectMachine {
        let eyeballs = Eyeballs::new(Addresses::Resolved(answer), route.ip);
        ConnectMachine {
            number,
            route,
            created,
            stage: Stage::Racing(Racing {
                eyeballs,
                attempts: Vec::new(),
                last_start: None,
            }),
            redials: 0,
            closer,
            settings,
        }
    }

    /// What closes its sockets, and what the connection keeps of the
    /// creating transfer's settings: a second attempt's, as the first's.
    pub(crate) fn makings(&self) -> (Closer, ConnSettings, Instant) {
        (self.closer.clone(), self.settings, self.created)
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
            Stage::Resolving(_) => (&[][..], None),
            Stage::Racing(r) => (&r.attempts[..], None),
            Stage::Dialed(d) => (&[][..], Some(d.stream.socket())),
        };
        running.iter().map(|a| a.socket.socket()).chain(dialed)
    }

    /// What each attempt running waits for: a TCP connect to write, a
    /// QUIC connection what it says (`cf_ngtcp2_adjust_pollset`).
    pub(crate) fn racing_wants(&self) -> impl Iterator<Item = (&dyn Socket, Events)> {
        let running = match &self.stage {
            Stage::Racing(r) => &r.attempts[..],
            Stage::Resolving(_) | Stage::Dialed(_) => &[][..],
        };
        running.iter().map(|a| {
            let wants = a.quic.as_ref().map_or(Events::OUT, |q| q.wants());
            (a.socket.socket(), wants)
        })
    }

    /// How long after it started the first of its QUIC attempts to hear
    /// from its peer did, if one has (`cf_ip_ballers_min_reply_ms`).
    pub(crate) fn reply_ms(&self) -> Option<u128> {
        let running = match &self.stage {
            Stage::Racing(r) => &r.attempts[..],
            Stage::Resolving(_) | Stage::Dialed(_) => &[][..],
        };
        running
            .iter()
            .filter_map(|a| a.quic.as_ref()?.reply_ms())
            .min()
    }

    /// How far it got, as C's filter chain shows it.
    pub(crate) fn reached(&self) -> SetupPoint {
        match &self.stage {
            Stage::Resolving(_) => SetupPoint::Resolving,
            Stage::Racing(r) => SetupPoint::Racing {
                started: r.last_start.is_some(),
            },
            Stage::Dialed(d) => SetupPoint::Dialed(d.made),
        }
    }

    /// The PROXY protocol's line is sent over the connection to the first
    /// hop, as was decided once the proxies' handshakes were made; false
    /// before.
    pub(crate) fn sends_preface(&self) -> bool {
        matches!(&self.stage, Stage::Dialed(d) if d.preface == Some(true))
    }

    /// The proxy's handshake `which` is made over the dialed connection.
    /// Once the route's are all made, whether the PROXY protocol's line
    /// follows is decided, `haproxy` read then and only then.
    pub(crate) fn proxied(&mut self, which: Made, haproxy: impl FnOnce() -> bool) {
        let Stage::Dialed(d) = &mut self.stage else {
            panic!("no handshake is made");
        };
        d.mark_made(which);
        let route = &self.route;
        let socks = route.socks().is_some() && !d.made.has(Made::SOCKS);
        let tunnel = route.proxy.as_ref().is_some_and(|p| p.tunnels()) && !d.made.has(Made::TUNNEL);
        if !socks && !tunnel {
            assert!(d.preface.is_none(), "the PROXY line is decided once");
            d.preface = Some(haproxy());
        }
    }

    /// The origin's QUIC connection, to be made through the tunnel the
    /// dialed connection carries, over the ends of that connection
    /// (`Curl_cf_quic_insert_after`).
    pub(crate) fn tunnel_quic(&self, cx: &mut dyn ConnCx) -> Result<Box<Quic>, ErrorKind> {
        let Stage::Dialed(d) = &self.stage else {
            panic!("a tunnel goes over a dialed connection");
        };
        assert!(self.route.tunnels_udp(), "a CONNECT-UDP tunnel");
        let none = SocketAddr::from(([0, 0, 0, 0], 0));
        let remote = d.remote.inet().unwrap_or(none);
        let local = d.stream.local_addr().unwrap_or(none);
        self.make_quic(cx, local, remote, true)
    }

    /// The addresses the name resolved to, once it has.
    pub(crate) fn answer(&self) -> Option<&TryArc<Answer>> {
        match &self.stage {
            Stage::Resolving(_) | Stage::Dialed(_) => None,
            Stage::Racing(r) => match &r.eyeballs.answer {
                Addresses::Resolved(answer) => Some(answer),
                Addresses::Unix => None,
            },
        }
    }

    /// What the layers on the connection to the first hop wait for, as
    /// they handshake, wanting nothing else.
    /// What the layers of the connection to the first hop answer `q`,
    /// once it is dialed.
    pub(crate) fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        match &self.stage {
            Stage::Dialed(d) => d.stream.query(q),
            Stage::Resolving(_) | Stage::Racing(_) => None,
        }
    }

    pub(crate) fn handshake_pollset(&self, wanted: Events) -> Events {
        match &self.stage {
            Stage::Dialed(d) => d.stream.adjust_pollset(wanted),
            Stage::Resolving(_) | Stage::Racing(_) => panic!("no handshake is made"),
        }
    }

    /// What a setup that fails keeps of its connection to the first hop,
    /// if it made one (`Curl_conn_report_failed`): its ends, and when it
    /// connected. Attempts still racing have nothing to keep.
    pub(crate) fn partly_made(&self) -> Option<(Remote, Option<SocketAddr>, Instant)> {
        match &self.stage {
            Stage::Dialed(d) => Some((d.remote.clone(), d.stream.local_addr(), d.connected_at)),
            Stage::Resolving(_) | Stage::Racing(_) => None,
        }
    }

    /// The connection to the first hop, while its handshakes are made.
    pub(crate) fn dialed(&mut self) -> &mut Dialed {
        match &mut self.stage {
            Stage::Dialed(d) => d,
            Stage::Resolving(_) | Stage::Racing(_) => panic!("no handshake is made"),
        }
    }

    /// The handshakes are made: the connection is up.
    pub(crate) fn handshaken(self) -> Conn {
        let Stage::Dialed(d) = self.stage else {
            panic!("no handshake is made");
        };
        let at = d.connected_at;
        let mut conn = Self::conn(
            (self.number, self.route, self.created, self.settings),
            d.stream,
            d.remote,
            at,
        );
        conn.socks5_authenticated = d.socks5_authenticated;
        conn
    }

    /// The proxy closed the connection as it asked for credentials: the
    /// setup starts over, racing the addresses its name resolved to
    /// (`cf_setup_connect` discards the chain below the name's filter,
    /// which keeps its answer). False, and nothing done, if it was started
    /// over too often.
    pub(crate) fn redial(&mut self, cx: &mut dyn ConnCx) -> bool {
        if self.redials >= MAX_REDIALS {
            return false;
        }
        self.redials += 1;
        let Stage::Dialed(d) = std::mem::replace(&mut self.stage, Stage::Resolving(None)) else {
            panic!("only a dialed setup is redialed");
        };
        let n = self.redials;
        cx.of(
            Component::Setup,
            format_args!("retrying connect, {n}. time"),
        );
        // The chain below the setup filter is discarded: of the setup
        // filters in it, the tunnel's says so.
        if self.route.proxy.as_ref().is_some_and(|p| p.tunnels()) {
            cx.of(Component::HttpProxy, format_args!("destroy"));
            cx.of(Component::H1Proxy, format_args!("destroy"));
        }
        discard(cx, self.route.socket_component(), d.stream.into_socket());
        self.stage = Stage::Racing(Racing {
            eyeballs: Eyeballs::new(d.answer, self.route.ip),
            attempts: Vec::new(),
            last_start: None,
        });
        true
    }

    /// Move the setup on by one event.
    pub(crate) fn drive(
        mut self,
        cx: &mut dyn ConnCx,
        setup: Setup,
    ) -> Result<Drove, ConnectError> {
        let now = cx.now();
        let delay = setup.delay;
        let component = self.route.socket_component();
        let r = match &mut self.stage {
            Stage::Resolving(pending) => {
                let pending = pending.take();
                let (answer, found) = match self.unix_peer() {
                    // Its one address, made at once (`resolv_unix`).
                    Some(peer) => {
                        if peer.path().len() >= curl_os::net::UNIX_PATH_ROOM {
                            return Err(ConnectError::Unresolved(Unresolved::UnixPathTooLong));
                        }
                        (Addresses::Unix, Found::Resolved(Asked::Shortcut))
                    }
                    None => {
                        let peer = self.route.destination();
                        let (name, port) = (peer.name(), peer.port());
                        let looked = match pending {
                            None => {
                                let family = family(self.route.ip, cx);
                                let shown = peer.shown();
                                lookup_start((shown, name, port), family, cx, setup, true)?
                            }
                            Some(p) => {
                                let id = p.id;
                                let mut polled = None;
                                cx.net().with_resolver(&mut |r| polled = Some(r.answer(id)));
                                match polled.expect("the network lends its resolver") {
                                    Some(answer) => {
                                        let (a, f) = settle(answer, (name, port), p, cx)?;
                                        Looked::Found(a, f)
                                    }
                                    None => Looked::Pending(p),
                                }
                            }
                        };
                        match looked {
                            Looked::Found(answer, found) => (Addresses::Resolved(answer), found),
                            // Nothing until the resolver answers, when the
                            // multi runs the transfer again.
                            Looked::Pending(p) => {
                                self.stage = Stage::Resolving(Some(p));
                                let mut retry = None;
                                cx.net().with_resolver(&mut |r| retry = r.retry());
                                let retry = retry.map(|after| cx.now().after(after));
                                return Ok(Drove::Connecting(self, Progress::Resolving { retry }));
                            }
                        }
                    }
                };
                let eyeballs = Eyeballs::new(answer, self.route.ip);
                if !eyeballs.more() {
                    return Err(ConnectError::Unresolved(Unresolved::NoAddress(found)));
                }
                self.stage = Stage::Racing(Racing {
                    eyeballs,
                    attempts: Vec::new(),
                    last_start: None,
                });
                return Ok(Drove::Connecting(self, Progress::Resolved(found)));
            }
            Stage::Racing(r) => r,
            Stage::Dialed(_) => unreachable!("a dialed setup is driven by its handshakes"),
        };
        // A running attempt that connected wins; one that failed is
        // dropped (`cf_ip_ballers_run`).
        match r.check(cx, component) {
            Checked::Pending => {}
            Checked::Won(i) => return self.won(cx, setup, i, now),
            Checked::Failed(i, error) => {
                let failure = r.attempts.remove(i).fail(cx, component, error)?;
                return r
                    .failed(Some(failure), ErrorKind::CouldntConnect)
                    .map(|p| Drove::Connecting(self, p));
            }
            Checked::QuicFailed(i, kind) => {
                r.attempts.remove(i).discard(cx, component);
                return r.failed(None, kind).map(|p| Drove::Connecting(self, p));
            }
        }
        let due = r.last_start.is_none_or(|at| now >= at.after(delay)) || r.attempts.is_empty();
        if !(due && r.eyeballs.more()) {
            let until = r.next_due(delay);
            return Ok(Drove::Connecting(self, Progress::Waiting { until }));
        }
        let first = r.attempts.is_empty();
        // What an attempt before said is let go, as C's race does as it
        // looks for the next address (`cf_ip_ballers_run`).
        cx.reset_fail();
        if !first {
            cx.of(
                Component::HappyEyeballs,
                format_args!("happy eyeballs timeout expired, start next attempt"),
            );
        }
        if r.attempts.len() == MAX_ATTEMPTS {
            // The oldest makes room (`cf_ip_ballers_prune`).
            let oldest = r.attempts.remove(0);
            oldest.discard(cx, component);
            cx.of(
                Component::HappyEyeballs,
                format_args!("discarding oldest attempt to keep limit"),
            );
        }
        if r.attempts.try_reserve(1).is_err() {
            return Err(ConnectError::OutOfMemory);
        }
        let candidate = r.eyeballs.next().expect("an address is left");
        // A Unix socket's family is not IPv4's either.
        let (which, v) = (
            if first { "first" } else { "next" },
            if matches!(candidate, Candidate::Ip(IpAddr::V4(_))) {
                4
            } else {
                6
            },
        );
        // An HTTP/3 proxy's filter is the attempt's, made as it starts
        // (`Curl_cf_h3_proxy_create`).
        if self.route.proxy_over_quic() {
            let udp = u8::from(self.route.tunnels_udp());
            cx.of(
                Component::H3Proxy,
                format_args!("created, udp_tunnel={udp}"),
            );
        }
        cx.of(
            Component::HappyEyeballs,
            format_args!("starting {which} attempt for ipv{v} -> 0"),
        );
        r.last_start = Some(now);
        // The attempts running are checked again before the new one's
        // first connect (`goto evaluate`): one connecting now wins before
        // it is made, and one failing now is dropped as it is made.
        match r.check(cx, component) {
            Checked::Pending => {}
            Checked::Won(i) => return self.won(cx, setup, i, now),
            Checked::Failed(i, error) => {
                // Traced; whatever the new attempt comes to supersedes it.
                let superseded = r.attempts.remove(i).fail(cx, component, error)?;
                drop(superseded);
            }
            Checked::QuicFailed(i, _) => r.attempts.remove(i).discard(cx, component),
        }
        let (mut remote, scope_found) = match candidate {
            Candidate::Ip(ip) => {
                let (at, found) = address(ip, self.route.destination(), setup.scope, cx.net());
                (Remote::Inet(at), found)
            }
            Candidate::Unix => {
                let peer = self.unix_peer().expect("a route to a Unix socket");
                (Remote::Unix(peer), None)
            }
        };
        if let Some(scope) = scope_found {
            cx.info(format_args!(
                "determined scope_id={scope} for link-local address from local interface"
            ));
        }
        let kind = if self.route.first_hop_quic() {
            SocketKind::Datagram
        } else {
            SocketKind::Stream
        };
        let opened = cx.open_socket(&mut remote, kind);
        let socket = match opened.socket {
            Ok(socket) => socket,
            Err(error) if !opened.by_application && error.kind() == io::ErrorKind::OutOfMemory => {
                return Err(ConnectError::OutOfMemory);
            }
            Err(error) => {
                // Neither address is known yet (`set_remote_ip`).
                cx.fail(format_args!("failed to open socket: {}", OsError(&error)));
                let none = io::Error::from_raw_os_error(0);
                return self.not_opened(cx, None, ErrorKind::CouldntConnect, none);
            }
        };
        trace_trying(cx, &remote);
        let fd = socket.key().get();
        // Only TCP's are set (`is_tcp`): neither a Unix socket nor
        // QUIC's UDP one.
        let tcp = matches!(remote, Remote::Inet(_)) && kind == SocketKind::Stream;
        if tcp {
            set_up(cx, &*socket, setup.socket);
        }
        let connected = match cx.configure_socket(&*socket) {
            Configured::Ok => false,
            Configured::AlreadyConnected => true,
            Configured::Abort => {
                cx.net().close(Sock::new(socket, self.closer.clone()));
                let none = io::Error::from_raw_os_error(0);
                let kind = ErrorKind::AbortedByCallback;
                return self.not_opened(cx, Some(&remote), kind, none);
            }
        };
        // The local end bound, as the route says, for the address's
        // family, TCP's alone (`bindlocal`); a failure closes the socket,
        // and one for the family alone lets the next address be tried.
        if let (Some(local), Remote::Inet(at)) = (self.route.local.clone(), &remote) {
            let scope = setup
                .scope
                .or(self.route.destination().scope())
                .map_or(0, NonZeroU32::get);
            if let Err(failed) = bind_local(cx, &*socket, *at, &local, scope, setup) {
                cx.net().close(Sock::new(socket, self.closer.clone()));
                if failed == BindFailed::OutOfMemory {
                    return Err(ConnectError::OutOfMemory);
                }
                let none = io::Error::from_raw_os_error(0);
                return self.not_opened(cx, Some(&remote), failed.kind(), none);
            }
        }
        if opened.by_application
            && let Err(error) = socket.set_nonblocking()
        {
            cx.net().close(Sock::new(socket, self.closer.clone()));
            let kind = ErrorKind::UnsupportedProtocol;
            return self.not_opened(cx, Some(&remote), kind, error);
        }
        cx.of(component, format_args!("cf_socket_open() -> 0, fd={fd}"));
        if kind == SocketKind::Datagram {
            return self.quic_attempt(cx, socket, remote, delay);
        }
        let Stage::Racing(r) = &mut self.stage else {
            unreachable!("an attempt is made in a race");
        };
        if connected {
            // The application connected it: it won as it opened, with no
            // connect to check.
            let socket = Sock::new(socket, self.closer.clone());
            r.attempts
                .try_push(Attempt {
                    remote,
                    socket,
                    quic: None,
                })
                .expect("reserved");
            let i = r.attempts.len() - 1;
            return self.won(cx, setup, i, now);
        }
        if tcp && setup.socket.fastopen && socket.set(SocketOption::FastOpenConnect).is_err() {
            cx.of(
                Component::Tcp,
                format_args!("Failed to enable TCP Fast Open on fd {fd}"),
            );
        }
        let connect = socket.connect(&remote);
        let local = socket.local_addr().ok();
        let (lip, lport) = (Ip(local.map(|l| l.ip())), local.map_or(0, |l| l.port()));
        cx.of(
            component,
            format_args!("local address {lip} port {lport}..."),
        );
        let socket = Sock::new(socket, self.closer.clone());
        match connect {
            Ok(connect) => {
                r.attempts
                    .try_push(Attempt {
                        remote: remote.clone(),
                        socket,
                        quic: None,
                    })
                    .expect("reserved");
                let tried = Progress::Trying {
                    remote,
                    at_once: connect == Connect::Done,
                    until: r.next_due(delay),
                };
                Ok(Drove::Connecting(self, tried))
            }
            Err(error) => {
                // The socket was opened before its connect failed, and
                // never got a local address (`cf_tcp_connect`).
                cx.socket_failed(&error);
                let why = OsError(&error);
                let rip = remote.shown_ip();
                cx.info(format_args!("Immediate connect fail for {rip}: {why}"));
                cx.net().close(socket);
                cx.info(format_args!(
                    "connect to {rip} port {} from {lip} port {lport} failed: {why}",
                    remote.port()
                ));
                cx.of(component, format_args!("destroy"));
                r.failed(Some(error), ErrorKind::CouldntConnect)
                    .map(|p| Drove::Connecting(self, p))
            }
        }
    }

    /// An attempt over QUIC, its socket `socket` opened for `remote`:
    /// connected, set as QUIC's sockets are (`cf_udp_setup_quic`), and
    /// the QUIC connection over it made and its first flight sent
    /// (`cf_connect_start`, `Curl_cf_ngtcp2_cmn_connect`).
    fn quic_attempt(
        mut self,
        cx: &mut dyn ConnCx,
        socket: Box<dyn Socket>,
        remote: Remote,
        delay: Duration,
    ) -> Result<Drove, ConnectError> {
        let component = self.route.socket_component();
        let fd = socket.key().get();
        let socket = Sock::new(socket, self.closer.clone());
        let Remote::Inet(addr) = remote else {
            unreachable!("HTTP/3 is refused over a Unix socket");
        };
        let rip = remote.shown_ip();
        if let Err(error) = socket.socket().connect(&remote) {
            cx.socket_failed(&error);
            let why = OsError(&error);
            cx.info(format_args!("Immediate connect fail for {rip}: {why}"));
            cx.of(self.quic_component(), format_args!("destroy"));
            discard(cx, component, socket);
            return self.quic_failed(Some(error), ErrorKind::CouldntConnect);
        }
        let local = socket.socket().local_addr().ok();
        let (lip, lport) = (Ip(local.map(|l| l.ip())), local.map_or(0, |l| l.port()));
        let rport = remote.port();
        cx.of(
            component,
            format_args!("QUIC socket {fd} connected: [{lip}:{lport}] -> [{rip}:{rport}]"),
        );
        // What the system does not take, it does without, as C does.
        for option in [
            SocketOption::ReceiveEcn,
            SocketOption::DiscoverMtu,
            SocketOption::ReceiveJoined,
        ] {
            socket.socket().set(option).ok();
        }
        cx.of(
            component,
            format_args!("cf_udp_connect(), opened socket={fd} ({lip}:{lport})"),
        );
        let made = match local {
            Some(local) => self.make_quic(cx, local, addr, false),
            None => Err(ErrorKind::QuicConnectError),
        };
        let started = made.and_then(|mut quic| {
            let mut over = crate::conn::quic::Over {
                cx: &mut *cx,
                path: crate::conn::quic::Path::Socket(socket.socket()),
            };
            let done = quic.start(&mut over)?;
            Ok((quic, done))
        });
        let (quic, done) = match started {
            Ok(started) => started,
            Err(ErrorKind::OutOfMemory) => {
                cx.net().close(socket);
                return Err(ConnectError::OutOfMemory);
            }
            Err(kind) => {
                cx.of(self.quic_component(), format_args!("destroy"));
                discard(cx, component, socket);
                return self.quic_failed(None, kind);
            }
        };
        let Stage::Racing(r) = &mut self.stage else {
            unreachable!("an attempt is made in a race");
        };
        r.attempts
            .try_push(Attempt {
                remote: remote.clone(),
                socket,
                quic: Some(quic),
            })
            .expect("reserved");
        // Connected as it started, for early data: won at once.
        let tried = Progress::Trying {
            remote,
            at_once: done,
            until: r.next_due(delay),
        };
        Ok(Drove::Connecting(self, tried))
    }

    /// The filter a QUIC attempt's connection is traced as: an HTTP/3
    /// proxy's (`H3-PROXY`), or the origin's (`HTTP/3`).
    fn quic_component(&self) -> Component {
        if self.route.proxy_over_quic() {
            Component::H3Proxy
        } else {
            Component::Http3
        }
    }

    /// The QUIC connection from `local` to `remote`: its TLS session made
    /// for the origin, or for the HTTP/3 proxy whose tunnel the route goes
    /// through, offering HTTP/3, and the HTTP/3 library's connection over
    /// it (`cf_connect_start`). One `tunnelled` is the origin's, through
    /// the proxy's CONNECT-UDP, its datagrams sent through the layers
    /// below; else it is the race's attempt, on its own socket. A failure
    /// is traced as C traces a connect call's.
    fn make_quic(
        &self,
        cx: &mut dyn ConnCx,
        local: SocketAddr,
        remote: SocketAddr,
        tunnelled: bool,
    ) -> Result<Box<Quic>, ErrorKind> {
        let oom = |OutOfMemory| ErrorKind::OutOfMemory;
        let component = if tunnelled {
            Component::Http3
        } else {
            self.quic_component()
        };
        let failed = |cx: &mut dyn ConnCx, kind: ErrorKind| {
            let (ip, port) = (remote.ip(), remote.port());
            let why = kind.message();
            cx.info(format_args!(
                "QUIC connect to {ip} port {port} failed: {why}"
            ));
            let code = crate::trace::Code(Err(kind));
            cx.of(component, format_args!("connect -> {code}, done=0"));
            kind
        };
        let Some(making) = cx.quic_making().map_err(oom)? else {
            return Err(failed(cx, ErrorKind::QuicConnectError));
        };
        let libraries = &*making.libraries;
        let (Some(backend), Some(h3)) = (libraries.tls.as_deref(), libraries.h3) else {
            return Err(failed(cx, ErrorKind::QuicConnectError));
        };
        // To an HTTP/3 proxy, its TLS is the proxy's, and no early data
        // goes before the tunnel's `CONNECT`.
        let proxied = !tunnelled && self.route.proxy_over_quic();
        let (identity, origin, via) = if proxied {
            let identity = self.route.proxy_tls().expect("an HTTP/3 proxy speaks TLS");
            (identity, self.route.destination(), None)
        } else {
            let identity = self
                .route
                .tls
                .as_ref()
                .expect("HTTP/3 is refused but over TLS");
            (identity, &*self.route.origin, self.route.via.as_deref())
        };
        let kept_for =
            crate::tls::SessionPeer::new(identity, origin, via, backend.id(), super::Dial::Quic)
                .map_err(oom)?;
        // Early data, where the transfer asks for it and makes requests
        // (`conn_cfg->earlydata`, `bits.connect_only`).
        let early_data = !proxied
            && identity
                .options
                .ssl_options
                .contains(crate::options::SslOptions::EARLYDATA)
            && making.requests;
        let peer = crate::tls::TlsPeer::of(origin, early_data);
        let tls = {
            let mut tcx = crate::tls::TlsCx::new(cx, component, &kept_for);
            backend.quic_session(identity, &peer, &making.shared, &mut tcx)
        };
        let tls = match tls {
            Ok(tls) => tls,
            Err(ErrorKind::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
            Err(kind) => return Err(failed(cx, kind)),
        };
        // The session resumed, if early data may go under it, read before
        // the connection takes the session.
        let early = match tls.early_data() {
            Some(ticket) => {
                let mut params = Vec::new();
                params
                    .try_extend_from_slice(&ticket.quic_params)
                    .map_err(oom)?;
                Some(crate::conn::quic::EarlyTicket {
                    most: ticket.earlydata_max,
                    alpn: ticket.alpn,
                    params,
                })
            }
            None => None,
        };
        let setup = crate::http3::ClientSetup {
            local,
            remote,
            now: making.clock.now(),
            handshake_timeout: making.handshake_timeout,
            max_window: H3_CONN_WINDOW_SIZE_MAX,
            stream_window: crate::conn::quic::STREAM_WINDOW_INITIAL,
            max_streams: QUIC_MAX_STREAMS,
        };
        let conn = match h3.client(&setup, tls) {
            Ok(conn) => conn,
            Err(crate::http3::ConnectFailed::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
            Err(crate::http3::ConnectFailed::Refused) => {
                return Err(failed(cx, ErrorKind::QuicConnectError));
            }
            Err(crate::http3::ConnectFailed::Crypto { why }) => {
                let kind = cx.fails(ErrorKind::FailedInit, format_args!("{why}"));
                return Err(failed(cx, kind));
            }
        };
        let mut quic = Quic::new(
            conn,
            kept_for,
            remote,
            making.clock.clone(),
            component,
            tunnelled,
        )
        .map_err(oom)?;
        if let Some(ticket) = early {
            match quic.early_data(cx, &ticket) {
                Ok(()) => {}
                Err(ErrorKind::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                Err(kind) => return Err(failed(cx, kind)),
            }
        }
        curl_alloc::try_box(quic).map_err(oom)
    }

    /// A QUIC attempt failed as it was made: the race goes on while
    /// another runs or an address is left.
    fn quic_failed(
        mut self,
        error: Option<io::Error>,
        kind: ErrorKind,
    ) -> Result<Drove, ConnectError> {
        let Stage::Racing(r) = &mut self.stage else {
            unreachable!("an attempt is made in a race");
        };
        r.failed(error, kind).map(|p| Drove::Connecting(self, p))
    }

    /// An attempt whose socket did not open, or was closed as it was set:
    /// traced as `cf_socket_open` and `cf_tcp_connect` trace it, the
    /// remote address only once it is known, and the local one never
    /// (`ip_quadruple` starts out empty). `error` is the socket's own
    /// (`ctx->sockerr`), none for most.
    fn not_opened(
        mut self,
        cx: &mut dyn ConnCx,
        remote: Option<&Remote>,
        kind: ErrorKind,
        error: io::Error,
    ) -> Result<Drove, ConnectError> {
        let code = crate::trace::Code(Err(kind));
        let component = self.route.socket_component();
        cx.of(component, format_args!("cf_socket_open() -> {code}, fd=-1"));
        let rport = remote.map_or(0, Remote::port);
        let why = OsError(&error);
        match remote {
            Some(remote) => cx.info(format_args!(
                "connect to {} port {rport} from  port 0 failed: {why}",
                remote.shown_ip()
            )),
            None => cx.info(format_args!(
                "connect to  port {rport} from  port 0 failed: {why}"
            )),
        }
        cx.of(component, format_args!("destroy"));
        let Stage::Racing(r) = &mut self.stage else {
            unreachable!("an attempt is made in a race");
        };
        r.failed(Some(error), kind)
            .map(|p| Drove::Connecting(self, p))
    }

    /// The race's attempt `i` connected: the others close, and the
    /// connection is up, or dialed for the handshakes over it.
    fn won(
        mut self,
        cx: &mut dyn ConnCx,
        setup: Setup,
        i: usize,
        now: Instant,
    ) -> Result<Drove, ConnectError> {
        let Stage::Racing(r) = &mut self.stage else {
            unreachable!("only a race is won");
        };
        cx.of(
            Component::HappyEyeballs,
            format_args!("connect attempt #{i} successful"),
        );
        let won = r.attempts.remove(i);
        let component = self.route.socket_component();
        for a in r.attempts.drain(..) {
            a.discard(cx, component);
        }
        // Whatever the attempts said is let go (`cf_ip_happy_connect`).
        cx.reset_fail();
        // A QUIC connection is up with its handshake: its TLS is its own.
        // One to an HTTP/3 proxy is the first hop's, with the tunnel's
        // `CONNECT` still to go over it.
        let mut quic = won.quic;
        let proxy_quic = if self.route.proxy_over_quic() {
            quic.take()
        } else {
            None
        };
        if quic.is_none() && (self.route.handshakes() || setup.haproxy || self.route.secured()) {
            // The connection is the first hop's; the handshakes over it
            // are still to be made.
            let answer = r.eyeballs.answer.clone();
            let target = match self.socks_target(cx, setup) {
                Ok(target) => target,
                Err(e) => {
                    cx.net().close(won.socket);
                    return Err(e);
                }
            };
            // A QUIC connection is connected as its first datagram came.
            let connected_at = proxy_quic
                .as_ref()
                .and_then(|q| q.first_byte_at())
                .unwrap_or(now);
            // The proxy's TLS is its QUIC connection's, made.
            let made = if proxy_quic.is_some() {
                Made::PROXY_TLS
            } else {
                Made::default()
            };
            self.stage = Stage::Dialed(Dialed {
                remote: won.remote,
                stream: Stream::new(won.socket),
                connected_at,
                answer,
                target,
                socks5_authenticated: false,
                made,
                // With no proxy's handshake to make first, the stage is
                // reached now.
                preface: (!self.route.handshakes()).then_some(setup.haproxy),
                quic: proxy_quic,
            });
            return Ok(Drove::Connecting(self, Progress::Dialed));
        }
        let made = (self.number, self.route, self.created, self.settings);
        #[cfg_attr(
            not(any(test, feature = "test-util")),
            expect(unused_mut, reason = "tests push a layer")
        )]
        let mut stream = Stream::new(won.socket);
        #[cfg(test)]
        if let Some(layer) = setup.layer {
            stream.layers_mut().push(layer()).expect("a test's memory");
        }
        #[cfg(any(test, feature = "test-util"))]
        if let Some(how) = setup.linger {
            let layer = super::layer::Lingering::boxed(how).expect("a test's memory");
            stream.layers_mut().push(layer).expect("a test's memory");
        }
        // A QUIC connection is connected as its first datagram came.
        let at = quic.as_ref().and_then(|q| q.first_byte_at()).unwrap_or(now);
        let mut conn = Self::conn(made, stream, won.remote, at);
        if let Some(quic) = quic {
            let h3 = crate::proto::http3::H3Conn::new(quic);
            conn.put_h3(curl_alloc::try_box(h3).map_err(|OutOfMemory| ConnectError::OutOfMemory)?);
        }
        Ok(Drove::Established(conn))
    }

    /// The Unix socket the first hop is at, if it is one.
    fn unix_peer(&self) -> Option<UnixPeer> {
        let peer = self.route.destination_shared();
        peer.is_unix().then(|| UnixPeer::of(peer.clone()))
    }

    /// The destination's addresses, for a SOCKS proxy that is not to
    /// resolve its name (`Curl_conn_dns_add_addr_resolve`); a resolver
    /// that finds nothing is for the handshake to say.
    #[expect(clippy::type_complexity, reason = "the field it fills")]
    fn socks_target(
        &self,
        cx: &mut dyn ConnCx,
        setup: Setup,
    ) -> Result<Option<Result<(TryArc<Answer>, Came), ()>>, ConnectError> {
        let Some(leg) = self.route.socks() else {
            return Ok(None);
        };
        if !leg.version.resolves_locally() {
            return Ok(None);
        }
        match resolve(leg.to, leg.version.ip(self.route.ip), cx, setup) {
            Ok((answer, found)) => Ok(Some(Ok((answer, Came::from(found))))),
            // The SOCKS handshake says the name failed, whatever the why.
            Err(ConnectError::Unresolved(_)) => Ok(Some(Err(()))),
            Err(e) => Err(e),
        }
    }
    /// The connection set up over `stream` to `remote`, found connected
    /// at `at`.
    /// The connection the setup `made` (its number, route, start and
    /// settings) becomes over `stream`.
    fn conn(
        made: (ConnNumber, Tcp, Instant, ConnSettings),
        stream: Stream,
        remote: Remote,
        at: Instant,
    ) -> Conn {
        let (number, route, created, settings) = made;
        Conn {
            number,
            route: Route::Tcp(route),
            transport: Transport::Tcp(stream),
            remote: Some(remote),
            created,
            connected_at: at,
            use_: Use::Leased(NonZeroU32::MIN),
            served: false,
            socks5_authenticated: false,
            seen_version: None,
            close: false,
            settings,
            negotiate: None,
            session: None,
        }
    }

    /// The setup lost a race of two (C's HTTPS connect filter discards
    /// the loser's chain): its attempts go as a race's losers do, with no
    /// goodbye to their peers.
    pub(crate) fn discard(self, cx: &mut dyn ConnCx) {
        let component = self.route.socket_component();
        match self.stage {
            Stage::Racing(mut r) => {
                cx.of(Component::HappyEyeballs, format_args!("destroy"));
                for a in r.attempts.drain(..) {
                    a.discard(cx, component);
                }
            }
            Stage::Dialed(d) => discard(cx, component, d.stream.into_socket()),
            stage @ Stage::Resolving(_) => ConnectMachine { stage, ..self }.close(cx.net()),
        }
    }

    /// End the setup, closing what it has open.
    pub(crate) fn close(self, net: &mut dyn Net) {
        match self.stage {
            Stage::Resolving(None) => {}
            // Its answer, if it comes, is not wanted.
            Stage::Resolving(Some(p)) => {
                net.with_resolver(&mut |r| r.cancel(p.id));
                p.done();
            }
            Stage::Racing(mut r) => r.close_all(net),
            Stage::Dialed(d) => net.close(d.stream.into_socket()),
        }
    }
}

/// What a check of the running attempts found.
enum Checked {
    /// None is decided yet.
    Pending,
    /// Attempt `.0` connected.
    Won(usize),
    /// Attempt `.0` failed with `.1`.
    Failed(usize, io::Error),
    /// Attempt `.0`, over QUIC, failed as `.1` says, traced as it did.
    QuicFailed(usize, ErrorKind),
}

impl Racing {
    /// Each running attempt's socket checked for its connect, oldest
    /// first, as `cf_tcp_connect` checks it (`SOCKET_WRITABLE(sock, 0)`):
    /// the first decided ends the check.
    fn check(&mut self, cx: &mut dyn ConnCx, component: Component) -> Checked {
        for (i, a) in self.attempts.iter_mut().enumerate() {
            let socket = a.socket.socket();
            // A QUIC attempt is decided by its handshake, its socket
            // connected from the start.
            if let Some(quic) = a.quic.as_mut() {
                let mut over = crate::conn::quic::Over {
                    cx: &mut *cx,
                    path: crate::conn::quic::Path::Socket(socket),
                };
                match quic.connect(&mut over) {
                    Ok(true) => return Checked::Won(i),
                    Ok(false) => continue,
                    Err(kind) => return Checked::QuicFailed(i, kind),
                }
            }
            let fd = socket.key().get();
            let mut watch = [SocketPoll::new(socket, Events::OUT)];
            let revents = match cx.net().poll(&mut watch, &mut [], Duration::ZERO) {
                Ok(_) => watch[0].revents(),
                Err(error) => return Checked::Failed(i, error),
            };
            if revents.is_empty() {
                cx.of(component, format_args!("not connected yet on fd={fd}"));
                continue;
            }
            // Writable alone, the connect is decided by the socket's
            // error; with an error or a hang-up it failed.
            let broken = [Events::ERR, Events::HUP, Events::PRI, Events::NVAL]
                .into_iter()
                .any(|e| revents.contains(e));
            if broken {
                cx.of(component, format_args!("poll/select error on fd={fd}"));
            }
            return match socket.take_error() {
                Ok(None) if !broken => {
                    cx.of(component, format_args!("connected on fd={fd}"));
                    Checked::Won(i)
                }
                // C fails it with whatever error the socket says, none
                // included.
                Ok(None) => Checked::Failed(i, io::Error::from_raw_os_error(0)),
                Ok(Some(error)) | Err(error) => Checked::Failed(i, error),
            };
        }
        Checked::Pending
    }

    /// When the next attempt is due, if an address is left for one.
    fn next_due(&self, delay: Duration) -> Option<Instant> {
        self.last_start
            .filter(|_| self.eyeballs.more())
            .map(|at| at.after(delay))
    }

    fn close_all(&mut self, net: &mut dyn Net) {
        for a in self.attempts.drain(..) {
            net.close(a.socket);
        }
    }

    /// An attempt failed: the setup goes on while an attempt runs or an
    /// address is left, and fails with it otherwise.
    /// The attempt failed with `error`, as `kind` says: the setup goes
    /// on while another runs or an address is left.
    fn failed(&self, error: Option<io::Error>, kind: ErrorKind) -> Result<Progress, ConnectError> {
        if !self.attempts.is_empty() || self.eyeballs.more() {
            Ok(Progress::Failed)
        } else {
            Err(ConnectError::Failed(error, kind))
        }
    }
}

impl Attempt {
    /// The attempt failed with `error`: its socket is closed, its local
    /// address read first, as C reads it for the trace, and the failure
    /// traced as the attempt goes.
    fn fail(
        self,
        cx: &mut dyn ConnCx,
        component: Component,
        error: io::Error,
    ) -> Result<io::Error, ConnectError> {
        let local = self.socket.socket().local_addr().ok();
        cx.net().close(self.socket);
        if error.kind() == io::ErrorKind::OutOfMemory {
            return Err(ConnectError::OutOfMemory);
        }
        cx.socket_failed(&error);
        let (lip, lport) = (Ip(local.map(|l| l.ip())), local.map_or(0, |l| l.port()));
        let why = OsError(&error);
        let remote = &self.remote;
        cx.info(format_args!(
            "connect to {} port {} from {lip} port {lport} failed: {why}",
            remote.shown_ip(),
            remote.port()
        ));
        cx.of(component, format_args!("destroy"));
        Ok(error)
    }
}

impl Attempt {
    /// The attempt goes, its QUIC connection first, then its socket
    /// (`cf_ip_attempt_free`).
    fn discard(self, cx: &mut dyn ConnCx, component: Component) {
        if let Some(quic) = &self.quic {
            cx.of(quic.component(), format_args!("destroy"));
        }
        drop(self.quic);
        discard(cx, component, self.socket);
    }
}

/// The receive window of a QUIC connection at its largest
/// (`H3_CONN_WINDOW_SIZE_MAX`).
const H3_CONN_WINDOW_SIZE_MAX: u64 = 100 * 10 * 1024 * 1024;
/// The streams the peer may open of each kind (`QUIC_MAX_STREAMS`).
const QUIC_MAX_STREAMS: u64 = 256 * 1024;

/// A socket whose filter goes, still open (`cf_socket_destroy`).
fn discard(cx: &mut dyn ConnCx, component: Component, socket: Sock) {
    let fd = socket.key().get();
    cx.of(component, format_args!("destroy"));
    cx.of(component, format_args!("cf_socket_close, fd={fd}"));
    cx.net().close(socket);
}

/// An attempt to `remote` has its socket (`cf_socket_open`), with the
/// scope it has.
fn trace_trying(cx: &mut dyn ConnCx, remote: &Remote) {
    match remote {
        Remote::Inet(remote @ SocketAddr::V4(_)) => cx.info(format_args!("  Trying {remote}...")),
        Remote::Inet(SocketAddr::V6(v6)) if v6.scope_id() != 0 => {
            let (ip, port, scope) = (v6.ip(), v6.port(), v6.scope_id());
            cx.info(format_args!("  Trying [{ip}]:{port} scope_id={scope}..."));
        }
        Remote::Inet(SocketAddr::V6(v6)) => {
            cx.info(format_args!("  Trying [{}]:{}...", v6.ip(), v6.port()));
        }
        Remote::Unix(_) => cx.info(format_args!("  Trying {}:0...", remote.shown_ip())),
    }
}

/// A socket set as the transfer asks, before the application's
/// configurer sees it (`tcpnodelay`, `tcpkeepalive`): a failure is
/// traced, and the socket goes on unset.
fn set_up(cx: &mut dyn ConnCx, socket: &dyn Socket, setup: SocketSetup) {
    let fd = socket.key().get();
    if setup.nodelay
        && let Err(e) = socket.set(SocketOption::NoDelay)
    {
        let why = OsError(&e);
        cx.of(
            Component::Tcp,
            format_args!("Could not set TCP_NODELAY: {why}"),
        );
    }
    let alive = setup.keepalive;
    if !alive.on {
        return;
    }
    // The times and count only once keepalive is on.
    let errno = |e: &io::Error| e.raw_os_error().unwrap_or(0);
    if let Err(e) = socket.set(SocketOption::KeepAlive) {
        let n = errno(&e);
        cx.of(
            Component::Tcp,
            format_args!("Failed to set SO_KEEPALIVE on fd {fd}: errno {n}"),
        );
        return;
    }
    let secs = |d: Duration| i32::try_from(d.as_secs()).unwrap_or(i32::MAX);
    let count = i32::try_from(alive.count).unwrap_or(i32::MAX);
    for (option, name) in [
        (SocketOption::KeepIdle(secs(alive.idle)), "TCP_KEEPIDLE"),
        (
            SocketOption::KeepInterval(secs(alive.interval)),
            "TCP_KEEPINTVL",
        ),
        (SocketOption::KeepCount(count), "TCP_KEEPCNT"),
    ] {
        if let Err(e) = socket.set(option) {
            let n = errno(&e);
            cx.of(
                Component::Tcp,
                format_args!("Failed to set {name} on fd {fd}: errno {n}"),
            );
        }
    }
}

/// The address an attempt to `ip` on `peer` connects to, and the scope
/// taken from a local interface for it, if one was. An IPv6 address is in
/// the application's scope, or else the peer's (`conn->scope_id`); a
/// link-local one with neither is in the first local interface's that
/// has a link-local address, as it is unreachable without one
/// (cf-socket.c's `get_scope_id`).
fn address(
    ip: IpAddr,
    peer: &Peer,
    given: Option<NonZeroU32>,
    net: &mut dyn Net,
) -> (SocketAddr, Option<NonZeroU32>) {
    let port = peer.port();
    let IpAddr::V6(v6) = ip else {
        return (SocketAddr::new(ip, port), None);
    };
    let scope = given.or(peer.scope());
    let found = match scope {
        None if v6.is_unicast_link_local() => net.link_local_scope(),
        _ => None,
    };
    let scope = scope.or(found).map_or(0, NonZeroU32::get);
    (SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope)), found)
}

/// The addresses `peer`'s name stands for, in the families `ip` allows:
/// from the cache, a shortcut or the resolver, kept in the cache.
fn resolve(
    peer: &Peer,
    ip: IpVersion,
    cx: &mut dyn ConnCx,
    setup: Setup,
) -> Result<(TryArc<Answer>, Found), ConnectError> {
    let family = family(ip, cx);
    resolve_name((peer.shown(), peer.name(), peer.port()), family, cx, setup)
}

/// The families a resolve in `ip` asks for: without IPv6 only IPv4's
/// (`Curl_resolv_dns_queries`).
fn family(ip: IpVersion, cx: &dyn ConnCx) -> Family {
    match ip {
        IpVersion::Any if cx.ipv6_works() => Family::Any,
        IpVersion::Any | IpVersion::V4 => Family::V4,
        IpVersion::V6 => Family::V6,
    }
}

/// The addresses of `family` the host `shown` stands for, as a URL shows
/// it, `name` without brackets, for a connection to `port`: from the
/// cache, a shortcut or the resolver, kept in the cache (`hostip_resolv`).
pub(super) fn resolve_name(
    (shown, name, port): (&[u8], &[u8], u16),
    family: Family,
    cx: &mut dyn ConnCx,
    setup: Setup,
) -> Result<(TryArc<Answer>, Found), ConnectError> {
    lookup_name((shown, name, port), family, cx, setup, true)
}

/// `resolve_name`, keeping that the name does not exist only if
/// `keep_negative`, as only the setup's own resolve does
/// (`Curl_dnscache_add_negative`); a resolver that answers later is
/// waited for, as C waits for these (`Curl_resolv_blocking`).
pub(super) fn lookup_name(
    (shown, name, port): (&[u8], &[u8], u16),
    family: Family,
    cx: &mut dyn ConnCx,
    setup: Setup,
    keep_negative: bool,
) -> Result<(TryArc<Answer>, Found), ConnectError> {
    match lookup_start((shown, name, port), family, cx, setup, keep_negative)? {
        Looked::Found(answer, found) => Ok((answer, found)),
        Looked::Pending(pending) => {
            let id = pending.id;
            let mut answer = None;
            cx.net().with_resolver(&mut |r| answer = Some(r.wait(id)));
            let answer = answer.expect("the network lends its resolver");
            settle(answer, (name, port), pending, cx)
        }
    }
}

/// Where a lookup stands: its answer, or a resolve the resolver answers
/// later.
pub(super) enum Looked {
    Found(TryArc<Answer>, Found),
    Pending(Pending),
}

/// A resolve the resolver answers later, and what its answer is to be.
#[derive(Debug)]
pub(super) struct Pending {
    pub(super) id: ResolveId,
    family: Family,
    /// Whether the cache had a stale answer.
    found: fn(Asked) -> Found,
    keep_negative: bool,
    /// Which families went as a query of their own, IPv6 and IPv4: in
    /// the padding, where a `Queued` would grow the setup's slot.
    queried: (bool, bool),
    held: Held,
}

/// A resolve held: one dropped neither answered nor cancelled leaves its
/// answer in the resolver for good, a bug, which aborts.
#[derive(Debug)]
struct Held;

impl Drop for Held {
    fn drop(&mut self) {
        assert!(
            std::thread::panicking(),
            "a resolve was dropped, neither answered nor cancelled"
        );
    }
}

impl Pending {
    /// Its answer taken, or the resolve cancelled: let go.
    fn done(self) -> (Family, fn(Asked) -> Found, bool) {
        std::mem::forget(self.held);
        (self.family, self.found, self.keep_negative)
    }

    /// How it was queued, if as queries of their own.
    fn queued(&self) -> Option<Queued> {
        let (v6, v4) = self.queried;
        (v6 || v4).then_some(Queued {
            id: self.id,
            v6,
            v4,
        })
    }
}

/// A lookup started: the cache, then the shortcuts, then the resolver,
/// whose answer may come later (`hostip_resolv_start`).
pub(super) fn lookup_start(
    (shown, name, port): (&[u8], &[u8], u16),
    family: Family,
    cx: &mut dyn ConnCx,
    setup: Setup,
    keep_negative: bool,
) -> Result<Looked, ConnectError> {
    if is_onion(name) {
        return Err(ConnectError::Unresolved(Unresolved::Onion));
    }
    if family == Family::V6 && cx.fails_ipv6_resolves() {
        return Err(ConnectError::Unresolved(Unresolved::DebugFailIpv6));
    }
    let now = cx.now();
    let ipv6 = cx.ipv6_works();
    let (wildcard, max_age) = (setup.wildcard, setup.max_age);
    let found: fn(Asked) -> Found = match cx
        .names()
        .section(|c| c.lookup((name, port), family, wildcard, max_age, now))
    {
        Lookup::Found(answer) => return Ok(Looked::Found(answer, Found::Cached)),
        Lookup::Negative => return Err(ConnectError::Unresolved(Unresolved::Negative)),
        Lookup::Stale => Found::Stale,
        Lookup::Missing => Found::Resolved,
    };
    let oom = |OutOfMemory| ConnectError::OutOfMemory;
    if let Some(answer) = shortcut(shown, name).map_err(oom)? {
        // Told though no resolver is asked, as C tells it.
        cx.announce_resolve()?;
        let answer = TryArc::try_new(answer).map_err(oom)?;
        cx.names()
            .section(|c| c.put(answer.clone(), port, now, false))
            .map_err(oom)?;
        return Ok(Looked::Found(answer, found(Asked::Shortcut)));
    }
    // A resolver is not asked for IPv6 addresses alone without IPv6
    // (`can_resolve_dns_queries`); nothing is kept of it.
    if family == Family::V6 && !ipv6 {
        return Err(ConnectError::Unresolved(Unresolved::NoIpv6));
    }
    cx.announce_resolve()?;
    let waiter = cx.waiter();
    let mut started = None;
    cx.net()
        .with_resolver(&mut |r| started = Some(r.start(name, family, waiter)));
    let pending = |q: Queued| Pending {
        id: q.id,
        queried: (q.v6, q.v4),
        family,
        found,
        keep_negative,
        held: Held,
    };
    match started.expect("the network lends its resolver") {
        Ok(Resolve::Pending(queued)) => Ok(Looked::Pending(pending(queued))),
        Ok(Resolve::Answer(addrs)) => {
            let at_once = pending(Queued::once(ResolveId::FIRST));
            let (answer, found) = settle(Ok(addrs), (name, port), at_once, cx)?;
            Ok(Looked::Found(answer, found))
        }
        Err(why) => Err(settle(
            Err(why),
            (name, port),
            pending(Queued::once(ResolveId::FIRST)),
            cx,
        )
        .expect_err("a failure settles as one")),
    }
}

/// The resolver's answer for `name` on `port`, as `pending` started it,
/// kept in the cache; that the name does not exist kept too, if the
/// lookup keeps negative answers.
pub(super) fn settle(
    answer: Result<Vec<IpAddr>, ResolveFailure>,
    (name, port): (&[u8], u16),
    pending: Pending,
    cx: &mut dyn ConnCx,
) -> Result<(TryArc<Answer>, Found), ConnectError> {
    let now = cx.now();
    let oom = |OutOfMemory| ConnectError::OutOfMemory;
    let queued = pending.queued();
    let (family, found, keep_negative) = pending.done();
    let refused = |why: ResolveFailure, cx: &mut dyn ConnCx| {
        let mut explained = None;
        cx.net().with_resolver(&mut |r| explained = r.explain(why));
        ConnectError::Unresolved(Unresolved::Resolver {
            why,
            queued,
            explained,
        })
    };
    let answer = match answer {
        Ok(addrs) => Answer::of(name, addrs, family).map_err(oom)?,
        Err(ResolveFailure::OutOfMemory) => return Err(ConnectError::OutOfMemory),
        Err(why @ (ResolveFailure::NotFound | ResolveFailure::NoData)) if keep_negative => {
            let none = Answer::of(name, Vec::new(), family).map_err(oom)?;
            let none = TryArc::try_new(none).map_err(oom)?;
            cx.names()
                .section(|c| c.put(none, port, now, false))
                .map_err(oom)?;
            return Err(refused(why, cx));
        }
        Err(why) => return Err(refused(why, cx)),
    };
    let answer = TryArc::try_new(answer).map_err(oom)?;
    cx.names()
        .section(|c| c.put(answer.clone(), port, now, false))
        .map_err(oom)?;
    Ok((answer, found(Asked::Resolver(queued))))
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

/// A name under `.onion`, with or without the root's dot, in any case,
/// which is never resolved (`hostip_resolv`, RFC 7686): `.onion` alone,
/// shorter than C looks, is not.
fn is_onion(name: &[u8]) -> bool {
    let ends = |tld: &[u8]| {
        name.len() >= 7
            && name.len() >= tld.len()
            && name[name.len() - tld.len()..].eq_ignore_ascii_case(tld)
    };
    ends(b".onion") || ends(b".onion.")
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
/// C's name for the address queries a resolve of `peer`'s name in `ip`
/// makes (`Curl_resolv_query_str`), with IPv6 working or not: an
/// address's own family is always asked for (`cf_dns_start`).
pub(crate) fn queries(peer: &Peer, ip: IpVersion, ipv6_works: bool) -> &'static str {
    let (mut a, mut aaaa) = match ip {
        IpVersion::Any => (true, ipv6_works),
        IpVersion::V4 => (true, false),
        IpVersion::V6 => (false, true),
    };
    match literal(peer.shown()) {
        Some(IpAddr::V4(_)) => a = true,
        Some(IpAddr::V6(_)) => aaaa = true,
        None => {}
    }
    match (a, aaaa) {
        (true, true) => "A+AAAA",
        (true, false) => "A",
        _ => "AAAA",
    }
}

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
            origin: TryArc::try_new(peer).unwrap(),
            via: None,
            ip,
            proxy: None,
            tls: None,
            local: None,
            delegation: Default::default(),
            dial: crate::conn::Dial::Tcp,
        };
        let mut m = ConnectMachine::new(
            ConnNumber(0),
            route,
            start,
            Closer::System,
            ConnSettings::DEFAULT,
        );
        m.stage = Stage::Racing(Racing {
            eyeballs: Eyeballs::new(
                Addresses::Resolved(
                    TryArc::try_new(Answer::new(b"abc.test", addrs).unwrap()).unwrap(),
                ),
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
                wildcard: false,
                max_age: Some(Duration::from_secs(60)),
                delay: he,
                scope: None,
                socket: SocketSetup::PLAIN,
                haproxy: false,
                layer: None,
                linger: None,
            };
            let mut cx = Plain {
                net: &mut net,
                dns: &mut DnsCache::default(),
                now: clock.now(),
            };
            match m.drive(&mut cx, setup) {
                Ok(Drove::Connecting(next, progress)) => {
                    m = next;
                    raced.most_running = raced.most_running.max(m.sockets().count());
                    match progress {
                        Progress::Trying {
                            remote: Remote::Inet(SocketAddr::V4(_)),
                            ..
                        } => raced.v4_starts.push(ms),
                        Progress::Trying {
                            remote: Remote::Inet(SocketAddr::V6(_)),
                            ..
                        } => raced.v6_starts.push(ms),
                        Progress::Trying {
                            remote: Remote::Unix(_),
                            ..
                        } => unreachable!("no Unix socket"),
                        Progress::Failed => {}
                        Progress::Waiting { .. } => clock.advance(Duration::from_millis(1)),
                        Progress::Resolved(_) | Progress::Resolving { .. } => {
                            unreachable!("resolved already")
                        }
                        Progress::Dialed => unreachable!("no proxy"),
                    }
                }
                Ok(Drove::Established(conn)) => panic!("{conn:?}"),
                Err(ConnectError::Failed(..)) => {
                    raced.failed_at = ms;
                    assert_eq!(net.open_sockets(), 0, "every attempt closed");
                    return raced;
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        panic!("no end: {raced:?}");
    }

    /// A setup to `late.test`, whose answer `late` holds, driven once: its
    /// resolve waits.
    fn waiting_for(late: &crate::conn::io::Late) -> (ConnectMachine, FakeNet) {
        let clock = ManualClock::new().unwrap();
        let mut net =
            FakeNet::new(clock.clone()).with_late_name("late.test", &[[127, 0, 0, 1].into()], late);
        let scheme = Scheme {
            name: "http",
            reuse: true,
        };
        let peer = Peer::new(scheme, b"late.test".to_vec(), 123, None);
        let route = Tcp {
            origin: TryArc::try_new(peer).unwrap(),
            via: None,
            ip: IpVersion::Any,
            proxy: None,
            tls: None,
            local: None,
            delegation: Default::default(),
            dial: crate::conn::Dial::Tcp,
        };
        let m = ConnectMachine::new(
            ConnNumber(0),
            route,
            clock.now(),
            Closer::System,
            ConnSettings::DEFAULT,
        );
        let setup = Setup {
            wildcard: false,
            max_age: Some(Duration::from_secs(60)),
            delay: Duration::from_millis(200),
            scope: None,
            socket: SocketSetup::PLAIN,
            haproxy: false,
            layer: None,
            linger: None,
        };
        let mut cx = Plain {
            net: &mut net,
            dns: &mut DnsCache::default(),
            now: clock.now(),
        };
        let m = match m.drive(&mut cx, setup) {
            Ok(Drove::Connecting(m, Progress::Resolving { retry: None })) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(net.resolving(), 1);
        (m, net)
    }

    /// A route that dials QUIC opens a socket for datagrams for each
    /// attempt, set as QUIC's are, and one over TCP a stream; TCP's
    /// options are set on a stream alone (`cf_socket_open`'s `is_tcp`).
    /// With no HTTP/3 library, the QUIC attempt fails once its socket is
    /// set.
    #[test]
    fn a_route_over_quic_opens_a_socket_for_datagrams() {
        for (dial, datagrams) in [(crate::conn::Dial::Tcp, 0), (crate::conn::Dial::Quic, 1)] {
            let clock = ManualClock::new().unwrap();
            let at: IpAddr = [127, 0, 0, 1].into();
            let wire = crate::conn::io::Conversation::new(b"", false);
            let mut net = FakeNet::new(clock.clone())
                .with_name("quic.test", &[at])
                .with_peer(SocketAddr::new(at, 443), FakePeer::Silent)
                .with_conversation(SocketAddr::new(at, 443), wire.clone());
            let scheme = Scheme {
                name: "https",
                reuse: true,
            };
            let peer = Peer::new(scheme, b"quic.test".to_vec(), 443, None);
            let route = Tcp {
                origin: TryArc::try_new(peer).unwrap(),
                via: None,
                ip: IpVersion::Any,
                proxy: None,
                tls: None,
                local: None,
                delegation: Default::default(),
                dial,
            };
            let mut m = Some(ConnectMachine::new(
                ConnNumber(0),
                route,
                clock.now(),
                Closer::System,
                ConnSettings::DEFAULT,
            ));
            let setup = Setup {
                wildcard: false,
                max_age: Some(Duration::from_secs(60)),
                delay: Duration::from_millis(200),
                scope: None,
                socket: SocketSetup {
                    nodelay: true,
                    keepalive: KeepAlive {
                        on: true,
                        ..KeepAlive::DEFAULT
                    },
                    fastopen: true,
                },
                haproxy: false,
                layer: None,
                linger: None,
            };
            let mut dns = DnsCache::default();
            for _ in 0..10 {
                let mut cx = Plain {
                    net: &mut net,
                    dns: &mut dns,
                    now: clock.now(),
                };
                match m
                    .take()
                    .expect("driven while it sets up")
                    .drive(&mut cx, setup)
                {
                    Ok(Drove::Connecting(next, Progress::Trying { .. })) => {
                        m = Some(next);
                        break;
                    }
                    Ok(Drove::Connecting(next, _)) => m = Some(next),
                    Err(ConnectError::Failed(None, ErrorKind::QuicConnectError))
                        if dial == crate::conn::Dial::Quic =>
                    {
                        break;
                    }
                    other => panic!("{other:?}"),
                }
            }
            assert_eq!(net.datagram_sockets(), datagrams, "{dial:?}");
            let options = wire.options();
            match dial {
                crate::conn::Dial::Tcp => {
                    assert_eq!(net.open_sockets(), 1);
                    assert!(options.contains(&SocketOption::NoDelay), "{options:?}");
                    assert!(options.contains(&SocketOption::KeepAlive), "{options:?}");
                    assert!(
                        options.contains(&SocketOption::FastOpenConnect),
                        "{options:?}"
                    );
                    m.expect("still trying").close(&mut net);
                }
                crate::conn::Dial::Quic => {
                    assert_eq!(net.open_sockets(), 0, "the failed attempt's closed");
                    let quic = [
                        SocketOption::ReceiveEcn,
                        SocketOption::DiscoverMtu,
                        SocketOption::ReceiveJoined,
                    ];
                    assert_eq!(options, quic);
                }
            }
        }
    }

    /// A setup closed while its resolve waits cancels it.
    #[test]
    fn a_closed_setup_cancels_its_resolve() {
        let late = crate::conn::io::Late::new();
        let (m, mut net) = waiting_for(&late);
        m.close(&mut net);
        assert_eq!(net.resolving(), 0);
    }

    /// A setup dropped while its resolve waits, neither answered nor
    /// cancelled, is a bug: its answer would stay in the resolver.
    #[test]
    #[should_panic = "neither answered nor cancelled"]
    fn a_dropped_pending_resolve_is_caught() {
        let late = crate::conn::io::Late::new();
        let (m, _net) = waiting_for(&late);
        drop(m);
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
            origin: TryArc::try_new(peer).unwrap(),
            via: None,
            ip: IpVersion::Any,
            proxy: None,
            tls: None,
            local: None,
            delegation: Default::default(),
            dial: crate::conn::Dial::Tcp,
        };
        let mut m = ConnectMachine::new(
            ConnNumber(0),
            route,
            clock.now(),
            Closer::System,
            ConnSettings::DEFAULT,
        );
        let he = Duration::from_millis(200);
        let mut dns = DnsCache::default();
        let conn = loop {
            let setup = Setup {
                wildcard: false,
                max_age: Some(Duration::from_secs(60)),
                delay: he,
                scope: None,
                socket: SocketSetup::PLAIN,
                haproxy: false,
                layer: None,
                linger: None,
            };
            let mut cx = Plain {
                net: &mut net,
                dns: &mut dns,
                now: clock.now(),
            };
            match m.drive(&mut cx, setup).unwrap() {
                Drove::Connecting(next, progress) => {
                    m = next;
                    if let Progress::Waiting { .. } = progress {
                        clock.advance(Duration::from_millis(1));
                    }
                }
                Drove::Established(conn) => break conn,
            }
        };
        assert_eq!(conn.remote, Some(Remote::Inet(up)));
        assert_eq!(net.open_sockets(), 1, "the winner's alone");
        let Transport::Tcp(stream) = conn.transport else {
            panic!("over the network");
        };
        net.close(stream.into_socket());
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
        let answer = || {
            Addresses::Resolved(
                TryArc::try_new(Answer::new(b"a.test", addrs.to_vec()).unwrap()).unwrap(),
            )
        };
        let order = |mut e: Eyeballs| {
            std::iter::from_fn(move || e.next())
                .map(|c| match c {
                    Candidate::Ip(ip) => ip,
                    Candidate::Unix => panic!("an answer has addresses"),
                })
                .collect::<Vec<_>>()
        };
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
        let literal = Addresses::Resolved(
            TryArc::try_new(Answer::new(b"1.1.1.1", vec![ip("1.1.1.1")]).unwrap()).unwrap(),
        );
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
