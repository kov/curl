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

use super::asyncs::{Holder, ResolveNumber};
use super::bind::{BindFailed, bind_local};
use super::chain::SetupPoint;
#[cfg(test)]
use super::dns::DnsCache;
use super::dns::{Answer, Lookup, Names};
use super::h3proxy::H3Proxy;
use super::io::{
    Closer, Connect, DnsRefused, DnsResolve, Events, Family, Net, Partial, Remote, Resolve,
    ResolveFailure, Resolving, Sock, Socket, SocketKind, SocketOption, SocketPoll, UnixPeer,
    Waiter,
};
use super::layer::{LayerAnswer, LayerCx, LayerQuery};
use super::quic::Quic;
use super::shutdown::ConnSettings;
use super::{Conn, ConnNumber, Dial, Dialing, NetRoute, Peer, Route, Stream, Transport, Use};
use crate::components::Component;
use crate::conn::layer::LayerCalls as _;
use crate::error::{AGAIN_NUMBER, ErrorKind};
use crate::handler::Configured;
use crate::http3::Flavour;
use crate::multi::doh::{Lookup as DohLookup, Polled as DohPolled};
use crate::multi::state::ConnRank;
use crate::options::{IpVersion, KeepAlive, Sockets};
use crate::time::Instant;
use crate::trace::{Ip, Line};
use curl_os::error::ErrorText;

/// A connection being set up.
#[derive(Debug)]
pub(crate) struct ConnectMachine {
    number: ConnNumber,
    route: NetRoute,
    /// How it dials the route's first hop.
    dial: Dial,
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
    /// The handshake under way over the connection to its first hop, once
    /// connected: a proxy's, the PROXY line or TLS. It goes with the
    /// machine.
    pub(crate) handshake: Option<Box<crate::multi::state::Handshake>>,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the dialed connection is held inline: boxed, each connection's setup would \
              make one allocation more"
)]
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
    /// Its end here, as the system said as it connected (C's
    /// `ctx->ip.local_*`): what the handshakes over it and a failure's
    /// report read, none asking again.
    local: Option<SocketAddr>,
    connected_at: Instant,
    /// The addresses raced to reach the proxy, raced again on a redial.
    answer: Addresses,
    /// The destination's addresses, for a SOCKS proxy that is not to
    /// resolve its name.
    target: SocksTarget,
    /// Its resolve, while it goes on (its own DNS filter's, below the
    /// setup's): `target` then says nothing yet.
    target_late: Option<Pending>,
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

/// What a setup says of its peer's answer (`CF_QUERY_CONNECT_REPLY_MS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    /// Racing, its happy eyeballs filter answers, and says so: the
    /// milliseconds its first QUIC attempt took to hear from its peer, if
    /// one has.
    Racing(Option<i64>),
    /// Dialed, the filter connected, the first hop answers, saying
    /// nothing: whether it has heard from its peer.
    Dialed(bool),
}

/// The handshakes made over a dialed connection, each once, in
/// cf-setup.c's order: SOCKS's and the tunnel's stay in C's chain as
/// filters that pass the bytes (`[H1-PROXY][SOCKS][TCP]`); the PROXY
/// line's filter goes once the chain is connected; the origin's TLS stays
/// as the layer on top (`[SSL][TCP]`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Made {
    /// The SOCKS proxy's.
    pub(crate) socks: bool,
    /// An HTTPS proxy's TLS, which stays as a layer below what follows
    /// (`[SSL-PROXY][TCP]`).
    pub(crate) proxy_tls: bool,
    /// The tunnel through the HTTP proxy, and what it is a stream of.
    pub(crate) tunnel: Option<Tunneled>,
    /// The PROXY protocol's line.
    pub(crate) preface: bool,
    /// The origin's TLS.
    pub(crate) tls: bool,
    /// The origin's QUIC connection through a CONNECT-UDP tunnel
    /// (`[HTTP/3][CAPSULE]`), in place of its TLS.
    pub(crate) quic: bool,
    /// The SOCKS proxy's target's DNS filter, made before the setup was
    /// started over: C's sits above the setup's, which a redial leaves as
    /// it is, so it is neither made nor started again.
    pub(crate) target_filter: bool,
}

/// What a tunnel through an HTTP proxy is a stream of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tunneled {
    /// The connection to the proxy itself, spoken to in HTTP/1
    /// (`[H1-PROXY]`).
    H1,
    /// An HTTP/2 session with the proxy (`[H2-PROXY]`).
    H2,
    /// A QUIC connection to an HTTP/3 proxy (`[H3-PROXY]`).
    H3,
}

/// One handshake made over a dialed connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Handshook {
    Socks,
    ProxyTls,
    Tunnel(Tunneled),
    Preface,
    Tls,
    Quic,
}

impl Made {
    /// With `which` made, which was not before: each is made once.
    pub(crate) fn with(mut self, which: Handshook) -> Made {
        let fresh = match which {
            Handshook::Socks => !std::mem::replace(&mut self.socks, true),
            Handshook::ProxyTls => !std::mem::replace(&mut self.proxy_tls, true),
            Handshook::Tunnel(over) => self.tunnel.replace(over).is_none(),
            Handshook::Preface => !std::mem::replace(&mut self.preface, true),
            Handshook::Tls => !std::mem::replace(&mut self.tls, true),
            Handshook::Quic => !std::mem::replace(&mut self.quic, true),
        };
        assert!(fresh, "{which:?} is made once");
        self
    }
}

impl Dialed {
    /// The handshakes made over it so far.
    pub(crate) fn made(&self) -> Made {
        self.made
    }

    /// The handshake `which` is made.
    pub(crate) fn mark_made(&mut self, which: Handshook) {
        self.made = self.made.with(which);
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
    pub(crate) fn target(&self) -> &SocksTarget {
        &self.target
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
        (self.remote.clone(), self.local)
    }

    /// The proxy's address.
    pub(crate) fn remote(&self) -> &Remote {
        &self.remote
    }
}

/// The most attempts running at once (`IP_HE_MAX_CONCURRENT_ATTEMPTS`).
pub(crate) const MAX_ATTEMPTS: usize = 6;

/// The attempts of a setup (C's `cf_ip_ballers`): each starts when the
/// one before has failed, or has run the happy eyeballs delay without
/// connecting, while an address is left.
#[derive(Debug)]
struct Racing {
    /// Its first run was made (`cf_ip_happy_init`), whether or not it had
    /// an address to start.
    ran: bool,
    /// How the last attempt failed, while more addresses may come.
    last_failed: Option<(Option<io::Error>, ErrorKind)>,
    eyeballs: Eyeballs,
    /// The attempts running, oldest first.
    attempts: Vec<Attempt>,
    /// When the last attempt started.
    last_start: Option<Instant>,
    /// The SOCKS proxy's target's addresses, found before the setup was
    /// started over: kept by their DNS filter, above the setup's, which a
    /// redial leaves as it is (`cf_setup_connect`).
    target: Option<SocksTarget>,
}

/// What a drive reaches while it works, as C's connection filters reach
/// the transfer they connect for: the time and the transfer's trace
/// (`LayerCx`), the network, and the names kept. A transfer's step
/// gives one over its own context (`DriveCx`); it is an argument, never
/// stored.
pub(crate) trait ConnCx: LayerCx {
    fn net(&mut self) -> &mut dyn Net;

    /// What a QUIC attempt is made with, if the transfer has an HTTP/3
    /// library.
    fn quic_making(&mut self) -> Result<Option<QuicMaking>, OutOfMemory>;

    /// What the setup knows of the origin's HTTPS record as its QUIC
    /// attempt is made, which the origin's TLS takes its ECH
    /// configurations from (`Curl_conn_dns_resolved_https`,
    /// `Curl_conn_dns_get_https`).
    fn https_record(&self) -> OriginRecord;

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

    /// Why the transfer fails, made of `parts`, kept if nothing said so
    /// before (`failf`). The parts need not be text: bytes of the
    /// application's or the system's are said as they are.
    fn fail_with(&mut self, parts: &[&[u8]]);

    /// Let go of the reason kept, as the race starts an attempt or ends
    /// (`Curl_reset_fail`): what an attempt said is not why the transfer
    /// fails.
    fn reset_fail(&mut self);

    /// Tell the application a resolve starts, if it asked to hear of
    /// it: it may stop it (`Curl_resolv_announce_start`).
    fn announce_resolve(&mut self) -> Result<(), ConnectError>;

    /// The transfer wants its names resolved over DoH (`set.doh`).
    fn wants_doh(&self) -> bool;

    /// Put `addrs` in a random order, with the handle's random bytes, if
    /// the transfer asks for it (`CURLOPT_DNS_SHUFFLE_ADDRESSES`), as the
    /// entry they go in is made (`dnsc_entry_assign_addr`); whether they
    /// were shuffled, which the caller says where C says it.
    fn shuffle(&mut self, addrs: &mut [IpAddr]) -> Result<bool, OutOfMemory>;

    /// Whether the transfer has a resolver library.
    fn has_dns_library(&self) -> bool;

    /// How long a blocking resolve begun at `since` may still be waited
    /// for, read from the clock now; none once its time is up
    /// (`Curl_timeleft_ms`, `CURL_TIMEOUT_RESOLVE_MS`).
    fn await_resolve_left(&mut self, since: Instant) -> Option<Duration>;

    /// The application hears of the transfer's progress while a blocking
    /// resolve waits, and may stop it (`Curl_pgrsUpdate`).
    #[allow(clippy::result_unit_err)]
    fn await_resolve_tick(&mut self) -> Result<(), ()>;

    /// The sockets the transfer's libraries closed are told, as soon as a
    /// library is back from its work (`Curl_multi_will_close`).
    fn libraries_closed(&mut self);

    /// The resolve of `name` in `family` by the transfer's resolver library,
    /// if it has one (`Curl_async_getaddrinfo`).
    fn dns_start(
        &mut self,
        name: &[u8],
        port: u16,
        family: Family,
    ) -> Option<Result<Box<dyn DnsResolve>, DnsRefused>>;

    /// The resolve of `name` in `family` over DoH started (`Curl_doh`).
    fn doh_start(&mut self, name: &[u8], family: Family) -> Result<DohLookup, ConnectError>;

    /// The number of the transfer the setup is for, as its lines name
    /// it, 0 before it has one.
    fn transfer_number(&self) -> u64;

    /// Which of the transfer's connections the setup is for.
    fn rank(&self) -> ConnRank;

    /// A record kept on the transfer of a resolve that answers later, for
    /// `holder`, numbered by the multi (`hostip_async_new`).
    fn resolve_kept(&mut self, holder: Holder) -> Result<(), OutOfMemory>;

    /// The newest of `holder`'s let go of (`Curl_async_destroy`).
    fn resolve_gone(&mut self, holder: Holder);

    /// The newest of `holder`'s told it is not wanted, its answer found
    /// in the cache meanwhile (`Curl_async_shutdown`).
    fn resolve_shut(&mut self, holder: Holder);

    /// The newest of `holder`'s answered by a resolver library, whose
    /// channel stays open until the record goes (`Curl_async_pollset`).
    fn resolve_answered_by_library(&mut self, holder: Holder);

    /// The number of the newest of `holder`'s, if one is kept.
    fn resolve_number(&self, holder: Holder) -> Option<ResolveNumber>;

    /// `holder`'s DNS filter, on the chain of the setup's rank, has the
    /// entry its resolve answered with, until the filter goes
    /// (`Holds`).
    fn hold(&mut self, holder: Holder);
}

/// What a setup knows of the origin's HTTPS record
/// (`Curl_conn_dns_resolved_https`, `Curl_conn_dns_get_https`).
#[derive(Clone, Debug)]
pub(crate) enum OriginRecord {
    /// Asked for, its answer still to come.
    Coming,
    /// Known, or not asked for: the record, if the origin has one.
    Known(Option<TryArc<crate::doh::HttpsRecord>>),
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

    fn trace(&mut self) -> Option<&mut dyn crate::conn::layer::Trace> {
        None
    }

    fn failures(&mut self) -> Option<&mut dyn crate::conn::layer::Failures> {
        None
    }

    fn transfer(&mut self) -> Option<&mut dyn crate::conn::layer::ForTransfer> {
        None
    }

    fn tls_sessions(&mut self) -> Option<&mut dyn crate::conn::layer::TlsSessions> {
        None
    }

    fn early_data(&mut self) -> Option<&mut dyn crate::conn::layer::EarlyData> {
        None
    }

    fn quic_timer(&mut self) -> Option<&mut dyn crate::conn::layer::QuicTimer> {
        None
    }

    fn h3_streams(&mut self) -> Option<&mut dyn crate::conn::layer::H3Streams> {
        None
    }

    fn recv_room(&mut self) -> Option<&mut crate::conn::quic::RecvRoom> {
        None
    }

    fn recv_buf(&mut self) -> Option<&mut crate::conn::buf::XferBuf> {
        None
    }
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

    fn https_record(&self) -> OriginRecord {
        OriginRecord::Known(None)
    }

    fn names(&mut self) -> Names<'_> {
        Names::Own {
            cache: self.dns,
            now: self.now,
        }
    }

    fn ipv6_works(&self) -> bool {
        true
    }

    fn transfer_number(&self) -> u64 {
        0
    }

    fn rank(&self) -> ConnRank {
        ConnRank::First
    }

    fn resolve_kept(&mut self, _: Holder) -> Result<(), OutOfMemory> {
        Ok(())
    }

    fn resolve_gone(&mut self, _: Holder) {}

    fn resolve_shut(&mut self, _: Holder) {}

    fn resolve_answered_by_library(&mut self, _: Holder) {}

    fn resolve_number(&self, _: Holder) -> Option<ResolveNumber> {
        None
    }

    fn hold(&mut self, _: Holder) {}

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

    fn fail_with(&mut self, _: &[&[u8]]) {}

    fn reset_fail(&mut self) {}

    fn wants_doh(&self) -> bool {
        false
    }

    fn shuffle(&mut self, _: &mut [IpAddr]) -> Result<bool, OutOfMemory> {
        Ok(false)
    }

    fn doh_start(&mut self, _: &[u8], _: Family) -> Result<DohLookup, ConnectError> {
        unreachable!("a plain setup wants no DoH");
    }

    fn announce_resolve(&mut self) -> Result<(), ConnectError> {
        Ok(())
    }

    fn has_dns_library(&self) -> bool {
        false
    }

    fn await_resolve_left(&mut self, _: Instant) -> Option<Duration> {
        None
    }

    fn await_resolve_tick(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn libraries_closed(&mut self) {}

    fn dns_start(
        &mut self,
        _: &[u8],
        _: u16,
        _: Family,
    ) -> Option<Result<Box<dyn DnsResolve>, DnsRefused>> {
        None
    }
}

/// What a drive needs beyond its context: the settings of the transfer
/// it is driven for.
#[derive(Clone, Copy)]
pub(crate) struct DriveOptions {
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
    /// Kept by another transfer while this one's resolve went on, and
    /// taken from the cache, its lines said as it was
    /// (`Curl_resolv_take_result`).
    Meanwhile,
}

/// The destination's addresses, as a setup found them for a SOCKS proxy.
#[derive(Clone, Debug)]
pub(crate) enum SocksTarget {
    /// The proxy resolves the name itself, or there is no SOCKS proxy.
    None,
    /// The name was looked up here and did not resolve.
    Unresolved,
    /// The name's addresses; where they came from was said as they were
    /// looked up.
    Found(TryArc<Answer>),
}

/// What answered a name the cache did not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Asked {
    /// The name is an address, or `localhost`: no resolver was asked.
    Shortcut,
    /// A resolver, which queued its queries as `.0` says, if it did.
    Resolver(Option<Queued>),
    /// DoH's transfers, a library or a resolver whose lines were said as
    /// it started and went on: only its answer is left to say.
    Doh,
    /// A library that had the answer as its resolve started, taken there
    /// and said with the start: only its keeping is left to say.
    InStart,
}

/// What a setup's attempts connect to: the addresses a name resolved to,
/// or the Unix socket the route's first hop is, its one address
/// (`Curl_unix2addr`). A pointer's size, as the setup's slot holds it.
#[derive(Clone, Debug)]
pub(crate) enum Addresses {
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
    /// The name's resolve is still going on, the race having only what
    /// came of it so far (`Curl_resolv_get_ai`): as the setup's [`Late`]
    /// said as the race was last moved on.
    resolving: bool,
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
            resolving: false,
            v6: 0,
            v4: 0,
            last_v4: true,
            use_v6: any || ip == IpVersion::V6,
            use_v4: any || ip == IpVersion::V4,
        }
    }

    /// Whether a resolve still going on may give more addresses.
    fn coming(&self) -> bool {
        self.resolving
    }

    /// What the name's resolve, `name`, has found by now, and whether more
    /// may come: every attempt of the setup asks the one DNS filter above
    /// them (`Curl_conn_dns_get_ai`).
    fn follow(&mut self, name: &Late) {
        if let Some(answer) = name.answer() {
            self.answer = Addresses::Resolved(answer.clone());
        }
        self.resolving = name.going();
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

    /// Whether the `n`th address of IPv6 if `v6`, else of IPv4 (a Unix
    /// socket's one), is there: C's race asks its DNS filter, which traces
    /// the question (`Curl_conn_dns_get_ai`). A Unix socket has no IPv6
    /// addresses to ask for.
    fn ask(&self, cx: &mut dyn LayerCx, of: Asking<'_>, v6: bool, n: usize) -> bool {
        let (family, there) = match &self.answer {
            Addresses::Unix if v6 => return false,
            Addresses::Unix => (AF_UNIX, n == 0),
            Addresses::Resolved(_) => (
                if v6 { AF_INET6 } else { AF_INET },
                self.nth(v6, n).is_some(),
            ),
        };
        if !cx.traces(Component::DnsFilter) {
            return there;
        }
        let mut line = Line::new();
        line.text(format_args!("get {n}th result for "))
            .raw(of.name)
            .text(format_args!(
                ":{}, family={family}, dns={}",
                of.port,
                u8::from(!self.coming())
            ));
        cx.of_with(Component::DnsFilter, &[line.bytes()]);
        there
    }

    /// Whether an address is left to try, IPv4's asked first
    /// (`cf_ai_iter_has_more`).
    fn more_asked(&self, cx: &mut dyn LayerCx, of: Asking<'_>) -> bool {
        self.ask(cx, of, false, self.v4) || self.ask(cx, of, true, self.v6)
    }

    /// The address to try next, if one is left, the families alternating,
    /// IPv6 first, as C's race looks for it (`cf_ip_ballers_run`).
    fn next(&mut self, cx: &mut dyn LayerCx, of: Asking<'_>) -> Option<Candidate> {
        let he = Component::HappyEyeballs;
        cx.of(he, format_args!("want to do more"));
        let said = |found: bool| if found { "found" } else { "none" };
        if self.last_v4 || !self.ask(cx, of, false, self.v4) {
            let found = self.ask(cx, of, true, self.v6);
            let shown = said(found);
            cx.of(he, format_args!("check for next AAAA address: {shown}"));
            if found {
                let a = self.nth(true, self.v6).expect("asked");
                self.v6 += 1;
                self.last_v4 = false;
                return Some(Candidate::Ip(a));
            }
        }
        let found = self.ask(cx, of, false, self.v4);
        let shown = said(found);
        cx.of(he, format_args!("check for next A address: {shown}"));
        if !found {
            return None;
        }
        self.v4 += 1;
        // A Unix socket's family is its own, not IPv4's
        // (`last_attempt_ai_family`).
        self.last_v4 = !matches!(self.answer, Addresses::Unix);
        match &self.answer {
            // Counted among IPv4's, as C's family is not IPv6's.
            Addresses::Unix => Some(Candidate::Unix),
            Addresses::Resolved(_) => self.nth(false, self.v4 - 1).map(Candidate::Ip),
        }
    }

    /// Whether an address is left to try, asking no one: the answer, as
    /// it comes, has one.
    fn more(&self) -> bool {
        match &self.answer {
            Addresses::Unix => self.v4 == 0,
            Addresses::Resolved(_) => {
                self.nth(true, self.v6).is_some() || self.nth(false, self.v4).is_some()
            }
        }
    }
}

/// What `route`'s race asks its addresses for.
fn asking(route: &NetRoute) -> Asking<'_> {
    let peer = route.destination();
    Asking {
        name: peer.name(),
        port: if peer.is_unix() { 0 } else { peer.port() },
    }
}

/// The peer a race asks its addresses for, as C's trace names it: its
/// name and port, a Unix socket's path and 0.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Asking<'a> {
    name: &'a [u8],
    port: u16,
}

// The address families as C's trace numbers them, Linux's.
const AF_UNIX: u8 = 1;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// A socket connecting to one address, and over it what decides the
/// attempt (C's `cf_ip_attempt` and its filter).
#[derive(Debug)]
struct Attempt {
    remote: Remote,
    socket: Sock,
    /// Its end here, as the system said when last asked (C's
    /// `ctx->ip.local_*`, which `set_local_ip` sets): as its connect
    /// started, and again as it connected.
    local: Option<SocketAddr>,
    link: Link,
}

/// What an attempt makes over its socket.
#[derive(Debug)]
enum Link {
    /// Its connect alone: TCP's, or a Unix socket's.
    Connect,
    /// A QUIC connection, decided by its handshake.
    Quic(Box<Quic>),
    /// The origin's QUIC connection before it is made, waiting for the
    /// origin's HTTPS record.
    Record(RecordWait),
    /// The tunnel through an HTTP/3 proxy, over the QUIC connection to
    /// it, its handshake done: decided as the proxy answers its
    /// `CONNECT`, the attempt being C's H3-PROXY filter
    /// (`cf_h3_proxy_connect`).
    Tunnel(Box<H3Proxy>),
}

impl Link {
    /// The QUIC connection it holds, if it is over QUIC and made.
    fn quic(&self) -> Option<&Quic> {
        match self {
            Link::Connect | Link::Record(_) => None,
            Link::Quic(q) => Some(q),
            Link::Tunnel(t) => Some(t.quic()),
        }
    }

    /// What its socket waits for: a TCP connect to write, a QUIC
    /// connection what it says (`cf_ngtcp2_adjust_pollset`); one not made
    /// yet, what the UDP socket's filter asks of a socket that is not
    /// the connection's yet (`adjust_pollset, !active, POLLIN`).
    fn wants(&self) -> Events {
        match self {
            Link::Connect => Events::OUT,
            Link::Quic(q) => q.wants(),
            Link::Tunnel(t) => t.quic().wants(),
            Link::Record(_) => Events::IN,
        }
    }
}

/// The origin's QUIC attempt whose UDP socket is connected, its QUIC
/// connection not made until the origin's HTTPS record is known: the
/// origin's TLS takes its ECH configurations from the record
/// (`Curl_ssl_need_httpsrr`, `need HTTPS-RR, delaying connect`). The
/// socket is the attempt's; this holds the ends it connects.
#[derive(Debug)]
struct RecordWait {
    local: SocketAddr,
    remote: SocketAddr,
}

impl RecordWait {
    /// What the origin's QUIC filter says as it puts its connect off.
    fn delays(cx: &mut dyn ConnCx) {
        cx.of(
            Component::Http3,
            format_args!("need HTTPS-RR, delaying connect"),
        );
    }

    /// Whether the origin's QUIC connection over `route` waits for the
    /// origin's record: its ECH is to take its configurations from it,
    /// which is still to come. A proxy's TLS takes none.
    fn needed(route: &NetRoute, cx: &dyn ConnCx) -> bool {
        !route.proxy_over_quic()
            && route
                .start_tls()
                .is_some_and(|t| t.options.ech.needs_record())
            && matches!(cx.https_record(), OriginRecord::Coming)
    }
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
    /// again (`EXPIRE_ASYNC_NAME`); or until `aaaa`, when what came is
    /// connected to though AAAA has not (`EXPIRE_HAPPY_EYEBALLS`, which
    /// stays armed as the race begins).
    Resolving {
        retry: Option<Instant>,
        aaaa: Option<Instant>,
    },
    /// Connected to the first hop, over which handshakes are to be made
    /// (`ConnLease::dialed`).
    Dialed,
    /// An attempt's QUIC connection to an HTTP/3 proxy is up: its
    /// tunnel's `CONNECT` is to go now, the attempt racing on until the
    /// proxy answers; the next attempt is due at `until`, as `Waiting`
    /// has it.
    Tunnel { until: Option<Instant> },
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
    /// A resolver library refused to start, its words said.
    Refused(ErrorKind),
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
        /// DoH's transfers said it: the lookup's lines were said as it
        /// started.
        over_doh: bool,
        /// It said its lines as it went, none left to say for it now.
        says_its_own: bool,
        /// A resolver library's status, which its trace numbers.
        library_status: Option<i32>,
        /// A library's failure taken inside the start of its resolve,
        /// whose record, this holder's, goes as the failure is said.
        in_start: Option<Holder>,
    },
    /// A blocking resolve was given up on: its time ran out, or the
    /// application stopped it.
    GaveUp,
    /// It said so before, and the cache kept its word.
    Negative,
    /// Another transfer found that it does not exist while this one's
    /// resolve went on, and the cache kept its word, found as the answer
    /// was taken (`Curl_resolv_take_result`'s `Curl_async_failed`).
    NegativeMeanwhile,
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
    /// through `closer`. Its TLS is made (`NetRoute::made`): a connection
    /// keeps the identities it was made with.
    pub(crate) fn new(
        number: ConnNumber,
        route: NetRoute,
        dial: Dial,
        created: Instant,
        closer: Closer,
        settings: ConnSettings,
    ) -> ConnectMachine {
        assert!(route.is_made(), "a connection is set up over a route made");
        ConnectMachine {
            number,
            route,
            dial,
            created,
            stage: Stage::Resolving(None),
            redials: 0,
            closer,
            settings,
            handshake: None,
        }
    }

    /// A second attempt of the same setup over `route`, another way of
    /// dialing, racing the addresses `answer` holds, which the first
    /// resolved (C's HTTPS connect filter's second baller, below the
    /// name's filter that holds its answer).
    pub(crate) fn racing(
        number: ConnNumber,
        route: NetRoute,
        dial: Dial,
        created: Instant,
        closer: Closer,
        settings: ConnSettings,
        answer: Addresses,
    ) -> ConnectMachine {
        assert!(route.is_made(), "a connection is set up over a route made");
        let eyeballs = Eyeballs::new(answer, route.ip());
        ConnectMachine {
            number,
            route,
            dial,
            created,
            stage: Stage::Racing(Racing {
                ran: false,
                last_failed: None,
                eyeballs,
                attempts: Vec::new(),
                last_start: None,
                target: None,
            }),
            redials: 0,
            closer,
            settings,
            handshake: None,
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

    pub(crate) fn route(&self) -> &NetRoute {
        &self.route
    }

    /// How it dials the route's first hop.
    pub(crate) fn dial(&self) -> Dial {
        self.dial
    }

    /// Dial as `dial`, the attempts not started: the HTTPS connect filter
    /// has chosen.
    pub(crate) fn set_dial(&mut self, dial: Dial) {
        self.dial = dial;
    }

    /// Its route, as it dials it.
    pub(crate) fn dialing(&self) -> Dialing<'_> {
        Dialing {
            route: &self.route,
            dial: self.dial,
        }
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

    /// What the resolves it holds wait for (`Curl_async_pollset`): its
    /// name's before its race begins, and a SOCKS proxy's target's beside
    /// its dialed connection. The name's resolve the race goes on beside is
    /// the setup's [`Late`], not the machine's.
    pub(crate) fn resolve_wants(&self) -> impl Iterator<Item = (&dyn Socket, Events)> {
        let (pending, beside) = match &self.stage {
            Stage::Resolving(p) => (p.as_ref(), None),
            Stage::Racing(_) => (None, None),
            Stage::Dialed(d) => (None, d.target_late.as_ref()),
        };
        [pending, beside]
            .into_iter()
            .flat_map(|p| p.map_or(&[][..], Pending::wants))
            .map(|(s, e)| (&**s, *e))
    }

    /// When the SOCKS proxy's target's resolve, held beside the dialed
    /// connection, wants to run again, `left` the time it has.
    pub(crate) fn resolve_due(&self, now: Instant, left: Duration) -> Option<Instant> {
        match &self.stage {
            Stage::Dialed(d) => d.target_late.as_ref()?.due(now, left),
            Stage::Racing(_) | Stage::Resolving(_) => None,
        }
    }

    /// What each attempt running waits for: a TCP connect to write, a
    /// QUIC connection what it says (`cf_ngtcp2_adjust_pollset`).
    pub(crate) fn racing_wants(&self) -> impl Iterator<Item = (&dyn Socket, Events)> {
        let running = match &self.stage {
            Stage::Racing(r) => &r.attempts[..],
            Stage::Resolving(_) | Stage::Dialed(_) => &[][..],
        };
        running.iter().map(|a| (a.socket.socket(), a.link.wants()))
    }

    /// Whether its peer has answered, as C's race asks it
    /// (`CF_QUERY_CONNECT_REPLY_MS`): while it races, the happy eyeballs
    /// filter answers how long after it started the first of its QUIC
    /// attempts to hear from its peer did, if one has
    /// (`cf_ip_ballers_min_reply_ms`); once the first hop is dialed, the
    /// filter is connected and passes the question down, to the socket
    /// that has heard the proxy or not, or to an HTTP/3 proxy's QUIC
    /// connection.
    pub(crate) fn reply(&self) -> Reply {
        match &self.stage {
            Stage::Racing(r) => Reply::Racing(
                r.attempts
                    .iter()
                    .filter_map(|a| a.link.quic()?.reply_ms())
                    .min(),
            ),
            Stage::Resolving(_) => Reply::Racing(None),
            Stage::Dialed(d) => Reply::Dialed(
                d.stream.heard() || d.quic.as_ref().is_some_and(|q| q.first_byte_at().is_some()),
            ),
        }
    }

    /// Its destination's name is not asked for yet: the setup's first
    /// connect is to come.
    pub(crate) fn unasked(&self) -> bool {
        matches!(self.stage, Stage::Resolving(None))
    }

    /// How far it got, as C's filter chain shows it.
    pub(crate) fn reached(&self) -> SetupPoint {
        match &self.stage {
            Stage::Resolving(_) => SetupPoint::Resolving,
            Stage::Racing(r) => SetupPoint::Racing { started: r.ran },
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
    pub(crate) fn proxied(&mut self, which: Handshook, haproxy: impl FnOnce() -> bool) {
        let Stage::Dialed(d) = &mut self.stage else {
            panic!("no handshake is made");
        };
        d.mark_made(which);
        let route = &self.route;
        let socks = route.socks().is_some() && !d.made.socks;
        let tunnel = route.proxy.as_ref().is_some_and(|p| p.tunnels()) && d.made.tunnel.is_none();
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
        assert!(self.dialing().tunnels_udp(), "a CONNECT-UDP tunnel");
        let none = SocketAddr::from(([0, 0, 0, 0], 0));
        let remote = d.remote.inet().unwrap_or(none);
        let local = d.local.unwrap_or(none);
        Self::make_quic(&self.route, cx, local, remote, true)
    }

    /// The race's attempts were checked and none decided: those running
    /// say so (`cf_ip_ballers_run`), as an attempt whose QUIC connection
    /// to an HTTP/3 proxy is made goes on to its tunnel.
    pub(crate) fn checked(&self, cx: &mut dyn LayerCx) {
        if let Stage::Racing(r) = &self.stage {
            let of = asking(&self.route);
            r.checked(cx);
            // Whether to start another, then when to be called again.
            r.eyeballs.more_asked(cx, of);
            r.eyeballs.more_asked(cx, of);
        }
    }

    /// Whether the name is still to be resolved, its resolve not yet
    /// handed to the setup's [`Late`] as the race begins.
    pub(crate) fn resolving(&self) -> bool {
        matches!(self.stage, Stage::Resolving(_))
    }

    /// Whether it races, its first hop not yet dialed.
    #[cfg(test)]
    pub(crate) fn races(&self) -> bool {
        matches!(self.stage, Stage::Racing(_))
    }

    pub(crate) fn answer(&self) -> Option<&TryArc<Answer>> {
        match self.addresses()? {
            Addresses::Resolved(answer) => Some(answer),
            Addresses::Unix => None,
        }
    }

    /// What its attempts connect to, the addresses or the Unix socket,
    /// once known.
    pub(crate) fn addresses(&self) -> Option<&Addresses> {
        match &self.stage {
            Stage::Resolving(_) => None,
            Stage::Racing(r) => Some(&r.eyeballs.answer),
            Stage::Dialed(d) => Some(&d.answer),
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
            Stage::Dialed(d) => Some((d.remote.clone(), d.local, d.connected_at)),
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
            (
                self.number,
                self.route,
                self.dial,
                self.created,
                self.settings,
            ),
            Transport::Stream(d.stream),
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
        self.tunnel_goes(cx);
        discard(
            cx,
            self.dialing().socket_component(),
            d.stream.into_socket(),
        );
        self.stage = Stage::Racing(Racing {
            ran: false,
            last_failed: None,
            // The name's filter, above the chain started over, goes on
            // resolving: the race follows it again as it is next driven.
            eyeballs: Eyeballs::new(d.answer, self.route.ip()),
            attempts: Vec::new(),
            last_start: None,
            target: match d.target {
                found @ SocksTarget::Found(..) => Some(found),
                SocksTarget::None | SocksTarget::Unresolved => None,
            },
        });
        true
    }

    /// Move the setup on by one event, `name` the resolve of its first
    /// hop's name the setup goes on beside, which the machine never holds:
    /// it hands it there as its race begins on part of the answer, and its
    /// race follows it from then on.
    pub(crate) fn drive(
        mut self,
        cx: &mut dyn ConnCx,
        setup: DriveOptions,
        late: &mut Late,
    ) -> Result<Drove, ConnectError> {
        let now = cx.now();
        let delay = setup.delay;
        let component = self.dialing().socket_component();
        let of = asking(&self.route);
        let r = match &mut self.stage {
            Stage::Resolving(pending) => {
                let pending = pending.take();
                let (answer, found) = match self.unix_peer() {
                    // Its one address, made at once (`resolv_unix`).
                    Some(peer) => {
                        if peer.path().len() >= curl_os::net::UNIX_PATH_ROOM {
                            return Err(ConnectError::Unresolved(Unresolved::UnixPathTooLong));
                        }
                        // An entry of no cache's, which the filter holds
                        // all the same (`Curl_dnsc_mk_addr`).
                        cx.hold(Holder::Addresses(cx.rank()));
                        (Addresses::Unix, Found::Resolved(Asked::Shortcut))
                    }
                    None => {
                        let peer = self.route.destination();
                        let (name, port) = (peer.name(), peer.port());
                        let (looked, fresh) = match pending {
                            None => {
                                let family = family(self.route.ip(), cx);
                                let holder = Holder::Addresses(cx.rank());
                                let looked =
                                    lookup_start((name, port), family, cx, setup, true, holder)?;
                                (looked, true)
                            }
                            Some(p) => (Looked::Pending(p), false),
                        };
                        // One that says its own lines, a library's or DoH's,
                        // is looked at again as soon as it started, as the
                        // filter takes the answer right after its start
                        // (`cf_dns_connect`'s `Curl_resolv_take_result`).
                        let looked = match looked {
                            Looked::Pending(p)
                                if p.says_its_own() || p.live.is_some() || !fresh =>
                            {
                                match p.take((name, port), cx) {
                                    Taken::Done(done) => {
                                        let (a, f) = done?;
                                        Looked::Found(a, f)
                                    }
                                    Taken::Waiting(p) => Looked::Pending(p),
                                }
                            }
                            other => other,
                        };
                        match looked {
                            // Held, though it has no address to try, until
                            // the transfer is done.
                            Looked::Found(answer, found) => {
                                cx.hold(Holder::Addresses(cx.rank()));
                                (Addresses::Resolved(answer), found)
                            }
                            // Nothing until the resolver answers, when the
                            // multi runs the transfer again.
                            Looked::Pending(mut p) => {
                                let says_its_own = p.says_its_own();
                                let mut retry = None;
                                if !says_its_own {
                                    cx.net().with_resolver(&mut |r| retry = r.retry());
                                }
                                let mut retry = retry.map(|after| cx.now().after(after));
                                let left = cx.await_resolve_left(p.asked).unwrap_or_default();
                                retry = retry.or(p.due(cx.now(), left));
                                // AAAA is preferred, and waited for a while
                                // before what came is connected to
                                // (`cf_dns_ready_to_connect`).
                                let oom = |OutOfMemory| ConnectError::OutOfMemory;
                                if let Some(part) = p.partial().map_err(oom)? {
                                    // In milliseconds, as C counts them.
                                    let left = crate::time::millis(p.aaaa_wait)
                                        .saturating_sub(now.ms_since(p.asked));
                                    if !part.v6_answered && left > 0 {
                                        let until =
                                            now.after(Duration::from_millis(left.unsigned_abs()));
                                        let queries = family_queries(p.family);
                                        cx.of(
                                            Component::DnsFilter,
                                            format_args!(
                                                "[{queries}] still waiting {left}ms \
                                                 for AAAA result"
                                            ),
                                        );
                                        self.stage = Stage::Resolving(Some(p));
                                        let aaaa = Some(until);
                                        let progress = Progress::Resolving { retry, aaaa };
                                        return Ok(Drove::Connecting(self, progress));
                                    } else {
                                        let answer = part.answer(name, p.family).map_err(oom)?;
                                        let mut eyeballs = Eyeballs::new(
                                            Addresses::Resolved(answer.clone()),
                                            self.route.ip(),
                                        );
                                        // The rest is the name's filter's,
                                        // above the setup.
                                        late.begin(p, answer).map_err(oom)?;
                                        eyeballs.follow(late);
                                        self.stage = Stage::Racing(Racing {
                                            ran: false,
                                            last_failed: None,
                                            eyeballs,
                                            attempts: Vec::new(),
                                            last_start: None,
                                            target: None,
                                        });
                                        // Nothing to say: the race starts, with
                                        // no address yet if none came, as what
                                        // heads it goes on without
                                        // (`cf_dns_ready_to_connect`).
                                        return Ok(Drove::Connecting(self, Progress::Failed));
                                    }
                                }
                                self.stage = Stage::Resolving(Some(p));
                                let progress = Progress::Resolving { retry, aaaa: None };
                                return Ok(Drove::Connecting(self, progress));
                            }
                        }
                    }
                };
                let eyeballs = Eyeballs::new(answer, self.route.ip());
                if !eyeballs.more() {
                    return Err(ConnectError::Unresolved(Unresolved::NoAddress(found)));
                }
                self.stage = Stage::Racing(Racing {
                    ran: false,
                    last_failed: None,
                    eyeballs,
                    attempts: Vec::new(),
                    last_start: None,
                    target: None,
                });
                return Ok(Drove::Connecting(self, Progress::Resolved(found)));
            }
            Stage::Racing(r) => {
                r.eyeballs.follow(late);
                r
            }
            Stage::Dialed(_) => unreachable!("a dialed setup is driven by its handshakes"),
        };
        // All tried, and nothing running: what is still to come may give
        // more, and without more the last failure is the setup's.
        let idle = r.attempts.is_empty() && !r.eyeballs.more();
        if idle && !r.eyeballs.coming() {
            // Looked for once more, as C's run does before it gives up.
            assert!(r.eyeballs.next(cx, of).is_none(), "no address is left");
            let (error, kind) = r
                .last_failed
                .take()
                .unwrap_or((None, ErrorKind::CouldntConnect));
            return Err(ConnectError::Failed(error, kind));
        }
        // The race's first run sets it up (`cf_ip_happy_init`).
        if !std::mem::replace(&mut r.ran, true) {
            let transport = match component {
                Component::Unix => 6,
                Component::Udp => 5,
                _ => 3,
            };
            cx.of(
                Component::HappyEyeballs,
                format_args!("init ip ballers for transport {transport}"),
            );
        }
        if idle {
            assert!(r.eyeballs.next(cx, of).is_none(), "no address is left");
            r.eyeballs.more_asked(cx, of);
            // The resolve's own timer, not the race's: the race has
            // nothing to start (`cf_ip_ballers_run`).
            let progress = match late.pending() {
                Some(p) => Progress::Resolving {
                    retry: p.due(now, cx.await_resolve_left(p.asked).unwrap_or_default()),
                    aaaa: None,
                },
                None => Progress::Waiting { until: None },
            };
            return Ok(Drove::Connecting(self, progress));
        }
        // A running attempt that connected wins; one that failed is
        // dropped (`cf_ip_ballers_run`).
        match r.check(cx, component, &self.route) {
            Checked::Pending => r.checked(cx),
            Checked::Won(i) => return self.won(cx, setup, i, now),
            Checked::OutOfMemory => return Err(ConnectError::OutOfMemory),
            Checked::Failed(i, error) => {
                let failure = r.attempts.remove(i).fail(cx, component, error)?;
                return r
                    .failed(cx, of, Some(failure), ErrorKind::CouldntConnect)
                    .map(|p| Drove::Connecting(self, p));
            }
            Checked::QuicFailed(i, kind) => {
                r.attempts.remove(i).discard(cx, component);
                return r
                    .failed(cx, of, None, kind)
                    .map(|p| Drove::Connecting(self, p));
            }
        }
        // With none running another is wanted; with some, one is if an
        // address is left and the last started long enough ago, in
        // milliseconds as C counts them.
        let do_more = r.attempts.is_empty()
            || (r.eyeballs.more_asked(cx, of)
                && r.last_start
                    .is_none_or(|at| now.ms_since(at) >= crate::time::millis(delay)));
        if !do_more {
            let until = r.next_due(cx, of, delay);
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
        let candidate = r.eyeballs.next(cx, of).expect("an address is left");
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
            let dialing = Dialing {
                route: &self.route,
                dial: self.dial,
            };
            let udp = u8::from(dialing.asks_udp());
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
        match r.check(cx, component, &self.route) {
            Checked::Pending => {}
            Checked::Won(i) => return self.won(cx, setup, i, now),
            Checked::OutOfMemory => return Err(ConnectError::OutOfMemory),
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
        let kind = if self.dialing().first_hop_quic() || self.dial == super::Dial::Udp {
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
                let why = ErrorText::of(&error);
                cx.fail_with(&[b"failed to open socket: ", why.as_bytes()]);
                let none = io::Error::from_raw_os_error(0);
                return self.not_opened(cx, None, ErrorKind::CouldntConnect, none);
            }
        };
        // Windows' IPv6 sockets reach IPv4 peers too, by their mapped
        // addresses, whatever the system's default; C ignores whether this
        // takes.
        #[cfg(windows)]
        if let Remote::Inet(SocketAddr::V6(_)) = remote {
            match socket.set(SocketOption::DualStack) {
                Ok(()) | Err(_) => {}
            }
        }
        trace_trying(cx, &remote);
        let fd = socket.key().get();
        // Only TCP's are set (`is_tcp`): neither a Unix socket nor
        // QUIC's UDP one.
        let tcp = matches!(remote, Remote::Inet(_)) && kind == SocketKind::Stream;
        if tcp {
            set_up(cx, &*socket, setup.socket);
            #[cfg(windows)]
            if let Remote::Inet(at) = remote {
                give_up_on_loopback(&*socket, at);
            }
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
        let cold = self.route.cold.clone();
        if let (Some(local), Remote::Inet(at)) = (cold.as_deref().map(|c| &c.local), &remote)
            && local.binds()
        {
            let scope = setup
                .scope
                .or(self.route.destination().scope())
                .map_or(0, NonZeroU32::get);
            match bind_local(cx, &*socket, *at, local, scope, setup) {
                Ok(bound) => self.settings.set_bound_local(bound),
                Err(failed) => {
                    cx.net().close(Sock::new(socket, self.closer.clone()));
                    if failed == BindFailed::OutOfMemory {
                        return Err(ConnectError::OutOfMemory);
                    }
                    let none = io::Error::from_raw_os_error(0);
                    return self.not_opened(cx, Some(&remote), failed.kind(), none);
                }
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
        if kind == SocketKind::Datagram && self.dial != super::Dial::Udp {
            return self.quic_attempt(cx, socket, remote, delay);
        }
        let Stage::Racing(r) = &mut self.stage else {
            unreachable!("an attempt is made in a race");
        };
        // A socket of datagrams the request sends itself connects to no
        // peer: it is up as it opens (`cf_udp_connect`).
        if connected || self.dial == super::Dial::Udp {
            // The application connected it: it won as it opened, with no
            // connect to check, its end here asked for once
            // (`cf_socket_open`, `cf_udp_connect`).
            let local = asked_local(&self.route, &*socket);
            let socket = Sock::new(socket, self.closer.clone());
            r.attempts
                .try_push(Attempt {
                    remote,
                    socket,
                    local,
                    link: Link::Connect,
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
        let local = asked_local(&self.route, &*socket);
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
                        local,
                        link: Link::Connect,
                    })
                    .expect("reserved");
                // Checked with those before it, the new attempt among
                // them (`goto evaluate`), unless it connected at once.
                let at_once = connect == Connect::Done;
                let until = if at_once {
                    None
                } else {
                    r.went_on(cx, of, delay)
                };
                let tried = Progress::Trying {
                    remote,
                    at_once,
                    until,
                };
                Ok(Drove::Connecting(self, tried))
            }
            Err(error) => {
                // The socket was opened before its connect failed, and
                // never got a local address (`cf_tcp_connect`).
                cx.socket_failed(&error);
                let why = ErrorText::of(&error);
                let why = why.as_bytes();
                let rip = remote.shown_ip();
                cx.info_with(&[b"Immediate connect fail for ", rip.bytes(), b": ", why]);
                cx.net().close(socket);
                let mut line = Line::new();
                line.raw(b"connect to ").raw(rip.bytes());
                line.text(format_args!(
                    " port {} from {lip} port {lport} failed: ",
                    remote.port()
                ));
                line.raw(why);
                cx.info_with(&[line.bytes()]);
                cx.of(component, format_args!("destroy"));
                r.failed(cx, of, Some(error), ErrorKind::CouldntConnect)
                    .map(|p| Drove::Connecting(self, p))
            }
        }
    }

    /// An attempt over QUIC, its socket `socket` opened for `remote`:
    /// connected, set as QUIC's sockets are (`cf_udp_setup_quic`), and
    /// the QUIC connection over it made and its first flight sent
    /// (`cf_connect_start`, `Curl_cf_ngtcp2_cmn_connect`).
    fn quic_attempt(
        self,
        cx: &mut dyn ConnCx,
        socket: Box<dyn Socket>,
        remote: Remote,
        delay: Duration,
    ) -> Result<Drove, ConnectError> {
        let component = self.dialing().socket_component();
        let fd = socket.key().get();
        let socket = Sock::new(socket, self.closer.clone());
        let Remote::Inet(addr) = remote else {
            unreachable!("HTTP/3 is refused over a Unix socket");
        };
        let rip = addr.ip();
        if let Err(error) = socket.socket().connect(&remote) {
            cx.socket_failed(&error);
            let why = ErrorText::of(&error);
            let rip = crate::text::Text::<48>::clipped(format_args!("{rip}: ")).0;
            cx.info_with(&[b"Immediate connect fail for ", rip.bytes(), why.as_bytes()]);
            cx.of(self.quic_component(), format_args!("destroy"));
            discard(cx, component, socket);
            return self.quic_failed(cx, Some(error), ErrorKind::CouldntConnect);
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
            Some(local) if RecordWait::needed(&self.route, cx) => {
                RecordWait::delays(cx);
                let wait = RecordWait {
                    local,
                    remote: addr,
                };
                let link = Link::Record(wait);
                return Ok(self.attempt_on(cx, remote, socket, Some(local), link, false, delay));
            }
            Some(local) => Self::make_quic(&self.route, cx, local, addr, false),
            None => Err(ErrorKind::QuicConnectError),
        };
        let started = made.and_then(|mut quic| {
            let mut over = crate::conn::quic::Over {
                cx: &mut *cx,
                on: socket.socket(),
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
                return self.quic_failed(cx, None, kind);
            }
        };
        Ok(self.attempt_on(cx, remote, socket, local, Link::Quic(quic), done, delay))
    }

    /// The QUIC attempt over `socket` to `remote`, its end here `local`,
    /// its `link` made, runs in the race: connected `done` as it started,
    /// for early data, it has won at once.
    #[allow(clippy::too_many_arguments)]
    fn attempt_on(
        mut self,
        cx: &mut dyn ConnCx,
        remote: Remote,
        socket: Sock,
        local: Option<SocketAddr>,
        link: Link,
        done: bool,
        delay: Duration,
    ) -> Drove {
        let of = asking(&self.route);
        let Stage::Racing(r) = &mut self.stage else {
            unreachable!("an attempt is made in a race");
        };
        r.attempts
            .try_push(Attempt {
                remote: remote.clone(),
                socket,
                local,
                link,
            })
            .expect("reserved");
        let until = if done { None } else { r.went_on(cx, of, delay) };
        let tried = Progress::Trying {
            remote,
            at_once: done,
            until,
        };
        Drove::Connecting(self, tried)
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
        route: &NetRoute,
        cx: &mut dyn ConnCx,
        local: SocketAddr,
        remote: SocketAddr,
        tunnelled: bool,
    ) -> Result<Box<Quic>, ErrorKind> {
        let oom = |OutOfMemory| ErrorKind::OutOfMemory;
        let component = if tunnelled || !route.proxy_over_quic() {
            Component::Http3
        } else {
            Component::H3Proxy
        };
        // As the library's filter says it: quiche's names no QUIC and
        // traces no connect call.
        let said = |cx: &mut dyn ConnCx, kind: ErrorKind, flavour: Flavour| {
            let (ip, port) = (remote.ip(), remote.port());
            let why = kind.message();
            if flavour == Flavour::Quiche {
                cx.info(format_args!("connect to {ip} port {port} failed: {why}"));
                return kind;
            }
            cx.info(format_args!(
                "QUIC connect to {ip} port {port} failed: {why}"
            ));
            let code = crate::trace::Code(Err(kind));
            cx.of(component, format_args!("connect -> {code}, done=0"));
            kind
        };
        let Some(making) = cx.quic_making().map_err(oom)? else {
            return Err(said(cx, ErrorKind::QuicConnectError, Flavour::Ngtcp2));
        };
        let libraries = &*making.libraries;
        let (Some(backend), Some(h3)) = (libraries.tls.as_deref(), libraries.h3) else {
            return Err(said(cx, ErrorKind::QuicConnectError, Flavour::Ngtcp2));
        };
        let flavour = h3.flavour();
        let failed = |cx: &mut dyn ConnCx, kind: ErrorKind| said(cx, kind, flavour);
        // To an HTTP/3 proxy, its TLS is the proxy's.
        let proxied = !tunnelled && route.proxy_over_quic();
        let (identity, origin, via) = if proxied {
            let identity = route.proxy_tls().expect("an HTTP/3 proxy speaks TLS");
            (identity, route.destination(), None)
        } else {
            let identity = route.start_tls().expect("HTTP/3 is refused but over TLS");
            (identity, &*route.origin, route.via.as_deref())
        };
        let kept_for =
            crate::tls::SessionPeer::new(identity, origin, via, backend.id(), super::Dial::Quic)
                .map_err(oom)?;
        let keeps = flavour.keeps_sessions();
        let kept_for = if keeps {
            kept_for
        } else {
            kept_for.keeping_none()
        };
        // Early data, where the transfer asks for it of this peer and
        // makes requests (`conn_cfg->earlydata`, `bits.connect_only`): to
        // an HTTP/3 proxy, the tunnel's `CONNECT` goes as early data.
        let early_data = identity
            .options
            .ssl_options
            .contains(crate::options::SslOptions::EARLYDATA)
            && making.requests
            && keeps;
        // The origin's TLS tries ECH with its HTTPS record's
        // configurations, if the record is known as the session is made
        // (`ossl_init_ech`, `wssl_init_ech`); a proxy's tries none.
        let record = match cx.https_record() {
            OriginRecord::Known(record) if !proxied => record,
            OriginRecord::Known(_) | OriginRecord::Coming => None,
        };
        let ech = record.as_deref().and_then(|r| r.ech_for(origin.port()));
        let peer = crate::tls::TlsPeer::of(origin, early_data, ech);
        let tls = {
            let mut tcx = crate::tls::TlsCx::new(cx, component, &kept_for);
            let setup = |ctx| h3.setup_tls_context(ctx);
            backend.quic_session(identity, &peer, &making.shared, &setup, &mut tcx)
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
                    alpn: ticket.chosen(),
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
            flavour,
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
        cx: &mut dyn ConnCx,
        error: Option<io::Error>,
        kind: ErrorKind,
    ) -> Result<Drove, ConnectError> {
        let of = asking(&self.route);
        let Stage::Racing(r) = &mut self.stage else {
            unreachable!("an attempt is made in a race");
        };
        r.failed(cx, of, error, kind)
            .map(|p| Drove::Connecting(self, p))
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
        let component = self.dialing().socket_component();
        cx.of(component, format_args!("cf_socket_open() -> {code}, fd=-1"));
        let rport = remote.map_or(0, Remote::port);
        let why = ErrorText::of(&error);
        let mut line = Line::new();
        line.raw(b"connect to ");
        if let Some(remote) = remote {
            line.raw(remote.shown_ip().bytes());
        }
        line.text(format_args!(" port {rport} from  port 0 failed: "));
        line.raw(why.as_bytes());
        cx.info_with(&[line.bytes()]);
        cx.of(component, format_args!("destroy"));
        let of = asking(&self.route);
        let Stage::Racing(r) = &mut self.stage else {
            unreachable!("an attempt is made in a race");
        };
        r.failed(cx, of, Some(error), kind)
            .map(|p| Drove::Connecting(self, p))
    }

    /// The race's attempt `i` connected: the others close, and the
    /// connection is up, or dialed for the handshakes over it. One whose
    /// QUIC connection to an HTTP/3 proxy is up races on, its tunnel to
    /// be made over it.
    fn won(
        mut self,
        cx: &mut dyn ConnCx,
        setup: DriveOptions,
        i: usize,
        now: Instant,
    ) -> Result<Drove, ConnectError> {
        let udp = self.dialing().asks_udp();
        let to_proxy = self.route.proxy_over_quic();
        let Stage::Racing(r) = &mut self.stage else {
            unreachable!("only a race is won");
        };
        if to_proxy && let Link::Quic(_) = r.attempts[i].link {
            let Link::Quic(quic) = std::mem::replace(&mut r.attempts[i].link, Link::Connect) else {
                unreachable!("matched");
            };
            let Ok(tunnel) = curl_alloc::try_box(H3Proxy::new(quic, udp)) else {
                r.close_all(cx.net());
                return Err(ConnectError::OutOfMemory);
            };
            r.attempts[i].link = Link::Tunnel(tunnel);
            let until = r
                .last_start
                .filter(|_| r.eyeballs.more())
                .map(|at| at.after(setup.delay));
            return Ok(Drove::Connecting(self, Progress::Tunnel { until }));
        }
        cx.of(
            Component::HappyEyeballs,
            format_args!("connect attempt #{i} successful"),
        );
        let won = r.attempts.remove(i);
        let component = Dialing {
            route: &self.route,
            dial: self.dial,
        }
        .socket_component();
        for a in r.attempts.drain(..) {
            a.discard(cx, component);
        }
        // Whatever the attempts said is let go (`cf_ip_happy_connect`).
        cx.reset_fail();
        // A QUIC connection is up with its handshake: its TLS is its own.
        // A tunnel through an HTTP/3 proxy is the first hop's, the
        // handshakes over it still to be made.
        let (quic, tunnel) = match won.link {
            Link::Connect => (None, None),
            Link::Record(_) => unreachable!("an attempt waiting for the record has not connected"),
            Link::Quic(quic) => (Some(quic), None),
            Link::Tunnel(tunnel) => (None, Some(tunnel)),
        };
        if quic.is_none() && (self.route.handshakes() || setup.haproxy || self.route.secured()) {
            // The connection is the first hop's; the handshakes over it
            // are still to be made.
            let answer = r.eyeballs.answer.clone();
            let kept = r.target.take();
            let kept_target = kept.is_some();
            let (target, target_late) = match self.socks_target(cx, setup, kept) {
                Ok(target) => target,
                Err(e) => {
                    cx.net().close(won.socket);
                    return Err(e);
                }
            };
            // A QUIC connection is connected as its first datagram came.
            let connected_at = tunnel
                .as_ref()
                .and_then(|t| t.quic().first_byte_at())
                .unwrap_or(now);
            // The proxy's TLS is its QUIC connection's, made.
            let mut made = if tunnel.is_some() {
                Made::default().with(Handshook::ProxyTls)
            } else {
                Made::default()
            };
            made.target_filter = kept_target;
            let mut stream = Stream::new(won.socket);
            // The tunnel is the layer its bytes pass through.
            if let Some(tunnel) = tunnel {
                let pushed = stream.push_over_received(|received| {
                    assert!(
                        received.is_empty(),
                        "nothing is read over QUIC's socket but by it"
                    );
                    Ok(tunnel as Box<dyn super::layer::Layer>)
                });
                if pushed.is_err() {
                    cx.net().close(stream.into_socket());
                    return Err(ConnectError::OutOfMemory);
                }
            }
            self.stage = Stage::Dialed(Dialed {
                remote: won.remote,
                stream,
                local: won.local,
                connected_at,
                answer,
                target,
                target_late,
                socks5_authenticated: false,
                made,
                // With no proxy's handshake to make first, the stage is
                // reached now.
                preface: (!self.route.handshakes()).then_some(setup.haproxy),
                quic: None,
            });
            if to_proxy {
                self.proxied(Handshook::Tunnel(super::Tunneled::H3), || setup.haproxy);
            }
            return Ok(Drove::Connecting(self, Progress::Dialed));
        }
        // A QUIC connection is connected as its first datagram came.
        let at = quic.as_ref().and_then(|q| q.first_byte_at()).unwrap_or(now);
        // Boxed before the connection is made, so that a refusal closes
        // the socket rather than dropping it open.
        let h3 = match quic.map(|q| curl_alloc::try_box(crate::proto::http3::H3Conn::new(q))) {
            None => None,
            Some(Ok(h3)) => Some(h3),
            Some(Err(OutOfMemory)) => {
                cx.net().close(won.socket);
                return Err(ConnectError::OutOfMemory);
            }
        };
        let made = (
            self.number,
            self.route,
            self.dial,
            self.created,
            self.settings,
        );
        // The request's own datagrams go to the socket as they are.
        if self.dial == super::Dial::Udp {
            let datagrams = Transport::Datagram(super::Datagrams::new(won.socket));
            let conn = Self::conn(made, datagrams, won.remote, at);
            return Ok(Drove::Established(conn));
        }
        let Some(h3) = h3 else {
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
            let conn = Self::conn(made, Transport::Stream(stream), won.remote, at);
            return Ok(Drove::Established(conn));
        };
        // QUIC dialed straight to its peer: its datagrams go to the socket
        // with nothing between, a test's layers over a stream alone.
        #[cfg(test)]
        assert!(setup.layer.is_none(), "a test's layer goes over a stream");
        #[cfg(any(test, feature = "test-util"))]
        assert!(setup.linger.is_none(), "a test's layer goes over a stream");
        let datagrams = Transport::Datagram(super::Datagrams::new(won.socket));
        let mut conn = Self::conn(made, datagrams, won.remote, at);
        conn.put_h3(h3);
        Ok(Drove::Established(conn))
    }

    /// The tunnels through an HTTP/3 proxy its race's attempts make,
    /// each with its index and the socket under it, for the transfer to
    /// drive as C's race checks its attempts (`cf_ip_attempt_connect`).
    pub(crate) fn tunnels(&mut self) -> impl Iterator<Item = (usize, &mut H3Proxy, &dyn Socket)> {
        let running = match &mut self.stage {
            Stage::Racing(r) => &mut r.attempts[..],
            Stage::Resolving(_) | Stage::Dialed(_) => &mut [][..],
        };
        running
            .iter_mut()
            .enumerate()
            .filter_map(|(i, a)| match &mut a.link {
                Link::Tunnel(t) => Some((i, &mut **t, a.socket.socket())),
                Link::Connect | Link::Quic(_) | Link::Record(_) => None,
            })
    }

    /// Attempt `i`'s tunnel is through: it won the race, the connection
    /// dialed for the handshakes over it.
    pub(crate) fn tunneled(
        self,
        cx: &mut dyn ConnCx,
        setup: DriveOptions,
        i: usize,
    ) -> Result<Drove, ConnectError> {
        let now = cx.now();
        self.won(cx, setup, i, now)
    }

    /// Attempt `i`'s tunnel failed with `kind`, traced: it goes, and the
    /// race goes on while another runs or an address is left, or more may
    /// come of `late`, the name's resolve (`cf_ip_ballers_run` discarding a
    /// failed baller).
    pub(crate) fn tunnel_failed(
        mut self,
        cx: &mut dyn ConnCx,
        late: &Late,
        i: usize,
        kind: ErrorKind,
    ) -> Result<Drove, ConnectError> {
        let component = self.dialing().socket_component();
        let of = asking(&self.route);
        let Stage::Racing(r) = &mut self.stage else {
            unreachable!("a tunnel is an attempt of a race");
        };
        r.eyeballs.follow(late);
        r.attempts.remove(i).discard(cx, component);
        r.failed(cx, of, None, kind)
            .map(|p| Drove::Connecting(self, p))
    }

    /// The Unix socket the first hop is at, if it is one.
    fn unix_peer(&self) -> Option<UnixPeer> {
        let peer = self.route.destination_shared();
        peer.is_unix().then(|| UnixPeer::of(peer.clone()))
    }

    /// The destination's addresses, for a SOCKS proxy that is not to
    /// resolve its name (`Curl_conn_dns_add_addr_resolve`); a resolver
    /// that finds nothing is for the handshake to say. Those `kept` from
    /// before a redial are the ones, not looked up again.
    fn socks_target(
        &self,
        cx: &mut dyn ConnCx,
        setup: DriveOptions,
        kept: Option<SocksTarget>,
    ) -> Result<(SocksTarget, Option<Pending>), ConnectError> {
        if let Some(kept) = kept {
            return Ok((kept, None));
        }
        let Some(leg) = self.route.socks() else {
            return Ok((SocksTarget::None, None));
        };
        if !leg.version.resolves_locally() {
            return Ok((SocksTarget::None, None));
        }
        let family = family(leg.version.ip(self.route.ip()), cx);
        let at = (leg.to.name(), leg.to.port());
        match lookup_start(at, family, cx, setup, true, Holder::Target) {
            Ok(Looked::Found(answer, _)) => {
                cx.hold(Holder::Target);
                Ok((SocksTarget::Found(answer), None))
            }
            // As the proxy's own name's, its answer comes later.
            Ok(Looked::Pending(p)) => Ok((SocksTarget::None, Some(p))),
            // The SOCKS handshake says the name failed, whatever the why.
            Err(ConnectError::Unresolved(_)) => Ok((SocksTarget::Unresolved, None)),
            Err(e) => Err(e),
        }
    }

    /// Whether what a SOCKS handshake needs of the destination's name has
    /// come (`Curl_conn_dns_addr_result`).
    pub(crate) fn target_known(&mut self, cx: &mut dyn ConnCx) -> Result<bool, ConnectError> {
        let Stage::Dialed(d) = &mut self.stage else {
            panic!("a handshake goes over a dialed connection");
        };
        let Some(p) = d.target_late.take() else {
            return Ok(true);
        };
        let leg = self.route.socks().expect("through a SOCKS proxy");
        let at = (leg.to.name(), leg.to.port());
        let done = match p.take(at, cx) {
            Taken::Waiting(p) => {
                d.target_late = Some(p);
                return Ok(false);
            }
            Taken::Done(done) => done,
        };
        d.target = match done {
            Ok((answer, _)) => {
                cx.hold(Holder::Target);
                SocksTarget::Found(answer)
            }
            Err(ConnectError::Unresolved(_)) => SocksTarget::Unresolved,
            Err(e) => return Err(e),
        };
        Ok(true)
    }
    /// The connection set up over `stream` to `remote`, found connected
    /// at `at`.
    /// The connection the setup `made` (its number, route, start and
    /// settings) becomes over `stream`.
    fn conn(
        made: (ConnNumber, NetRoute, Dial, Instant, ConnSettings),
        transport: Transport,
        remote: Remote,
        at: Instant,
    ) -> Conn {
        let (number, route, dial, created, settings) = made;
        Conn {
            number,
            route: Route::Net(route),
            dial,
            transport,
            remote: Some(remote),
            created,
            connected_at: at,
            use_: Use::Leased(NonZeroU32::MIN),
            // As it is found connected (`Curl_cpool_conn_was_used`).
            upkept_ms: at.ms_since(created),
            served: false,
            socks5_authenticated: false,
            multiplex_told: false,
            seen_version: None,
            local: std::sync::OnceLock::new(),
            close: false,
            settings,
            negotiate: None,
            session: super::mux::Speaks::Unmade,
        }
    }

    /// The setup lost a race of two, or failed after it was dialed and
    /// was kept until the race ended, and goes with the HTTPS connect
    /// filter: its chain below the setup filter, with no goodbye to its
    /// peers (`cf_hc_ctx_destroy`). Dialed, that is the tunnel's filters,
    /// then the happy eyeballs filter, still there until the whole chain
    /// connects, then the socket's.
    pub(crate) fn lose(self, cx: &mut dyn ConnCx) {
        if let Stage::Dialed(_) = &self.stage {
            self.tunnel_goes(cx);
            cx.of(Component::HappyEyeballs, format_args!("destroy"));
        }
        self.discard(cx);
    }

    /// The tunnel's filters go, if the route has them.
    fn tunnel_goes(&self, cx: &mut dyn ConnCx) {
        if self.route.proxy.as_ref().is_some_and(|p| p.tunnels()) {
            cx.of(Component::HttpProxy, format_args!("destroy"));
            cx.of(Component::H1Proxy, format_args!("destroy"));
        }
    }

    /// End the setup, its sockets told as they close, and a resolve it
    /// goes on beside let go of in the resolver (`Curl_resolv_destroy`).
    pub(crate) fn discard(self, cx: &mut dyn ConnCx) {
        let component = self.dialing().socket_component();
        match self.stage {
            Stage::Racing(mut r) => {
                cx.of(Component::HappyEyeballs, format_args!("destroy"));
                for a in r.attempts.drain(..) {
                    a.discard(cx, component);
                }
            }
            Stage::Dialed(mut d) => {
                discard(cx, component, d.stream.into_socket());
                d.target_late = None;
            }
            stage @ Stage::Resolving(_) => ConnectMachine { stage, ..self }.close(cx.net()),
        }
    }

    /// End the setup, closing what it has open.
    pub(crate) fn close(self, net: &mut dyn Net) {
        match self.stage {
            Stage::Resolving(None) => {}
            // Its answer, if it comes, is not wanted.
            Stage::Resolving(Some(p)) => drop(p),
            Stage::Racing(mut r) => r.close_all(net),
            Stage::Dialed(mut d) => {
                d.target_late = None;
                net.close(d.stream.into_socket());
            }
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
    /// An attempt's QUIC connection, made once the origin's record came,
    /// could not be for want of memory.
    OutOfMemory,
}

impl Racing {
    /// Each running attempt's socket checked for its connect, oldest
    /// first, as `cf_tcp_connect` checks it (`SOCKET_WRITABLE(sock, 0)`):
    /// the first decided ends the check. The race is over `route`.
    fn check(&mut self, cx: &mut dyn ConnCx, component: Component, route: &NetRoute) -> Checked {
        for (i, a) in self.attempts.iter_mut().enumerate() {
            let socket = a.socket.socket();
            // A QUIC attempt is decided by its handshake, its socket
            // connected from the start; a tunnel's, as the transfer
            // drives it.
            match &mut a.link {
                Link::Connect => {}
                // Its connect is put off again while the record is still
                // to come; once it is known, the connection is made with
                // its ECH configurations and its first flight sent
                // (`Curl_cf_ngtcp2_cmn_connect`, `cf_connect_start`).
                Link::Record(wait) => {
                    if RecordWait::needed(route, cx) {
                        RecordWait::delays(cx);
                        continue;
                    }
                    let (local, remote) = (wait.local, wait.remote);
                    let made = ConnectMachine::make_quic(route, cx, local, remote, false);
                    let mut quic = match made {
                        Ok(quic) => quic,
                        Err(ErrorKind::OutOfMemory) => return Checked::OutOfMemory,
                        Err(kind) => return Checked::QuicFailed(i, kind),
                    };
                    let mut over = crate::conn::quic::Over {
                        cx: &mut *cx,
                        on: socket,
                    };
                    let started = quic.start(&mut over);
                    a.link = Link::Quic(quic);
                    match started {
                        Ok(true) => return Checked::Won(i),
                        Ok(false) => continue,
                        Err(ErrorKind::OutOfMemory) => return Checked::OutOfMemory,
                        Err(kind) => return Checked::QuicFailed(i, kind),
                    }
                }
                Link::Quic(quic) => {
                    let mut over = crate::conn::quic::Over {
                        cx: &mut *cx,
                        on: socket,
                    };
                    match quic.connect(&mut over) {
                        Ok(true) => return Checked::Won(i),
                        Ok(false) => continue,
                        Err(kind) => return Checked::QuicFailed(i, kind),
                    }
                }
                Link::Tunnel(_) => continue,
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
                    // Its end here asked for again as it connected
                    // (`cf_tcp_connect`), kept as the connection's.
                    a.local = asked_local(route, socket);
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

    /// The attempts were checked and none decided: those running say so
    /// (`cf_ip_ballers_run`), none having failed inconclusively, to be
    /// started again.
    fn checked(&self, cx: &mut dyn LayerCx) {
        if self.attempts.is_empty() {
            return;
        }
        let ongoing = self.attempts.len();
        cx.of(
            Component::HappyEyeballs,
            format_args!("checked connect attempts: {ongoing} ongoing, 0 inconclusive"),
        );
    }

    /// When the next attempt is due, if an address is left for one, as
    /// C's run asks at its end to arm its timer (`cf_ip_ballers_run`).
    fn next_due(&self, cx: &mut dyn LayerCx, of: Asking<'_>, delay: Duration) -> Option<Instant> {
        let more = self.eyeballs.more_asked(cx, of);
        self.last_start.filter(|_| more).map(|at| at.after(delay))
    }

    /// An attempt started and the race goes on: those running are
    /// checked, whether to start another is asked, which it is too soon
    /// for, and when the next is due (`cf_ip_ballers_run`, `goto
    /// evaluate`).
    fn went_on(&self, cx: &mut dyn LayerCx, of: Asking<'_>, delay: Duration) -> Option<Instant> {
        self.checked(cx);
        self.eyeballs.more_asked(cx, of);
        self.next_due(cx, of, delay)
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
    /// With none running and no address left, C's run looks for one and
    /// finds none; the setup's failure says so.
    fn failed(
        &mut self,
        cx: &mut dyn LayerCx,
        of: Asking<'_>,
        error: Option<io::Error>,
        kind: ErrorKind,
    ) -> Result<Progress, ConnectError> {
        if !self.attempts.is_empty() || self.eyeballs.more() {
            return Ok(Progress::Failed);
        }
        if self.eyeballs.coming() {
            self.last_failed = Some((error, kind));
            return Ok(Progress::Failed);
        }
        let none = self.eyeballs.next(cx, of);
        assert!(none.is_none(), "no address is left");
        Err(ConnectError::Failed(error, kind))
    }
}

/// The end here of `socket`, connecting or connected, as the system says
/// (`set_local_ip`). A connection of a scheme of datagrams over `route`
/// never asks, even as it goes over a stream to a proxy.
fn asked_local(route: &NetRoute, socket: &dyn Socket) -> Option<SocketAddr> {
    if route.origin.scheme().no_tcp_proxy() {
        return None;
    }
    socket.local_addr().ok()
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
        let why = ErrorText::of(&error);
        let remote = &self.remote;
        let mut line = Line::new();
        line.raw(b"connect to ").raw(remote.shown_ip().bytes());
        line.text(format_args!(
            " port {} from {lip} port {lport} failed: ",
            remote.port()
        ));
        line.raw(why.as_bytes());
        cx.info_with(&[line.bytes()]);
        cx.of(component, format_args!("destroy"));
        Ok(error)
    }
}

impl Attempt {
    /// The attempt goes, its QUIC connection first, then its socket
    /// (`cf_ip_attempt_free`).
    fn discard(self, cx: &mut dyn ConnCx, component: Component) {
        match &self.link {
            Link::Connect => {}
            Link::Quic(quic) => cx.of(quic.component(), format_args!("destroy")),
            // C's filter, its connection not made, says it goes too
            // (`cf_ngtcp2_destroy`).
            Link::Record(_) => cx.of(Component::Http3, format_args!("destroy")),
            Link::Tunnel(_) => cx.of(Component::H3Proxy, format_args!("cf_h3_proxy_destroy()")),
        }
        drop(self.link);
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
        Remote::Unix(_) => cx.info_with(&[b"  Trying ", remote.shown_ip().bytes(), b":0..."]),
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
        let why = ErrorText::of(&e);
        cx.of_with(
            Component::Tcp,
            &[b"Could not set TCP_NODELAY: ", why.as_bytes()],
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
    // Windows 10 1709 and later, all Rust runs on, take the options C sets
    // on other systems.
    #[cfg(windows)]
    cx.of(Component::Tcp, format_args!("Set TCP_KEEP* on fd={fd}"));
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

/// A TCP socket to the loopback address, `127.0.0.1` or `::1` alone,
/// gives up on its connect after the first SYN, so that a refused one is
/// found at once, as C sets it on Windows (`tcplocalhost`); C ignores
/// whether this takes.
#[cfg(windows)]
fn give_up_on_loopback(socket: &dyn Socket, remote: SocketAddr) {
    if targets_localhost(remote.ip()) {
        match socket.set(SocketOption::NoSynRetransmissions) {
            Ok(()) | Err(_) => {}
        }
    }
}

/// Whether `ip` is the loopback address as C's `targets_localhost` tells
/// it, by its text: `127.0.0.1` or `::1`, no other.
#[cfg(any(windows, test))]
fn targets_localhost(ip: IpAddr) -> bool {
    ip == IpAddr::from(Ipv4Addr::LOCALHOST) || ip == IpAddr::from(Ipv6Addr::LOCALHOST)
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

/// The addresses of `family` `host` stands for, for port `port`,
/// resolved as C's blocking resolve does it (`Curl_resolv_blocking`):
/// through the cache, which keeps what is found but not that nothing
/// was, unless the library said so inside the resolve's start, as
/// `hostip_resolv` keeps it then (`Curl_dnscache_add_negative`); the
/// resolver waited for, and traced as `hostip_resolv` traces it. `None` if it stands for none, said as C fails it; the binding
/// to a local name's and FTP's address to offer the server. A resolve it
/// waited for lets go of its record as the wait ends, after its lines
/// (`Curl_resolv_blocking`'s `Curl_resolv_destroy`). The answer is held
/// as C's caller holds its entry, until the caller lets go of it.
pub(crate) fn resolve_blocking(
    cx: &mut dyn ConnCx,
    host: &[u8],
    port: u16,
    family: Family,
    setup: DriveOptions,
) -> Result<Option<Held>, ErrorKind> {
    let resolved = resolve_blocking_said(cx, host, port, family, setup);
    cx.resolve_gone(Holder::Blocking);
    resolved.map(|answer| answer.map(|answer| Held(Some(answer))))
}

/// A blocking resolve's answer, held as C's caller holds its entry of the
/// cache (`Curl_resolv_blocking`'s `pdns`) until it lets go of it with
/// `let_go`, a use of the cache a share's lock callbacks see
/// (`Curl_dns_entry_unlink`). Dropped without, a debug build panics: the
/// application would miss that use.
#[must_use = "a blocking resolve's answer is let go of with `let_go`"]
#[derive(Debug)]
pub(crate) struct Held(Option<TryArc<Answer>>);

impl Held {
    /// The addresses it holds.
    pub(crate) fn addrs(&self) -> &[IpAddr] {
        self.0.as_ref().expect("held until let go of").addrs()
    }

    /// Let go of it, a use of the cache it is kept in.
    pub(crate) fn let_go(mut self, cx: &mut dyn ConnCx) {
        self.0 = None;
        cx.names().release();
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        debug_assert!(
            self.0.is_none() || std::thread::panicking(),
            "a blocking resolve's answer let go of with `let_go`"
        );
    }
}

/// `resolve_blocking`'s resolve, and its lines.
fn resolve_blocking_said(
    cx: &mut dyn ConnCx,
    host: &[u8],
    port: u16,
    family: Family,
    setup: DriveOptions,
) -> Result<Option<TryArc<Answer>>, ErrorKind> {
    // `Curl_resolv_query_str`.
    let queries = match family {
        Family::V4 => "A",
        Family::V6 => "AAAA",
        Family::Any => "A+AAAA",
    };
    let name = host;
    // The port as a line shows it after the name, and the queries asked.
    let at = crate::text::Text::<8>::clipped(format_args!(":{port}")).0;
    let at = at.bytes();
    let dns = Component::Dns;
    // The lookup said its own lines as it looked in the cache.
    let looked = lookup_name((host, port), family, cx, setup, false);
    // A library's resolve said its lines as it went, and however it ends
    // the caller hears only that there is no answer (`Curl_resolv_blocking`,
    // whose result C ignores).
    match looked {
        Ok((answer, Found::Stale(Asked::Doh) | Found::Resolved(Asked::Doh))) => {
            return Ok(Some(answer));
        }
        // Taken inside the start, which said so: only its keeping is left
        // to say (`hostip_resolv`'s `Curl_dnscache_add`).
        Ok((answer, Found::Stale(Asked::InStart) | Found::Resolved(Asked::InStart))) => {
            cx.of_with(
                dns,
                &[
                    b"cached entry for ",
                    name,
                    at,
                    b" queries=",
                    queries.as_bytes(),
                ],
            );
            return Ok(Some(answer));
        }
        // Failed inside the start: the take's words, the start's, then
        // what is kept of it (`hostip_resolv_take_result`'s
        // `Curl_async_failed`, `hostip_resolv`).
        Err(ConnectError::Unresolved(Unresolved::Resolver {
            why,
            explained,
            library_status: Some(status),
            in_start: Some(holder),
            ..
        })) => {
            match explained {
                Some(reason) => cx.fail_with(&[
                    b"Could not resolve host: ",
                    name,
                    b" (",
                    reason.as_bytes(),
                    b")",
                ]),
                None => cx.fail_with(&[b"Could not resolve host: ", name]),
            }
            cx.of(
                dns,
                format_args!(
                    "[{queries}] ares_take_result, result=6, ares_result=0, \
                     ares_status={status}, dns=not found"
                ),
            );
            cx.fail_with(&[b"Could not resolve host: ", name]);
            cx.resolve_gone(holder);
            cx.of(dns, format_args!("[{queries}] hostip_resolv started -> 6"));
            if matches!(why, ResolveFailure::NotFound | ResolveFailure::NoData) {
                cx.of_with(
                    dns,
                    &[
                        b"cache negative name resolve for ",
                        name,
                        at,
                        b" type=",
                        queries.as_bytes(),
                    ],
                );
            }
            cx.fail_with(&[b"Could not resolve: ", name, at]);
            return Ok(None);
        }
        Err(ConnectError::Unresolved(Unresolved::GaveUp) | ConnectError::Refused(_)) => {
            return Ok(None);
        }
        Err(ConnectError::Unresolved(Unresolved::Resolver {
            explained,
            says_its_own: true,
            library_status: Some(status),
            ..
        })) => {
            match explained {
                Some(reason) => cx.fail_with(&[
                    b"Could not resolve host: ",
                    name,
                    b" (",
                    reason.as_bytes(),
                    b")",
                ]),
                None => cx.fail_with(&[b"Could not resolve host: ", name]),
            }
            cx.of(
                dns,
                format_args!(
                    "[{queries}] ares_take_result, result=6, ares_result=0, \
                     ares_status={status}, dns=not found"
                ),
            );
            return Ok(None);
        }
        _ => {}
    }
    if let Err(ConnectError::Unresolved(Unresolved::DebugFailIpv6)) = looked {
        cx.info(format_args!("DEBUG fail ipv6 resolve"));
        cx.fail_with(&[b"Could not resolve host: ", name]);
        cx.fail_with(&[b"Could not resolve: ", name, at]);
        return Ok(None);
    }
    let found = match &looked {
        Ok((_, found)) => Some(*found),
        Err(ConnectError::Unresolved(Unresolved::Negative)) => None,
        Err(ConnectError::Unresolved(Unresolved::Resolver { queued, .. })) => {
            Some(Found::Resolved(Asked::Resolver(*queued)))
        }
        Err(ConnectError::Unresolved(_)) => Some(Found::Resolved(Asked::Resolver(None))),
        Err(ConnectError::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(ConnectError::Aborted) => return Err(ErrorKind::AbortedByCallback),
        Err(ConnectError::Refused(kind)) => return Err(*kind),
        Err(ConnectError::Failed(..)) => unreachable!("a resolve makes no attempt"),
    };
    let queued = match found {
        Some(Found::Stale(Asked::Resolver(q)) | Found::Resolved(Asked::Resolver(q))) => q,
        _ => None,
    };
    if let Some(q) = queued {
        let xfer = cx.transfer_number();
        say_queued(xfer, q, name, at, &mut |parts| cx.of_with(dns, parts));
    }
    match looked {
        Ok((answer, found)) => {
            // An answer had at once said its start and keeping as it was
            // kept; one the resolver gives is waited for, and kept without
            // a word (`Curl_resolv_blocking`).
            if let Found::Stale(Asked::Resolver(_)) | Found::Resolved(Asked::Resolver(_)) = found {
                cx.of(
                    dns,
                    format_args!("[{queries}] hostip_resolv started -> {AGAIN_NUMBER}"),
                );
                if let Some(q) = queued {
                    let addrs = answer.addrs();
                    say_answered(q, name, at, addrs, &mut |parts| cx.of_with(dns, parts));
                    say_name_timer_cleared(cx);
                }
            }
            Ok(Some(answer))
        }
        Err(ConnectError::Unresolved(why)) => {
            if why != Unresolved::Negative {
                cx.of(
                    dns,
                    format_args!("[{queries}] hostip_resolv started -> {AGAIN_NUMBER}"),
                );
            }
            if let Some(q) = queued {
                say_answered(q, name, at, &[], &mut |parts| cx.of_with(dns, parts));
                say_name_timer_cleared(cx);
            }
            // With the resolver's reason, if it gives one, as the
            // reference build's c-ares does (`ares_strerror`).
            match why {
                Unresolved::Resolver {
                    explained: Some(reason),
                    ..
                } => cx.fail_with(&[
                    b"Could not resolve host: ",
                    name,
                    b" (",
                    reason.as_bytes(),
                    b")",
                ]),
                _ => cx.fail_with(&[b"Could not resolve host: ", name]),
            }
            Ok(None)
        }
        Err(_) => unreachable!("handled above"),
    }
}

/// How a resolve that answers later was queued, for its lines: the number
/// of the transfer's record of it, if the context keeps records, and which
/// families went as a query of their own, by a resolver that asks each
/// family apart (`async_thrdd_query`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Queued {
    pub(crate) record: Option<ResolveNumber>,
    pub(crate) v6: bool,
    pub(crate) v4: bool,
}

/// The threaded resolver's queries for `name` at `at`, as `q` queued
/// them for transfer `xfer`, IPv6's first, each line given to `say`
/// (`async_thrdd_query`): numbered as the transfer's record of the
/// resolve is; nothing for a context that keeps no records, and traces
/// nothing.
pub(crate) fn say_queued(
    xfer: u64,
    q: Queued,
    name: &[u8],
    at: &[u8],
    say: &mut dyn FnMut(&[&[u8]]),
) {
    let Some(record) = q.record else {
        return;
    };
    let id = record.get();
    for (queued, query) in [(q.v6, "AAAA"), (q.v4, "A")] {
        if queued {
            let ids =
                crate::text::Text::<80>::clipped(format_args!("queueing query [{xfer}/{id}] ")).0;
            say(&[ids.bytes(), query.as_bytes(), b" ", name, at]);
        }
    }
}

/// The threaded resolver's answers to the queries `q` queued for `name`
/// at `at`: each query's addresses of its family, of `addrs`, IPv4's
/// taken first, each line given to `say` (`async_thrdd_check_done`).
pub(crate) fn say_answered(
    q: Queued,
    name: &[u8],
    at: &[u8],
    addrs: &[IpAddr],
    say: &mut dyn FnMut(&[&[u8]]),
) {
    for (queued, v6) in [(q.v4, false), (q.v6, true)] {
        if queued {
            let (addrs, c) = (OfFamily(addrs, v6), if v6 { '6' } else { '4' });
            let mut line = Line::new();
            line.raw(b"Host ").raw(name).raw(at);
            line.text(format_args!(" resolved IPv{c}: {addrs}"));
            say(&[line.bytes()]);
        }
    }
}

/// The addresses of a family, IPv6 if `.1`, among `.0`, as the threaded
/// resolver says them: in order, or `(none)`.
pub(crate) struct OfFamily<'a>(pub(crate) &'a [IpAddr], pub(crate) bool);

impl std::fmt::Display for OfFamily<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut of = self.0.iter().filter(|a| a.is_ipv6() == self.1);
        let Some(first) = of.next() else {
            return f.write_str("(none)");
        };
        first.fmt(f)?;
        of.try_for_each(|a| write!(f, ", {a}"))
    }
}

/// The families a resolve in `ip` asks for: without IPv6 only IPv4's
/// (`Curl_resolv_dns_queries`).
pub(crate) fn family(ip: IpVersion, cx: &dyn ConnCx) -> Family {
    match ip {
        IpVersion::Any if cx.ipv6_works() => Family::Any,
        IpVersion::Any | IpVersion::V4 => Family::V4,
        IpVersion::V6 => Family::V6,
    }
}

/// The addresses of `family` the host `name` stands for, for a connection
/// to `port`, keeping that the name does not exist only if
/// `keep_negative`, as only the setup's own resolve does
/// (`Curl_dnscache_add_negative`); a resolver that answers later is
/// waited for, as C waits for these (`Curl_resolv_blocking`), never over
/// DoH (`Waited`).
pub(super) fn lookup_name(
    (name, port): (&[u8], u16),
    family: Family,
    cx: &mut dyn ConnCx,
    setup: DriveOptions,
    keep_negative: bool,
) -> Result<(TryArc<Answer>, Found), ConnectError> {
    match start::<Waited>(
        (name, port),
        family,
        cx,
        setup,
        keep_negative,
        Holder::Blocking,
    )? {
        Looked::Found(answer, found) => Ok((answer, found)),
        Looked::Pending(mut pending) => {
            let answer = match &mut pending.via {
                Waited::Resolver(resolve) => resolve.wait(),
                Waited::Library(resolve) => {
                    match await_library(resolve, pending.family, (name, port), cx) {
                        Some((answer, TakenAt::InStart)) => {
                            return taken_in_start(answer, (name, port), pending.widen(), cx);
                        }
                        Some((answer, TakenAt::Waited)) => answer,
                        None => {
                            drop(pending);
                            cx.libraries_closed();
                            return Err(ConnectError::Unresolved(Unresolved::GaveUp));
                        }
                    }
                }
            };
            settle(answer, (name, port), pending.widen().into_keeping(), cx)
        }
    }
}

/// The answer of `resolve`, a library's in `family`, waited for as long as
/// the transfer may; none if it may no longer, or the application stopped
/// it (`hostip_resolv`'s first look, then `Curl_async_await`).
fn await_library(
    resolve: &mut Box<dyn DnsResolve>,
    family: Family,
    (name, port): (&[u8], u16),
    cx: &mut dyn ConnCx,
) -> Option<(Result<Vec<IpAddr>, ResolveFailure>, TakenAt)> {
    let queries = family_queries(family);
    let since = cx.now();
    let dns = Component::Dns;
    let turn = |resolve: &mut Box<dyn DnsResolve>, cx: &mut dyn ConnCx| {
        let performed = resolve.perform();
        cx.libraries_closed();
        match performed {
            Ok(()) => resolve.answer(),
            Err(OutOfMemory) => Some(Err(ResolveFailure::OutOfMemory)),
        }
    };
    let mut answer = match take_in_start(resolve, queries, (name, port), cx) {
        Ok(Some(answer)) => return Some((answer, TakenAt::InStart)),
        Ok(None) => None,
        Err(_) => Some(Err(ResolveFailure::OutOfMemory)),
    };
    if answer.is_some() {
        return answer.map(|answer| (answer, TakenAt::Waited));
    }
    cx.of(
        dns,
        format_args!("[{queries}] hostip_resolv started -> {AGAIN_NUMBER}"),
    );
    while answer.is_none() {
        let left = cx.await_resolve_left(since)?;
        let mut polls = Vec::new();
        for (socket, events) in resolve.wants() {
            polls.try_push(SocketPoll::new(&**socket, *events)).ok()?;
        }
        if !polls.is_empty() {
            let wait = resolve.due(left.min(Duration::from_secs(1)));
            cx.net().poll(&mut polls, &mut [], wait).ok()?;
        }
        drop(polls);
        answer = turn(resolve, cx);
        if answer.is_none() {
            cx.await_resolve_tick().ok()?;
        }
    }
    if let Some(Ok(addrs)) = &mut answer {
        if shuffle_said(addrs, cx).is_err() {
            return Some((Err(ResolveFailure::OutOfMemory), TakenAt::Waited));
        }
        let status = resolve.status();
        say_taken(queries, status, cx);
    }
    answer.map(|answer| (answer, TakenAt::Waited))
}

/// Where a blocking resolve's answer was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TakenAt {
    /// Inside the start, as its queries were out (`hostip_resolv_start`).
    InStart,
    /// In the wait after it (`Curl_async_await`).
    Waited,
}

/// The line of a library's resolve answered.
/// Shuffle `addrs` if the transfer asks for it, and say so as C's debug
/// build says it, as the entry is made (`dnsc_entry_assign_addr`): for a
/// library's answer before its take is said, for an address or
/// `localhost` before the resolve is said to have started.
fn shuffle_said(addrs: &mut [IpAddr], cx: &mut dyn ConnCx) -> Result<(), OutOfMemory> {
    if cx.shuffle(addrs)? {
        say_shuffled(addrs.len(), cx);
    }
    Ok(())
}

/// C's debug line for `n` addresses shuffled (`dns_shuffle_addr`).
pub(crate) fn say_shuffled(n: usize, cx: &mut dyn LayerCx) {
    cx.of(Component::Dns, format_args!("Shuffling {n} addresses"));
}

fn say_taken(queries: &str, status: i32, cx: &mut dyn ConnCx) {
    cx.of(
        Component::Dns,
        format_args!(
            "[{queries}] ares_take_result, result=0, ares_result=0, \
             ares_status={status}, dns=found"
        ),
    );
}

/// Where a lookup stands: its answer, or a resolve the resolver answers
/// later, by one of `V`.
pub(super) enum Looked<V = Via> {
    Found(TryArc<Answer>, Found),
    Pending(Pending<V>),
}

/// A resolve the resolver answers later, by one of `V`, and what its
/// answer is to be.
#[derive(Debug)]
pub(super) struct Pending<V = Via> {
    via: V,
    family: Family,
    /// Whether the cache had a stale answer.
    found: fn(Asked) -> Found,
    keep_negative: bool,
    queried: Queried,
    /// When the resolve was asked, and how long AAAA is waited for from
    /// then.
    asked: Instant,
    aaaa_wait: Duration,
    /// How the cache is looked in as its answer is taken.
    looks: Looks,
    /// A resolver's resolve whose lines are said as it goes, as C's
    /// threaded resolver's are, not once its answer has come; and the
    /// families whose answers it has said.
    live: Option<Queried>,
    /// The number of the transfer's record of it, if the context keeps
    /// records.
    record: Option<ResolveNumber>,
}

/// How a resolve's answer is looked for in the cache as it is taken, and
/// whose record it is.
#[derive(Clone, Copy, Debug)]
pub(super) struct Looks {
    holder: Holder,
    wildcard: bool,
    max_age: Option<Duration>,
}

/// What came of taking a resolve's answer.
pub(super) enum Taken {
    /// Nothing yet: the resolve goes on.
    Waiting(Pending),
    /// Its answer, kept; or how it failed.
    Done(Result<(TryArc<Answer>, Found), ConnectError>),
}

/// Who answers a resolve, each owned: dropped, the resolve ends, and
/// nothing of it is left where it was asked. Each says its lines as its
/// backend in C does (`asyn-thrdd.c`, `doh.c`, `asyn-ares.c`).
#[derive(Debug)]
pub(super) enum Via {
    /// The network's resolver's.
    Resolver(Box<dyn Resolving>),
    /// Transfers of the multi's.
    Doh(DohLookup),
    /// A resolver library's own resolve.
    Library(Box<dyn DnsResolve>),
}

/// Who answers a resolve waited for where it is asked: DoH never does, as
/// C cannot wait for it (`Curl_resolv_blocking`).
#[derive(Debug)]
enum Waited {
    Resolver(Box<dyn Resolving>),
    Library(Box<dyn DnsResolve>),
}

impl From<Waited> for Via {
    fn from(waited: Waited) -> Self {
        match waited {
            Waited::Resolver(resolve) => Via::Resolver(resolve),
            Waited::Library(resolve) => Via::Library(resolve),
        }
    }
}

/// The backends a lookup may start its resolve with: the setup's any of
/// the three (`Via`), a blocking one's no DoH (`Waited`).
trait Backend: Into<Via> {
    /// Whether it is the setup's own resolve, which says its lines as it
    /// starts and goes; a blocking resolve's caller says them as it ends.
    const SETUP: bool;
    /// DoH's lookup made one of these, if the transfer wants DoH and DoH
    /// may answer this resolve.
    fn doh(cx: &dyn ConnCx) -> Option<fn(DohLookup) -> Self>;
    fn library(resolve: Box<dyn DnsResolve>) -> Self;
    fn resolver(resolve: Box<dyn Resolving>) -> Self;
    /// The library's resolve, if a library's.
    fn library_mut(&mut self) -> Option<&mut Box<dyn DnsResolve>>;
}

impl Backend for Via {
    const SETUP: bool = true;
    fn doh(cx: &dyn ConnCx) -> Option<fn(DohLookup) -> Self> {
        cx.wants_doh().then_some(Via::Doh)
    }
    fn library(resolve: Box<dyn DnsResolve>) -> Self {
        Via::Library(resolve)
    }
    fn resolver(resolve: Box<dyn Resolving>) -> Self {
        Via::Resolver(resolve)
    }
    fn library_mut(&mut self) -> Option<&mut Box<dyn DnsResolve>> {
        match self {
            Via::Library(resolve) => Some(resolve),
            Via::Resolver(_) | Via::Doh(_) => None,
        }
    }
}

impl Backend for Waited {
    const SETUP: bool = false;
    fn doh(_: &dyn ConnCx) -> Option<fn(DohLookup) -> Self> {
        None
    }
    fn library(resolve: Box<dyn DnsResolve>) -> Self {
        Waited::Library(resolve)
    }
    fn resolver(resolve: Box<dyn Resolving>) -> Self {
        Waited::Resolver(resolve)
    }
    fn library_mut(&mut self) -> Option<&mut Box<dyn DnsResolve>> {
        match self {
            Waited::Library(resolve) => Some(resolve),
            Waited::Resolver(_) => None,
        }
    }
}

impl<V: Into<Via>> Pending<V> {
    /// As a resolve of any backend, for what takes its answer.
    fn widen(self) -> Pending {
        let Pending {
            via,
            family,
            found,
            keep_negative,
            queried,
            asked,
            aaaa_wait,
            looks,
            live,
            record,
        } = self;
        Pending {
            via: via.into(),
            family,
            found,
            keep_negative,
            queried,
            asked,
            aaaa_wait,
            looks,
            live,
            record,
        }
    }
}

/// Which families went as a query of their own.
#[derive(Clone, Copy, Debug)]
struct Queried {
    v6: bool,
    v4: bool,
}

/// The resolve of a setup's first hop's name, still going on as its race
/// began on part of the answer: the name's DNS filter, which C's chain
/// holds above the setup and, for an HTTPS connect filter's race, above
/// both its attempts (`cf_dns`). Whoever sets the connection up holds it,
/// beside the attempts, which follow what it finds as they are driven
/// and never hold it themselves; it is let go of as the setup's chain
/// connects, as it is closed or discarded, or with whatever drops it.
///
/// Held apart from its holder, as only a setup whose resolve answers in
/// parts has one, the transfer's slot holding a pointer.
#[derive(Debug, Default)]
pub(crate) struct Late(Option<Box<Going>>);

/// A resolve the setup goes on beside.
#[derive(Debug)]
struct Going {
    /// The resolve, while it goes on.
    pending: Option<Pending>,
    /// What came of it so far, or all of it once it has come: the
    /// addresses the attempts race.
    answer: TryArc<Answer>,
}

/// What a look at a [`Late`] resolve came to.
#[derive(Debug)]
pub(crate) enum LateLook {
    /// More is still to come, or none was going on.
    Waiting,
    /// All of it came, and was found as it says.
    Found(Found),
    /// The resolve failed.
    Failed(ConnectError),
}

impl Late {
    /// `p` goes on, the race beginning on `answer`, part of its answer.
    fn begin(&mut self, p: Pending, answer: TryArc<Answer>) -> Result<(), OutOfMemory> {
        assert!(!self.going(), "one resolve for the name");
        let going = Going {
            pending: Some(p),
            answer,
        };
        self.0 = Some(curl_alloc::try_box(going)?);
        Ok(())
    }

    fn pending(&self) -> Option<&Pending> {
        self.0.as_ref()?.pending.as_ref()
    }

    /// Not wanted: let go of now, where C destroys it.
    pub(crate) fn end(&mut self) {
        if let Some(going) = &mut self.0 {
            going.pending = None;
        }
    }

    /// Whether a resolve is still going on.
    pub(crate) fn going(&self) -> bool {
        self.pending().is_some()
    }

    /// What has come of it, if it began.
    pub(crate) fn answer(&self) -> Option<&TryArc<Answer>> {
        self.0.as_ref().map(|going| &going.answer)
    }

    /// Looked at, as the DNS filter for `peer` looks at its resolve until
    /// the chain below it connects (`cf_dns_connect`): what has come so
    /// far kept for the attempts, and once all of it has, the resolve let
    /// go of, and how it was found said; or how the resolve failed, which
    /// is the caller's to weigh. Too little memory to take what came is
    /// the error.
    pub(crate) fn poll(
        &mut self,
        peer: &super::Peer,
        cx: &mut dyn ConnCx,
    ) -> Result<LateLook, OutOfMemory> {
        let Some(going) = self.0.as_deref_mut() else {
            return Ok(LateLook::Waiting);
        };
        let Some(p) = going.pending.take() else {
            return Ok(LateLook::Waiting);
        };
        let (name, port) = (peer.name(), peer.port());
        let mut p = match p.take((name, port), cx) {
            Taken::Done(Ok((answer, found))) => {
                cx.hold(Holder::Addresses(cx.rank()));
                going.answer = answer;
                return Ok(LateLook::Found(found));
            }
            Taken::Done(Err(e)) => return Ok(LateLook::Failed(e)),
            Taken::Waiting(p) => p,
        };
        if let Some(part) = p.partial()? {
            going.answer = part.answer(name, p.family)?;
        }
        going.pending = Some(p);
        Ok(LateLook::Waiting)
    }

    /// What its library waits on.
    pub(crate) fn wants(&self) -> impl Iterator<Item = (&dyn Socket, Events)> {
        self.pending()
            .map_or(&[][..], Pending::wants)
            .iter()
            .map(|(s, e)| (&**s, *e))
    }

    /// When it wants to be looked at again, `left` the time it has.
    pub(crate) fn due(&self, now: Instant, left: Duration) -> Option<Instant> {
        self.pending()?.due(now, left)
    }

    /// Let go of as the chain of the setup it went on beside connects,
    /// after its record's line (`cf_dns_connect`'s `Curl_resolv_destroy`):
    /// a library's sockets say they close, and DoH's probes that they are
    /// done (`doh_close`).
    pub(crate) fn chain_connected(self, cx: &mut dyn ConnCx) {
        let Some(p) = self.0.and_then(|going| going.pending) else {
            return;
        };
        let doh = p.over_doh();
        drop(p);
        cx.libraries_closed();
        if doh {
            cx.of(Component::Dns, format_args!("[DoH] probe done"));
        }
    }
}

/// How long AAAA's answer is waited for once A's came
/// (`CURL_HE_AAAA_AWAIT_MS`).
fn aaaa_await() -> Duration {
    #[cfg(feature = "debug-hooks")]
    {
        let mut buf = [0u8; 16];
        if let Some(ms) = curl_os::env::var_into(b"CURL_DBG_HE_AAAA_AWAIT_MS", &mut buf)
            && let Some(ms) = core::str::from_utf8(ms)
                .ok()
                .and_then(|m| m.parse::<u32>().ok())
        {
            return Duration::from_millis(u64::from(ms));
        }
    }
    Duration::from_millis(25)
}

impl Partial {
    /// As an answer the race can go through.
    fn answer(&self, name: &[u8], family: Family) -> Result<TryArc<Answer>, OutOfMemory> {
        let mut addrs = Vec::new();
        addrs.try_extend_from_slice(&self.addrs)?;
        TryArc::try_new(Answer::of(name, addrs, family)?)
    }
}

impl Pending {
    /// What has come so far, if it can say.
    fn partial(&mut self) -> Result<Option<Partial>, OutOfMemory> {
        match &mut self.via {
            Via::Doh(lookup) => lookup.partial().map(Some),
            Via::Library(resolve) => resolve.partial().map(Some),
            Via::Resolver(resolve) => resolve.partial(),
        }
    }

    /// What its answer is kept as and its failure said with, the resolve
    /// let go of: a library closes what it has left open, its sockets
    /// told as they close (`SocketsClosed`).
    fn into_keeping(self) -> Keeping {
        let (library_says, library_status) = match &self.via {
            Via::Library(resolve) => (resolve.explain(), Some(resolve.status())),
            Via::Resolver(_) | Via::Doh(_) => (None, None),
        };
        let library = self.says_its_own();
        Keeping {
            family: self.family,
            found: self.found,
            keep_negative: self.keep_negative,
            queued: self.queued(),
            over_doh: self.over_doh(),
            library,
            says_its_own: library || self.live.is_some(),
            library_says,
            library_status,
        }
    }

    /// How it was queued, if as queries of their own: only the network's
    /// resolver queues them so.
    fn queued(&self) -> Option<Queued> {
        let Queried { v6, v4 } = self.queried;
        match self.via {
            Via::Resolver(_) => (v6 || v4).then_some(Queued {
                record: self.record,
                v6,
                v4,
            }),
            Via::Doh(_) | Via::Library(_) => None,
        }
    }

    fn over_doh(&self) -> bool {
        matches!(self.via, Via::Doh(_))
    }

    /// Whether it says its own lines as it goes, not the network's resolver.
    fn says_its_own(&self) -> bool {
        !matches!(self.via, Via::Resolver(_))
    }

    /// When it wants to be looked at again, `left` the time it has
    /// (`Curl_async_pollset`): a library when it says, within that; the
    /// network's resolver, which wakes the multi as it answers, at the end
    /// of it, as C's threaded resolver arms its timer; DoH's transfers
    /// never, as they wake the multi themselves.
    fn due(&self, now: Instant, left: Duration) -> Option<Instant> {
        match &self.via {
            Via::Library(r) => Some(now.after(r.due(left).min(left))),
            Via::Resolver(_) => Some(now.after(left)),
            Via::Doh(_) => None,
        }
    }

    /// What its library waits on.
    fn wants(&self) -> &[(Box<dyn Socket>, Events)] {
        match &self.via {
            Via::Library(r) => r.wants(),
            Via::Resolver(_) | Via::Doh(_) => &[],
        }
    }

    /// Its answer for `name` on `port` taken, if it has come: looked for in
    /// the cache first, where another transfer may have kept it meanwhile,
    /// which ends this one (`Curl_resolv_take_result`).
    pub(super) fn take(mut self, (name, port): (&[u8], u16), cx: &mut dyn ConnCx) -> Taken {
        let Looks {
            holder,
            wildcard,
            max_age,
        } = self.looks;
        let family = self.family;
        let looked = cx
            .names()
            .section(|c| c.lookup((name, port), family, wildcard, max_age));
        let queries = family_queries(family);
        match looked {
            Lookup::Found(answer) => {
                say_found_cached(queries, (name, port), cx);
                cx.info_with(&[b"Hostname '", name, b"' was found in DNS cache"]);
                cx.resolve_shut(holder);
                drop(self);
                return Taken::Done(Ok((answer, Found::Meanwhile)));
            }
            // An entry without addresses (`fetch_entry`).
            Lookup::Negative => {
                cx.of(
                    Component::Dns,
                    format_args!("cache entry does not have type={queries} addresses"),
                );
                let shown = curl_alloc::Lossy(name);
                cx.of(
                    Component::Dns,
                    format_args!("cache lookup {shown}:{port} queries={queries} -> 6 not found"),
                );
                cx.resolve_shut(holder);
                drop(self);
                let failed = ConnectError::Unresolved(Unresolved::NegativeMeanwhile);
                return Taken::Done(Err(failed));
            }
            Lookup::Stale | Lookup::Missing => {}
        }
        match self.polled((name, port), cx) {
            None => Taken::Waiting(self),
            Some(answer) => Taken::Done(settle(answer, (name, port), self.into_keeping(), cx)),
        }
    }

    /// Its answer for `name` on `port`, if it has come
    /// (`hostip_resolv_take_result`).
    fn polled(
        &mut self,
        (name, port): (&[u8], u16),
        cx: &mut dyn ConnCx,
    ) -> Option<Result<Vec<IpAddr>, ResolveFailure>> {
        match &mut self.via {
            Via::Library(resolve) => {
                let queries = family_queries(self.family);
                say_not_cached(queries, (name, port), cx);
                let performed = resolve.perform();
                cx.libraries_closed();
                if performed.is_err() {
                    return Some(Err(ResolveFailure::OutOfMemory));
                }
                let answer = resolve.answer();
                let Some(mut answer) = answer else {
                    let (ongoing, responses) = resolve.ongoing();
                    let name = curl_alloc::Lossy(name);
                    cx.of(
                        Component::Dns,
                        format_args!(
                            "[{queries}] resolve incomplete, responses={responses}, \
                             ongoing={ongoing} for {name}:{port}"
                        ),
                    );
                    return None;
                };
                // Its channel stays open until the record goes, which
                // arms the name's timer meanwhile (`Curl_async_pollset`).
                cx.resolve_answered_by_library(self.looks.holder);
                // A failure's is said with the failure, after its words.
                if let Ok(addrs) = &mut answer {
                    if shuffle_said(addrs, cx).is_err() {
                        return Some(Err(ResolveFailure::OutOfMemory));
                    }
                    say_taken(queries, resolve.status(), cx);
                }
                Some(answer)
            }
            Via::Resolver(resolve) => {
                let Some(said) = self.live else {
                    return resolve.answer();
                };
                let queries = family_queries(self.family);
                say_not_cached(queries, (name, port), cx);
                let polled = resolve.answer();
                let at = crate::text::Text::<8>::clipped(format_args!(":{port}")).0;
                let queried = self.queried;
                // Each family's answer said once, as it is taken
                // (`async_thrdd_report_item`): what has come so far, or
                // all of it, none for a failure.
                let (came, addrs) = match &polled {
                    Some(Ok(addrs)) => (queried, Some(&addrs[..])),
                    Some(Err(_)) => (queried, None),
                    None => {
                        let Ok(part) = resolve.partial() else {
                            return Some(Err(ResolveFailure::OutOfMemory));
                        };
                        if let Some(part) = part {
                            let came = Queried {
                                v6: queried.v6 && part.v6_answered,
                                v4: queried.v4 && part.v4_answered,
                            };
                            say_came(said, came, name, at.bytes(), &part.addrs, cx);
                            self.live = Some(Queried {
                                v6: said.v6 || came.v6,
                                v4: said.v4 || came.v4,
                            });
                        }
                        let said = self.live.expect("said above");
                        let (v6, v4) = (said.v6, said.v4);
                        let responses = match (v4, v6) {
                            (true, true) => "A+AAAA",
                            (true, false) => "A",
                            (false, true) => "AAAA",
                            (false, false) => "-",
                        };
                        let asked = u8::from(queried.v6) + u8::from(queried.v4);
                        let ongoing = asked.max(1) - u8::from(v6) - u8::from(v4);
                        let shown = curl_alloc::Lossy(name);
                        cx.of(
                            Component::Dns,
                            format_args!(
                                "[{queries}] resolve incomplete, responses={responses}, \
                                 ongoing={ongoing} for {shown}:{port}"
                            ),
                        );
                        return None;
                    }
                };
                say_came(said, came, name, at.bytes(), addrs.unwrap_or(&[]), cx);
                say_name_timer_cleared(cx);
                self.live = Some(queried);
                polled
            }
            Via::Doh(lookup) => match lookup.poll() {
                DohPolled::Waiting { ongoing, responses } => {
                    let queries = family_queries(self.family);
                    say_not_cached(queries, (name, port), cx);
                    let name = curl_alloc::Lossy(name);
                    cx.of(
                        Component::Dns,
                        format_args!(
                            "[{queries}] resolve incomplete, responses={responses}, \
                             ongoing={ongoing} for {name}:{port}"
                        ),
                    );
                    None
                }
                DohPolled::Done(answer) => {
                    say_not_cached(family_queries(self.family), (name, port), cx);
                    cx.of(Component::Dns, format_args!("[DoH] probe done"));
                    if answer.as_ref().is_ok_and(|a| !a.is_empty()) {
                        say_cached_entry(family_queries(self.family), (name, port), cx);
                    }
                    cx.of(Component::Dns, format_args!("[DoH] probe done"));
                    Some(answer)
                }
            },
        }
    }
}

/// That the threaded resolver's answer, found or not, was taken and the
/// name's timer cleared with it (`Curl_async_thrdd_take_result`'s
/// `Curl_expire_clear`).
pub(crate) fn say_name_timer_cleared(cx: &mut dyn ConnCx) {
    let name = crate::multi::timers::TimerKind::AsyncName.name();
    cx.of(Component::Timer, format_args!("[{name}] cleared"));
}

/// That the name's entry is made, as `Curl_dnscache_add` says it.
fn say_cached_entry(queries: &str, (name, port): (&[u8], u16), cx: &mut dyn ConnCx) {
    let name = curl_alloc::Lossy(name);
    cx.of(
        Component::Dns,
        format_args!("cached entry for {name}:{port} queries={queries}"),
    );
}

/// The answers of the families in `came` the threaded resolver had not
/// said, of those in `said`: each family's addresses, of `addrs`, IPv4's
/// first (`async_thrdd_report_item`).
fn say_came(
    said: Queried,
    came: Queried,
    name: &[u8],
    at: &[u8],
    addrs: &[IpAddr],
    cx: &mut dyn ConnCx,
) {
    let new = Queued {
        record: None,
        v6: came.v6 && !said.v6,
        v4: came.v4 && !said.v4,
    };
    say_answered(new, name, at, addrs, &mut |parts| {
        cx.of_with(Component::Dns, parts);
    });
}

/// That the name is in the cache, as `Curl_dnscache_get` says it.
fn say_found_cached(queries: &str, (name, port): (&[u8], u16), cx: &mut dyn ConnCx) {
    let name = curl_alloc::Lossy(name);
    cx.of(
        Component::Dns,
        format_args!("cache lookup {name}:{port} queries={queries} -> 0 found"),
    );
}

/// That the cache keeps that the name has no addresses of the families
/// asked for, as `Curl_dnscache_get` says it (`fetch_entry`).
fn say_negative_cached(queries: &str, (name, port): (&[u8], u16), cx: &mut dyn ConnCx) {
    cx.of(
        Component::Dns,
        format_args!("cache entry does not have type={queries} addresses"),
    );
    let at = crate::text::Text::<8>::clipped(format_args!(":{port}")).0;
    let code = crate::trace::Code(Err(ErrorKind::CouldntResolveHost));
    let rest =
        crate::text::Text::<64>::clipped(format_args!(" queries={queries} -> {code} not found")).0;
    cx.of_with(
        Component::Dns,
        &[b"cache lookup ", name, at.bytes(), rest.bytes()],
    );
}

/// That the name is not in the cache, as `Curl_dnscache_get` says it each
/// time it is asked.
fn say_not_cached(queries: &str, (name, port): (&[u8], u16), cx: &mut dyn ConnCx) {
    let at = crate::text::Text::<8>::clipped(format_args!(":{port}")).0;
    let rest =
        crate::text::Text::<64>::clipped(format_args!(" queries={queries} -> 0 not found")).0;
    cx.of_with(
        Component::Dns,
        &[b"cache lookup ", name, at.bytes(), rest.bytes()],
    );
}

/// The queries of a setup's resolve in `family` of the address `ip`,
/// which asks for its own family too, as the DNS trace names them.
fn setup_queries(family: Family, ip: IpAddr) -> &'static str {
    match (family, ip) {
        (Family::Any, _) | (Family::V4, IpAddr::V6(_)) | (Family::V6, IpAddr::V4(_)) => "A+AAAA",
        (Family::V4, IpAddr::V4(_)) => "A",
        (Family::V6, IpAddr::V6(_)) => "AAAA",
    }
}

/// The queries of a resolve in `family`, as the DNS trace names them
/// (`Curl_resolv_query_str`).
fn family_queries(family: Family) -> &'static str {
    match family {
        Family::V4 => "A",
        Family::V6 => "AAAA",
        Family::Any => "A+AAAA",
    }
}

/// The setup's lookup started (`start`), DoH answering it if the
/// transfer wants it.
pub(super) fn lookup_start(
    (name, port): (&[u8], u16),
    family: Family,
    cx: &mut dyn ConnCx,
    setup: DriveOptions,
    keep_negative: bool,
    holder: Holder,
) -> Result<Looked, ConnectError> {
    start::<Via>((name, port), family, cx, setup, keep_negative, holder)
}

/// A lookup started: the cache, then the shortcuts, then, if `V` may be
/// DoH and the transfer wants it, DoH, else the resolver, whose answer
/// may come later (`hostip_resolv_start`). One that answers later is kept
/// on the transfer for `holder`, as C keeps its record of it.
fn start<V: Backend>(
    (name, port): (&[u8], u16),
    family: Family,
    cx: &mut dyn ConnCx,
    setup: DriveOptions,
    keep_negative: bool,
    holder: Holder,
) -> Result<Looked<V>, ConnectError> {
    if is_onion(name) {
        return Err(ConnectError::Unresolved(Unresolved::Onion));
    }
    // A setup's name an address asks for its own family too
    // (`cf_dns_start`); a blocking resolve's caller asks for `family`.
    let queries = match literal(name) {
        Some(ip) if V::SETUP => setup_queries(family, ip),
        _ => family_queries(family),
    };
    // The C debug build's line, before the cache is looked in.
    #[cfg(feature = "debug-hooks")]
    {
        let at = crate::text::Text::<8>::clipped(format_args!(":{port}")).0;
        cx.of_with(
            Component::Dns,
            &[
                b"[",
                queries.as_bytes(),
                b"] hostip_resolv(",
                name,
                at.bytes(),
                b")",
            ],
        );
    }
    if family == Family::V6 && cx.fails_ipv6_resolves() {
        return Err(ConnectError::Unresolved(Unresolved::DebugFailIpv6));
    }
    let now = cx.now();
    let ipv6 = cx.ipv6_works();
    let (wildcard, max_age) = (setup.wildcard, setup.max_age);
    let looks = Looks {
        holder,
        wildcard,
        max_age,
    };
    // What the cache had, said once it has been looked in, outside its
    // lock (`Curl_dnscache_get`, `hostip_resolv`).
    let (found, stale): (fn(Asked) -> Found, bool) = match cx
        .names()
        .section(|c| c.lookup((name, port), family, wildcard, max_age))
    {
        Lookup::Found(answer) => {
            say_found_cached(queries, (name, port), cx);
            cx.info_with(&[b"Hostname ", name, b" was found in DNS cache"]);
            return Ok(Looked::Found(answer, Found::Cached));
        }
        Lookup::Negative => {
            say_negative_cached(queries, (name, port), cx);
            return Err(ConnectError::Unresolved(Unresolved::Negative));
        }
        Lookup::Stale => (Found::Stale, true),
        Lookup::Missing => (Found::Resolved, false),
    };
    if stale {
        cx.info(format_args!("Hostname in DNS cache was stale, zapped"));
    }
    say_not_cached(queries, (name, port), cx);
    let oom = |OutOfMemory| ConnectError::OutOfMemory;
    if let Some(mut answer) = shortcut(name).map_err(oom)? {
        // Told though no resolver is asked, as C tells it.
        cx.announce_resolve()?;
        shuffle_said(answer.addrs_mut(), cx).map_err(oom)?;
        let answer = TryArc::try_new(answer).map_err(oom)?;
        // Started, then kept, each said where C says it: around the
        // cache's lock (`hostip_resolv`, `Curl_dnscache_add`).
        cx.of(
            Component::Dns,
            format_args!("[{queries}] hostip_resolv started -> 0"),
        );
        cx.names()
            .section(|c| c.put(answer.clone(), port, false))
            .map_err(oom)?;
        say_cached_entry(queries, (name, port), cx);
        return Ok(Looked::Found(answer, found(Asked::Shortcut)));
    }
    // Without IPv6 no caller asks for both families (`family`), and a
    // resolver library is not asked for IPv6 alone.
    let doh = V::doh(cx);
    let over_doh = doh.is_some();
    if over_doh || (cx.has_dns_library() && !(family == Family::V6 && !ipv6)) {
        cx.announce_resolve()?;
        let via = if let Some(doh) = doh {
            cx.doh_start(name, family).map(doh)
        } else {
            match cx.dns_start(name, port, family) {
                Some(Ok(resolve)) => Ok(V::library(resolve)),
                Some(Err(DnsRefused::OutOfMemory)) | None => Err(ConnectError::OutOfMemory),
                Some(Err(DnsRefused::Init)) => Err(ConnectError::Refused(ErrorKind::FailedInit)),
                Some(Err(DnsRefused::BadOption(why))) => {
                    // C's debug build says which.
                    #[cfg(feature = "debug-hooks")]
                    cx.info(format_args!("{why}"));
                    #[cfg(not(feature = "debug-hooks"))]
                    let _ = why;
                    Err(ConnectError::Refused(ErrorKind::BadFunctionArgument))
                }
                Some(Err(DnsRefused::BadRecord)) => {
                    Err(ConnectError::Refused(ErrorKind::BadFunctionArgument))
                }
            }
        };
        let mut via = match via {
            Ok(via) => via,
            Err(e) => {
                // `Curl_resolv`'s words for a failure of no resolver's.
                let refused = match &e {
                    ConnectError::OutOfMemory => Some(ErrorKind::OutOfMemory),
                    ConnectError::Refused(kind) => Some(*kind),
                    _ => None,
                };
                if let Some(kind) = refused {
                    // Its record was made before the resolve was asked
                    // for, and goes as it fails (`hostip_resolv_start`).
                    if kind != ErrorKind::OutOfMemory {
                        cx.resolve_kept(holder).map_err(oom)?;
                        cx.resolve_gone(holder);
                    }
                    let code = crate::trace::Code(Err(kind));
                    let port = crate::text::Text::<8>::clipped(format_args!(":{port}")).0;
                    let error =
                        crate::text::Text::<32>::clipped(format_args!("Error {code} resolving ")).0;
                    if !over_doh {
                        cx.of(
                            Component::Dns,
                            format_args!("[{queries}] hostip_resolv started -> {code}"),
                        );
                    }
                    cx.fail_with(&[error.bytes(), name, port.bytes()]);
                    // The setup's filter says these; a blocking resolve has none.
                    if V::SETUP {
                        cx.fail_with(&[b"Could not resolve: ", name]);
                        if !over_doh {
                            cx.of(
                                Component::Dns,
                                format_args!("[{queries}] error resolving: {code}"),
                            );
                        }
                    }
                }
                return Err(e);
            }
        };
        // What it found it could not use is gone already.
        cx.libraries_closed();
        // A blocking resolve looks for its answer as it waits for it.
        let mut at_once = None;
        if V::SETUP {
            if let Some(resolve) = via.library_mut() {
                at_once = take_in_start(resolve, queries, (name, port), cx)?;
            }
            if at_once.is_none() {
                cx.of(
                    Component::Dns,
                    format_args!("[{queries}] hostip_resolv started -> {AGAIN_NUMBER}"),
                );
            }
        }
        // Its record is made before the resolve starts, and goes at once
        // with an answer taken in the start (`hostip_async_new`,
        // `Curl_async_destroy`).
        cx.resolve_kept(holder).map_err(oom)?;
        let pending = Pending {
            via,
            queried: Queried {
                v6: false,
                v4: false,
            },
            record: cx.resolve_number(holder),
            family,
            found,
            keep_negative,
            asked: now,
            aaaa_wait: aaaa_await(),
            looks,
            live: None,
        };
        return match at_once {
            Some(answer) => taken_in_start(answer, (name, port), pending.widen(), cx)
                .map(|(a, f)| Looked::Found(a, f)),
            None => Ok(Looked::Pending(pending)),
        };
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
    // An answer had at once is kept as the resolver's, queued as no
    // queries of their own.
    let at_once = Keeping {
        family,
        found,
        keep_negative,
        queued: None,
        over_doh: false,
        library: false,
        says_its_own: false,
        library_says: None,
        library_status: None,
    };
    match started.expect("the network lends its resolver") {
        Ok(Resolve::Pending { resolve, v6, v4 }) => {
            // Dropped on a failure from here, it leaves nothing in the
            // resolver.
            cx.resolve_kept(holder).map_err(oom)?;
            let record = cx.resolve_number(holder);
            let queued = Queued { record, v6, v4 };
            let mut pending = Pending {
                via: V::resolver(resolve),
                queried: Queried { v6, v4 },
                record,
                family,
                found,
                keep_negative,
                asked: now,
                aaaa_wait: aaaa_await(),
                looks,
                live: None,
            };
            // The setup's resolve says its lines as it starts and as it
            // goes; a blocking resolve's caller says them as it ends.
            if V::SETUP {
                let at = crate::text::Text::<8>::clipped(format_args!(":{port}")).0;
                let xfer = cx.transfer_number();
                say_queued(xfer, queued, name, at.bytes(), &mut |parts| {
                    cx.of_with(Component::Dns, parts);
                });
                cx.of(
                    Component::Dns,
                    format_args!("[{queries}] hostip_resolv started -> {AGAIN_NUMBER}"),
                );
                pending.live = Some(Queried {
                    v6: false,
                    v4: false,
                });
            }
            Ok(Looked::Pending(pending))
        }
        Ok(Resolve::Answer(addrs)) => {
            let (answer, found) = settle(Ok(addrs), (name, port), at_once, cx)?;
            Ok(Looked::Found(answer, found))
        }
        Err(why) => {
            Err(settle(Err(why), (name, port), at_once, cx).expect_err("a failure settles as one"))
        }
    }
}

/// A library's answer taken inside the start of its resolve, as
/// `hostip_resolv_start` takes it on `CURLE_AGAIN`: looked for at once
/// if its queries were out as it was asked, and taken if that look ended
/// them, the take's lines said (`hostip_resolv_take_result`). One the
/// library had as it was asked, with no query out, is not looked for:
/// C's c-ares then returns `CURLE_OK` and the answer is taken at the next
/// look (`Curl_async_getaddrinfo`). `None` while it is to come.
fn take_in_start(
    resolve: &mut Box<dyn DnsResolve>,
    queries: &str,
    (name, port): (&[u8], u16),
    cx: &mut dyn ConnCx,
) -> Result<Option<Result<Vec<IpAddr>, ResolveFailure>>, ConnectError> {
    if resolve.ongoing().0 == 0 {
        return Ok(None);
    }
    if resolve.perform().is_err() {
        return Err(ConnectError::OutOfMemory);
    }
    cx.libraries_closed();
    let (ongoing, responses) = resolve.ongoing();
    if ongoing > 0 {
        let name = curl_alloc::Lossy(name);
        cx.of(
            Component::Dns,
            format_args!(
                "[{queries}] resolve incomplete, responses={responses}, \
                 ongoing={ongoing} for {name}:{port}"
            ),
        );
        return Ok(None);
    }
    match resolve.answer() {
        Some(Ok(mut addrs)) => {
            shuffle_said(&mut addrs, cx).map_err(|OutOfMemory| ConnectError::OutOfMemory)?;
            say_taken(queries, resolve.status(), cx);
            let shown = curl_alloc::Lossy(name);
            cx.of(
                Component::Dns,
                format_args!("[{queries}] resolve complete for {shown}:{port}"),
            );
            Ok(Some(Ok(addrs)))
        }
        // A failure's lines are said with the failure; one for memory fails
        // the start as it settles (`settle`).
        Some(Err(why)) => Ok(Some(Err(why))),
        None => Ok(None),
    }
}

/// A library's answer taken inside the start of its resolve, `pending`:
/// the resolve's record goes at once, and the start says it is done
/// (`hostip_resolv_start`'s `Curl_async_destroy`, `hostip_resolv`); the
/// answer kept, the name's not existing kept whatever `pending` says, as
/// `hostip_resolv` keeps it (`Curl_dnscache_add_negative`). A failure's
/// record goes with the failure's words, which come first
/// (`Curl_async_failed`): the failure says when.
fn taken_in_start(
    answer: Result<Vec<IpAddr>, ResolveFailure>,
    (name, port): (&[u8], u16),
    pending: Pending,
    cx: &mut dyn ConnCx,
) -> Result<(TryArc<Answer>, Found), ConnectError> {
    let (holder, found) = (pending.looks.holder, pending.found);
    match answer {
        Ok(addrs) => {
            cx.resolve_gone(holder);
            let queries = family_queries(pending.family);
            cx.of(
                Component::Dns,
                format_args!("[{queries}] hostip_resolv started -> 0"),
            );
            let keeping = pending.into_keeping();
            let (answer, _) = settle(Ok(addrs), (name, port), keeping, cx)?;
            Ok((answer, found(Asked::InStart)))
        }
        Err(why) => {
            let keeping = Keeping {
                keep_negative: true,
                ..pending.into_keeping()
            };
            let mut failed = match settle(Err(why), (name, port), keeping, cx) {
                Ok(_) => unreachable!("a failure settles as one"),
                Err(failed) => failed,
            };
            if let ConnectError::Unresolved(Unresolved::Resolver { in_start, .. }) = &mut failed {
                *in_start = Some(holder);
            }
            Err(failed)
        }
    }
}

/// What a resolve's answer is kept as, and what its failure is said
/// with, taken from the resolve as its answer is, or made for one had at
/// once.
#[derive(Clone, Copy)]
pub(super) struct Keeping {
    family: Family,
    /// Whether the cache had a stale answer.
    found: fn(Asked) -> Found,
    keep_negative: bool,
    queued: Option<Queued>,
    over_doh: bool,
    /// A library's or DoH's, which says its own lines, not the network's
    /// resolver.
    library: bool,
    /// It said its lines as it went, none left to say for it now.
    says_its_own: bool,
    library_says: Option<&'static str>,
    library_status: Option<i32>,
}

/// The resolver's answer for `name` on `port`, kept in the cache as
/// `keeping` says; that the name does not exist kept too, if the lookup
/// keeps negative answers.
pub(super) fn settle(
    answer: Result<Vec<IpAddr>, ResolveFailure>,
    (name, port): (&[u8], u16),
    keeping: Keeping,
    cx: &mut dyn ConnCx,
) -> Result<(TryArc<Answer>, Found), ConnectError> {
    let oom = |OutOfMemory| ConnectError::OutOfMemory;
    let Keeping {
        family,
        found,
        keep_negative,
        queued,
        over_doh,
        library,
        says_its_own,
        library_says,
        library_status,
    } = keeping;
    let refused = |why: ResolveFailure, cx: &mut dyn ConnCx| {
        let mut explained = library_says;
        if !library {
            cx.net().with_resolver(&mut |r| explained = r.explain(why));
        }
        ConnectError::Unresolved(Unresolved::Resolver {
            why,
            queued,
            explained,
            over_doh,
            says_its_own,
            library_status,
            in_start: None,
        })
    };
    let answer = match answer {
        // A library's were shuffled as they were taken, which said so.
        Ok(mut addrs) if !library => {
            let shuffled = cx.shuffle(&mut addrs).map_err(oom)?;
            let mut answer = Answer::of(name, addrs, family).map_err(oom)?;
            match shuffled && says_its_own {
                true => say_shuffled(answer.addrs().len(), cx),
                false if shuffled => answer.mark_shuffled(),
                false => {}
            }
            answer
        }
        Ok(addrs) => Answer::of(name, addrs, family).map_err(oom)?,
        Err(ResolveFailure::OutOfMemory) => return Err(ConnectError::OutOfMemory),
        Err(why @ (ResolveFailure::NotFound | ResolveFailure::NoData)) if keep_negative => {
            let none = Answer::of(name, Vec::new(), family).map_err(oom)?;
            let none = TryArc::try_new(none).map_err(oom)?;
            cx.names()
                .section(|c| c.put(none, port, false))
                .map_err(oom)?;
            return Err(refused(why, cx));
        }
        Err(why) => return Err(refused(why, cx)),
    };
    let answer = TryArc::try_new(answer).map_err(oom)?;
    cx.names()
        .section(|c| c.put(answer.clone(), port, false))
        .map_err(oom)?;
    let asked = if says_its_own {
        Asked::Doh
    } else {
        Asked::Resolver(queued)
    };
    Ok((answer, found(asked)))
}

/// The addresses `name`, a host without brackets, stands for without
/// asking a resolver (`hostip_resolv_start`'s shortcuts): an address
/// itself, or the loopback addresses for `localhost` and the names under
/// it (RFC 6761). None for any other name, which a resolver must find.
fn shortcut(name: &[u8]) -> Result<Option<Answer>, OutOfMemory> {
    let mut addrs = Vec::new();
    if let Some(ip) = literal(name) {
        addrs.try_push(ip)?;
    } else if is_localhost(name) {
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

/// C's name for the address queries a resolve of `peer`'s name in `ip`
/// makes (`Curl_resolv_query_str`), with IPv6 working or not: an
/// address's own family is always asked for (`cf_dns_start`).
pub(crate) fn queries(peer: &Peer, ip: IpVersion, ipv6_works: bool) -> &'static str {
    let (mut a, mut aaaa) = match ip {
        IpVersion::Any => (true, ipv6_works),
        IpVersion::V4 => (true, false),
        IpVersion::V6 => (false, true),
    };
    match literal(peer.name()) {
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

/// `name`, a host without brackets, as an address if it is one: IPv4
/// dotted, or IPv6 without a zone (`Curl_is_ipaddr`, whose
/// `inet_pton` takes no zone either).
fn literal(name: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(name).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolve that never answers, for a test that only holds one.
    #[derive(Debug)]
    struct Unanswered;

    impl Resolving for Unanswered {
        fn answer(&mut self) -> Option<Result<Vec<IpAddr>, ResolveFailure>> {
            None
        }

        fn wait(&mut self) -> Result<Vec<IpAddr>, ResolveFailure> {
            unreachable!("not waited for")
        }
    }

    /// A resolve of the name that never answers.
    fn unanswered() -> Pending {
        Pending {
            via: Via::Resolver(Box::new(Unanswered)),
            family: Family::Any,
            found: Found::Resolved,
            keep_negative: false,
            queried: Queried { v6: true, v4: true },
            record: None,
            asked: ManualClock::new().unwrap().now(),
            aaaa_wait: Duration::ZERO,
            looks: Looks {
                holder: Holder::Addresses(crate::multi::state::ConnRank::First),
                wildcard: false,
                max_age: None,
            },
            live: None,
        }
    }

    /// The name's resolve, going on with `answer` found so far, or ended
    /// with it.
    fn name_with(answer: TryArc<Answer>, going: bool) -> Late {
        Late(Some(Box::new(Going {
            pending: going.then(unanswered),
            answer,
        })))
    }

    /// A race expects more addresses only while the name's resolve it
    /// follows goes on: with none it is out of addresses at once, not
    /// waiting for some that never come.
    #[test]
    fn more_addresses_are_coming_only_while_a_resolve_goes_on() {
        let mut e = Eyeballs::new(Addresses::Unix, IpVersion::Any);
        assert!(!e.coming(), "nothing goes on");
        let answer = TryArc::try_new(Answer::new(b"abc.test", Vec::new()).unwrap()).unwrap();
        e.follow(&name_with(answer.clone(), true));
        assert!(e.coming(), "the name's resolve goes on");
        e.follow(&name_with(answer, false));
        assert!(!e.coming(), "the name's resolve ended");
    }
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

    /// A second attempt, on what another's resolve has found so far: it
    /// waits while more may come, starts once an address does, and without
    /// any and none to come it fails rather than expecting one.
    #[test]
    fn a_second_attempt_goes_on_what_the_firsts_resolve_finds() {
        let clock = ManualClock::new().unwrap();
        let start = clock.now();
        let at = SocketAddr::new("127.0.0.1".parse().unwrap(), 123);
        let mut net = FakeNet::new(clock.clone()).with_peer(at, FakePeer::Silent);
        let peer = Peer::new(Scheme::HTTP, b"abc.test".to_vec(), 123, None);
        let route = NetRoute {
            origin: TryArc::try_new(peer).unwrap(),
            via: None,
            proxy: None,
            tls: None,
            cold: None,
        };
        let answer =
            |addrs: Vec<IpAddr>| TryArc::try_new(Answer::new(b"abc.test", addrs).unwrap()).unwrap();
        let setup = || DriveOptions {
            wildcard: false,
            max_age: Some(Duration::from_secs(60)),
            delay: Duration::from_millis(200),
            scope: None,
            socket: SocketSetup::PLAIN,
            haproxy: false,
            layer: None,
            linger: None,
        };
        let machine = || {
            ConnectMachine::racing(
                ConnNumber(0),
                route.clone(),
                crate::conn::Dial::Stream,
                start,
                Closer::System,
                ConnSettings::DEFAULT,
                Addresses::Resolved(answer(Vec::new())),
            )
        };
        let mut dns = DnsCache::default();

        let m = machine();
        let mut name = name_with(answer(Vec::new()), true);
        let mut cx = Plain {
            net: &mut net,
            dns: &mut dns,
            now: clock.now(),
        };
        let Ok(Drove::Connecting(m, Progress::Resolving { .. })) =
            m.drive(&mut cx, setup(), &mut name)
        else {
            panic!("it waits for what comes");
        };
        let mut name = name_with(answer(vec![at.ip()]), true);
        let Ok(Drove::Connecting(m, Progress::Trying { .. })) =
            m.drive(&mut cx, setup(), &mut name)
        else {
            panic!("it starts on what came");
        };
        m.close(cx.net);

        let m = machine();
        let mut name = name_with(answer(Vec::new()), false);
        assert!(matches!(
            m.drive(&mut cx, setup(), &mut name),
            Err(ConnectError::Failed(None, ErrorKind::CouldntConnect))
        ));
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
        let scheme = Scheme::HTTP;
        let peer = Peer::new(scheme, b"abc.test".to_vec(), 123, None);
        let route = NetRoute {
            origin: TryArc::try_new(peer).unwrap(),
            via: None,
            proxy: None,
            tls: None,
            cold: crate::conn::RouteCold::of_ip(ip),
        };
        let mut m = ConnectMachine::new(
            ConnNumber(0),
            route,
            crate::conn::Dial::Stream,
            start,
            Closer::System,
            ConnSettings::DEFAULT,
        );
        m.stage = Stage::Racing(Racing {
            ran: false,
            last_failed: None,
            eyeballs: Eyeballs::new(
                Addresses::Resolved(
                    TryArc::try_new(Answer::new(b"abc.test", addrs).unwrap()).unwrap(),
                ),
                ip,
            ),
            attempts: Vec::new(),
            last_start: None,
            target: None,
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
            let setup = DriveOptions {
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
            match m.drive(&mut cx, setup, &mut Late::default()) {
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
                        Progress::Dialed | Progress::Tunnel { .. } => unreachable!("no proxy"),
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
        let scheme = Scheme::HTTP;
        let peer = Peer::new(scheme, b"late.test".to_vec(), 123, None);
        let route = NetRoute {
            origin: TryArc::try_new(peer).unwrap(),
            via: None,
            proxy: None,
            tls: None,
            cold: None,
        };
        let m = ConnectMachine::new(
            ConnNumber(0),
            route,
            crate::conn::Dial::Stream,
            clock.now(),
            Closer::System,
            ConnSettings::DEFAULT,
        );
        let setup = DriveOptions {
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
        let m = match m.drive(&mut cx, setup, &mut Late::default()) {
            // Looked at again as its time runs out, as C's threaded
            // resolver arms its timer (`Curl_async_pollset`).
            Ok(Drove::Connecting(m, Progress::Resolving { retry: Some(_), .. })) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(net.resolving(), 1);
        (m, net)
    }

    /// A route that dials QUIC opens a socket for datagrams for each
    /// attempt, set as QUIC's are, and one over TCP a stream; TCP's
    /// options are set on a stream alone (`cf_socket_open`'s `is_tcp`).
    /// With no HTTP/3 library, the QUIC attempt fails once its socket is
    /// set. On Windows an IPv6 socket is made to reach IPv4 too, and one
    /// to the loopback address gives up after its first SYN.
    #[test]
    fn a_route_over_quic_opens_a_socket_for_datagrams() {
        let v4: IpAddr = [127, 0, 0, 1].into();
        let v6 = IpAddr::from(Ipv6Addr::LOCALHOST);
        for (dial, datagrams, at) in [
            (crate::conn::Dial::Stream, 0, v4),
            (crate::conn::Dial::Stream, 0, v6),
            (crate::conn::Dial::Quic, 1, v4),
        ] {
            let clock = ManualClock::new().unwrap();
            let wire = crate::conn::io::Conversation::new(b"", false);
            let mut net = FakeNet::new(clock.clone())
                .with_name("quic.test", &[at])
                .with_peer(SocketAddr::new(at, 443), FakePeer::Silent)
                .with_conversation(SocketAddr::new(at, 443), wire.clone());
            let scheme = Scheme::HTTPS;
            let peer = Peer::new(scheme, b"quic.test".to_vec(), 443, None);
            let route = NetRoute {
                origin: TryArc::try_new(peer).unwrap(),
                via: None,
                proxy: None,
                tls: None,
                cold: None,
            };
            let mut m = Some(ConnectMachine::new(
                ConnNumber(0),
                route,
                dial,
                clock.now(),
                Closer::System,
                ConnSettings::DEFAULT,
            ));
            let setup = DriveOptions {
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
                match m.take().expect("driven while it sets up").drive(
                    &mut cx,
                    setup,
                    &mut Late::default(),
                ) {
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
                crate::conn::Dial::Stream => {
                    assert_eq!(net.open_sockets(), 1);
                    assert!(options.contains(&SocketOption::NoDelay), "{options:?}");
                    assert!(options.contains(&SocketOption::KeepAlive), "{options:?}");
                    assert!(
                        options.contains(&SocketOption::FastOpenConnect),
                        "{options:?}"
                    );
                    #[cfg(windows)]
                    {
                        let dual = options.contains(&SocketOption::DualStack);
                        assert_eq!(dual, at.is_ipv6(), "{options:?}");
                        let first = options.first();
                        assert_eq!(dual, first == Some(&SocketOption::DualStack));
                        // After TCP's own options, before the connect's.
                        let at = |o| options.iter().position(|p| *p == o);
                        let rto = at(SocketOption::NoSynRetransmissions);
                        let count = at(SocketOption::KeepCount(9));
                        assert_eq!(rto, count.map(|c| c + 1), "{options:?}");
                    }
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
                crate::conn::Dial::Udp => unreachable!("not tried"),
            }
        }
    }

    /// The loopback address is told by its text, as C tells it: a mapped
    /// IPv4 one, or another in 127/8, is not it.
    #[test]
    fn the_loopback_address_is_told_as_c_tells_it() {
        assert!(targets_localhost([127, 0, 0, 1].into()));
        assert!(targets_localhost(Ipv6Addr::LOCALHOST.into()));
        assert!(!targets_localhost([127, 0, 0, 2].into()));
        assert!(!targets_localhost(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped().into()
        ));
    }

    /// A setup closed while its resolve waits cancels it.
    #[test]
    fn a_closed_setup_cancels_its_resolve() {
        let late = crate::conn::io::Late::new();
        let (m, mut net) = waiting_for(&late);
        m.close(&mut net);
        assert_eq!(net.resolving(), 0);
    }

    /// A setup dropped while its resolve waits, by whatever drops it,
    /// leaves nothing in the resolver.
    #[test]
    fn a_dropped_setup_leaves_nothing_in_the_resolver() {
        let late = crate::conn::io::Late::new();
        let (m, net) = waiting_for(&late);
        drop(m);
        assert_eq!(net.resolving(), 0);
    }

    /// A race begun on what AAAA answered hands the resolve still waiting
    /// for A to the name's filter above it, and holds none of it: once the
    /// race connects, the name's still has it, for the chain's connect to
    /// let go of (`cf_dns_connect`'s `Curl_resolv_destroy`). Until then the
    /// resolver keeps it, and once let go of, forgets it rather than
    /// answering a setup that is gone.
    #[test]
    fn a_race_connected_leaves_the_resolve_to_the_name() {
        let clock = ManualClock::new().unwrap();
        let late = crate::conn::io::Late::new();
        let up: SocketAddr = "[::1]:5".parse().unwrap();
        let mut net = FakeNet::new(clock.clone())
            .with_late_name("late.test", &[up.ip(), [127, 0, 0, 1].into()], &late)
            .with_v6_first()
            .with_peer(up, FakePeer::AcceptsAfter(Duration::from_millis(10)));
        let peer = Peer::new(Scheme::HTTP, b"late.test".to_vec(), 5, None);
        let route = NetRoute {
            origin: TryArc::try_new(peer).unwrap(),
            via: None,
            proxy: None,
            tls: None,
            cold: None,
        };
        let mut m = ConnectMachine::new(
            ConnNumber(0),
            route,
            crate::conn::Dial::Stream,
            clock.now(),
            Closer::System,
            ConnSettings::DEFAULT,
        );
        let mut dns = DnsCache::default();
        let mut name = Late::default();
        let mut raced = false;
        let conn = loop {
            let setup = DriveOptions {
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
                dns: &mut dns,
                now: clock.now(),
            };
            match m.drive(&mut cx, setup, &mut name).unwrap() {
                Drove::Connecting(next, progress) => {
                    m = next;
                    raced |= name.going() && m.races();
                    match progress {
                        Progress::Waiting { .. } | Progress::Resolving { .. } => {
                            clock.advance(Duration::from_millis(1));
                        }
                        _ => {}
                    }
                }
                Drove::Established(conn) => break conn,
            }
        };
        assert!(raced, "the race began while A was awaited");
        assert_eq!(conn.remote, Some(Remote::Inet(up)));
        assert!(name.going(), "the name's");
        assert_eq!(net.resolving(), 1, "still asked for");
        drop(name);
        assert_eq!(net.resolving(), 0, "the resolve was cancelled");
        let Transport::Stream(stream) = conn.transport else {
            panic!("over the network");
        };
        net.close(stream.into_socket());
    }

    /// A setup to `late.test` driven until its race has begun on what
    /// AAAA answered, A still awaited by the name's resolve.
    fn racing_while_a_is_awaited() -> (ConnectMachine, Late, FakeNet, DnsCache, ManualClock) {
        let clock = ManualClock::new().unwrap();
        let late = crate::conn::io::Late::new();
        let up: SocketAddr = "[::1]:5".parse().unwrap();
        let mut net = FakeNet::new(clock.clone())
            .with_late_name("late.test", &[up.ip(), [127, 0, 0, 1].into()], &late)
            .with_v6_first()
            .with_peer(up, FakePeer::AcceptsAfter(Duration::from_secs(60)));
        let peer = Peer::new(Scheme::HTTP, b"late.test".to_vec(), 5, None);
        let route = NetRoute {
            origin: TryArc::try_new(peer).unwrap(),
            via: None,
            proxy: None,
            tls: None,
            cold: None,
        };
        let mut m = ConnectMachine::new(
            ConnNumber(0),
            route,
            crate::conn::Dial::Stream,
            clock.now(),
            Closer::System,
            ConnSettings::DEFAULT,
        );
        let mut dns = DnsCache::default();
        let setup = DriveOptions {
            wildcard: false,
            max_age: Some(Duration::from_secs(60)),
            delay: Duration::from_millis(200),
            scope: None,
            socket: SocketSetup::PLAIN,
            haproxy: false,
            layer: None,
            linger: None,
        };
        let mut name = Late::default();
        let m = loop {
            let mut cx = Plain {
                net: &mut net,
                dns: &mut dns,
                now: clock.now(),
            };
            match m.drive(&mut cx, setup, &mut name).unwrap() {
                Drove::Connecting(next, _) => {
                    if name.going() && next.races() {
                        break next;
                    }
                    m = next;
                    clock.advance(Duration::from_millis(1));
                }
                Drove::Established(..) => panic!("the race is not won"),
            }
        };
        assert_eq!(net.resolving(), 1, "A is awaited");
        (m, name, net, dns, clock)
    }

    /// A race begun on what AAAA answered, discarded while A is still
    /// awaited, as an HTTPS race's other attempt's win or its own failure
    /// discards it, leaves the resolve to the name's filter above it, for
    /// the attempt still racing to follow; the name's let go of, the
    /// resolver forgets it, none left to answer a setup that is gone
    /// (`Curl_resolv_destroy`).
    #[test]
    fn a_race_discarded_leaves_the_resolve_to_the_name() {
        let (m, mut name, mut net, mut dns, clock) = racing_while_a_is_awaited();
        let mut cx = Plain {
            net: &mut net,
            dns: &mut dns,
            now: clock.now(),
        };
        m.discard(&mut cx);
        assert_eq!(net.resolving(), 1, "the name's goes on");
        name.end();
        assert_eq!(net.resolving(), 0, "the resolve was cancelled");
    }

    /// The name's resolve a race goes on beside, dropped by whatever drops
    /// it, leaves nothing in the resolver; the race dropped leaves it.
    #[test]
    fn a_name_dropped_leaves_nothing_in_the_resolver() {
        let (m, name, net, _dns, _clock) = racing_while_a_is_awaited();
        drop(m);
        assert_eq!(net.resolving(), 1, "the race holds none of it");
        drop(name);
        assert_eq!(net.resolving(), 0, "the resolve went with the name");
    }

    /// The attempt that connects wins, and the others are closed.
    #[test]
    fn the_winner_closes_the_other_attempts() {
        let clock = ManualClock::new().unwrap();
        let (silent, up) = ("[::1]:5".parse().unwrap(), "127.0.0.1:5".parse().unwrap());
        let mut net = FakeNet::new(clock.clone())
            .with_peer(silent, FakePeer::Silent)
            .with_peer(up, FakePeer::AcceptsAfter(Duration::from_millis(10)));
        let scheme = Scheme::HTTP;
        let peer = Peer::new(scheme, b"localhost".to_vec(), 5, None);
        let route = NetRoute {
            origin: TryArc::try_new(peer).unwrap(),
            via: None,
            proxy: None,
            tls: None,
            cold: None,
        };
        let mut m = ConnectMachine::new(
            ConnNumber(0),
            route,
            crate::conn::Dial::Stream,
            clock.now(),
            Closer::System,
            ConnSettings::DEFAULT,
        );
        let he = Duration::from_millis(200);
        let mut dns = DnsCache::default();
        let conn = loop {
            let setup = DriveOptions {
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
            match m.drive(&mut cx, setup, &mut Late::default()).unwrap() {
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
        let Transport::Stream(stream) = conn.transport else {
            panic!("over the network");
        };
        net.close(stream.into_socket());
    }

    /// unit2600's cases, read from its source: how many attempts of each
    /// family start, how many run at once, that the setup fails no sooner
    /// than C expects, and where both families start, that the preferred
    /// one starts at once and the other no sooner than the delay. Each
    /// address refuses after the case's delay, the same for each family.
    #[test]
    fn unit2600_attempts_race() {
        let rows = crate::c_source::table("tests/unit/unit2600.c", "TEST_CASES[] =", |c| match c {
            "defined(USE_IPV6)" => true,
            other => panic!("{other}"),
        });
        assert_eq!(rows.len(), 10);
        let ms = |v: &crate::c_source::Value| u64::try_from(v.int()).unwrap();
        let count = |v: &crate::c_source::Value| usize::try_from(v.int()).unwrap();
        for row in &rows {
            let r = row.group();
            let id = r[0].int();
            let resolve = std::str::from_utf8(r[2].str()).unwrap();
            let addrs: Vec<&str> = resolve
                .strip_prefix("abc.test:123:")
                .unwrap()
                .split(',')
                .collect();
            let ip = match r[3].word() {
                "CURL_IPRESOLVE_WHATEVER" => IpVersion::Any,
                "CURL_IPRESOLVE_V4" => IpVersion::V4,
                "CURL_IPRESOLVE_V6" => IpVersion::V6,
                other => panic!("{other}"),
            };
            let (he, fail4, fail6) = (ms(&r[5]), ms(&r[6]), ms(&r[7]));
            assert_eq!(fail4, fail6, "case {id}: one delay for both families");
            let got = race(&addrs, ip, he, fail4);
            assert_eq!(got.v4_starts.len(), count(&r[8]), "case {id}: {got:?}");
            assert_eq!(got.v6_starts.len(), count(&r[9]), "case {id}: {got:?}");
            assert!(got.failed_at >= ms(&r[10]), "case {id}: {got:?}");
            assert_eq!(r[12].word(), "R_FAIL");
            assert_eq!(got.most_running, count(&r[14]), "case {id}: {got:?}");
            let starts = (got.v4_starts.first(), got.v6_starts.first());
            if let ((Some(&v4), Some(&v6)), Some(pref)) = (starts, r[13].bytes()) {
                let (first, other) = match pref {
                    b"v6" => (v6, v4),
                    b"v4" => (v4, v6),
                    other => panic!("{other:?}"),
                };
                assert!(first <= 100, "case {id}: {got:?}");
                assert!(other >= he, "case {id}: {got:?}");
            }
        }
    }

    /// unit2600's cases as the rewrite times them: when each attempt of
    /// each family starts, and when the setup fails. The next attempt
    /// starts once the delay has passed since the last one started, or
    /// once none runs; six run at most, the oldest making room.
    #[test]
    fn attempts_start_on_the_delay() {
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
        let answer = shortcut(b"localhost").unwrap().unwrap();
        let loopback = [
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ];
        assert_eq!((answer.addrs(), answer.resolved()), (&loopback[..], true));
        let answer = shortcut(b"::1").unwrap().unwrap();
        assert_eq!((answer.addrs(), answer.resolved()), (&loopback[..1], false));
        assert_eq!(answer.name(), b"::1");
        assert!(shortcut(b"example.com").unwrap().is_none());
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
        let now = crate::time::ManualClock::new().unwrap().now();
        let of = Asking {
            name: b"a.test",
            port: 80,
        };
        let mut cx = crate::conn::layer::Silent(now);
        let order = |mut e: Eyeballs| {
            let mut cx = crate::conn::layer::Silent(now);
            std::iter::from_fn(move || e.next(&mut cx, of))
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
        e.next(&mut cx, of);
        e.next(&mut cx, of);
        assert!(!e.more());
    }

    /// An address named bare, as FTP's `PORT` names its own, is its own
    /// answer, the resolver never asked (`hostip_resolv_start`'s
    /// `Curl_is_ipaddr`): this network's resolver knows no name.
    #[test]
    fn a_bare_address_is_not_resolved() {
        let clock = ManualClock::new().unwrap();
        let mut net = FakeNet::new(clock.clone());
        let setup = DriveOptions {
            wildcard: false,
            max_age: Some(Duration::from_secs(60)),
            delay: Duration::from_millis(200),
            scope: None,
            socket: SocketSetup::PLAIN,
            haproxy: false,
            layer: None,
            linger: None,
        };
        for (host, ip) in [("::1", "::1"), ("127.0.0.1", "127.0.0.1")] {
            let mut cx = Plain {
                net: &mut net,
                dns: &mut DnsCache::default(),
                now: clock.now(),
            };
            let answer = resolve_blocking(&mut cx, host.as_bytes(), 0, Family::Any, setup).unwrap();
            let answer = answer.unwrap_or_else(|| panic!("{host} resolved"));
            assert_eq!(answer.addrs(), [ip.parse::<IpAddr>().unwrap()]);
            answer.let_go(&mut cx);
        }
        let mut cx = Plain {
            net: &mut net,
            dns: &mut DnsCache::default(),
            now: clock.now(),
        };
        let named = resolve_blocking(&mut cx, b"example.com", 0, Family::Any, setup).unwrap();
        assert!(named.is_none(), "a name is the resolver's");
    }

    #[test]
    fn literals_are_addresses() {
        assert_eq!(literal(b"127.0.0.1"), Some(IpAddr::from([127, 0, 0, 1])));
        assert_eq!(literal(b"::1"), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        let mapped = "::ffff:1.2.3.4".parse().unwrap();
        assert_eq!(literal(b"::ffff:1.2.3.4"), Some(IpAddr::V6(mapped)));
        assert_eq!(literal(b"[::1]"), None, "a name has no brackets");
        assert_eq!(literal(b"fe80::1%eth0"), None, "a zone is resolved");
        assert_eq!(literal(b"[127.0.0.1]"), None);
        assert_eq!(literal(b"example.com"), None);
        assert_eq!(literal(b"localhost"), None);
    }
}
