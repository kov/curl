//! Connections: what a transfer talks over, owned by the pool and leased to
//! transfers.
//!
//! A networkless connection is what `file:` leases, as C attaches a
//! connection to every transfer. A TCP one is set up by a
//! `ConnectMachine`, in the slot it keeps once established. `io` is the
//! engine's way to the network.

mod buf;
pub(crate) mod chain;
mod connect;
mod connect_to;
mod dns;
pub mod io;
pub(crate) mod layer;
pub(crate) mod pool;
pub(crate) mod proxy;
pub(crate) mod shutdown;
pub(crate) mod socks;
mod stream;

pub(crate) use connect::{
    Asked, ConnCx, ConnectError, Found, MAX_ATTEMPTS, Made, Opened, Progress, Setup, SocketSetup,
    Unresolved, queries,
};
pub(crate) use connect_to::{BadVia, via};
pub(crate) use dns::{Answer, BadEntry, DnsCache, ListEntry, Names, parse_entry};
pub(crate) use pool::{
    Acquired, AddLimits, ConnLease, Connected, Finish, Full, Home, Limit, Pool, PoolNote, Released,
    ReuseRules, WaitReason,
};

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};

use crate::options::{IpVersion, ProxyType};
use crate::report::ResponseVersion;

pub(crate) use self::buf::RecvBuf;
/// How the tests' layer shuts down, for `Multi::linger_connections`.
#[cfg(any(test, feature = "test-util"))]
pub use self::layer::Linger;
pub use self::socks::ProxyError;
pub(crate) use self::stream::Stream;

/// What transfers keep for those after them: the connections and the
/// names resolved. A multi holds its own; a share will hold them in its
/// place.
pub(crate) struct Caches {
    pub(crate) pool: Pool,
    pub(crate) dns: DnsCache,
}

impl Caches {
    pub(crate) fn new() -> Result<Caches, curl_alloc::OutOfMemory> {
        Ok(Caches {
            pool: Pool::new()?,
            dns: DnsCache::default(),
        })
    }
}
use self::connect::ConnectMachine;
use self::io::{Recv, Sent};
use self::layer::LayerCx;
use crate::id::Key;
use crate::time::Instant;

/// A connection's number in its pool, counting from 0 in the order the
/// pool made them: the `#N` of "Connection #N" (C's `connection_id`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnNumber(u64);

impl ConnNumber {
    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConnNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// A connection's place in the pool; stale once the connection is gone.
pub(crate) type ConnId = Key<ConnSlot>;

/// A connection in the pool.
#[derive(Debug)]
pub(crate) enum ConnSlot {
    /// Being set up.
    Connecting(ConnectMachine),
    Open(Conn),
    /// Its setup failed; it holds nothing open, and goes when its lease
    /// is given back.
    Failed(ConnNumber),
}

impl ConnSlot {
    /// The peer the connection goes to, if over a network.
    fn destination(&self) -> Option<&Peer> {
        let route = match self {
            ConnSlot::Connecting(m) => m.route(),
            ConnSlot::Open(Conn {
                route: Route::Tcp(tcp),
                ..
            }) => tcp,
            ConnSlot::Open(_) | ConnSlot::Failed(_) => return None,
        };
        Some(route.destination())
    }
}

/// What a transfer needs of a connection, decided once per leg. A
/// connection serves another transfer only if its route serves the
/// transfer's.
#[derive(Clone, Debug)]
pub(crate) enum Route {
    /// No network: the protocol does its own I/O (C's
    /// `PROTOPT_NONETWORK`).
    Local,
    Tcp(Tcp),
}

impl Route {
    /// Whether a connection set up for this route may serve a transfer
    /// that needs `wanted` (`url_match_conn`, `url_match_destination`):
    /// the same origin through the same peer, and the same addresses
    /// unless the transfer takes any.
    pub(crate) fn serves(&self, wanted: &Route) -> bool {
        match (self, wanted) {
            (Route::Tcp(have), Route::Tcp(want)) => {
                // Every field by name, so that one added does not compile
                // until it is compared here or said why not.
                let Tcp {
                    origin,
                    via,
                    ip,
                    proxy,
                } = have;
                let Tcp {
                    origin: want_origin,
                    via: want_via,
                    ip: want_ip,
                    proxy: want_proxy,
                } = want;
                **origin == **want_origin
                    // C compares the detours without their schemes
                    // (`Curl_peer_same_destination`); each has its
                    // origin's.
                    && via.as_deref() == want_via.as_deref()
                    // A transfer that takes any family takes either.
                    && (*want_ip == IpVersion::Any || want_ip == ip)
                    && proxy.as_ref().map(ProxyRoute::key)
                        == want_proxy.as_ref().map(ProxyRoute::key)
            }
            (Route::Local | Route::Tcp(..), Route::Local | Route::Tcp(..)) => false,
        }
    }
}

/// A route over TCP to `origin`, the peer shared by the transfer and the
/// connection; through `via` when a connect-to entry names another peer
/// for it (C's `via_peer`); over the addresses of `ip`; through `proxy`
/// if there is one, which is the origin itself for a proxy the requests
/// go to whole.
#[derive(Clone, Debug)]
pub(crate) struct Tcp {
    pub(crate) origin: TryArc<Peer>,
    pub(crate) via: Option<TryArc<Peer>>,
    pub(crate) ip: IpVersion,
    pub(crate) proxy: Option<ProxyRoute>,
}

impl Tcp {
    /// The peer connected to (`Curl_conn_get_first_peer`): the first
    /// proxy, if the route has one.
    pub(crate) fn destination(&self) -> &Peer {
        match &self.proxy {
            Some(proxy) => proxy.first_peer(),
            None => self.target(),
        }
    }

    /// The SOCKS proxy on the way, and where it is asked to connect.
    pub(crate) fn socks(&self) -> Option<SocksLeg<'_>> {
        self.proxy.as_ref()?.socks(self.target())
    }

    /// The peer the requests reach, through a proxy's tunnel or not.
    pub(crate) fn target(&self) -> &Peer {
        self.via.as_deref().unwrap_or(&self.origin)
    }

    /// The route goes through a proxy by a handshake the setup makes
    /// over the connection to it: SOCKS's, or an HTTP proxy's tunnel.
    pub(crate) fn handshakes(&self) -> bool {
        self.proxy
            .as_ref()
            .is_some_and(|p| p.tunnels() || p.socks(self.target()).is_some())
    }
}

/// A SOCKS proxy on a route, and the peer it is asked to connect to: the
/// HTTP proxy it is in front of, or the request's.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SocksLeg<'a> {
    pub(crate) version: socks::Version,
    pub(crate) creds: Option<&'a ProxyCreds>,
    pub(crate) to: &'a Peer,
}

/// A SOCKS proxy an HTTP proxy is reached through (`CURLOPT_PRE_PROXY`;
/// C's `socks_proxy` beside its `http_proxy`).
#[derive(Clone, Debug)]
pub(crate) struct PreProxy {
    pub(crate) kind: ProxyType,
    pub(crate) peer: TryArc<Peer>,
    pub(crate) creds: Option<TryArc<ProxyCreds>>,
}

/// The proxy a route goes through (C's `conn->http_proxy`).
#[derive(Clone, Debug)]
pub(crate) struct ProxyRoute {
    pub(crate) kind: ProxyType,
    pub(crate) peer: TryArc<Peer>,
    /// The user and password the proxy is given, if any.
    pub(crate) creds: Option<TryArc<ProxyCreds>>,
    /// The requests go to the proxy, which sends them on, rather than
    /// through a tunnel it opens.
    pub(crate) forward: bool,
    /// A SOCKS5 proxy must have authenticated the user (`CURLAUTH_ONLY`
    /// in `CURLOPT_SOCKS5_AUTH`): what the transfer asks of a connection,
    /// not what the connection shares with it.
    pub(crate) auth_only: bool,
    /// The SOCKS proxy in front of it, which only an HTTP proxy has.
    pre: Option<PreProxy>,
}

/// The user and password a proxy is given, each empty for none.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProxyCreds {
    pub(crate) user: Vec<u8>,
    pub(crate) password: Vec<u8>,
}

/// What of a route's proxy a connection must share to serve another
/// transfer (`proxy_info_matches`, `origin_is_proxy`).
#[derive(PartialEq)]
struct ProxyKey<'a> {
    kind: ProxyType,
    peer: Destination<'a>,
    creds: Option<&'a ProxyCreds>,
    forward: bool,
    pre: Option<(ProxyType, Destination<'a>, Option<&'a ProxyCreds>)>,
}

impl ProxyRoute {
    pub(crate) fn new(
        kind: ProxyType,
        peer: TryArc<Peer>,
        creds: Option<TryArc<ProxyCreds>>,
        forward: bool,
        auth_only: bool,
    ) -> ProxyRoute {
        ProxyRoute {
            kind,
            peer,
            creds,
            forward,
            auth_only,
            pre: None,
        }
    }

    /// The same HTTP proxy, reached through the SOCKS proxy `pre`.
    pub(crate) fn behind(self, pre: PreProxy) -> ProxyRoute {
        assert!(self.http(), "only an HTTP proxy has a SOCKS proxy in front");
        assert!(
            socks::Version::of(pre.kind).is_some(),
            "a pre-proxy is SOCKS"
        );
        ProxyRoute {
            pre: Some(pre),
            ..self
        }
    }

    /// The peer connected to first.
    pub(crate) fn first_peer(&self) -> &Peer {
        self.pre.as_ref().map_or(&self.peer, |pre| &pre.peer)
    }

    /// The SOCKS proxy on the way to `target`: the one in front, asked
    /// for this proxy, else this one if it is SOCKS.
    pub(crate) fn socks<'a>(&'a self, target: &'a Peer) -> Option<SocksLeg<'a>> {
        match &self.pre {
            Some(pre) => Some(SocksLeg {
                version: socks::Version::of(pre.kind).expect("a pre-proxy is SOCKS"),
                creds: pre.creds.as_deref(),
                to: &self.peer,
            }),
            None => socks::Version::of(self.kind).map(|version| SocksLeg {
                version,
                creds: self.creds.as_deref(),
                to: target,
            }),
        }
    }

    /// It is an HTTP proxy the setup opens a tunnel through.
    pub(crate) fn tunnels(&self) -> bool {
        self.http() && !self.forward
    }

    /// Whether it is an HTTP proxy, not a SOCKS one.
    pub(crate) fn http(&self) -> bool {
        !matches!(
            self.kind,
            ProxyType::Socks4 | ProxyType::Socks4a | ProxyType::Socks5 | ProxyType::Socks5Hostname
        )
    }

    fn key(&self) -> ProxyKey<'_> {
        // Every field by name, as in `Route::serves`.
        let ProxyRoute {
            kind,
            peer,
            creds,
            forward,
            // What the transfer asks of a connection, which
            // `Conn::serves` checks against what the connection did; not
            // something the two routes share.
            auth_only: _,
            pre,
        } = self;
        ProxyKey {
            kind: *kind,
            peer: Destination(peer),
            creds: creds.as_deref(),
            forward: *forward,
            pre: pre.as_ref().map(|pre| {
                let PreProxy { kind, peer, creds } = pre;
                (*kind, Destination(peer), creds.as_deref())
            }),
        }
    }
}

/// A peer compared without its scheme (`Curl_peer_same_destination`).
struct Destination<'a>(&'a Peer);

impl PartialEq for Destination<'_> {
    fn eq(&self, other: &Self) -> bool {
        let (a, b) = (self.0, other.0);
        // Every field by name, as in `Peer`'s `eq`.
        let Peer {
            // The difference from `Peer`'s `eq`.
            scheme: _,
            // Compared as its name, below.
            host: _,
            port,
            zone,
            scope,
        } = a;
        *port == b.port
            && a.ipv6() == b.ipv6()
            && a.name().eq_ignore_ascii_case(b.name())
            && *scope == b.scope
            && (*scope != 0 || *zone == b.zone)
    }
}

/// The protocol a connection speaks, as reuse sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scheme {
    /// Its name, as "Reusing existing tcp: connection" names it.
    pub(crate) name: &'static str,
    /// Whether a connection is kept for another transfer once done
    /// (`PROTOPT_CONN_REUSE`).
    pub(crate) reuse: bool,
}

/// Who a connection talks to (C's `struct Curl_peer`): the scheme, the
/// host as the URL names it, the port and the IPv6 zone. The transfer
/// and its connection share one.
#[derive(Debug)]
pub(crate) struct Peer {
    scheme: Scheme,
    /// An IPv6 address in brackets (`user_hostname`).
    host: Vec<u8>,
    port: u16,
    zone: Option<Vec<u8>>,
    /// The IPv6 scope: the zone as a number, or the index of the
    /// interface it names; 0 if neither (`scopeid`).
    scope: u32,
}

impl Peer {
    pub(crate) fn new(scheme: Scheme, host: Vec<u8>, port: u16, zone: Option<Vec<u8>>) -> Peer {
        // A zone that is a plain number is the scope, and a name is its
        // interface's index; one naming no interface leaves none, without
        // an error (`peer_create`).
        let scope = zone
            .as_deref()
            .filter(|z| !z.is_empty())
            .and_then(|z| {
                let number = z
                    .iter()
                    .all(u8::is_ascii_digit)
                    .then(|| std::str::from_utf8(z).ok()?.parse().ok())
                    .flatten();
                number.or_else(|| curl_os::net::interface_index(z).map(NonZeroU32::get))
            })
            .unwrap_or(0);
        Peer {
            scheme,
            host,
            port,
            zone,
            scope,
        }
    }

    /// A peer in the IPv6 scope `scope`, which takes the place of any
    /// zone the URL names (`CURLOPT_ADDRESS_SCOPE`, `Curl_peer_from_url`).
    pub(crate) fn scoped(scheme: Scheme, host: Vec<u8>, port: u16, scope: NonZeroU32) -> Peer {
        Peer {
            scheme,
            host,
            port,
            zone: None,
            scope: scope.get(),
        }
    }

    /// The IPv6 scope a connection to the peer is made in, if it has one.
    pub(crate) fn scope(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.scope)
    }

    pub(crate) fn try_clone(&self) -> Result<Peer, OutOfMemory> {
        let copy = |bytes: &[u8]| {
            let mut v = Vec::new();
            v.try_extend_from_slice(bytes).map(|()| v)
        };
        Ok(Peer {
            scheme: self.scheme,
            host: copy(&self.host)?,
            port: self.port,
            zone: self.zone.as_deref().map(copy).transpose()?,
            scope: self.scope,
        })
    }

    /// The same peer at port `port`: a connect-to entry that names only
    /// a port keeps the origin's zone and scope (`Curl_peer_from_connect_to`).
    pub(crate) fn at_port(&self, port: u16) -> Result<Peer, OutOfMemory> {
        let mut peer = self.try_clone()?;
        peer.port = port;
        Ok(peer)
    }

    pub(crate) fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host as the URL names it, an IPv6 address in brackets.
    pub(crate) fn shown(&self) -> &[u8] {
        &self.host
    }

    /// The host without an IPv6 address's brackets (`hostname`).
    pub(crate) fn name(&self) -> &[u8] {
        self.host
            .strip_prefix(b"[")
            .and_then(|h| h.strip_suffix(b"]"))
            .unwrap_or(&self.host)
    }

    /// Whether the host is an IPv6 address.
    pub(crate) fn ipv6(&self) -> bool {
        self.host.first() == Some(&b'[')
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// The IPv6 zone, as given.
    #[cfg(test)]
    pub(crate) fn zone(&self) -> Option<&[u8]> {
        self.zone.as_deref()
    }
}

/// The same peer (`Curl_peer_equal`): the same scheme, port and IPv6
/// zone, and the same host in any case.
impl PartialEq for Peer {
    fn eq(&self, other: &Peer) -> bool {
        // Every field by name, so that one added does not compile until it
        // is compared here or said why not.
        let Peer {
            scheme,
            // Compared as its name, below.
            host: _,
            port,
            zone,
            scope,
        } = self;
        *scheme == other.scheme
            && *port == other.port
            && self.ipv6() == other.ipv6()
            && self.name().eq_ignore_ascii_case(other.name())
            && *scope == other.scope
            && (*scope != 0 || *zone == other.zone)
    }
}

impl Eq for Peer {}

impl Peer {
    /// Whether connections to the two count toward one per-host limit:
    /// C's `destination`, `host:port` in lowercase, an IPv6 address in
    /// brackets with its scope; the scheme and a zone's name aside.
    pub(crate) fn same_bundle(&self, other: &Peer) -> bool {
        self.port == other.port
            && self.ipv6() == other.ipv6()
            && self.name().eq_ignore_ascii_case(other.name())
            && self.scope == other.scope
    }
}

/// What a connection's bytes travel over.
#[derive(Debug)]
pub(crate) enum Transport {
    Local,
    Tcp(Stream),
}

/// An established connection.
#[derive(Debug)]
pub(crate) struct Conn {
    number: ConnNumber,
    route: Route,
    transport: Transport,
    /// The address connected to; none without a network. Its end here
    /// is its socket's to say (`local`).
    remote: Option<SocketAddr>,
    /// When its setup started (C's `conn->created`), and when it was
    /// found connected (TIMER_CONNECT's `connected_at`).
    created: Instant,
    connected_at: Instant,
    use_: Use,
    /// It carried a request before the one leasing it (C's
    /// `bits.reuse`).
    served: bool,
    /// Its SOCKS5 proxy authenticated the user
    /// (`bits.socks5_authenticated`).
    socks5_authenticated: bool,
    /// The version its last HTTP response said (`httpversion_seen`).
    seen_version: Option<ResponseVersion>,
    /// It is not to be kept for another request (C's `connclose`), or
    /// its peer closed it, which no request can use again.
    close: bool,
    /// What it keeps of its creating transfer's settings.
    settings: shutdown::ConnSettings,
}

impl Conn {
    fn stream(&mut self) -> &mut Stream {
        match &mut self.transport {
            Transport::Tcp(stream) => stream,
            Transport::Local => unreachable!("a local connection moves no bytes"),
        }
    }

    /// The proxy requests go to whole over it, if they do
    /// (`origin_is_proxy`).
    pub(crate) fn forwarding(&self) -> Option<&ProxyRoute> {
        match &self.route {
            Route::Tcp(Tcp { proxy: Some(p), .. }) if p.forward => Some(p),
            _ => None,
        }
    }

    /// Whether it goes through an HTTP proxy (`http_proxy.peer`).
    pub(crate) fn http_proxy(&self) -> bool {
        matches!(&self.route, Route::Tcp(Tcp { proxy: Some(p), .. }) if p.http())
    }

    /// Whether it may serve a transfer whose route is `wanted`: a route
    /// that serves it, and the user authenticated by a SOCKS5 proxy if
    /// the transfer insists (`url_match_proxy_use`).
    pub(crate) fn serves(&self, wanted: &Route) -> bool {
        let insists = match wanted {
            Route::Tcp(tcp @ Tcp { proxy: Some(p), .. }) => {
                p.auth_only
                    && tcp.socks().is_some_and(|s| {
                        matches!(s.version, socks::Version::V5 | socks::Version::V5Hostname)
                    })
            }
            Route::Tcp(_) | Route::Local => false,
        };
        self.route.serves(wanted) && (!insists || self.socks5_authenticated)
    }

    /// Whether it carried a request before this one.
    pub(crate) fn reused(&self) -> bool {
        self.served
    }

    /// The version its last HTTP response said.
    pub(crate) fn seen_version(&self) -> Option<ResponseVersion> {
        self.seen_version
    }

    pub(crate) fn saw_version(&mut self, version: ResponseVersion) {
        self.seen_version = Some(version);
    }

    /// The connection's end here, as its socket says; none without a
    /// network, or if the system does not say.
    pub(crate) fn local(&self) -> Option<SocketAddr> {
        match &self.transport {
            Transport::Tcp(stream) => stream.local_addr(),
            Transport::Local => None,
        }
    }

    /// Keep it for no other request: it closes when its lease goes back.
    pub(crate) fn mark_close(&mut self) {
        self.close = true;
    }

    /// Received bytes no request has used yet.
    pub(crate) fn rx_mut(&mut self) -> &mut RecvBuf {
        self.stream().rx_mut()
    }

    /// Read once from the network, up to `max` bytes. Bytes received and
    /// not used, which only a handshake's read past its answer leaves,
    /// are given first, the socket not asked, as a layer gives what it
    /// holds: they came first.
    pub(crate) fn recv(&mut self, cx: &mut dyn LayerCx, max: usize) -> Result<Recv, RecvFailed> {
        let stream = self.stream();
        if let Some(n) = std::num::NonZeroUsize::new(stream.received().len()) {
            return Ok(Recv::Data(n));
        }
        let got = stream.recv(cx, max);
        if let Ok(Recv::Eof) = got {
            // Shut down by the server, not reused (`multi_done`).
            self.close = true;
        }
        got
    }

    /// Send from `bytes`, which is not empty, what the network takes now.
    pub(crate) fn send(&mut self, cx: &mut dyn LayerCx, bytes: &[u8]) -> std::io::Result<Sent> {
        self.stream().send(cx, bytes)
    }

    /// Whether bytes wait where a poll of its socket cannot see them, so
    /// a read that would block is to be tried again at once.
    pub(crate) fn data_pending(&mut self) -> bool {
        match &mut self.transport {
            Transport::Tcp(stream) => stream.data_pending(),
            Transport::Local => false,
        }
    }
}

/// Why reading from a connection failed.
#[derive(Debug)]
pub(crate) enum RecvFailed {
    /// No room could be made for what is read.
    OutOfMemory,
    /// The socket failed.
    Os(std::io::Error),
}

/// Whether a connection is leased.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Use {
    /// Leased this many times; once, as no connection is shared yet.
    Leased(NonZeroU32),
    /// Leased by no one since this time (C's `lastused`).
    Idle { since: Instant },
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTTP: Scheme = Scheme {
        name: "http",
        reuse: true,
    };

    fn peer(host: &[u8], port: u16, zone: Option<&[u8]>) -> Peer {
        Peer::new(HTTP, host.to_vec(), port, zone.map(<[u8]>::to_vec))
    }

    /// Peers are the same as `Curl_peer_equal` finds them: the host in
    /// any case, the port, the scheme, and the zone by its scope, a
    /// number or an interface's index, or else by name.
    #[test]
    fn peers_compare_as_c_compares_them() {
        assert_eq!(
            peer(b"Example.COM", 80, None),
            peer(b"example.com", 80, None)
        );
        assert_ne!(
            peer(b"example.com", 80, None),
            peer(b"example.com", 81, None)
        );
        assert_ne!(
            peer(b"example.com", 80, None),
            peer(b"example.org", 80, None)
        );
        let other = Scheme {
            name: "tcp",
            reuse: true,
        };
        let tcp = Peer::new(other, b"example.com".to_vec(), 80, None);
        assert_ne!(tcp, peer(b"example.com", 80, None));
        let v6 = |zone| peer(b"[fe80::1]", 80, zone);
        assert_eq!(v6(Some(b"2")), v6(Some(b"02")), "one scope by number");
        assert_ne!(v6(Some(b"2")), v6(Some(b"3")));
        assert_eq!(v6(Some(b"nosuch0")), v6(Some(b"nosuch0")));
        assert_ne!(
            v6(Some(b"nosuch0")),
            v6(Some(b"nosuch1")),
            "no index: by name"
        );
        assert_ne!(v6(Some(b"nosuch0")), v6(None));
        // A name is its interface's index, the same scope as the number.
        let lo = curl_os::net::interface_index(b"lo").expect("Linux has a loopback");
        let index = lo.to_string();
        assert_eq!(v6(Some(b"lo")), v6(Some(index.as_bytes())));
        assert_eq!(v6(Some(b"lo")).scope(), Some(lo));
        assert_eq!(v6(Some(b"nosuch0")).scope(), None);
        // The application's scope, in place of a zone, is a number's.
        let scoped = Peer::scoped(HTTP, b"[fe80::1]".to_vec(), 80, lo);
        assert_eq!(scoped, v6(Some(b"lo")));
        assert_eq!(v6(None).name(), b"fe80::1");
        assert_eq!(v6(None).shown(), b"[fe80::1]");
        assert!(v6(None).ipv6() && !peer(b"fe80", 80, None).ipv6());
    }

    /// A proxy is the same destination as another by its name in any
    /// case, its port, and its zone by number however spelt, or by name
    /// when it has none (`Curl_peer_same_destination`).
    #[test]
    fn proxies_compare_as_destinations() {
        let same = |a: &Peer, b: &Peer| Destination(a) == Destination(b);
        let v6 = |zone| peer(b"[fe80::1]", 80, zone);
        assert!(same(&v6(Some(b"2")), &v6(Some(b"02"))));
        assert!(!same(&v6(Some(b"2")), &v6(Some(b"3"))));
        assert!(same(&v6(Some(b"nosuch0")), &v6(Some(b"nosuch0"))));
        assert!(!same(&v6(Some(b"nosuch0")), &v6(Some(b"nosuch1"))));
        let lo = curl_os::net::interface_index(b"lo").expect("Linux has a loopback");
        assert!(same(&v6(Some(b"lo")), &v6(Some(lo.to_string().as_bytes()))));
        assert!(same(
            &peer(b"P.example", 80, None),
            &peer(b"p.example", 80, None)
        ));
        assert!(!same(
            &peer(b"p.example", 80, None),
            &peer(b"p.example", 81, None)
        ));
    }

    /// A connection serves only a transfer whose route agrees on each
    /// field: the origin, the connect-to peer, the family unless the
    /// transfer takes any, and the proxy.
    #[test]
    fn routes_compare_every_field() {
        let arc = |host: &[u8]| TryArc::try_new(peer(host, 80, None)).unwrap();
        let tcp = |origin: &[u8], via: Option<&[u8]>, ip, proxy: Option<&[u8]>| {
            Route::Tcp(Tcp {
                origin: arc(origin),
                via: via.map(arc),
                ip,
                proxy: proxy
                    .map(|host| ProxyRoute::new(ProxyType::Socks5, arc(host), None, false, false)),
            })
        };
        let have = tcp(
            b"o.example",
            Some(b"v.example"),
            IpVersion::V4,
            Some(b"p.example"),
        );
        let same = tcp(
            b"o.example",
            Some(b"v.example"),
            IpVersion::V4,
            Some(b"p.example"),
        );
        assert!(have.serves(&same));
        let any = tcp(
            b"o.example",
            Some(b"v.example"),
            IpVersion::Any,
            Some(b"p.example"),
        );
        assert!(have.serves(&any), "a transfer taking any family");
        for (field, other) in [
            (
                "origin",
                tcp(
                    b"x.example",
                    Some(b"v.example"),
                    IpVersion::V4,
                    Some(b"p.example"),
                ),
            ),
            (
                "via",
                tcp(
                    b"o.example",
                    Some(b"x.example"),
                    IpVersion::V4,
                    Some(b"p.example"),
                ),
            ),
            (
                "no via",
                tcp(b"o.example", None, IpVersion::V4, Some(b"p.example")),
            ),
            (
                "ip",
                tcp(
                    b"o.example",
                    Some(b"v.example"),
                    IpVersion::V6,
                    Some(b"p.example"),
                ),
            ),
            (
                "proxy",
                tcp(
                    b"o.example",
                    Some(b"v.example"),
                    IpVersion::V4,
                    Some(b"x.example"),
                ),
            ),
            (
                "no proxy",
                tcp(b"o.example", Some(b"v.example"), IpVersion::V4, None),
            ),
        ] {
            assert!(!have.serves(&other), "{field}");
        }
    }

    fn via_proxy(host: &[u8], user: Option<&[u8]>, forward: bool) -> Route {
        let proxy = TryArc::try_new(peer(host, 3128, None)).unwrap();
        let creds = user.map(|u| {
            TryArc::try_new(ProxyCreds {
                user: u.to_vec(),
                password: Vec::new(),
            })
            .unwrap()
        });
        let origin = if forward {
            proxy.clone()
        } else {
            TryArc::try_new(peer(b"origin.example", 80, None)).unwrap()
        };
        Route::Tcp(Tcp {
            origin,
            via: None,
            ip: IpVersion::Any,
            proxy: Some(ProxyRoute::new(
                ProxyType::Http,
                proxy,
                creds,
                forward,
                false,
            )),
        })
    }

    /// A connection through a proxy serves a transfer through the same
    /// proxy, the same way, as the same user (`url_match_proxy_use`); a
    /// forwarding one serves any origin, being the proxy's.
    #[test]
    fn proxied_routes_match_as_c() {
        let direct = Route::Tcp(Tcp {
            origin: TryArc::try_new(peer(b"proxy.example", 3128, None)).unwrap(),
            via: None,
            ip: IpVersion::Any,
            proxy: None,
        });
        let route = via_proxy(b"proxy.example", None, true);
        assert!(route.serves(&via_proxy(b"PROXY.example", None, true)));
        assert!(!route.serves(&via_proxy(b"other.example", None, true)));
        assert!(!route.serves(&via_proxy(b"proxy.example", Some(b"u"), true)));
        assert!(!route.serves(&via_proxy(b"proxy.example", None, false)));
        assert!(!route.serves(&direct) && !direct.serves(&route));
        let user = via_proxy(b"proxy.example", Some(b"u"), true);
        assert!(user.serves(&via_proxy(b"proxy.example", Some(b"u"), true)));
        assert!(!user.serves(&via_proxy(b"proxy.example", Some(b"v"), true)));
        // Behind the same SOCKS proxy, or none, as C compares
        // `socks_proxy` beside `http_proxy`.
        let behind = |kind, host: &[u8]| match via_proxy(b"proxy.example", None, true) {
            Route::Tcp(mut tcp) => {
                let pre = PreProxy {
                    kind,
                    peer: TryArc::try_new(peer(host, 1080, None)).unwrap(),
                    creds: None,
                };
                tcp.proxy = tcp.proxy.map(|p| p.behind(pre));
                Route::Tcp(tcp)
            }
            Route::Local => unreachable!(),
        };
        let socks = behind(ProxyType::Socks5, b"socks.example");
        assert!(socks.serves(&behind(ProxyType::Socks5, b"socks.example")));
        assert!(!socks.serves(&behind(ProxyType::Socks5, b"other.example")));
        assert!(!socks.serves(&behind(ProxyType::Socks4, b"socks.example")));
        assert!(!socks.serves(&route) && !route.serves(&socks));
    }
}
