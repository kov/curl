//! Connections: what a transfer talks over, owned by the pool and leased to
//! transfers.
//!
//! A networkless connection is what `file:` leases, as C attaches a
//! connection to every transfer. A TCP one is set up by a
//! `ConnectMachine`, in the slot it keeps once established. `io` is the
//! engine's way to the network.

mod buf;
mod connect;
mod connect_to;
mod dns;
pub mod io;
mod pool;
pub(crate) mod proxy;
pub(crate) mod socks;

pub(crate) use connect::{ConnectError, Failure, Found, Progress, Setup, Unresolved};
pub(crate) use connect_to::{BadVia, via};
pub(crate) use dns::{Answer, BadEntry, DnsCache, ListEntry, parse_entry};
pub(crate) use pool::{
    Acquired, AddLimits, ConnLease, Connected, Finish, Full, Limit, Pool, PoolNote, Released,
    ReuseRules, WaitReason,
};

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;

use curl_alloc::{OutOfMemory, TryRc, TryVec as _};

use crate::options::{IpVersion, ProxyType};
use crate::report::ResponseVersion;

pub(crate) use self::buf::RecvBuf;
pub use self::socks::ProxyError;

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
use self::io::{Recv, Sent, Socket};
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
                // C compares the detours without their schemes
                // (`Curl_peer_same_destination`); each has its origin's.
                *have.origin == *want.origin
                    && have.via.as_deref() == want.via.as_deref()
                    && (want.ip == IpVersion::Any || want.ip == have.ip)
                    && have.proxy.as_ref().map(ProxyRoute::key)
                        == want.proxy.as_ref().map(ProxyRoute::key)
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
    pub(crate) origin: TryRc<Peer>,
    pub(crate) via: Option<TryRc<Peer>>,
    pub(crate) ip: IpVersion,
    pub(crate) proxy: Option<ProxyRoute>,
}

impl Tcp {
    /// The peer connected to (`Curl_conn_get_destination`): the proxy,
    /// if the route has one.
    pub(crate) fn destination(&self) -> &Peer {
        match &self.proxy {
            Some(proxy) => &proxy.peer,
            None => self.target(),
        }
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
            .is_some_and(|p| (p.http() && !p.forward) || socks::Version::of(p.kind).is_some())
    }
}

/// The proxy a route goes through (C's `conn->http_proxy`).
#[derive(Clone, Debug)]
pub(crate) struct ProxyRoute {
    pub(crate) kind: ProxyType,
    pub(crate) peer: TryRc<Peer>,
    /// The user and password the proxy is given, if any.
    pub(crate) creds: Option<TryRc<ProxyCreds>>,
    /// The requests go to the proxy, which sends them on, rather than
    /// through a tunnel it opens.
    pub(crate) forward: bool,
    /// A SOCKS5 proxy must have authenticated the user (`CURLAUTH_ONLY`
    /// in `CURLOPT_SOCKS5_AUTH`): what the transfer asks of a connection,
    /// not what the connection shares with it.
    pub(crate) auth_only: bool,
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
}

impl ProxyRoute {
    /// Whether it is an HTTP proxy, not a SOCKS one.
    pub(crate) fn http(&self) -> bool {
        !matches!(
            self.kind,
            ProxyType::Socks4 | ProxyType::Socks4a | ProxyType::Socks5 | ProxyType::Socks5Hostname
        )
    }

    fn key(&self) -> ProxyKey<'_> {
        ProxyKey {
            kind: self.kind,
            peer: Destination(&self.peer),
            creds: self.creds.as_deref(),
            forward: self.forward,
        }
    }
}

/// A peer compared without its scheme (`Curl_peer_same_destination`).
struct Destination<'a>(&'a Peer);

impl PartialEq for Destination<'_> {
    fn eq(&self, other: &Self) -> bool {
        let (a, b) = (self.0, other.0);
        a.port == b.port
            && a.ipv6() == b.ipv6()
            && a.name().eq_ignore_ascii_case(b.name())
            && a.scope == b.scope
            && (a.scope != 0 || a.zone == b.zone)
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
    /// The zone as a number, if it is one; 0 if not (`scopeid`).
    scope: u32,
}

impl Peer {
    pub(crate) fn new(scheme: Scheme, host: Vec<u8>, port: u16, zone: Option<Vec<u8>>) -> Peer {
        // A zone that is a plain number is the scope; a name's would be
        // its interface's index, which is not looked up yet.
        let scope = zone
            .as_deref()
            .filter(|z| !z.is_empty() && z.iter().all(u8::is_ascii_digit))
            .and_then(|z| std::str::from_utf8(z).ok()?.parse().ok())
            .unwrap_or(0);
        Peer {
            scheme,
            host,
            port,
            zone,
            scope,
        }
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
    pub(crate) fn zone(&self) -> Option<&[u8]> {
        self.zone.as_deref()
    }
}

/// The same peer (`Curl_peer_equal`): the same scheme, port and IPv6
/// zone, and the same host in any case.
impl PartialEq for Peer {
    fn eq(&self, other: &Peer) -> bool {
        self.scheme == other.scheme
            && self.port == other.port
            && self.ipv6() == other.ipv6()
            && self.name().eq_ignore_ascii_case(other.name())
            && self.scope == other.scope
            && (self.scope != 0 || self.zone == other.zone)
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
    Tcp(Box<dyn Socket>),
}

/// An established connection.
#[derive(Debug)]
pub(crate) struct Conn {
    number: ConnNumber,
    route: Route,
    transport: Transport,
    /// The address connected to, and from; none without a network.
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
    /// When its setup started (C's `conn->created`), and when it was
    /// found connected (TIMER_CONNECT's `connected_at`).
    created: Instant,
    connected_at: Instant,
    use_: Use,
    rx: RecvBuf,
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
}

impl Conn {
    fn socket(&self) -> &dyn Socket {
        match &self.transport {
            Transport::Tcp(socket) => &**socket,
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

    /// Its SOCKS5 proxy authenticated the user.
    pub(crate) fn socks5_authenticated(&mut self) {
        self.socks5_authenticated = true;
    }

    /// Whether it may serve a transfer whose route is `wanted`: a route
    /// that serves it, and the user authenticated by a SOCKS5 proxy if
    /// the transfer insists (`url_match_proxy_use`).
    pub(crate) fn serves(&self, wanted: &Route) -> bool {
        let insists = match wanted {
            Route::Tcp(Tcp { proxy: Some(p), .. }) => {
                p.auth_only && matches!(p.kind, ProxyType::Socks5 | ProxyType::Socks5Hostname)
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

    /// Keep it for no other request: it closes when its lease goes back.
    pub(crate) fn mark_close(&mut self) {
        self.close = true;
    }

    /// Received bytes no request has used yet.
    pub(crate) fn rx_mut(&mut self) -> &mut RecvBuf {
        &mut self.rx
    }

    /// Read once from the network, up to `max` bytes, behind what `rx`
    /// holds.
    pub(crate) fn recv(&mut self, max: usize) -> Result<Recv, RecvFailed> {
        let socket = match &self.transport {
            Transport::Tcp(socket) => &**socket,
            Transport::Local => unreachable!("a local connection moves no bytes"),
        };
        // Borrowed apart from `rx`, which the read fills.
        let room = self.rx.room(max).map_err(|_| RecvFailed::OutOfMemory)?;
        let got = socket.recv(room).map_err(RecvFailed::Os);
        let n = match got {
            Ok(Recv::Data(n)) => n.get(),
            Ok(Recv::Eof) => {
                // Shut down by the server, not reused (`multi_done`).
                self.close = true;
                0
            }
            Ok(Recv::WouldBlock) | Err(_) => 0,
        };
        self.rx.commit(max, n);
        got
    }

    /// Send from `bytes`, which is not empty, what the network takes now.
    pub(crate) fn send(&mut self, bytes: &[u8]) -> std::io::Result<Sent> {
        self.socket().send(bytes)
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
    /// any case, the port, the scheme, and the zone by number or name.
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
        assert_eq!(v6(Some(b"eth0")), v6(Some(b"eth0")));
        assert_ne!(v6(Some(b"eth0")), v6(Some(b"eth1")), "unnumbered: by name");
        assert_ne!(v6(Some(b"eth0")), v6(None));
        assert_eq!(v6(None).name(), b"fe80::1");
        assert_eq!(v6(None).shown(), b"[fe80::1]");
        assert!(v6(None).ipv6() && !peer(b"fe80", 80, None).ipv6());
    }

    fn via_proxy(host: &[u8], user: Option<&[u8]>, forward: bool) -> Route {
        let proxy = TryRc::try_new(peer(host, 3128, None)).unwrap();
        let creds = user.map(|u| {
            TryRc::try_new(ProxyCreds {
                user: u.to_vec(),
                password: Vec::new(),
            })
            .unwrap()
        });
        let origin = if forward {
            proxy.clone()
        } else {
            TryRc::try_new(peer(b"origin.example", 80, None)).unwrap()
        };
        Route::Tcp(Tcp {
            origin,
            via: None,
            ip: IpVersion::Any,
            proxy: Some(ProxyRoute {
                kind: ProxyType::Http,
                peer: proxy,
                creds,
                forward,
                auth_only: false,
            }),
        })
    }

    /// A connection through a proxy serves a transfer through the same
    /// proxy, the same way, as the same user (`url_match_proxy_use`); a
    /// forwarding one serves any origin, being the proxy's.
    #[test]
    fn proxied_routes_match_as_c() {
        let direct = Route::Tcp(Tcp {
            origin: TryRc::try_new(peer(b"proxy.example", 3128, None)).unwrap(),
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
    }
}
