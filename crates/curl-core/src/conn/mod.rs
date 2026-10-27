//! Connections: what a transfer talks over, owned by the pool and leased to
//! transfers.
//!
//! A networkless connection is what `file:` leases, as C attaches a
//! connection to every transfer. A TCP one is set up by a
//! `ConnectMachine`, in the slot it keeps once established. `io` is the
//! engine's way to the network.

mod bind;
mod buf;
pub(crate) mod chain;
mod connect;
mod connect_to;
mod dns;
pub(crate) mod h2proxy;
pub mod io;
pub(crate) mod layer;
pub(crate) mod mux;
pub(crate) mod part;
pub(crate) mod pool;
pub(crate) mod proxy;
pub(crate) mod quic;
pub(crate) mod shutdown;
pub(crate) mod socks;
mod stream;
pub mod threaded;
pub(crate) mod tls;

pub(crate) use connect::{
    Asked, Came, ConnCx, ConnectError, Found, MAX_ATTEMPTS, Made, Opened, Progress, QuicMaking,
    Setup, SocketSetup, Unresolved, queries,
};
pub(crate) use connect_to::{BadVia, via};
pub(crate) use dns::{
    Answer, BadEntry, DnsCache, HttpsLookup, ListEntry, Names, address, parse_entry,
};
pub(crate) use pool::{
    Acquired, AddLimits, ConnLease, Connected, Finish, Full, Home, Limit, Pool, PoolNote, Released,
    ReuseRules, WaitReason,
};

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};

use crate::idn::{Idn, IdnFailure};
use crate::options::{IpVersion, ProxyType};
use crate::report::ResponseVersion;
use crate::tls::TlsIdentity;

pub(crate) use self::buf::RecvBuf;
/// How the tests' layer shuts down, for `Multi::linger_connections`.
#[cfg(any(test, feature = "test-util"))]
pub use self::layer::Linger;
pub use self::socks::ProxyError;
pub(crate) use self::stream::Stream;

/// What transfers keep for those after them: the connections, the names
/// resolved and the TLS sessions to resume. A multi holds its own; a
/// share may hold them in its place.
pub(crate) struct Caches {
    pub(crate) pool: Pool,
    pub(crate) dns: DnsCache,
    /// The TLS sessions kept to resume (`multi->ssl_scache`).
    pub(crate) sessions: crate::tls::SessionCache,
}

impl Caches {
    pub(crate) fn new() -> Result<Caches, curl_alloc::OutOfMemory> {
        Ok(Caches {
            pool: Pool::new()?,
            dns: DnsCache::default(),
            sessions: crate::tls::SessionCache::new(crate::tls::SessionCache::PEERS),
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
    pub fn get(self) -> u64 {
        self.0
    }
}

/// A transfer's number in the pool it joined, counting from 0 in the
/// order they joined (C's `data->id`, `CURLINFO_XFER_ID`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransferNumber(u64);

impl TransferNumber {
    pub fn get(self) -> u64 {
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
                    tls,
                    local,
                    delegation,
                    dial,
                } = have;
                let Tcp {
                    origin: want_origin,
                    via: want_via,
                    ip: want_ip,
                    proxy: want_proxy,
                    tls: want_tls,
                    local: want_local,
                    delegation: want_delegation,
                    dial: want_dial,
                } = want;
                **origin == **want_origin
                    && delegation == want_delegation
                    && dial == want_dial
                    // C compares the detours without their schemes
                    // (`Curl_peer_same_destination`); each has its
                    // origin's.
                    && via.as_deref() == want_via.as_deref()
                    // A transfer that takes any family takes either.
                    && (*want_ip == IpVersion::Any || want_ip == ip)
                    && proxy.as_ref().map(ProxyRoute::key)
                        == want_proxy.as_ref().map(ProxyRoute::key)
                    // TLS made with every setting the transfer's has, or
                    // none on both (`url_match_ssl_config`): a transfer
                    // that verifies its peer never takes a connection
                    // made without.
                    && tls.as_deref() == want_tls.as_deref()
                    && binds_as(local.as_deref(), want_local.as_deref())
            }
            (Route::Local | Route::Tcp(..), Route::Local | Route::Tcp(..)) => false,
        }
    }
}

/// Whether a connection bound as `have` serves a transfer that binds as
/// `want` (`url_match_connect_config`): the same interface, or none on
/// both, as it may go another way; and the same port and range if the
/// transfer names an interface or a port, as one that names neither
/// takes any.
fn binds_as(
    have: Option<&crate::options::LocalBind>,
    want: Option<&crate::options::LocalBind>,
) -> bool {
    use crate::options::LocalBind;
    let have = have.unwrap_or(&LocalBind::NONE);
    let want = want.unwrap_or(&LocalBind::NONE);
    // Every field by name, as in `Route::serves`.
    let LocalBind {
        interface,
        port,
        port_range,
    } = want;
    let anywhere = interface.is_none() && *port == 0;
    *interface == have.interface
        && (anywhere || (*port == have.port && *port_range == have.port_range))
}

/// A route over TCP to `origin`, the peer shared by the transfer and the
/// connection; through `via` when a connect-to entry names another peer
/// for it (C's `via_peer`); over the addresses of `ip`; through `proxy`
/// if there is one, which is the origin itself for a proxy the requests
/// go to whole; secured by TLS made with `tls`, if its scheme is (C's
/// `PROTOPT_SSL`).
#[derive(Clone, Debug)]
pub(crate) struct Tcp {
    pub(crate) origin: TryArc<Peer>,
    pub(crate) via: Option<TryArc<Peer>>,
    pub(crate) ip: IpVersion,
    pub(crate) proxy: Option<ProxyRoute>,
    /// Shared with the connection set up for it, as every connection's
    /// slot holds its route inline.
    pub(crate) tls: Option<TryArc<crate::tls::TlsIdentity>>,
    /// What each socket's local end is bound to, if anything (C's
    /// `interface_opts`, `localport`, `localportrange`): shared, as few
    /// routes bind and every connection's slot holds its route inline.
    pub(crate) local: Option<TryArc<crate::options::LocalBind>>,
    /// How far GSS-API contexts over it delegate the user's credentials
    /// (`conn->gssapi_delegation`): a transfer reusing it must ask the
    /// same (`url_match_auth`).
    pub(crate) delegation: crate::options::Delegation,
    /// How the connection to its first hop is made: a TCP stream, or QUIC
    /// over UDP (C's `transport_wanted`). A connection serves only a
    /// transfer that dials as it did.
    pub(crate) dial: Dial,
}

/// How a route's connection is dialed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Dial {
    /// A TCP stream, or a Unix socket's (`TRNSPRT_TCP`, `TRNSPRT_UNIX`).
    #[default]
    Tcp,
    /// QUIC over UDP (`TRNSPRT_QUIC`).
    Quic,
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

    /// `destination`, shared.
    pub(crate) fn destination_shared(&self) -> &TryArc<Peer> {
        match &self.proxy {
            Some(proxy) => proxy.first_peer_shared(),
            None => self.via.as_ref().unwrap_or(&self.origin),
        }
    }

    /// What the socket's filter traces as: `UNIX` for a Unix socket's
    /// (`Curl_cft_unix`), `UDP` for QUIC's (`Curl_cft_udp`), else `TCP`.
    pub(crate) fn socket_component(&self) -> crate::components::Component {
        if self.destination().is_unix() {
            crate::components::Component::Unix
        } else if self.dial == Dial::Quic {
            crate::components::Component::Udp
        } else {
            crate::components::Component::Tcp
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

    /// A connection on it speaks TLS: to the origin, to an HTTPS proxy,
    /// or to both, one inside the other.
    pub(crate) fn secured(&self) -> bool {
        self.tls.is_some() || self.proxy_tls().is_some()
    }

    /// The settings an HTTPS proxy's TLS is made with, if the route goes
    /// through one.
    pub(crate) fn proxy_tls(&self) -> Option<&TryArc<TlsIdentity>> {
        self.proxy.as_ref()?.tls()
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
    /// The SOCKS proxy itself.
    pub(crate) at: &'a Peer,
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
    /// What few proxies have: shared, as every connection's slot holds
    /// its route inline.
    cold: Option<TryArc<ProxyCold>>,
}

/// What of a proxy few routes have.
#[derive(Debug, Default)]
struct ProxyCold {
    /// The SOCKS proxy in front of it, which only an HTTP proxy has.
    pre: Option<PreProxy>,
    /// The settings an HTTPS proxy's TLS is made with, which a connection
    /// must share to serve the transfer (C's `proxy_ssl_config`); none for
    /// any other proxy.
    tls: Option<TryArc<TlsIdentity>>,
}

/// The user and password a proxy is given, and the service it is
/// authenticated as, each empty for none (C's `http_proxy.creds`, its
/// `sasl_service` from `CURLOPT_PROXY_SERVICE_NAME`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProxyCreds {
    pub(crate) user: Vec<u8>,
    pub(crate) password: Vec<u8>,
    pub(crate) service: Vec<u8>,
}

impl ProxyCreds {
    /// What the proxy is authenticated with.
    pub(crate) fn secret(&self) -> crate::proto::http1::auth::Secret<'_> {
        crate::proto::http1::auth::Secret::new(&self.user, &self.password, &self.service)
    }
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
    /// An HTTPS proxy's TLS settings (`url_match_proxy_use`'s
    /// `Curl_ssl_conn_config_match`).
    tls: Option<&'a TlsIdentity>,
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
            cold: None,
        }
    }

    /// The same proxy, what few have changed by `change`.
    fn with_cold(self, change: impl FnOnce(&mut ProxyCold)) -> Result<ProxyRoute, OutOfMemory> {
        let mut cold = match self.cold.as_deref() {
            Some(ProxyCold { pre, tls }) => ProxyCold {
                pre: pre.clone(),
                tls: tls.clone(),
            },
            None => ProxyCold::default(),
        };
        change(&mut cold);
        Ok(ProxyRoute {
            cold: Some(TryArc::try_new(cold)?),
            ..self
        })
    }

    /// The same proxy, an HTTPS one, its TLS made with `identity`.
    pub(crate) fn secured(self, identity: TryArc<TlsIdentity>) -> Result<ProxyRoute, OutOfMemory> {
        assert!(self.https(), "only an HTTPS proxy speaks TLS");
        self.with_cold(|cold| cold.tls = Some(identity))
    }

    /// The settings an HTTPS proxy's TLS is made with; none for any other
    /// proxy.
    pub(crate) fn tls(&self) -> Option<&TryArc<TlsIdentity>> {
        self.cold.as_deref()?.tls.as_ref()
    }

    /// The SOCKS proxy in front of it, if any.
    fn pre(&self) -> Option<&PreProxy> {
        self.cold.as_deref()?.pre.as_ref()
    }

    /// Whether it is an HTTPS proxy, which the connection to speaks TLS
    /// (`CURL_PROXY_IS_HTTPS`).
    pub(crate) fn https(&self) -> bool {
        matches!(
            self.kind,
            ProxyType::Https | ProxyType::Https2 | ProxyType::Https3
        )
    }

    /// The same HTTP proxy, reached through the SOCKS proxy `pre`.
    pub(crate) fn behind(self, pre: PreProxy) -> Result<ProxyRoute, OutOfMemory> {
        assert!(self.http(), "only an HTTP proxy has a SOCKS proxy in front");
        assert!(
            socks::Version::of(pre.kind).is_some(),
            "a pre-proxy is SOCKS"
        );
        self.with_cold(|cold| cold.pre = Some(pre))
    }

    /// The peer connected to first.
    pub(crate) fn first_peer(&self) -> &Peer {
        self.first_peer_shared()
    }

    /// `first_peer`, shared.
    pub(crate) fn first_peer_shared(&self) -> &TryArc<Peer> {
        self.pre().map_or(&self.peer, |pre| &pre.peer)
    }

    /// The SOCKS proxy on the way to `target`: the one in front, asked
    /// for this proxy, else this one if it is SOCKS.
    pub(crate) fn socks<'a>(&'a self, target: &'a Peer) -> Option<SocksLeg<'a>> {
        match self.pre() {
            Some(pre) => Some(SocksLeg {
                version: socks::Version::of(pre.kind).expect("a pre-proxy is SOCKS"),
                at: &pre.peer,
                creds: pre.creds.as_deref(),
                to: &self.peer,
            }),
            None => socks::Version::of(self.kind).map(|version| SocksLeg {
                version,
                at: &self.peer,
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
            cold,
        } = self;
        let (pre, tls) = match cold.as_deref() {
            Some(ProxyCold { pre, tls }) => (pre.as_ref(), tls.as_deref()),
            None => (None, None),
        };
        ProxyKey {
            kind: *kind,
            peer: Destination(peer),
            creds: creds.as_deref(),
            forward: *forward,
            pre: pre.map(|pre| {
                let PreProxy { kind, peer, creds } = pre;
                (*kind, Destination(peer), creds.as_deref())
            }),
            tls,
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
            ascii: _,
            port,
            zone,
            scope,
            at,
        } = a;
        *port == b.port
            && *at == b.at
            && a.same_name(b)
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
    /// The name the host is looked up and sent by, when the URL names it
    /// in Unicode: its ASCII form (C's `hostname`, set apart from
    /// `user_hostname` by IDN).
    ascii: Option<Vec<u8>>,
    port: u16,
    zone: Option<Vec<u8>>,
    /// The IPv6 scope: the zone as a number, or the index of the
    /// interface it names; 0 if neither (`scopeid`).
    scope: u32,
    /// What the host names: a host on the network, or the path of a Unix
    /// socket (`unix_socket`, `abstract_uds`).
    at: PeerAt,
}

/// What a peer's host names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerAt {
    Network,
    /// A Unix socket by its path, the host, at port 0.
    Unix,
    /// A Unix socket in the abstract namespace, the host its name.
    AbstractUnix,
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
            ascii: None,
            port,
            zone,
            scope,
            at: PeerAt::Network,
        }
    }

    /// The same peer, its host looked up by its ASCII form where the URL
    /// names it in Unicode and `idn` converts it (`peer_parse_host`); a
    /// name that does not convert, or converts to nothing, is refused.
    pub(crate) fn idn(mut self, idn: Option<&dyn Idn>) -> Result<Peer, IdnFailure> {
        if self.at == PeerAt::Network && !self.ipv6() {
            self.ascii = crate::idn::lookup_name(idn, &self.host)?;
        }
        Ok(self)
    }

    /// The Unix socket at `path`, in the abstract namespace if
    /// `abstract_name`, spoken to with `scheme`'s protocol: one the
    /// options name is at port 0 (`Curl_peer_uds_create`), a SOCKS
    /// proxy's at its URL's port, which no connect uses.
    pub(crate) fn unix(scheme: Scheme, path: Vec<u8>, port: u16, abstract_name: bool) -> Peer {
        Peer {
            scheme,
            host: path,
            ascii: None,
            port,
            zone: None,
            scope: 0,
            at: if abstract_name {
                PeerAt::AbstractUnix
            } else {
                PeerAt::Unix
            },
        }
    }

    /// What the host names.
    pub(crate) fn at(&self) -> PeerAt {
        self.at
    }

    /// Whether the host is a Unix socket's path.
    pub(crate) fn is_unix(&self) -> bool {
        self.at != PeerAt::Network
    }

    /// The same host: a Unix socket's path exactly, as file systems tell
    /// case apart, and a host's name in any case (`peer_same_hostname`).
    fn same_name(&self, other: &Peer) -> bool {
        self.ipv6() == other.ipv6()
            && match self.at {
                PeerAt::Network => self.name().eq_ignore_ascii_case(other.name()),
                PeerAt::Unix | PeerAt::AbstractUnix => self.host == other.host,
            }
    }

    /// A peer in the IPv6 scope `scope`, which takes the place of any
    /// zone the URL names (`CURLOPT_ADDRESS_SCOPE`, `Curl_peer_from_url`).
    pub(crate) fn scoped(scheme: Scheme, host: Vec<u8>, port: u16, scope: NonZeroU32) -> Peer {
        Peer {
            scheme,
            host,
            ascii: None,
            port,
            zone: None,
            scope: scope.get(),
            at: PeerAt::Network,
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
            ascii: self.ascii.as_deref().map(copy).transpose()?,
            port: self.port,
            zone: self.zone.as_deref().map(copy).transpose()?,
            scope: self.scope,
            at: self.at,
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

    /// The host without an IPv6 address's brackets, and a name the URL
    /// gives in Unicode in its ASCII form (`hostname`); a Unix socket's
    /// path as it is.
    pub(crate) fn name(&self) -> &[u8] {
        if self.is_unix() {
            return &self.host;
        }
        if let Some(ascii) = &self.ascii {
            return ascii;
        }
        self.host
            .strip_prefix(b"[")
            .and_then(|h| h.strip_suffix(b"]"))
            .unwrap_or(&self.host)
    }

    /// The host as a request's `Host:` names it: an IPv6 address in
    /// brackets, without its zone; any other by its name, in ASCII.
    pub(crate) fn request_host(&self) -> &[u8] {
        if self.ipv6() { &self.host } else { self.name() }
    }

    /// Whether the name is the URL's host converted from Unicode, which a
    /// request to a proxy then names in its target in place of the URL's.
    pub(crate) fn converted(&self) -> bool {
        self.ascii.is_some()
    }

    /// Whether the host is an IPv6 address.
    pub(crate) fn ipv6(&self) -> bool {
        !self.is_unix() && self.host.first() == Some(&b'[')
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
            ascii: _,
            port,
            zone,
            scope,
            at,
        } = self;
        *scheme == other.scheme
            && *port == other.port
            && *at == other.at
            && self.same_name(other)
            && *scope == other.scope
            && (*scope != 0 || *zone == other.zone)
    }
}

impl Eq for Peer {}

impl Peer {
    /// Whether connections to the two count toward one per-host limit:
    /// C's `destination`, `host:port` in lowercase, an IPv6 address in
    /// brackets with its scope; the scheme and a zone's name aside.
    /// A Unix socket's path is lowercased too, as it is in C's text.
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
    remote: Option<io::Remote>,
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
    /// HTTP Negotiate's context with the origin, and what the connection
    /// is bound to by it; made the first time a request negotiates.
    negotiate: Option<Box<crate::proto::http::negotiate::Negotiate>>,
    /// The session it multiplexes over, once its first request found a
    /// version that does agreed on (`cf-h2`): it speaks nothing else from
    /// then on.
    session: Option<mux::Session>,
}

impl Conn {
    /// Who its requests are for; none without a network.
    pub(crate) fn origin(&self) -> Option<&TryArc<Peer>> {
        match &self.route {
            Route::Tcp(tcp) => Some(&tcp.origin),
            Route::Local => None,
        }
    }

    /// Its number among those the pool made (`connection_id`).
    pub(crate) fn number(&self) -> ConnNumber {
        self.number
    }

    /// Whether it multiplexes: a session speaks for it
    /// (`Curl_conn_is_multiplex`).
    pub(crate) fn multiplexes(&self) -> bool {
        self.session.is_some()
    }

    /// The session it multiplexes over, if it does.
    pub(crate) fn session(&self) -> Option<&mux::Session> {
        self.session.as_ref()
    }

    /// Its HTTP/2 session, if it speaks HTTP/2.
    pub(crate) fn h2(&self) -> Option<&crate::proto::http2::H2Conn> {
        match self.session.as_ref()? {
            mux::Session::H2(h2) => Some(&**h2),
            mux::Session::H3(_) => None,
        }
    }

    /// Its HTTP/3 session, if it speaks HTTP/3.
    pub(crate) fn h3(&self) -> Option<&crate::proto::http3::H3Conn> {
        match self.session.as_ref()? {
            mux::Session::H3(h3) => Some(&**h3),
            mux::Session::H2(_) => None,
        }
    }

    /// Its HTTP/2 session, taken out for a step to drive beside the
    /// connection, which it is put back on after (`put_h2`).
    pub(crate) fn take_h2(&mut self) -> Option<Box<crate::proto::http2::H2Conn>> {
        match self.session.take()? {
            mux::Session::H2(h2) => Some(h2),
            other @ mux::Session::H3(_) => {
                self.session = Some(other);
                None
            }
        }
    }

    /// Its HTTP/3 session, taken out for a step to drive beside the
    /// connection, which it is put back on after (`put_h3`).
    pub(crate) fn take_h3(&mut self) -> Option<Box<crate::proto::http3::H3Conn>> {
        match self.session.take()? {
            mux::Session::H3(h3) => Some(h3),
            other @ mux::Session::H2(_) => {
                self.session = Some(other);
                None
            }
        }
    }

    /// The socket under it, if it has a network.
    pub(crate) fn stream_socket(&self) -> Option<&dyn io::Socket> {
        match &self.transport {
            Transport::Tcp(stream) => Some(stream.socket()),
            Transport::Local => None,
        }
    }

    /// Put its HTTP/3 session on it, as its QUIC handshake is done.
    pub(crate) fn put_h3(&mut self, h3: Box<crate::proto::http3::H3Conn>) {
        assert!(self.session.is_none(), "one session per connection");
        self.session = Some(mux::Session::H3(h3));
    }

    /// Put an HTTP/2 session on it, a new one or one taken out.
    pub(crate) fn put_h2(&mut self, h2: Box<crate::proto::http2::H2Conn>) {
        assert!(self.session.is_none(), "one session per connection");
        self.session = Some(mux::Session::H2(h2));
    }

    /// What its session works over: its stream. A connection without a
    /// network has none.
    pub(crate) fn carrier(&mut self) -> mux::Carrier<'_> {
        self.split().1.expect("a local connection moves no bytes")
    }

    /// Its session, and what it works over, borrowed apart.
    fn split(&mut self) -> (&mut Option<mux::Session>, Option<mux::Carrier<'_>>) {
        let socket = self.socket_component();
        let Conn {
            transport,
            close,
            session,
            ..
        } = self;
        let carrier = match transport {
            Transport::Tcp(stream) => Some(mux::Carrier {
                stream,
                socket,
                close,
            }),
            Transport::Local => None,
        };
        (session, carrier)
    }

    /// Whether it seems usable, asked of its pieces from the top: its
    /// session, which reads what the peer sent it, else its layers and
    /// socket, for which input waiting is input pending
    /// (`Curl_conn_is_alive`).
    pub(crate) fn alive(&mut self, cx: &mut dyn LayerCx) -> layer::Alive {
        use part::{Lower as _, Part as _};
        match self.split() {
            (_, None) => layer::Alive::Alive {
                input_pending: false,
            },
            (Some(session), Some(carrier)) => session.is_alive(cx, carrier),
            (None, Some(carrier)) => carrier.alive(cx),
        }
    }

    /// Say goodbye from the top as it shuts down: its session's, which
    /// goes as the connection takes it, never waited on; its layers' are
    /// the stream's (`cf_h2_shutdown`).
    pub(crate) fn goodbye(&mut self, cx: &mut dyn LayerCx) {
        use part::Part as _;
        if let (Some(session), Some(carrier)) = self.split() {
            let _done = session.shutdown(cx, carrier);
        }
    }

    /// The filter at the top of its chain once it is up, which a question
    /// of it is asked of first (`conn->cfilter[FIRSTSOCKET]`).
    pub(crate) fn top(&self) -> crate::components::Component {
        match &self.route {
            Route::Tcp(route) => {
                let tunnel = match &self.transport {
                    Transport::Tcp(stream) => stream.query(layer::LayerQuery::Tunnel),
                    Transport::Local => None,
                };
                let tunnel = match tunnel {
                    Some(layer::LayerAnswer::Tunnel(filter)) => filter,
                    _ => crate::components::Component::H1Proxy,
                };
                chain::Chain::connected(route, chain::Head::default(), false, tunnel)
                    .reduced()
                    .top()
                    .expect("a connection has a socket")
            }
            Route::Local => crate::components::Component::Tcp,
        }
    }

    /// What its socket's filter traces as (`TCP`, `UNIX`).
    pub(crate) fn socket_component(&self) -> crate::components::Component {
        match &self.route {
            Route::Tcp(route) => route.socket_component(),
            Route::Local => crate::components::Component::Tcp,
        }
    }

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

    /// Whether it goes through an HTTP proxy's tunnel.
    pub(crate) fn tunnels(&self) -> bool {
        matches!(&self.route, Route::Tcp(Tcp { proxy: Some(p), .. }) if p.tunnels())
    }

    /// Whether any of it is TLS, the origin's or an HTTPS proxy's
    /// (`Curl_conn_is_ssl`).
    pub(crate) fn over_tls(&self) -> bool {
        match &self.route {
            Route::Tcp(t) => t.tls.is_some() || t.proxy.as_ref().is_some_and(|p| p.tls().is_some()),
            Route::Local => false,
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

    /// HTTP Negotiate on it, if a request negotiated.
    pub(crate) fn negotiate(&self) -> Option<&crate::proto::http::negotiate::Negotiate> {
        self.negotiate.as_deref()
    }

    pub(crate) fn negotiate_mut(
        &mut self,
    ) -> &mut Option<Box<crate::proto::http::negotiate::Negotiate>> {
        &mut self.negotiate
    }

    /// Its Negotiate, and the stream an exchange is bound to the TLS of.
    pub(crate) fn negotiate_over(
        &mut self,
    ) -> (
        &mut Option<Box<crate::proto::http::negotiate::Negotiate>>,
        Option<&Stream>,
    ) {
        let stream = match &self.transport {
            Transport::Tcp(stream) => Some(stream),
            Transport::Local => None,
        };
        (&mut self.negotiate, stream)
    }

    /// Whether a transfer with `wants` may have it, as far as Negotiate's
    /// binding goes (`url_match_auth`, `url_match_auth_nego`).
    pub(crate) fn serves_auth(&self, wants: &crate::proto::http::negotiate::Wants<'_>) -> bool {
        self.negotiate.as_ref().is_none_or(|n| n.serves(wants))
    }

    /// Whether it is in the middle of Negotiate's handshake with the
    /// origin or the proxy, a challenge taken and the request to go again
    /// on it, which the application's forbidding its reuse does not close
    /// (`multi_conn_should_close`).
    pub(crate) fn negotiating(&self) -> bool {
        use crate::proto::http::negotiate::State;
        use crate::proto::http1::auth::Side;
        self.negotiate.as_ref().is_some_and(|n| {
            n.state(Side::Host) == State::Recv || n.state(Side::Proxy) == State::Recv
        })
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
    /// The socket's receive is traced, and its failure said, as it
    /// reaches the socket, below any layer (`cf_socket_recv`).
    pub(crate) fn recv(&mut self, cx: &mut dyn LayerCx, max: usize) -> Result<Recv, RecvFailed> {
        self.carrier().recv(cx, max)
    }

    /// Send from `bytes`, which is not empty, what the network takes now:
    /// the socket's send traced, and its failure said, as it reaches the
    /// socket, below any layer (`cf_socket_send`).
    pub(crate) fn send(&mut self, cx: &mut dyn LayerCx, bytes: &[u8]) -> std::io::Result<Sent> {
        self.carrier().send(cx, bytes)
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
    /// Leased this many times: once, or by each transfer on a connection
    /// that multiplexes.
    Leased(NonZeroU32),
    /// Leased by no one since this time (C's `lastused`), its health
    /// last found good this many whole milliseconds after it was made
    /// (C's `lastchecked_ms`), as it was returned at first. Past `u32`'s
    /// range it is looked at every time.
    Idle { since: Instant, checked_ms: u32 },
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

    /// A Unix socket is the same as another of the same path, in the same
    /// namespace, its path's case told apart, and never a host of that
    /// name (`peer_same_hostname`).
    #[test]
    fn unix_sockets_are_told_apart_as_c_tells_them() {
        let unix = |path: &[u8], abstract_name| Peer::unix(HTTP, path.to_vec(), 0, abstract_name);
        assert_eq!(unix(b"/tmp/s", false), unix(b"/tmp/s", false));
        assert_ne!(unix(b"/tmp/s", false), unix(b"/tmp/S", false));
        assert_ne!(unix(b"/tmp/s", false), unix(b"/tmp/s", true));
        assert_ne!(
            unix(b"/tmp/s", false),
            Peer::new(HTTP, b"/tmp/s".to_vec(), 0, None)
        );
        assert!(Destination(&unix(b"s", true)) != Destination(&unix(b"S", true)));
        assert!(!unix(b"[::1]", false).ipv6());
        assert_eq!(unix(b"[::1]", false).name(), b"[::1]");
        // A connection over one serves only a transfer over the same.
        let over = |path: &[u8]| {
            Route::Tcp(Tcp {
                origin: TryArc::try_new(peer(b"o.example", 80, None)).unwrap(),
                via: Some(TryArc::try_new(unix(path, false)).unwrap()),
                ip: IpVersion::Any,
                proxy: None,
                tls: None,
                local: None,
                delegation: Default::default(),
                dial: crate::conn::Dial::Tcp,
            })
        };
        assert!(over(b"/tmp/s").serves(&over(b"/tmp/s")));
        assert!(!over(b"/tmp/s").serves(&over(b"/tmp/t")));
    }

    /// A connection dialed over QUIC serves only a transfer that dials
    /// QUIC, and one over TCP only one over TCP, the same origin
    /// otherwise (`url_match_conn`'s `transport` check).
    #[test]
    fn a_connection_serves_only_a_transfer_that_dials_as_it_did() {
        let dialed = |dial| {
            Route::Tcp(Tcp {
                origin: TryArc::try_new(peer(b"o.example", 443, None)).unwrap(),
                via: None,
                ip: IpVersion::Any,
                proxy: None,
                tls: None,
                local: None,
                delegation: Default::default(),
                dial,
            })
        };
        assert!(dialed(Dial::Quic).serves(&dialed(Dial::Quic)));
        assert!(dialed(Dial::Tcp).serves(&dialed(Dial::Tcp)));
        assert!(!dialed(Dial::Quic).serves(&dialed(Dial::Tcp)));
        assert!(!dialed(Dial::Tcp).serves(&dialed(Dial::Quic)));
        // Its socket's lines are traced as C's UDP filter's.
        let Route::Tcp(quic) = dialed(Dial::Quic) else {
            unreachable!()
        };
        assert_eq!(quic.socket_component(), crate::components::Component::Udp);
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
                tls: None,
                local: None,
                delegation: Default::default(),
                dial: crate::conn::Dial::Tcp,
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

    /// A connection made with TLS serves only a transfer whose TLS has
    /// every setting its handshake had, and one without TLS only one
    /// without (`url_match_ssl_use`, `url_match_ssl_config`): a transfer
    /// that verifies its peer never takes a connection that did not, nor
    /// the other way round (the CVE-2021-22924 class).
    #[test]
    fn routes_compare_their_tls() {
        use crate::options::Tls;
        use crate::tls::TlsIdentity;
        let secured = |tls: Option<&Tls>| {
            Route::Tcp(Tcp {
                origin: TryArc::try_new(peer(b"o.example", 443, None)).unwrap(),
                via: None,
                ip: IpVersion::Any,
                proxy: None,
                tls: tls.map(|t| TlsIdentity::of(t, Default::default()).unwrap()),
                local: None,
                delegation: Default::default(),
                dial: crate::conn::Dial::Tcp,
            })
        };
        let verified = Tls::default();
        let insecure = Tls {
            verify_peer: false,
            verify_host: false,
            ..Tls::default()
        };
        let unverified_peer = Tls {
            verify_peer: false,
            ..Tls::default()
        };
        let have = secured(Some(&verified));
        assert!(have.serves(&secured(Some(&Tls::default()))));
        for other in [&insecure, &unverified_peer] {
            assert!(!have.serves(&secured(Some(other))));
            assert!(!secured(Some(other)).serves(&have));
        }
        assert!(!have.serves(&secured(None)) && !secured(None).serves(&have));
        let mut blob = Tls::default();
        blob.options.make_mut().unwrap().ca_blob = Some(b"pem".to_vec());
        assert!(!have.serves(&secured(Some(&blob))));
    }

    fn via_proxy(host: &[u8], user: Option<&[u8]>, forward: bool) -> Route {
        let proxy = TryArc::try_new(peer(host, 3128, None)).unwrap();
        let creds = user.map(|u| {
            TryArc::try_new(ProxyCreds {
                user: u.to_vec(),
                password: Vec::new(),
                service: Vec::new(),
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
            tls: None,
            local: None,
            delegation: Default::default(),
            dial: crate::conn::Dial::Tcp,
        })
    }

    /// A connection bound serves a transfer bound to the same interface,
    /// written the same way, and to the same ports if the transfer names
    /// an interface or a port; one that names neither takes any port, but
    /// no interface (`url_match_connect_config`).
    #[test]
    fn bound_routes_match_as_c() {
        use crate::options::{Interface, LocalBind};
        let bound = |interface: &str, port, port_range| {
            let local = LocalBind {
                interface: Interface::parse(interface.as_bytes()).unwrap(),
                port,
                port_range,
            };
            Route::Tcp(Tcp {
                origin: TryArc::try_new(peer(b"o.example", 80, None)).unwrap(),
                via: None,
                ip: IpVersion::Any,
                proxy: None,
                tls: None,
                local: local.binds().then(|| TryArc::try_new(local).unwrap()),
                delegation: Default::default(),
                dial: crate::conn::Dial::Tcp,
            })
        };
        let plain = bound("", 0, 0);
        assert!(plain.serves(&plain));
        // A port named takes only the same ports.
        assert!(bound("", 4000, 1).serves(&bound("", 4000, 1)));
        assert!(!bound("", 4000, 2).serves(&bound("", 4000, 1)));
        assert!(!bound("", 4001, 1).serves(&bound("", 4000, 1)));
        assert!(!plain.serves(&bound("", 4000, 1)));
        // None named takes any port, but not an interface.
        assert!(bound("", 4000, 1).serves(&plain));
        assert!(!bound("eth0", 0, 0).serves(&plain));
        assert!(!plain.serves(&bound("eth0", 0, 0)));
        // An interface as it was written, and its ports with it.
        assert!(bound("eth0", 0, 0).serves(&bound("eth0", 0, 0)));
        assert!(!bound("if!eth0", 0, 0).serves(&bound("eth0", 0, 0)));
        assert!(!bound("eth0", 4000, 1).serves(&bound("eth0", 0, 0)));
        assert!(!bound("eth1", 0, 0).serves(&bound("eth0", 0, 0)));
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
            tls: None,
            local: None,
            delegation: Default::default(),
            dial: crate::conn::Dial::Tcp,
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
        // The service the proxy is authenticated as is the credentials'
        // too (`Curl_creds_same`).
        let serving_as = |service: &[u8]| match via_proxy(b"proxy.example", Some(b"u"), true) {
            Route::Tcp(mut tcp) => {
                let p = tcp.proxy.as_mut().unwrap();
                p.creds = Some(
                    TryArc::try_new(ProxyCreds {
                        user: b"u".to_vec(),
                        password: Vec::new(),
                        service: service.to_vec(),
                    })
                    .unwrap(),
                );
                Route::Tcp(tcp)
            }
            Route::Local => unreachable!(),
        };
        assert!(serving_as(b"").serves(&user) && user.serves(&serving_as(b"")));
        assert!(!serving_as(b"pxy").serves(&user) && !user.serves(&serving_as(b"pxy")));
        assert!(serving_as(b"pxy").serves(&serving_as(b"pxy")));
        // Behind the same SOCKS proxy, or none, as C compares
        // `socks_proxy` beside `http_proxy`.
        let behind = |kind, host: &[u8]| match via_proxy(b"proxy.example", None, true) {
            Route::Tcp(mut tcp) => {
                let pre = PreProxy {
                    kind,
                    peer: TryArc::try_new(peer(host, 1080, None)).unwrap(),
                    creds: None,
                };
                tcp.proxy = tcp.proxy.map(|p| p.behind(pre).unwrap());
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
