//! Connections: what a transfer talks over, owned by the pool and leased to
//! transfers.
//!
//! A networkless connection is what `file:` leases, as C attaches a
//! connection to every transfer. A TCP one is set up by a
//! `ConnectMachine`, in the slot it keeps once established. `io` is the
//! engine's way to the network.

pub(crate) mod asyncs;
mod bind;
mod buf;
pub(crate) mod capsule;
pub(crate) mod chain;
mod connect;
mod connect_to;
mod dns;
pub(crate) mod h2proxy;
pub(crate) mod h3proxy;
pub mod io;
pub(crate) mod layer;
pub(crate) mod line;
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
    Addresses, Asked, ConnCx, ConnectError, ConnectMachine, DriveOptions, Drove, Found, Handshook,
    Held, MAX_ATTEMPTS, Made, OfFamily, Opened, Progress, QuicMaking, Reply, SocketSetup,
    SocksTarget, Tunneled, Unresolved, family, queries, resolve_blocking, say_answered, say_queued,
};
pub(crate) use connect_to::{BadVia, via};
pub(crate) use dns::{
    Answer, BadEntry, DnsCache, Holds, HttpsLookup, ListEntry, Names, address, parse_entry,
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
#[cfg(any(test, feature = "test-util"))]
use crate::url::schemes::Flags;
use crate::url::schemes::{self, Known};

pub(crate) use self::buf::RecvBuf;
/// How the tests' layer shuts down, for `Multi::linger_connections`.
#[cfg(any(test, feature = "test-util"))]
pub use self::layer::Linger;
pub use self::socks::ProxyError;
pub(crate) use self::stream::{Datagrams, Stream};

/// What transfers keep for those after them: the connections, the names
/// resolved and the TLS sessions to resume. A multi holds its own; a
/// share may hold them in its place.
pub(crate) struct Caches {
    pub(crate) pool: Pool,
    pub(crate) dns: DnsCache,
    /// The TLS sessions kept to resume (`multi->ssl_scache`).
    pub(crate) sessions: crate::tls::SessionCache,
    /// The public suffix list its transfers use, unless their share keeps
    /// one (`multi->psl`).
    pub(crate) psl: crate::psl::PslCache,
    /// The numbers its transfers' resolves are given, as C's multi numbers
    /// them, beside the connections' (`last_resolv_id`).
    pub(crate) resolves: asyncs::ResolveCount,
    /// Whether the sessions are going out to the application's function:
    /// made by the first export, as few multis have one.
    pub(crate) sessions_out: Option<crate::multi::SessionsOut>,
}

impl Caches {
    pub(crate) fn new() -> Result<Caches, curl_alloc::OutOfMemory> {
        Ok(Caches {
            pool: Pool::new()?,
            dns: DnsCache::default(),
            sessions: crate::tls::SessionCache::new(crate::tls::SessionCache::PEERS),
            psl: crate::psl::PslCache::default(),
            resolves: asyncs::ResolveCount::default(),
            sessions_out: None,
        })
    }
}
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

    /// The number `n`, for tests outside the pool that hands them out.
    #[cfg(test)]
    pub(crate) fn for_tests(n: u64) -> ConnNumber {
        ConnNumber(n)
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
                route: Route::Net(tcp),
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
    Net(NetRoute),
}

impl Route {
    /// Whether a connection set up for this route may serve a transfer
    /// that needs `wanted` (`url_match_conn`): it reaches what the
    /// transfer wants, and it is set up as the transfer would set it up.
    pub(crate) fn serves(&self, wanted: &Route) -> bool {
        self.reaches(wanted) && self.suits(wanted)
    }

    /// The checks that come before C's notes of what the search saw
    /// (`url_match_connect_config`, `url_match_destination`): bound as the
    /// transfer binds, over the addresses it takes, through the same
    /// detour to the same origin.
    pub(crate) fn reaches(&self, wanted: &Route) -> bool {
        let (Route::Net(have), Route::Net(want)) = (self, wanted) else {
            return false;
        };
        // Every field by name, here and in `suits`, so that one added
        // does not compile until it is compared in one or said why not.
        let NetRoute {
            origin,
            via,
            ip,
            proxy: _,
            tls: _,
            cold: _,
            delegation: _,
        } = have;
        let NetRoute {
            origin: want_origin,
            via: want_via,
            ip: want_ip,
            proxy: _,
            tls: _,
            cold: _,
            delegation: _,
        } = want;
        // A transfer that takes any family takes either.
        (*want_ip == IpVersion::Any || want_ip == ip)
            && binds_as(have.local(), want.local())
            // C compares the detours without their schemes
            // (`Curl_peer_same_destination`); each has its origin's.
            && match (via.as_deref(), want_via.as_deref()) {
                (Some(have), Some(want)) => have.same_destination(want),
                (have, want) => have.is_none() && want.is_none(),
            }
            && origin.scheme().serves(want_origin.scheme())
            && origin.same_destination(want_origin)
    }

    /// The checks after (`url_match_proxy_use`, `url_match_ssl_config`,
    /// `url_match_auth`): through the same proxy, with TLS made with
    /// every setting the transfer's has, delegating as it asks.
    fn suits(&self, wanted: &Route) -> bool {
        let (Route::Net(have), Route::Net(want)) = (self, wanted) else {
            return false;
        };
        let NetRoute {
            origin: _,
            via: _,
            ip: _,
            proxy,
            tls,
            // `RouteCold::suits`.
            cold: _,
            delegation,
        } = have;
        let NetRoute {
            origin: _,
            via: _,
            ip: _,
            proxy: want_proxy,
            tls: want_tls,
            cold: _,
            delegation: want_delegation,
        } = want;
        let none = &RouteCold::NONE;
        let cold = have.cold.as_deref().unwrap_or(none);
        let want_cold = want.cold.as_deref().unwrap_or(none);
        proxy.as_ref().map(ProxyRoute::key) == want_proxy.as_ref().map(ProxyRoute::key)
            && cold.suits(
                want_cold,
                tls.as_deref(),
                want_tls.as_deref(),
                want.origin.scheme(),
            )
            && delegation == want_delegation
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
pub(crate) struct NetRoute {
    pub(crate) origin: TryArc<Peer>,
    pub(crate) via: Option<TryArc<Peer>>,
    pub(crate) ip: IpVersion,
    pub(crate) proxy: Option<ProxyRoute>,
    /// Shared with the connection set up for it, as every connection's
    /// slot holds its route inline.
    pub(crate) tls: Option<TryArc<crate::tls::TlsIdentity>>,
    /// What few routes have: shared, as every connection's slot holds
    /// its route inline. None for none of it.
    pub(crate) cold: Option<TryArc<RouteCold>>,
    /// How far GSS-API contexts over it delegate the user's credentials
    /// (`conn->gssapi_delegation`): a transfer reusing it must ask the
    /// same (`url_match_auth`).
    pub(crate) delegation: crate::options::Delegation,
}

/// What of a network route few have.
#[derive(Debug)]
pub(crate) struct RouteCold {
    /// What each socket's local end is bound to, if anything (C's
    /// `interface_opts`, `localport`, `localportrange`).
    pub(crate) local: crate::options::LocalBind,
    /// The credentials the connection logs in with once, for a scheme
    /// that logs in per connection, its first transfer's (`conn->creds`);
    /// a transfer reusing it must have the same (`url_match_auth`).
    pub(crate) login: Option<crate::auth::creds::Credentials>,
    /// The TLS a connection not over it from the start is upgraded to,
    /// or may be: made with the transfer's settings, which a transfer
    /// reusing it must share (C's `ssl_config` for `may_tls`, or for a
    /// scheme that may reuse TLS, `PROTOPT_SSL_REUSE`).
    pub(crate) upgrade: Option<TryArc<crate::tls::TlsIdentity>>,
    /// How far the transfer asks for TLS (`CURLOPT_USE_SSL`): a transfer
    /// that requires it never reuses a connection not over it.
    pub(crate) use_ssl: crate::options::UseSsl,
    /// What an FTP connection logged in and set up with, which a
    /// transfer reusing it must share (`Curl_ftp_conns_match`); none for
    /// another scheme's.
    pub(crate) ftp: Option<FtpSetup>,
    /// The key files an SCP or SFTP connection logs in with, as its first
    /// transfer found them, which a transfer reusing it must find the
    /// same (`ssh_config_matches`); none for another scheme's.
    pub(crate) ssh: Option<crate::proto::ssh::Keys>,
}

/// What an FTP connection logged in and set up with, beyond its
/// credentials.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FtpSetup {
    /// The account it gave (`CURLOPT_FTP_ACCOUNT`).
    pub(crate) account: Option<Vec<u8>>,
    /// The command sent in place of a refused `USER`
    /// (`CURLOPT_FTP_ALTERNATIVE_TO_USER`).
    pub(crate) alternative_to_user: Option<Vec<u8>>,
    /// Whether, and how, its commands went back to the clear
    /// (`CURLOPT_FTP_SSL_CCC`).
    pub(crate) ccc: crate::options::Ccc,
}

impl FtpSetup {
    /// Whether a connection set up as `self` serves a transfer that
    /// would set one up as `want`, the first asking for TLS as `have_ssl`
    /// and the other as `want_ssl` (`Curl_ftp_conns_match`): the same
    /// account, alternative and CCC; a transfer that only tries TLS takes
    /// one that asked for any, else the asking must be the same.
    pub(crate) fn serves(
        &self,
        want: &FtpSetup,
        have_ssl: crate::options::UseSsl,
        want_ssl: crate::options::UseSsl,
    ) -> bool {
        use crate::options::UseSsl;
        self == want
            && match want_ssl {
                UseSsl::Try => have_ssl != UseSsl::None,
                _ => want_ssl == have_ssl,
            }
    }
}

impl RouteCold {
    /// What a route without any of it has.
    const NONE: RouteCold = RouteCold {
        local: crate::options::LocalBind::NONE,
        login: None,
        upgrade: None,
        use_ssl: crate::options::UseSsl::None,
        ftp: None,
        ssh: None,
    };

    /// Whether it holds nothing a route without it does not. Every field
    /// by name, so that one added does not compile until it is asked.
    pub(crate) fn is_empty(&self) -> bool {
        let RouteCold {
            local,
            login,
            upgrade,
            use_ssl,
            ftp,
            ssh,
        } = self;
        !local.binds()
            && login.is_none()
            && upgrade.is_none()
            && *use_ssl == crate::options::UseSsl::None
            && ftp.is_none()
            && ssh.is_none()
    }

    /// Whether a connection of a route with `self` and TLS made with `tls`
    /// suits a transfer of `scheme` with `want` and `want_tls`
    /// (`url_match_ssl_config`, `url_match_auth`, and each scheme's match).
    /// Every field by name, so that one added does not compile until it is
    /// compared here or said why not.
    fn suits(
        &self,
        want: &RouteCold,
        tls: Option<&crate::tls::TlsIdentity>,
        want_tls: Option<&crate::tls::TlsIdentity>,
        scheme: Scheme,
    ) -> bool {
        let RouteCold {
            // `Route::reaches`, before C's notes of what the search saw.
            local: _,
            login,
            upgrade,
            use_ssl,
            ftp,
            ssh,
        } = self;
        let RouteCold {
            local: _,
            login: want_login,
            upgrade: want_upgrade,
            use_ssl: want_use_ssl,
            ftp: want_ftp,
            ssh: want_ssh,
        } = want;
        let (upgrade, want_upgrade) = (upgrade.as_deref(), want_upgrade.as_deref());
        // A connection over TLS from the start serves a transfer not, of
        // its family, that may reuse TLS, made with the settings that
        // transfer would upgrade with (`url_match_ssl_use`).
        let tls_reused =
            want_tls.is_none() && tls.is_some() && scheme.reuses_tls() && tls == want_upgrade;
        // The TLS a transfer may upgrade to, or is made with from the
        // start, is made with every setting the connection's is, which it
        // was made with or would upgrade with (`url_match_ssl_config`
        // with `may_tls`).
        let upgrade_same = !want_use_ssl.may() || tls.or(upgrade) == want_tls.or(want_upgrade);
        // A connection logged in once serves only the same credentials
        // (`url_match_auth`).
        let login_same = !scheme.logs_in_per_connection()
            || match (login, want_login) {
                (Some(have), Some(want)) => have.same(want),
                (have, want) => have.is_none() && want.is_none(),
            };
        // An FTP connection serves only a transfer that would set it up the
        // same way (`Curl_ftp_conns_match`).
        let ftp_same = match (ftp, want_ftp) {
            (Some(have), Some(want)) => have.serves(want, *use_ssl, *want_use_ssl),
            _ => true,
        };
        // An SSH connection serves only a transfer that found the same key
        // files, both having them (`ssh_config_matches`).
        let ssh_same = match (ssh, want_ssh) {
            (Some(have), Some(want)) => have.same(want),
            (have, want) => have.is_none() && want.is_none(),
        };
        // TLS made with every setting the transfer's has, or none on both
        // (`url_match_ssl_config`): a transfer that verifies its peer never
        // takes a connection made without.
        ftp_same && ssh_same && (tls == want_tls || tls_reused) && upgrade_same && login_same
    }
}

/// A network route as one attempt dials it: how the connection to its
/// first hop is made, a TCP stream or QUIC over UDP (C's
/// `transport_wanted`), is the attempt's, not the route's, so that two
/// attempts racing over one route each say their own. A connection serves
/// a transfer whichever way it was dialed, if the transfer allows the
/// version it speaks.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Dialing<'a> {
    pub(crate) route: &'a NetRoute,
    pub(crate) dial: Dial,
}

impl std::ops::Deref for Dialing<'_> {
    type Target = NetRoute;

    fn deref(&self) -> &NetRoute {
        self.route
    }
}

impl Dialing<'_> {
    /// The first hop is QUIC: to an HTTP/3 proxy whose tunnel the route
    /// goes through, or to the origin dialed over QUIC with no proxy on
    /// the way (`first_transport`). A request sent whole to a proxy is
    /// never dialed over QUIC: only HTTPS is, which a proxy tunnels.
    pub(crate) fn first_hop_quic(&self) -> bool {
        match &self.route.proxy {
            Some(proxy) => {
                assert!(
                    proxy.tunnels() || self.dial != Dial::Quic,
                    "QUIC is dialed only to a proxy that tunnels"
                );
                proxy.over_quic()
            }
            None => self.dial == Dial::Quic,
        }
    }

    /// The origin is spoken to over QUIC through an HTTP proxy's tunnel,
    /// CONNECT-UDP's: its QUIC connection's datagrams go through the
    /// layers of the connection to the proxy, over TCP or over QUIC
    /// (`tunnel_transport` is QUIC's).
    pub(crate) fn tunnels_udp(&self) -> bool {
        self.dial == Dial::Quic && self.route.proxy.as_ref().is_some_and(ProxyRoute::tunnels)
    }

    /// The tunnel through the proxy is asked for as CONNECT-UDP
    /// (`tunnel_transport` is a datagram's): for QUIC, or for a scheme of
    /// datagrams, TFTP's, which goes on over the same connection with no
    /// QUIC of its own.
    pub(crate) fn asks_udp(&self) -> bool {
        self.tunnels_udp()
            || (self.route.origin.scheme().no_tcp_proxy()
                && self.route.proxy.as_ref().is_some_and(ProxyRoute::tunnels))
    }

    /// What the socket's filter traces as: `UNIX` for a Unix socket's
    /// (`Curl_cft_unix`), `UDP` for QUIC's (`Curl_cft_udp`), else `TCP`.
    pub(crate) fn socket_component(&self) -> crate::components::Component {
        if self.route.destination().is_unix() {
            crate::components::Component::Unix
        } else if self.first_hop_quic() || self.dial == Dial::Udp {
            crate::components::Component::Udp
        } else {
            crate::components::Component::Tcp
        }
    }
}

/// How a route's connection is dialed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Dial {
    /// A TCP stream, or a Unix socket's (`TRNSPRT_TCP`, `TRNSPRT_UNIX`).
    #[default]
    Stream,
    /// QUIC over UDP (`TRNSPRT_QUIC`).
    Quic,
    /// Datagrams of the request's own, TFTP's, the socket bound but
    /// connected to no peer (`TRNSPRT_UDP`).
    Udp,
}

impl NetRoute {
    /// What each socket's local end is bound to, if anything.
    pub(crate) fn local(&self) -> Option<&crate::options::LocalBind> {
        self.cold.as_deref().map(|c| &c.local).filter(|l| l.binds())
    }

    /// The TLS settings a connection over it is upgraded with, if it may
    /// be.
    pub(crate) fn upgrade(&self) -> Option<&crate::tls::TlsIdentity> {
        self.cold.as_deref().and_then(|c| c.upgrade.as_deref())
    }

    /// How far the transfer asks for TLS.
    pub(crate) fn use_ssl(&self) -> crate::options::UseSsl {
        self.cold
            .as_deref()
            .map_or(crate::options::UseSsl::None, |c| c.use_ssl)
    }

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

    /// The route's tunnel is a stream of a QUIC connection to an HTTP/3
    /// proxy.
    pub(crate) fn proxy_over_quic(&self) -> bool {
        self.proxy.as_ref().is_some_and(ProxyRoute::over_quic)
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
    pub(crate) fn secret(&self) -> crate::auth::creds::Secret<'_> {
        crate::auth::creds::Secret::new(&self.user, &self.password, &self.service)
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

    /// It is an HTTP/3 proxy whose tunnel is a stream of a QUIC
    /// connection to it (`Curl_http_proxy_transport`), which requests
    /// sent to it whole do not use.
    pub(crate) fn over_quic(&self) -> bool {
        self.kind == ProxyType::Https3 && self.tunnels()
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

/// The scheme a connection's peer is spoken to with: its row in the
/// table of those libcurl knows (C's `struct Curl_scheme`), or a test's
/// own. Two are the same scheme by name.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Scheme(&'static Known);

impl PartialEq for Scheme {
    fn eq(&self, other: &Self) -> bool {
        self.0.name == other.0.name
    }
}

impl Eq for Scheme {}

impl Scheme {
    pub(crate) const HTTP: Scheme = Scheme::of("http");
    pub(crate) const HTTPS: Scheme = Scheme::of("https");

    /// The scheme `name`, lowercase, which libcurl must know: a name it
    /// does not fails the build where this is a constant.
    pub(crate) const fn of(name: &str) -> Scheme {
        match crate::url::known_index(name.as_bytes()) {
            Some(i) => Scheme(&schemes::KNOWN[i]),
            None => panic!("a scheme libcurl does not know"),
        }
    }

    /// The scheme `name`, in any case, if libcurl knows it.
    pub(crate) fn named(name: &[u8]) -> Option<Scheme> {
        crate::url::known(name).map(Scheme)
    }

    /// A scheme of the tests' own, which libcurl's table does not have.
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) const fn own(row: &'static Known) -> Scheme {
        Scheme(row)
    }

    /// Its name, as "Reusing existing tcp: connection" names it.
    pub(crate) fn name(self) -> &'static str {
        self.0.name
    }

    /// Whether it names a proxy and carries no transfer: SOCKS's
    /// (`PROTOPT_NO_TRANSFER`).
    pub(crate) fn no_transfer(self) -> bool {
        self.0.flags.no_transfer
    }

    /// Whether it is FTP's or FTPS's (`CURLPROTO_FTP`'s family).
    pub(crate) fn ftp_family(self) -> bool {
        self.0.family == Some(crate::url::schemes::Protocol::Ftp)
    }

    /// Whether it is HTTP's, HTTPS's or WebSocket's (`PROTO_FAMILY_HTTP`).
    pub(crate) fn http_family(self) -> bool {
        self.0.family == Some(crate::url::schemes::Protocol::Http)
    }

    /// Whether it goes over no network, and has no origin to name
    /// (`PROTOPT_NONETWORK`).
    pub(crate) fn no_network(self) -> bool {
        self.0.flags.no_network
    }

    /// Whether a connection is kept for another transfer once done
    /// (`PROTOPT_CONN_REUSE`).
    pub(crate) fn reuse(self) -> bool {
        self.0.flags.conn_reuse
    }

    /// Whether it sends datagrams of its own, over a UDP socket that
    /// connects to no peer: TFTP's (`TRNSPRT_UDP`, which `tftp_setup_connection`
    /// asks for, as C's scheme table has no transport).
    pub(crate) fn sends_datagrams(self) -> bool {
        self.0.protocol == Some(crate::url::schemes::Protocol::Tftp)
    }

    /// Whether its bytes are datagrams, which a proxy tunnels as CONNECT-UDP
    /// and not as a TCP stream: TFTP's (`PROTOPT_NOTCPPROXY`).
    pub(crate) fn no_tcp_proxy(self) -> bool {
        self.0.flags.no_tcp_proxy
    }

    /// Whether its library is handed the connection's socket, to read and
    /// write past every layer of ours: SCP's and SFTP's, which libssh
    /// speaks (`SSH_OPTIONS_FD`).
    pub(crate) fn hands_socket_over(self) -> bool {
        use crate::url::schemes::Protocol;
        matches!(self.0.protocol, Some(Protocol::Scp | Protocol::Sftp))
    }

    /// Whether a request of it may be handed whole to an HTTP proxy: one
    /// of HTTP's family, or one a proxy takes as HTTP, and not one that
    /// must tunnel (`Curl_proxy_init_conn`). The tests' own schemes are
    /// handed, as HTTP's are.
    pub(crate) fn proxies_as_http(self) -> bool {
        use crate::url::schemes::Protocol;
        let flags = self.0.flags;
        let http = match self.0.family {
            Some(Protocol::Http | Protocol::Ws) => true,
            Some(_) => false,
            None => self.0.protocol.is_none(),
        };
        !flags.http_proxy_tunnel && (http || flags.proxy_as_http)
    }

    /// Whether its user and password may hold control bytes
    /// (`PROTOPT_USERPWDCTRL`).
    pub(crate) fn takes_control_bytes(self) -> bool {
        self.0.flags.user_password_ctrl
    }

    /// Whether it is over TLS from the start (`PROTOPT_SSL`).
    pub(crate) fn over_tls(self) -> bool {
        self.0.flags.ssl
    }

    /// Whether, not over TLS itself, it may take a TLS connection of its
    /// family (`PROTOPT_SSL_REUSE`): the line protocols, which upgrade.
    pub(crate) fn reuses_tls(self) -> bool {
        self.0.flags.ssl_reuse
    }

    /// Whether its TLS offers ALPN (`PROTOPT_ALPN`): HTTPS's does, and
    /// the tests' own schemes', which stand in for it.
    pub(crate) fn offers_alpn(self) -> bool {
        self.0.protocol.is_none() || self.0.flags.alpn
    }

    /// Whether a connection logs in once, with the credentials of the
    /// transfer that made it, rather than per request
    /// (`PROTOPT_CREDSPERREQUEST` unset).
    pub(crate) fn logs_in_per_connection(self) -> bool {
        self.0.protocol.is_some() && !self.0.flags.creds_per_request
    }

    /// Whether a connection made for this scheme may serve a transfer of
    /// `wanted` (`url_match_destination`): the same scheme, or one whose
    /// protocol is this one's family, as an IMAPS connection serves IMAP
    /// and never the reverse. A scheme C does not know serves only
    /// itself.
    pub(crate) fn serves(self, wanted: Scheme) -> bool {
        self == wanted
            || self
                .0
                .family
                .is_some_and(|family| wanted.0.protocol == Some(family))
    }
}

/// The tests' scheme `tcp:`, which connects and completes.
#[cfg(any(test, feature = "test-util"))]
pub(crate) static TCP_SCHEME: Known = Known {
    name: "tcp",
    protocol: None,
    family: None,
    default_port: 0,
    flags: Flags {
        conn_reuse: true,
        ..Flags::NONE
    },
    built: false,
};

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
    /// The same scheme to the same destination (`Curl_peer_equal`).
    fn eq(&self, other: &Peer) -> bool {
        self.scheme == other.scheme && self.same_destination(other)
    }
}

impl Eq for Peer {}

impl Peer {
    /// Whether the two are one place, whatever their schemes
    /// (`Curl_peer_same_destination`).
    pub(crate) fn same_destination(&self, other: &Peer) -> bool {
        // Every field by name, so that one added does not compile until it
        // is compared here or said why not.
        let Peer {
            // The destination's alone; `eq` compares it.
            scheme: _,
            // Compared as its name, below.
            host: _,
            ascii: _,
            port,
            zone,
            scope,
            at,
        } = self;
        *port == other.port
            && *at == other.at
            && self.same_name(other)
            && *scope == other.scope
            && (*scope != 0 || *zone == other.zone)
    }

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
    Stream(Stream),
    /// A QUIC connection's socket, dialed straight to its peer.
    Datagram(Datagrams),
}

/// An established connection.
#[derive(Debug)]
pub(crate) struct Conn {
    number: ConnNumber,
    route: Route,
    /// How its first hop was dialed, recorded as it came up; a stream's
    /// for one without a network, which dials nothing.
    dial: Dial,
    transport: Transport,
    /// The address connected to; none without a network. Its end here
    /// is its socket's to say (`local`).
    remote: Option<io::Remote>,
    /// When its setup started (C's `conn->created`), and when it was
    /// found connected (TIMER_CONNECT's `connected_at`).
    created: Instant,
    connected_at: Instant,
    use_: Use,
    /// When it was last kept alive, or else used: whole milliseconds
    /// after it was made, as it was found connected, given back by a
    /// transfer or sent a keep-alive (C's `lastupkeep_ms`).
    upkept_ms: u64,
    /// It carried a request before the one leasing it (C's
    /// `bits.reuse`).
    served: bool,
    /// Its SOCKS5 proxy authenticated the user
    /// (`bits.socks5_authenticated`).
    socks5_authenticated: bool,
    /// The multi was told it multiplexes (`bits.multiplex`, set once by
    /// `Curl_conn_set_multiplex`).
    multiplex_told: bool,
    /// The version its last HTTP response said (`httpversion_seen`).
    seen_version: Option<ResponseVersion>,
    /// Its end here, as its socket said when first asked: a socket's
    /// address does not change once it is connected, and C keeps it from
    /// the connect rather than ask again on each reuse (`ip.local`).
    local: std::sync::OnceLock<Option<SocketAddr>>,
    /// It is not to be kept for another request (C's `connclose`), or
    /// its peer closed it, which no request can use again.
    close: bool,
    /// What it keeps of its creating transfer's settings.
    settings: shutdown::ConnSettings,
    /// HTTP Negotiate's context with the origin, and what the connection
    /// is bound to by it; made the first time a request negotiates.
    negotiate: Option<Box<crate::proto::http::negotiate::Negotiate>>,
    /// What it speaks: the session it multiplexes over, once its first
    /// request found a version that does agreed on (`cf-h2`), speaking
    /// nothing else from then on; or none, or not found yet, or its
    /// session out for a step.
    session: mux::Speaks,
}

/// A connection that speaks WebSocket, lent to a step: all it gives is
/// the WebSocket and what that works over, never the rest of the
/// connection (ENGINE.md decision 9's exception).
pub(crate) struct WsLend<'a>(&'a mut Conn);

impl WsLend<'_> {
    /// The WebSocket.
    pub(crate) fn ws(&self) -> &crate::proto::ws::WsConn {
        self.0.ws().expect("a lent connection speaks WebSocket")
    }

    /// The WebSocket, and what it works over.
    pub(crate) fn parts(&mut self) -> (&mut crate::proto::ws::WsConn, mux::Carrier<'_>) {
        self.0.ws_mut().expect("a lent connection speaks WebSocket")
    }
}

impl Conn {
    /// Who its requests are for; none without a network.
    pub(crate) fn origin(&self) -> Option<&TryArc<Peer>> {
        match &self.route {
            Route::Net(tcp) => Some(&tcp.origin),
            Route::Local => None,
        }
    }

    /// Its number among those the pool made (`connection_id`).
    pub(crate) fn number(&self) -> ConnNumber {
        self.number
    }

    /// The address connected to; none without a network.
    pub(crate) fn remote(&self) -> Option<&io::Remote> {
        self.remote.as_ref()
    }

    /// Its stream and the address it reached, for a connection made as a
    /// protocol's second, which no pool holds (FTP's data connection,
    /// `SECONDARYSOCKET`): nothing else of it needs closing.
    pub(crate) fn into_stream(self) -> (Stream, Option<io::Remote>) {
        let Transport::Stream(stream) = self.transport else {
            panic!("a second connection is a stream");
        };
        assert!(
            matches!(self.session, mux::Speaks::Unmade),
            "a second connection speaks nothing of its own"
        );
        (stream, self.remote)
    }

    /// The route it was set up over; none without a network.
    pub(crate) fn tcp_route(&self) -> Option<&NetRoute> {
        match &self.route {
            Route::Net(tcp) => Some(tcp),
            Route::Local => None,
        }
    }

    /// Its route as it was dialed; none without a network.
    pub(crate) fn dialing(&self) -> Option<Dialing<'_>> {
        let route = self.tcp_route()?;
        Some(Dialing {
            route,
            dial: self.dial,
        })
    }

    /// Whether it multiplexes: a session speaks for it
    /// (`Curl_conn_is_multiplex`). One taken out for a step does not.
    pub(crate) fn multiplexes(&self) -> bool {
        self.session.session().is_some()
    }

    /// It multiplexes, and the multi is to be told so, which is once
    /// (`Curl_conn_set_multiplex`).
    pub(crate) fn tell_multiplex(&mut self) -> bool {
        self.multiplexes() && !std::mem::replace(&mut self.multiplex_told, true)
    }

    /// The session it multiplexes over, if it does.
    pub(crate) fn session(&self) -> Option<&mux::Session> {
        self.session.session()
    }

    /// Its HTTP/2 session, if it speaks HTTP/2.
    pub(crate) fn h2(&self) -> Option<&crate::proto::http2::H2Conn> {
        match self.session.session()? {
            mux::Session::H2(h2) => Some(&**h2),
            mux::Session::H3(_) => None,
        }
    }

    /// Its HTTP/3 session, if it speaks HTTP/3.
    pub(crate) fn h3(&self) -> Option<&crate::proto::http3::H3Conn> {
        match self.session.session()? {
            mux::Session::H3(h3) => Some(&**h3),
            mux::Session::H2(_) => None,
        }
    }

    /// Its HTTP/2 session, taken out for a step to drive beside the
    /// connection, which gives it back after (`give_back_h2`).
    pub(crate) fn take_h2(&mut self) -> Option<Box<crate::proto::http2::H2Conn>> {
        let mux::Speaks::Made(mux::Session::H2(_)) = &self.session else {
            return None;
        };
        let out = mux::Speaks::Out(mux::SessionVersion::H2);
        match std::mem::replace(&mut self.session, out) {
            mux::Speaks::Made(mux::Session::H2(h2)) => Some(h2),
            _ => unreachable!("an HTTP/2 session, matched above"),
        }
    }

    /// Its HTTP/3 session, taken out for a step to drive beside the
    /// connection, which gives it back after (`give_back_h3`).
    pub(crate) fn take_h3(&mut self) -> Option<Box<crate::proto::http3::H3Conn>> {
        let mux::Speaks::Made(mux::Session::H3(_)) = &self.session else {
            return None;
        };
        let out = mux::Speaks::Out(mux::SessionVersion::H3);
        match std::mem::replace(&mut self.session, out) {
            mux::Speaks::Made(mux::Session::H3(h3)) => Some(h3),
            _ => unreachable!("an HTTP/3 session, matched above"),
        }
    }

    /// Its HTTP/2 session, taken out for a step, given back.
    pub(crate) fn give_back_h2(&mut self, h2: Box<crate::proto::http2::H2Conn>) {
        assert!(
            matches!(self.session, mux::Speaks::Out(mux::SessionVersion::H2)),
            "an HTTP/2 session is given back where it was taken out"
        );
        self.session = mux::Speaks::Made(mux::Session::H2(h2));
    }

    /// Its HTTP/3 session, taken out for a step, given back.
    pub(crate) fn give_back_h3(&mut self, h3: Box<crate::proto::http3::H3Conn>) {
        assert!(
            matches!(self.session, mux::Speaks::Out(mux::SessionVersion::H3)),
            "an HTTP/3 session is given back where it was taken out"
        );
        self.session = mux::Speaks::Made(mux::Session::H3(h3));
    }

    /// Its first request found it speaks HTTP/1: no session
    /// (`http_check_new_conn`).
    pub(crate) fn speaks_http1(&mut self) {
        assert!(
            matches!(self.session, mux::Speaks::Unmade | mux::Speaks::Http1),
            "a connection with a session speaks it"
        );
        self.session = mux::Speaks::Http1;
    }

    /// Its own datagram socket, which a QUIC connection dialed to its
    /// peer sends on; none for one over a stream, which a QUIC
    /// connection layered over a tunnel sends through.
    pub(crate) fn datagram_socket(&self) -> Option<&dyn io::Socket> {
        match &self.transport {
            Transport::Datagram(datagrams) => Some(datagrams.socket()),
            Transport::Stream(_) | Transport::Local => None,
        }
    }

    /// Whether its connect bound the socket to an address or a port
    /// (`bits.bound`).
    pub(crate) fn bound_local(&self) -> bool {
        self.settings.bound_local()
    }

    /// The socket under it, whatever goes over that; none without a
    /// network.
    pub(crate) fn socket(&self) -> Option<&dyn io::Socket> {
        match &self.transport {
            Transport::Datagram(datagrams) => Some(datagrams.socket()),
            Transport::Stream(stream) => Some(stream.socket()),
            Transport::Local => None,
        }
    }

    /// Put its HTTP/3 session on it, as its QUIC handshake is done.
    pub(crate) fn put_h3(&mut self, h3: Box<crate::proto::http3::H3Conn>) {
        assert!(
            matches!(self.session, mux::Speaks::Unmade),
            "one session per connection"
        );
        self.session = mux::Speaks::Made(mux::Session::H3(h3));
    }

    /// Put a new HTTP/2 session on it: as its first request finds it
    /// speaks HTTP/2, or as a response upgrades it from HTTP/1.
    pub(crate) fn put_h2(&mut self, h2: Box<crate::proto::http2::H2Conn>) {
        assert!(
            matches!(self.session, mux::Speaks::Unmade | mux::Speaks::Http1),
            "one session per connection"
        );
        self.session = mux::Speaks::Made(mux::Session::H2(h2));
    }

    /// What its session works over: its stream. A connection without a
    /// network has none.
    pub(crate) fn carrier(&mut self) -> mux::Carrier<'_> {
        self.split().1.expect("a local connection moves no bytes")
    }

    /// What it speaks, and what that works over, borrowed apart.
    fn speaks_over(&mut self) -> (&mut mux::Speaks, Option<mux::Carrier<'_>>) {
        let socket = self.socket_component();
        let Conn {
            transport,
            close,
            session,
            ..
        } = self;
        let carrier = match transport {
            Transport::Stream(stream) => Some(mux::Carrier {
                over: mux::Over::Stream(stream),
                socket,
                close,
            }),
            Transport::Datagram(datagrams) => Some(mux::Carrier {
                over: mux::Over::Datagrams(datagrams),
                socket,
                close,
            }),
            Transport::Local => None,
        };
        (session, carrier)
    }

    /// Its session, if any, and what it works over.
    fn split(&mut self) -> (Option<&mut mux::Session>, Option<mux::Carrier<'_>>) {
        let (speaks, carrier) = self.speaks_over();
        (speaks.session_mut(), carrier)
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

    /// Its protocol's goodbye, once as it shuts down, before its session
    /// and layers say theirs (`cshutdn_run_conn_handler`); `dead` if no
    /// one knows what state it is in. Said on `trace` as C's debug build
    /// says it, for a protocol that has one. `Waiting` if it awaits an
    /// answer, which [`goodbye_answer`](Self::goodbye_answer) reads on.
    pub(crate) fn protocol_goodbye(
        &mut self,
        cx: &mut dyn LayerCx,
        trace: Option<&crate::trace::Internal>,
        dead: bool,
    ) -> layer::Handshake {
        let n = self.number.get();
        let (mux::Speaks::Line(line), Some(carrier)) = self.speaks_over() else {
            return layer::Handshake::Done;
        };
        if cfg!(feature = "debug-hooks")
            && line.says_goodbye()
            && let Some(t) = trace
        {
            t.info(format_args!(
                "connection #{n}, shutdown protocol handler (aborted={})",
                u8::from(dead)
            ));
        }
        line.goodbye(cx, carrier, dead)
    }

    /// Read on the answer its protocol's goodbye awaits: `Done` once it
    /// came, or the connection failed or closed.
    pub(crate) fn goodbye_answer(&mut self, cx: &mut dyn LayerCx) -> layer::Handshake {
        let (mux::Speaks::Line(line), Some(carrier)) = self.speaks_over() else {
            panic!("a goodbye awaits an answer on a connection that said none");
        };
        line.goodbye_answer(cx, carrier)
    }

    /// A protocol keeps its state on it.
    pub(crate) fn keeps_line(&self) -> bool {
        matches!(self.session, mux::Speaks::Line(_))
    }

    /// The state its protocol keeps on it, if one does.
    pub(crate) fn line(&self) -> Option<&line::LineConn> {
        match &self.session {
            mux::Speaks::Line(line) => Some(line),
            _ => None,
        }
    }

    /// The state its protocol keeps on it, if one does, and what that
    /// works over, borrowed apart for a step to drive both.
    pub(crate) fn line_mut(&mut self) -> Option<(&mut line::LineConn, mux::Carrier<'_>)> {
        match self.speaks_over() {
            (mux::Speaks::Line(line), Some(carrier)) => Some((&mut **line, carrier)),
            _ => None,
        }
    }

    /// The protocol `line` keeps its state on it, as its first request
    /// connects.
    pub(crate) fn put_line(&mut self, line: Box<line::LineConn>) {
        assert!(
            matches!(self.session, mux::Speaks::Unmade),
            "one protocol's state per connection"
        );
        self.session = mux::Speaks::Line(line);
    }

    /// It speaks WebSocket from here, its HTTP/1.1 request upgraded by a
    /// 101 (`Curl_ws_accept`).
    pub(crate) fn switch_to_ws(&mut self, ws: Box<line::LineConn>) {
        assert!(
            matches!(self.session, mux::Speaks::Unmade | mux::Speaks::Http1),
            "a WebSocket upgrades an HTTP/1.1 connection"
        );
        assert!(
            matches!(*ws, line::LineConn::Ws(_)),
            "switched to a WebSocket"
        );
        self.session = mux::Speaks::Line(ws);
    }

    /// Its WebSocket, if it switched to one, and what that works over,
    /// borrowed apart.
    pub(crate) fn ws_mut(&mut self) -> Option<(&mut crate::proto::ws::WsConn, mux::Carrier<'_>)> {
        match self.line_mut() {
            Some((line::LineConn::Ws(ws), carrier)) => Some((&mut **ws, carrier)),
            _ => None,
        }
    }

    /// What RTSP keeps on it, if it is RTSP's.
    pub(crate) fn rtsp_mut(&mut self) -> Option<&mut crate::proto::http::rtsp::RtspConn> {
        match &mut self.session {
            mux::Speaks::Line(line) => match &mut **line {
                line::LineConn::Rtsp(rtsp) => Some(rtsp),
                _ => None,
            },
            _ => None,
        }
    }

    /// Whether it is RTSP's, which may have input waiting while idle: a
    /// server's RTP between requests (`rtsp_conn_is_dead`).
    pub(crate) fn speaks_rtsp(&self) -> bool {
        matches!(&self.session, mux::Speaks::Line(line) if matches!(**line, line::LineConn::Rtsp(_)))
    }

    /// Its WebSocket, if it switched to one.
    pub(crate) fn ws(&self) -> Option<&crate::proto::ws::WsConn> {
        match &self.session {
            mux::Speaks::Line(line) => match &**line {
                line::LineConn::Ws(ws) => Some(ws),
                _ => None,
            },
            _ => None,
        }
    }

    /// It, lent to a step for its handlers' WebSocket calls, if it
    /// switched to a WebSocket.
    pub(crate) fn ws_lend(&mut self) -> Option<WsLend<'_>> {
        self.ws()?;
        Some(WsLend(self))
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

    /// Keep it alive, if `interval` has passed by `now` since it last was
    /// or was used, in whole milliseconds since it was made
    /// (`conn_upkeep`): its session sends what keeps it so, and its
    /// layers have nothing to (`Curl_conn_keep_alive`). Whether it was
    /// due, and if so how the keep-alive went.
    pub(crate) fn upkeep(
        &mut self,
        cx: &mut dyn LayerCx,
        interval: std::time::Duration,
    ) -> Option<Result<(), crate::error::ErrorKind>> {
        let now = cx.now();
        self.upkeep_at(cx, interval, now)
    }

    /// As `upkeep`, asked at `at` and judged due then: what a share's pool
    /// asked of the multi the connection is lent to, done as the multi
    /// gets to it.
    pub(crate) fn upkeep_at(
        &mut self,
        cx: &mut dyn LayerCx,
        interval: std::time::Duration,
        at: Instant,
    ) -> Option<Result<(), crate::error::ErrorKind>> {
        use part::Part as _;
        let made_ms = u64::try_from(at.since(self.created).as_millis()).unwrap_or(u64::MAX);
        let interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        if made_ms.saturating_sub(self.upkept_ms) < interval_ms {
            return None;
        }
        self.upkept_ms = made_ms;
        Some(match self.split() {
            (Some(session), Some(carrier)) => session.keep_alive(cx, carrier),
            (None, _) | (_, None) => Ok(()),
        })
    }

    /// It was given back by a transfer at `now` (`Curl_cpool_return`):
    /// its next keep-alive is due an interval from then.
    pub(crate) fn returned(&mut self, now: Instant) {
        self.upkept_ms = u64::try_from(now.since(self.created).as_millis()).unwrap_or(u64::MAX);
    }

    /// The filter at the top of its chain once it is up, which a question
    /// of it is asked of first (`conn->cfilter[FIRSTSOCKET]`).
    pub(crate) fn top(&self) -> crate::components::Component {
        // An HTTP/2 session's filter goes on top (`Curl_http2_switch_at`,
        // `Curl_http2_switch`).
        if self.h2().is_some() {
            return crate::components::Component::Http2;
        }
        self.chain().map_or(crate::components::Component::Tcp, |c| {
            c.top().expect("a connection has a socket")
        })
    }

    /// Its chain of filters once it is up, its setup's gone
    /// (`Curl_conn_remove_setup_filters`), as its route made it; none for
    /// a local one.
    pub(crate) fn chain(&self) -> Option<chain::Chain> {
        self.connected_chain().map(|connected| connected.reduced())
    }

    /// Its chain of filters as it connected, its setup's still there;
    /// none for a local one.
    pub(crate) fn connected_chain(&self) -> Option<chain::Chain> {
        let Route::Net(route) = &self.route else {
            return None;
        };
        let tunnel = match &self.transport {
            Transport::Stream(stream) => stream.query(layer::LayerQuery::Tunnel),
            Transport::Datagram(_) | Transport::Local => None,
        };
        let tunnel = match tunnel {
            Some(layer::LayerAnswer::Tunnel(filter)) => filter,
            _ => crate::components::Component::H1Proxy,
        };
        Some(chain::Chain::connected(
            Dialing {
                route,
                dial: self.dial,
            },
            chain::Head::default(),
            false,
            tunnel,
        ))
    }

    /// What its socket's filter traces as (`TCP`, `UNIX`).
    pub(crate) fn socket_component(&self) -> crate::components::Component {
        match &self.route {
            Route::Net(route) => Dialing {
                route,
                dial: self.dial,
            }
            .socket_component(),
            Route::Local => crate::components::Component::Tcp,
        }
    }

    fn stream(&mut self) -> &mut Stream {
        match &mut self.transport {
            Transport::Stream(stream) => stream,
            Transport::Datagram(_) => unreachable!("a QUIC connection's bytes are its own"),
            Transport::Local => unreachable!("a local connection moves no bytes"),
        }
    }

    /// The proxy requests go to whole over it, if they do
    /// (`origin_is_proxy`).
    pub(crate) fn forwarding(&self) -> Option<&ProxyRoute> {
        match &self.route {
            Route::Net(NetRoute { proxy: Some(p), .. }) if p.forward => Some(p),
            _ => None,
        }
    }

    /// Whether it goes through an HTTP proxy's tunnel.
    pub(crate) fn tunnels(&self) -> bool {
        matches!(&self.route, Route::Net(NetRoute { proxy: Some(p), .. }) if p.tunnels())
    }

    /// Whether any of it is TLS now, the origin's or an HTTPS proxy's,
    /// as its layers say: one upgraded to TLS is.
    pub(crate) fn over_tls(&self) -> bool {
        match &self.transport {
            Transport::Stream(stream) => {
                stream.query(layer::LayerQuery::TlsWaits).is_some()
                    || stream.query(layer::LayerQuery::ProxyTlsWaits).is_some()
            }
            // QUIC is always under TLS.
            Transport::Datagram(_) => true,
            Transport::Local => false,
        }
    }

    /// Whether the origin's bytes go through TLS now, as its layers say,
    /// a proxy's tunnel's TLS not counted (`Curl_conn_is_ssl`, which
    /// stops at the tunnel).
    pub(crate) fn origin_tls(&self) -> bool {
        match &self.transport {
            Transport::Stream(stream) => stream.query(layer::LayerQuery::TlsWaits).is_some(),
            Transport::Datagram(_) => true,
            Transport::Local => false,
        }
    }

    /// The route it was made for.
    pub(crate) fn net_route(&self) -> Option<&NetRoute> {
        match &self.route {
            Route::Net(t) => Some(t),
            Route::Local => None,
        }
    }

    /// Whether it goes through an HTTP proxy (`http_proxy.peer`).
    pub(crate) fn http_proxy(&self) -> bool {
        matches!(&self.route, Route::Net(NetRoute { proxy: Some(p), .. }) if p.http())
    }

    /// Whether it may serve a transfer whose route is `wanted`: a route
    /// that serves it, and the user authenticated by a SOCKS5 proxy if
    /// the transfer insists (`url_match_proxy_use`).
    pub(crate) fn serves(&self, wanted: &Route) -> bool {
        let insists = match wanted {
            Route::Net(tcp @ NetRoute { proxy: Some(p), .. }) => {
                p.auth_only
                    && tcp.socks().is_some_and(|s| {
                        matches!(s.version, socks::Version::V5 | socks::Version::V5Hostname)
                    })
            }
            Route::Net(_) | Route::Local => false,
        };
        self.route.serves(wanted)
            && (!insists || self.socks5_authenticated)
            && self.tls_serves(wanted)
    }

    /// Whether, as its layers are now, it serves a transfer of a scheme
    /// that may upgrade to TLS (`url_match_ssl_use`): one upgraded is
    /// reused with the settings it was upgraded with; one not is not
    /// reused by a transfer that requires TLS.
    fn tls_serves(&self, wanted: &Route) -> bool {
        let (Route::Net(have), Route::Net(want)) = (&self.route, wanted) else {
            return true;
        };
        if want.tls.is_some() || have.tls.is_some() || !want.origin.scheme().reuses_tls() {
            // Over TLS from the start, or never upgraded: the route's to
            // say.
            return true;
        }
        if self.origin_tls() {
            want.origin.scheme().reuses_tls() && have.upgrade() == want.upgrade()
        } else {
            !want.use_ssl().requires()
        }
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
        // QUIC's TLS is its own, with no binding to give.
        let stream = match &self.transport {
            Transport::Stream(stream) => Some(stream),
            Transport::Datagram(_) | Transport::Local => None,
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
        use crate::auth::http::Side;
        use crate::proto::http::negotiate::State;
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
        // A connection of a scheme of datagrams is not asked, even as it
        // goes over a stream to a proxy (`set_local_ip`).
        if matches!(&self.route, Route::Net(net) if net.origin.scheme().no_tcp_proxy()) {
            return None;
        }
        *self.local.get_or_init(|| match &self.transport {
            Transport::Stream(stream) => stream.local_addr(),
            Transport::Datagram(datagrams) => datagrams.local_addr(),
            Transport::Local => None,
        })
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
    /// a read that would block is to be tried again at once: asked of its
    /// session first, then what it works over, as C asks its filters from
    /// the top (`Curl_conn_data_pending`).
    pub(crate) fn data_pending(&mut self) -> bool {
        use crate::conn::part::{Lower, Part};
        match self.split() {
            (Some(session), Some(carrier)) => session.data_pending(carrier),
            (None, Some(carrier)) => carrier.data_pending(),
            (_, None) => false,
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

    const HTTP: Scheme = Scheme::HTTP;

    fn peer(host: &[u8], port: u16, zone: Option<&[u8]>) -> Peer {
        Peer::new(HTTP, host.to_vec(), port, zone.map(<[u8]>::to_vec))
    }

    /// What each scheme's flags in C's table say of it: control bytes in
    /// its credentials, TLS from the start, a TLS connection reused, ALPN
    /// offered, a login per connection, a request handed whole to an HTTP
    /// proxy.
    #[test]
    fn schemes_say_what_c_s_flags_say() {
        let says = |name: &[u8]| {
            let s = Scheme::named(name).unwrap();
            [
                s.takes_control_bytes(),
                s.over_tls(),
                s.reuses_tls(),
                s.offers_alpn(),
                s.logs_in_per_connection(),
                s.proxies_as_http(),
            ]
        };
        let (t, f) = (true, false);
        assert_eq!(says(b"http"), [t, f, f, f, f, t]);
        assert_eq!(says(b"https"), [t, t, f, t, f, f]);
        assert_eq!(says(b"ws"), [t, f, f, f, f, f]);
        assert_eq!(says(b"pop3"), [f, f, t, f, t, f]);
        assert_eq!(says(b"pop3s"), [f, t, f, f, t, f]);
        assert_eq!(says(b"ftp"), [f, f, t, f, t, t]);
        assert_eq!(says(b"gopher"), [f, f, f, f, t, f]);
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
            Route::Net(NetRoute {
                origin: TryArc::try_new(peer(b"o.example", 80, None)).unwrap(),
                via: Some(TryArc::try_new(unix(path, false)).unwrap()),
                ip: IpVersion::Any,
                proxy: None,
                tls: None,
                cold: None,
                delegation: Default::default(),
            })
        };
        assert!(over(b"/tmp/s").serves(&over(b"/tmp/s")));
        assert!(!over(b"/tmp/s").serves(&over(b"/tmp/t")));
    }

    /// A route dialed over QUIC has its socket's lines traced as C's UDP
    /// filter's, over TCP as its TCP filter's; a connection serves a
    /// transfer whichever way either dials, as the route holds no dial
    /// and C compares no transport (`url_match_http_version` weighs the
    /// version apart).
    #[test]
    fn a_route_s_socket_is_traced_as_its_attempt_dials() {
        let route = NetRoute {
            origin: TryArc::try_new(peer(b"o.example", 443, None)).unwrap(),
            via: None,
            ip: IpVersion::Any,
            proxy: None,
            tls: None,
            cold: None,
            delegation: Default::default(),
        };
        let dialed = |dial| {
            Dialing {
                route: &route,
                dial,
            }
            .socket_component()
        };
        assert_eq!(dialed(Dial::Quic), crate::components::Component::Udp);
        assert_eq!(dialed(Dial::Stream), crate::components::Component::Tcp);
    }

    /// Peers are the same as `Curl_peer_equal` finds them: the host in
    /// any case, the port, the scheme, and the zone by its scope, a
    /// number or an interface's index, or else by name.
    /// The zone names Linux's loopback, which Windows names otherwise.
    #[cfg(unix)]
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
        let other = Scheme::own(&crate::conn::TCP_SCHEME);
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
        let lo = curl_os::net::interface_index(crate::LOOPBACK.as_bytes()).expect("a loopback");
        let index = lo.to_string();
        assert_eq!(
            v6(Some(crate::LOOPBACK.as_bytes())),
            v6(Some(index.as_bytes()))
        );
        assert_eq!(v6(Some(crate::LOOPBACK.as_bytes())).scope(), Some(lo));
        assert_eq!(v6(Some(b"nosuch0")).scope(), None);
        // The application's scope, in place of a zone, is a number's.
        let scoped = Peer::scoped(HTTP, b"[fe80::1]".to_vec(), 80, lo);
        assert_eq!(scoped, v6(Some(crate::LOOPBACK.as_bytes())));
        assert_eq!(v6(None).name(), b"fe80::1");
        assert_eq!(v6(None).shown(), b"[fe80::1]");
        assert!(v6(None).ipv6() && !peer(b"fe80", 80, None).ipv6());
    }

    /// A proxy is the same destination as another by its name in any
    /// case, its port, and its zone by number however spelt, or by name
    /// when it has none (`Curl_peer_same_destination`).
    /// The zone names Linux's loopback, which Windows names otherwise.
    #[cfg(unix)]
    #[test]
    fn proxies_compare_as_destinations() {
        let same = |a: &Peer, b: &Peer| Destination(a) == Destination(b);
        let v6 = |zone| peer(b"[fe80::1]", 80, zone);
        assert!(same(&v6(Some(b"2")), &v6(Some(b"02"))));
        assert!(!same(&v6(Some(b"2")), &v6(Some(b"3"))));
        assert!(same(&v6(Some(b"nosuch0")), &v6(Some(b"nosuch0"))));
        assert!(!same(&v6(Some(b"nosuch0")), &v6(Some(b"nosuch1"))));
        let lo = curl_os::net::interface_index(crate::LOOPBACK.as_bytes()).expect("a loopback");
        assert!(same(
            &v6(Some(crate::LOOPBACK.as_bytes())),
            &v6(Some(lo.to_string().as_bytes()))
        ));
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
            Route::Net(NetRoute {
                origin: arc(origin),
                via: via.map(arc),
                ip,
                proxy: proxy
                    .map(|host| ProxyRoute::new(ProxyType::Socks5, arc(host), None, false, false)),
                tls: None,
                cold: None,
                delegation: Default::default(),
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

    /// A connection reaches a transfer of another scheme only if its own
    /// scheme's family is the transfer's protocol, through a detour to
    /// the same place whatever its scheme (`url_match_destination`): an
    /// HTTPS or IMAPS one reaches HTTP or IMAP, never the reverse, nor
    /// another family. HTTP's then takes no TLS connection, its TLS
    /// settings being none.
    #[test]
    fn a_connection_reaches_transfers_of_its_family() {
        let route = |scheme: &str, via: bool| {
            let scheme = Scheme::of(scheme);
            let arc = |host: &[u8]| TryArc::try_new(Peer::new(scheme, host.to_vec(), 80, None));
            Route::Net(NetRoute {
                origin: arc(b"o.example").unwrap(),
                via: via.then(|| arc(b"v.example").unwrap()),
                ip: IpVersion::Any,
                proxy: None,
                tls: None,
                cold: None,
                delegation: Default::default(),
            })
        };
        for via in [false, true] {
            for (have, want, reaches) in [
                ("https", "http", true),
                ("http", "https", false),
                ("imaps", "imap", true),
                ("imap", "imaps", false),
                ("https", "imap", false),
                ("imaps", "http", false),
                ("ftps", "ftp", true),
            ] {
                assert_eq!(
                    route(have, via).reaches(&route(want, via)),
                    reaches,
                    "{have} for {want}, via {via}"
                );
            }
        }
        let mut https = route("https", false);
        let Route::Net(r) = &mut https else {
            unreachable!()
        };
        r.tls = Some(
            crate::tls::TlsIdentity::of(&Default::default(), crate::tls::CaDefaults::NONE).unwrap(),
        );
        assert!(!https.serves(&route("http", false)), "TLS for none");
    }

    /// A connection made with TLS serves only a transfer whose TLS has
    /// every setting its handshake had, and one without TLS only one
    /// without (`url_match_ssl_use`, `url_match_ssl_config`): a transfer
    /// that verifies its peer never takes a connection that did not, nor
    /// the other way round (the CVE-2021-22924 class).
    /// An FTP connection serves only a transfer that would set it up the
    /// same way: the same account, alternative to `USER` and CCC, and TLS
    /// asked for alike, a transfer that only tries TLS taking one that
    /// asked for any (`Curl_ftp_conns_match`); one of another scheme's
    /// setup is not compared. A transfer that does not ask for TLS takes a
    /// connection whatever TLS it would have upgraded to
    /// (`url_match_ssl_config` without `may_tls`).
    #[test]
    fn ftp_connections_serve_transfers_set_up_alike() {
        use crate::options::{Ccc, Tls, UseSsl};
        use crate::tls::TlsIdentity;
        let route = |ftp: Option<FtpSetup>, use_ssl, upgrade: Option<&Tls>| {
            Route::Net(NetRoute {
                origin: TryArc::try_new(Peer::new(
                    Scheme::of("ftp"),
                    b"f.example".to_vec(),
                    21,
                    None,
                ))
                .unwrap(),
                via: None,
                ip: IpVersion::Any,
                proxy: None,
                tls: None,
                cold: Some(
                    TryArc::try_new(RouteCold {
                        local: crate::options::LocalBind::NONE,
                        login: None,
                        upgrade: upgrade
                            .map(|t| TlsIdentity::of(t, crate::tls::CaDefaults::NONE).unwrap()),
                        use_ssl,
                        ftp,
                        ssh: None,
                    })
                    .unwrap(),
                ),
                delegation: Default::default(),
            })
        };
        let setup = |account: Option<&[u8]>, alternative: Option<&[u8]>, ccc| FtpSetup {
            account: account.map(<[u8]>::to_vec),
            alternative_to_user: alternative.map(<[u8]>::to_vec),
            ccc,
        };
        let plain = || setup(None, None, Ccc::None);
        let ftp = |s: FtpSetup, use_ssl| route(Some(s), use_ssl, None);
        let have = ftp(plain(), UseSsl::None);
        assert!(have.serves(&ftp(plain(), UseSsl::None)));
        assert!(!have.serves(&ftp(setup(Some(b"a"), None, Ccc::None), UseSsl::None)));
        assert!(!have.serves(&ftp(setup(None, Some(b"alt"), Ccc::None), UseSsl::None)));
        assert!(!have.serves(&ftp(setup(None, None, Ccc::Passive), UseSsl::None)));
        // TLS asked for alike, or only tried over a connection that asked.
        let all = ftp(plain(), UseSsl::All);
        assert!(all.serves(&ftp(plain(), UseSsl::Try)));
        assert!(all.serves(&ftp(plain(), UseSsl::All)));
        assert!(!all.serves(&ftp(plain(), UseSsl::Control)));
        assert!(!have.serves(&ftp(plain(), UseSsl::Try)));
        assert!(!ftp(plain(), UseSsl::Try).serves(&all));
        // Without an FTP setup on either side, none is compared.
        assert!(route(None, UseSsl::None, None).serves(&have));
        assert!(have.serves(&route(None, UseSsl::None, None)));
        // A connection that would have upgraded serves a transfer that
        // asks for no TLS.
        let upgrading = route(Some(plain()), UseSsl::None, Some(&Tls::default()));
        assert!(upgrading.serves(&have));
    }

    #[test]
    fn routes_compare_their_tls() {
        use crate::options::Tls;
        use crate::tls::TlsIdentity;
        let secured = |tls: Option<&Tls>| {
            Route::Net(NetRoute {
                origin: TryArc::try_new(peer(b"o.example", 443, None)).unwrap(),
                via: None,
                ip: IpVersion::Any,
                proxy: None,
                tls: tls.map(|t| TlsIdentity::of(t, crate::tls::CaDefaults::NONE).unwrap()),
                cold: None,
                delegation: Default::default(),
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
        blob.options.make_mut().unwrap().ca_blob =
            crate::options::CaSetting::Given(b"pem".to_vec());
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
        Route::Net(NetRoute {
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
            cold: None,
            delegation: Default::default(),
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
            Route::Net(NetRoute {
                origin: TryArc::try_new(peer(b"o.example", 80, None)).unwrap(),
                via: None,
                ip: IpVersion::Any,
                proxy: None,
                tls: None,
                cold: local.binds().then(|| {
                    TryArc::try_new(RouteCold {
                        local,
                        login: None,
                        upgrade: None,
                        use_ssl: crate::options::UseSsl::None,
                        ftp: None,
                        ssh: None,
                    })
                    .unwrap()
                }),
                delegation: Default::default(),
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
        let direct = Route::Net(NetRoute {
            origin: TryArc::try_new(peer(b"proxy.example", 3128, None)).unwrap(),
            via: None,
            ip: IpVersion::Any,
            proxy: None,
            tls: None,
            cold: None,
            delegation: Default::default(),
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
            Route::Net(mut tcp) => {
                let p = tcp.proxy.as_mut().unwrap();
                p.creds = Some(
                    TryArc::try_new(ProxyCreds {
                        user: b"u".to_vec(),
                        password: Vec::new(),
                        service: service.to_vec(),
                    })
                    .unwrap(),
                );
                Route::Net(tcp)
            }
            Route::Local => unreachable!(),
        };
        assert!(serving_as(b"").serves(&user) && user.serves(&serving_as(b"")));
        assert!(!serving_as(b"pxy").serves(&user) && !user.serves(&serving_as(b"pxy")));
        assert!(serving_as(b"pxy").serves(&serving_as(b"pxy")));
        // Behind the same SOCKS proxy, or none, as C compares
        // `socks_proxy` beside `http_proxy`.
        let behind = |kind, host: &[u8]| match via_proxy(b"proxy.example", None, true) {
            Route::Net(mut tcp) => {
                let pre = PreProxy {
                    kind,
                    peer: TryArc::try_new(peer(host, 1080, None)).unwrap(),
                    creds: None,
                };
                tcp.proxy = tcp.proxy.map(|p| p.behind(pre).unwrap());
                Route::Net(tcp)
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
