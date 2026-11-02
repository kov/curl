//! C's filter chain for a connection being set up, rendered for the trace
//! (`Curl_conn_trc_filters`). The typed connect machine stands for C's
//! setup filters (SETUP, DNS, HAPPY-EYEBALLS, HTTP-PROXY, HAPROXY), which
//! exist in C only until the chain connects; this says which filters C's
//! chain would hold at a point of the setup, top first, and which of them
//! are connected, from how far the machine got and the handshake under
//! way. It allocates nothing.

use std::fmt;

use super::connect::{Made, Tunneled};
use super::{Dialing, NetRoute};
use crate::components::Component;
use crate::multi::state::ConnRank;

/// How far a setup got, as the chain shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupPoint {
    /// Its first hop's name is being resolved.
    Resolving,
    /// Attempts are made to the first hop, once the race `started`: it has
    /// run, with an address to try or none yet.
    Racing { started: bool },
    /// Connected to the first hop, the handshakes in `made` made over it.
    Dialed(Made),
}

/// What heads a setup's chain above its SETUP filter: the HTTPS connect
/// filter, for an `https` origin no proxy forwards to with ALPN on
/// (`Curl_cf_https_setup`), and above the name's DNS filter the one that
/// asks for the origin's HTTPS record, unless the origin is an address.
/// Below the HTTPS connect filter, once its winner agreed on HTTP/2, the
/// HTTP/2 filter it inserts (`baller_connected`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Head {
    pub(crate) https: bool,
    pub(crate) record: bool,
    pub(crate) h2: bool,
}

/// The most filters a chain holds: three DNS, HTTPS-CONNECT, HTTP/2,
/// SETUP, SSL, HAPROXY, HTTP-PROXY, H1-PROXY, SSL-PROXY, SOCKS,
/// HAPPY-EYEBALLS and TCP.
const MOST: usize = 14;

/// A chain of filters, top first, each connected or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Chain {
    filters: [(Component, bool); MOST],
    len: usize,
    /// The connection's chain it is, which its rendering opens with.
    rank: ConnRank,
}

impl Chain {
    fn new() -> Chain {
        Chain {
            filters: [(Component::Tcp, false); MOST],
            len: 0,
            rank: ConnRank::First,
        }
    }

    /// The same chain, as the connection's `rank` one
    /// (`conn->cfilter[sockindex]`).
    pub(crate) fn on(mut self, rank: ConnRank) -> Chain {
        self.rank = rank;
        self
    }

    fn push(&mut self, filter: Component, connected: bool) {
        self.filters[self.len] = (filter, connected);
        self.len += 1;
    }

    /// The chain of a setup over `route` that got as far as `reached`,
    /// with the handshake `under_way` started over the first hop: the
    /// SOCKS, HTTP-PROXY or HAPROXY filter, added but not connected. A
    /// handshake's filter is there once it is under way or made. The
    /// HTTP proxy's tunnel shows its H1-PROXY filter once `installed`, as
    /// C installs it in the tunnel filter's first connect, or H2-PROXY for
    /// a tunnel that is a stream of an HTTP/2 session. An HTTPS
    /// proxy's TLS under way below a tunnel has the tunnel's filter added
    /// with it, as C adds both at once (`cf_setup_add_http_proxy`), its
    /// H1-PROXY not yet installed.
    pub(crate) fn of(
        route: Dialing<'_>,
        head: Head,
        reached: SetupPoint,
        under_way: Option<Component>,
        installed: bool,
    ) -> Chain {
        let mut chain = Chain::new();
        let made = match reached {
            SetupPoint::Resolving | SetupPoint::Racing { started: false } => {
                chain.head(head, false);
                chain.push(Component::Setup, false);
                return chain;
            }
            SetupPoint::Racing { started: true } => {
                chain.head(head, false);
                chain.push(Component::Setup, false);
                chain.push(Component::HappyEyeballs, false);
                return chain;
            }
            // An HTTP/3 proxy's tunnel is the race's attempt, held apart
            // from the chain until it connects.
            SetupPoint::Dialed(made) if route.proxy_over_quic() && made.tunnel.is_none() => {
                return Chain::of(
                    route,
                    head,
                    SetupPoint::Racing { started: true },
                    None,
                    false,
                );
            }
            SetupPoint::Dialed(made) => made,
        };
        let added = |made: bool, filter: Component| made || under_way == Some(filter);
        let tunnels = route.proxy.as_ref().is_some_and(|p| p.tunnels());
        let proxy_tls_first = tunnels && under_way == Some(Component::SslProxy);
        let h2 = made.tunnel == Some(Tunneled::H2) || under_way == Some(Component::H2Proxy);
        let added = Handshakes {
            socks: added(made.socks, Component::Socks),
            proxy_tls: added(made.proxy_tls, Component::SslProxy),
            tunnel: added(made.tunnel.is_some(), Component::HttpProxy)
                || proxy_tls_first
                || under_way == Some(Component::H2Proxy),
            preface: added(made.preface, Component::Haproxy),
            tls: added(made.tls, Component::Ssl),
            quic: added(made.quic, Component::Http3),
        };
        // The capsule filter connects at once, its tunnel up.
        let capsules = installed || made.quic;
        let connected = |filter| match filter {
            Component::Socks => made.socks,
            Component::SslProxy => made.proxy_tls,
            Component::HttpProxy | Component::H1Proxy | Component::H2Proxy | Component::H3Proxy => {
                made.tunnel.is_some()
            }
            Component::Haproxy => made.preface,
            Component::Ssl => made.tls,
            Component::Http3 => made.quic,
            Component::Capsule => capsules,
            Component::HappyEyeballs | Component::Tcp | Component::Udp | Component::Unix => true,
            _ => false,
        };
        let installed = (installed && !proxy_tls_first) || made.tunnel.is_some() || h2;
        let tunnel = if h2 {
            Component::H2Proxy
        } else {
            Component::H1Proxy
        };
        Chain::dialed(route, head, added, (installed, tunnel), connected)
    }

    /// The DNS filters over the name the setup connects to first, the
    /// record's above them, then the HTTPS connect filter.
    fn head(&mut self, head: Head, connected: bool) {
        if head.record {
            self.push(Component::DnsFilter, connected);
        }
        self.push(Component::DnsFilter, connected);
        if head.https {
            self.push(Component::HttpsConnect, connected);
        }
    }

    /// The chain of a setup over `route` once it is connected, every
    /// filter connected; `haproxy` if the PROXY line was sent, `tunnel`
    /// the filter of a tunnel through the proxy, H1-PROXY or H2-PROXY.
    pub(crate) fn connected(
        route: Dialing<'_>,
        head: Head,
        haproxy: bool,
        tunnel: Component,
    ) -> Chain {
        let added = Handshakes {
            socks: route.socks().is_some(),
            proxy_tls: route.proxy_tls().is_some(),
            tunnel: route.proxy.as_ref().is_some_and(|p| p.tunnels()),
            preface: haproxy,
            tls: route.tls.is_some(),
            quic: route.tunnels_udp(),
        };
        Chain::dialed(route, head, added, (true, tunnel), |_| true)
    }

    /// The chain over a first hop connected, with the handshakes `added`,
    /// the tunnel's filter shown if it is installed.
    fn dialed(
        route: Dialing<'_>,
        head: Head,
        added: Handshakes,
        (installed, tunnel_filter): (bool, Component),
        connected: impl Fn(Component) -> bool,
    ) -> Chain {
        let mut chain = Chain::new();
        let mut push = |filter| chain.push(filter, connected(filter));
        if head.record {
            push(Component::DnsFilter);
        }
        push(Component::DnsFilter);
        // The SOCKS proxy's goes after the last DNS filter there is
        // (`cf_dns_add_resolve`), above the HTTPS connect filter.
        if added.socks && resolves_target(route.route) {
            push(Component::DnsFilter);
        }
        if head.https {
            push(Component::HttpsConnect);
            if head.h2 {
                push(Component::Http2);
            }
        }
        push(Component::Setup);
        // Each filter the setup adds goes right below it, so the last,
        // TLS's, is on top. An HTTPS proxy's TLS goes below its tunnel,
        // or, with none, is the origin's filter (`origin_is_proxy`), added
        // last.
        let tunnels = route.proxy.as_ref().is_some_and(|p| p.tunnels());
        // QUIC's TLS is its own, in its filter below the race's. An
        // HTTP/3 proxy's tunnel is its QUIC filter's, the race's attempt,
        // with neither the HTTP proxy's filter nor its TLS's
        // (`CF_SETUP_CNNCT_HTTP_PROXY`).
        let h3_proxy = route.proxy_over_quic();
        let quic = route.dial == crate::conn::Dial::Quic;
        // Through a CONNECT-UDP tunnel, the origin's QUIC filter is the
        // last the setup adds, over the capsules the tunnel carries
        // (`Curl_cf_quic_insert_after`); the race is the proxy's.
        let tunnels_udp = route.tunnels_udp();
        if added.quic && tunnels_udp {
            push(Component::Http3);
            push(Component::Capsule);
        }
        if added.tls && !quic {
            push(Component::Ssl);
        }
        if added.proxy_tls && !tunnels {
            push(Component::SslProxy);
        }
        if added.preface {
            push(Component::Haproxy);
        }
        if added.tunnel && !h3_proxy {
            push(Component::HttpProxy);
            if installed {
                push(tunnel_filter);
            }
        }
        if added.proxy_tls && tunnels && !h3_proxy {
            push(Component::SslProxy);
        }
        if added.socks {
            push(Component::Socks);
        }
        push(Component::HappyEyeballs);
        if quic && !tunnels_udp {
            push(Component::Http3);
        } else if h3_proxy {
            push(Component::H3Proxy);
        }
        push(route.socket_component());
        chain
    }

    /// The chain as a failed call leaves it: the HTTPS connect filter, if
    /// there is one, holds its attempt's filters apart from the chain
    /// outside its connect (`cf_hc_baller_connect`), so the chain ends
    /// there.
    pub(crate) fn failed(&self) -> Chain {
        let mut left = Chain::new().on(self.rank);
        for &(filter, connected) in &self.filters[..self.len] {
            left.push(filter, connected);
            if filter == Component::HttpsConnect {
                break;
            }
        }
        left
    }

    /// What is left once the setup filters go
    /// (`Curl_conn_remove_setup_filters`).
    pub(crate) fn reduced(&self) -> Chain {
        let mut left = Chain::new().on(self.rank);
        for &(filter, connected) in &self.filters[..self.len] {
            if !is_setup(filter) {
                left.push(filter, connected);
            }
        }
        left
    }

    /// What a second connection accepted from the server is
    /// (`Curl_conn_tcp_listen_set`): its one filter.
    pub(crate) fn accepted() -> Chain {
        let mut chain = Chain::new();
        chain.push(Component::TcpAccept, true);
        chain
    }

    /// This connected chain with a second connection's TLS below its setup
    /// filter: `made`, all of it connected; or being made, it and what is
    /// above it not yet (`cf_setup_connect`'s `CF_SETUP_CNNCT_SSL`).
    pub(crate) fn with_tls(&self, made: bool) -> Chain {
        let filters = &self.filters[..self.len];
        let at = filters
            .iter()
            .position(|&(filter, _)| filter == Component::Setup)
            .map_or(0, |setup| setup + 1);
        let mut chain = Chain::new().on(self.rank);
        for &(filter, _) in &filters[..at] {
            chain.push(filter, made);
        }
        chain.push(Component::Ssl, made);
        for &(filter, connected) in &filters[at..] {
            chain.push(filter, connected);
        }
        chain
    }

    /// How many DNS filters it holds.
    pub(crate) fn dns_filters(&self) -> usize {
        self.filters[..self.len]
            .iter()
            .filter(|&&(filter, _)| filter == Component::DnsFilter)
            .count()
    }

    /// The chain with `filter` put on top of it, `connected` or not, as a
    /// filter added to a connection already up goes (`Curl_conn_cf_add`):
    /// TLS upgraded to in place.
    pub(crate) fn under(&self, filter: Component, connected: bool) -> Chain {
        let mut topped = Chain::new().on(self.rank);
        topped.push(filter, connected);
        for &(filter, connected) in &self.filters[..self.len] {
            topped.push(filter, connected);
        }
        topped
    }

    /// The filter at its top, which a question of the connection is
    /// asked of first (`conn->cfilter[FIRSTSOCKET]`).
    pub(crate) fn top(&self) -> Option<Component> {
        self.filters[..self.len].first().map(|&(filter, _)| filter)
    }

    /// The setup filters that go once the chain is connected, top first,
    /// each tracing its going.
    pub(crate) fn going(&self) -> impl Iterator<Item = Component> + '_ {
        self.filters[..self.len]
            .iter()
            .map(|&(filter, _)| filter)
            .filter(|&f| is_setup(f))
    }
}

/// The handshakes whose filters a chain holds.
#[derive(Clone, Copy)]
struct Handshakes {
    socks: bool,
    proxy_tls: bool,
    tunnel: bool,
    preface: bool,
    tls: bool,
    /// The origin's QUIC filter, over a CONNECT-UDP tunnel.
    quic: bool,
}

/// A filter that is only there while the chain connects (`CF_TYPE_SETUP`).
fn is_setup(filter: Component) -> bool {
    matches!(
        filter,
        Component::DnsFilter
            | Component::HttpsConnect
            | Component::Setup
            | Component::HappyEyeballs
            | Component::HttpProxy
            | Component::Haproxy
    )
}

/// The route's SOCKS proxy is given an address, not a name, so a DNS
/// filter of its own resolves the peer it is to reach
/// (`Curl_cf_socks_proxy_insert_after`).
pub(crate) fn resolves_target(route: &NetRoute) -> bool {
    route
        .socks()
        .is_some_and(|leg| leg.version.resolves_locally())
}

/// As C traces a chain: the socket's index, then each filter, `!` before
/// one not connected yet.
impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.rank {
            ConnRank::First => "[0]",
            ConnRank::Second => "[1]",
        })?;
        for &(filter, connected) in &self.filters[..self.len] {
            let not = if connected { "" } else { "!" };
            write!(f, "[{not}{}]", filter.name())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use curl_alloc::TryArc;

    use super::*;
    use crate::conn::{Handshook, Peer, Scheme};

    /// Each handshake is made once: a second mark of one is a setup that
    /// lost its place, which the chain would show wrong.
    #[test]
    #[should_panic(expected = "is made once")]
    fn a_handshake_is_made_once() {
        let made = Made::default().with(Handshook::Tunnel(Tunneled::H1));
        let _ = made.with(Handshook::Tunnel(Tunneled::H2));
    }
    use crate::options::IpVersion;

    /// A handshake's filter shows connected once it is made, as C's does
    /// until the setup filters go; the PROXY line's while a later one is
    /// still to be made over the same connection.
    #[test]
    fn a_handshake_made_shows_connected() {
        let scheme = Scheme::HTTP;
        let route = NetRoute {
            origin: TryArc::try_new(Peer::new(scheme, b"o.test".to_vec(), 80, None)).unwrap(),
            via: None,
            ip: IpVersion::Any,
            proxy: None,
            tls: None,
            cold: None,
            delegation: Default::default(),
        };
        let route = &route;
        let shown = |made, under_way| {
            Chain::of(
                Dialing {
                    route,
                    dial: crate::conn::Dial::Stream,
                },
                Head::default(),
                SetupPoint::Dialed(made),
                under_way,
                false,
            )
            .to_string()
        };
        assert_eq!(
            shown(Made::default().with(Handshook::Preface), None),
            "[0][!DNS][!SETUP][HAPROXY][HAPPY-EYEBALLS][TCP]"
        );
        assert_eq!(
            shown(Made::default(), Some(Component::Haproxy)),
            "[0][!DNS][!SETUP][!HAPROXY][HAPPY-EYEBALLS][TCP]"
        );
        assert_eq!(
            shown(Made::default(), None),
            "[0][!DNS][!SETUP][HAPPY-EYEBALLS][TCP]"
        );
        let tls = crate::tls::TlsIdentity::of(&Default::default(), Default::default()).unwrap();
        let route = NetRoute {
            tls: Some(tls),
            ..route.clone()
        };
        let route = &route;
        let shown = |made, under_way| {
            Chain::of(
                Dialing {
                    route,
                    dial: crate::conn::Dial::Stream,
                },
                Head::default(),
                SetupPoint::Dialed(made),
                under_way,
                false,
            )
            .to_string()
        };
        assert_eq!(
            shown(Made::default().with(Handshook::Tls), None),
            "[0][!DNS][!SETUP][SSL][HAPPY-EYEBALLS][TCP]"
        );
        assert_eq!(
            shown(Made::default(), Some(Component::Ssl)),
            "[0][!DNS][!SETUP][!SSL][HAPPY-EYEBALLS][TCP]"
        );
    }

    /// An HTTPS proxy's TLS shows connected once it is made, its tunnel's
    /// filter then under way above it: H2-PROXY under HTTP-PROXY for one
    /// that is a stream of an HTTP/2 session, under way and made, as C's
    /// chain shows it.
    #[test]
    fn an_https_proxy_s_tls_made_shows_connected() {
        let scheme = Scheme::HTTP;
        let peer =
            |name: &[u8], port| TryArc::try_new(Peer::new(scheme, name.to_vec(), port, None));
        let tls = crate::tls::TlsIdentity::of(&Default::default(), Default::default()).unwrap();
        let proxy = crate::conn::ProxyRoute::new(
            crate::options::ProxyType::Https,
            peer(b"p.test", 443).unwrap(),
            None,
            false,
            false,
        )
        .secured(tls)
        .unwrap();
        let route = NetRoute {
            origin: peer(b"o.test", 80).unwrap(),
            via: None,
            ip: IpVersion::Any,
            proxy: Some(proxy),
            tls: None,
            cold: None,
            delegation: Default::default(),
        };
        let shown = |made, under_way| {
            Chain::of(
                Dialing {
                    route: &route,
                    dial: crate::conn::Dial::Stream,
                },
                Head::default(),
                SetupPoint::Dialed(made),
                under_way,
                false,
            )
            .to_string()
        };
        assert_eq!(
            shown(Made::default(), Some(Component::SslProxy)),
            "[0][!DNS][!SETUP][!HTTP-PROXY][!SSL-PROXY][HAPPY-EYEBALLS][TCP]"
        );
        assert_eq!(
            shown(
                Made::default().with(Handshook::ProxyTls),
                Some(Component::HttpProxy)
            ),
            "[0][!DNS][!SETUP][!HTTP-PROXY][SSL-PROXY][HAPPY-EYEBALLS][TCP]"
        );
        assert_eq!(
            shown(
                Made::default().with(Handshook::ProxyTls),
                Some(Component::H2Proxy)
            ),
            "[0][!DNS][!SETUP][!HTTP-PROXY][!H2-PROXY][SSL-PROXY][HAPPY-EYEBALLS][TCP]"
        );
        assert_eq!(
            shown(
                Made::default()
                    .with(Handshook::ProxyTls)
                    .with(Handshook::Tunnel(Tunneled::H2)),
                None
            ),
            "[0][!DNS][!SETUP][HTTP-PROXY][H2-PROXY][SSL-PROXY][HAPPY-EYEBALLS][TCP]"
        );
    }

    /// An HTTP/3 proxy's tunnel is the race's attempt in C, held apart
    /// from the chain until it connects: the chain is the race's until
    /// then, then the attempt's filters below HAPPY-EYEBALLS, with no
    /// HTTP-PROXY or SSL-PROXY.
    #[test]
    fn an_http3_proxy_s_tunnel_is_the_race_s_attempt() {
        let scheme = Scheme::HTTP;
        let peer =
            |name: &[u8], port| TryArc::try_new(Peer::new(scheme, name.to_vec(), port, None));
        let tls = crate::tls::TlsIdentity::of(&Default::default(), Default::default()).unwrap();
        let proxy = crate::conn::ProxyRoute::new(
            crate::options::ProxyType::Https3,
            peer(b"p.test", 443).unwrap(),
            None,
            false,
            false,
        )
        .secured(tls)
        .unwrap();
        let route = NetRoute {
            origin: peer(b"o.test", 80).unwrap(),
            via: None,
            ip: IpVersion::Any,
            proxy: Some(proxy),
            tls: None,
            cold: None,
            delegation: Default::default(),
        };
        let route = &route;
        let shown = |made, under_way| {
            Chain::of(
                Dialing {
                    route,
                    dial: crate::conn::Dial::Stream,
                },
                Head::default(),
                SetupPoint::Dialed(made),
                under_way,
                false,
            )
            .to_string()
        };
        assert_eq!(
            shown(
                Made::default().with(Handshook::ProxyTls),
                Some(Component::H3Proxy)
            ),
            "[0][!DNS][!SETUP][!HAPPY-EYEBALLS]"
        );
        let made = Made::default()
            .with(Handshook::ProxyTls)
            .with(Handshook::Tunnel(Tunneled::H3));
        let up = Chain::of(
            Dialing {
                route,
                dial: crate::conn::Dial::Stream,
            },
            Head::default(),
            SetupPoint::Dialed(made),
            None,
            false,
        );
        assert_eq!(
            up.to_string(),
            "[0][!DNS][!SETUP][HAPPY-EYEBALLS][H3-PROXY][UDP]"
        );
        let going: Vec<_> = up.going().collect();
        assert_eq!(
            going,
            [
                Component::DnsFilter,
                Component::Setup,
                Component::HappyEyeballs
            ]
        );
        assert_eq!(up.reduced().to_string(), "[0][H3-PROXY][UDP]");
    }

    /// Through an HTTP proxy's CONNECT-UDP, the race is the proxy's, in
    /// TCP; the origin's QUIC filter, over the capsule filter, is the
    /// last the setup adds, on top, the capsule filter connected at once;
    /// connected, HAPPY-EYEBALLS goes with the setup's others and both
    /// stay (`Curl_cf_quic_insert_after`).
    #[test]
    fn http3_through_connect_udp_is_over_the_tunnel_s_filters() {
        let scheme = Scheme::HTTPS;
        let peer =
            |name: &[u8], port| TryArc::try_new(Peer::new(scheme, name.to_vec(), port, None));
        let proxy = crate::conn::ProxyRoute::new(
            crate::options::ProxyType::Http,
            peer(b"p.test", 3128).unwrap(),
            None,
            false,
            false,
        );
        let tls = crate::tls::TlsIdentity::of(&Default::default(), Default::default()).unwrap();
        let route = NetRoute {
            origin: peer(b"o.test", 443).unwrap(),
            via: None,
            ip: IpVersion::Any,
            proxy: Some(proxy),
            tls: Some(tls),
            cold: None,
            delegation: Default::default(),
        };
        let route = &route;
        let route = Dialing {
            route,
            dial: crate::conn::Dial::Quic,
        };
        assert!(route.tunnels_udp());
        let shown = |made, under_way, installed| {
            Chain::of(
                route,
                Head::default(),
                SetupPoint::Dialed(made),
                under_way,
                installed,
            )
            .to_string()
        };
        assert_eq!(
            shown(Made::default(), Some(Component::HttpProxy), false),
            "[0][!DNS][!SETUP][!HTTP-PROXY][HAPPY-EYEBALLS][TCP]"
        );
        assert_eq!(
            shown(
                Made::default().with(Handshook::Tunnel(Tunneled::H1)),
                Some(Component::Http3),
                false
            ),
            "[0][!DNS][!SETUP][!HTTP/3][!CAPSULE][HTTP-PROXY][H1-PROXY][HAPPY-EYEBALLS][TCP]"
        );
        assert_eq!(
            shown(
                Made::default().with(Handshook::Tunnel(Tunneled::H1)),
                Some(Component::Http3),
                true
            ),
            "[0][!DNS][!SETUP][!HTTP/3][CAPSULE][HTTP-PROXY][H1-PROXY][HAPPY-EYEBALLS][TCP]"
        );
        assert_eq!(
            shown(
                Made::default()
                    .with(Handshook::Tunnel(Tunneled::H1))
                    .with(Handshook::Quic),
                None,
                true
            ),
            "[0][!DNS][!SETUP][HTTP/3][CAPSULE][HTTP-PROXY][H1-PROXY][HAPPY-EYEBALLS][TCP]"
        );
        let up = Chain::connected(route, Head::default(), false, Component::H1Proxy);
        assert_eq!(
            up.to_string(),
            "[0][DNS][SETUP][HTTP/3][CAPSULE][HTTP-PROXY][H1-PROXY][HAPPY-EYEBALLS][TCP]"
        );
        let going: Vec<_> = up.going().collect();
        assert_eq!(
            going,
            [
                Component::DnsFilter,
                Component::Setup,
                Component::HttpProxy,
                Component::HappyEyeballs
            ]
        );
        assert_eq!(
            up.reduced().to_string(),
            "[0][HTTP/3][CAPSULE][H1-PROXY][TCP]"
        );
    }
}
