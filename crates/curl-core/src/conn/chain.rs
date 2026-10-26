//! C's filter chain for a connection being set up, rendered for the trace
//! (`Curl_conn_trc_filters`). The typed connect machine stands for C's
//! setup filters (SETUP, DNS, HAPPY-EYEBALLS, HTTP-PROXY, HAPROXY), which
//! exist in C only until the chain connects; this says which filters C's
//! chain would hold at a point of the setup, top first, and which of them
//! are connected, from how far the machine got and the handshake under
//! way. It allocates nothing.

use std::fmt;

use super::Tcp;
use super::connect::Made;
use crate::components::Component;

/// How far a setup got, as the chain shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupPoint {
    /// Its first hop's name is being resolved.
    Resolving,
    /// Attempts are made to the first hop, once `started`.
    Racing { started: bool },
    /// Connected to the first hop, the handshakes in `made` made over it.
    Dialed(Made),
}

/// What heads a setup's chain above its SETUP filter: the HTTPS connect
/// filter, for an `https` origin no proxy forwards to with ALPN on
/// (`Curl_cf_https_setup`), and above the name's DNS filter the one that
/// asks for the origin's HTTPS record, unless the origin is an address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Head {
    pub(crate) https: bool,
    pub(crate) record: bool,
}

/// The most filters a chain holds: three DNS, HTTPS-CONNECT, SETUP, SSL,
/// HAPROXY, HTTP-PROXY, H1-PROXY, SSL-PROXY, SOCKS, HAPPY-EYEBALLS and
/// TCP.
const MOST: usize = 13;

/// A chain of filters, top first, each connected or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Chain {
    filters: [(Component, bool); MOST],
    len: usize,
}

impl Chain {
    fn new() -> Chain {
        Chain {
            filters: [(Component::Tcp, false); MOST],
            len: 0,
        }
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
        route: &Tcp,
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
            SetupPoint::Dialed(made) => made,
        };
        let added = |which: Made, filter: Component| made.has(which) || under_way == Some(filter);
        let tunnels = route.proxy.as_ref().is_some_and(|p| p.tunnels());
        let proxy_tls_first = tunnels && under_way == Some(Component::SslProxy);
        let h2 = made.has(Made::H2_TUNNEL) || under_way == Some(Component::H2Proxy);
        let added = Handshakes {
            socks: added(Made::SOCKS, Component::Socks),
            proxy_tls: added(Made::PROXY_TLS, Component::SslProxy),
            tunnel: added(Made::TUNNEL, Component::HttpProxy)
                || proxy_tls_first
                || under_way == Some(Component::H2Proxy),
            preface: added(Made::PREFACE, Component::Haproxy),
            tls: added(Made::TLS, Component::Ssl),
        };
        let connected = |filter| match filter {
            Component::Socks => made.has(Made::SOCKS),
            Component::SslProxy => made.has(Made::PROXY_TLS),
            Component::HttpProxy | Component::H1Proxy | Component::H2Proxy => {
                made.has(Made::TUNNEL)
            }
            Component::Haproxy => made.has(Made::PREFACE),
            Component::Ssl => made.has(Made::TLS),
            Component::HappyEyeballs | Component::Tcp | Component::Unix => true,
            _ => false,
        };
        let installed = (installed && !proxy_tls_first) || made.has(Made::TUNNEL) || h2;
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
            self.push(Component::Dns, connected);
        }
        self.push(Component::Dns, connected);
        if head.https {
            self.push(Component::HttpsConnect, connected);
        }
    }

    /// The chain of a setup over `route` once it is connected, every
    /// filter connected; `haproxy` if the PROXY line was sent, `tunnel`
    /// the filter of a tunnel through the proxy, H1-PROXY or H2-PROXY.
    pub(crate) fn connected(route: &Tcp, head: Head, haproxy: bool, tunnel: Component) -> Chain {
        let added = Handshakes {
            socks: route.socks().is_some(),
            proxy_tls: route.proxy_tls().is_some(),
            tunnel: route.proxy.as_ref().is_some_and(|p| p.tunnels()),
            preface: haproxy,
            tls: route.tls.is_some(),
        };
        Chain::dialed(route, head, added, (true, tunnel), |_| true)
    }

    /// The chain over a first hop connected, with the handshakes `added`,
    /// the tunnel's filter shown if it is installed.
    fn dialed(
        route: &Tcp,
        head: Head,
        added: Handshakes,
        (installed, tunnel_filter): (bool, Component),
        connected: impl Fn(Component) -> bool,
    ) -> Chain {
        let mut chain = Chain::new();
        let mut push = |filter| chain.push(filter, connected(filter));
        if head.record {
            push(Component::Dns);
        }
        push(Component::Dns);
        // The SOCKS proxy's goes after the last DNS filter there is
        // (`cf_dns_add_resolve`), above the HTTPS connect filter.
        if added.socks && resolves_target(route) {
            push(Component::Dns);
        }
        if head.https {
            push(Component::HttpsConnect);
        }
        push(Component::Setup);
        // Each filter the setup adds goes right below it, so the last,
        // TLS's, is on top. An HTTPS proxy's TLS goes below its tunnel,
        // or, with none, is the origin's filter (`origin_is_proxy`), added
        // last.
        let tunnels = route.proxy.as_ref().is_some_and(|p| p.tunnels());
        if added.tls {
            push(Component::Ssl);
        }
        if added.proxy_tls && !tunnels {
            push(Component::SslProxy);
        }
        if added.preface {
            push(Component::Haproxy);
        }
        if added.tunnel {
            push(Component::HttpProxy);
            if installed {
                push(tunnel_filter);
            }
        }
        if added.proxy_tls && tunnels {
            push(Component::SslProxy);
        }
        if added.socks {
            push(Component::Socks);
        }
        push(Component::HappyEyeballs);
        push(route.socket_component());
        chain
    }

    /// The chain as a failed call leaves it: the HTTPS connect filter, if
    /// there is one, holds its attempt's filters apart from the chain
    /// outside its connect (`cf_hc_baller_connect`), so the chain ends
    /// there.
    pub(crate) fn failed(&self) -> Chain {
        let mut left = Chain::new();
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
        let mut left = Chain::new();
        for &(filter, connected) in &self.filters[..self.len] {
            if !is_setup(filter) {
                left.push(filter, connected);
            }
        }
        left
    }

    /// The filter at its top, which a question of the connection is
    /// asked of first (`conn->cfilter[FIRSTSOCKET]`).
    pub(crate) fn top(&self) -> Option<Component> {
        self.filters[..self.len].first().map(|&(filter, _)| filter)
    }

    /// The setup filters that go once the chain is connected, top first,
    /// that trace their going: C's DNS and HAPPY-EYEBALLS filters' own
    /// lines are not traced.
    pub(crate) fn going(&self) -> impl Iterator<Item = Component> + '_ {
        self.filters[..self.len]
            .iter()
            .map(|&(filter, _)| filter)
            .filter(|&f| is_setup(f) && f != Component::Dns && f != Component::HappyEyeballs)
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
}

/// A filter that is only there while the chain connects (`CF_TYPE_SETUP`).
fn is_setup(filter: Component) -> bool {
    matches!(
        filter,
        Component::Dns
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
fn resolves_target(route: &Tcp) -> bool {
    route
        .socks()
        .is_some_and(|leg| leg.version.resolves_locally())
}

/// As C traces a chain: the socket's index, then each filter, `!` before
/// one not connected yet.
impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[0]")?;
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
    use crate::conn::{Peer, Scheme};
    use crate::options::IpVersion;

    /// A handshake's filter shows connected once it is made, as C's does
    /// until the setup filters go; the PROXY line's while a later one is
    /// still to be made over the same connection.
    #[test]
    fn a_handshake_made_shows_connected() {
        let scheme = Scheme {
            name: "http",
            reuse: true,
        };
        let route = Tcp {
            origin: TryArc::try_new(Peer::new(scheme, b"o.test".to_vec(), 80, None)).unwrap(),
            via: None,
            ip: IpVersion::Any,
            proxy: None,
            tls: None,
            local: None,
            delegation: Default::default(),
            dial: crate::conn::Dial::Tcp,
        };
        let shown = |made, under_way| {
            Chain::of(
                &route,
                Head::default(),
                SetupPoint::Dialed(made),
                under_way,
                false,
            )
            .to_string()
        };
        assert_eq!(
            shown(Made::PREFACE, None),
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
        let route = Tcp {
            tls: Some(tls),
            ..route
        };
        let shown = |made, under_way| {
            Chain::of(
                &route,
                Head::default(),
                SetupPoint::Dialed(made),
                under_way,
                false,
            )
            .to_string()
        };
        assert_eq!(
            shown(Made::TLS, None),
            "[0][!DNS][!SETUP][SSL][HAPPY-EYEBALLS][TCP]"
        );
        assert_eq!(
            shown(Made::default(), Some(Component::Ssl)),
            "[0][!DNS][!SETUP][!SSL][HAPPY-EYEBALLS][TCP]"
        );
    }
}
