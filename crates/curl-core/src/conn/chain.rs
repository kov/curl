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

/// The most filters a chain holds: two DNS, SETUP, SSL, HAPROXY,
/// HTTP-PROXY, H1-PROXY, SOCKS, HAPPY-EYEBALLS and TCP.
const MOST: usize = 10;

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
    /// C installs it in the tunnel filter's first connect.
    pub(crate) fn of(
        route: &Tcp,
        reached: SetupPoint,
        under_way: Option<Component>,
        installed: bool,
    ) -> Chain {
        let mut chain = Chain::new();
        let made = match reached {
            SetupPoint::Resolving | SetupPoint::Racing { started: false } => {
                chain.push(Component::Dns, false);
                chain.push(Component::Setup, false);
                return chain;
            }
            SetupPoint::Racing { started: true } => {
                chain.push(Component::Dns, false);
                chain.push(Component::Setup, false);
                chain.push(Component::HappyEyeballs, false);
                return chain;
            }
            SetupPoint::Dialed(made) => made,
        };
        let added = |which: Made, filter: Component| made.has(which) || under_way == Some(filter);
        let added = Handshakes {
            socks: added(Made::SOCKS, Component::Socks),
            tunnel: added(Made::TUNNEL, Component::HttpProxy),
            preface: added(Made::PREFACE, Component::Haproxy),
            tls: added(Made::TLS, Component::Ssl),
        };
        let connected = |filter| match filter {
            Component::Socks => made.has(Made::SOCKS),
            Component::HttpProxy | Component::H1Proxy => made.has(Made::TUNNEL),
            Component::Haproxy => made.has(Made::PREFACE),
            Component::Ssl => made.has(Made::TLS),
            Component::HappyEyeballs | Component::Tcp => true,
            _ => false,
        };
        let installed = installed || made.has(Made::TUNNEL);
        Chain::dialed(route, added, installed, connected)
    }

    /// The chain of a setup over `route` once it is connected, every
    /// filter connected; `haproxy` if the PROXY line was sent.
    pub(crate) fn connected(route: &Tcp, haproxy: bool) -> Chain {
        let added = Handshakes {
            socks: route.socks().is_some(),
            tunnel: route.proxy.as_ref().is_some_and(|p| p.tunnels()),
            preface: haproxy,
            tls: route.tls.is_some(),
        };
        Chain::dialed(route, added, true, |_| true)
    }

    /// The chain over a first hop connected, with the handshakes `added`.
    fn dialed(
        route: &Tcp,
        added: Handshakes,
        installed: bool,
        connected: impl Fn(Component) -> bool,
    ) -> Chain {
        let mut chain = Chain::new();
        let mut push = |filter| chain.push(filter, connected(filter));
        push(Component::Dns);
        if added.socks && resolves_target(route) {
            push(Component::Dns);
        }
        push(Component::Setup);
        // Each filter the setup adds goes right below it, so the last,
        // TLS's, is on top.
        if added.tls {
            push(Component::Ssl);
        }
        if added.preface {
            push(Component::Haproxy);
        }
        if added.tunnel {
            push(Component::HttpProxy);
            if installed {
                push(Component::H1Proxy);
            }
        }
        if added.socks {
            push(Component::Socks);
        }
        push(Component::HappyEyeballs);
        push(Component::Tcp);
        chain
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
    tunnel: bool,
    preface: bool,
    tls: bool,
}

/// A filter that is only there while the chain connects (`CF_TYPE_SETUP`).
fn is_setup(filter: Component) -> bool {
    matches!(
        filter,
        Component::Dns
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
        };
        let shown = |made, under_way| {
            Chain::of(&route, SetupPoint::Dialed(made), under_way, false).to_string()
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
            Chain::of(&route, SetupPoint::Dialed(made), under_way, false).to_string()
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
