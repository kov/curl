//! A socket's local end bound before it connects (`bindlocal` in
//! cf-socket.c): to an interface by its name, else to the address an
//! interface or a name has, and to a port, the ports of a range tried in
//! turn. Its traces and failures are C's.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use super::connect::{Asked, ConnCx, ConnectError, Found, Setup, Unresolved, lookup_name};
use super::io::{AF_INET, AF_INET6, Family, InterfaceAddress, Socket, SocketOption, ipv6_scope};
use crate::components::Component;
use crate::error::{AGAIN_NUMBER, ErrorKind};
use crate::options::LocalBind;
use crate::text::Text;
use crate::trace::{Bytes, Code, OsError};

/// Why a socket's local end was not bound.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum BindFailed {
    /// The attempt fails as this says, its reason given.
    Failed(ErrorKind),
    /// What is bound to has no address of the family connected over:
    /// the attempt fails, and the next address is tried
    /// (`CURLE_UNSUPPORTED_PROTOCOL`, made `CURLE_COULDNT_CONNECT`).
    OtherFamily,
    OutOfMemory,
}

impl BindFailed {
    /// What the attempt fails with.
    pub(super) fn kind(&self) -> ErrorKind {
        match self {
            BindFailed::Failed(kind) => *kind,
            BindFailed::OtherFamily => ErrorKind::CouldntConnect,
            BindFailed::OutOfMemory => ErrorKind::OutOfMemory,
        }
    }
}

/// The port a host's name is resolved for, as C resolves it to bind.
const BIND_RESOLVE_PORT: u16 = 80;

/// Bind `socket`, about to connect to `remote`, as `bind` says: in
/// `scope_id`, the connection's IPv6 scope (0 for none), an interface's
/// address is taken (`bindlocal`).
pub(super) fn bind_local(
    cx: &mut dyn ConnCx,
    socket: &dyn Socket,
    remote: SocketAddr,
    bind: &LocalBind,
    scope_id: u32,
    setup: Setup,
) -> Result<(), BindFailed> {
    let v6 = remote.is_ipv6();
    let parts = bind
        .interface
        .as_ref()
        .map(crate::options::Interface::parts);
    let (iface, host, iface_in, host_in) = match &parts {
        Some(p) => (p.interface, p.host, p.interface_named, p.host_named),
        None => (None, None, false, false),
    };
    if iface.is_none() && host.is_none() && bind.port == 0 {
        return Ok(());
    }
    if iface.is_some_and(|name| name.len() >= 255) {
        return Err(BindFailed::Failed(ErrorKind::BadFunctionArgument));
    }
    let (ip, scope) = if iface.is_some() || host.is_some() {
        match where_to_bind(
            cx,
            socket,
            remote,
            (iface, host, iface_in, host_in),
            scope_id,
            setup,
        )? {
            Some(at) => at,
            // Bound to the interface by its name, and nothing else.
            None => return Ok(()),
        }
    } else if v6 {
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let mut port = bind.port;
    let mut at = match ip {
        IpAddr::V4(_) => SocketAddr::new(ip, port),
        IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope)),
    };
    // The port is left for the connect to choose, if it is to choose
    // one; C ignores whether the system takes this.
    match socket.set(SocketOption::BindAddressNoPort) {
        Ok(()) | Err(_) => {}
    }
    let mut tries = i32::from(bind.port_range);
    let error = loop {
        let error = match socket.bind(at) {
            Ok(()) => {
                cx.info(format_args!("Local port: {port}"));
                return Ok(());
            }
            Err(error) => error,
        };
        if error.kind() == io::ErrorKind::OutOfMemory {
            return Err(BindFailed::OutOfMemory);
        }
        tries -= 1;
        if tries <= 0 {
            break error;
        }
        port = port.wrapping_add(1);
        if port == 0 {
            break error;
        }
        let tried = port - 1;
        cx.info(format_args!(
            "Bind to local port {tried} failed, trying next"
        ));
        at.set_port(port);
    };
    cx.socket_failed(&error);
    let n = error.raw_os_error().unwrap_or(0);
    cx.fail(format_args!(
        "bind failed with errno {n}: {}",
        OsError(&error)
    ));
    Err(BindFailed::Failed(ErrorKind::InterfaceFailed))
}

/// The address `bindlocal` binds to, with its IPv6 scope id, for the
/// interface and host named; `None` if the socket was bound to the
/// interface by its name and is to be bound to nothing else.
fn where_to_bind(
    cx: &mut dyn ConnCx,
    socket: &dyn Socket,
    remote: SocketAddr,
    (iface, host, iface_in, host_in): (Option<&[u8]>, Option<&[u8]>, bool, bool),
    scope_id: u32,
    setup: Setup,
) -> Result<Option<(IpAddr, u32)>, BindFailed> {
    let v6 = remote.is_ipv6();
    let af = if v6 { AF_INET6 } else { AF_INET };
    // An interface bound to by name, unless a host is named too: not
    // allowed to most users, it fails then, and its address is looked
    // for instead.
    let mut by_name = None;
    if let Some(name) = iface {
        match socket.bind_to_device(name) {
            Ok(()) if !host_in => {
                cx.info(format_args!(
                    "socket successfully bound to interface '{}'",
                    Bytes(name)
                ));
                return Ok(None);
            }
            Ok(()) => {}
            Err(error) => by_name = Some(error),
        }
    }
    let mut found = None;
    // The host, or what the interface's address is, as text.
    let host_text: Text<64>;
    let mut host = host.unwrap_or_default();
    if !host_in {
        let name = iface.expect("an interface is named where no host is");
        let remote_scope = ipv6_scope(remote.ip());
        match cx.net().interface_address(name, v6, remote_scope, scope_id) {
            InterfaceAddress::NotFound if iface_in => {
                // Not taken for a host's name.
                let error = by_name.unwrap_or_else(|| io::Error::from_raw_os_error(0));
                cx.socket_failed(&error);
                let n = error.raw_os_error().unwrap_or(0);
                cx.fail(format_args!(
                    "Could not bind to interface '{}' with errno {n}: {}",
                    Bytes(name),
                    OsError(&error)
                ));
                return Err(BindFailed::Failed(ErrorKind::InterfaceFailed));
            }
            InterfaceAddress::NotFound => {}
            InterfaceAddress::OtherFamily => return Err(BindFailed::OtherFamily),
            InterfaceAddress::Found(ip, scope) => {
                host_text = Text::clipped(format_args!("{ip}{}", Scope(scope))).0;
                host = host_text.bytes();
                cx.info(format_args!(
                    "Local Interface {} is ip {} using address family {af}",
                    Bytes(name),
                    Bytes(host)
                ));
                found = Some((ip, scope));
            }
        }
    }
    if !iface_in || host_in {
        // Not an interface: a name or an address, of the family connected
        // over alone.
        found = match resolve_host(cx, host, v6, setup)? {
            Some(ip) => {
                let h_af = if ip.is_ipv6() { AF_INET6 } else { AF_INET };
                cx.info(format_args!(
                    "Name '{}' family {af} resolved to '{ip}' family {h_af}",
                    Bytes(host)
                ));
                if ip.is_ipv6() != v6 {
                    return Err(BindFailed::OtherFamily);
                }
                Some((ip, 0))
            }
            None => None,
        };
    }
    match found {
        Some(at) => Ok(Some(at)),
        None => {
            // Whatever the system said last; this reason replaces any
            // given before (`state.errorbuf` cleared).
            let error = io::Error::last_os_error();
            cx.socket_failed(&error);
            let n = error.raw_os_error().unwrap_or(0);
            cx.reset_fail();
            cx.fail(format_args!(
                "Could not bind to '{}' with errno {n}: {}",
                Bytes(host),
                OsError(&error)
            ));
            Err(BindFailed::Failed(ErrorKind::InterfaceFailed))
        }
    }
}

/// An IPv6 scope id as an address's text ends with it, `%N`, none for 0.
struct Scope(u32);

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => Ok(()),
            n => write!(f, "%{n}"),
        }
    }
}

/// The first address of the family IPv6 if `v6`, else IPv4, `host`
/// stands for, resolved as C's blocking resolve does it
/// (`Curl_resolv_blocking`, for port 80): through the cache, which keeps
/// what is found but not that nothing was, traced as `hostip_resolv`
/// traces it. `None` if it has none.
fn resolve_host(
    cx: &mut dyn ConnCx,
    host: &[u8],
    v6: bool,
    setup: Setup,
) -> Result<Option<IpAddr>, BindFailed> {
    let (family, queries) = if v6 {
        (Family::V6, "AAAA")
    } else {
        (Family::V4, "A")
    };
    let port = BIND_RESOLVE_PORT;
    let name = Bytes(host);
    // An IPv6 address is a host as a URL shows it in brackets.
    let bare_v6 = std::str::from_utf8(host)
        .ok()
        .is_some_and(|h| h.parse::<Ipv6Addr>().is_ok());
    let bracketed: Text<64>;
    let shown = if bare_v6 {
        bracketed = Text::clipped(format_args!("[{name}]")).0;
        bracketed.bytes()
    } else {
        host
    };
    let dns = Component::Dns;
    // The C debug build's line.
    #[cfg(feature = "debug-hooks")]
    cx.of(
        dns,
        format_args!("[{queries}] hostip_resolv({name}:{port})"),
    );
    let looked = lookup_name((shown, host, port), family, cx, setup, false);
    if let Err(ConnectError::Unresolved(Unresolved::DebugFailIpv6)) = looked {
        cx.info(format_args!("DEBUG fail ipv6 resolve"));
        cx.fail(format_args!("Could not resolve host: {name}"));
        cx.fail(format_args!("Could not resolve: {name}:{port}"));
        return Ok(None);
    }
    let found = match &looked {
        Ok((_, found)) => Some(*found),
        Err(ConnectError::Unresolved(Unresolved::Negative)) => None,
        Err(ConnectError::Unresolved(_)) => Some(Found::Resolved(Asked::Resolver(None))),
        Err(ConnectError::OutOfMemory) => return Err(BindFailed::OutOfMemory),
        Err(ConnectError::Failed(..)) => unreachable!("a resolve makes no attempt"),
    };
    match found {
        Some(Found::Stale(_)) => {
            cx.info(format_args!("Hostname in DNS cache was stale, zapped"));
        }
        None => cx.of(
            dns,
            format_args!("cache entry does not have type={queries} addresses"),
        ),
        Some(_) => {}
    }
    let (code, not) = match found {
        Some(Found::Cached) => (Ok(()), ""),
        Some(Found::Stale(_) | Found::Resolved(_)) => (Ok(()), "not "),
        None => (Err(ErrorKind::CouldntResolveHost), "not "),
    };
    let code = Code(code);
    cx.of(
        dns,
        format_args!("cache lookup {name}:{port} queries={queries} -> {code} {not}found"),
    );
    if found == Some(Found::Cached) {
        cx.info(format_args!("Hostname {name} was found in DNS cache"));
    }
    match looked {
        Ok((answer, found)) => {
            if let Found::Stale(asked) | Found::Resolved(asked) = found {
                let started = match asked {
                    Asked::Shortcut => 0,
                    Asked::Resolver(_) => AGAIN_NUMBER,
                };
                cx.of(
                    dns,
                    format_args!("[{queries}] hostip_resolv started -> {started}"),
                );
                // Only an answer had at once is said to be kept: one the
                // resolver gives is waited for without a word
                // (`Curl_resolv_blocking`).
                if asked == Asked::Shortcut {
                    cx.of(
                        dns,
                        format_args!("cached entry for {name}:{port} queries={queries}"),
                    );
                }
            }
            Ok(answer.addrs().first().copied())
        }
        Err(ConnectError::Unresolved(why)) => {
            if why != Unresolved::Negative {
                cx.of(
                    dns,
                    format_args!("[{queries}] hostip_resolv started -> {AGAIN_NUMBER}"),
                );
            }
            // With the resolver's reason, if it gives one, as the
            // reference build's c-ares does (`ares_strerror`).
            match why {
                Unresolved::Resolver {
                    explained: Some(reason),
                    ..
                } => cx.fail(format_args!("Could not resolve host: {name} ({reason})")),
                _ => cx.fail(format_args!("Could not resolve host: {name}")),
            }
            Ok(None)
        }
        Err(_) => unreachable!("handled above"),
    }
}
