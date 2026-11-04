//! A socket's local end bound before it connects (`bindlocal` in
//! cf-socket.c): to an interface by its name, else to the address an
//! interface or a name has, and to a port, the ports of a range tried in
//! turn. Its traces and failures are C's.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use super::connect::{ConnCx, DriveOptions, Held, resolve_blocking};
use super::io::{AF_INET, AF_INET6, Family, InterfaceAddress, Socket, SocketOption, ipv6_scope};
use crate::conn::layer::LayerCalls as _;
use crate::error::ErrorKind;
use crate::options::LocalBind;
use crate::text::Text;
use curl_os::error::ErrorText;

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
/// address is taken (`bindlocal`). Whether it was bound to an address or a
/// port (`bits.bound`), not merely to an interface by its name, or nothing.
pub(super) fn bind_local(
    cx: &mut dyn ConnCx,
    socket: &dyn Socket,
    remote: SocketAddr,
    bind: &LocalBind,
    scope_id: u32,
    setup: DriveOptions,
) -> Result<bool, BindFailed> {
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
        return Ok(false);
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
            None => return Ok(false),
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
                return Ok(true);
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
    let n = Text::<48>::clipped(format_args!("bind failed with errno {n}: ")).0;
    cx.fail_with(&[n.bytes(), ErrorText::of(&error).as_bytes()]);
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
    setup: DriveOptions,
) -> Result<Option<(IpAddr, u32)>, BindFailed> {
    let v6 = remote.is_ipv6();
    let af = if v6 { AF_INET6 } else { AF_INET };
    // An interface bound to by name, unless a host is named too: not
    // allowed to most users, it fails then, and its address is looked
    // for instead. Windows has no binding by name (`SO_BINDTODEVICE`), so
    // C looks for the address alone there.
    #[cfg(windows)]
    let (by_name, _unused): (Option<io::Error>, _) = (None, socket);
    #[cfg(unix)]
    let mut by_name = None;
    #[cfg(unix)]
    if let Some(name) = iface {
        match socket.bind_to_device(name) {
            Ok(()) if !host_in => {
                cx.info_with(&[b"socket successfully bound to interface '", name, b"'"]);
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
                let n = Text::<32>::clipped(format_args!("' with errno {n}: ")).0;
                cx.fail_with(&[
                    b"Could not bind to interface '",
                    name,
                    n.bytes(),
                    ErrorText::of(&error).as_bytes(),
                ]);
                return Err(BindFailed::Failed(ErrorKind::InterfaceFailed));
            }
            InterfaceAddress::NotFound => {}
            InterfaceAddress::OtherFamily => return Err(BindFailed::OtherFamily),
            InterfaceAddress::Found(ip, scope) => {
                host_text = Text::clipped(format_args!("{ip}{}", Scope(scope))).0;
                host = host_text.bytes();
                let af = Text::<32>::clipped(format_args!(" using address family {af}")).0;
                cx.info_with(&[b"Local Interface ", name, b" is ip ", host, af.bytes()]);
                found = Some((ip, scope));
            }
        }
    }
    if !iface_in || host_in {
        // Not an interface: a name or an address, of the family connected
        // over alone.
        found = match resolve_host(cx, host, v6, setup)? {
            // Let go of once said, as C does (`Curl_dns_entry_unlink`).
            Some(held) => {
                let ip = held.addrs().first().copied();
                if let Some(ip) = ip {
                    let h_af = if ip.is_ipv6() { AF_INET6 } else { AF_INET };
                    let rest = Text::<128>::clipped(format_args!(
                        "' family {af} resolved to '{ip}' family {h_af}"
                    ))
                    .0;
                    cx.info_with(&[b"Name '", host, rest.bytes()]);
                }
                held.let_go(cx);
                match ip {
                    Some(ip) if ip.is_ipv6() != v6 => return Err(BindFailed::OtherFamily),
                    Some(ip) => Some((ip, 0)),
                    None => None,
                }
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
            let n = Text::<32>::clipped(format_args!("' with errno {n}: ")).0;
            cx.fail_with(&[
                b"Could not bind to '",
                host,
                n.bytes(),
                ErrorText::of(&error).as_bytes(),
            ]);
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

/// The addresses of the family IPv6 if `v6`, else IPv4, `host` stands
/// for, resolved as C's blocking resolve does it (`Curl_resolv_blocking`,
/// for port 80), held until let go of. `None` if it has none.
fn resolve_host(
    cx: &mut dyn ConnCx,
    host: &[u8],
    v6: bool,
    setup: DriveOptions,
) -> Result<Option<Held>, BindFailed> {
    let family = if v6 { Family::V6 } else { Family::V4 };
    match resolve_blocking(cx, host, BIND_RESOLVE_PORT, family, setup) {
        Ok(held) => Ok(held),
        Err(ErrorKind::OutOfMemory) => Err(BindFailed::OutOfMemory),
        Err(kind) => Err(BindFailed::Failed(kind)),
    }
}
