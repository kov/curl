//! A socket's local end bound before it connects (`bindlocal`): to a
//! port of a range, to an interface by its name, to the address an
//! interface or a name has. Each expected sequence is the C build's for
//! the same setup, its descriptors and local ports the fake network's.

use std::net::IpAddr;

use super::*;
use crate::components::Components;
use crate::options::{Interface, LocalBind};

/// A handle tracing the socket.
fn tracing_tcp() -> Easy {
    let mut e = Easy::new();
    let components = Components::new().unwrap();
    components.configure(b"tcp");
    e.set_components(Some(components));
    e
}

/// The lines of a run about binding and its socket, but the socket's
/// sends, receives and pollset.
fn bind_lines(ran: &Ran) -> Vec<String> {
    let said = [
        "  Trying ",
        "Local port",
        "Bind to local port",
        "bind failed",
        "socket successfully bound",
        "Local Interface",
        "Name '",
        "Could not bind",
        "connect to ",
        "Failed to connect",
        "Established connection",
    ];
    ran.seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| {
            let tcp = l.strip_prefix("[TCP] ").is_some_and(|rest| {
                !["send(", "recv(", "adjust_pollset", "query ALPN"]
                    .iter()
                    .any(|p| rest.starts_with(p))
            });
            tcp || said.iter().any(|p| l.starts_with(p))
        })
        .collect()
}

fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            if l.starts_with("Trying ") {
                format!("  {l}")
            } else {
                l.to_owned()
            }
        })
        .collect()
}

/// A GET from a server at 127.0.0.1 on a network `net` makes of the
/// fake one, its sockets bound as `bind` says.
fn bound(net: impl FnOnce(FakeNet) -> FakeNet, bind: LocalBind) -> Ran {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::replies(&[OK], false);
    let fake = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net(fake)),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    get_with(&mut m, tracing_tcp(), "/", talk, |o| {
        o.sockets.make_mut().unwrap().local = bind;
    })
}

fn interface(given: &str) -> LocalBind {
    LocalBind {
        interface: Interface::parse(given.as_bytes()).unwrap(),
        ..LocalBind::NONE
    }
}

fn ports(port: u16, port_range: u16) -> LocalBind {
    LocalBind {
        port,
        port_range,
        ..LocalBind::NONE
    }
}

/// A port in use is passed over for the next of the range.
#[test]
fn a_port_in_use_gives_way_to_the_next_of_the_range() {
    let ran = bound(|n| n.with_port_in_use(18700), ports(18700, 2));
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        bind_lines(&ran),
        lines(&format!(
            "Trying 127.0.0.1:{PORT}...
            Bind to local port 18700 failed, trying next
            Local port: 18701
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address 127.0.0.1 port 18701...
            [TCP] connected on fd=1000
            Established connection to 127.0.0.1 (127.0.0.1 port {PORT}) from 127.0.0.1 port 18701"
        ))
    );
}

/// With every port of the range in use the attempt fails, the bind's
/// reason given way to the connect's.
#[test]
fn a_range_all_in_use_fails_to_bind() {
    let ran = bound(
        |n| n.with_port_in_use(18700).with_port_in_use(18701),
        ports(18700, 2),
    );
    assert_eq!(ran.result, Err(ErrorKind::InterfaceFailed));
    assert_eq!(
        bind_lines(&ran),
        lines(&format!(
            "Trying 127.0.0.1:{PORT}...
            Bind to local port 18700 failed, trying next
            bind failed with errno 98: Address already in use
            [TCP] cf_socket_open() -> 45, fd=-1
            connect to 127.0.0.1 port {PORT} from  port 0 failed: Success
            [TCP] destroy
            Failed to connect to 127.0.0.1:{PORT} after 0 ms: Failed binding local connection end"
        ))
    );
    let said = format!(
        "Failed to connect to 127.0.0.1:{PORT} after 0 ms: Failed binding local connection end"
    );
    assert_eq!(ran.easy.report().failure(), Some(said.as_bytes()));
}

/// A plain name binds to the interface of that name, and to nothing
/// else.
#[test]
fn a_name_binds_to_its_interface() {
    let ran = bound(|n| n.with_device("eth9"), interface("eth9"));
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        bind_lines(&ran)[..3],
        lines(&format!(
            "Trying 127.0.0.1:{PORT}...
            socket successfully bound to interface 'eth9'
            [TCP] cf_socket_open() -> 0, fd=1000"
        ))
    );
}

/// An interface that cannot be bound to by name is bound to by its
/// address.
#[test]
fn an_interface_is_bound_to_by_its_address() {
    let ip = IpAddr::from([127, 0, 0, 5]);
    let ran = bound(|n| n.with_interface("eth9", ip, 0), interface("if!eth9"));
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        bind_lines(&ran)[..5],
        lines(&format!(
            "Trying 127.0.0.1:{PORT}...
            Local Interface eth9 is ip 127.0.0.5 using address family 2
            Local port: 0
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address 127.0.0.5 port 40000..."
        ))
    );
}

/// An interface the system does not have fails the attempt, with the
/// reason the bind by name gave.
#[test]
fn an_interface_not_there_fails_to_bind() {
    let ran = bound(|n| n, interface("if!nonexist"));
    assert_eq!(ran.result, Err(ErrorKind::InterfaceFailed));
    assert_eq!(
        bind_lines(&ran)[..3],
        lines(&format!(
            "Trying 127.0.0.1:{PORT}...
            Could not bind to interface 'nonexist' with errno 19: No such device
            [TCP] cf_socket_open() -> 45, fd=-1"
        ))
    );
}

/// A host's address of the other family fails the attempt, as one that
/// could not connect: the next address would be tried.
#[test]
fn a_host_of_the_other_family_cannot_connect() {
    let ran = bound(|n| n, interface("host!::1"));
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert_eq!(
        bind_lines(&ran)[..3],
        lines(&format!(
            "Trying 127.0.0.1:{PORT}...
            Name '::1' family 2 resolved to '::1' family 10
            [TCP] cf_socket_open() -> 7, fd=-1"
        ))
    );
}

/// A host's name is resolved for its address, which is bound to.
#[test]
fn a_host_s_name_is_bound_to_as_resolved() {
    let ip = IpAddr::from([127, 0, 0, 7]);
    let ran = bound(
        |n| n.with_name("bindhost", &[ip]),
        interface("host!bindhost"),
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        bind_lines(&ran)[..5],
        lines(&format!(
            "Trying 127.0.0.1:{PORT}...
            Name 'bindhost' family 2 resolved to '127.0.0.7' family 2
            Local port: 0
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address 127.0.0.7 port 40000..."
        ))
    );
}

/// An interface named with a host is bound to by name, and the host's
/// address bound to as well.
#[test]
fn an_interface_with_a_host_binds_to_both() {
    let ran = bound(
        |n| n.with_device("eth9"),
        interface("ifhost!eth9!127.0.0.7"),
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        bind_lines(&ran)[..5],
        lines(&format!(
            "Trying 127.0.0.1:{PORT}...
            Name '127.0.0.7' family 2 resolved to '127.0.0.7' family 2
            Local port: 0
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address 127.0.0.7 port 40000..."
        ))
    );
}
