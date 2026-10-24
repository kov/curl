//! A transfer over a Unix socket the options name
//! (`CURLOPT_UNIX_SOCKET_PATH`, `CURLOPT_ABSTRACT_UNIX_SOCKET`): connected
//! to in place of the host and of any proxy, its socket's filter tracing
//! as `UNIX`. Each expected sequence is the C build's for the same setup,
//! its descriptors the fake network's.

use super::*;
use crate::components::Components;
use crate::conn::io::{Remote, UnixPeer};
use crate::conn::{Peer as Host, Scheme};
use crate::options::UnixSocket;

/// A handle tracing the socket, the race and the names.
fn tracing() -> Easy {
    let mut e = Easy::new();
    let components = Components::new().unwrap();
    components.configure(b"tcp,unix,happy-eyeballs,dns");
    e.set_components(Some(components));
    e
}

/// The Unix socket at `path`, or of the abstract name.
fn unix_at(path: &str, abstract_name: bool) -> Remote {
    let scheme = Scheme {
        name: "http",
        reuse: true,
    };
    let peer = Host::unix(scheme, path.as_bytes().to_vec(), 0, abstract_name);
    Remote::Unix(UnixPeer::of(curl_alloc::TryArc::try_new(peer).unwrap()))
}

/// A GET over the Unix socket `at`, which a peer listens at as `peer`
/// says, as `set` and the options naming it set up the transfer.
fn over(at: &Remote, peer: Peer, set: impl FnOnce(&mut Options)) -> (Ran, Conversation) {
    let clock = ManualClock::new().unwrap();
    let talk = Conversation::replies(&[OK], false);
    let net = FakeNet::new(clock.clone())
        .with_peer_at(at.clone(), peer)
        .with_conversation_at(at.clone(), talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    let Remote::Unix(u) = at else {
        panic!("a Unix socket");
    };
    let unix = UnixSocket {
        path: u.path().to_vec(),
        abstract_name: u.is_abstract(),
    };
    let ran = get_with(&mut m, tracing(), "/", talk.clone(), |o| {
        o.sockets.make_mut().unwrap().unix = Some(unix);
        set(o);
    });
    (ran, talk)
}

/// The lines about the names, the race and the socket, but the socket's
/// sends, receives and pollset.
fn setup_lines(ran: &Ran) -> Vec<String> {
    let said = [
        "  Trying ",
        "Immediate connect fail",
        "connect to ",
        "Established connection",
        "Failed to connect",
        "Unix socket path",
        "Could not resolve",
    ];
    ran.seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| {
            let socket = l.strip_prefix("[UNIX] ").is_some_and(|rest| {
                !["send(", "recv(", "adjust_pollset"]
                    .iter()
                    .any(|p| rest.starts_with(p))
            });
            socket
                || l.starts_with("[TCP] ")
                || (l.starts_with("[DNS] ") && !l.contains("] Curl_conn_connect("))
                || l.starts_with("[HAPPY-EYEBALLS] ")
                || said.iter().any(|p| l.starts_with(p))
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

/// The socket at the path is connected to, its address made, not looked
/// up, and its filter traced as `UNIX`; the transfer's ends are the path
/// and nothing.
#[test]
fn a_unix_socket_is_connected_in_place_of_the_host() {
    let at = unix_at("/tmp/t.sock", false);
    let (ran, talk) = over(&at, Peer::Accepts, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(talk.options(), [], "no option of TCP's set");
    assert_eq!(
        setup_lines(&ran),
        lines(
            "[HAPPY-EYEBALLS] starting first attempt for ipv6 -> 0
            Trying /tmp/t.sock:0...
            [UNIX] cf_socket_open() -> 0, fd=1000
            [UNIX] local address  port 0...
            [UNIX] connected on fd=1000
            [HAPPY-EYEBALLS] connect attempt #0 successful
            [HAPPY-EYEBALLS] Connected to /tmp/t.sock (/tmp/t.sock) port 0
            Established connection to /tmp/t.sock (/tmp/t.sock port 0) from  port 0
            [UNIX] query ALPN"
        )
    );
    let ends = ran.easy.report().primary().expect("the ends");
    assert_eq!((&ends.remote, ends.local), (&at, None));
}

/// An abstract name shows as nothing where C prints its address, which
/// starts with a zero byte.
#[test]
fn an_abstract_name_shows_as_nothing() {
    let at = unix_at("t-abs", true);
    let (ran, _) = over(&at, Peer::Accepts, |_| {});
    assert_eq!(ran.result, Ok(()));
    let lines = setup_lines(&ran);
    assert_eq!(lines[1], "  Trying :0...");
    assert_eq!(
        lines[lines.len() - 2..],
        [
            "Established connection to t-abs ( port 0) from  port 0",
            "[UNIX] query ALPN"
        ]
    );
}

/// A socket nothing listens at fails the transfer, named as the way to
/// the origin.
#[test]
fn a_unix_socket_refused_fails_over_it() {
    let at = unix_at("/tmp/t.sock", false);
    let (ran, _) = over(&at, Peer::Refuses, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let failure = format!(
        "Failed to connect to 127.0.0.1:{PORT} over unix:///tmp/t.sock after 0 ms: \
         Could not connect to server"
    );
    assert_eq!(ran.easy.report().failure(), Some(failure.as_bytes()));
}

/// A proxy is not gone through over a Unix socket: the request names the
/// path alone, and goes to the socket.
#[test]
fn a_proxy_is_not_gone_through_over_a_unix_socket() {
    let at = unix_at("/tmp/t.sock", false);
    let (ran, _) = over(&at, Peer::Accepts, |o| {
        o.proxy.make_mut().unwrap().url = Some(b"http://proxy.example:3128".to_vec());
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.request, request_of("/"));
    assert!(!ran.easy.report().used_proxy());
}

/// A path its address cannot hold fails the transfer as a name not
/// resolved, before any socket opens (`resolv_unix`).
#[test]
fn a_path_too_long_is_not_resolved() {
    let long = format!("/tmp/{}", "x".repeat(curl_os::net::UNIX_PATH_ROOM - 5));
    let at = unix_at(&long, false);
    let (ran, _) = over(&at, Peer::Accepts, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::CouldntResolveHost));
    let said = format!("Unix socket path too long: '{long}'");
    assert_eq!(ran.easy.report().failure(), Some(said.as_bytes()));
    assert_eq!(
        setup_lines(&ran),
        [said, format!("Could not resolve: {long}")]
    );
}

/// An empty path fails the transfer, unsaid (`Curl_peer_uds_create`).
#[test]
fn an_empty_path_fails_the_transfer() {
    let at = unix_at("/tmp/t.sock", false);
    let (ran, _) = over(&at, Peer::Accepts, |o| {
        o.sockets
            .make_mut()
            .unwrap()
            .unix
            .as_mut()
            .unwrap()
            .path
            .clear();
    });
    assert_eq!(ran.result, Err(ErrorKind::FailedInit));
    assert_eq!(ran.easy.report().failure(), None);
}
