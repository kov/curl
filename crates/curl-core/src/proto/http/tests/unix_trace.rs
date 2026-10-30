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
/// and nothing. The race asks for the path's one address as C's does,
/// in IPv4's place with no IPv6 asked for. The fake's connect is under
/// way as it starts, where a real one's connects at once, as C's then
/// does with no check traced and nothing asked after.
#[test]
fn a_unix_socket_is_connected_in_place_of_the_host() {
    let at = unix_at("/tmp/t.sock", false);
    let (ran, talk) = over(&at, Peer::Accepts, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(talk.options(), [], "no option of TCP's set");
    assert_eq!(
        setup_lines(&ran),
        lines(
            "[DNS] [A+AAAA] created DNS filter for /tmp/t.sock:0, transport=6
            [DNS] added
            [DNS] [A+AAAA] cf_dns_start unix-domain-socket /tmp/t.sock:0
            [DNS] resolved unix:///tmp/t.sock
            [HAPPY-EYEBALLS] init ip ballers for transport 6
            [HAPPY-EYEBALLS] want to do more
            [HAPPY-EYEBALLS] check for next AAAA address: none
            [DNS] get 0th result for /tmp/t.sock:0, family=1, dns=1
            [HAPPY-EYEBALLS] check for next A address: found
            [HAPPY-EYEBALLS] starting first attempt for ipv6 -> 0
            Trying /tmp/t.sock:0...
            [UNIX] cf_socket_open() -> 0, fd=1000
            [UNIX] local address  port 0...
            [HAPPY-EYEBALLS] checked connect attempts: 1 ongoing, 0 inconclusive
            [DNS] get 1th result for /tmp/t.sock:0, family=1, dns=1
            [DNS] get 1th result for /tmp/t.sock:0, family=1, dns=1
            [HAPPY-EYEBALLS] adjust_pollset -> 0, 1 socks
            [UNIX] connected on fd=1000
            [HAPPY-EYEBALLS] connect attempt #0 successful
            [HAPPY-EYEBALLS] Connected to /tmp/t.sock (/tmp/t.sock) port 0
            [DNS] connected filter chain below
            Established connection to /tmp/t.sock (/tmp/t.sock port 0) from  port 0
            [DNS] removing connected setup filter
            [DNS] destroy
            [HAPPY-EYEBALLS] removing connected setup filter
            [HAPPY-EYEBALLS] destroy
            [UNIX] query ALPN"
        )
    );
    let ends = ran.easy.report().primary().expect("the ends");
    assert_eq!((&ends.remote, ends.local), (&at, None));
}

/// A Unix socket's path longer than the longest IP address's text shows
/// cut to that length wherever its address shows, as C prints it into a
/// buffer of that size (`sockaddr2string`, `MAX_IPADR_LEN`): in the
/// attempt's line, the race's and the connection's, and as the transfer's
/// address; the path itself is whole where it names the socket. C's tool
/// against such a path says the same.
#[test]
fn a_long_unix_socket_path_shows_cut_as_an_address() {
    let path = "/tmp/claude-1000/s66d-unix-socket-path-longer-than-forty-five.sock";
    let cut = &path[..45];
    let at = unix_at(path, false);
    let (ran, _) = over(&at, Peer::Accepts, |_| {});
    assert_eq!(ran.result, Ok(()));
    let shown: Vec<String> = setup_lines(&ran)
        .into_iter()
        .filter(|l| {
            l.starts_with("  Trying ")
                || l.starts_with("Established")
                || l.starts_with("[HAPPY-EYEBALLS] Connected to")
        })
        .collect();
    assert_eq!(
        shown,
        [
            format!("  Trying {cut}:0..."),
            format!("[HAPPY-EYEBALLS] Connected to {path} ({cut}) port 0"),
            format!("Established connection to {path} ({cut} port 0) from  port 0"),
        ]
    );
    let ends = ran.easy.report().primary().expect("the ends");
    assert_eq!(ends.remote.unix_path(), Some(cut.as_bytes()));
}

/// A Unix socket refused ends the race as C's does: looking for another
/// address, its family its own and not IPv4's, it asks for the path's
/// second address before saying it has no IPv6 one, then again for its
/// IPv4 place, and finds none. C's tool against a path nothing listens
/// at traces the same questions.
#[test]
fn a_unix_socket_refused_looks_for_no_other() {
    let at = unix_at("/tmp/t.sock", false);
    let (ran, _) = over(&at, Peer::Refuses, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let raced: Vec<String> = setup_lines(&ran)
        .into_iter()
        .filter(|l| l.starts_with("[HAPPY-EYEBALLS] ") || l.starts_with("[DNS] get "))
        .collect();
    let at = raced
        .iter()
        .position(|l| l == "[HAPPY-EYEBALLS] no more attempts to try")
        .expect("the race ends");
    assert_eq!(
        raced[at - 5..at],
        [
            "[HAPPY-EYEBALLS] want to do more",
            "[DNS] get 1th result for /tmp/t.sock:0, family=1, dns=1",
            "[HAPPY-EYEBALLS] check for next AAAA address: none",
            "[DNS] get 1th result for /tmp/t.sock:0, family=1, dns=1",
            "[HAPPY-EYEBALLS] check for next A address: none",
        ]
    );
}

/// An abstract name shows as nothing where C prints its address, which
/// starts with a zero byte, and as its name where C asks for it.
#[test]
fn an_abstract_name_shows_as_nothing() {
    let at = unix_at("t-abs", true);
    let (ran, _) = over(&at, Peer::Accepts, |_| {});
    assert_eq!(ran.result, Ok(()));
    let lines = setup_lines(&ran);
    assert_eq!(
        lines[7],
        "[DNS] get 0th result for t-abs:0, family=1, dns=1"
    );
    assert_eq!(lines[3], "[DNS] resolved unix://t-abs");
    assert_eq!(lines[10], "  Trying :0...");
    assert_eq!(
        lines[lines.len() - 6..],
        [
            "Established connection to t-abs ( port 0) from  port 0",
            "[DNS] removing connected setup filter",
            "[DNS] destroy",
            "[HAPPY-EYEBALLS] removing connected setup filter",
            "[HAPPY-EYEBALLS] destroy",
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
    // The name's filter is made and starts, and reports no address.
    assert_eq!(
        setup_lines(&ran),
        [
            format!("[DNS] [A+AAAA] created DNS filter for {long}:0, transport=6"),
            "[DNS] added".to_owned(),
            format!("[DNS] [A+AAAA] cf_dns_start unix-domain-socket {long}:0"),
            said,
            format!("Could not resolve: {long}")
        ]
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
