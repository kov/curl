//! The socket filter's trace over a connection's setup (`cf_socket_open`,
//! the local address, `connected on`, `not connected yet on`,
//! `poll/select error on`, `destroy`, `cf_socket_close`) and the multi's
//! `Curl_multi_will_close`, among the race's lines. Each expected sequence
//! is the C build's for the same setup, its descriptors and local ports
//! the fake network's.

use std::net::IpAddr;

use super::*;
use crate::components::Components;

/// A handle tracing the socket, the race and the multi.
fn tracing_tcp() -> Easy {
    let mut e = Easy::new();
    let components = Components::new().unwrap();
    components.configure(b"tcp,happy-eyeballs,multi,setup,http-proxy,h1-proxy");
    e.set_components(Some(components));
    e
}

/// The lines of a run about its sockets: the socket filter's but its
/// sends, receives and pollset, the race's attempts, the multi's closes,
/// and the lines that say where an attempt went.
fn socket_lines(ran: &Ran) -> Vec<String> {
    let race = [
        "starting ",
        "happy eyeballs timeout expired",
        "connect attempt #",
        "discarding oldest",
        "Connected to",
    ];
    let said = [
        "  Trying ",
        "connect to ",
        "Immediate connect fail",
        "Established connection",
        "[SETUP] retrying",
        "[HTTP-PROXY] destroy",
        "[H1-PROXY] destroy",
    ];
    ran.seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| {
            let tcp = l.strip_prefix("[TCP] ").is_some_and(|rest| {
                !["send(", "recv(", "adjust_pollset"]
                    .iter()
                    .any(|p| rest.starts_with(p))
            });
            let he = l
                .strip_prefix("[HAPPY-EYEBALLS] ")
                .is_some_and(|rest| race.iter().any(|p| rest.starts_with(p)));
            tcp || he
                || l.contains("Curl_multi_will_close")
                || said.iter().any(|p| l.starts_with(p))
        })
        .collect()
}

/// The lines of `lines`, as indented here; C's `Trying` lines keep their
/// own two spaces.
fn expect(lines: &str) -> Vec<String> {
    lines
        .lines()
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

/// A multi whose network knows `name` as `addrs`, with a peer at each on
/// `PORT`, the one accepting holding `talk`.
fn named(name: &str, peers: &[(IpAddr, Peer)], talk: &Conversation) -> Multi {
    let clock = ManualClock::new().unwrap();
    let addrs: Vec<IpAddr> = peers.iter().map(|&(ip, _)| ip).collect();
    let mut net = FakeNet::new(clock.clone()).with_name(name, &addrs);
    for &(ip, peer) in peers {
        let at = SocketAddr::new(ip, PORT);
        net = net.with_peer(at, peer);
        if matches!(peer, Peer::Accepts) {
            net = net.with_conversation(at, talk.clone());
        }
    }
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    Multi::new(env).unwrap()
}

fn v4(last: u8) -> IpAddr {
    IpAddr::from([127, 0, 0, last])
}

/// A direct connection: its socket opened, then found connected in the
/// next call.
#[test]
fn a_socket_s_setup_is_traced_as_c() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, tracing_tcp(), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        socket_lines(&ran),
        expect(&format!(
            "[HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0
              Trying 127.0.0.1:{PORT}...
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address 127.0.0.1 port 40000...
            [TCP] connected on fd=1000
            [HAPPY-EYEBALLS] connect attempt #0 successful
            [HAPPY-EYEBALLS] Connected to 127.0.0.1 (127.0.0.1) port {PORT}
            Established connection to 127.0.0.1 (127.0.0.1 port {PORT}) from 127.0.0.1 port 40000"
        ))
    );
}

/// A refused connect polls in error; its socket is closed, said to the
/// multi, before the failure is, and its filter goes after.
#[test]
fn a_refused_socket_is_traced_as_c() {
    let mut m = serving(Peer::Refuses, &[]);
    let talk = Conversation::replies(&[], false);
    let ran = get_with(&mut m, tracing_tcp(), "/", talk, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert_eq!(
        socket_lines(&ran),
        expect(&format!(
            "[HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0
              Trying 127.0.0.1:{PORT}...
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address 127.0.0.1 port 40000...
            [TCP] poll/select error on fd=1000
            [MULTI] [CONNECTING] Curl_multi_will_close fd=1000
            connect to 127.0.0.1 port {PORT} from 127.0.0.1 port 40000 failed: Connection refused
            [TCP] destroy"
        ))
    );
}

/// An IPv6 address refused, then an IPv4 one taken: the descriptor the
/// first closed is the second's (the fake network's local port goes with
/// it).
#[test]
fn a_refused_family_gives_way_to_the_next() {
    let talk = Conversation::replies(&[OK], false);
    let v6 = IpAddr::from(std::net::Ipv6Addr::LOCALHOST);
    let mut m = named(
        "dual.example",
        &[(v6, Peer::Refuses), (v4(1), Peer::Accepts)],
        &talk,
    );
    let ran = get_with(&mut m, tracing_tcp(), "/", talk, |o| {
        let url = format!("http://dual.example:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let lines = socket_lines(&ran);
    assert_eq!(
        lines,
        expect(&format!(
            "[HAPPY-EYEBALLS] starting first attempt for ipv6 -> 0
              Trying [::1]:{PORT}...
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address ::1 port 40000...
            [TCP] poll/select error on fd=1000
            [MULTI] [CONNECTING] Curl_multi_will_close fd=1000
            connect to ::1 port {PORT} from ::1 port 40000 failed: Connection refused
            [TCP] destroy
            [HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0
              Trying 127.0.0.1:{PORT}...
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address 127.0.0.1 port 40000...
            [TCP] connected on fd=1000
            [HAPPY-EYEBALLS] connect attempt #0 successful
            [HAPPY-EYEBALLS] Connected to dual.example (127.0.0.1) port {PORT}
            Established connection to dual.example (127.0.0.1 port {PORT}) from 127.0.0.1 port 40000"
        ))
    );
}

/// A silent address, then one that answers once the eyeballs delay has
/// passed: the first is checked again before the second is opened, and
/// closes as the second wins.
#[test]
fn a_losing_attempt_is_closed_as_c_closes_it() {
    let talk = Conversation::replies(&[OK], false);
    let silent = IpAddr::from([192, 0, 2, 1]);
    let mut m = named(
        "two.example",
        &[(silent, Peer::Silent), (v4(1), Peer::Accepts)],
        &talk,
    );
    let ran = get_with(&mut m, tracing_tcp(), "/", talk, |o| {
        let url = format!("http://two.example:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        socket_lines(&ran),
        expect(&format!(
            "[HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0
              Trying 192.0.2.1:{PORT}...
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address 127.0.0.1 port 40000...
            [TCP] not connected yet on fd=1000
            [HAPPY-EYEBALLS] happy eyeballs timeout expired, start next attempt
            [HAPPY-EYEBALLS] starting next attempt for ipv4 -> 0
            [TCP] not connected yet on fd=1000
              Trying 127.0.0.1:{PORT}...
            [TCP] cf_socket_open() -> 0, fd=1001
            [TCP] local address 127.0.0.1 port 40001...
            [TCP] not connected yet on fd=1000
            [TCP] connected on fd=1001
            [HAPPY-EYEBALLS] connect attempt #1 successful
            [TCP] destroy
            [TCP] cf_socket_close, fd=1000
            [MULTI] [CONNECTING] Curl_multi_will_close fd=1000
            [HAPPY-EYEBALLS] Connected to two.example (127.0.0.1) port {PORT}
            Established connection to two.example (127.0.0.1 port {PORT}) from 127.0.0.1 port 40001"
        ))
    );
}

/// A proxy that closes on its 407 has the setup start over: the tunnel's
/// filters and the socket's go, the socket closed, and the race starts
/// again.
#[test]
fn a_redial_closes_the_socket_as_c() {
    let challenge: &[u8] = b"HTTP/1.1 407 Who\r\n\
        Proxy-Authenticate: Basic realm=\"p\"\r\nConnection: close\r\n\
        Content-Length: 0\r\n\r\n";
    let first = Conversation::replies(&[challenge], true).late_replies();
    let second = Conversation::replies(&[TUNNEL_UP, OK], false).late_replies();
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let ran = get_with(&mut m, tracing_tcp(), "/", second, |o| {
        tunneled(o);
        o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
        o.proxy.make_mut().unwrap().auth = crate::options::HttpAuth(AuthMethods::ANY);
    });
    assert_eq!(ran.result, Ok(()));
    let attempt = || {
        format!(
            "[HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0
              Trying 127.0.0.1:{PORT}...
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address 127.0.0.1 port 40000...
            [TCP] connected on fd=1000
            [HAPPY-EYEBALLS] connect attempt #0 successful
            [HAPPY-EYEBALLS] Connected to 127.0.0.1 (127.0.0.1) port {PORT}"
        )
    };
    // The descriptor closed is opened again, with the fake network's local
    // port for it.
    let mut want = expect(&attempt());
    want.extend(expect(
        "[SETUP] retrying connect, 1. time
        [HTTP-PROXY] destroy
        [H1-PROXY] destroy
        [TCP] destroy
        [TCP] cf_socket_close, fd=1000
        [MULTI] [CONNECTING] Curl_multi_will_close fd=1000",
    ));
    want.extend(expect(&attempt()));
    want.extend(expect(&format!(
        "Established connection to 127.0.0.1 (127.0.0.1 port {PORT}) from 127.0.0.1 port 40000
        [HTTP-PROXY] destroy"
    )));
    assert_eq!(socket_lines(&ran), want);
}
