//! The socket filter's trace over a connection's setup (`cf_socket_open`,
//! the local address, `connected on`, `not connected yet on`,
//! `poll/select error on`, `destroy`, `cf_socket_close`) and the multi's
//! `Curl_multi_will_close`, among the race's lines. Each expected sequence
//! is the C build's for the same setup, its descriptors and local ports
//! the fake network's.

use std::net::IpAddr;

use super::*;
use crate::components::Components;
use crate::conn::io::Remote;

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
        "failed to open socket",
        "Failed to connect",
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
    let ran = get_with(&mut m, tracing_tcp(), "/", talk.clone(), |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(talk.made_nonblocking_after(), None, "nonblocking as opened");
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
            Established connection to 127.0.0.1 (127.0.0.1 port {PORT}) from 127.0.0.1 port 40000
            [TCP] query ALPN"
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
            [TCP] destroy
            Failed to connect to 127.0.0.1:{PORT} after 0 ms: Could not connect to server"
        ))
    );
}

/// A connect that polls hung up fails, though the socket says no error,
/// as C fails it on the poll's error alone (`cf_tcp_connect`).
#[test]
fn a_socket_hung_up_without_an_error_fails() {
    let mut m = serving(Peer::HangsUp, &[]);
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
            connect to 127.0.0.1 port {PORT} from 127.0.0.1 port 40000 failed: Success
            [TCP] destroy
            Failed to connect to 127.0.0.1:{PORT} after 0 ms: Could not connect to server"
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
            Established connection to dual.example (127.0.0.1 port {PORT}) from 127.0.0.1 port 40000
            [TCP] query ALPN"
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
            Established connection to two.example (127.0.0.1 port {PORT}) from 127.0.0.1 port 40001
            [TCP] query ALPN"
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

/// A connect failing at once: the socket was opened and traced as it
/// opened, never bound, then closed (C's capture `immediate6`, there
/// unreachable, here refused: no peer is at the address).
#[test]
fn a_connect_failing_at_once_is_traced_as_c() {
    let mut m = serving(Peer::Accepts, &[]);
    let talk = Conversation::replies(&[], false);
    let ran = get_with(&mut m, tracing_tcp(), "/", talk, |o| {
        let url = format!("http://[::1]:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert_eq!(
        socket_lines(&ran),
        expect(&format!(
            "[HAPPY-EYEBALLS] starting first attempt for ipv6 -> 0
              Trying [::1]:{PORT}...
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address :: port 0...
            Immediate connect fail for ::1: Connection refused
            [MULTI] [CONNECTING] Curl_multi_will_close fd=1000
            connect to ::1 port {PORT} from :: port 0 failed: Connection refused
            [TCP] destroy
            Failed to connect to ::1:{PORT} after 0 ms: Could not connect to server"
        ))
    );
}

/// What a test's application does with a transfer's sockets: opens
/// them on the fake network, to `to` if it says so, connecting them
/// itself if `dial`, or opens none if `fail`; says `configured` of each;
/// and keeps the numbers of those it set and closed.
struct Hooks {
    net: Arc<Mutex<FakeNet>>,
    to: Option<SocketAddr>,
    /// The error number an opener that opens nothing leaves.
    fail: Option<i32>,
    dial: bool,
    configured: crate::handler::Configured,
    /// The option the configurer sets, if any.
    mark: Option<crate::conn::io::SocketOption>,
    /// The port the URL names, if not the server's.
    url_port: Option<u16>,
    set: Arc<Mutex<Vec<i32>>>,
    closed: Arc<Mutex<Vec<i32>>>,
}

impl crate::handler::SocketOpener for Hooks {
    fn open(
        &self,
        _: &mut TransferCx<'_>,
        address: &mut Remote,
        kind: crate::conn::io::SocketKind,
    ) -> std::io::Result<Box<dyn crate::conn::io::Socket>> {
        if let Some(errno) = self.fail {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        if let Some(to) = self.to {
            *address = Remote::Inet(to);
        }
        let socket = crate::conn::io::Net::open(&mut *self.net.lock().unwrap(), address, kind)?;
        if self.dial {
            socket.connect(address)?;
        }
        Ok(socket)
    }
}

impl crate::handler::SocketConfigurer for Hooks {
    fn configure(
        &self,
        _: &mut TransferCx<'_>,
        socket: crate::handler::SocketToSet<'_>,
    ) -> crate::handler::Configured {
        self.set.lock().unwrap().push(socket.key().get());
        if let Some(option) = self.mark {
            socket.set(option).unwrap();
        }
        self.configured
    }
}

impl crate::handler::SocketCloser for Hooks {
    fn close(&self, socket: crate::conn::io::SocketKey) {
        self.closed.lock().unwrap().push(socket.get());
    }
}

/// What a run with `hooks` saw: the run, the sockets its configurer was
/// given, and those its closer closed.
struct Hooked {
    ran: Ran,
    talk: Conversation,
    set: Vec<i32>,
    closed: Vec<i32>,
}

/// A GET from a server at `PORT` that does as `peer` says, the
/// application's hooks made by `hooks` over the network.
fn hooked(peer: Peer, hooks: impl FnOnce(&mut Hooks)) -> Hooked {
    use crate::handler::Handler;
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::replies(&[OK], false);
    let net = FakeNet::new(clock.clone())
        .with_peer(at, peer)
        .with_conversation(at, talk.clone());
    let net = Arc::new(Mutex::new(net));
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(crate::conn::io::SharedNet(net.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    let (set, closed) = (Arc::default(), Arc::default());
    let mut h = Hooks {
        net: net.clone(),
        to: None,
        fail: None,
        dial: false,
        configured: crate::handler::Configured::Ok,
        mark: None,
        url_port: None,
        set: Arc::clone(&set),
        closed: Arc::clone(&closed),
    };
    hooks(&mut h);
    let url = format!("http://127.0.0.1:{}/", h.url_port.unwrap_or(PORT));
    let h = Arc::new(h);
    struct Shared(Arc<Hooks>);
    impl crate::handler::SocketOpener for Shared {
        fn open(
            &self,
            cx: &mut TransferCx<'_>,
            a: &mut Remote,
            kind: crate::conn::io::SocketKind,
        ) -> std::io::Result<Box<dyn crate::conn::io::Socket>> {
            self.0.open(cx, a, kind)
        }
    }
    impl crate::handler::SocketConfigurer for Shared {
        fn configure(
            &self,
            cx: &mut TransferCx<'_>,
            s: crate::handler::SocketToSet<'_>,
        ) -> crate::handler::Configured {
            self.0.configure(cx, s)
        }
    }
    impl crate::handler::SocketCloser for Shared {
        fn close(&self, s: crate::conn::io::SocketKey) {
            self.0.close(s);
        }
    }
    let ran = get_with(&mut m, tracing_tcp(), "/", talk.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        let sockets = o.sockets.make_mut().unwrap();
        sockets.open = Some(Handler::socket_opener(Shared(h.clone())).unwrap());
        sockets.configure = Some(Handler::socket_configurer(Shared(h.clone())).unwrap());
        sockets.close = Some(Handler::socket_closer(Shared(h.clone())).unwrap());
    });
    drop(m);
    let set = set.lock().unwrap().clone();
    let closed = closed.lock().unwrap().clone();
    Hooked {
        ran,
        talk,
        set,
        closed,
    }
}

/// An opener that opens nothing fails the attempt before anything about
/// it is known: its addresses are traced empty, and the transfer fails
/// for the open (C's capture `hooks.txt`, mode 0). What the attempt said
/// is let go as the race looks for another address, so the reason kept
/// is the race's: C's error buffer reads the same.
#[test]
fn an_opener_opening_nothing_fails_as_c() {
    // C's errno after a callback that opened nothing: none.
    let h = hooked(Peer::Accepts, |h| h.fail = Some(0));
    assert_eq!(h.ran.result, Err(ErrorKind::CouldntConnect));
    assert_eq!(
        socket_lines(&h.ran),
        expect(&format!(
            "[HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0
            failed to open socket: Success
            [TCP] cf_socket_open() -> 7, fd=-1
            connect to  port 0 from  port 0 failed: Success
            [TCP] destroy
            Failed to connect to 127.0.0.1:{PORT} after 0 ms: Could not connect to server"
        ))
    );
    let race =
        format!("Failed to connect to 127.0.0.1:{PORT} after 0 ms: Could not connect to server");
    assert_eq!(
        h.ran.easy.report().failure(),
        Some(race.as_bytes()),
        "the attempt's reason is let go"
    );
    assert!(h.set.is_empty() && h.closed.is_empty());
}

/// An opener out of memory opens nothing like any other: the attempt
/// fails, not the transfer for memory, as only the system's socket
/// running out is (`socket_open`).
#[test]
fn an_opener_out_of_memory_fails_its_attempt() {
    let h = hooked(Peer::Accepts, |h| h.fail = Some(12));
    assert_eq!(h.ran.result, Err(ErrorKind::CouldntConnect));
    let lines = socket_lines(&h.ran);
    assert!(
        lines
            .iter()
            .any(|l| l == "failed to open socket: Cannot allocate memory"),
        "{lines:?}"
    );
}

/// A configurer that fails the socket has it closed through the closer,
/// and the transfer fails as aborted (C's capture, mode 1).
#[test]
fn a_configurer_failing_a_socket_aborts_as_c() {
    let h = hooked(Peer::Accepts, |h| {
        h.configured = crate::handler::Configured::Abort;
    });
    assert_eq!(h.ran.result, Err(ErrorKind::AbortedByCallback));
    assert_eq!(
        socket_lines(&h.ran),
        expect(&format!(
            "[HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0
              Trying 127.0.0.1:{PORT}...
            [MULTI] [CONNECTING] Curl_multi_will_close fd=1000
            [TCP] cf_socket_open() -> 42, fd=-1
            connect to 127.0.0.1 port {PORT} from  port 0 failed: Success
            [TCP] destroy
            Failed to connect to 127.0.0.1:{PORT} after 0 ms: Operation was aborted by an application callback"
        ))
    );
    assert_eq!((h.set, h.closed), (vec![1000], vec![1000]));
}

/// A socket the application connected skips its connect: it wins as it
/// opens (C's capture, mode 2).
#[test]
fn a_socket_already_connected_wins_as_it_opens() {
    let h = hooked(Peer::Accepts, |h| {
        h.dial = true;
        h.configured = crate::handler::Configured::AlreadyConnected;
    });
    assert_eq!(h.ran.result, Ok(()));
    let lines = socket_lines(&h.ran);
    assert_eq!(
        lines[..5],
        expect(&format!(
            "[HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0
              Trying 127.0.0.1:{PORT}...
            [TCP] cf_socket_open() -> 0, fd=1000
            [HAPPY-EYEBALLS] connect attempt #0 successful
            [HAPPY-EYEBALLS] Connected to 127.0.0.1 (127.0.0.1) port {PORT}"
        ))
    );
    assert_eq!(
        lines[5],
        format!(
            "Established connection to 127.0.0.1 (127.0.0.1 port {PORT}) from 127.0.0.1 port 40000"
        )
    );
    assert_eq!(h.set, [1000]);
    assert_eq!(
        h.talk.made_nonblocking_after(),
        Some(1),
        "after the options set"
    );
}

/// A configurer sets its socket's options after the library's, and the
/// application's socket is made nonblocking after both
/// (`cf_socket_open`).
#[test]
fn a_configurer_sets_its_socket_s_options() {
    use crate::conn::io::SocketOption;
    let h = hooked(Peer::Accepts, |h| h.mark = Some(SocketOption::Priority(3)));
    assert_eq!(h.ran.result, Ok(()));
    assert_eq!(
        h.talk.options(),
        [SocketOption::NoDelay, SocketOption::Priority(3)]
    );
    assert_eq!(h.talk.made_nonblocking_after(), Some(2));
}

/// An opener may change the address, which the attempt then connects to
/// and traces (C's capture, mode 3).
#[test]
fn an_opener_may_change_the_address() {
    // The URL names a port nothing is at; the opener points to the
    // server's.
    let h = hooked(Peer::Accepts, |h| {
        h.url_port = Some(PORT + 1);
        h.to = Some(SocketAddr::from(([127, 0, 0, 1], PORT)));
    });
    assert_eq!(h.ran.result, Ok(()));
    assert_eq!(
        socket_lines(&h.ran)[..4],
        expect(&format!(
            "[HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0
              Trying 127.0.0.1:{PORT}...
            [TCP] cf_socket_open() -> 0, fd=1000
            [TCP] local address 127.0.0.1 port 40000..."
        ))
    );
    // The application's socket is made nonblocking once set: here after
    // the `TCP_NODELAY` the library sets.
    assert_eq!(h.talk.made_nonblocking_after(), Some(1));
}

/// What a GET of a name with an IPv6 and an IPv4 address told the
/// application of its reasons for failing, its IPv6 peer answering as
/// `v6` says and the opener opening no socket for the families
/// `refused`.
fn told_by_two_attempts(v6: Option<Peer>, refused: &'static [bool]) -> (Ran, Vec<Vec<u8>>) {
    use crate::handler::{Handler, SocketOpener, TextSink};
    struct Refusing(Arc<Mutex<FakeNet>>, &'static [bool]);
    impl SocketOpener for Refusing {
        fn open(
            &self,
            _: &mut TransferCx<'_>,
            address: &mut Remote,
            kind: crate::conn::io::SocketKind,
        ) -> std::io::Result<Box<dyn crate::conn::io::Socket>> {
            let v6 = address.inet().is_some_and(|a| a.is_ipv6());
            if self.1[usize::from(v6)] {
                return Err(std::io::Error::from_raw_os_error(0));
            }
            crate::conn::io::Net::open(&mut *self.0.lock().unwrap(), address, kind)
        }
    }
    #[derive(Clone, Default)]
    struct Told(Arc<Mutex<Vec<Vec<u8>>>>);
    impl TextSink for Told {
        fn write(&self, text: &[u8]) {
            self.0.lock().unwrap().push(text.to_vec());
        }
    }
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let at6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, PORT));
    let talk = Conversation::replies(&[OK], false);
    let both: [IpAddr; 2] = [at6.ip(), at.ip()];
    let mut net = FakeNet::new(clock.clone())
        .with_name("both.example", &both)
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    if let Some(v6) = v6 {
        net = net.with_peer(at6, v6).with_conversation(at6, talk.clone());
    }
    let net = Arc::new(Mutex::new(net));
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(crate::conn::io::SharedNet(net.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    let told = Told::default();
    let ran = get_with(&mut m, tracing_tcp(), "/", talk, |o| {
        let url = format!("http://both.example:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        let sockets = o.sockets.make_mut().unwrap();
        sockets.open = Some(Handler::socket_opener(Refusing(net.clone(), refused)).unwrap());
        o.callbacks.failure = Some(Handler::text(told.clone()).unwrap());
    });
    let told = told.0.lock().unwrap().clone();
    (ran, told)
}

/// An attempt that fails as the race starts it gives its reason, let go
/// as the race starts the next; the race failing lets go of the last
/// and gives its own, as C's error buffer reads (`Curl_reset_fail`).
#[test]
fn each_attempt_s_reason_is_let_go_as_the_race_goes_on() {
    let (ran, told) = told_by_two_attempts(None, &[true, true]);
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let open = b"failed to open socket: Success".to_vec();
    let race =
        format!("Failed to connect to both.example:{PORT} after 0 ms: Could not connect to server");
    assert_eq!(
        told,
        [
            open.clone(),
            Vec::new(),
            open,
            Vec::new(),
            race.into_bytes()
        ]
    );
}

/// An attempt that connects lets go of what one started after it said:
/// no reason is kept, and what the application was told is emptied.
#[test]
fn a_reason_is_let_go_as_an_attempt_connects() {
    let slow = Peer::AcceptsAfter(std::time::Duration::from_millis(300));
    let (ran, told) = told_by_two_attempts(Some(slow), &[true, false]);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.easy.report().failure(), None);
    assert_eq!(told, [&b"failed to open socket: Success"[..], b""]);
}
