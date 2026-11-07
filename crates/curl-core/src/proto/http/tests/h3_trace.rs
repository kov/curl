//! The race over QUIC (`cf-ip-happy.c` with `cf-ngtcp2.c`'s connect),
//! through the fake TLS and HTTP/3 libraries: each attempt a QUIC
//! connection over its UDP socket, won by its handshake once its peer is
//! checked. Each expected sequence is the C build's against a local
//! server with `--http3-only`, `build/m5-c-h3-get.trace` and
//! `build/m5-c-h3-badca.trace`, but for what the fakes do apart: their
//! packets' sizes, a server that answers at once, and its address's port.

use std::sync::{Arc, Mutex};

use super::*;
use crate::components::Components;
use crate::http3::fake::{FakeHttp3, Script, Told};
use crate::libraries::{Libraries, Library, SharedLibraries};
use crate::options::IpVersion;
use crate::tls::fake::FakeTls;

/// A handle with the fake TLS library `tls` and an HTTP/3 one running
/// `script`, tracing everything.
fn tracing(tls: FakeTls, script: &Arc<Mutex<Script>>) -> Easy {
    tracing_by(Box::leak(Box::new(tls)), script)
}

/// `tracing`, by the TLS backend `tls`, which the test reads.
fn tracing_by(tls: &'static FakeTls, script: &Arc<Mutex<Script>>) -> Easy {
    tracing_with(tls, FakeHttp3::new(script.clone()))
}

/// `tracing`, by the TLS backend `tls` and the HTTP/3 library `h3`.
fn tracing_with(tls: &'static FakeTls, h3: FakeHttp3) -> Easy {
    let h3: &'static FakeHttp3 = Box::leak(Box::new(h3));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(tls)),
        h3: Some(h3),
        ..Libraries::NONE
    })
    .unwrap();
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let c = Components::new().unwrap();
    c.configure(b"all");
    e.set_components(Some(c));
    e
}

/// The lines a run traced that start with one of `starts`, past their
/// ids, the waits the multi's clock makes left out.
fn lines(ran: &Ran, starts: &[&str]) -> Vec<String> {
    lines_of(&ran.seen, starts)
}

/// `lines`, of what `seen` saw.
fn lines_of(seen: &Seen, starts: &[&str]) -> Vec<String> {
    seen.text()
        .into_iter()
        .map(|l| {
            let l = l.trim_end();
            let past_ids = l.strip_prefix('[').and_then(|r| r.split_once("] "));
            past_ids.map_or(l, |(_, rest)| rest).trim_start().to_owned()
        })
        .filter(|l| starts.iter().any(|s| l.starts_with(s)))
        .filter(|l| !l.contains("] pollset[") && !l.contains("] multi_wait("))
        .filter(|l| !l.contains("expires in") && !l.contains("gives multi timeout"))
        .collect()
}

fn expect(lines: &str) -> Vec<String> {
    lines
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A peer at `PORT`, over IPv4 and IPv6, answering each datagram sent
/// with its next of `replies`.
fn quic_server(replies: &[&[u8]]) -> Multi {
    quic_server_on(ManualClock::new().unwrap(), replies)
}

/// `quic_server`'s peer, for a multi reading `clock`.
fn quic_server_on(clock: ManualClock, replies: &[&[u8]]) -> Multi {
    quic_peer(clock, &[replies]).0
}

/// `quic_server_on`'s multi, whose peer gives each connection made to it
/// the replies of its turn; and the conversations of those over IPv6,
/// the address tried first.
fn quic_peer(clock: ManualClock, conns: &[&[&[u8]]]) -> (Multi, Vec<Conversation>) {
    let reads = Box::new(clock.clone());
    quic_peer_reading(clock, reads, conns)
}

/// `quic_peer`, the multi reading `reads`, a clock that tells `clock`'s
/// time.
fn quic_peer_reading(
    clock: ManualClock,
    reads: Box<dyn crate::time::Clock>,
    conns: &[&[&[u8]]],
) -> (Multi, Vec<Conversation>) {
    let mut net = records_as_built(FakeNet::new(clock.clone()).with_name(
        "localhost",
        &[
            std::net::Ipv6Addr::LOCALHOST.into(),
            std::net::Ipv4Addr::LOCALHOST.into(),
        ],
    ));
    let ats = [
        SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, PORT)),
        SocketAddr::from(([127, 0, 0, 1], PORT)),
    ];
    let mut talks = Vec::new();
    for at in ats {
        net = net.with_peer(at, Peer::Accepts);
        for replies in conns {
            let talk = Conversation::replies(replies, false).per_send();
            if at.is_ipv6() {
                talks.push(talk.clone());
            }
            net = net.with_conversation(at, talk);
        }
    }
    let env = Env {
        clock: reads,
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), talks)
}

/// A clock that moves a millisecond on as each reading of it is taken,
/// as the system's moves while a step runs: one clock with `ManualClock`
/// it wraps, and with that one's clones.
struct Ticking(ManualClock);

impl crate::time::Clock for Ticking {
    fn now(&self) -> crate::time::Instant {
        let at = self.0.now();
        self.0.advance(std::time::Duration::from_millis(1));
        at
    }

    fn unix_time(&self) -> i64 {
        self.0.unix_time()
    }

    fn identity(&self) -> crate::time::ClockId {
        self.0.identity()
    }
}

/// A GET of `https://localhost:PORT/` in HTTP/3 alone, by `e`.
fn h3_get(m: &mut Multi, e: Easy) -> Ran {
    let url = format!("https://localhost:{PORT}/");
    get_with(m, e, "/", Conversation::replies(&[], false), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3Only;
        o.ip_version = IpVersion::Any;
    })
}

/// The client's first flight goes as one run of two packets the kernel
/// cuts; the server's flight completes the handshake, the peer checked,
/// and the attempt wins: the connection is up over QUIC, its chain QUIC's
/// filter over its UDP socket, its connect timed as its first datagram
/// came and its TLS as its handshake completed.
#[test]
fn a_quic_attempt_is_won_by_its_handshake() {
    let script = Script::new();
    {
        let mut s = script.lock().unwrap();
        s.out.extend([vec![1; 1200], vec![2; 1200]]);
        s.on_read
            .push_back(vec![Told::HandshakeDone, Told::MaxBidiStreams(100)]);
        s.expiry = Some(std::time::Duration::from_micros(4500));
    }
    let mut m = quic_server(&[b"server flight"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    // HTTP/3 asked for is the HTTPS connect filter's to choose: the
    // connection wants TCP, as C's says.
    let made = ran.seen.text();
    let made: Vec<_> = made.iter().filter(|l| l.contains("created DNS")).collect();
    assert!(
        !made.is_empty() && made.iter().all(|l| l.ends_with(", transport=3\n")),
        "{made:?}"
    );
    let got = lines(
        &ran,
        &[
            "[HAPPY-EYEBALLS]",
            "[UDP]",
            "[HTTP/3]",
            "[HTTPS-CONNECT] 1st",
            "[TIMER] [QUIC]",
            "[MULTI] [CONNECTING] c",
            "[MULTI] [CONNECTING] reduced",
            "[MULTI] [CONNECTING] [PGRS-CONNECT]",
            "[MULTI] [CONNECTING] [PGRS-APPCONNECT]",
            "Trying",
            "Established",
            "fake QUIC",
            "using",
        ],
    );
    // The connect's, to the version it found; the request's are its own
    // test's.
    let end = got
        .iter()
        .position(|l| l == "using HTTP/3")
        .map_or(got.len(), |i| i + 1);
    let got = got[..end].to_vec();
    let want = expect(&format!(
        "[HTTPS-CONNECT] 1st attempt uses h3 from wanted versions
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [HAPPY-EYEBALLS] init ip ballers for transport 5
        [HAPPY-EYEBALLS] want to do more
        [HAPPY-EYEBALLS] check for next AAAA address: found
        [HAPPY-EYEBALLS] starting first attempt for ipv6 -> 0
        Trying [::1]:{PORT}...
        [UDP] cf_socket_open() -> 0, fd=1000
        [UDP] QUIC socket 1000 connected: [::1:40000] -> [::1:{PORT}]
        [UDP] cf_udp_connect(), opened socket=1000 (::1:40000)
        [HTTP/3] fake QUIC session 1
        [HTTP/3] egress, collect and send packets, quantum=12000
        [HTTP/3] egress, send collected 2 packets in 2400 bytes
        [HTTP/3] vquic_sendmsg(len=2400, gso=1200, calls=1) -> 0, sent=2400
        [TIMER] [QUIC] set for 5000us
        [HAPPY-EYEBALLS] checked connect attempts: 1 ongoing, 0 inconclusive
        [HAPPY-EYEBALLS] next HAPPY_EYEBALLS timeout in 200ms
        [UDP] adjust_pollset, !active, POLLIN fd=1000
        [HAPPY-EYEBALLS] adjust_pollset -> 0, 1 socks
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [HTTP/3] fake QUIC session 1 trusts
        [HTTP/3] progress_ingress(socket)
        fake QUIC peer verified
        [HTTP/3] handshake complete after 0ms, remote transport[max_udp_payload=1452, initial_max_data=786432]
        [HTTP/3] max bidi streams now 100, used 0
        [HTTP/3] ingress, recvmmsg -> EAGAIN
        [HTTP/3] vquic_recvmmsg(len=13, packets=1, calls=1) -> 0
        [HTTP/3] egress, collect and send packets, quantum=12000
        [HTTP/3] peer verified
        [TIMER] [QUIC] set for 5000us
        [HTTP/3] connect -> 0, done=1
        [HAPPY-EYEBALLS] connect attempt #0 successful
        [HAPPY-EYEBALLS] Connected to localhost (::1) port {PORT}
        [MULTI] [CONNECTING] [PGRS-CONNECT] added 1us
        [MULTI] [CONNECTING] [PGRS-APPCONNECT] added 1us
        Established connection to localhost (::1 port {PORT}) from ::1 port 40000
        [MULTI] [CONNECTING] connected [0][DNS][DNS][HTTPS-CONNECT][SETUP][HAPPY-EYEBALLS][HTTP/3][UDP]
        [HAPPY-EYEBALLS] removing connected setup filter
        [HAPPY-EYEBALLS] destroy
        [MULTI] [CONNECTING] reduced to [0][HTTP/3][UDP]
        [HTTP/3] query ALPN
        using HTTP/3"
    ));
    assert_eq!(got, want);
    let s = script.lock().unwrap();
    assert_eq!(s.read, [(b"server flight".to_vec(), 0)]);
    assert_eq!(s.checked, [Ok(())]);
}

/// A peer whose check fails fails its attempt as its handshake
/// completes: the connection closes with what the library failed with,
/// its close sent at once, and the next address is tried; the last's
/// failure is the setup's, the check's own.
#[test]
fn an_unverified_peer_fails_each_attempt_and_the_setup() {
    let script = Script::new();
    {
        let mut s = script.lock().unwrap();
        // Each attempt's flight, then its end.
        for _ in 0..2 {
            s.out.extend([vec![1; 1200], vec![2; 1200], vec![]]);
            s.on_read.push_back(vec![Told::HandshakeDone]);
        }
    }
    let mut m = quic_server(&[b"server flight"]);
    let e = tracing(FakeTls::quic_unverified().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Err(ErrorKind::PeerFailedVerification));
    let got = lines(
        &ran,
        &[
            "[HAPPY-EYEBALLS]",
            "[UDP] destroy",
            "[UDP] cf_socket_close",
            "[HTTP/3] ingress, read",
            "[HTTP/3] start",
            "[HTTP/3] shutdown",
            "[HTTP/3] vquic_sendmsg(len=5",
            "[HTTP/3] vquic_recvmmsg",
            "[HTTP/3] connect ->",
            "[HTTP/3] destroy",
            "QUIC connect",
            "Failed to connect",
            "fake QUIC peer",
        ],
    );
    // The second attempt is the last: no timer for another is set. The
    // race is set up once, and looks for each attempt's address, IPv4's
    // first after an IPv6 attempt.
    let attempt = |v: u8, ip: &str| {
        let (next, looked) = if v == 6 {
            (
                "[HAPPY-EYEBALLS] next HAPPY_EYEBALLS timeout in 200ms",
                "[HAPPY-EYEBALLS] init ip ballers for transport 5
                [HAPPY-EYEBALLS] want to do more
                [HAPPY-EYEBALLS] check for next AAAA address: found",
            )
        } else {
            (
                "",
                "[HAPPY-EYEBALLS] want to do more
                [HAPPY-EYEBALLS] check for next A address: found",
            )
        };
        format!(
            "{looked}
            [HAPPY-EYEBALLS] starting first attempt for ipv{v} -> 0
            [HAPPY-EYEBALLS] checked connect attempts: 1 ongoing, 0 inconclusive
            {next}
            [HAPPY-EYEBALLS] adjust_pollset -> 0, 1 socks
            fake QUIC peer not verified
            [HTTP/3] ingress, read_pkt -> ERR_FAKE (-502)
            [HTTP/3] start shutdown(err_type=0, err_code=502) -> 5
            [HTTP/3] shutdown, flushing egress
            [HTTP/3] vquic_sendmsg(len=5, gso=5, calls=1) -> 0, sent=5
            [HTTP/3] shutdown completely sent off, done
            [HTTP/3] vquic_recvmmsg(len=13, packets=0, calls=1) -> 56
            QUIC connect to {ip} port {PORT} failed: SSL peer certificate or SSH remote key was not OK
            [HTTP/3] connect -> 60, done=0
            [HTTP/3] destroy
            [UDP] destroy
            [UDP] cf_socket_close, fd=1000"
        )
    };
    let want = expect(&format!(
        "{}
        {}
        [HAPPY-EYEBALLS] want to do more
        [HAPPY-EYEBALLS] check for next AAAA address: none
        [HAPPY-EYEBALLS] check for next A address: none
        [HAPPY-EYEBALLS] no more attempts to try
        Failed to connect to localhost:{PORT} after 0 ms: SSL peer certificate or SSH remote key was not OK",
        attempt(6, "::1"),
        attempt(4, "127.0.0.1"),
    ));
    assert_eq!(got, want);
}

/// HTTP/3 alone is refused where it cannot be had, before anything is
/// connected (`Curl_conn_may_http3`): over a Unix socket, to an origin
/// not over TLS, through a SOCKS proxy.
#[test]
fn http3_alone_is_refused_where_it_cannot_be() {
    type Set = fn(&mut Options);
    let cases: [(&str, Set, ErrorKind, &str); 3] = [
        (
            "https",
            |o| {
                o.sockets.make_mut().unwrap().unix = Some(crate::options::UnixSocket {
                    path: b"/tmp/h3.sock".to_vec(),
                    abstract_name: false,
                });
            },
            ErrorKind::QuicConnectError,
            "HTTP/3 cannot be used over UNIX domain sockets",
        ),
        (
            "http",
            |_| {},
            ErrorKind::UrlMalformat,
            "HTTP/3 requested for non-HTTPS URL",
        ),
        (
            "https",
            |o| o.proxy.make_mut().unwrap().url = Some(b"socks5://127.0.0.1:1080".to_vec()),
            ErrorKind::UrlMalformat,
            "HTTP/3 is not supported over a SOCKS proxy",
        ),
    ];
    for (scheme, set, kind, why) in cases {
        let script = Script::new();
        let mut m = quic_server(&[]);
        let e = tracing(FakeTls::new().unwrap(), &script);
        let url = format!("{scheme}://localhost:{PORT}/");
        let ran = get_with(&mut m, e, "/", Conversation::replies(&[], false), |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
            o.http.version = crate::options::HttpVersion::Http3Only;
            set(o);
        });
        assert_eq!(ran.result, Err(kind), "{why}");
        assert!(lines(&ran, &[why]).len() == 1, "{why}");
        assert!(lines(&ran, &["Trying"]).is_empty(), "{why}");
        assert!(script.lock().unwrap().read.is_empty());
    }
}

/// A script for a GET: the handshake's flights, then the request's
/// packet, answered by a response of `body` that closes the stream. Each
/// egress ends at an empty packet: the connect's two, then the
/// request's.
fn get_script(body: &[u8]) -> Arc<Mutex<Script>> {
    let script = Script::new();
    {
        let mut s = script.lock().unwrap();
        s.idle = Some(std::time::Duration::from_secs(30));
        s.out.extend([
            vec![1; 1200],
            vec![2; 1200],
            vec![],
            vec![],
            vec![3; 75],
            vec![],
        ]);
        s.on_read
            .push_back(vec![Told::HandshakeDone, Told::MaxBidiStreams(100)]);
        let header = |name: &[u8], value: &[u8]| Told::Header {
            stream: 0,
            name: name.to_vec(),
            value: value.to_vec(),
        };
        s.on_read.push_back(vec![
            header(b":status", b"200"),
            header(b"content-length", body.len().to_string().as_bytes()),
            Told::HeadersDone(0),
            Told::Data(0, body.to_vec()),
            Told::Closed(0, 0x100),
            Told::QuicClosed(0, 0x100),
        ]);
    }
    script
}

/// A transfer paused both ways waits on nothing, its QUIC connection's
/// unsent packets among it: the connection's own wish to write is not
/// put in a pollset that wants no I/O, as C's filters are not asked then
/// (`Curl_conn_adjust_pollset`), or the multi would be woken by a socket
/// that is always writable while the transfer can do nothing.
#[test]
fn a_paused_transfer_waits_on_nothing_while_its_connection_holds_packets() {
    use crate::conn::io::Events;
    use crate::deliver::PauseRequest;
    let script = get_script(b"123456789");
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    // The handshake's sends go; the request's are refused from then on.
    let talk = Conversation::replies(&[b"server flight", b"response"], false)
        .per_send()
        .stalling_sends_after(1, 1000);
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk);
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let mut e = tracing(FakeTls::new().unwrap(), &script);
    let url = format!("https://127.0.0.1:{PORT}/");
    e.options_mut().set_url(Some(url.as_bytes())).unwrap();
    e.options_mut().http.version = crate::options::HttpVersion::Http3Only;
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let mut waits = Events::NONE;
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
        waits = Events::NONE;
        m.sockets(&mut NoEvents, |_, e| waits = waits | e).unwrap();
        if matches!(
            m.state_of(id),
            crate::multi::state::TransferState::Exchanging(_)
        ) && waits.contains(Events::OUT)
        {
            break;
        }
    }
    assert!(
        matches!(
            m.state_of(id),
            crate::multi::state::TransferState::Exchanging(_)
        ),
        "the request is under way"
    );
    assert!(waits.contains(Events::OUT), "the connection holds packets");
    m.pause(id, PauseRequest::ALL, &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let mut paused = Events::NONE;
    m.sockets(&mut NoEvents, |_, e| paused = paused | e)
        .unwrap();
    assert_eq!(paused, Events::NONE);
}

/// A QUIC connection's socket is not drained as it closes: C reads the
/// 1 KB of dangling bytes off a TCP socket alone (`cf_socket_shutdown`),
/// a datagram socket's being QUIC's to read.
#[test]
fn a_quic_connection_closes_without_draining_its_socket() {
    let script = get_script(b"123456789");
    let (mut m, talks) = quic_peer(
        ManualClock::new().unwrap(),
        &[&[b"server flight", b"response"]],
    );
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    let (reads, _) = talks[0].reads();
    assert!(reads > 0, "the connection read its datagrams");
    m.close_connections(&mut NoEvents);
    let (after, room) = talks[0].reads();
    assert!(
        after == reads || room != 1024,
        "drained: {after} reads, the last of {room}"
    );
}

/// A GET goes on the connection's first stream, its fields traced as
/// C's, its response written as it is read, the head a line at a time,
/// and the transfer done as the stream closes: the stream is done with
/// once the request is, and the connection no longer kept alive.
#[test]
fn a_get_over_http3_is_answered() {
    let script = get_script(b"123456789");
    let mut m = quic_server(&[b"server flight", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Ok(()));
    let got = lines(
        &ran,
        &[
            "[HTTP/3]",
            "using",
            "Request completely sent off",
            "[TIMER] [QUIC]",
            "[WRITE] xfer_write_resp",
            "[WRITE] [OUT] done",
            "[MULTI] [DONE] multi_done_locked",
            "Connection #0",
        ],
    );
    let from = got.iter().position(|l| l == "using HTTP/3").unwrap();
    let want = expect(&format!(
        "using HTTP/3
        [HTTP/3] progress_ingress(socket)
        [HTTP/3] ingress, recvmmsg -> EAGAIN
        [HTTP/3] peer idle timeout is 30000ms, set keep-alive to 15000 ms.
        [HTTP/3] [0] rx window, extend by 10452992 bytes
        [HTTP/3] [0] OPENED stream for https://localhost:{PORT}/
        [HTTP/3] [0] [:method: GET]
        [HTTP/3] [0] [:scheme: https]
        [HTTP/3] [0] [:authority: localhost:{PORT}]
        [HTTP/3] [0] [:path: /]
        [HTTP/3] [0] [user-agent: curl/test]
        [HTTP/3] [0] [accept: */*]
        [HTTP/3] egress, collect and send packets, quantum=12000
        [HTTP/3] egress, send collected 1 packets in 75 bytes
        [HTTP/3] vquic_sendmsg(len=75, gso=75, calls=1) -> 0, sent=75
        [HTTP/3] [0] cf_send(74), added 74, inflight=0, reduce tx_win=30720
        [HTTP/3] [0] cf_send(len=74) -> 0, 74
        Request completely sent off
        [HTTP/3] progress_ingress(socket)
        [HTTP/3] [0] status: HTTP/3 200
        [HTTP/3] [0] header: content-length: 9
        [HTTP/3] [0] end_headers, status=200
        [WRITE] xfer_write_resp(len=9, eos=0) -> 0
        [HTTP/3] [0] DATA len=9, rx win=10485751
        [HTTP/3] [0] rx window, extend by 9 bytes
        [HTTP/3] [0] CLOSED
        [HTTP/3] [0] quic close(app_error=256) -> 0
        [HTTP/3] ingress, recvmmsg -> EAGAIN
        [HTTP/3] vquic_recvmmsg(len=8, packets=1, calls=1) -> 0
        [HTTP/3] egress, collect and send packets, quantum=12000
        [HTTP/3] [0] cf_recv(buflen=16384) -> 0, 0
        [WRITE] xfer_write_resp(len=0, eos=1) -> 0
        [WRITE] [OUT] done
        [HTTP/3] [0] easy handle is done
        [HTTP/3] no active streams, unset keep-alive
        [MULTI] [DONE] multi_done_locked, in use=0
        [HTTP/3] query conn[0]: MAX_CONCURRENT -> 99 (0 in use)
        Connection #0 to host localhost:{PORT} left intact"
    ));
    assert_eq!(got[from..], want);
    let s = script.lock().unwrap();
    assert_eq!(
        s.requests,
        [[
            ":method: GET",
            ":scheme: https",
            &format!(":authority: localhost:{PORT}"),
            ":path: /",
            "user-agent: curl/test",
            "accept: */*",
        ]]
    );
    // Kept alive while the stream was open, and no longer after.
    assert_eq!(s.keep_alive, Some(None), "the last set unsets it");
    assert_eq!(ran.seen.body(), b"123456789");
    assert_eq!(
        ran.seen.of("header"),
        [
            b"HTTP/3 200 \r\n".to_vec(),
            b"content-length: 9\r\n".to_vec(),
            b"\r\n".to_vec()
        ]
    );
    // The window opened as the body was taken, once the read returned.
    assert_eq!(s.windows, [(0, 10452992), (0, 9)]);
}

/// The request's packet goes unanswered: the transfer waits for the
/// library's timer, which the multi runs as it comes due, and what the
/// library then sends, its retransmission, has the response come.
#[test]
fn the_library_s_timer_runs_while_a_response_is_awaited() {
    let script = get_script(b"123456789");
    {
        let mut s = script.lock().unwrap();
        // Its reply comes to nothing; the retransmission's has the
        // response.
        let response = s.on_read.pop_back().unwrap();
        s.on_read.push_back(vec![]);
        s.on_read.push_back(response);
        s.on_expiry = vec![vec![4; 75], vec![]];
        s.timer = Some(std::time::Duration::from_millis(25));
    }
    let mut m = quic_server(&[b"server flight", b"ack", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Ok(()));
    let s = script.lock().unwrap();
    assert_eq!(s.expired, 1, "the timer ran once");
    // As it came due: the clock stood still until then.
    let (first, last) = (s.sent_at[0], *s.sent_at.last().unwrap());
    assert_eq!(last.since(first), std::time::Duration::from_millis(25));
    let got = lines(&ran, &["[TIMER] [QUIC]", "[HTTP/3] vquic_sendmsg"]);
    assert_eq!(
        got.last().map(String::as_str),
        Some("[HTTP/3] vquic_sendmsg(len=75, gso=75, calls=1) -> 0, sent=75"),
        "the retransmission went last: {got:#?}"
    );
    assert_eq!(ran.seen.body(), b"123456789");
}

/// A response's stream closed with `told` in place of its last events.
fn closed_early(told: Vec<Told>) -> Ran {
    let script = get_script(b"123456789");
    {
        let mut s = script.lock().unwrap();
        *s.on_read.back_mut().unwrap() = told;
    }
    let mut m = quic_server(&[b"server flight", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    h3_get(&mut m, e)
}

/// A reset after some of the body fails the transfer as a partial file,
/// saying the code by its name (`recv_closed_stream`).
#[test]
fn a_stream_reset_mid_body_is_a_partial_file() {
    let header = |name: &[u8], value: &[u8]| Told::Header {
        stream: 0,
        name: name.to_vec(),
        value: value.to_vec(),
    };
    let ran = closed_early(vec![
        header(b":status", b"200"),
        header(b"content-length", b"9"),
        Told::HeadersDone(0),
        Told::Data(0, b"1234".to_vec()),
        Told::Closed(0, 0x102),
    ]);
    assert_eq!(ran.result, Err(ErrorKind::PartialFile));
    assert_eq!(
        lines(&ran, &["HTTP/3 stream", "[HTTP/3] [0] RESET"]),
        [
            "[HTTP/3] [0] RESET: error 258",
            "HTTP/3 stream 0 reset by server (error 0x102 INTERNAL_ERROR)",
        ]
    );
}

/// A stream that closes before its response's head is whole fails the
/// transfer, though no error closed it.
#[test]
fn a_stream_closed_before_its_head_fails() {
    let ran = closed_early(vec![
        Told::Header {
            stream: 0,
            name: b":status".to_vec(),
            value: b"200".to_vec(),
        },
        Told::Closed(0, 0x100),
    ]);
    assert_eq!(ran.result, Err(ErrorKind::Http3));
    assert_eq!(
        lines(&ran, &["HTTP/3 stream"]),
        [
            "HTTP/3 stream 0 was closed cleanly, but before getting all response header fields, \
             treated as error"
        ]
    );
}

/// The head of a response of 9 bytes and 4 of them, then `then`.
fn short_body(then: Vec<Told>) -> Vec<Told> {
    let header = |name: &[u8], value: &[u8]| Told::Header {
        stream: 0,
        name: name.to_vec(),
        value: value.to_vec(),
    };
    let mut told = vec![
        header(b":status", b"200"),
        header(b"content-length", b"9"),
        Told::HeadersDone(0),
        Told::Data(0, b"1234".to_vec()),
    ];
    told.extend(then);
    told
}

/// A stream the server closes cleanly before the body its
/// `content-length` gave is whole fails the transfer as a partial file,
/// as the end of the response (`cw_download_write`'s EOS check): the end
/// of a stream is not the end of a body.
#[test]
fn a_stream_closed_cleanly_mid_body_is_a_partial_file() {
    let ran = closed_early(short_body(vec![Told::Closed(0, 0x100)]));
    assert_eq!(ran.result, Err(ErrorKind::PartialFile));
    assert_eq!(ran.seen.body(), b"1234");
    assert_eq!(
        lines(&ran, &["[HTTP/3] [0] CLOSED", "end of response"]),
        [
            "[HTTP/3] [0] CLOSED",
            "end of response with 5 bytes missing"
        ]
    );
}

/// The connection lost mid-body, the peer closing it, fails the transfer
/// as a receive (`cf_ngtcp2_recv`'s failed ingress), not as a response
/// that ended.
#[test]
fn a_connection_closed_mid_body_fails_the_transfer() {
    // NGTCP2_ERR_DRAINING: the peer's CONNECTION_CLOSE was read.
    let ran = closed_early(short_body(vec![Told::ReadFails(-224)]));
    assert_eq!(ran.result, Err(ErrorKind::RecvError));
    assert_eq!(ran.seen.body(), b"1234");
    assert_eq!(
        lines(
            &ran,
            &["[HTTP/3] ingress, read_pkt", "[HTTP/3] [0] cf_recv"]
        )
        .last(),
        Some(&"[HTTP/3] [0] cf_recv(buflen=16384) -> 56, 0".to_owned())
    );
    assert!(
        lines(&ran, &["[WRITE] xfer_write_resp(len=0, eos=1)"]).is_empty(),
        "the response was not ended"
    );
}

/// The connection idle past its timeout mid-body, the library's timer
/// saying so, fails the transfer as a send, as C's expiry check does
/// (`check_and_set_expiry`), not as a response that ended.
#[test]
fn an_idle_close_mid_body_fails_the_transfer() {
    let script = get_script(b"123456789");
    {
        let mut s = script.lock().unwrap();
        *s.on_read.back_mut().unwrap() = short_body(vec![]);
        s.timer = Some(std::time::Duration::from_millis(25));
        // NGTCP2_ERR_IDLE_CLOSE.
        s.expiry_fails = Some(-238);
    }
    let mut m = quic_server(&[b"server flight", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Err(ErrorKind::SendError));
    assert_eq!(ran.seen.body(), b"1234");
    assert_eq!(
        lines(&ran, &["ngtcp2_conn_handle_expiry"]),
        ["ngtcp2_conn_handle_expiry returned error: ERR_FAKE"]
    );
    assert!(
        lines(&ran, &["[WRITE] xfer_write_resp(len=0, eos=1)"]).is_empty(),
        "the response was not ended"
    );
}

/// A connection a share keeps is reused by another multi on the one clock
/// they read, the library never handed a time before one it had though
/// the clock moves within each step.
#[test]
fn a_shared_connection_is_reused_by_another_multi_on_their_clock() {
    use crate::share::{Kind, Share};
    let share = Share::new().unwrap();
    share.keep(Kind::Connections).unwrap();
    let script = get_script(b"123456789");
    {
        let mut s = script.lock().unwrap();
        let header = |name: &[u8], value: &[u8]| Told::Header {
            stream: 4,
            name: name.to_vec(),
            value: value.to_vec(),
        };
        s.on_read.push_back(vec![
            header(b":status", b"200"),
            header(b"content-length", b"2"),
            Told::HeadersDone(4),
            Told::Data(4, b"ok".to_vec()),
            Told::Closed(4, 0x100),
        ]);
    }
    // A clock that moves as it is read: the connection reads it again for
    // each call into its library, whoever steps it, never the step's time
    // from before an earlier call.
    let clock = ManualClock::new().unwrap();
    let replies: &[&[u8]] = &[b"server flight", b"response", b"second"];
    let on = |clock: &ManualClock| {
        let reads = Box::new(Ticking(clock.clone()));
        quic_peer_reading(clock.clone(), reads, &[replies]).0
    };
    let mut first = on(&clock);
    let mut e = tracing(FakeTls::new().unwrap(), &script);
    e.set_share(Some(share.clone())).unwrap();
    assert_eq!(h3_get(&mut first, e).result, Ok(()));
    // The second request's packet, once the first is done.
    script.lock().unwrap().out.extend([vec![5; 75], vec![]]);
    let mut second = on(&clock);
    let mut e = tracing(FakeTls::new().unwrap(), &script);
    e.set_share(Some(share.clone())).unwrap();
    let ran = h3_get(&mut second, e);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"ok");
    assert_eq!(
        script.lock().unwrap().requests.len(),
        2,
        "both on the one connection"
    );
}

/// `get_script`, then a second response on the connection's next stream,
/// `ok`, and the packet the second request goes in.
fn and_then_ok(script: &Arc<Mutex<Script>>) {
    let mut s = script.lock().unwrap();
    let header = |name: &[u8], value: &[u8]| Told::Header {
        stream: 4,
        name: name.to_vec(),
        value: value.to_vec(),
    };
    s.on_read.push_back(vec![
        header(b":status", b"200"),
        header(b"content-length", b"2"),
        Told::HeadersDone(4),
        Told::Data(4, b"ok".to_vec()),
        Told::Closed(4, 0x100),
    ]);
}

/// A GET of `https://localhost:PORT/` by `e`, asking for `version`.
fn get_as(m: &mut Multi, e: Easy, version: crate::options::HttpVersion) -> Ran {
    let url = format!("https://localhost:{PORT}/");
    get_with(m, e, "/", Conversation::replies(&[], false), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = version;
        o.ip_version = IpVersion::Any;
        o.limits.connect = crate::time::TimeLimit::from_millis(1000);
    })
}

/// A connection in HTTP/3 serves a transfer that asks for no version,
/// which allows HTTP/3 though it does not want it: C compares no
/// transport, only the version spoken against those allowed
/// (`url_match_http_version`).
#[test]
fn an_http3_connection_serves_a_transfer_that_asks_for_no_version() {
    let script = get_script(b"123456789");
    and_then_ok(&script);
    let replies: &[&[u8]] = &[b"server flight", b"response", b"second"];
    let mut m = quic_server(replies);
    let e = tracing(FakeTls::new().unwrap(), &script);
    assert_eq!(h3_get(&mut m, e).result, Ok(()));
    script.lock().unwrap().out.extend([vec![5; 75], vec![]]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = get_as(&mut m, e, crate::options::HttpVersion::Any);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"ok");
    assert_eq!(
        script.lock().unwrap().requests.len(),
        2,
        "both on the one connection"
    );
}

/// A transfer that allows HTTP/1 alone passes an HTTP/3 connection over,
/// as C's debug build says (`url_match_http_version`).
#[cfg(feature = "debug-hooks")]
#[test]
fn an_http3_connection_is_passed_over_by_a_transfer_in_http1() {
    let script = get_script(b"123456789");
    let mut m = quic_server(&[b"server flight", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    assert_eq!(h3_get(&mut m, e).result, Ok(()));
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = get_as(&mut m, e, crate::options::HttpVersion::Http11);
    let text = ran.seen.text();
    let at = |line: &str| text.iter().position(|l| l.ends_with(line));
    // Before the connection the transfer makes, on none, as in C.
    let unwanted = at("[1-x] not reusing conn #0, we do not want h3\n");
    let added = at("[CPOOL] added connection 1. The cache now contains 2 members\n");
    assert!(unwanted.is_some() && unwanted < added, "{text:#?}");
    assert_eq!(script.lock().unwrap().requests.len(), 1, "none on it");
}

/// Two transfers at once: the second, finding the first's connection
/// being set up, waits for it (`CURLOPT_PIPEWAIT`, which the tool sets for
/// `-Z`), then joins it on a stream of its own, as many as the peer allows
/// and those open. The second leaves the pass once its request is sent
/// (`multistate_did`), so the first's read hands each stream's response to
/// its transfer, the second's to its sibling, and the first is done first;
/// the connection is kept for the last.
#[test]
fn a_second_transfer_multiplexes_on_the_first_s_connection() {
    let (script, mut m) = two_streams();
    let mut ids = Vec::new();
    let mut seen = Vec::new();
    for _ in 0..2 {
        let s = Seen::default();
        let e = pipewaiting(&script, &s);
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
        seen.push(s);
    }
    let a = drive_to_completion(&mut m, ids[0], &mut NoEvents).unwrap();
    let b = drive_to_completion(&mut m, ids[1], &mut NoEvents).unwrap();
    for id in ids {
        m.remove(id, &mut NoEvents).unwrap();
    }
    assert_eq!((a, b), (Ok(()), Ok(())), "{:#?}", seen[1].text());
    assert_eq!(seen[0].body(), b"first");
    assert_eq!(seen[1].body(), b"second");
    let says = |s: &Seen| {
        lines_of(
            s,
            &[
                "Connection #0 is not open enough",
                "Found pending candidate",
                "[HTTP/3] query conn",
                "Multiplexed connection found",
                "Reusing existing",
                "[HTTP/3] [0] OPENED",
                "[HTTP/3] [4] OPENED",
                "[HTTP/3] [0] easy handle",
                "[HTTP/3] [4] easy handle",
                "[MULTI] [DONE] Connection still in use",
                "Connection #0 to host",
            ],
        )
    };
    assert_eq!(
        says(&seen[0]),
        expect(&format!(
            "[HTTP/3] [0] OPENED stream for https://localhost:{PORT}/
            [HTTP/3] [0] easy handle is done
            [MULTI] [DONE] Connection still in use 1, no more multi_done now!"
        ))
    );
    assert_eq!(
        says(&seen[1]),
        expect(&format!(
            "Connection #0 is not open enough, cannot reuse
            Found pending candidate for reuse and CURLOPT_PIPEWAIT is set
            [HTTP/3] query conn[0]: MAX_CONCURRENT -> 100 (1 in use)
            Multiplexed connection found
            Reusing existing https: connection with host localhost
            [HTTP/3] [4] OPENED stream for https://localhost:{PORT}/
            [HTTP/3] [4] easy handle is done
            [HTTP/3] query conn[0]: MAX_CONCURRENT -> 98 (0 in use)
            Connection #0 to host localhost:{PORT} left intact"
        ))
    );
}

/// The fake HTTP/3 library's script for two transfers' streams on one
/// connection, the first's request only acknowledged and both answered
/// in one read, and a peer for it.
fn two_streams() -> (Arc<Mutex<Script>>, Multi) {
    let script = Script::new();
    {
        let mut s = script.lock().unwrap();
        s.idle = Some(std::time::Duration::from_secs(30));
        s.out.extend([vec![1; 1200], vec![2; 1200], vec![], vec![]]);
        s.on_submit
            .extend([vec![vec![3; 75], vec![]], vec![vec![4; 76], vec![]]]);
        s.on_read
            .push_back(vec![Told::HandshakeDone, Told::MaxBidiStreams(100)]);
        // Stream 0's request is only acknowledged.
        s.on_read.push_back(vec![]);
        let mut both = Vec::new();
        for (stream, body) in [(0, b"first".as_slice()), (4, b"second".as_slice())] {
            let header = |name: &[u8], value: &[u8]| Told::Header {
                stream,
                name: name.to_vec(),
                value: value.to_vec(),
            };
            both.extend([
                header(b":status", b"200"),
                header(b"content-length", body.len().to_string().as_bytes()),
                Told::HeadersDone(stream),
                Told::Data(stream, body.to_vec()),
                Told::Closed(stream, 0x100),
            ]);
        }
        s.on_read.push_back(both);
    }
    let m = quic_server(&[b"server flight", b"ack", b"responses"]);
    (script, m)
}

/// A handle getting `https://localhost:PORT/` in HTTP/3 alone, by the
/// fake libraries running `script`, that waits for a connection being
/// set up to say whether it multiplexes; what it is given and says seen
/// by `seen`.
fn pipewaiting(script: &Arc<Mutex<Script>>, seen: &Seen) -> Easy {
    let url = format!("https://localhost:{PORT}/");
    let mut e = tracing(FakeTls::new().unwrap(), script);
    let o = e.options_mut();
    o.set_url(Some(url.as_bytes())).unwrap();
    o.output.verbose = true;
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.http.user_agent = Some(b"curl/test".to_vec());
    o.http.version = crate::options::HttpVersion::Http3Only;
    o.http.pipewait = true;
    o.ip_version = IpVersion::Any;
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    o.callbacks.header = Some(Handler::header(seen.clone()).unwrap());
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    e
}

/// The second, waiting for the first's connection, is let out as that
/// connection is made, as it multiplexes, before the first goes on; the
/// first then says the multi changed as its next step starts, once: C's
/// lines in C's order (`build/m5-c-h3-par.trace`; `multi_connecting`,
/// `Curl_conn_set_multiplex`, `multi_runsingle`).
#[test]
fn a_connection_made_to_multiplex_lets_one_waiting_out_and_says_so() {
    let (script, mut m) = two_streams();
    let both = Seen::default();
    let ids = [0, 1].map(|_| {
        let e = pipewaiting(&script, &both);
        m.add(Box::new(e), (), &mut NoEvents).unwrap()
    });
    for id in ids {
        let done = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(done, Ok(()));
    }
    let lines = lines_of(&both, &["[MULTI] ["]);
    let states: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .filter(|l| l.contains("] -> [") || l.contains("multi changed") || l.contains("reduced"))
        .collect();
    let at = states
        .iter()
        .position(|l| l.starts_with("[MULTI] [CONNECTING] reduced to"))
        .unwrap();
    assert_eq!(
        states[at + 1..at + 5],
        [
            "[MULTI] [PENDING] -> [CONNECT]",
            "[MULTI] [CONNECTING] -> [PROTOCONNECT]",
            "[MULTI] [PROTOCONNECT] multi changed, check CONNECT_PEND queue",
            "[MULTI] [PROTOCONNECT] -> [DO]",
        ],
        "{states:#?}"
    );
    let said = states
        .iter()
        .filter(|l| l.contains("multi changed"))
        .count();
    assert_eq!(said, 1, "{states:#?}");
}

/// A connection kept idle is closed as the multi goes, saying goodbye:
/// the packet that closes it goes to the peer
/// (`Curl_cf_ngtcp2_cmn_shutdown`).
#[test]
fn an_idle_connection_closes_saying_goodbye() {
    let script = get_script(b"123456789");
    let (mut m, talks) = quic_peer(
        ManualClock::new().unwrap(),
        &[&[b"server flight", b"response"]],
    );
    let e = tracing(FakeTls::new().unwrap(), &script);
    assert_eq!(h3_get(&mut m, e).result, Ok(()));
    let before = talks[0].received().len();
    drop(m);
    let sent = talks[0].received();
    assert_eq!(&sent[before..], b"CLOSE", "the close, and nothing else");
}

/// A connection dialed straight is checked before reuse over its own
/// socket, not through layers, its transport saying so: what came late
/// on it is read from the socket in a batch's room, not a tunnel's
/// datagram room, the library failing it so that it is not reused; and
/// the next connection, which its transfer forbids reusing, says goodbye
/// on its socket (`Curl_cf_ngtcp2_cmn_conn_is_alive`,
/// `Curl_cf_ngtcp2_cmn_shutdown`, the same call's context).
#[test]
fn a_direct_connection_is_checked_and_closed_over_its_socket() {
    let script = get_script(b"123456789");
    // After the response, one more packet goes, whose answer comes late.
    script.lock().unwrap().out.extend([vec![4; 20], vec![]]);
    let clock = ManualClock::new().unwrap();
    let (mut m, talks) = quic_peer(
        clock.clone(),
        &[
            &[b"server flight", b"response", b"late"],
            &[b"server flight", b"response"],
        ],
    );
    let e = tracing(FakeTls::new().unwrap(), &script);
    assert_eq!(h3_get(&mut m, e).result, Ok(()));
    #[derive(Clone, Default)]
    struct Written(Arc<Mutex<Vec<u8>>>);
    impl crate::handler::TextSink for Written {
        fn write(&self, text: &[u8]) {
            self.0.lock().unwrap().extend_from_slice(text);
        }
    }
    let components = crate::components::Components::new().unwrap();
    components.set(
        crate::components::Component::Http3,
        crate::components::Level::Info,
    );
    let written = Written::default();
    m.trace_internally_to(
        components,
        crate::handler::Handler::text(written.clone()).unwrap(),
    );
    let (reads, _) = talks[0].reads();
    script.lock().unwrap().read_fails = Some(-502);
    // Idle long enough to be checked (`Curl_conn_seems_dead`).
    clock.advance(std::time::Duration::from_secs(2));
    let e = tracing(FakeTls::new().unwrap(), &get_script(b"abc"));
    let url = format!("https://localhost:{PORT}/");
    let ran = get_with(&mut m, e, "/", Conversation::replies(&[], false), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3Only;
        o.ip_version = IpVersion::Any;
        o.limits.reuse.forbid = true;
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"abc");
    let (after, room) = talks[0].reads();
    assert!(after > reads, "the check read what came late");
    // A batch read off the socket, not one datagram of a tunnel's 64 KiB.
    assert_eq!(room, crate::conn::io::SLOT, "a batch's room");
    assert!(
        talks[1].received().ends_with(b"CLOSE"),
        "the second said goodbye"
    );
    // The check's failure and the goodbye, each on the multi's internal
    // trace, went on the socket.
    let text = String::from_utf8(written.0.lock().unwrap().clone()).unwrap();
    let sent: Vec<&str> = text.lines().filter(|l| l.contains("vquic_send")).collect();
    assert_eq!(
        sent, ["* [HTTP/3] vquic_sendmsg(len=5, gso=5, calls=1) -> 0, sent=5"; 2],
        "{text}"
    );
}

/// The script of `get_script`, then the same again for a second
/// connection, whose response is `body`.
fn twice(script: &Arc<Mutex<Script>>, body: &[u8]) {
    let again = get_script(body);
    let mut again = again.lock().unwrap();
    let mut s = script.lock().unwrap();
    s.out.extend(again.out.drain(..));
    s.on_read.extend(again.on_read.drain(..));
}

/// A connection idle past the time its peer said it closes one by is
/// dead: it is closed, saying goodbye, and the next transfer makes its
/// own (`Curl_cf_ngtcp2_cmn_conn_is_alive`).
#[test]
fn a_connection_idle_past_the_peer_s_timeout_is_not_reused() {
    let script = get_script(b"123456789");
    let clock = ManualClock::new().unwrap();
    let (mut m, talks) = quic_peer(
        clock.clone(),
        &[
            &[b"server flight", b"response"],
            &[b"server flight", b"response"],
        ],
    );
    let e = tracing(FakeTls::new().unwrap(), &script);
    assert_eq!(h3_get(&mut m, e).result, Ok(()));
    twice(&script, b"abc");
    clock.advance(std::time::Duration::from_secs(31));
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"abc");
    let text = ran.seen.text();
    assert!(
        text.iter()
            .any(|l| l.ends_with("] Connection #1 to host localhost:8990 left intact\n"))
            && !text.iter().any(|l| l.contains("] Re-using")),
        "{text:#?}"
    );
    assert!(
        talks[0].received().ends_with(b"CLOSE"),
        "the first said goodbye"
    );
    assert!(!talks[1].received().is_empty(), "a second connection");
}

/// A request the server refuses is made again on a new connection, the
/// refused one closed (`recv_closed_stream`, `Curl_retry_request`).
#[test]
fn a_refused_request_is_made_again_on_a_new_connection() {
    let script = get_script(b"");
    {
        let mut s = script.lock().unwrap();
        *s.on_read.back_mut().unwrap() = vec![Told::Closed(0, 0x10b)];
        // The refused connection's egress after the reset: nothing.
        s.out.push_back(vec![]);
    }
    twice(&script, b"again");
    let (mut m, talks) = quic_peer(
        ManualClock::new().unwrap(),
        &[
            &[b"server flight", b"refused"],
            &[b"server flight", b"response"],
        ],
    );
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"again");
    assert_eq!(
        lines(
            &ran,
            &[
                "HTTP/3 stream",
                "REFUSED",
                "Connection died",
                "Issue another"
            ]
        ),
        [
            "HTTP/3 stream 0 refused by server, try again on a new connection",
            "REFUSED_STREAM, retrying a fresh connect",
            "Connection died, retrying a fresh connect (retry count: 1)",
            "Issue another request to this URL: 'https://localhost:8990/'",
        ]
    );
    assert_eq!(script.lock().unwrap().requests.len(), 2);
    assert!(!talks[1].received().is_empty(), "a second connection");
}

/// `get_script`, for a request with a body: the response answers the
/// last of `packets` the request and its body go in, the others answered
/// with nothing.
fn post_script(response: &[u8], packets: usize) -> Arc<Mutex<Script>> {
    let script = get_script(response);
    {
        let mut s = script.lock().unwrap();
        let reply = s.on_read.pop_back().unwrap();
        s.on_read.extend(std::iter::repeat_n(vec![], packets - 1));
        s.on_read.push_back(reply);
    }
    script
}

/// `h3_get` with the options `set` sets, its peer answering each of
/// `packets`, as `post_script`'s script says; a transfer that spins
/// fails.
fn h3_with(script: &Arc<Mutex<Script>>, packets: usize, set: impl FnOnce(&mut Options)) -> Ran {
    let mut replies: Vec<&[u8]> = vec![b"server flight"];
    replies.extend(std::iter::repeat_n(&b"ack"[..], packets - 1));
    replies.push(b"response");
    let mut m = quic_server(&replies);
    let mut e = tracing(FakeTls::new().unwrap(), script);
    let url = format!("https://localhost:{PORT}/");
    let seen = Seen::default();
    let o = e.options_mut();
    o.set_url(Some(url.as_bytes())).unwrap();
    o.output.verbose = true;
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.http.user_agent = Some(b"curl/test".to_vec());
    o.http.version = crate::options::HttpVersion::Http3Only;
    o.ip_version = IpVersion::Any;
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    o.callbacks.header = Some(Handler::header(seen.clone()).unwrap());
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    set(o);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = crate::multi::drive_within(&mut m, id, 1000, &mut NoEvents).unwrap();
    let easy = *m.remove(id, &mut NoEvents).unwrap().easy;
    Ran {
        result,
        request: Vec::new(),
        seen,
        easy,
    }
}

/// The lines of a request body's sending, as C's QUIC filter traces it.
fn body_lines(ran: &Ran) -> Vec<String> {
    lines(
        ran,
        &[
            "[HTTP/3] [0] read req",
            "[HTTP/3] [0] cf_send",
            "[MULTI] [DO] -> ",
            "[MULTI] [DID] -> ",
            "upload completely",
        ],
    )
}

/// A POST's body.
fn bytes(body: &[u8]) -> UploadSource {
    UploadSource::Bytes(curl_alloc::TryArc::try_new(body.to_vec()).unwrap())
}

/// A body of known size goes after the head, once the request is under
/// way, and ends with its last bytes: the library reads it as it next
/// writes the stream (C's lines for `-d hello`).
#[test]
fn a_body_of_known_size_ends_with_its_last_bytes() {
    let script = post_script(b"5\n", 2);
    let ran = h3_with(&script, 2, |o| {
        o.method = Method::Post;
        o.upload = bytes(b"hello");
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(
        body_lines(&ran),
        [
            "[HTTP/3] [0] read req body -> AGAIN",
            "[HTTP/3] [0] cf_send(148), added 143, inflight=0, reduce tx_win=30720",
            "[HTTP/3] [0] cf_send(len=148) -> 0, 143",
            "[MULTI] [DO] -> [DID]",
            "[MULTI] [DID] -> [PERFORMING]",
            "[HTTP/3] [0] cf_send, add to sendbuf(len=5) -> 0, 5",
            "[HTTP/3] [0] read req body -> 1 vecs EOF with 5 (buffered=5, left=0)",
            "[HTTP/3] [0] cf_send(5), added 5, inflight=5, reduce tx_win=28672",
            "[HTTP/3] [0] cf_send(len=5) -> 0, 5",
            "upload completely sent off: 5 bytes",
        ]
    );
    let s = script.lock().unwrap();
    assert_eq!((&s.body.bytes[..], s.body.ended), (&b"hello"[..], true));
}

/// A body of unknown size ends once all of it is sent: the library is
/// told then, and its end goes as the connection next sends
/// (`CF_CTRL_DATA_DONE_SEND`; C's lines for `-T -`).
#[test]
fn a_body_of_unknown_size_ends_once_it_is_sent() {
    let script = post_script(b"13\n", 3);
    let ran = h3_with(&script, 3, |o| {
        o.method = Method::Post;
        o.upload = super::pieces(&[b"streamed body"]);
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(
        body_lines(&ran)[5..],
        [
            "[HTTP/3] [0] cf_send, add to sendbuf(len=13) -> 0, 13",
            "[HTTP/3] [0] read req body -> 1 vecs with 13 (buffered=13, left=-1)",
            "[HTTP/3] [0] read req body -> AGAIN",
            "[HTTP/3] [0] cf_send(13), added 13, inflight=13, reduce tx_win=28672",
            "[HTTP/3] [0] cf_send(len=13) -> 0, 13",
            "upload completely sent off: 13 bytes",
            "[HTTP/3] [0] read req body -> 0 vecs EOF with 0 (buffered=13, left=0)",
        ]
    );
    assert_eq!(
        script.lock().unwrap().read.len(),
        4,
        "the end in a packet of its own"
    );
}

/// A body of no bytes is none: the head ends the stream, and the library
/// never reads one (`h3_stream_open`'s `upload_left`).
#[test]
fn an_empty_body_is_none() {
    let script = post_script(b"0\n", 1);
    let ran = h3_with(&script, 1, |o| {
        o.method = Method::Post;
        o.upload = bytes(b"");
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(
        lines(
            &ran,
            &[
                "[HTTP/3] [0] read req",
                "Request completely",
                "[MULTI] [DO] -> "
            ]
        ),
        ["Request completely sent off", "[MULTI] [DO] -> [DID]"]
    );
    assert!(!script.lock().unwrap().body.ended);
}

/// Whether the response's writer reaches its connection's TLS session.
#[derive(Clone, Default)]
struct Natives(Arc<Mutex<Vec<bool>>>);

impl crate::handler::WriteHandler for Natives {
    fn write(&self, cx: &mut TransferCx<'_>, _: &[u8]) -> crate::handler::Write {
        let me = cx.me();
        let session = cx.tls_native(me).and_then(|n| n.session());
        self.0.lock().unwrap().push(session.is_some());
        crate::handler::Write::Accepted
    }
}

/// The QUIC connection's TLS session is the transfer's, as C's filter
/// answers for its own (`cf_ngtcp2_query`, `CF_QUERY_SSL_INFO`): what
/// `CURLINFO_TLS_SSL_PTR` gives an application's callbacks.
#[test]
fn a_callback_reaches_the_quic_connection_s_tls_session() {
    let script = post_script(b"5\n", 1);
    let natives = Natives::default();
    let ran = h3_with(&script, 1, |o| {
        o.callbacks.write = Some(Handler::write(natives.clone()).unwrap());
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    let natives = natives.0.lock().unwrap();
    assert!(!natives.is_empty());
    assert!(natives.iter().all(|&reached| reached), "{natives:?}");
}

/// The HTTPS connect filter's timer among the transfer's, for HTTP/3
/// alone: armed while the origin's record is to come, which it is over
/// a resolver library; the threaded resolver says at once there is none,
/// and C's filter, its attempts then complete, arms nothing
/// (`cf_hc_connect`).
fn alpn_eyeballs_timer() -> usize {
    usize::from(!cfg!(feature = "threaded-resolver"))
}

/// A body with as much in flight as is meant to be waits, the transfer
/// waiting on what the peer says rather than on the socket's room, until
/// the peer acknowledges some (`cf_ngtcp2_send`, `cf_ngtcp2_adjust_pollset`).
#[test]
fn a_body_in_flight_waits_for_its_acknowledgement() {
    let body = vec![b'x'; 100_000];
    // The peer answers the request's packet and the body's first with
    // nothing; the packet the library's timer sends is answered with the
    // acknowledgement, the body's last with the response.
    let script = post_script(b"100000\n", 4);
    {
        let mut s = script.lock().unwrap();
        s.on_read[3] = vec![Told::Acked(65_388)];
        s.timer = Some(std::time::Duration::from_millis(25));
        s.on_expiry = vec![vec![9; 20]];
    }
    let ran = h3_with(&script, 4, |o| {
        o.method = Method::Post;
        o.upload = bytes(&body);
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    // The pollset, which `lines` leaves out, waits on what comes alone.
    let said: Vec<String> = ran
        .seen
        .text()
        .iter()
        .map(|l| {
            l.trim_end()
                .split_once("] ")
                .map_or("", |(_, r)| r)
                .to_owned()
        })
        .filter(|l| {
            l.starts_with("[HTTP/3] [0] cf_send(len=34612)")
                || l.starts_with("[MULTI] [PERFORMING] pollset")
        })
        .collect();
    // The rest of the body is read and sent in the pass after the one
    // that sent the first buffer, as C reads before it flushes alone
    // (`Curl_req_send_more`).
    assert_eq!(
        said[..4],
        [
            format!(
                "[MULTI] [PERFORMING] pollset[fd=1000 IN], timeouts={}",
                2 + alpn_eyeballs_timer()
            ),
            "[HTTP/3] [0] cf_send(len=34612) -> 81, 0".to_owned(),
            format!(
                "[MULTI] [PERFORMING] pollset[fd=1000 IN], timeouts={}",
                2 + alpn_eyeballs_timer()
            ),
            "[HTTP/3] [0] cf_send(len=34612) -> 0, 34612".to_owned(),
        ]
    );
    let s = script.lock().unwrap();
    assert_eq!((s.body.bytes.len(), s.body.ended), (100_000, true));
}

/// An error response read while the head is sent, as the library's timer
/// runs at the send's end (`cf_ngtcp2_send`'s `check_and_set_expiry`),
/// stops the upload there: what that send took is still the head's,
/// traced and counted as the head, and none of the body goes (`xfer_send`
/// after `Curl_req_abort_sending`).
#[test]
fn an_error_read_as_the_head_is_sent_stops_the_body() {
    let script = post_script(b"no\n", 1);
    {
        let mut s = script.lock().unwrap();
        for told in s.on_read.back_mut().unwrap() {
            if let Told::Header { name, value, .. } = told
                && name == b":status"
            {
                *value = b"400".to_vec();
            }
        }
        // Due as soon as the request is submitted: the send reads.
        s.timer = Some(std::time::Duration::ZERO);
    }
    let ran = h3_with(&script, 1, |o| {
        o.method = Method::Post;
        o.upload = bytes(b"hello");
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    let said = lines(
        &ran,
        &[
            "HTTP error before end of send",
            "abort upload",
            "upload completely",
            "Request completely",
            "[HTTP/3] [0] cf_send(len=",
        ],
    );
    assert_eq!(
        said,
        [
            "HTTP error before end of send, stop sending",
            "abort upload",
            "[HTTP/3] [0] cf_send(len=148) -> 0, 143",
        ]
    );
    // Traced once, whole, behind the transfer's ids.
    let head = format!(
        "POST / HTTP/3\r\nHost: localhost:{PORT}\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\
         Content-Length: 5\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
    );
    assert_eq!(head.len(), 143);
    assert_eq!(ran.seen.of("out"), [format!("[0-0] {head}").into_bytes()]);
    assert_eq!(ran.seen.of("dataout"), Vec::<Vec<u8>>::new());
    let sizes = ran.easy.report().sizes();
    assert_eq!((sizes.request(), sizes.upload()), (143, 0));
    assert_eq!(ran.seen.of("header")[0], b"HTTP/3 400 \r\n");
    assert_eq!(script.lock().unwrap().body.bytes, b"");
}

/// A peer at `PORT` on IPv4 alone, whose datagrams meet `quic`, its first
/// conversation `quic_talk`, and whose streams meet `tcp`, its next
/// `tcp_talk`: the race's two attempts, QUIC's opened first.
fn racing_peer(quic: Peer, quic_talk: &Conversation, tcp: Peer, tcp_talk: &Conversation) -> Multi {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let net = records_as_built(FakeNet::new(clock.clone()))
        .with_peer(at, tcp)
        .with_datagram_peer(at, quic)
        .with_conversation(at, quic_talk.clone())
        .with_conversation(at, tcp_talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    Multi::new(env).unwrap()
}

/// `racing_peer`, the TCP attempt's socket opened first, as a TCP first
/// attempt's is.
fn tcp_first_peer(
    quic: Peer,
    quic_talk: &Conversation,
    tcp: Peer,
    tcp_talk: &Conversation,
) -> Multi {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, tcp)
        .with_datagram_peer(at, quic)
        .with_conversation(at, tcp_talk.clone())
        .with_conversation(at, quic_talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    Multi::new(env).unwrap()
}

/// What the TCP attempt's peer says over TLS: an HTTP/1.1 response of
/// `hello`.
fn tls_hello() -> Conversation {
    use crate::tls::fake::{self, WELCOME};
    let response = fake::records(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").unwrap();
    Conversation::replies(&[WELCOME, &response], false).per_send()
}

/// A GET of `https://127.0.0.1:PORT/` by `e` in HTTP/3, falling back to
/// HTTP/1.1 (`--http3`), with no HTTP/2 library.
fn h3_race(m: &mut Multi, e: Easy, talk: &Conversation) -> Ran {
    let url = format!("https://127.0.0.1:{PORT}/");
    get_with(m, e, "/", talk.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3;
    })
}

/// A QUIC script that sends its first flight and hears nothing it can
/// use.
fn first_flight_only() -> Arc<Mutex<Script>> {
    let script = Script::new();
    script
        .lock()
        .unwrap()
        .out
        .extend([vec![1; 1200], vec![2; 1200], vec![]]);
    script
}

/// The HTTPS connect filter's lines, the first attempt's reply asked for
/// and the destroys of the attempts that lost, in order.
fn race_lines(ran: &Ran) -> Vec<String> {
    lines(
        ran,
        &[
            "[HTTPS-CONNECT]",
            "[HAPPY-EYEBALLS] query",
            "[HAPPY-EYEBALLS] destroy",
            "[SETUP] destroy",
            "[HTTP/3] destroy",
            "[UDP] destroy",
            "[TCP] destroy",
            "[TIMER] [ALPN_EYEBALLS]",
            "using HTTP",
        ],
    )
}

/// A QUIC peer that never answers: the first attempt has seen nothing by
/// the soft timeout, half the eyeballs timeout, and the second, over TCP,
/// starts then and wins; the QUIC attempt goes with the HTTPS connect
/// filter, its setup's filters with it (`time_to_start_baller2`,
/// `cf_hc_ctx_destroy`). C's `--http3` against a server whose UDP port
/// takes datagrams and answers none.
#[test]
fn a_silent_quic_peer_gives_way_to_tcp_at_the_soft_timeout() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = tls_hello();
    let mut m = racing_peer(Peer::Silent, &quic_talk, Peer::Accepts, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let ran = h3_race(&mut m, e, &tcp_talk);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"hello");
    let want = expect(
        "
        [HTTPS-CONNECT] added
        [HTTPS-CONNECT] connect, init
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] 1st attempt uses h3 from wanted versions
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] 2nd attempt uses h1 from wanted versions
        [TIMER] [ALPN_EYEBALLS] set for 100000us
        [HTTPS-CONNECT] connect -> 0, done=0
        [HTTPS-CONNECT] adjust_pollset -> 0, 1 socks
        [HAPPY-EYEBALLS] query connect reply: -1ms
        [HTTPS-CONNECT] h3 has not seen any data after 100ms, starting h1
        [HTTPS-CONNECT] connect -> 0, done=0
        [HTTPS-CONNECT] adjust_pollset -> 0, 2 socks
        ",
    );
    let got = race_lines(&ran);
    assert_eq!(got[..want.len()], want[..], "{got:#?}");
    let end = expect(
        "
        [HTTPS-CONNECT] connect -> 0, done=1
        [HTTPS-CONNECT] removing connected setup filter
        [HTTPS-CONNECT] destroy
        [SETUP] destroy
        [HAPPY-EYEBALLS] destroy
        [HTTP/3] destroy
        [UDP] destroy
        [SETUP] destroy
        [HAPPY-EYEBALLS] destroy
        using HTTP/1.x
        ",
    );
    let tail = got.len() - end.len();
    assert_eq!(got[tail..], end[..], "{got:#?}");
    // The TCP attempt started at the soft timeout.
    let connect = ran.easy.report().timings().connect();
    assert_eq!(connect.as_millis(), 100, "{got:#?}");
}

/// A TCP second that connects a while after it starts leads beside the
/// QUIC first still running (`cf_hc_connect`): each pass drives the
/// first, then the second; the pollset holds the first's socket, then the
/// second's (`cf_hc_adjust_pollset`, the ballers in their order); the
/// second's connect sets the race's timers; and once it wins, the first
/// goes with the HTTPS connect filter.
#[test]
fn a_tcp_second_leads_beside_a_quic_first_until_it_wins() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = tls_hello();
    let mut m = racing_peer(
        Peer::Silent,
        &quic_talk,
        Peer::AcceptsAfter(Duration::from_millis(50)),
        &tcp_talk,
    );
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let ran = h3_race(&mut m, e, &tcp_talk);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    let text: Vec<String> = ran
        .seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .collect();
    let from = text
        .iter()
        .position(|l| l.contains("starting h1"))
        .expect("the second starts");
    let to = text
        .iter()
        .position(|l| l.contains("using HTTP"))
        .expect("the transfer goes on");
    let got = &text[from..=to];
    let want = expect(
        "
        [0-0] [HTTPS-CONNECT] h3 has not seen any data after 100ms, starting h1
        [0-0] [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP]
        [0-0] [SETUP] happy eyeballing to origin 127.0.0.1:8990
        [0-0] [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [0-0] [HAPPY-EYEBALLS] init ip ballers for transport 3
        [0-0] [HAPPY-EYEBALLS] want to do more
        [0-0] [DNS] get 0th result for 127.0.0.1:8990, family=10, dns=1
        [0-0] [HAPPY-EYEBALLS] check for next AAAA address: none
        [0-0] [DNS] get 0th result for 127.0.0.1:8990, family=2, dns=1
        [0-0] [HAPPY-EYEBALLS] check for next A address: found
        [0-0] [HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0
        [0-0]   Trying 127.0.0.1:8990...
        [0-0] [TCP] cf_socket_open() -> 0, fd=1001
        [0-0] [TCP] local address 127.0.0.1 port 40001...
        [0-0] [HAPPY-EYEBALLS] checked connect attempts: 1 ongoing, 0 inconclusive
        [0-0] [DNS] get 1th result for 127.0.0.1:8990, family=2, dns=1
        [0-0] [DNS] get 0th result for 127.0.0.1:8990, family=10, dns=1
        [0-0] [DNS] get 1th result for 127.0.0.1:8990, family=2, dns=1
        [0-0] [DNS] get 0th result for 127.0.0.1:8990, family=10, dns=1
        [0-0] [HTTPS-CONNECT] connect -> 0, done=0
        [0-0] [DNS] Curl_conn_connect(block=0) -> 0, done=0
        [0-0] [UDP] adjust_pollset, !active, POLLIN fd=1000
        [0-0] [HAPPY-EYEBALLS] adjust_pollset -> 0, 1 socks
        [0-0] [TCP] adjust_pollset, !connected, POLLOUT fd=1001
        [0-0] [HAPPY-EYEBALLS] adjust_pollset -> 0, 2 socks
        [0-0] [HTTPS-CONNECT] adjust_pollset -> 0, 2 socks
        [0-0] [MULTI] [CONNECTING] pollset[fd=1000 IN, fd=1001 OUT], timeouts=1
        [0-0] [TIMER] [TIMEOUT] expires in 9900000us
        [0-0] [TIMER] [TIMEOUT] gives multi timeout in 9900ms
        [0-0] [MULTI] [CONNECTING] multi_wait(fds=2, timeout=1000) tinternal=9900
        [0-0] [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [0-0] [HTTP/3] progress_ingress(socket)
        [0-0] [HTTP/3] ingress, recvmmsg -> EAGAIN
        [0-0] [HTTP/3] egress, collect and send packets, quantum=12000
        [0-0] [HAPPY-EYEBALLS] checked connect attempts: 1 ongoing, 0 inconclusive
        [0-0] [DNS] get 1th result for 127.0.0.1:8990, family=2, dns=1
        [0-0] [DNS] get 0th result for 127.0.0.1:8990, family=10, dns=1
        [0-0] [DNS] get 1th result for 127.0.0.1:8990, family=2, dns=1
        [0-0] [DNS] get 0th result for 127.0.0.1:8990, family=10, dns=1
        [0-0] [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [0-0] [TCP] connected on fd=1001
        [0-0] [HAPPY-EYEBALLS] connect attempt #0 successful
        [0-0] [HAPPY-EYEBALLS] Connected to 127.0.0.1 (127.0.0.1) port 8990
        [0-0] [TIMER] [HAPPY_EYEBALLS] cleared
        [0-0] [SETUP] added SSL filter for origin
        [0-0] [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP][!SSL][HAPPY-EYEBALLS][TCP]
        [0-0] [SSL] cf_connect()
        [0-0] [TCP] send(len=17) -> 0, 17
        [0-0] [TCP] recv(len=19) -> 0, 19
        [0-0] [TCP] send(len=17) -> 0, 17
        [0-0] [SSL] cf_connect() -> 0, done=1
        [0-0] [SETUP] query ALPN
        [0-0] [SSL] query ALPN: returning 'http/1.1'
        [0-0] [HTTPS-CONNECT] connect -> 0, done=1
        [0-0] [DNS] connected filter chain below
        [0-0] [DNS] Curl_conn_connect(block=0) -> 0, done=1
        [0-0] [MULTI] [CONNECTING] [PGRS-APPCONNECT] added 150000us
        [0-0] [MULTI] [CONNECTING] [PGRS-CONNECT] added 150000us
        [0-0] Established connection to 127.0.0.1 (127.0.0.1 port 8990) from 127.0.0.1 port 40001
        [0-0] [MULTI] [CONNECTING] connected [0][DNS][HTTPS-CONNECT][SETUP][SSL][HAPPY-EYEBALLS][TCP]
        [0-0] [DNS] removing connected setup filter
        [0-0] [DNS] destroy
        [0-0] [HTTPS-CONNECT] removing connected setup filter
        [0-0] [HTTPS-CONNECT] destroy
        [0-0] [SETUP] destroy
        [0-0] [HAPPY-EYEBALLS] destroy
        [0-0] [HTTP/3] destroy
        [0-0] [UDP] destroy
        [0-0] [UDP] cf_socket_close, fd=1000
        [0-0] [MULTI] [CONNECTING] Curl_multi_will_close fd=1000
        [0-0] [SETUP] removing connected setup filter
        [0-0] [SETUP] destroy
        [0-0] [HAPPY-EYEBALLS] removing connected setup filter
        [0-0] [HAPPY-EYEBALLS] destroy
        [0-0] [MULTI] [CONNECTING] reduced to [0][SSL][TCP]
        [0-0] [MULTI] [CONNECTING] -> [PROTOCONNECT]
        [0-0] [MULTI] [PROTOCONNECT] -> [DO]
        [0-0] [SSL] query ALPN
        [0-0] [SSL] query ALPN: returning 'http/1.1'
        [0-0] using HTTP/1.x
        ",
    );
    assert_eq!(got, &want[..], "{got:#?}");
}

/// A TCP second leading beside a QUIC first answers for the connection
/// while it is set up: its TLS filter, waiting for the server's
/// handshake, puts its socket in the pollset beside the first's.
#[test]
fn a_tcp_second_leading_answers_for_the_connection() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = tls_hello().late_replies();
    let mut m = racing_peer(
        Peer::Silent,
        &quic_talk,
        Peer::AcceptsAfter(Duration::from_millis(50)),
        &tcp_talk,
    );
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let ran = h3_race(&mut m, e, &tcp_talk);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    let text: Vec<String> = ran
        .seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .collect();
    let from = text
        .iter()
        .position(|l| l.contains("[TCP] recv(len=19) -> 81, 0"))
        .expect("the second's TLS waits");
    let to = from
        + text[from..]
            .iter()
            .position(|l| l.contains("pollset[fd="))
            .expect("its pollset is made");
    // As C's: the first's socket and its racing HAPPY-EYEBALLS saying
    // how many sockets the pollset has, then the second's TLS filter's and
    // its socket filter's, its HAPPY-EYEBALLS connected and silent.
    let want = expect(
        "
        [0-0] [TCP] recv(len=19) -> 81, 0
        [0-0] [SSL] cf_connect() -> 0, done=0
        [0-0] [HTTPS-CONNECT] connect -> 0, done=0
        [0-0] [DNS] Curl_conn_connect(block=0) -> 0, done=0
        [0-0] [UDP] adjust_pollset, !active, POLLIN fd=1000
        [0-0] [HAPPY-EYEBALLS] adjust_pollset -> 0, 1 socks
        [0-0] [SSL] adjust_pollset, POLLIN fd=1001
        [0-0] [TCP] adjust_pollset, !active, POLLIN fd=1001
        [0-0] [HTTPS-CONNECT] adjust_pollset -> 0, 2 socks
        [0-0] [MULTI] [CONNECTING] pollset[fd=1000 IN, fd=1001 IN], timeouts=1
        ",
    );
    assert_eq!(&text[from..=to], &want[..], "{text:#?}");
}

/// Whether `want` are among `got`, in order.
fn in_order(got: &[String], want: &[String]) -> bool {
    let mut left = got.iter();
    want.iter().all(|w| left.any(|g| g == w))
}

/// A QUIC peer that answers with a datagram the library makes nothing
/// of: the first attempt has seen data by the soft timeout, which arms the
/// hard one again for what is left of it, and the second starts at the
/// hard timeout (`time_to_start_baller2`). C's `--http3` against a server
/// whose UDP port answers each datagram with a zero byte.
#[test]
fn a_stalled_quic_peer_gives_way_to_tcp_at_the_hard_timeout() {
    let quic_talk = Conversation::replies(&[b"\0"], false).per_send();
    let tcp_talk = tls_hello();
    let mut m = racing_peer(Peer::Accepts, &quic_talk, Peer::Accepts, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let ran = h3_race(&mut m, e, &tcp_talk);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"hello");
    let got = race_lines(&ran);
    let want = expect(
        "
        [HTTPS-CONNECT] 2nd attempt uses h1 from wanted versions
        [TIMER] [ALPN_EYEBALLS] set for 100000us
        [HAPPY-EYEBALLS] query connect reply: 0ms
        [TIMER] [ALPN_EYEBALLS] set for 100000us
        [HTTPS-CONNECT] h3 inconclusive after 200, starting h1
        [HTTPS-CONNECT] destroy
        [SETUP] destroy
        [HAPPY-EYEBALLS] destroy
        [HTTP/3] destroy
        [UDP] destroy
        using HTTP/1.x
        ",
    );
    assert!(in_order(&got, &want), "{got:#?}");
    // The reply is asked for once, as it is known from then on.
    let asked = got
        .iter()
        .filter(|l| l.contains("query connect reply"))
        .count();
    assert_eq!(asked, 1, "{got:#?}");
    assert_eq!(ran.easy.report().timings().connect().as_millis(), 200);
}

/// A QUIC peer that refuses: the first attempt fails, and the second
/// starts at once; the first's setup's filters go with the HTTPS connect
/// filter, its attempt gone as it failed. C's `--http3` against a server
/// with no UDP port open.
#[test]
fn a_refused_quic_attempt_starts_tcp_at_once() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = tls_hello();
    let mut m = racing_peer(Peer::Refuses, &quic_talk, Peer::Accepts, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let ran = h3_race(&mut m, e, &tcp_talk);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"hello");
    let got = race_lines(&ran);
    let want = expect(
        "
        [HTTPS-CONNECT] 2nd attempt uses h1 from wanted versions
        [HTTP/3] destroy
        [UDP] destroy
        [HTTPS-CONNECT] h3 baller failed, starting h1
        [HTTPS-CONNECT] removing connected setup filter
        [HTTPS-CONNECT] destroy
        [SETUP] destroy
        [HAPPY-EYEBALLS] destroy
        [SETUP] destroy
        using HTTP/1.x
        ",
    );
    assert!(in_order(&got, &want), "{got:#?}");
    assert!(
        !got.iter().any(|l| l.contains("query connect reply")),
        "{got:#?}"
    );
    // What the first attempt said of its failure is let go.
    assert!(ran.easy.report().unsaid());
}

/// A QUIC peer that answers late, after the soft timeout started the
/// second attempt over TCP, whose peer never answers: the first wins, and
/// the second goes with the HTTPS connect filter (`baller_connected`,
/// `cf_hc_ctx_destroy`).
#[test]
fn a_late_quic_peer_wins_over_a_tcp_attempt_running() {
    let quic_talk = Conversation::replies(&[b"server flight", b"response"], false).per_send();
    let tcp_talk = Conversation::replies(&[], false).per_send();
    let late = Peer::AcceptsAfter(std::time::Duration::from_millis(150));
    let mut m = racing_peer(late, &quic_talk, Peer::Silent, &tcp_talk);
    // The request's packet goes as it is submitted, however often the
    // attempt was driven as it waited.
    let script = get_script(b"quic");
    {
        let mut s = script.lock().unwrap();
        s.out.truncate(3);
        s.on_submit.push_back(vec![vec![3; 75], vec![]]);
    }
    let e = tracing(FakeTls::agreeing().unwrap(), &script);
    let ran = h3_race(&mut m, e, &tcp_talk);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"quic");
    let got = race_lines(&ran);
    let want = expect(
        "
        [HTTPS-CONNECT] h3 has not seen any data after 100ms, starting h1
        [HTTPS-CONNECT] connect -> 0, done=1
        [HTTPS-CONNECT] removing connected setup filter
        [HTTPS-CONNECT] destroy
        [SETUP] destroy
        [HAPPY-EYEBALLS] destroy
        [TCP] destroy
        using HTTP/3
        ",
    );
    assert!(in_order(&got, &want), "{got:#?}");
    assert!(tcp_talk.received().is_empty(), "nothing goes over TCP");
}

/// A QUIC peer that answers late, after the soft timeout started the
/// second attempt over TCP, which leads and is refused: the race goes on
/// with the first, which wins, the second's failure not taken for the
/// first's (`cf_hc_connect` fails only once every baller has).
#[test]
fn a_late_quic_peer_wins_after_the_leading_tcp_attempt_failed() {
    let quic_talk = Conversation::replies(&[b"server flight", b"response"], false).per_send();
    let tcp_talk = Conversation::replies(&[], false).per_send();
    let late = Peer::AcceptsAfter(std::time::Duration::from_millis(150));
    let mut m = racing_peer(late, &quic_talk, Peer::Refuses, &tcp_talk);
    let script = get_script(b"quic");
    {
        let mut s = script.lock().unwrap();
        s.out.truncate(3);
        s.on_submit.push_back(vec![vec![3; 75], vec![]]);
    }
    let e = tracing(FakeTls::agreeing().unwrap(), &script);
    let ran = h3_race(&mut m, e, &tcp_talk);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"quic");
    let got = race_lines(&ran);
    let want = expect(
        "
        [HTTPS-CONNECT] h3 has not seen any data after 100ms, starting h1
        [HTTPS-CONNECT] connect -> 0, done=0
        [HTTPS-CONNECT] adjust_pollset -> 0, 2 socks
        [TCP] destroy
        [HTTPS-CONNECT] connect -> 0, done=0
        [HTTPS-CONNECT] adjust_pollset -> 0, 1 socks
        [HTTPS-CONNECT] connect -> 0, done=1
        [HTTPS-CONNECT] removing connected setup filter
        [HTTPS-CONNECT] destroy
        [SETUP] destroy
        [HAPPY-EYEBALLS] destroy
        using HTTP/3
        ",
    );
    let from = got
        .iter()
        .position(|l| l.contains("starting h1"))
        .expect("the second starts");
    assert_eq!(got[from..], want[..], "{got:#?}");
}

/// Both attempts fail: the setup fails with the first's failure, not the
/// second's (`cf_hc_connect`'s `ctx->result = ballers[0].result`).
#[test]
fn a_race_both_attempts_lose_fails_with_the_first_s_failure() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = Conversation::replies(&[], false).per_send();
    let mut m = racing_peer(Peer::Refuses, &quic_talk, Peer::HangsUp, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let ran = h3_race(&mut m, e, &tcp_talk);
    assert_eq!(
        ran.result,
        Err(ErrorKind::CouldntConnect),
        "{:#?}",
        ran.seen.text()
    );
    let got = race_lines(&ran);
    assert!(
        in_order(
            &got,
            &expect(
                "
                [HTTPS-CONNECT] h3 baller failed, starting h1
                [HTTPS-CONNECT] connect, all attempts failed
                [HTTPS-CONNECT] connect -> 7, done=0
                "
            )
        ),
        "{got:#?}"
    );
}

/// Both attempts fail, the second once TCP connected, its handshake cut
/// short: the second, kept as it failed, is the one attempt connected at
/// the network level, and reports the ends the transfer keeps (`cf_hc_cntrl`'s
/// `CF_CTRL_CONN_INFO_UPDATE`). C's tool, `--http3` to a TCP server that
/// hangs up on the handshake and nothing on UDP, reports them so.
#[test]
fn a_race_lost_after_the_second_connected_keeps_the_second_s_ends() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = Conversation::replies(&[b""], true).greeting();
    let mut m = racing_peer(Peer::Refuses, &quic_talk, Peer::Accepts, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let ran = h3_race(&mut m, e, &tcp_talk);
    assert_eq!(
        ran.result,
        Err(ErrorKind::CouldntConnect),
        "{:#?}",
        ran.seen.text()
    );
    let ends = ran.easy.report().primary().expect("the second's ends");
    assert_eq!(
        ends.remote,
        crate::conn::io::Remote::Inet(std::net::SocketAddr::from(([127, 0, 0, 1], PORT)))
    );
    assert!(ends.local.is_some());
}

/// `e` with an alt-svc cache that knows `entry`, a line of its file.
fn knowing(mut e: Easy, name: &str, entry: &str) -> Easy {
    let file = std::env::temp_dir().join(format!("curl-core-h3-alt-{name}-{}", std::process::id()));
    std::fs::write(&file, format!("{entry} \"20991231 00:00:00\" 0 0\n")).unwrap();
    e.add_alt_svc_file(Some(file.as_os_str().as_encoded_bytes()))
        .unwrap();
    std::fs::remove_file(&file).unwrap();
    e
}

/// A GET of `https://127.0.0.1:PORT/` by `e`, in `version`.
fn race_in(
    m: &mut Multi,
    e: Easy,
    talk: &Conversation,
    version: crate::options::HttpVersion,
) -> Ran {
    let url = format!("https://127.0.0.1:{PORT}/");
    get_with(m, e, "/", talk.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = version;
    })
}

/// An alternative service for the origin itself in HTTP/3 has a transfer
/// that asks for no version try HTTP/3 first, as the version preferred,
/// HTTP/3 now wanted too; refused, HTTP/1.1 over TCP takes over
/// (`url_set_conn_peer`'s same destination, `cf_hc_get_pref_alpn`). C's
/// test_06_20.
#[test]
fn an_alternative_here_in_http3_is_tried_first() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = tls_hello();
    let mut m = racing_peer(Peer::Refuses, &quic_talk, Peer::Accepts, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let entry = format!("h1 127.0.0.1 {PORT} h3 127.0.0.1 {PORT}");
    let e = knowing(e, "here-h3", &entry);
    let ran = race_in(&mut m, e, &tcp_talk, crate::options::HttpVersion::Any);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"hello");
    let got = race_lines(&ran);
    let want = expect(
        "
        [HTTPS-CONNECT] 1st attempt uses h3 from preferred version
        [HTTPS-CONNECT] 2nd attempt uses h1 from wanted versions
        [HTTPS-CONNECT] h3 baller failed, starting h1
        using HTTP/1.x
        ",
    );
    assert!(in_order(&got, &want), "{got:#?}");
    // No other peer is gone to.
    let text = ran.seen.text();
    assert!(!text.iter().any(|l| l.contains("Alt-svc connecting")));
}

/// An alternative service for the origin itself in HTTP/1.1 has a
/// transfer in HTTP/3 try HTTP/1.1 first, offering it alone, and HTTP/3
/// second; TCP answers at once and wins (`cf_hc_set_baller1` clearing
/// HTTP/2 from the wanted versions). C's test_06_21.
#[test]
fn an_alternative_here_in_http1_leads_an_http3_transfer() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = tls_hello();
    let mut m = tcp_first_peer(Peer::Silent, &quic_talk, Peer::Accepts, &tcp_talk);
    let tls: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    let e = tracing_by(tls, &first_flight_only());
    let entry = format!("h3 127.0.0.1 {PORT} http/1.1 127.0.0.1 {PORT}");
    let e = knowing(e, "here-h1", &entry);
    let ran = race_in(&mut m, e, &tcp_talk, crate::options::HttpVersion::Http3);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"hello");
    let got = race_lines(&ran);
    let want = expect(
        "
        [HTTPS-CONNECT] 1st attempt uses h1 from preferred version
        [HTTPS-CONNECT] 2nd attempt uses h3 from wanted versions
        [TIMER] [ALPN_EYEBALLS] set for 100000us
        using HTTP/1.x
        ",
    );
    assert!(in_order(&got, &want), "{got:#?}");
    assert_eq!(tls.log().alpn, Some(crate::tls::Alpn::Http11));
    assert!(!got.iter().any(|l| l.contains("starting h3")), "{got:#?}");
    assert_eq!(ran.easy.report().timings().connect().as_millis(), 0);
}

/// A TCP first attempt whose peer never answers gives way at the soft
/// timeout to HTTP/3, the second, which is driven and polled after it
/// and wins; the TCP attempt goes with the HTTPS connect filter.
#[test]
fn a_silent_tcp_first_gives_way_to_quic_at_the_soft_timeout() {
    let quic_talk = Conversation::replies(&[b"server flight", b"response"], false).per_send();
    let tcp_talk = Conversation::replies(&[], false).per_send();
    let mut m = tcp_first_peer(Peer::Accepts, &quic_talk, Peer::Silent, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &get_script(b"quic"));
    let entry = format!("h3 127.0.0.1 {PORT} http/1.1 127.0.0.1 {PORT}");
    let e = knowing(e, "tcp-first", &entry);
    let ran = race_in(&mut m, e, &tcp_talk, crate::options::HttpVersion::Http3);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"quic");
    let got = race_lines(&ran);
    let want = expect(
        "
        [HTTPS-CONNECT] 1st attempt uses h1 from preferred version
        [HTTPS-CONNECT] 2nd attempt uses h3 from wanted versions
        [HAPPY-EYEBALLS] query connect reply: -1ms
        [HTTPS-CONNECT] h1 has not seen any data after 100ms, starting h3
        [HTTPS-CONNECT] adjust_pollset -> 0, 2 socks
        [HTTPS-CONNECT] connect -> 0, done=1
        [HTTPS-CONNECT] removing connected setup filter
        [HTTPS-CONNECT] destroy
        [SETUP] destroy
        [HAPPY-EYEBALLS] destroy
        [TCP] destroy
        using HTTP/3
        ",
    );
    assert!(in_order(&got, &want), "{got:#?}");
    // The first attempt's socket is polled, and traced, before the
    // second's.
    let text = ran.seen.text();
    assert!(
        text.iter()
            .any(|l| l.contains("[CONNECTING] pollset[fd=1000 OUT, fd=1001 IN]")),
        "{text:#?}"
    );

    let adjusted = lines(&ran, &["[TCP] adjust_pollset", "[UDP] adjust_pollset"]);
    let tcp = adjusted.iter().position(|l| l.starts_with("[TCP]"));
    let udp = adjusted.iter().position(|l| l.starts_with("[UDP]"));
    assert!(tcp.is_some() && tcp < udp, "{adjusted:#?}");
    assert_eq!(ran.easy.report().timings().connect().as_millis(), 100);
    assert!(tcp_talk.received().is_empty(), "nothing goes over TCP");
}

/// A TCP first attempt refused starts HTTP/3, the second, at once, which
/// wins as the first lies failed in the lease.
#[test]
fn a_refused_tcp_first_starts_quic_at_once() {
    let quic_talk = Conversation::replies(&[b"server flight", b"response"], false).per_send();
    let tcp_talk = Conversation::replies(&[], false).per_send();
    let mut m = tcp_first_peer(Peer::Accepts, &quic_talk, Peer::Refuses, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &get_script(b"quic"));
    let entry = format!("h3 127.0.0.1 {PORT} http/1.1 127.0.0.1 {PORT}");
    let e = knowing(e, "tcp-refused", &entry);
    let ran = race_in(&mut m, e, &tcp_talk, crate::options::HttpVersion::Http3);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"quic");
    let got = race_lines(&ran);
    let want = expect(
        "
        [HTTPS-CONNECT] h1 baller failed, starting h3
        [HTTPS-CONNECT] connect -> 0, done=1
        [HTTPS-CONNECT] destroy
        [SETUP] destroy
        [HAPPY-EYEBALLS] destroy
        using HTTP/3
        ",
    );
    assert!(in_order(&got, &want), "{got:#?}");
    assert_eq!(ran.easy.report().timings().connect().as_millis(), 0);
}

/// A TCP first attempt and the HTTP/3 second both fail: the setup fails
/// with the first's failure, TCP's.
#[test]
fn a_tcp_first_and_quic_second_failing_fail_with_tcp_s_failure() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    // The TCP peer hangs up in the TLS handshake.
    let tcp_talk = Conversation::replies(&[], true).per_send();
    let mut m = tcp_first_peer(Peer::Refuses, &quic_talk, Peer::Accepts, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let entry = format!("h3 127.0.0.1 {PORT} http/1.1 127.0.0.1 {PORT}");
    let e = knowing(e, "both-fail", &entry);
    let ran = race_in(&mut m, e, &tcp_talk, crate::options::HttpVersion::Http3);
    let got = race_lines(&ran);
    assert!(
        ran.result.is_err_and(|e| e != ErrorKind::CouldntConnect),
        "{:?} {got:#?}",
        ran.result
    );
    assert!(
        in_order(
            &got,
            &expect(
                "
                [HTTPS-CONNECT] h1 baller failed, starting h3
                [HTTPS-CONNECT] connect, all attempts failed
                "
            )
        ),
        "{got:#?}"
    );
}

/// The HTTP/3 first attempt, set aside, fails after the TCP second
/// failed: the setup fails with the first's failure, QUIC's, though it
/// came last.
#[test]
fn a_quic_first_failing_last_still_names_the_failure() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = Conversation::replies(&[], false).per_send();
    let late = Peer::RefusesAfter(std::time::Duration::from_millis(150));
    let mut m = racing_peer(late, &quic_talk, Peer::HangsUp, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let ran = h3_race(&mut m, e, &tcp_talk);
    let got = race_lines(&ran);
    assert_eq!(
        ran.result,
        Err(ErrorKind::CouldntConnect),
        "{:#?}",
        ran.seen.text()
    );
    assert!(
        in_order(
            &got,
            &expect(
                "
                [HTTPS-CONNECT] h3 has not seen any data after 100ms, starting h1
                [HTTPS-CONNECT] connect, all attempts failed
                [HTTPS-CONNECT] connect -> 7, done=0
                "
            )
        ),
        "{got:#?}"
    );
}

/// An alternative service elsewhere in HTTP/3 has the transfer dial QUIC
/// alone, HTTP/3 the one version it then wants (`conn->transport_wanted`).
#[test]
fn an_alternative_elsewhere_in_http3_is_dialed_over_quic() {
    let quic_talk = Conversation::replies(&[b"server flight", b"response"], false).per_send();
    let tcp_talk = Conversation::replies(&[], false).per_send();
    let mut m = racing_peer(Peer::Accepts, &quic_talk, Peer::Refuses, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &get_script(b"quic"));
    let entry = format!("h1 127.0.0.1 1 h3 127.0.0.1 {PORT}");
    let e = knowing(e, "elsewhere", &entry);
    let url = "https://127.0.0.1:1/".to_string();
    let ran = get_with(&mut m, e, "/", quic_talk.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"quic");
    let got = race_lines(&ran);
    let want = expect(
        "
        [HTTPS-CONNECT] 1st attempt uses h3 from wanted versions
        using HTTP/3
        ",
    );
    assert!(in_order(&got, &want), "{got:#?}");
    assert!(!got.iter().any(|l| l.contains("2nd attempt")), "{got:#?}");
    let text = ran.seen.text();
    let switch = format!("Alt-svc connecting from [h1]127.0.0.1:1 to [h3]127.0.0.1:{PORT}");
    assert!(text.iter().any(|l| l.contains(&switch)), "{text:#?}");
    // Its connection wants QUIC from the start, as its name's filter says
    // (`transport_wanted`).
    let made = format!("[DNS] [A+AAAA] created DNS filter for 127.0.0.1:{PORT}, transport=5\n");
    assert!(text.iter().any(|l| l.ends_with(&made)), "{text:#?}");
}

/// A race that runs out of time with both its attempts under way fails,
/// both attempts closed with the request, the QUIC one first, as C's
/// connect filter destroys its attempts in their order
/// (`cf_hc_ctx_destroy`). They go with the connection, on no transfer's
/// trace: C's says nothing of their sockets between the request's end
/// and the connection's close.
#[test]
fn a_race_timed_out_closes_both_attempts() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = Conversation::replies(&[], false).per_send();
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Silent)
        .with_datagram_peer(at, Peer::Silent)
        .with_conversation(at, quic_talk.clone())
        .with_conversation(at, tcp_talk.clone());
    let closed = Arc::new(Mutex::new(Vec::new()));
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(Closes(net, closed.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let url = format!("https://127.0.0.1:{PORT}/");
    let ran = get_with(&mut m, e, "/", tcp_talk.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3;
        o.limits.connect = crate::time::TimeLimit::from_millis(300);
    });
    assert_eq!(
        ran.result,
        Err(ErrorKind::OperationTimedout),
        "{:#?}",
        ran.seen.text()
    );
    let got = race_lines(&ran);
    assert!(
        got.iter().any(|l| l.contains("starting h1")),
        "both ran: {got:#?}"
    );
    assert_eq!(*closed.lock().unwrap(), [1000, 1001]);
    let text: Vec<String> = ran
        .seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .collect();
    let from = text
        .iter()
        .position(|l| l.starts_with("Connection timed out"))
        .expect("the race runs out");
    let after: Vec<&str> = text[from..]
        .iter()
        .map(String::as_str)
        .filter(|l| l.starts_with("[0-0] [MULTI]") || l.starts_with("[0-0] closing"))
        .take(5)
        .collect();
    assert_eq!(
        after,
        [
            "[0-0] [MULTI] [CONNECTING] multi_done: status: 28 prem: 1 done: 0",
            "[0-0] [MULTI] [CONNECTING] multi_done_locked, in use=0",
            "[0-0] [MULTI] [CONNECTING] multi_done, terminating conn #0 to 127.0.0.1:8990, \
             forbid=0, close=0, premature=1, conn_multiplex=0",
            "[0-0] closing connection #0",
            "[0-0] [MULTI] [CONNECTING] -> [COMPLETED]",
        ],
        "{text:#?}"
    );
}
/// A network that keeps the descriptor of each socket it closes, in
/// order.
struct Closes(FakeNet, Arc<Mutex<Vec<crate::conn::io::RawSocket>>>);

impl crate::conn::io::Net for Closes {
    fn poll(
        &mut self,
        sockets: &mut [crate::conn::io::SocketPoll<'_>],
        fds: &mut [crate::conn::io::PollFd<'_>],
        timeout: Duration,
    ) -> std::io::Result<u32> {
        self.0.poll(sockets, fds, timeout)
    }

    fn open(
        &mut self,
        addr: &crate::conn::io::Remote,
        kind: crate::conn::io::SocketKind,
    ) -> std::io::Result<Box<dyn crate::conn::io::Socket>> {
        self.0.open(addr, kind)
    }

    fn close(&mut self, socket: crate::conn::io::Sock) {
        self.1.lock().unwrap().push(socket.key().get());
        self.0.close(socket);
    }

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn crate::conn::io::Resolver)) {
        self.0.with_resolver(f);
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.0.link_local_scope()
    }

    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: crate::conn::io::Ipv6Scope,
        scope_id: u32,
    ) -> crate::conn::io::InterfaceAddress {
        self.0.interface_address(name, v6, remote_scope, scope_id)
    }
}

/// The TCP first attempt fails after the HTTP/3 second failed: the setup
/// fails with the first's failure, though it came last.
#[test]
fn a_tcp_first_failing_last_still_names_the_failure() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = Conversation::replies(&[], false).per_send();
    let late = Peer::RefusesAfter(std::time::Duration::from_millis(150));
    let mut m = tcp_first_peer(Peer::Refuses, &quic_talk, late, &tcp_talk);
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let entry = format!("h3 127.0.0.1 {PORT} http/1.1 127.0.0.1 {PORT}");
    let e = knowing(e, "tcp-last", &entry);
    let ran = race_in(&mut m, e, &tcp_talk, crate::options::HttpVersion::Http3);
    let got = race_lines(&ran);
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect), "{got:#?}");
    assert!(
        in_order(
            &got,
            &expect(
                "
                [HTTPS-CONNECT] h1 has not seen any data after 100ms, starting h3
                [HTTPS-CONNECT] connect, all attempts failed
                "
            )
        ),
        "{got:#?}"
    );
    assert_eq!(ran.easy.report().timings().total().as_millis(), 150);
}

/// A transfer in HTTP/3 or older through a proxy: through a SOCKS proxy,
/// HTTP/3 may not be spoken, which is said as HTTP/3 is first weighed, and
/// the one attempt is over TCP (`cf_hc_may_h3`); through an HTTP proxy,
/// HTTP/3 is weighed as anywhere, its attempt over the proxy's
/// CONNECT-UDP first and the other over CONNECT once it fails, as C's
/// race runs through a proxy that refuses both.
#[test]
fn http3_through_a_proxy_is_weighed_as_c_weighs_it() {
    let cases = [
        ("socks5", Some("HTTP/3 is not supported over a SOCKS proxy")),
        ("http", None),
    ];
    for (proxy, why) in cases {
        let quic_talk = Conversation::replies(&[], false).per_send();
        let tcp_talk = Conversation::replies(&[], false).per_send();
        let mut m = tcp_first_peer(Peer::Accepts, &quic_talk, Peer::Refuses, &tcp_talk);
        let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
        let url = format!("https://localhost:{PORT}/");
        let ran = get_with(&mut m, e, "/", tcp_talk.clone(), |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
            o.http.version = crate::options::HttpVersion::Http3;
            let to = format!("{proxy}://127.0.0.1:{PORT}");
            o.proxy.make_mut().unwrap().url = Some(to.into_bytes());
        });
        assert_eq!(ran.result, Err(ErrorKind::CouldntConnect), "{proxy}");
        let got = race_lines(&ran);
        let has = |line: &str| got.iter().any(|l| l == line);
        if why.is_some() {
            assert!(
                has("[HTTPS-CONNECT] 1st attempt uses h1 from wanted versions"),
                "{got:#?}"
            );
            assert!(!got.iter().any(|l| l.contains("2nd attempt")), "{got:#?}");
        } else {
            assert!(
                has("[HTTPS-CONNECT] 1st attempt uses h3 from wanted versions"),
                "{got:#?}"
            );
            let order = lines(
                &ran,
                &[
                    "[HTTPS-CONNECT] 2nd attempt uses h1",
                    "[HTTPS-CONNECT] h3 baller failed, starting h1",
                    "[HTTPS-CONNECT] connect, all attempts failed",
                ],
            );
            assert_eq!(
                order,
                [
                    "[HTTPS-CONNECT] 2nd attempt uses h1 from wanted versions",
                    "[HTTPS-CONNECT] h3 baller failed, starting h1",
                    "[HTTPS-CONNECT] connect, all attempts failed",
                ],
                "{got:#?}"
            );
        }
        let said = lines(&ran, &["HTTP/3 is not supported"]);
        assert_eq!(said.len(), usize::from(why.is_some()), "{proxy}: {said:#?}");
        // Said as the first attempt is chosen, before it is named.
        if let Some(why) = why {
            let order = lines(&ran, &["HTTP/3 is not supported", "[HTTPS-CONNECT] 1st"]);
            assert_eq!(order[0], why, "{order:#?}");
        }
    }
}

/// A GET of `https://localhost:PORT/` by `e` in HTTP/3 alone, asking for
/// early data.
fn h3_early_get(m: &mut Multi, e: Easy) -> Ran {
    let url = format!("https://localhost:{PORT}/");
    get_with(m, e, "/", Conversation::replies(&[], false), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3Only;
        o.ip_version = IpVersion::Any;
        o.tls.options.make_mut().unwrap().ssl_options = crate::options::SslOptions::EARLYDATA;
    })
}

/// A session resumed that allows early data, made for HTTP/3 and kept
/// with its connection's transport parameters: they are set, HTTP/3 is
/// set up at once, and the connection counts as connected before its
/// first packet goes, which goes with the request's; the request goes as
/// early data, which the peer takes, and that is reported as the
/// handshake ends, the handshake's time the connection's
/// (`cf_ngtcp2_on_session_reuse`, `earlydata_skip`).
#[test]
fn a_request_goes_as_early_data_under_a_session_resumed() {
    for rejected in [false, true] {
        let script = get_script(b"123456789");
        script.lock().unwrap().early_rejected = rejected;
        let mut m = quic_server(&[b"server flight", b"response"]);
        let tls = FakeTls::quic_resuming(16384, Some(crate::tls::Chosen::H3), b"params").unwrap();
        let tls: &'static FakeTls = Box::leak(Box::new(tls));
        let e = tracing_by(tls, &script);
        let ran = h3_early_get(&mut m, e);
        assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
        assert_eq!(ran.seen.body(), b"123456789");
        assert_eq!(script.lock().unwrap().early_params, b"params");
        // The session told it goes, once, as the parameters were taken.
        assert_eq!(tls.log().early_decided, Some(true));
        assert_eq!(tls.log().early_decisions, 1);
        let got = lines(
            &ran,
            &[
                "SSL session allows",
                "[HTTP/3] connect ->",
                "[HTTP/3] egress, send collected",
                "[HTTP/3] [0] cf_send(len=",
                "[HTTP/3] handshake complete",
                "[HTTP/3] server did",
                "using HTTP/3",
            ],
        );
        let did = if rejected { " not" } else { "" };
        let want = expect(&format!(
            "SSL session allows 16384 bytes of early data, reusing ALPN 'h3'
            [HTTP/3] connect -> 0, done=1
            using HTTP/3
            [HTTP/3] egress, send collected 2 packets in 2400 bytes
            [HTTP/3] [0] cf_send(len=74) -> 0, 74
            [HTTP/3] handshake complete after 0ms, remote transport[max_udp_payload=1452, initial_max_data=786432]
            [HTTP/3] server did{did} accept 74 bytes of early data"
        ));
        assert_eq!(got[..want.len()], want[..], "{got:#?}");
        let sent = if rejected { -74 } else { 74 };
        assert_eq!(ran.easy.report().earlydata_sent(), sent);
    }
}

/// A session resumed that cannot carry early data says why, and the
/// connection is made as any other: one that allows none, one made for
/// another protocol, one kept without transport parameters, one whose
/// parameters the library refuses, and one the TLS library will not send
/// early data under (`cf_ngtcp2_on_session_reuse`). The session is told
/// none goes, its offer whole, but for the last: C's says early data
/// goes before the TLS library refuses it, the offer restricted.
#[test]
fn a_session_resumed_without_early_data_says_why() {
    use crate::tls::Chosen;
    type Case = (
        usize,
        Option<Chosen>,
        &'static [u8],
        Option<&'static str>,
        bool,
        &'static str,
        bool,
    );
    let cases: [Case; 5] = [
        (
            0,
            Some(Chosen::H3),
            b"params",
            None,
            false,
            "[HTTP/3] SSL session does not allow earlydata",
            false,
        ),
        (
            16384,
            Some(Chosen::H2),
            b"params",
            None,
            false,
            "[HTTP/3] SSL session from different ALPN, no early data",
            false,
        ),
        (
            16384,
            Some(Chosen::H3),
            b"",
            None,
            false,
            "[HTTP/3] no 0RTT transport parameters, no early data",
            false,
        ),
        (
            16384,
            Some(Chosen::H3),
            b"params",
            Some("ERR_MALFORMED_TRANSPORT_PARAM"),
            false,
            "[HTTP/3] no early data, failed to set 0RTT transport parameters: ERR_MALFORMED_TRANSPORT_PARAM",
            false,
        ),
        (
            16384,
            Some(Chosen::H3),
            b"params",
            None,
            true,
            "[HTTP/3] OpenSSL refused to use early data",
            true,
        ),
    ];
    for (most, alpn, params, refused, tls_refuses, why, decided) in cases {
        let script = get_script(b"123456789");
        {
            let mut s = script.lock().unwrap();
            s.early_params_refused = refused;
            s.early_tls_refuses = tls_refuses;
        }
        let mut m = quic_server(&[b"server flight", b"response"]);
        let tls = FakeTls::quic_resuming(most, alpn, params).unwrap();
        let tls: &'static FakeTls = Box::leak(Box::new(tls));
        let e = tracing_by(tls, &script);
        let ran = h3_early_get(&mut m, e);
        assert_eq!(ran.result, Ok(()), "{why}: {:#?}", ran.seen.text());
        assert_eq!(tls.log().early_decided, Some(decided), "{why}");
        assert_eq!(tls.log().early_decisions, 1, "{why}");
        assert_eq!(lines(&ran, &[why]).len(), 1, "{why}");
        assert!(lines(&ran, &["[HTTP/3] server did"]).is_empty(), "{why}");
        assert_eq!(ran.easy.report().earlydata_sent(), 0, "{why}");
        // Connected as the handshake ended, not before.
        let order = lines(
            &ran,
            &["[HTTP/3] connect ->", "[HTTP/3] handshake complete"],
        );
        assert!(
            order[0].starts_with("[HTTP/3] handshake complete"),
            "{why}: {order:#?}"
        );
    }
}

/// A transfer that does not ask for early data sends none under a
/// session resumed that allows it (`conn_cfg->earlydata`).
#[test]
fn a_transfer_not_asking_for_early_data_sends_none() {
    let script = get_script(b"123456789");
    let mut m = quic_server(&[b"server flight", b"response"]);
    let tls = FakeTls::quic_resuming(16384, Some(crate::tls::Chosen::H3), b"params").unwrap();
    let e = tracing(tls, &script);
    let url = format!("https://localhost:{PORT}/");
    let ran = get_with(&mut m, e, "/", Conversation::replies(&[], false), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3Only;
        o.ip_version = IpVersion::Any;
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"123456789");
    assert!(script.lock().unwrap().early_params.is_empty());
    assert!(lines(&ran, &["SSL session allows", "[HTTP/3] server did"]).is_empty());
    assert_eq!(ran.easy.report().earlydata_sent(), 0);
}

/// Two GETs on new connections, by a TLS backend whose QUIC sessions
/// give their ticket as `at` says: how many the second resumed.
fn second_resumes(at: crate::tls::fake::QuicTickets) -> usize {
    let tls = FakeTls::quic_ticketing(at).unwrap();
    let tls: &'static FakeTls = Box::leak(Box::new(tls));
    let conn: &[&[u8]] = &[b"server flight", b"response"];
    // A time of day well past 1970, which a ticket timed by no transfer
    // would be out of date at.
    let clock = ManualClock::new().unwrap();
    clock.set_unix_time(1_700_000_000);
    let (mut m, _) = quic_peer(clock, &[conn, conn]);
    for _ in 0..2 {
        let e = tracing_by(tls, &get_script(b"123456789"));
        let url = format!("https://localhost:{PORT}/");
        let ran = get_with(&mut m, e, "/", Conversation::replies(&[], false), |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
            o.http.version = crate::options::HttpVersion::Http3Only;
            o.ip_version = IpVersion::V6;
            o.limits.reuse.fresh = true;
        });
        assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    }
    tls.log().resumed
}

/// A QUIC connection's TLS session keeps its ticket in the transfer's
/// cache, valid by the transfer's time of day, whether it comes as the
/// handshake ends, in the setup's race, or in a packet read after, in a
/// request's step; the next connection to the peer resumes it
/// (`quic_ossl_new_session_cb`, `Curl_ssl_scache_put`).
#[test]
fn a_quic_session_ticket_is_kept_in_the_setup_or_the_request() {
    use crate::tls::fake::QuicTickets;
    assert_eq!(second_resumes(QuicTickets::AtHandshake), 1);
    assert_eq!(second_resumes(QuicTickets::After), 1);
}

/// What the TLS library made of the peer's certificate as a QUIC
/// handshake ends in the setup's race is the transfer's report, as a
/// transfer not checking its peer reads it (`CURLINFO_SSL_VERIFYRESULT`
/// after `-k`; `Curl_vquic_tls_verify_peer`).
#[test]
fn a_quic_peer_s_verify_result_is_reported() {
    let script = get_script(b"123456789");
    let mut m = quic_server(&[b"server flight", b"response"]);
    let e = tracing(FakeTls::quic_verifying(20).unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.easy.report().verify_result(), 20);
}

/// A request's packet the socket fails to send fails the transfer, the
/// connection saying why as it sends (`vquic_send_packets`' `failf`) in
/// the request's step.
#[test]
fn a_request_the_socket_fails_to_send_says_why() {
    let (mut m, talks) = quic_peer(
        ManualClock::new().unwrap(),
        &[&[b"server flight", b"response"]],
    );
    // The first flight goes; the GET's send fails as on a reset.
    let _ = talks[0].clone().breaking_after(1);
    let e = tracing(FakeTls::new().unwrap(), &get_script(b"123456789"));
    let ran = h3_get(&mut m, e);
    assert_eq!(
        ran.result,
        Err(ErrorKind::SendError),
        "{:#?}",
        ran.seen.text()
    );
    // The fake's broken peer fails a send as a closed pipe, EPIPE.
    let got = lines(&ran, &["sendmsg() returned", "[HTTP/3] [0] OPENED"]);
    assert_eq!(
        got[..2],
        [
            format!("[HTTP/3] [0] OPENED stream for https://localhost:{PORT}/"),
            "sendmsg() returned -1 (errno 32)".to_owned(),
        ]
    );
}

/// A script for a tunnel through an HTTP/3 proxy: the handshake's
/// flights, then the `CONNECT`'s packet, answered by `status`, then the
/// origin's request's packet, answered with `told`.
fn tunnel_script(status: &[u8], told: Vec<Told>) -> Arc<Mutex<Script>> {
    tunnel_script_with(status, &[(b"via", b"h3proxy")], told)
}

/// `tunnel_script`, the `CONNECT`'s answer with the `fields` after its
/// status.
fn tunnel_script_with(
    status: &[u8],
    fields: &[(&[u8], &[u8])],
    told: Vec<Told>,
) -> Arc<Mutex<Script>> {
    let script = Script::new();
    {
        let mut s = script.lock().unwrap();
        s.idle = Some(std::time::Duration::from_secs(30));
        s.out.extend([
            vec![1; 1200],
            vec![2; 1200],
            vec![],
            vec![],
            vec![3; 75],
            vec![],
            vec![4; 150],
            vec![],
        ]);
        s.on_read
            .push_back(vec![Told::HandshakeDone, Told::MaxBidiStreams(100)]);
        let header = |name: &[u8], value: &[u8]| Told::Header {
            stream: 0,
            name: name.to_vec(),
            value: value.to_vec(),
        };
        let mut answer = vec![header(b":status", status)];
        answer.extend(fields.iter().map(|&(name, value)| header(name, value)));
        answer.push(Told::HeadersDone(0));
        s.on_read.push_back(answer);
        s.on_read.push_back(told);
    }
    script
}

/// A GET of `http://origin.example/p` by `e` through the HTTP/3 proxy at
/// `https://localhost:PORT`, its tunnel a stream of a QUIC connection to
/// it.
fn through_h3_proxy(m: &mut Multi, e: Easy) -> Ran {
    through_h3_proxy_over(m, e, IpVersion::Any)
}

/// `through_h3_proxy`, the proxy's addresses tried those of `ip`: IPv6's
/// alone for a setup with one address to try.
fn through_h3_proxy_over(m: &mut Multi, e: Easy, ip: IpVersion) -> Ran {
    get_with(m, e, "/", Conversation::replies(&[], false), move |o| {
        o.set_url(Some(b"http://origin.example/p")).unwrap();
        o.ip_version = ip;
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("https://localhost:{PORT}").into_bytes());
        proxy.kind = crate::options::ProxyType::Https3;
        proxy.tunnel = true;
    })
}

/// A tunnel through an HTTP/3 proxy is a stream of a QUIC connection to
/// it, which the race makes as its attempt (`cf-ngtcp2-proxy.c`): the
/// `CONNECT` goes as the stream's fields once the handshake is done, the
/// proxy's answer is traced as C traces it, and the origin's request and
/// response, in HTTP/1.1, go as the stream's DATA.
#[test]
fn a_tunnel_through_an_http3_proxy_is_a_stream_of_its_connection() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n".to_vec();
    let script = tunnel_script(b"200", vec![Told::Data(0, response)]);
    let mut m = quic_server(&[b"server flight", b"connect answer", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = through_h3_proxy(&mut m, e);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"ok\n");
    // No filter of C's chain reports the connect through an HTTP/3 proxy:
    // its time stays 0, as C's tool reports it through h2o.
    assert_eq!(ran.easy.report().timings().connect(), Duration::ZERO);
    assert!(lines(&ran, &["[MULTI] [CONNECTING] [PGRS-CONNECT]"]).is_empty());
    {
        let s = script.lock().unwrap();
        assert_eq!(
            s.requests[0],
            [
                ":method: CONNECT",
                ":authority: origin.example:80",
                "user-agent: curl/test"
            ]
        );
        let request =
            b"GET /p HTTP/1.1\r\nHost: origin.example\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\r\n";
        assert_eq!(s.body.bytes, request);
    }
    let got = lines(
        &ran,
        &[
            "[SETUP] happy eyeballing",
            "[H3-PROXY]",
            "[HAPPY-EYEBALLS] checked",
            "[DNS] get ",
            "Establishing",
            "CONNECT",
            "Response Headers",
            "via",
            "[READ] client_reset",
        ],
    );
    let from = got
        .iter()
        .position(|l| l.starts_with("[SETUP] happy eyeballing"))
        .unwrap();
    let want = expect(&format!(
        "[SETUP] happy eyeballing to HTTP/3 proxy localhost:{PORT}
        [DNS] get 0th result for localhost:{PORT}, family=10, dns=1
        [H3-PROXY] created, udp_tunnel=0
        [H3-PROXY] fake QUIC session 1
        [HAPPY-EYEBALLS] checked connect attempts: 1 ongoing, 0 inconclusive
        [DNS] get 0th result for localhost:{PORT}, family=2, dns=1
        [DNS] get 0th result for localhost:{PORT}, family=2, dns=1
        [H3-PROXY] fake QUIC session 1 trusts
        [H3-PROXY] handshake complete after 0ms, remote transport[max_udp_payload=1452, initial_max_data=786432]
        [H3-PROXY] max bidi streams now 100, used 0
        [H3-PROXY] peer verified
        [H3-PROXY] connect -> 0, done=1
        [H3-PROXY] [0] CONNECT start for origin.example:80
        Establishing HTTP/3 proxy tunnel to origin.example:80
        [H3-PROXY] peer idle timeout is 30000ms, set keep-alive to 15000 ms.
        [H3-PROXY] [0] opened bidi stream
        [H3-PROXY] [H3-PROXY] [0] OPENED stream for http://origin.example/p
        [H3-PROXY] [0] -> [connect]
        [H3-PROXY] [0] read req body -> AGAIN
        [H3-PROXY] [0] header: via: h3proxy
        [H3-PROXY] [0] end_headers, status=200
        [H3-PROXY] [0] -> [response]
        CONNECT Response Status 200
        Response Headers (1 total):
        via: h3proxy
        CONNECT tunnel established, response 200
        [H3-PROXY] [0] -> [established]
        CONNECT phase completed for HTTP/3 proxy
        [HAPPY-EYEBALLS] checked connect attempts: 1 ongoing, 0 inconclusive
        [DNS] get 0th result for localhost:{PORT}, family=2, dns=1
        [DNS] get 0th result for localhost:{PORT}, family=2, dns=1
        [READ] client_reset, clear readers
        [H3-PROXY] query ALPN"
    ));
    let got: Vec<String> = got[from..]
        .iter()
        .filter(|l| {
            !l.contains("progress_ingress")
                && !l.contains("egress")
                && !l.contains("recvmmsg")
                && !l.contains("vquic_")
        })
        .cloned()
        .collect();
    assert_eq!(got[..want.len()], want);
    // C's chain holds the attempt apart until the tunnel is up, then the
    // HAPPY-EYEBALLS filter goes with the setup's others.
    let chain = lines(
        &ran,
        &[
            "[MULTI] [CONNECTING] cf_setup_connect",
            "[MULTI] [CONNECTING] connected [",
            "[MULTI] [CONNECTING] reduced",
            "[HAPPY-EYEBALLS] removing",
        ],
    );
    let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
    assert!(
        chain.contains(&"[MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP][!HAPPY-EYEBALLS]"),
        "{chain:#?}"
    );
    assert_eq!(
        chain[chain.len() - 3..],
        [
            "[MULTI] [CONNECTING] connected [0][DNS][SETUP][HAPPY-EYEBALLS][H3-PROXY][UDP]",
            "[HAPPY-EYEBALLS] removing connected setup filter",
            "[MULTI] [CONNECTING] reduced to [0][H3-PROXY][UDP]",
        ]
    );
}

/// The origin's answer taken in by the HTTP/3 proxy's connection as the
/// request's body is sent through its tunnel, in a step whose read found
/// nothing, is held, and the transfer runs again to read it without a
/// wait, as C's pollset marks it (`multi_adjust_pollset`): C's tool
/// sending a 2 MB body through h2o traces the same mark as its sends
/// take the origin's bytes in. The body's second piece is read as the
/// transfer performs, after its step's read, and the proxy's answer
/// comes as it is.
#[test]
fn a_tunnel_s_input_taken_in_as_the_body_goes_is_read() {
    struct LetsAnswer {
        talk: Conversation,
        pieces: Mutex<Vec<&'static [u8]>>,
    }
    impl crate::handler::ReadHandler for LetsAnswer {
        fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> crate::handler::Read {
            let mut pieces = self.pieces.lock().unwrap();
            if pieces.is_empty() {
                return crate::handler::Read::Eof;
            }
            let piece = pieces.remove(0);
            if pieces.is_empty() {
                // The proxy's packet with the answer is on its way.
                self.talk.allow(3);
            }
            buf[..piece.len()].copy_from_slice(piece);
            crate::handler::Read::Data(std::num::NonZeroUsize::new(piece.len()).unwrap())
        }
    }
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n".to_vec();
    let script = tunnel_script(b"200", vec![Told::Data(0, response)]);
    let replies: &[&[u8]] = &[b"server flight", b"connect answer", b"response"];
    let (mut m, talks) = quic_peer(ManualClock::new().unwrap(), &[replies]);
    talks[0].allow(2);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let upload = crate::options::UploadSource::Read {
        handler: Handler::read(LetsAnswer {
            talk: talks[0].clone(),
            pieces: Mutex::new(vec![b"hel", b"lo"]),
        })
        .unwrap(),
        rewind: None,
        size: Some(5),
    };
    let ran = get_with(&mut m, e, "/", Conversation::replies(&[], false), |o| {
        o.set_url(Some(b"http://origin.example/p")).unwrap();
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("https://localhost:{PORT}").into_bytes());
        proxy.kind = crate::options::ProxyType::Https3;
        proxy.tunnel = true;
        o.method = Method::Post;
        o.upload = upload;
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"ok\n");
    // The lines name the pollset and the wait, which `lines` leaves out:
    // the mark, and the wait after it, for nothing.
    let marked: Vec<String> = ran
        .seen
        .text()
        .into_iter()
        .map(|l| l.trim_start_matches("[0-0] ").trim_end().to_owned())
        .skip_while(|l| !l.contains("pollset[] has POLLIN"))
        .filter(|l| l.contains("pollset[] has POLLIN") || l.contains("multi_wait("))
        .take(2)
        .collect();
    assert_eq!(
        marked,
        [
            "[MULTI] [PERFORMING] pollset[] has POLLIN, but there is still buffered input -> mark as dirty",
            "[MULTI] [PERFORMING] multi_wait(fds=1, timeout=0) tinternal=0",
        ],
        "{:#?}",
        ran.seen.text()
    );
}

/// A `CONNECT` the proxy refuses fails the race's attempt, as C's
/// attempt is the H3-PROXY filter the tunnel is: the proxy's connection
/// goes, and with no address left the setup says it could not connect
/// over the proxy; with one left, the race goes on to it
/// (`cf_ip_ballers_run`).
#[test]
fn a_tunnel_an_http3_proxy_refuses_fails_the_attempt() {
    let script = tunnel_script(b"403", vec![]);
    let mut m = quic_server(&[b"server flight", b"connect answer", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = through_h3_proxy(&mut m, e);
    let next = lines(
        &ran,
        &[
            "[H3-PROXY] [0] -> [f",
            "[H3-PROXY] cf_h3",
            "[HAPPY-EYEBALLS] starting",
            "[HAPPY-EYEBALLS] no more",
        ],
    );
    assert_eq!(
        next[..4],
        expect(
            "[HAPPY-EYEBALLS] starting first attempt for ipv6 -> 0
            [H3-PROXY] [0] -> [failed]
            [H3-PROXY] cf_h3_proxy_destroy()
            [HAPPY-EYEBALLS] starting first attempt for ipv4 -> 0"
        ),
        "{next:#?}"
    );
    let script = tunnel_script(b"403", vec![]);
    let mut m = quic_server(&[b"server flight", b"connect answer", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = through_h3_proxy_over(&mut m, e, IpVersion::V6);
    assert_eq!(
        ran.result,
        Err(ErrorKind::CouldntConnect),
        "{:#?}",
        ran.seen.text()
    );
    let got = lines(
        &ran,
        &[
            "[H3-PROXY] [0] -> [f",
            "[H3-PROXY] cf_h3",
            "[HAPPY-EYEBALLS] no more",
            "Failed to connect",
        ],
    );
    assert_eq!(
        got,
        expect(
            "[H3-PROXY] [0] -> [failed]
            [H3-PROXY] cf_h3_proxy_destroy()
            [HAPPY-EYEBALLS] no more attempts to try
            Failed to connect to origin.example:80 over proxy localhost after 0 ms: Could not connect to server"
        )
    );
}

/// A `CONNECT` the HTTP/3 proxy never answers times out as the race
/// does, the attempt still running: the multi's own check says the
/// connection timed out (`multi_handle_timeout`), as C's H3-PROXY filter
/// has no timeout of its own, unlike the HTTP/1.1 and HTTP/2 tunnels'.
#[test]
fn a_tunnel_an_http3_proxy_never_answers_times_out_as_its_race() {
    let script = tunnel_script(b"200", vec![]);
    let mut m = quic_server(&[b"server flight"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = through_h3_proxy_over(&mut m, e, IpVersion::V6);
    assert_eq!(
        ran.result,
        Err(ErrorKind::OperationTimedout),
        "{:#?}",
        ran.seen.text()
    );
    let got = lines(
        &ran,
        &[
            "[H3-PROXY] [0] CONNECT start",
            "[H3-PROXY] [0] -> [",
            "Connection timed out",
            "Proxy CONNECT aborted",
        ],
    );
    // The `CONNECT` goes once, the attempt waiting on its answer.
    assert_eq!(
        got,
        expect(
            "[H3-PROXY] [0] CONNECT start for origin.example:80
            [H3-PROXY] [0] -> [connect]
            Connection timed out after 10000 milliseconds"
        ),
        "{got:#?}"
    );
}

/// A request not tunnelled goes to an HTTP/3 proxy over TCP, as C sends
/// it (`Curl_http_proxy_transport`): the setup dials TCP to the proxy,
/// and the GET goes to it over TLS.
#[test]
fn a_request_not_tunnelled_goes_to_an_http3_proxy_over_tcp() {
    let talk = tls_hello();
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let ran = get_with(&mut m, e, "/", talk, |o| {
        o.set_url(Some(b"http://origin.example/p")).unwrap();
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("https://127.0.0.1:{PORT}").into_bytes());
        proxy.kind = crate::options::ProxyType::Https3;
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"hello");
    let socket = lines(&ran, &["[TCP] cf_socket_open", "[UDP] cf_socket_open"]);
    assert_eq!(
        socket,
        ["[TCP] cf_socket_open() -> 0, fd=1000"],
        "{socket:#?}"
    );
}

/// A 407 has its `Proxy-Authenticate` taken in, traced as C traces it;
/// a Basic challenge does not make the `CONNECT` go again, and the setup
/// fails. Only a 407's is taken: a success's is let be.
#[test]
fn a_tunnel_s_407_takes_its_challenge_in() {
    let challenge: &[(&[u8], &[u8])] = &[(b"proxy-authenticate", b"Basic realm=\"x\"")];
    let script = tunnel_script_with(b"407", challenge, vec![]);
    let mut m = quic_server(&[b"server flight", b"connect answer", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = through_h3_proxy_over(&mut m, e, IpVersion::V6);
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert_eq!(
        lines(&ran, &["[H3-PROXY] [0] CONNECT: fwd auth"]),
        ["[H3-PROXY] [0] CONNECT: fwd auth header 'Basic realm=\"x\"'"]
    );
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n".to_vec();
    let script = tunnel_script_with(b"200", challenge, vec![Told::Data(0, response)]);
    let mut m = quic_server(&[b"server flight", b"connect answer", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = through_h3_proxy(&mut m, e);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert!(lines(&ran, &["CONNECT: fwd auth"]).is_empty());
}

/// The proxy closing the tunnel's stream mid-response fails the read:
/// the stream is gone (`cf_h3_proxy_recv`, `!stream`).
#[test]
fn a_tunnel_an_http3_proxy_closes_fails_the_read() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nok\n".to_vec();
    // The response and the close come once the request is written, as
    // the peer answers the packet carrying it.
    let script = tunnel_script(b"200", vec![]);
    {
        let mut s = script.lock().unwrap();
        s.out.extend([vec![5; 60], vec![]]);
        s.on_read
            .push_back(vec![Told::Data(0, response), Told::Closed(0, 0x100)]);
    }
    let mut m = quic_server(&[b"server flight", b"connect answer", b"ack", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = through_h3_proxy(&mut m, e);
    assert_eq!(
        ran.result,
        Err(ErrorKind::RecvError),
        "{:#?}",
        ran.seen.text()
    );
    assert_eq!(lines(&ran, &["[H3-PROXY] [0] CLOSED"]).len(), 1);
}

/// A tunnel whose response, read to its end, comes in one packet and
/// whose stream the proxy then closes with `code` in the next, which a
/// read finds with nothing held (`cf_h3_proxy_recv_closed_stream`); and
/// its script.
fn tunnel_closed_after(code: u64) -> (Ran, Arc<Mutex<Script>>) {
    let response = b"HTTP/1.1 200 OK\r\n\r\nok\n".to_vec();
    let script = tunnel_script(b"200", vec![]);
    {
        let mut s = script.lock().unwrap();
        s.out.extend([vec![5; 60], vec![], vec![6; 40], vec![]]);
        s.on_read.push_back(vec![Told::Data(0, response)]);
        s.on_read.push_back(vec![Told::Closed(0, code)]);
    }
    let mut m = quic_server(&[
        b"server flight",
        b"connect answer",
        b"ack",
        b"response",
        b"close",
    ]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    (through_h3_proxy(&mut m, e), script)
}

/// The proxy closing the tunnel's stream cleanly once its answer was
/// final ends the tunnel's bytes: a response read to its end is whole.
/// The stream's window was opened to 512 KiB as its DATA came, and by
/// as much again as the layer above read (`cf_h3_proxy_upd_rx_win`).
#[test]
fn a_tunnel_closed_cleanly_ends_its_bytes() {
    let (ran, script) = tunnel_closed_after(0x100);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"ok\n");
    assert_eq!(lines(&ran, &["[H3-PROXY] [0] CLOSED"]).len(), 1);
    assert_eq!(script.lock().unwrap().windows, [(0, 491_520), (0, 22)]);
}

/// The proxy resetting the tunnel's stream fails the read, said as C
/// says it: a stream it refused may be tried again, any other reset is
/// HTTP/3's error.
#[test]
fn a_tunnel_reset_fails_the_read_as_c_says_it() {
    let (ran, _) = tunnel_closed_after(0x10b);
    assert_eq!(
        ran.result,
        Err(ErrorKind::RecvError),
        "{:#?}",
        ran.seen.text()
    );
    assert_eq!(
        lines(&ran, &["[H3-PROXY] [0] RESET", "HTTP/3 stream"]),
        expect(
            "[H3-PROXY] [0] RESET: error 267
            HTTP/3 stream 0 refused by server, try again on a new connection"
        )
    );
    let (ran, _) = tunnel_closed_after(0x102);
    assert_eq!(ran.result, Err(ErrorKind::Http3), "{:#?}", ran.seen.text());
    assert_eq!(
        lines(&ran, &["[H3-PROXY] [0] RESET", "HTTP/3 stream"]),
        expect(
            "[H3-PROXY] [0] RESET: error 258
            HTTP/3 stream 0 reset by server (error 0x102 INTERNAL_ERROR)"
        )
    );
}

/// The proxy closing the tunnel's stream before its answer fails the
/// tunnel at once (`cf_h3_proxy_tunnel`, `H3_TUNNEL_FAILED`), not as the
/// connect times out.
#[test]
fn a_tunnel_closed_before_its_answer_fails() {
    let script = Script::new();
    {
        let mut s = script.lock().unwrap();
        s.idle = Some(std::time::Duration::from_secs(30));
        s.out.extend([
            vec![1; 1200],
            vec![2; 1200],
            vec![],
            vec![],
            vec![3; 75],
            vec![],
        ]);
        s.on_read
            .push_back(vec![Told::HandshakeDone, Told::MaxBidiStreams(100)]);
        s.on_read.push_back(vec![Told::Closed(0, 0x100)]);
    }
    let mut m = quic_server(&[b"server flight", b"close"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = through_h3_proxy_over(&mut m, e, IpVersion::V6);
    assert_eq!(
        ran.result,
        Err(ErrorKind::RecvError),
        "{:#?}",
        ran.seen.text()
    );
    assert_eq!(ran.easy.report().timings().total().as_millis(), 0);
}

/// The proxy a CONNECT-UDP goes through, at `127.0.0.1`.
const UDP_PROXY_PORT: u16 = 3128;

/// `payload` as a capsule of a datagram (RFC 9297), as a proxy sends it
/// through a CONNECT-UDP tunnel.
fn capsule(payload: &[u8]) -> Vec<u8> {
    let (head, len) = crate::conn::capsule::header(payload.len());
    let mut c = head[..len].to_vec();
    c.extend_from_slice(payload);
    c
}

/// A CONNECT-UDP the proxy answers with anything but switching
/// protocols, or a success, fails the tunnel, said as C says it.
#[test]
fn a_connect_udp_refused_fails_the_tunnel() {
    let script = get_script(b"123456789");
    let head = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
    let talk = Conversation::replies(&[&head], false).per_send();
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], UDP_PROXY_PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let e = tracing(FakeTls::new().unwrap(), &script);
    let url = format!("https://localhost:{PORT}/");
    let ran = get_with(&mut m, e, "/", talk, |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3Only;
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("http://127.0.0.1:{UDP_PROXY_PORT}").into_bytes());
    });
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert_eq!(
        lines(&ran, &["CONNECT-UDP tunnel"]),
        ["CONNECT-UDP tunnel failed, response 403"]
    );
}

/// `--http3` through an HTTP proxy that refuses CONNECT-UDP: the race's
/// HTTP/3 attempt goes over CONNECT-UDP and fails at the proxy's answer,
/// its connection kept; the second, over CONNECT on a connection of its
/// own, makes the connection, and the first goes then with its chain,
/// its socket closed last, as C's failed baller goes with the filter.
#[test]
fn http3_through_a_proxy_refusing_connect_udp_falls_back_to_connect() {
    use crate::tls::fake::{self, WELCOME};
    let refused = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
    let tunnel = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
    let response = fake::records(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").unwrap();
    let refusing = Conversation::replies(&[&refused], false).per_send();
    let talk = Conversation::replies(&[&tunnel, WELCOME, &response], false).per_send();
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], UDP_PROXY_PORT));
    let net = records_as_built(FakeNet::new(clock.clone()))
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, refusing)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let url = format!("https://localhost:{PORT}/");
    let ran = get_with(&mut m, e, "/", talk, |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3;
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("http://127.0.0.1:{UDP_PROXY_PORT}").into_bytes());
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"hello");
    let got = lines(
        &ran,
        &[
            "[HTTPS-CONNECT] 1st",
            "[HTTPS-CONNECT] 2nd",
            "CONNECT-UDP tunnel",
            "[HTTPS-CONNECT] h3 baller",
            "[SETUP] happy eyeballing",
            "CONNECT tunnel",
            "[MULTI] [CONNECTING] connected [",
            "[MULTI] [CONNECTING] reduced to",
            "[HTTPS-CONNECT] destroy",
            "[SETUP] destroy",
            "[HTTP-PROXY] destroy",
            "[H1-PROXY] destroy",
            "[HAPPY-EYEBALLS] destroy",
            "[TCP] destroy",
            "[TCP] cf_socket_close",
        ],
    );
    // The second attempt is chosen as soon as the record is known: over a
    // resolver library, at the connect after the first attempt starts; over
    // the threaded resolver, which says at once there is none, before it
    // starts (`cf_hc_set_baller2` in `cf_hc_connect`'s init).
    let start = "[SETUP] happy eyeballing to proxy 127.0.0.1:3128";
    let second = "[HTTPS-CONNECT] 2nd attempt uses h1 from wanted versions";
    let (a, b) = if cfg!(feature = "threaded-resolver") {
        (second, start)
    } else {
        (start, second)
    };
    let want = expect(&format!(
        "
        [HTTPS-CONNECT] 1st attempt uses h3 from wanted versions
        {a}
        {b}
        CONNECT-UDP tunnel failed, response 403
        [HTTPS-CONNECT] h3 baller failed, starting h1
        [SETUP] happy eyeballing to proxy 127.0.0.1:3128
        CONNECT tunnel established, response 200
        [MULTI] [CONNECTING] connected [0][DNS][DNS][HTTPS-CONNECT][SETUP][SSL][HTTP-PROXY][H1-PROXY][HAPPY-EYEBALLS][TCP]
        [HTTPS-CONNECT] destroy
        [SETUP] destroy
        [HTTP-PROXY] destroy
        [H1-PROXY] destroy
        [HAPPY-EYEBALLS] destroy
        [TCP] destroy
        [TCP] cf_socket_close, fd=1000
        [SETUP] destroy
        [HTTP-PROXY] destroy
        [HAPPY-EYEBALLS] destroy
        [MULTI] [CONNECTING] reduced to [0][SSL][H1-PROXY][TCP]
        ",
    ));
    assert_eq!(got, want, "{got:#?}");
}

/// A transfer given up as it connects lets its name's answer go as C's
/// does, on a share that keeps names: two uses of the share's names as
/// it is removed, a race's or not, its first hop dialed and its TLS
/// handshake waiting, after two as it looked the name up. C's library,
/// given up 300 ms into a GET of `https://127.0.0.1:PORT/` from a server
/// that accepts and says nothing, its UDP port closed, tells the lock
/// function of the names twice as the setup goes and twice at the
/// removal, in HTTP/3, HTTP/2 and HTTP/1.1 alike.
#[test]
fn a_transfer_given_up_as_it_connects_lets_its_answer_go_as_c() {
    use crate::share::{Kind, Share, Told};
    for version in [
        crate::options::HttpVersion::Http3,
        crate::options::HttpVersion::Http11,
    ] {
        // A TCP first takes the first conversation, opening the first
        // socket.
        let first = Conversation::replies(&[], false);
        let second = Conversation::replies(&[], false);
        let mut m = racing_peer(Peer::Refuses, &first, Peer::Accepts, &second);
        let share = Share::new().unwrap();
        share.keep(Kind::Names).unwrap();
        let told = Told::new(&share);
        let mut e = tracing(FakeTls::new().unwrap(), &first_flight_only());
        e.set_share_watched(share.clone(), told.handler()).unwrap();
        let url = format!("https://127.0.0.1:{PORT}/");
        e.options_mut().set_url(Some(url.as_bytes())).unwrap();
        e.options_mut().http.version = version;
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        for _ in 0..30 {
            m.perform(&mut NoEvents).unwrap();
            m.wait(
                &mut [],
                Duration::from_millis(10),
                crate::multi::WaitMode::Wait,
                &mut NoEvents,
            )
            .unwrap();
        }
        let hello = |c: &Conversation| c.received().starts_with(crate::tls::fake::HELLO);
        assert!(
            hello(&first) || hello(&second),
            "{version:?}: the TLS hello went"
        );
        assert_eq!(told.uses(), [Kind::Names; 2], "{version:?}");
        m.remove(id, &mut NoEvents).unwrap();
        assert_eq!(told.uses(), [Kind::Names; 2], "{version:?}");
    }
}

/// A name looked up for an `https` origin is used on a share that keeps
/// names as C's is: its HTTPS record looked for, and looked for again
/// as its resolve starts (`Curl_resolv_take_result`), its addresses
/// looked for and kept, the record looked for once more as its answer
/// comes, and the answer, none, kept; then two uses as the transfer,
/// given up as it connects, is removed. C's library, given up 300 ms
/// into a GET of `https://localhost:PORT/` from a server that accepts
/// and says nothing, tells the lock function of the names six times as
/// the setup goes and twice at the removal, in HTTP/3, HTTP/2 and
/// HTTP/1.1 alike. Over the threaded resolver, which answers no record,
/// nothing comes to look for or keep: C's threaded build tells it four
/// times as the setup goes, and twice at the removal.
#[test]
fn a_name_s_https_record_is_looked_for_as_c_locks_it() {
    let setup = if cfg!(feature = "threaded-resolver") {
        4
    } else {
        6
    };
    use crate::share::{Kind, Share, Told};
    for version in [
        crate::options::HttpVersion::Http3,
        crate::options::HttpVersion::Http11,
    ] {
        let first = Conversation::replies(&[], false);
        let second = Conversation::replies(&[], false);
        let mut m = racing_peer(Peer::Refuses, &first, Peer::Accepts, &second);
        let share = Share::new().unwrap();
        share.keep(Kind::Names).unwrap();
        let told = Told::new(&share);
        let mut e = tracing(FakeTls::new().unwrap(), &first_flight_only());
        e.set_share_watched(share.clone(), told.handler()).unwrap();
        let url = format!("https://localhost:{PORT}/");
        e.options_mut().set_url(Some(url.as_bytes())).unwrap();
        e.options_mut().http.version = version;
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        for _ in 0..30 {
            m.perform(&mut NoEvents).unwrap();
            m.wait(
                &mut [],
                Duration::from_millis(10),
                crate::multi::WaitMode::Wait,
                &mut NoEvents,
            )
            .unwrap();
        }
        let hello = |c: &Conversation| c.received().starts_with(crate::tls::fake::HELLO);
        assert!(
            hello(&first) || hello(&second),
            "{version:?}: the TLS hello went"
        );
        assert_eq!(told.uses(), vec![Kind::Names; setup], "{version:?}");
        m.remove(id, &mut NoEvents).unwrap();
        assert_eq!(told.uses(), [Kind::Names; 2], "{version:?}");
    }
}

/// Two transfers to one name's `https` origin, set up together, both
/// ask for its HTTPS record; the first's answer, none, is kept, and the
/// second, looking in the cache again as its answer is taken, finds it
/// there and keeps nothing, telling its own ask it is not wanted
/// (`Curl_resolv_take_result`'s `Curl_async_shutdown`). C's tool, given
/// two such URLs at once (`-Z --parallel-immediate`), traces the same; its
/// threaded build keeps no record, and the second finds the addresses.
#[test]
fn a_record_kept_meanwhile_is_found_not_kept_again() {
    let talk = [
        Conversation::replies(&[], false),
        Conversation::replies(&[], false),
    ];
    let mut m = racing_peer(Peer::Refuses, &talk[0], Peer::Accepts, &talk[1]);
    let url = format!("https://localhost:{PORT}/");
    let seen = [Seen::default(), Seen::default()];
    for s in &seen {
        let mut e = tracing(FakeTls::new().unwrap(), &first_flight_only());
        let o = e.options_mut();
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http11;
        o.output.verbose = true;
        o.callbacks.debug = Some(Handler::debug(s.clone()).unwrap());
        m.add(Box::new(e), (), &mut NoEvents).unwrap();
    }
    for _ in 0..5 {
        m.perform(&mut NoEvents).unwrap();
    }
    // The records of the two asks numbered 1 and 2 by the multi.
    let starts = [
        "[DNS] cache negative",
        "Hostname ",
        "HTTPS-RR ",
        "[DNS] [1] shutdown",
        "[DNS] [2] shutdown",
    ];
    let [one, two] = seen.map(|s| lines_of(&s, &starts));
    if cfg!(feature = "threaded-resolver") {
        // The threaded resolver answers no record: none is kept, and the
        // second finds only the first's addresses, as C's threaded tool
        // traces the same two URLs.
        assert_eq!(one, expect(""));
        assert_eq!(two, expect("Hostname localhost was found in DNS cache"));
        return;
    }
    assert_eq!(
        one,
        expect(&format!(
            "[DNS] cache negative name resolve for localhost:{PORT} type=HTTPS"
        ))
    );
    assert_eq!(
        two,
        expect(&format!(
            "Hostname localhost was found in DNS cache
            Hostname 'localhost' was found in DNS cache
            [DNS] [2] shutdown async
            HTTPS-RR localhost:{PORT}: -"
        ))
    );
}

/// HTTP/3 through an HTTP proxy over CONNECT-UDP, the proxy's first
/// connection saying `first` and then nothing, the second a CONNECT
/// tunnel to the origin: the race's lines.
fn connect_udp_soft_timeout(first: &[u8]) -> Vec<String> {
    use crate::tls::fake::{self, WELCOME};
    let tunnel = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
    let response = fake::records(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").unwrap();
    let silent = Conversation::replies(&[first], false).per_send();
    let talk = Conversation::replies(&[&tunnel, WELCOME, &response], false).per_send();
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], UDP_PROXY_PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, silent)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let url = format!("https://localhost:{PORT}/");
    let ran = get_with(&mut m, e, "/", talk, |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3;
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("http://127.0.0.1:{UDP_PROXY_PORT}").into_bytes());
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"hello");
    lines(
        &ran,
        &[
            "CONNECT-UDP tunnel",
            "[HTTPS-CONNECT] h3",
            "[HAPPY-EYEBALLS] query connect reply",
        ],
    )
}

/// HTTP/3 through an HTTP proxy whose CONNECT-UDP it answers, the
/// origin then silent: the first attempt's socket has heard the proxy, so
/// at the soft timeout the race finds it answered, its happy eyeballs
/// filter connected and silent, and the second starts only at the hard
/// one. C's tool against a proxy that answers 101 and then says nothing
/// traces `h3 inconclusive after 200, starting h2` and no `query connect
/// reply`.
#[test]
fn a_connect_udp_tunnel_answered_holds_the_second_to_the_hard_timeout() {
    let switched = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\
                     Upgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n";
    let want = expect(
        "
        CONNECT-UDP tunnel established, response 101
        [HTTPS-CONNECT] h3 inconclusive after 200, starting h1
        ",
    );
    let got = connect_udp_soft_timeout(switched);
    assert_eq!(got, want, "{got:#?}");
}

/// HTTP/3 through an HTTP proxy that takes the connection and never
/// answers its CONNECT-UDP: the first attempt's socket has heard nothing,
/// so the second starts at the soft timeout, the question answered
/// untraced by the dialed first hop. C's tool against such a proxy
/// traces `h3 has not seen any data after 100ms, starting h2` and no
/// `query connect reply`.
#[test]
fn a_connect_udp_tunnel_unanswered_starts_the_second_at_the_soft_timeout() {
    let want = expect(
        "
        [HTTPS-CONNECT] h3 has not seen any data after 100ms, starting h1
        ",
    );
    let got = connect_udp_soft_timeout(b"");
    assert_eq!(got, want, "{got:#?}");
}

/// HTTP/3 through an HTTP proxy that refuses CONNECT-UDP and then
/// CONNECT: both attempts fail once dialed, which fails the race, and
/// both go with the connection, the CONNECT-UDP one first, on no
/// transfer's trace: C's tool against such a proxy traces nothing of
/// either's sockets between the second refusal and the connection's
/// close.
#[test]
fn http3_through_a_proxy_refusing_both_tunnels_fails() {
    let refused = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
    let first = Conversation::replies(&[&refused], false).per_send();
    let second = Conversation::replies(&[&refused], false).per_send();
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], UDP_PROXY_PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, first)
        .with_conversation(at, second.clone());
    let closed = Arc::new(Mutex::new(Vec::new()));
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(Closes(net, closed.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let e = tracing(FakeTls::agreeing().unwrap(), &first_flight_only());
    let url = format!("https://localhost:{PORT}/");
    let ran = get_with(&mut m, e, "/", second, |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3;
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("http://127.0.0.1:{UDP_PROXY_PORT}").into_bytes());
    });
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert_eq!(*closed.lock().unwrap(), [1000, 1001]);
    let text = ran.seen.text();
    let from = text
        .iter()
        .position(|l| l.contains("CONNECT tunnel failed, response 403"))
        .expect("the second is refused");
    let to = text
        .iter()
        .position(|l| l.ends_with("closing connection #0\n"))
        .expect("the connection closes");
    let between: Vec<String> = text[from..=to]
        .iter()
        .filter(|l| {
            [
                "[TCP]",
                "[HTTPS-CONNECT]",
                "[DNS] Curl_conn_connect",
                "[MULTI] [CONNECTING]",
                "closing",
            ]
            .iter()
            .any(|n| l.contains(n))
        })
        .map(|l| match l.find(" added ") {
            Some(at) => format!("{} added Nus\n", &l[..at]),
            None => l.clone(),
        })
        .collect();
    // C's, the connect time that of the first attempt to connect to the
    // proxy (`cf_hc_cntrl`), after the chain that failed.
    assert_eq!(
        between,
        [
            "[0-0] [HTTPS-CONNECT] connect, all attempts failed\n",
            "[0-0] [HTTPS-CONNECT] connect -> 7, done=0\n",
            "[0-0] [DNS] Curl_conn_connect(block=0) -> 7, done=0\n",
            "[0-0] [DNS] Curl_conn_connect(), filter returned 7\n",
            "[0-0] [MULTI] [CONNECTING] failed to connect [0][!DNS][!DNS][!HTTPS-CONNECT]\n",
            "[0-0] [MULTI] [CONNECTING] [PGRS-CONNECT] added Nus\n",
            "[0-0] [MULTI] [CONNECTING] connect failed -> 7\n",
            "[0-0] [MULTI] [CONNECTING] multi_done: status: 7 prem: 1 done: 0\n",
            "[0-0] [MULTI] [CONNECTING] multi_done_locked, in use=0\n",
            "[0-0] [MULTI] [CONNECTING] multi_done, terminating conn #0 to localhost:8990, \
             forbid=0, close=0, premature=1, conn_multiplex=0\n",
            "[0-0] closing connection #0\n",
        ],
        "{text:#?}"
    );
}

/// HTTP/3 alone through an HTTP proxy goes over its CONNECT-UDP
/// (`http_proxy_create_CONNECTUDP`): the race's attempt is the proxy's,
/// in TCP; the request asks the proxy at the path naming the origin to
/// switch protocols; once it has, the origin's QUIC connection is made
/// over capsules on the tunnel, the chain C's (`[HTTP/3][CAPSULE]` over
/// the tunnel's filters), and the GET goes over it. C's build against
/// h2o, `test_60_01[h3_over_h1_proxytunnel]`, but for the proxy's TLS.
#[test]
fn http3_through_an_http_proxy_goes_over_connect_udp() {
    let script = get_script(b"123456789");
    let head = b"HTTP/1.1 101 Switching Protocols\r\nCapsule-Protocol: ?1\r\n\r\n".to_vec();
    let flight = capsule(b"server flight");
    let response = capsule(b"response");
    // The tunnel's request, then each datagram of the client's flight,
    // then the GET's.
    let talk = Conversation::replies(&[&head, &[], &flight, &response], false).per_send();
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], UDP_PROXY_PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let e = tracing(FakeTls::new().unwrap(), &script);
    let url = format!("https://localhost:{PORT}/");
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3Only;
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("http://127.0.0.1:{UDP_PROXY_PORT}").into_bytes());
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"123456789");
    let request = format!(
        "GET http://127.0.0.1:{UDP_PROXY_PORT}/.well-known/masque/udp/localhost/{PORT}/ HTTP/1.1\r\n\
         Host: 127.0.0.1:{UDP_PROXY_PORT}\r\n\
         User-Agent: curl/test\r\n\
         Proxy-Connection: Keep-Alive\r\n\
         Connection: Upgrade\r\n\
         Upgrade: connect-udp\r\n\
         Capsule-Protocol: ?1\r\n\r\n"
    );
    let sent = talk.received();
    assert_eq!(
        String::from_utf8_lossy(&sent[..request.len()]),
        request,
        "{:?}",
        String::from_utf8_lossy(&sent)
    );
    // The client's flight and its GET follow, each datagram a capsule.
    let mut capsules = capsule(&[1; 1200]);
    capsules.extend(capsule(&[2; 1200]));
    capsules.extend(capsule(&[3; 75]));
    assert_eq!(sent[request.len()..], capsules);
    let got = lines(
        &ran,
        &[
            "Establishing",
            "CONNECT-UDP",
            "[SETUP] added",
            "[MULTI] [CONNECTING] cf_setup_connect",
            "[MULTI] [CONNECTING] connected [",
            "[MULTI] [CONNECTING] reduced",
            "[HTTP/3] handshake complete",
            "using HTTP",
            "[READ] client_reset",
        ],
    );
    let mut got = got;
    got.dedup();
    // The fake proxy answers at once, so the chain is not traced while
    // the answer is awaited. The request follows the tunnel's request,
    // so what reads it starts over once the tunnel is up
    // (`cf_h1_proxy_connect`'s `Curl_client_reset`).
    let want = expect(&format!(
        "[READ] client_reset, clear readers
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [SETUP] added HTTP proxy tunnel filter
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HTTP-PROXY][HAPPY-EYEBALLS][TCP]
        CONNECT-UDP: no ALPN negotiated
        Establishing HTTP proxy UDP tunnel to localhost:{PORT}
        CONNECT-UDP phase completed for HTTP proxy
        CONNECT-UDP tunnel established, response 101
        [READ] client_reset, clear readers
        [SETUP] added QUIC filter for origin
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HTTP/3][!CAPSULE][HTTP-PROXY][H1-PROXY][HAPPY-EYEBALLS][TCP]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HTTP/3][CAPSULE][HTTP-PROXY][H1-PROXY][HAPPY-EYEBALLS][TCP]
        [HTTP/3] handshake complete after 0ms, remote transport[max_udp_payload=1452, initial_max_data=786432]
        [MULTI] [CONNECTING] connected [0][DNS][DNS][HTTPS-CONNECT][SETUP][HTTP/3][CAPSULE][HTTP-PROXY][H1-PROXY][HAPPY-EYEBALLS][TCP]
        [MULTI] [CONNECTING] reduced to [0][HTTP/3][CAPSULE][H1-PROXY][TCP]
        using HTTP/3
        [READ] client_reset, clear readers"
    ));
    assert_eq!(got, want);
}

/// A QUIC connection layered over a CONNECT-UDP tunnel says goodbye
/// through the tunnel's layers, its transport saying so: the packet that
/// closes it goes as a capsule, not on a socket, as the multi's internal
/// trace says (`Curl_cf_ngtcp2_cmn_shutdown`, `vquic_send_packets` with
/// `qctx->sockfd == CURL_SOCKET_BAD`).
#[test]
fn a_tunnelled_connection_says_goodbye_through_its_layers() {
    #[derive(Clone, Default)]
    struct Written(Arc<Mutex<Vec<u8>>>);
    impl crate::handler::TextSink for Written {
        fn write(&self, text: &[u8]) {
            self.0.lock().unwrap().extend_from_slice(text);
        }
    }
    let script = get_script(b"123456789");
    let head = b"HTTP/1.1 101 Switching Protocols\r\nCapsule-Protocol: ?1\r\n\r\n".to_vec();
    let flight = capsule(b"server flight");
    let response = capsule(b"response");
    let talk = Conversation::replies(&[&head, &[], &flight, &response], false).per_send();
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], UDP_PROXY_PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let components = crate::components::Components::new().unwrap();
    components.set(
        crate::components::Component::Http3,
        crate::components::Level::Info,
    );
    let written = Written::default();
    m.trace_internally_to(
        components,
        crate::handler::Handler::text(written.clone()).unwrap(),
    );
    let e = tracing(FakeTls::new().unwrap(), &script);
    let url = format!("https://localhost:{PORT}/");
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3Only;
        o.limits.reuse.forbid = true;
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("http://127.0.0.1:{UDP_PROXY_PORT}").into_bytes());
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert!(
        talk.received().ends_with(&capsule(b"CLOSE")),
        "the goodbye went as a capsule"
    );
    let text = String::from_utf8(written.0.lock().unwrap().clone()).unwrap();
    // One datagram goes below untraced, as C's `send_packet_no_gso_cf`
    // traces only a run cut into several; never a socket's send.
    assert!(
        text.contains("* [HTTP/3] shutdown completely sent off, done")
            && !text.contains("vquic_sendmsg"),
        "{text}"
    );
}

/// The same over a CONNECT-UDP tunnel: a body with as much in flight as
/// is meant to be waits on what the peer says, not on the room of the
/// tunnel's socket, as the HTTP/3 filter on top of the tunnel's says
/// (`cf_ngtcp2_adjust_pollset` above the capsule filter).
#[test]
fn a_tunnelled_body_in_flight_waits_for_its_acknowledgement() {
    let body = vec![b'x'; 100_000];
    let script = post_script(b"100000\n", 4);
    {
        let mut s = script.lock().unwrap();
        s.on_read[3] = vec![Told::Acked(65_388)];
        s.timer = Some(std::time::Duration::from_millis(25));
        s.on_expiry = vec![vec![9; 20]];
    }
    let head = b"HTTP/1.1 101 Switching Protocols\r\nCapsule-Protocol: ?1\r\n\r\n".to_vec();
    let (flight, ack, response) = (
        capsule(b"server flight"),
        capsule(b"ack"),
        capsule(b"response"),
    );
    let talk = Conversation::replies(&[&head, &[], &flight, &ack, &ack, &ack, &response], false)
        .per_send();
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], UDP_PROXY_PORT));
    let net = records_as_built(FakeNet::new(clock.clone()))
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let e = tracing(FakeTls::new().unwrap(), &script);
    let url = format!("https://localhost:{PORT}/");
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = crate::options::HttpVersion::Http3Only;
        o.method = Method::Post;
        o.upload = bytes(&body);
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("http://127.0.0.1:{UDP_PROXY_PORT}").into_bytes());
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    let said: Vec<String> = ran
        .seen
        .text()
        .iter()
        .map(|l| {
            l.trim_end()
                .split_once("] ")
                .map_or("", |(_, r)| r)
                .to_owned()
        })
        .filter(|l| {
            l.starts_with("[HTTP/3] [0] cf_send(len=34612)")
                || l.starts_with("[MULTI] [PERFORMING] pollset")
        })
        .collect();
    let alpn = alpn_eyeballs_timer();
    assert_eq!(
        said,
        [
            format!(
                "[MULTI] [PERFORMING] pollset[fd=1000 IN], timeouts={}",
                2 + alpn
            ),
            "[HTTP/3] [0] cf_send(len=34612) -> 81, 0".to_owned(),
            format!(
                "[MULTI] [PERFORMING] pollset[fd=1000 IN], timeouts={}",
                2 + alpn
            ),
            "[HTTP/3] [0] cf_send(len=34612) -> 0, 34612".to_owned(),
            format!(
                "[MULTI] [PERFORMING] pollset[fd=1000 IN], timeouts={}",
                1 + alpn
            ),
        ]
    );
    let s = script.lock().unwrap();
    assert_eq!((s.body.bytes.len(), s.body.ended), (100_000, true));
}

/// The script of the QUIC connection to an HTTP/3 proxy a CONNECT-UDP
/// goes through: `tunnel_script`'s, the answer naming `capsules` as its
/// capsule protocol, then the origin's datagrams the tunnel brings.
fn udp_tunnel_script(capsules: &[u8]) -> Arc<Mutex<Script>> {
    let proxy = tunnel_script(b"200", vec![]);
    {
        let mut s = proxy.lock().unwrap();
        s.on_read.pop_back();
        let answer = s.on_read.back_mut().unwrap();
        answer.insert(
            1,
            Told::Header {
                stream: 0,
                name: b"capsule-protocol".to_vec(),
                value: capsules.to_vec(),
            },
        );
        s.out.clear();
        s.out.extend([
            vec![1; 1200],
            vec![2; 1200],
            vec![],
            vec![],
            vec![3; 75],
            vec![],
        ]);
        // The origin's flight goes in two packets; the second's reply
        // tells nothing, and the GET's brings the response.
        s.on_read
            .push_back(vec![Told::Data(0, capsule(b"server flight"))]);
        s.on_read.push_back(vec![]);
        s.on_read
            .push_back(vec![Told::Data(0, capsule(b"response"))]);
    }
    proxy
}

/// A GET of `https://origin.example/p` in HTTP/3 alone by `e`, through
/// the HTTP/3 proxy at `https://localhost:PORT`.
fn h3_through_h3_proxy(m: &mut Multi, e: Easy) -> Ran {
    h3_through_h3_proxy_over(m, e, IpVersion::Any)
}

/// `h3_through_h3_proxy`, the proxy's addresses tried those of `ip`.
fn h3_through_h3_proxy_over(m: &mut Multi, e: Easy, ip: IpVersion) -> Ran {
    get_with(m, e, "/", Conversation::replies(&[], false), move |o| {
        o.set_url(Some(b"https://origin.example/p")).unwrap();
        o.http.version = crate::options::HttpVersion::Http3Only;
        o.ip_version = ip;
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("https://localhost:{PORT}").into_bytes());
        proxy.kind = crate::options::ProxyType::Https3;
        proxy.tunnel = true;
    })
}

/// HTTP/3 alone through an HTTP/3 proxy goes over its CONNECT-UDP, QUIC
/// in QUIC (`cf-ngtcp2-proxy.c` with `udp_tunnel=1`): the race's attempt
/// is the proxy's QUIC connection; the tunnel's request is an extended
/// `CONNECT` at the path naming the origin; once the proxy agrees, the
/// origin's QUIC connection is made over capsules sent as the tunnel
/// stream's DATA, the chain C's (`[HTTP/3][CAPSULE]` over the proxy's
/// filter), and the GET goes over it. C's build against h2o,
/// `test_60_01[h3_over_h3_proxytunnel]`.
#[test]
fn http3_through_an_http3_proxy_is_quic_in_quic() {
    let proxy = udp_tunnel_script(b"?1");
    let origin = get_script(b"123456789");
    let h3 = FakeHttp3::new(proxy.clone());
    h3.then.lock().unwrap().push_back(origin.clone());
    let tls: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    let e = tracing_with(tls, h3);
    let mut m = quic_server(&[
        b"server flight",
        b"connect answer",
        b"origin flight",
        b"origin response",
        b"more",
        b"more",
    ]);
    let ran = h3_through_h3_proxy(&mut m, e);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"123456789");
    // The origin's TLS, the last session made, is the origin's own.
    assert_eq!(tls.log().name(), b"origin.example");
    {
        let s = proxy.lock().unwrap();
        assert_eq!(
            s.requests[0],
            [
                ":method: CONNECT",
                ":scheme: https",
                &format!(":authority: localhost:{PORT}"),
                ":path: /.well-known/masque/udp/origin.example/443/",
                ":protocol: connect-udp",
                "capsule-protocol: ?1",
            ]
        );
        // The origin's flight and its GET, each datagram a capsule.
        let mut capsules = capsule(&[1; 1200]);
        capsules.extend(capsule(&[2; 1200]));
        capsules.extend(capsule(&[3; 75]));
        assert_eq!(s.body.bytes, capsules);
    }
    let got = lines(
        &ran,
        &[
            "Establishing",
            "CONNECT-UDP",
            "[H3-PROXY] created",
            "[H3-PROXY] [0] -> [",
            "[SETUP] added",
            "[MULTI] [CONNECTING] cf_setup_connect",
            "[MULTI] [CONNECTING] connected [",
            "[MULTI] [CONNECTING] reduced",
            "[HTTP/3] handshake complete",
            "using HTTP",
            "[READ] client_reset",
            "[HAPPY-EYEBALLS] connect attempt",
            "[HAPPY-EYEBALLS] Connected to",
        ],
    );
    let mut got = got;
    got.dedup();
    let from = got
        .iter()
        .position(|l| l.starts_with("[MULTI] [CONNECTING]"))
        .expect("the setup is traced");
    let to = got
        .iter()
        .position(|l| l.starts_with("using HTTP"))
        .expect("the protocol is said");
    let got = got[from..=to].to_vec();
    // The fake proxy answers at once, so the chain is not traced again
    // while the answer is awaited; the attempt is connected at the pass
    // after the proxy agreed, as C's H3-PROXY filter is
    // (`H3_TUNNEL_ESTABLISHED`), and the race won then.
    let want = expect(
        "[MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [H3-PROXY] created, udp_tunnel=1
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        Establishing HTTP/3 proxy UDP tunnel to origin.example:443
        [H3-PROXY] [0] -> [connect]
        [H3-PROXY] [0] -> [response]
        CONNECT-UDP Response Status 200
        CONNECT-UDP tunnel established, response 200
        [H3-PROXY] [0] -> [established]
        CONNECT-UDP phase completed for HTTP/3 proxy
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [READ] client_reset, clear readers
        [HAPPY-EYEBALLS] connect attempt #0 successful
        [HAPPY-EYEBALLS] Connected to localhost (::1) port 8990
        [SETUP] added QUIC filter for origin
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HTTP/3][!CAPSULE][HAPPY-EYEBALLS][H3-PROXY][UDP]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HTTP/3][CAPSULE][HAPPY-EYEBALLS][H3-PROXY][UDP]
        [HTTP/3] handshake complete after 0ms, remote transport[max_udp_payload=1452, initial_max_data=786432]
        [MULTI] [CONNECTING] connected [0][DNS][DNS][HTTPS-CONNECT][SETUP][HTTP/3][CAPSULE][HAPPY-EYEBALLS][H3-PROXY][UDP]
        [MULTI] [CONNECTING] reduced to [0][HTTP/3][CAPSULE][H3-PROXY][UDP]
        using HTTP/3",
    );
    assert_eq!(got, want);
}

/// The origin's QUIC connection over a CONNECT-UDP tunnel, under a
/// session resumed that allows early data, is connected at once as one
/// over a socket is: the GET goes as early data, and what the origin
/// took is reported (`Curl_cf_ngtcp2_cmn_connect` and
/// `cf_ngtcp2_on_session_reuse` are the same filter's either way). C's
/// build against h2o's proxy reports the 61 bytes of its GET sent.
#[test]
fn early_data_goes_to_an_origin_through_an_http3_proxy() {
    let proxy = udp_tunnel_script(b"?1");
    let origin = get_script(b"123456789");
    let h3 = FakeHttp3::new(proxy.clone());
    h3.then.lock().unwrap().push_back(origin.clone());
    let tls = FakeTls::quic_resuming(16384, Some(crate::tls::Chosen::H3), b"params").unwrap();
    let tls: &'static FakeTls = Box::leak(Box::new(tls));
    let e = tracing_with(tls, h3);
    let mut m = quic_server(&[
        b"server flight",
        b"connect answer",
        b"origin flight",
        b"origin response",
        b"more",
        b"more",
    ]);
    let ran = get_with(&mut m, e, "/", Conversation::replies(&[], false), |o| {
        o.set_url(Some(b"https://origin.example/p")).unwrap();
        o.http.version = crate::options::HttpVersion::Http3Only;
        o.tls.options.make_mut().unwrap().ssl_options = crate::options::SslOptions::EARLYDATA;
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("https://localhost:{PORT}").into_bytes());
        proxy.kind = crate::options::ProxyType::Https3;
        proxy.tunnel = true;
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"123456789");
    // The proxy's connection is not asked for early data, the origin's is.
    assert!(proxy.lock().unwrap().early_params.is_empty());
    assert_eq!(origin.lock().unwrap().early_params, b"params");
    let got = lines(
        &ran,
        &[
            "SSL session allows",
            "[HTTP/3] connect ->",
            "[HTTP/3] handshake complete",
            "[HTTP/3] server did",
            "[MULTI] [CONNECTING] connected [",
        ],
    );
    let want = expect(
        "SSL session allows 16384 bytes of early data, reusing ALPN 'h3'
        [HTTP/3] connect -> 0, done=1
        [MULTI] [CONNECTING] connected [0][DNS][DNS][HTTPS-CONNECT][SETUP][HTTP/3][CAPSULE][HAPPY-EYEBALLS][H3-PROXY][UDP]
        [HTTP/3] handshake complete after 0ms, remote transport[max_udp_payload=1452, initial_max_data=786432]
        [HTTP/3] server did accept 75 bytes of early data",
    );
    assert_eq!(got, want, "{:#?}", ran.seen.text());
    assert_eq!(ran.easy.report().earlydata_sent(), 75);
}

/// An HTTP/1.1 GET through an HTTP/3 proxy, the proxy's TLS options
/// `early`, under a session resumed that allows early data; what the
/// handle reported of early data before is `before`.
fn through_h3_proxy_early(early: crate::options::SslOptions, before: i64) -> Ran {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n".to_vec();
    let script = tunnel_script(b"200", vec![Told::Data(0, response)]);
    let mut m = quic_server(&[b"server flight", b"connect answer", b"response"]);
    let tls = FakeTls::quic_resuming(16384, Some(crate::tls::Chosen::H3), b"params").unwrap();
    let mut e = tracing(tls, &script);
    e.report_mut().set_earlydata_sent(before);
    let ran = get_with(
        &mut m,
        e,
        "/",
        Conversation::replies(&[], false),
        move |o| {
            o.set_url(Some(b"http://origin.example/p")).unwrap();
            // One address to try, so one attempt.
            o.ip_version = IpVersion::V6;
            let proxy = o.proxy.make_mut().unwrap();
            proxy.url = Some(format!("https://localhost:{PORT}").into_bytes());
            proxy.kind = crate::options::ProxyType::Https3;
            proxy.tunnel = true;
            proxy.tls.options.make_mut().unwrap().ssl_options = early;
        },
    );
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"ok\n");
    let params = script.lock().unwrap().early_params.clone();
    let asked = early.contains(crate::options::SslOptions::EARLYDATA);
    assert_eq!(params, if asked { &b"params"[..] } else { b"" });
    ran
}

/// The connection to an HTTP/3 proxy whose TLS options ask for early
/// data goes under a session resumed that allows it as the origin's
/// does: connected at once, the tunnel's `CONNECT` going before the
/// handshake ends, and what went early counted for the transfer, which
/// keeps no count from before; the transfer's TLS is not timed by it
/// (`cf_ngtcp2_on_session_reuse`, `Curl_pgrsEarlyData`, and no
/// `TIMER_APPCONNECT` for a `CF_TYPE_PROXY` filter). C's build against
/// h2o's proxy: `[H3-PROXY] connect -> 0, done=1` before `CONNECT
/// start`, `server did accept 0 bytes of early data`, and an
/// `CURLINFO_EARLYDATA_SENT_T` of 0 where the transfer before it on the
/// handle reported 63.
#[test]
fn early_data_goes_to_an_http3_proxy_counted_but_untimed() {
    let none = crate::options::SslOptions::NONE;
    let early = crate::options::SslOptions::EARLYDATA;
    let without = through_h3_proxy_early(none, 63);
    let ran = through_h3_proxy_early(early, 63);
    let got = lines(
        &ran,
        &[
            "SSL session allows",
            "[H3-PROXY] connect ->",
            "[H3-PROXY] [0] CONNECT start",
            "[H3-PROXY] handshake complete",
            "[H3-PROXY] server did",
        ],
    );
    let want = expect(
        "SSL session allows 16384 bytes of early data, reusing ALPN 'h3'
        [H3-PROXY] connect -> 0, done=1
        [H3-PROXY] [0] CONNECT start for origin.example:80
        [H3-PROXY] handshake complete after 0ms, remote transport[max_udp_payload=1452, initial_max_data=786432]
        [H3-PROXY] server did accept 0 bytes of early data",
    );
    assert_eq!(got, want, "{:#?}", ran.seen.text());
    assert_eq!(ran.easy.report().earlydata_sent(), 0);
    // Not asking, the count from before stays, as C's does.
    assert!(lines(&without, &["SSL session allows", "server did"]).is_empty());
    assert_eq!(without.easy.report().earlydata_sent(), 63);
    // The transfer's times are those of the same transfer not asking.
    let timed = |r: &Ran| {
        let t = r.easy.report().timings();
        (t.connect(), t.appconnect())
    };
    assert_eq!(timed(&ran), timed(&without));
    assert_eq!(timed(&ran).0, Duration::ZERO);
}

/// An HTTP/3 proxy naming another capsule protocol than RFC 9297's in
/// its answer to a CONNECT-UDP fails the tunnel, as one over HTTP/2 does
/// (`Curl_http_proxy_inspect_tunnel_response`).
#[test]
fn an_http3_proxy_s_other_capsule_protocol_fails_the_tunnel() {
    let proxy = udp_tunnel_script(b"?0");
    let h3 = FakeHttp3::new(proxy.clone());
    h3.then.lock().unwrap().push_back(Script::new());
    let tls: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    let e = tracing_with(tls, h3);
    let mut m = quic_server(&[b"server flight", b"connect answer"]);
    let ran = h3_through_h3_proxy_over(&mut m, e, IpVersion::V6);
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert_eq!(
        lines(&ran, &["Failed to establish", "[H3-PROXY] [0] -> [f", "[HTTP/3]"]),
        expect(
            "Failed to establish CONNECT-UDP tunnel, response 200, unsupported capsule-protocol value '?0'
            [H3-PROXY] [0] -> [failed]"
        )
    );
}

/// The trace lines of `ran` that contain `needle`, as their bytes.
fn raw_lines_with(ran: &Ran, needle: &[u8]) -> Vec<Vec<u8>> {
    ran.seen
        .of("text")
        .into_iter()
        .filter(|l| l.windows(needle.len()).any(|w| w == needle))
        .collect()
}

/// A response header whose value is not UTF-8 (obs-text) is traced as
/// its bytes, as C's `%s` writes them (`cb_h3_recv_header`), and handed
/// to the application as its bytes.
#[test]
fn an_http3_header_not_utf8_is_traced_as_its_bytes() {
    let script = get_script(b"123456789");
    script.lock().unwrap().on_read[1].insert(
        1,
        Told::Header {
            stream: 0,
            name: b"x-obs".to_vec(),
            value: b"caf\xe9 \xff\xfe!".to_vec(),
        },
    );
    let mut m = quic_server(&[b"server flight", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Ok(()));
    let traced = raw_lines_with(&ran, b"header: x-obs: ");
    assert_eq!(traced.len(), 1, "{traced:?}");
    assert!(
        traced[0].ends_with(b"[HTTP/3] [0] header: x-obs: caf\xe9 \xff\xfe!\n"),
        "{:?}",
        traced[0]
    );
    assert!(
        ran.seen
            .of("header")
            .contains(&b"x-obs: caf\xe9 \xff\xfe!\r\n".to_vec())
    );
}

/// The same through an HTTP/3 proxy: its answer's header that is not
/// UTF-8 is traced as its bytes (`cb_h3_recv_header` in
/// `cf-ngtcp2-proxy.c`).
#[test]
fn an_http3_proxy_header_not_utf8_is_traced_as_its_bytes() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n".to_vec();
    let script = tunnel_script(b"200", vec![Told::Data(0, response)]);
    script.lock().unwrap().on_read[1][1] = Told::Header {
        stream: 0,
        name: b"via".to_vec(),
        value: b"h3\xc3proxy".to_vec(),
    };
    let mut m = quic_server(&[b"server flight", b"connect answer", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = through_h3_proxy(&mut m, e);
    assert_eq!(ran.result, Ok(()));
    let traced = raw_lines_with(&ran, b"[0] header: via: ");
    assert_eq!(traced.len(), 1, "{traced:?}");
    assert!(
        traced[0].ends_with(b"[H3-PROXY] [0] header: via: h3\xc3proxy\n"),
        "{:?}",
        traced[0]
    );
}

/// A capsule protocol the proxy names that is not UTF-8 is said as its
/// bytes in the tunnel's failure, as C's `failf` with `%s` says it.
#[test]
fn an_http3_proxy_s_capsule_protocol_not_utf8_fails_as_its_bytes() {
    let proxy = udp_tunnel_script(b"?\xff");
    let h3 = FakeHttp3::new(proxy.clone());
    h3.then.lock().unwrap().push_back(Script::new());
    let tls: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    let e = tracing_with(tls, h3);
    let mut m = quic_server(&[b"server flight", b"connect answer"]);
    let ran = h3_through_h3_proxy_over(&mut m, e, IpVersion::V6);
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let why = b"Failed to establish CONNECT-UDP tunnel, response 200, \
        unsupported capsule-protocol value '?\xff'";
    let mut line = why.to_vec();
    line.push(b'\n');
    assert!(
        raw_lines_with(&ran, b"unsupported capsule-protocol")
            .iter()
            .any(|l| l.ends_with(&line)),
        "traced as its bytes"
    );
}

/// The HTTP/3 proxy's `CONNECT` names a host that is not UTF-8 as its
/// bytes in the tunnel's trace (`cf-ngtcp2-proxy.c`'s "CONNECT start").
#[test]
fn an_http3_proxy_connect_names_its_host_as_its_bytes() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n".to_vec();
    let script = tunnel_script(b"200", vec![Told::Data(0, response)]);
    let mut m = quic_server(&[b"server flight", b"connect answer", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = get_with(&mut m, e, "/", Conversation::replies(&[], false), |o| {
        o.set_url(Some(b"http://caf\xe9.example/p")).unwrap();
        o.ip_version = IpVersion::Any;
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("https://localhost:{PORT}").into_bytes());
        proxy.kind = crate::options::ProxyType::Https3;
        proxy.tunnel = true;
    });
    let traced = raw_lines_with(&ran, b"CONNECT start for ");
    assert_eq!(traced.len(), 1, "{:?} {traced:?}", ran.result);
    assert!(
        traced[0].ends_with(b"[H3-PROXY] [0] CONNECT start for caf\xe9.example:80\n"),
        "{:?}",
        traced[0]
    );
}

/// Two GETs of `/a` and `/b` on one QUIC connection to 127.0.0.1, the
/// second waiting for the first's to multiplex on it, both heads read in
/// the third packet in; the fourth, which the connection reads with
/// `then`, comes only once the test lets it (`talk.allow(4)`). The first
/// alone has a timer to run it: its speed checked each second.
fn two_heads_on_quic(then: Vec<Told>) -> TwoOnQuic {
    use std::num::{NonZeroU16, NonZeroU64};
    let script = Script::new();
    {
        let mut s = script.lock().unwrap();
        s.idle = Some(std::time::Duration::from_secs(30));
        s.out.extend([vec![1; 1200], vec![2; 1200], vec![], vec![]]);
        s.on_submit
            .extend([vec![vec![3; 75], vec![]], vec![vec![4; 76], vec![]]]);
        s.on_read
            .push_back(vec![Told::HandshakeDone, Told::MaxBidiStreams(100)]);
        // Stream 0's request is only acknowledged.
        s.on_read.push_back(vec![]);
        let mut heads = Vec::new();
        for stream in [0, 4] {
            let header = |name: &[u8], value: &[u8]| Told::Header {
                stream,
                name: name.to_vec(),
                value: value.to_vec(),
            };
            heads.extend([
                header(b":status", b"200"),
                header(b"content-length", b"9"),
                Told::HeadersDone(stream),
            ]);
        }
        s.on_read.push_back(heads);
        s.on_read.push_back(then);
    }
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::replies(&[b"server flight", b"ack", b"heads", b"then"], false)
        .per_send()
        .volunteering(1)
        .held();
    talk.allow(3);
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let mut ids = Vec::new();
    let mut seen = Vec::new();
    for (path, timed) in [("/a", true), ("/b", false)] {
        let mut e = tracing(FakeTls::new().unwrap(), &script);
        let s = Seen::default();
        let o = e.options_mut();
        let url = format!("https://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.output.verbose = true;
        o.http.version = crate::options::HttpVersion::Http3Only;
        o.http.pipewait = true;
        if timed {
            o.flow.make_mut().unwrap().low_speed = Some(crate::options::LowSpeed {
                limit: NonZeroU64::new(1).unwrap(),
                time: NonZeroU16::new(30).unwrap(),
            });
        }
        o.callbacks.write = Some(Handler::write(s.clone()).unwrap());
        o.callbacks.header = Some(Handler::header(s.clone()).unwrap());
        o.callbacks.debug = Some(Handler::debug(s.clone()).unwrap());
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
        seen.push(s);
    }
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
        if seen.iter().all(|s| s.of("header").len() == 3) {
            break;
        }
    }
    for s in &seen {
        assert_eq!(s.of("header").len(), 3, "both heads read: {:#?}", s.text());
    }
    TwoOnQuic {
        m,
        talk,
        ids,
        seen,
        clock,
    }
}

/// What `two_heads_on_quic` made.
struct TwoOnQuic {
    m: Multi,
    talk: Conversation,
    ids: Vec<crate::multi::TransferId>,
    seen: Vec<Seen>,
    clock: ManualClock,
}

impl TwoOnQuic {
    /// The `[HTTP/3]` lines transfer `i` traced.
    fn text(&self, i: usize) -> Vec<String> {
        lines_of(&self.seen[i], &["[HTTP/3]"])
    }

    fn said(&self, i: usize, line: &str) -> bool {
        self.text(i).iter().any(|l| l == line)
    }

    /// Each transfer's result, none for one still running.
    fn results(&mut self) -> Vec<Option<Result<(), ErrorKind>>> {
        let mut results = vec![None; self.ids.len()];
        while let Some(msg) = self.m.info_read() {
            let i = self.ids.iter().position(|&id| id == msg.id).unwrap();
            results[i] = Some(msg.result);
        }
        results
    }
}

/// The HTTP/3 library refusing a sibling's stream as a transfer reads
/// fails the read, the stream's own transfer saying so as C's
/// `cb_recv_stream_data` does on the stream's transfer; the library's
/// failure closes the connection, and the other fails as it runs.
#[test]
fn a_refused_stream_is_said_on_its_own_transfer() {
    let mut two = two_heads_on_quic(vec![Told::Refused(4)]);
    two.talk.allow(4);
    for _ in 0..5 {
        two.m.perform(&mut NoEvents).unwrap();
    }
    assert!(
        two.said(1, "[HTTP/3] [4] error on known stream, reset=0, closed=0"),
        "{:#?}",
        two.text(1)
    );
    assert!(
        !two.text(0)
            .iter()
            .any(|l| l.contains("error on known stream")),
        "{:#?}",
        two.text(0)
    );
    assert!(
        two.said(0, "[HTTP/3] ingress, read_pkt -> ERR_FAKE (-502)"),
        "{:#?}",
        two.text(0)
    );
    for (i, id) in [(0, 0), (1, 4)] {
        let read = format!("[HTTP/3] [{id}] cf_recv(buflen=16384) -> 56, 0");
        assert!(two.said(i, &read), "{read:?} in {:#?}", two.text(i));
    }
    let results = two.results();
    assert_eq!(
        results,
        [
            Some(Err(ErrorKind::RecvError)),
            Some(Err(ErrorKind::RecvError))
        ]
    );
}

/// Two streams of one connection the server closes cleanly, each short of
/// the body its `content-length` gave, in one packet: each transfer fails
/// as a partial file, neither taken for whole.
#[test]
fn streams_closed_cleanly_mid_body_together_are_each_a_partial_file() {
    let mut two = two_heads_on_quic(vec![
        Told::Data(0, b"1234".to_vec()),
        Told::Data(4, b"12345678".to_vec()),
        Told::Closed(0, 0x100),
        Told::Closed(4, 0x100),
    ]);
    two.talk.allow(4);
    for _ in 0..5 {
        two.m.perform(&mut NoEvents).unwrap();
    }
    assert_eq!(
        two.results(),
        [
            Some(Err(ErrorKind::PartialFile)),
            Some(Err(ErrorKind::PartialFile))
        ]
    );
    assert_eq!(two.seen[0].body(), b"1234");
    assert_eq!(two.seen[1].body(), b"12345678");
    for (i, missing) in [(0, 5), (1, 1)] {
        let said = format!("end of response with {missing} bytes missing");
        let got = lines_of(&two.seen[i], &["end of response"]);
        assert_eq!(got, [said], "transfer {i}");
    }
}

/// The library giving the connection up mid-body, both transfers on it
/// reading part of their bodies, fails each, the one whose read failed
/// and the other as it next runs on the connection closed.
#[test]
fn a_connection_dropped_mid_body_fails_each_transfer_on_it() {
    let mut two = two_heads_on_quic(vec![
        Told::Data(0, b"1234".to_vec()),
        Told::Data(4, b"12345678".to_vec()),
        // NGTCP2_ERR_DROP_CONN.
        Told::ReadFails(-232),
    ]);
    two.talk.allow(4);
    for _ in 0..5 {
        two.m.perform(&mut NoEvents).unwrap();
    }
    assert_eq!(
        two.results(),
        [
            Some(Err(ErrorKind::RecvError)),
            Some(Err(ErrorKind::RecvError))
        ]
    );
    assert_eq!(two.seen[0].body(), b"1234");
    assert_eq!(two.seen[1].body(), b"12345678");
}

/// What a transfer's step reads for its sibling's stream has the sibling
/// run when its turn next comes only if it must act on it, as C's
/// callbacks mark it dirty: its body, written to it as it is read, does
/// not (`cb_h3_recv_data`); its stream's close does (`cb_h3_stream_close`),
/// and so does its flow unblocked once it was blocked.
/// The first runs alone, by its timer, and reads the packet with the
/// second's.
#[test]
fn a_sibling_runs_for_its_stream_s_close_and_not_for_its_body() {
    use crate::multi::SocketEvent;
    let ran = |then: Vec<Told>| {
        let mut two = two_heads_on_quic(then);
        two.talk.allow(4);
        two.clock.advance(std::time::Duration::from_millis(1000));
        let before = two.seen[1].text().len();
        two.m
            .socket_action(SocketEvent::Timeout, &mut NoEvents)
            .unwrap();
        let after: Vec<String> = two.seen[1].text()[before..].to_vec();
        let ran = after.iter().any(|l| l.contains("multi_run_dirty"));
        (ran, two.seen[1].body(), after)
    };
    let (sibling_ran, body, after) = ran(vec![Told::Data(4, b"part".to_vec())]);
    assert_eq!(body, b"part", "written to it in the first's step");
    assert!(!sibling_ran, "not run for its body: {after:#?}");
    let (sibling_ran, body, after) = ran(vec![
        Told::Data(4, b"all of it".to_vec()),
        Told::Closed(4, 0x100),
    ]);
    assert_eq!(body, b"all of it");
    assert!(sibling_ran, "run for its close: {after:#?}");
    // Its flow unblocked once it was blocked, it runs to send more
    // (`cb_extend_max_stream_data`); unblocked when it was not, it has
    // nothing to act on.
    let (sibling_ran, _, after) = ran(vec![Told::Blocked(4), Told::Unblocked(4)]);
    assert!(sibling_ran, "run for its flow unblocked: {after:#?}");
    let (sibling_ran, _, after) = ran(vec![Told::Unblocked(4)]);
    assert!(!sibling_ran, "not run, never blocked: {after:#?}");
}

/// The transfers on one connection wait on its socket together: a wait
/// polls it once, counts it once as it is ready and says one descriptor,
/// as C folds a socket listed twice (`cpfds_add_sock`).
#[test]
fn a_wait_polls_a_shared_connection_s_socket_once() {
    let mut two = two_heads_on_quic(vec![]);
    two.talk.allow(4);
    let ready = two.m.wait(
        &mut [],
        std::time::Duration::ZERO,
        crate::multi::WaitMode::Wait,
        &mut NoEvents,
    );
    assert_eq!(ready, Ok(1));
    let waits: Vec<String> = two.seen[1]
        .text()
        .into_iter()
        .filter(|l| l.contains("multi_wait("))
        .collect();
    let last = waits.last().expect("the wait traced");
    assert!(last.contains("multi_wait(fds=1, "), "{waits:#?}");
}

/// A read that fails in a step its socket did not start, the first
/// transfer's run by its timer, fails the other transfer on the
/// connection in the same call: the connection's failure has the other
/// run at once, with C's code and line, rather than wait for an event of
/// its socket that will not come or a timer it may not have.
#[test]
fn a_failed_read_run_by_a_timer_fails_the_other_transfer_at_once() {
    use crate::multi::SocketEvent;
    // The first's own stream is refused: nothing the library tells is
    // the other's.
    let mut two = two_heads_on_quic(vec![Told::Refused(0)]);
    two.talk.allow(4);
    // The first's speed check comes due; the socket's event is not
    // looked at, as an application's loop runs its due timers first.
    two.clock.advance(std::time::Duration::from_millis(1000));
    let running = two
        .m
        .socket_action(SocketEvent::Timeout, &mut NoEvents)
        .unwrap();
    assert_eq!(running, 0, "{:#?}\n{:#?}", two.text(0), two.text(1));
    assert!(
        two.said(0, "[HTTP/3] ingress, read_pkt -> ERR_FAKE (-502)"),
        "the first read: {:#?}",
        two.text(0)
    );
    assert!(
        two.said(1, "[HTTP/3] [4] cf_recv(buflen=16384) -> 56, 0"),
        "{:#?}",
        two.text(1)
    );
    assert_eq!(
        two.results(),
        [
            Some(Err(ErrorKind::RecvError)),
            Some(Err(ErrorKind::RecvError))
        ]
    );
}

/// `get_script`, spoken as quiche's filter speaks it: its stream ends
/// with no word from the QUIC library of its own, which quiche has none
/// of.
fn quiche_script(body: &[u8]) -> Arc<Mutex<Script>> {
    let script = get_script(body);
    {
        let mut s = script.lock().unwrap();
        s.flavour = crate::http3::Flavour::Quiche;
        let response = s.on_read.back_mut().unwrap();
        assert!(matches!(response.pop(), Some(Told::QuicClosed(..))));
    }
    script
}

/// A GET over quiche is traced as C's quiche filter traces it: its
/// Initial said, its handshake said complete before the peer is checked,
/// its request said sent with the stream it opened, each packet sent as
/// it is short of the largest with that as its segment size, and the
/// head, body and end of its stream said as they come; no window opened
/// and no ngtcp2 egress said (`cf-quiche.c`).
#[test]
fn a_get_over_quiche_is_traced_as_its_filter_traces_it() {
    let script = quiche_script(b"123456789");
    let mut m = quic_server(&[b"server flight", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Ok(()));
    let got = lines(
        &ran,
        &[
            "[HTTP/3]",
            "using",
            "Request completely sent off",
            "[WRITE] xfer_write_resp",
            "Connection #0",
        ],
    );
    let want = expect(&format!(
        "[HTTP/3] fake QUIC session 1
        [HTTP/3] vquic_sendmsg(len=2400, gso=1200, calls=1) -> 0, sent=2400
        [HTTP/3] Sent QUIC client Initial, ALPN: h3
        [HTTP/3] fake QUIC session 1 trusts
        [HTTP/3] ingress, recvmmsg -> EAGAIN
        [HTTP/3] vquic_recvmmsg(len=13, packets=1, calls=1) -> 0
        [HTTP/3] peer verified
        [HTTP/3] query ALPN
        using HTTP/3
        [HTTP/3] ingress, recvmmsg -> EAGAIN
        [HTTP/3] quiche_send_request() -> 0
        [HTTP/3] [0] OPENED stream for https://localhost:{PORT}/
        [HTTP/3] [0] [:method: GET]
        [HTTP/3] [0] [:scheme: https]
        [HTTP/3] [0] [:authority: localhost:{PORT}]
        [HTTP/3] [0] [:path: /]
        [HTTP/3] [0] [user-agent: curl/test]
        [HTTP/3] [0] [accept: */*]
        [HTTP/3] vquic_sendmsg(len=75, gso=1200, calls=1) -> 0, sent=75
        [HTTP/3] [0] cf_send(len=74) -> 0, 74
        Request completely sent off
        [HTTP/3] [0] status: HTTP/3 200
        [HTTP/3] [0] header: content-length: 9
        [HTTP/3] [0] <- [HEADERS]
        [WRITE] xfer_write_resp(len=9, eos=0) -> 0
        [HTTP/3] [0] <- [DATA]
        [HTTP/3] [0] CLOSED
        [HTTP/3] ingress, recvmmsg -> EAGAIN
        [HTTP/3] vquic_recvmmsg(len=8, packets=1, calls=1) -> 0
        [HTTP/3] [0] cf_recv(len=16384) -> 0, 0, total=0
        [WRITE] xfer_write_resp(len=0, eos=1) -> 0
        [HTTP/3] [0] easy handle is done
        [HTTP/3] query conn[0]: MAX_CONCURRENT -> 99 (0 in use)
        Connection #0 to host localhost:{PORT} left intact"
    ));
    assert_eq!(got, want);
    // The end of the head is written after the head is said to have
    // come, its fields before.
    assert_eq!(
        ran.seen.of("header"),
        [
            b"HTTP/3 200 \r\n".to_vec(),
            b"content-length: 9\r\n".to_vec(),
            b"\r\n".to_vec()
        ]
    );
    {
        // A header as it was written; a line of text past its ids.
        let saw = ran.seen.0.lock().unwrap();
        let at = |what: &str, bytes: &[u8]| {
            saw.iter()
                .position(|(w, b)| {
                    *w == what && (b == bytes || (what == "text" && b.ends_with(bytes)))
                })
                .unwrap_or_else(|| panic!("no {what} {:?}", String::from_utf8_lossy(bytes)))
        };
        let field = at("header", b"content-length: 9\r\n");
        let said = at("text", b"[HTTP/3] [0] <- [HEADERS]\n");
        let ended = at("header", b"\r\n");
        assert!(field < said && said < ended, "{field} {said} {ended}");
    }
    assert_eq!(ran.seen.body(), b"123456789");
    let s = script.lock().unwrap();
    assert!(s.windows.is_empty(), "quiche opens its windows itself");
    assert_eq!(s.cancelled, [], "the stream ended of itself");
}

/// A request quiche's flow control holds back is said blocked, by C's
/// id for a stream not yet open, and made again as the transfer next
/// sends (`h3_open_stream`).
#[test]
fn a_request_quiche_holds_back_is_made_again() {
    let script = quiche_script(b"123456789");
    script.lock().unwrap().submit_blocked = 1;
    let mut m = quic_server(&[b"server flight", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Ok(()));
    let got = lines(
        &ran,
        &["[HTTP/3] quiche_send", "[HTTP/3] [18446744073709551615]"],
    );
    assert_eq!(
        got,
        expect(
            "[HTTP/3] quiche_send_request() -> -13
            [HTTP/3] [18446744073709551615] blocked
            [HTTP/3] quiche_send_request() -> 0"
        )
    );
    assert_eq!(script.lock().unwrap().requests.len(), 1);
    assert_eq!(ran.seen.body(), b"123456789");
}

/// Two GETs on new connections, the first spoken as `first` and the
/// second as `second`, by a TLS backend whose QUIC sessions give their
/// ticket as the handshake ends: how many the second resumed.
fn second_resumes_over(first: crate::http3::Flavour, second: crate::http3::Flavour) -> usize {
    let tls = FakeTls::quic_ticketing(crate::tls::fake::QuicTickets::AtHandshake).unwrap();
    let tls: &'static FakeTls = Box::leak(Box::new(tls));
    let conn: &[&[u8]] = &[b"server flight", b"response"];
    let clock = ManualClock::new().unwrap();
    clock.set_unix_time(1_700_000_000);
    let (mut m, _) = quic_peer(clock, &[conn, conn]);
    for flavour in [first, second] {
        let script = get_script(b"123456789");
        script.lock().unwrap().flavour = flavour;
        let e = tracing_by(tls, &script);
        let url = format!("https://localhost:{PORT}/");
        let ran = get_with(&mut m, e, "/", Conversation::replies(&[], false), |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
            o.http.version = crate::options::HttpVersion::Http3Only;
            o.ip_version = IpVersion::V6;
            o.limits.reuse.fresh = true;
        });
        assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    }
    tls.log().resumed
}

/// quiche's filter keeps no session the peer gives, as it sets its TLS
/// no callback for them, but looks one up and resumes one kept already
/// (`Curl_vquic_tls_init`, `Curl_ossl_ctx_init`).
#[test]
fn quiche_keeps_no_session_but_resumes_one_kept() {
    use crate::http3::Flavour::{Ngtcp2, Quiche};
    assert_eq!(second_resumes_over(Quiche, Quiche), 0);
    assert_eq!(second_resumes_over(Ngtcp2, Quiche), 1);
    assert_eq!(second_resumes_over(Quiche, Ngtcp2), 0);
}

/// A request quiche refuses opens no stream: the transfer fails to send,
/// the request named by its URL, as quiche's filter names it
/// (`h3_open_stream`).
#[test]
fn a_request_quiche_refuses_fails_naming_its_url() {
    let script = quiche_script(b"123456789");
    script.lock().unwrap().submit_refused = Some(-6);
    let mut m = quic_server(&[b"server flight", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Err(ErrorKind::SendError));
    let got = lines(&ran, &["[HTTP/3] quiche_send", "[HTTP/3] send_request"]);
    assert_eq!(
        got,
        expect(&format!(
            "[HTTP/3] quiche_send_request() -> -6
            [HTTP/3] send_request(https://localhost:{PORT}/) -> -6"
        ))
    );
    assert!(
        script.lock().unwrap().cancelled.is_empty(),
        "no stream to cancel"
    );
}

/// A request quiche's peer refuses, its stream reset with
/// `H3_REQUEST_REJECTED`, is made again on a new connection: the reset's
/// code is the peer's, as quiche gives it, where C's quiche filter keeps
/// none and fails the transfer (`DIVERGENCE.md`).
#[test]
fn a_request_quiche_s_peer_refuses_is_made_again() {
    let script = quiche_script(b"");
    {
        let mut s = script.lock().unwrap();
        *s.on_read.back_mut().unwrap() = vec![Told::Closed(0, 0x10b)];
        s.out.push_back(vec![]);
    }
    twice(&script, b"again");
    script.lock().unwrap().on_read.back_mut().unwrap().pop();
    let (mut m, _) = quic_peer(
        ManualClock::new().unwrap(),
        &[
            &[b"server flight", b"refused"],
            &[b"server flight", b"response"],
        ],
    );
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"again");
    assert_eq!(
        lines(&ran, &["HTTP/3 stream", "[HTTP/3] [0] RESET"]),
        [
            "[HTTP/3] [0] RESET",
            "HTTP/3 stream 0 refused by server, try again on a new connection",
        ]
    );
}

/// An interim response's head ends before the final one's starts, each
/// at its end over quiche as over ngtcp2, where C's quiche filter ends
/// only the last, at the body (`DIVERGENCE.md`).
#[test]
fn an_interim_head_over_quiche_ends_before_the_final_one() {
    let script = quiche_script(b"ok");
    {
        let mut s = script.lock().unwrap();
        let header = |name: &[u8], value: &[u8]| Told::Header {
            stream: 0,
            name: name.to_vec(),
            value: value.to_vec(),
        };
        let response = s.on_read.back_mut().unwrap();
        let interim = [
            header(b":status", b"103"),
            header(b"link", b"</style.css>; rel=preload"),
            Told::HeadersDone(0),
        ];
        response.splice(0..0, interim);
    }
    let mut m = quic_server(&[b"server flight", b"response"]);
    let e = tracing(FakeTls::new().unwrap(), &script);
    let ran = h3_get(&mut m, e);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(
        ran.seen.of("interim"),
        [
            b"HTTP/3 103 \r\n".to_vec(),
            b"link: </style.css>; rel=preload\r\n".to_vec(),
            b"\r\n".to_vec(),
        ]
    );
    assert_eq!(
        ran.seen.of("header"),
        [
            b"HTTP/3 200 \r\n".to_vec(),
            b"content-length: 2\r\n".to_vec(),
            b"\r\n".to_vec(),
        ]
    );
    assert_eq!(ran.seen.body(), b"ok");
}
