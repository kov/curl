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
    let tls: &'static FakeTls = Box::leak(Box::new(tls));
    let h3: &'static FakeHttp3 = Box::leak(Box::new(FakeHttp3::new(script.clone())));
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
    ran.seen
        .text()
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
    let clock = ManualClock::new().unwrap();
    let mut net = FakeNet::new(clock.clone()).with_name(
        "localhost",
        &[
            std::net::Ipv6Addr::LOCALHOST.into(),
            std::net::Ipv4Addr::LOCALHOST.into(),
        ],
    );
    for at in [
        SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, PORT)),
        SocketAddr::from(([127, 0, 0, 1], PORT)),
    ] {
        net = net
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, Conversation::replies(replies, false).per_send());
    }
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    Multi::new(env).unwrap()
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
    let want = expect(&format!(
        "[HTTPS-CONNECT] 1st attempt uses h3 from wanted versions
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
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
        [HAPPY-EYEBALLS] next HAPPY_EYEBALLS timeout in 200ms
        [UDP] adjust_pollset, !active, POLLIN fd=1000
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
    // The second attempt is the last: no timer for another is set.
    let attempt = |v: u8, ip: &str| {
        let next = if v == 6 {
            "[HAPPY-EYEBALLS] next HAPPY_EYEBALLS timeout in 200ms"
        } else {
            ""
        };
        format!(
            "[HAPPY-EYEBALLS] starting first attempt for ipv{v} -> 0
            {next}
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
