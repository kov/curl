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
