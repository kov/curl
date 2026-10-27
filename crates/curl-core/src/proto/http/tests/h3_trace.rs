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
    let mut net = FakeNet::new(clock.clone()).with_name(
        "localhost",
        &[
            std::net::Ipv6Addr::LOCALHOST.into(),
            std::net::Ipv4Addr::LOCALHOST.into(),
        ],
    );
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
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), talks)
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

/// A connection a share keeps is reused by a multi whose clock reads
/// behind the one it was made under: it goes on reading its own, so the
/// library is never handed a time before one it had.
#[test]
fn a_shared_connection_keeps_its_clock_under_another_multi() {
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
    let ahead = ManualClock::new().unwrap();
    ahead.advance(std::time::Duration::from_secs(10));
    let replies: &[&[u8]] = &[b"server flight", b"response", b"second"];
    let mut first = quic_server_on(ahead, replies);
    let mut e = tracing(FakeTls::new().unwrap(), &script);
    e.set_share(Some(share.clone()));
    assert_eq!(h3_get(&mut first, e).result, Ok(()));
    // The second request's packet, once the first is done.
    script.lock().unwrap().out.extend([vec![5; 75], vec![]]);
    let mut second = quic_server_on(ManualClock::new().unwrap(), replies);
    let mut e = tracing(FakeTls::new().unwrap(), &script);
    e.set_share(Some(share.clone()));
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
/// and those open; the second's read hands each stream's response to its
/// transfer, the first's to its sibling, so the second is done first; the
/// connection is kept for the last.
#[test]
fn a_second_transfer_multiplexes_on_the_first_s_connection() {
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
    let mut m = quic_server(&[b"server flight", b"ack", b"responses"]);
    let url = format!("https://localhost:{PORT}/");
    let mut ids = Vec::new();
    let mut seen = Vec::new();
    for _ in 0..2 {
        let mut e = tracing(FakeTls::new().unwrap(), &script);
        let s = Seen::default();
        let o = e.options_mut();
        o.set_url(Some(url.as_bytes())).unwrap();
        o.output.verbose = true;
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.http.user_agent = Some(b"curl/test".to_vec());
        o.http.version = crate::options::HttpVersion::Http3Only;
        o.http.pipewait = true;
        o.ip_version = IpVersion::Any;
        o.callbacks.write = Some(Handler::write(s.clone()).unwrap());
        o.callbacks.header = Some(Handler::header(s.clone()).unwrap());
        o.callbacks.debug = Some(Handler::debug(s.clone()).unwrap());
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
            [HTTP/3] query conn[0]: MAX_CONCURRENT -> 98 (0 in use)
            Connection #0 to host localhost:{PORT} left intact"
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
            [MULTI] [DONE] Connection still in use 1, no more multi_done now!"
        ))
    );
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
    assert_eq!(
        said[..3],
        [
            "[HTTP/3] [0] cf_send(len=34612) -> 81, 0",
            "[MULTI] [PERFORMING] pollset[fd=1000 IN], timeouts=3",
            "[HTTP/3] [0] cf_send(len=34612) -> 0, 34612",
        ]
    );
    let s = script.lock().unwrap();
    assert_eq!((s.body.bytes.len(), s.body.ended), (100_000, true));
}

/// A peer at `PORT` on IPv4 alone, whose datagrams meet `quic`, its first
/// conversation `quic_talk`, and whose streams meet `tcp`, its next
/// `tcp_talk`: the race's two attempts, QUIC's opened first.
fn racing_peer(quic: Peer, quic_talk: &Conversation, tcp: Peer, tcp_talk: &Conversation) -> Multi {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let net = FakeNet::new(clock.clone())
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
        using HTTP/1.x
        ",
    );
    let tail = got.len() - end.len();
    assert_eq!(got[tail..], end[..], "{got:#?}");
    // The TCP attempt started at the soft timeout.
    let connect = ran.easy.report().timings().connect();
    assert_eq!(connect.as_millis(), 100, "{got:#?}");
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
}

/// A race that runs out of time with both its attempts under way fails,
/// both attempts closed with the request: the one out of the lease goes
/// with the lease's.
#[test]
fn a_race_timed_out_closes_both_attempts() {
    let quic_talk = Conversation::replies(&[], false).per_send();
    let tcp_talk = Conversation::replies(&[], false).per_send();
    let mut m = racing_peer(Peer::Silent, &quic_talk, Peer::Silent, &tcp_talk);
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

/// A transfer in HTTP/3 or older through a proxy makes one attempt, over
/// TCP: through a SOCKS proxy, HTTP/3 may not be spoken, which is said
/// as HTTP/3 is weighed (`cf_hc_may_h3`); through an HTTP proxy's tunnel,
/// not yet made over CONNECT-UDP, it is not weighed.
#[test]
fn http3_through_a_proxy_goes_over_tcp_alone() {
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
        assert!(
            got.contains(&"[HTTPS-CONNECT] 1st attempt uses h1 from wanted versions".to_string()),
            "{proxy}: {got:#?}"
        );
        assert!(
            !got.iter().any(|l| l.contains("2nd attempt")),
            "{proxy}: {got:#?}"
        );
        let said = lines(&ran, &["HTTP/3 is not supported"]);
        assert_eq!(said.len(), usize::from(why.is_some()), "{proxy}: {said:#?}");
    }
}
