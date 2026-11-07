//! The connection against a quiche server of the test's own, run on a
//! thread of its process: a peer that can be made to do what caddy will
//! not on demand (hold an upload back, send fields curl refuses, go
//! away, close, fall idle), and that reports what it saw of the client.

#![cfg(boringssl)]
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

mod common;

use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant as StdInstant};

use common::{Dir, Told, certs, flush, refs, request, run, take_one, with_client};
use curl_core::http3::{
    CloseError, CloseKind, Connection, Expiry, Layer, QuicError, StreamId, SubmitFailed,
};

/// How the server answers.
#[derive(Clone)]
struct Serve {
    /// The window it gives each stream the client opens.
    stream_window: u64,
    /// Its idle timeout.
    idle: Duration,
    /// The extra fields of each response.
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    /// Each response's body.
    body: Vec<u8>,
    /// It says GOAWAY once HTTP/3 is up.
    goaway: bool,
    /// It closes the connection with this application error once a
    /// response is sent whole.
    close_with: Option<u64>,
    /// Its certificate and key: `cert.pem` and `key.pem`, or
    /// `ku-cert.pem`, whose key may not sign, and `ku-key.pem`.
    cert: (&'static str, &'static str),
    /// How long each datagram it sends takes to arrive: the path's delay.
    delay: Duration,
}

impl Default for Serve {
    fn default() -> Serve {
        Serve {
            stream_window: 1024 * 1024,
            idle: Duration::from_secs(30),
            fields: Vec::new(),
            body: b"hello".to_vec(),
            goaway: false,
            close_with: None,
            cert: ("cert.pem", "key.pem"),
            delay: Duration::ZERO,
        }
    }
}

/// What the server saw of the client.
#[derive(Debug, Default)]
struct Seen {
    /// The client's transport parameters: its connection window, its
    /// windows of the streams it opens, the peer opens and the peer's
    /// one-way ones, the streams the peer may open both ways and one way,
    /// and whether it migrates.
    params: Option<(u64, u64, u64, u64, u64, u64, bool)>,
    /// Each request's stream, and whether it ended with its fields.
    requests: Vec<(u64, bool)>,
    /// The bodies the client sent, whole.
    bodies: Vec<Vec<u8>>,
    /// The most the client let it send on a stream at once.
    room: usize,
    /// How the client closed the connection: as the application or not,
    /// and its code.
    closed_with: Option<(bool, u64)>,
}

/// A server on 127.0.0.1, stopped and joined as this goes.
struct Peer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    seen: Arc<Mutex<Seen>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

impl Peer {
    fn seen(&self) -> std::sync::MutexGuard<'_, Seen> {
        self.seen.lock().unwrap()
    }
}

/// A response being sent: its stream, and what of its body is left.
struct Sending {
    stream: u64,
    at: usize,
}

/// Start a server with the certificate and key in `dir`, answering as
/// `serve` says.
fn peer(dir: &Path, serve: Serve) -> Peer {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    let cert = dir.join(serve.cert.0);
    let key = dir.join(serve.cert.1);
    config
        .load_cert_chain_from_pem_file(cert.to_str().unwrap())
        .unwrap();
    config
        .load_priv_key_from_pem_file(key.to_str().unwrap())
        .unwrap();
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_max_idle_timeout(serve.idle.as_millis() as u64);
    config.set_initial_max_data(64 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(serve.stream_window);
    config.set_initial_max_stream_data_uni(1024 * 1024);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    // A congestion window that is not what holds a body back: the
    // client's flow control is.
    config.set_initial_congestion_window_packets(1000);
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(Mutex::new(Seen::default()));
    let thread = {
        let (stop, seen) = (stop.clone(), seen.clone());
        std::thread::spawn(move || serve_on(sock, config, &serve, &stop, &seen))
    };
    Peer {
        addr,
        stop,
        seen,
        thread: Some(thread),
    }
}

/// The server's loop: one connection, served until the test stops it or
/// the connection closes.
fn serve_on(
    sock: UdpSocket,
    mut config: quiche::Config,
    serve: &Serve,
    stop: &AtomicBool,
    seen: &Mutex<Seen>,
) {
    let local = sock.local_addr().unwrap();
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut conn: Option<quiche::Connection> = None;
    let mut h3: Option<quiche::h3::Connection> = None;
    let mut from = None;
    let mut sending: Vec<Sending> = Vec::new();
    let mut bodies: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut buf = vec![0u8; 65536];
    let mut out = vec![0u8; 1350];
    // What was sent, each datagram with when it arrives.
    let mut path: std::collections::VecDeque<(StdInstant, Vec<u8>)> = Default::default();
    while !stop.load(Ordering::SeqCst) {
        let next = path
            .front()
            .map(|(at, _)| at.saturating_duration_since(StdInstant::now()));
        let wait = conn
            .as_ref()
            .and_then(|c| c.timeout())
            .into_iter()
            .chain(next)
            .min()
            .unwrap_or(Duration::from_millis(20))
            .clamp(Duration::from_millis(1), Duration::from_millis(20));
        sock.set_read_timeout(Some(wait)).unwrap();
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                from = Some(peer);
                if conn.is_none() {
                    let hdr = quiche::Header::from_slice(&mut buf[..n], quiche::MAX_CONN_ID_LEN);
                    let Ok(hdr) = hdr else { continue };
                    if hdr.ty != quiche::Type::Initial {
                        continue;
                    }
                    let scid = quiche::ConnectionId::from_ref(&[7; quiche::MAX_CONN_ID_LEN]);
                    conn = Some(quiche::accept(&scid, None, local, peer, &mut config).unwrap());
                }
                let c = conn.as_mut().unwrap();
                let info = quiche::RecvInfo {
                    from: peer,
                    to: local,
                };
                let _ = c.recv(&mut buf[..n], info);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => panic!("server recv: {e}"),
        }
        let Some(c) = conn.as_mut() else { continue };
        if c.timeout() == Some(Duration::ZERO) {
            c.on_timeout();
        }
        if c.is_established() && h3.is_none() {
            let p = c
                .peer_transport_params()
                .expect("the client's, as it is established");
            seen.lock().unwrap().params = Some((
                p.initial_max_data,
                p.initial_max_stream_data_bidi_local,
                p.initial_max_stream_data_bidi_remote,
                p.initial_max_stream_data_uni,
                p.initial_max_streams_bidi,
                p.initial_max_streams_uni,
                p.disable_active_migration,
            ));
            let mut made = quiche::h3::Connection::with_transport(c, &h3_config).unwrap();
            if serve.goaway {
                made.send_goaway(c, 0).unwrap();
            }
            h3 = Some(made);
        }
        if let Some(h) = h3.as_mut() {
            loop {
                match h.poll(c) {
                    Ok((stream, quiche::h3::Event::Headers { more_frames, .. })) => {
                        seen.lock().unwrap().requests.push((stream, !more_frames));
                        if more_frames {
                            bodies.push((stream, Vec::new()));
                        } else {
                            respond(h, c, serve, stream, &mut sending);
                        }
                    }
                    Ok((stream, quiche::h3::Event::Data)) => {
                        let at = bodies.iter().position(|(s, _)| *s == stream).unwrap();
                        while let Ok(n) = h.recv_body(c, stream, &mut buf) {
                            bodies[at].1.extend_from_slice(&buf[..n]);
                        }
                    }
                    Ok((stream, quiche::h3::Event::Finished)) => {
                        if let Some(at) = bodies.iter().position(|(s, _)| *s == stream) {
                            let (_, body) = bodies.remove(at);
                            seen.lock().unwrap().bodies.push(body);
                            respond(h, c, serve, stream, &mut sending);
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            sending.retain_mut(|s| {
                loop {
                    if let Ok(room) = c.stream_capacity(s.stream) {
                        let mut seen = seen.lock().unwrap();
                        seen.room = seen.room.max(room);
                    }
                    match h.send_body(c, s.stream, &serve.body[s.at..], true) {
                        Ok(n) if s.at + n == serve.body.len() => {
                            if let Some(code) = serve.close_with {
                                c.close(true, code, b"bye").unwrap();
                            }
                            return false;
                        }
                        Ok(0) | Err(_) => return true,
                        Ok(n) => s.at += n,
                    }
                }
            });
        }
        if let Some(to) = from {
            while let Ok((n, _)) = c.send(&mut out) {
                path.push_back((StdInstant::now() + serve.delay, out[..n].to_vec()));
            }
            while path.front().is_some_and(|(at, _)| *at <= StdInstant::now()) {
                let (_, datagram) = path.pop_front().unwrap();
                sock.send_to(&datagram, to).unwrap();
            }
        }
        if c.is_closed() {
            let mut seen = seen.lock().unwrap();
            seen.closed_with = c.peer_error().map(|e| (e.is_app, e.error_code));
            break;
        }
    }
}

/// The response to the request on `stream`: its fields at once, its body
/// as the client lets it go.
fn respond(
    h: &mut quiche::h3::Connection,
    c: &mut quiche::Connection,
    serve: &Serve,
    stream: u64,
    sending: &mut Vec<Sending>,
) {
    let mut fields = vec![
        quiche::h3::Header::new(b":status", b"200"),
        quiche::h3::Header::new(b"content-length", serve.body.len().to_string().as_bytes()),
    ];
    fields.extend(
        serve
            .fields
            .iter()
            .map(|(n, v)| quiche::h3::Header::new(n, v)),
    );
    h.send_response(c, stream, &fields, false).unwrap();
    sending.push(Sending { stream, at: 0 });
}

/// The server answering as `serve` says, and a connection to it, its
/// handshake done, the peer checked: what `f` returns, and the notes.
fn connected<R>(
    test: &str,
    serve: Serve,
    f: impl FnOnce(
        &mut dyn Connection,
        &mut curl_core::tls::TlsCx<'_>,
        &common::Over<'_>,
        &Peer,
        &mut Told,
    ) -> R,
) -> (R, Vec<String>) {
    let dir = Dir::new(test);
    certs(&dir.0);
    let server = peer(&dir.0, serve);
    with_client(&dir.0, "ca.pem", server.addr, |conn, cx, over, _| {
        let mut told = Told::default();
        run(conn, cx, over, &mut told, |t| t.checked.is_some()).unwrap();
        assert_eq!(told.checked, Some(Ok(())));
        f(conn, cx, over, &server, &mut told)
    })
}

/// A GET of `/`, answered.
fn get(
    conn: &mut dyn Connection,
    cx: &mut curl_core::tls::TlsCx<'_>,
    over: &common::Over<'_>,
    addr: SocketAddr,
    told: &mut Told,
) -> StreamId {
    let fields = request("GET", "/", addr);
    let stream = conn.submit_request(&refs(&fields), false).unwrap();
    run(conn, cx, over, told, |t| t.closed_streams.contains(&stream)).unwrap();
    stream
}

/// The client asks for C's windows and streams (`cf_quiche_ctx_open`):
/// 1 MiB for the connection, 128 KiB for each stream, 100 streams each
/// way, no migration. What the core weighs of the connection is what C's
/// filter weighs: packets as large as quiche sends, ten of them at a
/// time, a timer quiche keeps, no idle timeout of the peer's to keep the
/// connection alive by, room to send, and no failed call closing it.
#[test]
fn the_client_asks_for_c_s_windows_and_weighs_what_c_weighs() {
    let ((), notes) = connected(
        "params",
        Serve::default(),
        |conn, cx, over, server, told| {
            get(conn, cx, over, server.addr, told);
            assert_eq!(told.body, b"hello");
            let kib = 1024;
            assert_eq!(
                server.seen().params,
                Some((1024 * kib, 128 * kib, 128 * kib, 128 * kib, 100, 100, true))
            );
            // quiche's own, for a peer that allows more.
            assert_eq!(conn.max_payload(), 1200);
            assert_eq!(conn.path_max_payload(), 1200);
            assert_eq!(conn.send_quantum(), 10 * 1200);
            assert!(
                matches!(conn.expiry(over.clock.now()), Expiry::In(d) if !d.is_zero()),
                "quiche's idle timer"
            );
            assert_eq!(conn.peer_idle_timeout(), None);
            assert!(conn.send_room());
            let error = QuicError {
                layer: Layer::Quic,
                call: "test",
                code: -1,
                text: "",
            };
            assert!(!conn.failed(error));
            assert!(!conn.draining());
            assert_eq!(conn.closed_with(), None);
        },
    );
    // Each datagram is read whole.
    assert!(
        !notes.iter().any(|n| n.contains("quiche only read")),
        "{notes:#?}"
    );
}

/// The windows grow past their first size as a large body comes in over
/// a path of some delay, as far as C's ceilings let quiche grow them
/// (`quiche_config_set_max_connection_window`,
/// `quiche_config_set_max_stream_window`): the server is let send more
/// than a stream's first window at once, and the body arrives whole.
#[test]
fn the_windows_grow_as_a_large_body_comes() {
    let body: Vec<u8> = (0..8_000_000u32).map(|i| (i % 251) as u8).collect();
    let serve = Serve {
        body: body.clone(),
        delay: Duration::from_millis(50),
        ..Serve::default()
    };
    let ((), _) = connected("windows", serve, |conn, cx, over, server, told| {
        get(conn, cx, over, server.addr, told);
        assert!(told.body == body, "{} bytes", told.body.len());
        let room = server.seen().room;
        assert!(room > 136 * 1024, "{room}");
    });
}

/// What a datagram brought is told whole as it is read: a small response
/// sent at once, its head, body and end, all by the ingress that read it
/// (`cf_poll_events`, polling until quiche has no more).
#[test]
fn a_response_read_at_once_is_told_at_once() {
    let ((), _) = connected(
        "at-once",
        Serve::default(),
        |conn, cx, over, server, told| {
            let fields = request("GET", "/", server.addr);
            let stream = conn.submit_request(&refs(&fields), false).unwrap();
            run(conn, cx, over, told, |t| t.head_done).unwrap();
            assert_eq!(told.body, b"hello");
            assert_eq!(told.closed_streams, [stream]);
        },
    );
}

/// A request's fields end its stream unless a body follows
/// (`quiche_h3_send_request`'s `fin`).
#[test]
fn a_get_ends_its_stream_with_its_fields() {
    let ((), _) = connected("fin", Serve::default(), |conn, cx, over, server, told| {
        let stream = get(conn, cx, over, server.addr, told);
        let id = u64::try_from(stream.0).unwrap();
        assert_eq!(server.seen().requests, [(id, true)]);
    });
}

/// An upload the server's window holds back is taken as far as quiche
/// lets it, each time quiche takes nothing the stream told it may send
/// again once packets come (`cf_quiche_do_resume`), and its end offered
/// until taken: the server has it whole. quiche holds what it took, so
/// none is in flight or buffered of the connection's own.
#[test]
fn an_upload_held_back_goes_on_as_packets_come() {
    let serve = Serve {
        stream_window: 4096,
        ..Serve::default()
    };
    let upload: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
    let ((), _) = connected("upload", serve, |conn, cx, over, server, told| {
        let fields = request("POST", "/", server.addr);
        let stream = conn.submit_request(&refs(&fields), true).unwrap();
        let deadline = StdInstant::now() + Duration::from_secs(10);
        let (mut sent, mut held) = (0, 0);
        while sent < upload.len() {
            assert!(StdInstant::now() < deadline, "the upload takes too long");
            let n = conn.write_body(stream, &upload[sent..]).unwrap();
            assert_eq!(conn.body_in_flight(stream), 0);
            assert_eq!(conn.body_buffered(stream), 0);
            sent += n;
            if n > 0 {
                // Told to go on only after it took nothing: not as what
                // it took is acknowledged.
                flush(conn, cx, over, told).unwrap();
                take_one(conn, cx, over, told).unwrap();
                assert_eq!(told.unblocked.len(), held, "{:?}", told.unblocked);
                continue;
            }
            held += 1;
            run(conn, cx, over, told, |t| t.unblocked.len() == held).unwrap();
            assert_eq!(told.unblocked.last(), Some(&stream));
        }
        assert!(held > 0, "the window held the upload back");
        conn.end_body(stream);
        run(conn, cx, over, told, |t| t.closed_streams.contains(&stream)).unwrap();
        assert!(server.seen().bodies == [upload.clone()], "the body whole");
    });
}

/// Fields with a CR, LF or NUL in their value, or in a name but the
/// status's, are not handed on, each said with its size
/// (`is_valid_h3_header`).
#[test]
fn a_field_curl_refuses_is_said_and_left_out() {
    let serve = Serve {
        fields: vec![
            (b"x-bad-value".to_vec(), b"a\rb".to_vec()),
            (b"x-bad\0name".to_vec(), b"v".to_vec()),
            (b"x-good".to_vec(), b"yes".to_vec()),
        ],
        ..Serve::default()
    };
    let (headers, notes) = connected("fields", serve, |conn, cx, over, server, told| {
        get(conn, cx, over, server.addr, told);
        std::mem::take(&mut told.headers)
    });
    let names: Vec<&[u8]> = headers.iter().map(|(n, _)| &n[..]).collect();
    assert_eq!(names, [&b"content-length"[..], b"x-good"], "{headers:?}");
    let ignored: Vec<_> = notes
        .iter()
        .filter(|n| n.contains("bad header"))
        .map(|n| n.trim_start_matches("trace: "))
        .collect();
    assert_eq!(
        ignored,
        [
            "[0] ignore 14 bytes bad header",
            "[0] ignore 11 bytes bad header"
        ],
        "{notes:#?}"
    );
}

/// Once the peer said GOAWAY, it allows no more streams, and a request
/// is refused with no stream of its own (`quiche_h3_send_request`).
#[test]
fn after_goaway_a_request_is_refused() {
    let serve = Serve {
        goaway: true,
        ..Serve::default()
    };
    let ((), _) = connected("goaway", serve, |conn, cx, over, _, told| {
        run(conn, cx, over, told, |t| t.max_streams.last() == Some(&0)).unwrap();
        let fields = request("GET", "/", "127.0.0.1:443".parse().unwrap());
        match conn.submit_request(&refs(&fields), false) {
            Err(SubmitFailed::Refused { stream, .. }) => assert_eq!(stream, StreamId(-1)),
            Err(_) => panic!("refused otherwise"),
            Ok(stream) => panic!("opened {stream:?}"),
        }
    });
}

/// A connection the server closes drains, then closes as quiche's timer
/// says: the call that runs it fails, every transfer on it with it, and
/// the server's error is what it was closed with.
#[test]
fn a_connection_the_server_closes_drains_then_fails() {
    let serve = Serve {
        close_with: Some(0x10c),
        ..Serve::default()
    };
    let (failed, notes) = connected("closed", serve, |conn, cx, over, server, told| {
        let fields = request("GET", "/", server.addr);
        conn.submit_request(&refs(&fields), false).unwrap();
        let deadline = StdInstant::now() + Duration::from_secs(10);
        while !conn.draining() {
            assert!(StdInstant::now() < deadline, "the close takes too long");
            flush(conn, cx, over, told).unwrap();
            take_one(conn, cx, over, told).unwrap();
        }
        assert_eq!(conn.closed_with(), None, "draining, not closed");
        expire(conn, cx, over, told)
    });
    assert_eq!(failed.0.call, "quiche_conn_on_timeout");
    assert_eq!(failed.0.text, "connection closed by server");
    assert_eq!(
        failed.1,
        Some(CloseError {
            kind: CloseKind::Application,
            code: 0x10c
        })
    );
    assert!(
        notes
            .iter()
            .any(|n| n == "trace: conn closed, expire all transfers"),
        "{notes:#?}"
    );
}

/// Wait for the connection's timers, run each as it is due, until one
/// fails the connection: how, and what it was closed with.
fn expire(
    conn: &mut dyn Connection,
    cx: &mut curl_core::tls::TlsCx<'_>,
    over: &common::Over<'_>,
    told: &mut Told,
) -> (QuicError, Option<CloseError>) {
    let deadline = StdInstant::now() + Duration::from_secs(10);
    loop {
        assert!(StdInstant::now() < deadline, "no timer closes it");
        match conn.expiry(over.clock.now()) {
            Expiry::Due => {}
            Expiry::In(d) => std::thread::sleep(d.min(Duration::from_millis(50))),
            Expiry::Never => panic!("no timer is kept"),
        }
        if conn.expiry(over.clock.now()) == Expiry::Due
            && let Err(e) = conn.handle_expiry(cx, over.clock.now(), &mut |_, e| told.hear(e))
        {
            return (e, conn.closed_with());
        }
    }
}

/// A connection left idle past the idle timeout the two agree on closes
/// as quiche's timer runs out: the call fails, said so.
#[test]
fn an_idle_connection_closes_at_its_timeout() {
    let serve = Serve {
        idle: Duration::from_millis(300),
        ..Serve::default()
    };
    let (failed, _) = connected("idle", serve, |conn, cx, over, server, told| {
        get(conn, cx, over, server.addr, told);
        flush(conn, cx, over, told).unwrap();
        expire(conn, cx, over, told)
    });
    assert_eq!(failed.0.text, "connection closed by idle timeout");
    assert_eq!(
        failed.1,
        Some(CloseError {
            kind: CloseKind::IdleClose,
            code: 0
        })
    );
}

/// The connection closed as the application, with no error
/// (`cf_quiche_shutdown`): the packet saying so is written whole, and the
/// server reads that close; with no room, none is written.
#[test]
fn a_close_written_reaches_the_server() {
    let ((), _) = connected("close", Serve::default(), |conn, _, over, server, _| {
        assert_eq!(conn.write_close(over.clock.now(), &mut []), Ok(0));
        let mut buf = [0u8; 1500];
        let n = conn.write_close(over.clock.now(), &mut buf).unwrap();
        assert!(n > 20, "{n} bytes");
        over.sock.send(&buf[..n]).unwrap();
        let deadline = StdInstant::now() + Duration::from_secs(10);
        while server.seen().closed_with.is_none() {
            assert!(StdInstant::now() < deadline, "the server never reads it");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(server.seen().closed_with, Some((true, 0)));
    });
}

/// A handshake whose TLS fails is said by the chain's check, as quiche's
/// filter asks the TLS library for its verdict first
/// (`cf_quiche_recv_pkts`, `SSL_get_verify_result`): a certificate whose
/// key may not sign fails before the chain is checked, which BoringSSL
/// reports as a check never made, however good the chain.
#[test]
fn a_failed_handshake_says_the_chain_s_check() {
    let dir = Dir::new("tlsfail");
    certs(&dir.0);
    let serve = Serve {
        cert: ("ku-cert.pem", "ku-key.pem"),
        ..Serve::default()
    };
    let server = peer(&dir.0, serve);
    let (failed, notes) = with_client(&dir.0, "ca.pem", server.addr, |conn, cx, over, _| {
        let mut told = Told::default();
        run(conn, cx, over, &mut told, |_| false).unwrap_err()
    });
    assert_eq!(
        (failed.layer, failed.call, failed.code),
        (Layer::Crypto, "quiche_conn_recv", -10),
        "{notes:#?}"
    );
    let said = "fail: PeerFailedVerification: SSL certificate problem: \
                Invalid certificate verification context";
    assert!(notes.iter().any(|n| n == said), "{notes:#?}");
}
