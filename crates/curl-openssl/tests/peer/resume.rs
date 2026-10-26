//! Sessions resumed (`ossl_new_session_cb`, `ossl_apply_session`): what a
//! peer gives as its handshake ends, or after it for TLS 1.3, is kept in
//! the multi's cache and resumed by the next connection to the peer; and
//! the key log (`SSLKEYLOGFILE`).

use curl_core::tls::{KeyLog, SharedKeyLog};
use openssl::ssl::{SslAcceptor, SslVersion};

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "the_next_connection_resumes_a_tls_1_3_ticket",
        the_next_connection_resumes_a_tls_1_3_ticket,
    ),
    (
        "the_next_connection_resumes_a_tls_1_2_session",
        the_next_connection_resumes_a_tls_1_2_session,
    ),
    (
        "a_transfer_keeping_no_session_resumes_none",
        a_transfer_keeping_no_session_resumes_none,
    ),
    (
        "a_failed_check_forgets_the_peer_s_sessions",
        a_failed_check_forgets_the_peer_s_sessions,
    ),
    (
        "the_key_log_has_each_connection_s_secrets",
        the_key_log_has_each_connection_s_secrets,
    ),
    (
        "a_session_keeps_its_key_log_past_its_owner",
        a_session_keeps_its_key_log_past_its_owner,
    ),
    (
        "a_resumed_session_sends_the_request_as_early_data",
        a_resumed_session_sends_the_request_as_early_data,
    ),
    (
        "early_data_a_server_refuses_is_sent_again",
        early_data_a_server_refuses_is_sent_again,
    ),
];

/// A server's TLS, as `serve_configured` makes it.
fn acceptor(certs: &Certs, configure: impl FnOnce(&mut SslAcceptorBuilder)) -> SslAcceptor {
    let mut a = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    a.set_private_key(&certs.key).unwrap();
    a.set_certificate(&certs.cert).unwrap();
    configure(&mut a);
    a.build()
}

/// A server answering one GET on each of its connections, the `n`th
/// accepted with the `n`th of `acceptors`: one that is the same resumes
/// the sessions it gave. A handshake that fails ends that connection.
fn serve_each(acceptors: Vec<SslAcceptor>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for acceptor in acceptors {
            let (tcp, _) = listener.accept().unwrap();
            let Ok(mut tls) = acceptor.accept(tcp) else {
                continue;
            };
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", BODY.len());
            let _ = tls.write_all(head.as_bytes());
            let _ = tls.write_all(BODY);
            let _ = tls.shutdown();
        }
    });
    (at, server)
}

/// A server's TLS taking `most` bytes of early data and agreeing to
/// HTTP/1.1 by ALPN, so that its tickets allow early data.
fn early_acceptor(certs: &Certs, most: u32) -> SslAcceptor {
    acceptor(certs, |a| {
        a.set_max_early_data(most).unwrap();
        a.set_alpn_select_callback(|_, offer| {
            openssl::ssl::select_next_proto(b"\x08http/1.1", offer)
                .ok_or(openssl::ssl::AlpnError::NOACK)
        });
    })
}

/// As `serve_each`, each connection's early data read first: what each
/// was sent early, and after its handshake.
type EarlySeen = Vec<(Vec<u8>, Vec<u8>)>;
type EarlyServer = JoinHandle<EarlySeen>;

fn serve_early(acceptors: Vec<SslAcceptor>) -> (SocketAddr, EarlyServer) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for acceptor in acceptors {
            let (tcp, _) = listener.accept().unwrap();
            let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut tls = openssl::ssl::SslStream::new(ssl, tcp).unwrap();
            let mut early = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match tls.read_early_data(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => early.extend_from_slice(&buf[..n]),
                    Err(e) => panic!("the server's early read: {e}"),
                }
            }
            tls.accept().unwrap();
            let mut late = Vec::new();
            while ![&early[..], &late[..]]
                .concat()
                .windows(4)
                .any(|w| w == b"\r\n\r\n")
            {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => late.extend_from_slice(&buf[..n]),
                }
            }
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", BODY.len());
            let _ = tls.write_all(head.as_bytes());
            let _ = tls.write_all(BODY);
            let _ = tls.shutdown();
            seen.push((early, late));
        }
        seen
    });
    (at, server)
}

/// Two GETs asking for early data, on connections of their own, the
/// second to a server made by `second`: the server's, and the GETs'.
fn early_pair(second: impl FnOnce(&SslAcceptor, &Certs) -> SslAcceptor) -> (EarlySeen, Got, Got) {
    let certs = certs("early", "localhost", &["localhost"]);
    let a = early_acceptor(&certs, 16384);
    let b = second(&a, &certs);
    let (at, server) = serve_early(vec![a, b]);
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let set = |o: &mut Options| {
        trusting(&certs)(o);
        o.limits.reuse.fresh = true;
        o.tls.options.make_mut().unwrap().ssl_options = SslOptions::EARLYDATA;
    };
    let one = get_in(&mut m, "https", "localhost", at, set, false);
    let two = get_in(&mut m, "https", "localhost", at, set, false);
    let seen = server.join().unwrap();
    assert_eq!(one.result, Ok(()), "{:#?}", one.seen.lines);
    assert_eq!(two.result, Ok(()), "{:#?}", two.seen.lines);
    assert_eq!(two.seen.body, BODY);
    assert_eq!(one.early, 0, "the first resumes nothing");
    (seen, one, two)
}

/// A session that allows early data, resumed, has the handshake put off
/// until the request, which goes in it; the server taking it, it is not
/// sent again (`ossl_send_earlydata`, `ssl_cf_connect_deferred`).
fn a_resumed_session_sends_the_request_as_early_data() {
    let (seen, _, two) = early_pair(|a, _| a.clone());
    let (early, late) = &seen[1];
    let n = early.len();
    assert!(early.starts_with(b"GET / HTTP/1.1\r\n"), "{early:?}");
    assert!(late.is_empty(), "{late:?}");
    assert_eq!(two.early, n as i64);
    for line in [
        "SSL session allows 16384 bytes of early data, reusing ALPN 'http/1.1'".to_owned(),
        "ALPN: deferred handshake for early data using 'http/1.1'.".to_owned(),
        format!("SSL sending {n} bytes of early data"),
        "ALPN: server confirmed to use 'http/1.1'".to_owned(),
        format!("Server accepted {n} bytes of TLS early data."),
    ] {
        assert!(said(&two, &line), "no {line:?} in {:#?}", two.seen.lines);
    }
    assert!(
        !two.seen
            .lines
            .iter()
            .any(|l| l.starts_with("ALPN: curl offers"))
    );
}

/// A server that cannot resume the session refuses the early data: the
/// request goes again after the handshake.
fn early_data_a_server_refuses_is_sent_again() {
    let (seen, _, two) = early_pair(|_, certs| early_acceptor(certs, 16384));
    let (early, late) = &seen[1];
    assert!(early.is_empty(), "{early:?}");
    assert!(late.starts_with(b"GET / HTTP/1.1\r\n"), "{late:?}");
    assert!(two.early < 0, "{}", two.early);
    assert!(
        said(&two, "Server rejected TLS early data."),
        "{:#?}",
        two.seen.lines
    );
}

fn resumed(got: &Got) -> bool {
    starts(got, "SSL reusing session with ALPN")
}

/// Two GETs in one multi, each on its own connection: the second resumes
/// a ticket the first was given after its handshake, says so, and
/// reports no chain, as a resumed session's is not sent.
fn the_next_connection_resumes_a_tls_1_3_ticket() {
    let certs = certs("resume13", "localhost", &["localhost"]);
    let a = acceptor(&certs, |_| {});
    let (at, server) = serve_each(vec![a.clone(), a]);
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let set = |o: &mut Options| {
        trusting(&certs)(o);
        o.tls.certinfo = true;
    };
    let one = get_in(&mut m, "https", "localhost", at, set, false);
    let two = get_in(&mut m, "https", "localhost", at, set, false);
    server.join().unwrap();
    assert_eq!(one.result, Ok(()), "{:#?}", one.seen.lines);
    assert_eq!(two.result, Ok(()), "{:#?}", two.seen.lines);
    assert!(!resumed(&one), "{:#?}", one.seen.lines);
    assert!(one.chain.is_some(), "the first reports its chain");
    for line in [
        "SSL reusing session with ALPN '-'",
        "SSL verify result: 0",
        "SSL certificate verified via OpenSSL.",
    ] {
        assert!(said(&two, line), "no {line:?} in {:#?}", two.seen.lines);
    }
    assert!(
        two.seen
            .lines
            .iter()
            .any(|l| l.starts_with("SSL connection using TLSv1.3 / ")),
        "{:#?}",
        two.seen.lines
    );
    assert!(two.chain.is_none(), "a resumed session's chain is not sent");
}

/// Before TLS 1.3, the session of the handshake, by its id, is resumed
/// and given back to the cache for the next.
fn the_next_connection_resumes_a_tls_1_2_session() {
    let certs = certs("resume12", "localhost", &["localhost"]);
    let a = acceptor(&certs, |a| {
        a.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    });
    let (at, server) = serve_each(vec![a.clone(), a.clone(), a]);
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let gets: Vec<Got> = (0..3)
        .map(|_| get_in(&mut m, "https", "localhost", at, trusting(&certs), false))
        .collect();
    server.join().unwrap();
    for (i, got) in gets.iter().enumerate() {
        assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
        assert!(
            got.seen
                .lines
                .iter()
                .any(|l| l.starts_with("SSL connection using TLSv1.2 / ")),
            "{:#?}",
            got.seen.lines
        );
        assert_eq!(resumed(got), i > 0, "{i}: {:#?}", got.seen.lines);
    }
}

/// `CURLOPT_SSL_SESSIONID_CACHE` off: a transfer neither keeps a session
/// nor resumes one.
fn a_transfer_keeping_no_session_resumes_none() {
    let certs = certs("nosessionid", "localhost", &["localhost"]);
    let a = acceptor(&certs, |_| {});
    let (at, server) = serve_each(vec![a.clone(), a.clone(), a]);
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let off = |o: &mut Options| {
        trusting(&certs)(o);
        o.tls.options.make_mut().unwrap().session_cache = false;
    };
    let one = get_in(&mut m, "https", "localhost", at, off, false);
    let two = get_in(&mut m, "https", "localhost", at, trusting(&certs), false);
    let three = get_in(&mut m, "https", "localhost", at, off, false);
    server.join().unwrap();
    for got in [&one, &two, &three] {
        assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    }
    assert!(!resumed(&two), "the first kept none: {:#?}", two.seen.lines);
    assert!(
        !resumed(&three),
        "the third takes none: {:#?}",
        three.seen.lines
    );
}

/// A connection whose peer fails its check forgets the sessions kept for
/// the peer: the next connection, to a server that would resume them,
/// resumes none.
fn a_failed_check_forgets_the_peer_s_sessions() {
    let certs = certs("forget", "localhost", &["localhost"]);
    let wrong = self::certs("forget-wrong", "elsewhere", &["elsewhere.example"]);
    let good = acceptor(&certs, |_| {});
    // Another server's TLS, which resumes none of the first's.
    let bad = acceptor(&wrong, |_| {});
    let (at, server) = serve_each(vec![good.clone(), bad, good]);
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let one = get_in(&mut m, "https", "localhost", at, trusting(&certs), false);
    let two = get_in(&mut m, "https", "localhost", at, trusting(&certs), false);
    let three = get_in(&mut m, "https", "localhost", at, trusting(&certs), false);
    server.join().unwrap();
    assert_eq!(one.result, Ok(()), "{:#?}", one.seen.lines);
    assert_eq!(two.result, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(three.result, Ok(()), "{:#?}", three.seen.lines);
    assert!(!resumed(&three), "{:#?}", three.seen.lines);
}

/// The key log the tests' OpenSSL logs to.
static KEYLOG: KeyLog = KeyLog::new();
static LOGGING: curl_openssl::OpenSsl =
    curl_openssl::OpenSsl::logging_keys_to(curl_core::tls::SharedKeyLog::of_static(&KEYLOG));
static LOGGING_LIBRARIES: Libraries = Libraries {
    tls: Some(Library::Static(&LOGGING)),
    ..Libraries::NONE
};

/// With the key log opened to a file, as `SSLKEYLOGFILE` names one, each
/// connection's secrets are appended to it in the NSS format, five for
/// TLS 1.3 and the master secret before it, and its handshake says where
/// they go.
fn the_key_log_has_each_connection_s_secrets() {
    let path = certs_dir().join("keys.log");
    std::fs::create_dir_all(certs_dir()).unwrap();
    std::fs::write(&path, b"").unwrap();
    KEYLOG.open_named(path.to_str().unwrap().as_bytes());
    assert!(KEYLOG.enabled());
    let certs = certs("keylog", "localhost", &["localhost"]);
    let tls12 = acceptor(&certs, |a| {
        a.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    });
    let (at, server) = serve_each(vec![acceptor(&certs, |_| {}), tls12]);
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let mut gets = Vec::new();
    for _ in 0..2 {
        let seen = track::untracked(|| Arc::new(Mutex::new(Seen::default())));
        let mut easy = Easy::new();
        easy.set_libraries(SharedLibraries::of_static(&LOGGING_LIBRARIES));
        let o = easy.options_mut();
        let url = track::untracked(|| format!("https://localhost:{}/", at.port()));
        o.set_url(Some(url.as_bytes())).unwrap();
        o.ip_version = IpVersion::V4;
        o.output.verbose = true;
        o.callbacks.debug = Some(Handler::debug(Taker(seen.clone())).unwrap());
        o.callbacks.write = Some(Handler::write(Taker(seen.clone())).unwrap());
        trusting(&certs)(o);
        // The second's server knows only TLS 1.2: a session of the first
        // is not resumed by it, and the first's is not offered.
        o.tls.options.make_mut().unwrap().session_cache = false;
        let id = m.add(try_box(easy).unwrap(), (), &mut NoEvents).unwrap();
        let result = curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        m.remove(id, &mut NoEvents).unwrap();
        assert_eq!(result, Ok(()));
        gets.push(track::untracked(|| {
            std::mem::take(&mut *seen.lock().unwrap())
        }));
    }
    server.join().unwrap();
    KEYLOG.close();
    let said = format!(
        "SSLKEYLOGFILE set, all TLS secrets are logged to '{}'",
        path.display()
    );
    for seen in &gets {
        assert!(seen.lines.contains(&said), "{:#?}", seen.lines);
    }
    let log = std::fs::read_to_string(&path).unwrap();
    let labels: Vec<&str> = log.lines().map(|l| l.split(' ').next().unwrap()).collect();
    let mut first: Vec<&str> = labels[..5].to_vec();
    first.sort_unstable();
    assert_eq!(
        first,
        [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_TRAFFIC_SECRET_0",
        ],
        "{log}"
    );
    assert_eq!(&labels[5..], ["CLIENT_RANDOM"], "{log}");
    for line in log.lines() {
        let parts: Vec<&str> = line.split(' ').collect();
        assert_eq!(parts.len(), 3, "{line}");
        assert_eq!(parts[1].len(), 64, "the client random: {line}");
        assert!(
            parts[1..]
                .iter()
                .all(|p| p.bytes().all(|b| b.is_ascii_hexdigit()))
        );
    }
}

/// A key log of the tool's kind, owned and shared rather than static,
/// lasts while a session holds it: with the log's maker, the libraries
/// naming it and the handle's hold on them all gone mid-handshake, the
/// session still writes the connection's secrets to the file.
fn a_session_keeps_its_key_log_past_its_owner() {
    let path = certs_dir().join("keys-owned.log");
    std::fs::create_dir_all(certs_dir()).unwrap();
    std::fs::write(&path, b"").unwrap();
    let certs = certs("keylog-owned", "localhost", &["localhost"]);
    let (at, server) = serve_each(vec![acceptor(&certs, |_| {})]);
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let seen = track::untracked(|| Arc::new(Mutex::new(Seen::default())));
    let mut easy = Easy::new();
    {
        let log = SharedKeyLog::new().unwrap();
        log.open_named(path.to_str().unwrap().as_bytes());
        let tls = try_box(curl_openssl::OpenSsl::logging_keys_to(log.clone())).unwrap();
        easy.set_libraries(
            SharedLibraries::new(Libraries {
                tls: Some(Library::Owned(tls)),
                ..Libraries::NONE
            })
            .unwrap(),
        );
    }
    let o = easy.options_mut();
    let url = track::untracked(|| format!("https://localhost:{}/", at.port()));
    o.set_url(Some(url.as_bytes())).unwrap();
    o.ip_version = IpVersion::V4;
    o.output.verbose = true;
    o.callbacks.debug = Some(Handler::debug(Taker(seen.clone())).unwrap());
    o.callbacks.write = Some(Handler::write(Taker(seen.clone())).unwrap());
    trusting(&certs)(o);
    let id = m.add(try_box(easy).unwrap(), (), &mut NoEvents).unwrap();
    // Until the client hello is sent: the session exists, the handshake
    // is not done.
    let hello = |seen: &Seen| seen.lines.iter().any(|l| l.contains("Client hello"));
    while !track::untracked(|| hello(&seen.lock().unwrap())) {
        m.perform(&mut NoEvents).unwrap();
        assert!(m.info_read().is_none(), "{:#?}", seen.lock().unwrap().lines);
    }
    m.easy_mut(id)
        .unwrap()
        .set_libraries(SharedLibraries::default());
    let result = curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    m.remove(id, &mut NoEvents).unwrap();
    server.join().unwrap();
    assert_eq!(result, Ok(()));
    let said = format!(
        "SSLKEYLOGFILE set, all TLS secrets are logged to '{}'",
        path.display()
    );
    let lines = track::untracked(|| std::mem::take(&mut seen.lock().unwrap().lines));
    assert!(lines.contains(&said), "{lines:#?}");
    let log = std::fs::read_to_string(&path).unwrap();
    assert_eq!(log.lines().count(), 5, "TLS 1.3's five secrets: {log}");
}
