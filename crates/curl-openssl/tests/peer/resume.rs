//! Sessions resumed (`ossl_new_session_cb`, `ossl_apply_session`): what a
//! peer gives as its handshake ends, or after it for TLS 1.3, is kept in
//! the multi's cache and resumed by the next connection to the peer; and
//! the key log (`SSLKEYLOGFILE`).

use curl_core::tls::KeyLog;
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
static LOGGING: curl_openssl::OpenSsl = curl_openssl::OpenSsl::logging_keys_to(&KEYLOG);
static LOGGING_LIBRARIES: Libraries = Libraries {
    tls: Some(&LOGGING),
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
        easy.set_libraries(&LOGGING_LIBRARIES);
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
