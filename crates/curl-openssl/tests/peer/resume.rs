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
    // The forks' servers here take no early data, and C's build over them
    // sends none (`HAVE_OPENSSL_EARLYDATA` unset).
    #[cfg(not(boringssl_like))]
    (
        "a_resumed_session_sends_the_request_as_early_data",
        a_resumed_session_sends_the_request_as_early_data,
    ),
    #[cfg(not(boringssl_like))]
    (
        "early_data_a_server_refuses_is_sent_again",
        early_data_a_server_refuses_is_sent_again,
    ),
    #[cfg(all(target_os = "macos", feature = "apple-sectrust"))]
    (
        "a_session_sectrust_verified_resumes_and_is_kept_so",
        a_session_sectrust_verified_resumes_and_is_kept_so,
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
    serve_each_after(acceptors, None)
}

/// As `serve_each`, the first connection's handshake held until `gate`
/// is sent to (or dropped): the client's hello waits in the socket
/// meanwhile, however the client's tries are scheduled.
fn serve_each_after(
    acceptors: Vec<SslAcceptor>,
    gate: Option<std::sync::mpsc::Receiver<()>>,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut first = true;
        for acceptor in acceptors {
            let (tcp, _) = curl_core::test_server::accept(&listener);
            if let Some(gate) = gate.as_ref().filter(|_| first) {
                let _ = gate.recv_timeout(std::time::Duration::from_secs(30));
            }
            first = false;
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
#[cfg(not(boringssl_like))]
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
#[cfg(not(boringssl_like))]
type EarlySeen = Vec<(Vec<u8>, Vec<u8>)>;
#[cfg(not(boringssl_like))]
type EarlyServer = JoinHandle<EarlySeen>;

#[cfg(not(boringssl_like))]
fn serve_early(acceptors: Vec<SslAcceptor>) -> (SocketAddr, EarlyServer) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for acceptor in acceptors {
            let (tcp, _) = curl_core::test_server::accept(&listener);
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
#[cfg(not(boringssl_like))]
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

/// LibreSSL keeps no TLS 1.3 session and sends no early data, nor does
/// C's build over it: the second request goes after its handshake.
#[cfg(libressl)]
fn no_early_data(seen: &EarlySeen, two: &Got) {
    let (early, late) = &seen[1];
    assert!(early.is_empty(), "{early:?}");
    assert!(late.starts_with(b"GET / HTTP/1.1\r\n"), "{late:?}");
    assert_eq!(two.early, 0);
    for line in [
        "SSL session allows",
        "SSL sending",
        "Server accepted",
        "Server rejected",
    ] {
        assert!(!starts(two, line), "{line:?} in {:#?}", two.seen.lines);
    }
}

#[cfg(libressl)]
fn a_resumed_session_sends_the_request_as_early_data() {
    let (seen, _, two) = early_pair(|a, _| a.clone());
    no_early_data(&seen, &two);
}

#[cfg(libressl)]
fn early_data_a_server_refuses_is_sent_again() {
    let (seen, _, two) = early_pair(|_, certs| early_acceptor(certs, 16384));
    no_early_data(&seen, &two);
}

/// A session that allows early data, resumed, has the handshake put off
/// until the request, which goes in it; the server taking it, it is not
/// sent again (`ossl_send_earlydata`, `ssl_cf_connect_deferred`).
#[cfg(not(any(libressl, boringssl_like)))]
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
#[cfg(not(any(libressl, boringssl_like)))]
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
    // LibreSSL's server gives no TLS 1.3 ticket, and its client keeps no
    // session without one: the second makes a handshake of its own, as
    // C's build over it does against the same server.
    #[cfg(libressl)]
    {
        assert!(!resumed(&two), "{:#?}", two.seen.lines);
        assert!(two.chain.is_some(), "the second reports its chain");
    }
    #[cfg(not(libressl))]
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
    #[cfg(not(libressl))]
    assert!(two.chain.is_none(), "a resumed session's chain is not sent");
}

/// Before TLS 1.3, the session of the handshake, by its id, is resumed
/// and given back to the cache for the next. The library gives it inside
/// the handshake, before the protocol ALPN chose is recorded: it is kept
/// with none, as C keeps it, though the server agreed to HTTP/1.1.
fn the_next_connection_resumes_a_tls_1_2_session() {
    let certs = certs("resume12", "localhost", &["localhost"]);
    let a = acceptor(&certs, |a| {
        a.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
        a.set_alpn_select_callback(|_, offer| {
            openssl::ssl::select_next_proto(b"\x08http/1.1", offer)
                .ok_or(openssl::ssl::AlpnError::NOACK)
        });
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
        assert!(said(got, "ALPN: server accepted http/1.1"), "{i}");
        if i > 0 {
            assert!(
                said(got, "SSL reusing session with ALPN '-'"),
                "{i}: {:#?}",
                got.seen.lines
            );
        }
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

/// A session whose peer Apple's SecTrust verified is resumed on that word
/// by a transfer trusting the system's store, though OpenSSL never
/// verified its peer, and the session that transfer is given is kept
/// saying so in turn, so the next resumes too (`ossl_apply_session`,
/// `ossl_new_session_cb`'s `sectrust_verified`); a session not marked so
/// is not resumed, and the peer, which the system does not trust, fails.
///
/// SecTrust trusts no local server without a change to the system's
/// trust settings, so the first session is made unverified and marked
/// by hand: exported, and imported under a verified transfer's key with
/// the packed form's SecTrust tag (`CURL_SPACK_SECTRUST`). C's Apple
/// build answers both cases as this does (measured on macOS 27).
#[cfg(all(target_os = "macos", feature = "apple-sectrust"))]
fn a_session_sectrust_verified_resumes_and_is_kept_so() {
    use curl_core::tls::SessionFor;
    let certs = certs("sectrust", "localhost", &["localhost"]);
    for marked in [true, false] {
        let a = acceptor(&certs, |a| {
            a.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
        });
        let (at, server) = serve_each(vec![a.clone(), a.clone(), a]);
        let mut m = multi(try_box(SystemClock::new()).unwrap());
        let unverified = |o: &mut Options| {
            o.tls.verify_peer = false;
            o.tls.verify_host = false;
        };
        let one = get_in(&mut m, "https", "localhost", at, unverified, false);
        assert_eq!(one.result, Ok(()), "{:#?}", one.seen.lines);
        let mut easy = Easy::new();
        easy.set_libraries(SharedLibraries::of_static(&LIBRARIES));
        let id = m.add(try_box(easy).unwrap(), (), &mut NoEvents).unwrap();
        let mut kept: Option<(Vec<u8>, Vec<u8>)> = None;
        let done = m.ssls_export(id).unwrap().unwrap().deliver(&mut |s| {
            kept = Some((s.key.unwrap().to_vec(), s.packed.to_vec()));
            Ok::<(), ()>(())
        });
        m.ssls_export_end(id, done, &mut |_, _| {})
            .expect("in the multi")
            .expect("the export ends");
        let (key, mut packed) = kept.expect("the first transfer's session");
        let key = String::from_utf8(key)
            .unwrap()
            .replace(":NO-VRFY-PEER", "")
            .replace(":NO-VRFY-HOST", "");
        if marked {
            packed.push(0x08);
        }
        m.ssls_import(id, SessionFor::Key(key.as_bytes()), &packed, &mut |_, _| {})
            .unwrap()
            .unwrap();
        m.remove(id, &mut NoEvents).unwrap();
        let two = get_in(&mut m, "https", "localhost", at, |_| {}, false);
        let three = get_in(&mut m, "https", "localhost", at, |_| {}, false);
        server.join().unwrap();
        for got in [&two, &three] {
            if marked {
                assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
                assert!(resumed(got), "{:#?}", got.seen.lines);
                assert!(
                    said(got, "SSL certificate verified via Apple SecTrust."),
                    "{:#?}",
                    got.seen.lines
                );
            } else {
                assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
                assert!(!resumed(got), "{:#?}", got.seen.lines);
            }
        }
        if !marked {
            assert!(
                said(&two, "SSL session not peer verified, not reusing"),
                "{:#?}",
                two.seen.lines
            );
        }
    }
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
        let seen = track::untracked(|| Arc::new(Lock::new(Seen::default())));
        let mut easy = Easy::new();
        easy.set_libraries(SharedLibraries::of_static(&LOGGING_LIBRARIES));
        let o = easy.options_mut();
        let url = track::untracked(|| format!("https://localhost:{}/", at.port()));
        o.set_url(Some(url.as_bytes())).unwrap();
        o.ip_version = IpVersion::V4;
        o.output.verbose = true;
        o.callbacks
            .rare
            .set(
                |r| &mut r.debug,
                Some(Handler::debug(Taker(seen.clone())).unwrap()),
            )
            .unwrap();
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
    // LibreSSL gives no TLS 1.3 secrets, which C notes: the TLS 1.2
    // connection's master secret alone is logged, as C's build over it
    // logs it.
    #[cfg(libressl)]
    {
        for seen in &gets {
            let note = "Note LibreSSL only supports SSLKEYLOGFILE for TLS <= 1.2".to_owned();
            assert!(seen.lines.contains(&note), "{:#?}", seen.lines);
        }
        assert_eq!(labels, ["CLIENT_RANDOM"], "{log}");
    }
    #[cfg(not(libressl))]
    {
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
    }
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
/// session still writes the connection's secrets to the file. LibreSSL
/// gives TLS 1.2's secret alone, which the session writes after the
/// handshake: there the server speaks TLS 1.2.
fn a_session_keeps_its_key_log_past_its_owner() {
    let path = certs_dir().join("keys-owned.log");
    std::fs::create_dir_all(certs_dir()).unwrap();
    std::fs::write(&path, b"").unwrap();
    let certs = certs("keylog-owned", "localhost", &["localhost"]);
    // The server answers the hello only once the libraries are swapped.
    let (release, gate) = track::untracked(std::sync::mpsc::channel::<()>);
    let (at, server) = serve_each_after(
        vec![acceptor(&certs, |_a| {
            #[cfg(libressl)]
            _a.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
        })],
        Some(gate),
    );
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let seen = track::untracked(|| Arc::new(Lock::new(Seen::default())));
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
    o.callbacks
        .rare
        .set(
            |r| &mut r.debug,
            Some(Handler::debug(Taker(seen.clone())).unwrap()),
        )
        .unwrap();
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
    release.send(()).unwrap();
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
    #[cfg(not(libressl))]
    assert_eq!(log.lines().count(), 5, "TLS 1.3's five secrets: {log}");
    #[cfg(libressl)]
    assert_eq!(
        log.lines()
            .map(|l| l.split(' ').next().unwrap())
            .collect::<Vec<_>>(),
        ["CLIENT_RANDOM"],
        "TLS 1.2's master secret: {log}"
    );
}
