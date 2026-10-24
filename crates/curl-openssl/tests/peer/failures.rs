//! How the records end, both ways (`ossl_recv`, `ossl_send`,
//! `ossl_connect_step2`): a peer that says goodbye, one that goes without
//! a word, one that resets the connection, and the handshakes a
//! peer fails; each said as C says it.

use std::net::TcpStream;
use std::time::Duration;

use curl_core::options::TlsMaxVersion;
use openssl::ssl::{SslStream, SslVerifyMode};

use super::client::bytes;
use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "a_close_notify_ends_a_body_read_to_its_end",
        a_close_notify_ends_a_body_read_to_its_end,
    ),
    (
        "a_peer_gone_without_close_notify_fails_the_read",
        a_peer_gone_without_close_notify_fails_the_read,
    ),
    (
        "a_reset_fails_the_read_as_the_socket_says",
        a_reset_fails_the_read_as_the_socket_says,
    ),
    (
        "a_handshake_the_peer_ends_or_resets_fails_as_c_says",
        a_handshake_the_peer_ends_or_resets_fails_as_c_says,
    ),
    (
        "an_alert_in_the_handshake_fails_as_c_says",
        an_alert_in_the_handshake_fails_as_c_says,
    ),
];

/// A server for one connection that, its handshake done, does `then`
/// with the TLS stream.
fn serve_then(
    certs: &Certs,
    configure: impl FnOnce(&mut SslAcceptorBuilder),
    then: impl FnOnce(SslStream<TcpStream>) + Send + 'static,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&certs.key).unwrap();
    acceptor.set_certificate(&certs.cert).unwrap();
    configure(&mut acceptor);
    let acceptor = acceptor.build();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        match acceptor.accept(tcp) {
            Ok(tls) => then(tls),
            // The alert sent, what the client sends after is read until
            // it closes, as `serve` does.
            Err(openssl::ssl::HandshakeError::Failure(mut mid)) => {
                let tcp = mid.get_mut();
                tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut buf = [0u8; 4096];
                while matches!(tcp.read(&mut buf), Ok(n) if n > 0) {}
            }
            Err(e) => panic!("{e}"),
        }
    });
    (at, server)
}

/// Read what the client sent until the end of its request's head.
fn read_head(tls: &mut SslStream<TcpStream>) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        match tls.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    got
}

/// The library's version as `ossl_strerror` puts it before its errors.
fn version() -> &'static str {
    openssl::version::version().split(' ').nth(1).unwrap()
}

/// A body without a length is read until the peer's close_notify, which
/// ends it (`SSL_ERROR_ZERO_RETURN`), traced.
fn a_close_notify_ends_a_body_read_to_its_end() {
    let certs = certs("closenotify", "localhost", &["localhost"]);
    let (at, server) = serve_then(
        &certs,
        |_| {},
        |mut tls| {
            read_head(&mut tls);
            tls.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .unwrap();
            tls.write_all(BODY).unwrap();
            tls.shutdown().unwrap();
            // The client's own goodbye, or its close.
            let mut buf = [0u8; 64];
            let _ = tls.read(&mut buf);
        },
    );
    let got = get_traced("localhost", at, trusting(&certs), true);
    server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert_eq!(got.seen.body, BODY);
    assert!(
        got.seen
            .lines
            .iter()
            .any(|l| l.ends_with("TLS close_notify")),
        "{:#?}",
        got.seen.lines
    );
}

/// A peer that closes the connection in the body's middle, without a
/// close_notify, fails the read as OpenSSL 3 says it (an unexpected end),
/// the library's version before its error.
fn a_peer_gone_without_close_notify_fails_the_read() {
    let certs = certs("abrupt", "localhost", &["localhost"]);
    let (at, server) = serve_then(
        &certs,
        |_| {},
        |mut tls| {
            read_head(&mut tls);
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                .unwrap();
            tls.write_all(BODY).unwrap();
            // Dropped without a word: the socket closes.
        },
    );
    let got = get("localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(
        got.result,
        Err(ErrorKind::RecvError),
        "{:#?}",
        got.seen.lines
    );
    assert_eq!(
        String::from_utf8(got.failure).unwrap(),
        format!(
            "OpenSSL SSL_read: OpenSSL/{}: error:0A000126:SSL routines::unexpected eof while \
             reading, errno 0",
            version()
        )
    );
}

/// A peer that resets the connection (closing it with the request
/// unread) fails the read: the socket's failure said first, then
/// OpenSSL's read said with the socket's error (`SSL_ERROR_SYSCALL`).
fn a_reset_fails_the_read_as_the_socket_says() {
    let certs = certs("reset", "localhost", &["localhost"]);
    let (at, server) = serve_then(
        &certs,
        |_| {},
        |tls| {
            // The request comes in, and stays unread as the socket closes.
            std::thread::sleep(Duration::from_millis(200));
            drop(tls);
        },
    );
    let got = get("localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(
        got.result,
        Err(ErrorKind::RecvError),
        "{:#?}",
        got.seen.lines
    );
    assert_eq!(got.failure, b"Recv failure: Connection reset by peer");
    assert!(
        said(
            &got,
            "OpenSSL SSL_read: Connection reset by peer, errno 104"
        ),
        "{:#?}",
        got.seen.lines
    );
}

/// A peer that closes during the handshake fails it as OpenSSL says (an
/// unexpected end), nothing more said; one that resets it fails with the
/// socket's failure, then OpenSSL's said with the socket's error and the
/// peer (`ossl_connect_step2`).
fn a_handshake_the_peer_ends_or_resets_fails_as_c_says() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let ends = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        let mut header = [0u8; 5];
        tcp.read_exact(&mut header).unwrap();
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut hello = vec![0u8; len];
        tcp.read_exact(&mut hello).unwrap();
    });
    let got = get("localhost", at, |_| {});
    ends.join().unwrap();
    assert_eq!(got.result, Err(ErrorKind::SslConnectError));
    assert_eq!(
        got.failure,
        b"TLS connect error: error:0A000126:SSL routines::unexpected eof while reading"
    );
    assert!(
        !starts(&got, "OpenSSL SSL_connect:"),
        "{:#?}",
        got.seen.lines
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let resets = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        // The hello's start read, the rest unread as the socket closes.
        let mut header = [0u8; 5];
        tcp.read_exact(&mut header).unwrap();
        std::thread::sleep(Duration::from_millis(100));
    });
    let got = get("localhost", at, |_| {});
    resets.join().unwrap();
    assert_eq!(got.result, Err(ErrorKind::SslConnectError));
    assert_eq!(got.failure, b"Recv failure: Connection reset by peer");
    let line = format!(
        "OpenSSL SSL_connect: Connection reset by peer in connection to localhost:{}",
        at.port()
    );
    assert!(said(&got, &line), "{line:?} in {:#?}", got.seen.lines);
}

/// A server that refuses the client's certificate as expired fails the
/// TLS 1.2 handshake as a verification: said by what OpenSSL made of the
/// server's certificate if that failed, else as verification failed. A
/// server that wants a certificate and gets none fails it as a TLS
/// connect error, OpenSSL's alert said.
fn an_alert_in_the_handshake_fails_as_c_says() {
    let certs = certs("alerts", "localhost", &["localhost"]);
    let other = super::certs("alerts-other", "localhost", &["localhost"]);
    // The client's certificate again, its validity over a day ago.
    let made = super::certs("alerts-expired-client", "client", &[]);
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name("client")).unwrap();
    cert.set_issuer_name(made.ca.subject_name()).unwrap();
    cert.set_pubkey(&made.key).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    cert.set_not_before(&Asn1Time::from_unix(now - 3 * 86400).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::from_unix(now - 2 * 86400).unwrap())
        .unwrap();
    cert.sign(&made.ca_key, MessageDigest::sha256()).unwrap();
    let cert_file = certs_dir().join("alerts-expired-client.pem");
    std::fs::write(&cert_file, cert.build().to_pem().unwrap()).unwrap();
    let key_file = certs_dir().join("alerts-expired-client.key");
    std::fs::write(&key_file, made.key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let client_ca = made.ca.clone();
    let asking = move |a: &mut SslAcceptorBuilder| {
        a.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        a.cert_store_mut().add_cert(client_ca.clone()).unwrap();
    };
    for (trusted, failure) in [
        (&certs, "SSL certificate verification failed"),
        (
            &other,
            "SSL certificate problem: unable to get local issuer certificate",
        ),
    ] {
        let (at, server) = serve_then(&certs, asking.clone(), |_| {});
        let got = get("localhost", at, |o| {
            trusting(trusted)(o);
            let t = o.tls.options.make_mut().unwrap();
            t.max_version = TlsMaxVersion::Tls1_2;
            t.cert = Some(bytes(&cert_file));
            t.key = Some(bytes(&key_file));
        });
        server.join().unwrap();
        assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
        assert_eq!(String::from_utf8(got.failure).unwrap(), failure);
    }
    let (at, server) = serve_then(&certs, asking, |_| {});
    let got = get("localhost", at, |o| {
        trusting(&certs)(o);
        o.tls.options.make_mut().unwrap().max_version = TlsMaxVersion::Tls1_2;
    });
    server.join().unwrap();
    assert_eq!(got.result, Err(ErrorKind::SslConnectError));
    assert_eq!(
        got.failure,
        b"TLS connect error: error:0A000410:SSL routines::ssl/tls alert handshake failure"
    );
}
