//! A WebSocket over TLS (`wss://`): the upgrade and its frames go through
//! the TLS layer as an HTTPS request's do.

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[(
    "a_wss_upgrade_reads_its_frames_over_tls",
    a_wss_upgrade_reads_its_frames_over_tls,
)];

/// A server for one connection that answers the request's head with a
/// 101, a text frame of `BODY` and a close, then closes; what it was sent
/// read until the head's end.
fn serve_ws(certs: &Certs) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&certs.key).unwrap();
    acceptor.set_certificate(&certs.cert).unwrap();
    let acceptor = acceptor.build();
    let server = std::thread::spawn(move || {
        let (tcp, _) = curl_core::test_server::accept(&listener);
        let mut tls = acceptor.accept(tcp).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => return got,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        let mut reply = b"HTTP/1.1 101 Switching Protocols\r\n\
            Upgrade: websocket\r\nConnection: Upgrade\r\n\
            Sec-WebSocket-Accept: x\r\n\r\n"
            .to_vec();
        reply.push(0x81);
        reply.push(u8::try_from(BODY.len()).unwrap());
        reply.extend_from_slice(BODY);
        reply.extend_from_slice(b"\x88\x00");
        let _ = tls.write_all(&reply);
        let _ = tls.shutdown();
        got
    });
    (at, server)
}

/// With a TLS library, wss:// is a WebSocket over TLS: the upgrade is
/// asked for over the verified connection, and the frames after the 101
/// are read through it to the write callback.
fn a_wss_upgrade_reads_its_frames_over_tls() {
    let certs = certs("wss", "localhost", &["localhost"]);
    let (at, server) = serve_ws(&certs);
    let got = get_scheme("wss", "localhost", at, trusting(&certs));
    let request = server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:?}", got.seen.lines);
    assert_eq!(got.seen.body, BODY);
    let request = String::from_utf8_lossy(&request);
    assert!(request.starts_with("GET / HTTP/1.1\r\n"), "{request}");
    assert!(request.contains("\r\nUpgrade: websocket\r\n"), "{request}");
    assert!(
        got.seen
            .lines
            .iter()
            .any(|l| l == "SSL certificate verified via OpenSSL."),
        "{:?}",
        got.seen.lines
    );
}
