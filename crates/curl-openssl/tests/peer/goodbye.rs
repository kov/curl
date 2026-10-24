//! The goodbye (`ossl_shutdown`): a connection the transfers are done
//! with says close_notify as it closes, whichever side says it first,
//! and one an aborted transfer leaves says nothing.

use openssl::ssl::ShutdownState;

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "a_kept_connection_says_goodbye_as_the_multi_goes",
        a_kept_connection_says_goodbye_as_the_multi_goes,
    ),
    (
        "a_goodbye_answers_the_peer_s_own",
        a_goodbye_answers_the_peer_s_own,
    ),
    (
        "an_aborted_transfer_s_connection_says_no_goodbye",
        an_aborted_transfer_s_connection_says_no_goodbye,
    ),
];

/// A server for one connection answering one GET with `BODY`, the
/// connection kept, then saying goodbye itself if `first`; it reads
/// until the client says goodbye or closes, and whether a close_notify
/// came is what it ends with.
fn serve_goodbye(certs: &Certs, first: bool) -> (SocketAddr, JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&certs.key).unwrap();
    acceptor.set_certificate(&certs.cert).unwrap();
    let acceptor = acceptor.build();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut tls = acceptor.accept(tcp).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => return false,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", BODY.len());
        tls.write_all(head.as_bytes()).unwrap();
        tls.write_all(BODY).unwrap();
        if first {
            tls.shutdown().unwrap();
        }
        while matches!(tls.read(&mut buf), Ok(n) if n > 0) {}
        tls.get_shutdown().contains(ShutdownState::RECEIVED)
    });
    (at, server)
}

/// The response leaves the connection open; the multi's going shuts it
/// down (`Curl_cpool_destroy`), and close_notify reaches the server.
fn a_kept_connection_says_goodbye_as_the_multi_goes() {
    let certs = certs("goodbye-kept", "localhost", &["localhost"]);
    let (at, server) = serve_goodbye(&certs, false);
    let got = get("localhost", at, trusting(&certs));
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert_eq!(got.seen.body, BODY);
    assert!(server.join().unwrap(), "no close_notify came");
}

/// The server's close_notify comes first, with its socket left open:
/// the client still sends its own, as the reference does.
fn a_goodbye_answers_the_peer_s_own() {
    let certs = certs("goodbye-second", "localhost", &["localhost"]);
    let (at, server) = serve_goodbye(&certs, true);
    let got = get("localhost", at, trusting(&certs));
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert!(server.join().unwrap(), "no close_notify came");
}

/// Refused the body, the transfer is aborted, and its connection is
/// closed without a goodbye, which would tell the server all went well.
fn an_aborted_transfer_s_connection_says_no_goodbye() {
    struct Refuse;
    impl WriteHandler for Refuse {
        fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
            Write::Fail
        }
    }
    let certs = certs("goodbye-aborted", "localhost", &["localhost"]);
    let (at, server) = serve_goodbye(&certs, false);
    let got = get("localhost", at, |o| {
        trusting(&certs)(o);
        o.callbacks.write = Some(Handler::write(Refuse).unwrap());
    });
    assert_eq!(got.result, Err(ErrorKind::WriteError));
    assert!(!server.join().unwrap(), "a close_notify came");
}
