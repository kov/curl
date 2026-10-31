//! FTP's `CCC` over OpenSSL (`Curl_ssl_cfilter_remove`): the control
//! connection's TLS shut down, as the server's close_notify asks, and
//! the login going on in clear.

use std::net::TcpStream;

use curl_core::options::{Ccc, Method};

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "a_passive_ccc_answers_no_close_notify",
        a_passive_ccc_answers_no_close_notify,
    ),
    (
        "an_active_ccc_answers_the_server_s_close_notify",
        an_active_ccc_answers_the_server_s_close_notify,
    ),
];

/// What the server saw after `CCC`: whether the client's close_notify
/// came before its next command, and the commands it then sent in clear.
struct Cleared {
    goodbye: bool,
    commands: String,
}

/// An implicit FTPS server for one connection: the login in TLS, `CCC`
/// answered and its close_notify said, then each command read and
/// answered in clear until `QUIT`.
fn serve_ccc(certs: &Certs) -> (SocketAddr, JoinHandle<Cleared>) {
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
        let line = |r: &mut dyn Read| {
            let mut got = Vec::new();
            let mut b = [0u8; 1];
            while !got.ends_with(b"\r\n") {
                match r.read(&mut b) {
                    Ok(1) => got.push(b[0]),
                    _ => break,
                }
            }
            String::from_utf8_lossy(&got).into_owned()
        };
        tls.write_all(b"220 hi\r\n").unwrap();
        loop {
            let command = line(&mut tls);
            let answer: &[u8] = match command.split(' ').next().unwrap().trim_end() {
                "USER" => b"331 password?\r\n",
                "PASS" => b"230 in\r\n",
                "PBSZ" | "PROT" => b"200 ok\r\n",
                "CCC" => b"200 CCC\r\n",
                _ => panic!("{command:?} before CCC"),
            };
            tls.write_all(answer).unwrap();
            if answer.starts_with(b"200 CCC") {
                break;
            }
        }
        // Our close_notify, not waiting for the client's.
        tls.shutdown().unwrap();
        let tcp: &mut TcpStream = tls.get_mut();
        // A close_notify is a record: an alert, or as TLS 1.3 hides it,
        // application data; a command is text.
        let mut first = [0u8; 1];
        tcp.read_exact(&mut first).unwrap();
        let goodbye = first[0] == 0x15 || first[0] == 0x17;
        let mut commands = String::new();
        if goodbye {
            let mut header = [0u8; 4];
            tcp.read_exact(&mut header).unwrap();
            let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let mut body = vec![0u8; len];
            tcp.read_exact(&mut body).unwrap();
        } else {
            commands.push(char::from(first[0]));
        }
        loop {
            let command = line(tcp);
            commands.push_str(&command);
            let answer: &[u8] = match command.trim_end() {
                "WD" | "PWD" => b"257 \"/\" is it\r\n",
                "QUIT" => b"221 bye\r\n",
                "" => break,
                _ => b"200 ok\r\n",
            };
            if tcp.write_all(answer).is_err() || command.starts_with("QUIT") {
                break;
            }
        }
        Cleared { goodbye, commands }
    });
    (at, server)
}

/// An implicit FTPS look at `/`, cleared as `ccc` says.
fn look(certs: &Certs, at: SocketAddr, ccc: Ccc) -> Got {
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let got = get_in(
        &mut m,
        "ftps",
        "localhost",
        at,
        |o| {
            trusting(certs)(o);
            o.method = Method::Head;
            o.line.make_mut().unwrap().ftp.ssl_ccc = ccc;
        },
        true,
    );
    drop(m);
    got
}

/// Passive, the server's close_notify is read and none is sent back:
/// the next command is the first bytes after it.
fn a_passive_ccc_answers_no_close_notify() {
    let certs = certs("ccc-passive", "localhost", &["localhost"]);
    let (at, server) = serve_ccc(&certs);
    let got = look(&certs, at, Ccc::Passive);
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert!(
        said(&got, "[SSL] SSL shutdown received, not sending"),
        "{:#?}",
        got.seen.lines
    );
    let cleared = server.join().unwrap();
    assert!(!cleared.goodbye, "a close_notify came");
    assert!(
        cleared.commands.starts_with("PWD\r\n"),
        "{}",
        cleared.commands
    );
    assert!(
        cleared.commands.ends_with("QUIT\r\n"),
        "{}",
        cleared.commands
    );
}

/// Active, the client says its close_notify before it goes on in clear.
fn an_active_ccc_answers_the_server_s_close_notify() {
    let certs = certs("ccc-active", "localhost", &["localhost"]);
    let (at, server) = serve_ccc(&certs);
    let got = look(&certs, at, Ccc::Active);
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let cleared = server.join().unwrap();
    assert!(cleared.goodbye, "no close_notify came");
    assert!(
        cleared.commands.starts_with("PWD\r\n"),
        "{}",
        cleared.commands
    );
}
