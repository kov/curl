//! Names resolved by c-ares, against a DNS server of the test's own.
#![cfg(not(feature = "threaded-resolver"))]
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// A server on a port of its own that answers each query with `127.0.0.1`
/// for A, `alpn=http/1.1` for HTTPS and nothing for AAAA, or with NXDOMAIN
/// for a name under `nx`. Each query's type and name is sent on the channel.
fn dns_server() -> (u16, mpsc::Receiver<(u16, String)>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let (told, heard) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let q = &buf[..n];
            let (mut i, mut labels) = (12, Vec::new());
            while q[i] != 0 {
                let len = usize::from(q[i]);
                labels.push(String::from_utf8(q[i + 1..i + 1 + len].to_vec()).unwrap());
                i += len + 1;
            }
            let kind = u16::from_be_bytes([q[i + 1], q[i + 2]]);
            let name = labels.join(".").to_lowercase();
            let nx = name.starts_with("nx");
            let mut answer = Vec::new();
            if !nx && kind == 1 {
                answer.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x37\x00\x04");
                answer.extend_from_slice(&[127, 0, 0, 1]);
            }
            if !nx && kind == 65 {
                answer.extend_from_slice(b"\xc0\x0c\x00\x41\x00\x01\x00\x00\x00\x37\x00\x10");
                answer.extend_from_slice(b"\x00\x01\x00\x00\x01\x00\x09\x08http/1.1");
            }
            let mut reply = vec![q[0], q[1], 0x81, if nx { 0x83 } else { 0x80 }, 0, 1, 0];
            reply.push(u8::from(!answer.is_empty()));
            reply.extend_from_slice(&[0, 0, 0, 0]);
            reply.extend_from_slice(&q[12..i + 5]);
            reply.extend_from_slice(&answer);
            socket.send_to(&reply, peer).unwrap();
            if told.send((kind, name)).is_err() {
                return;
            }
        }
    });
    (port, heard)
}

/// An HTTP server that answers one request.
fn http_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut c, _) = listener.accept().unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 1024];
        let _read = c.read(&mut buf).unwrap();
        c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    port
}

fn curl(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_curl"))
        .args(["-sS", "--max-time", "20"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn the_servers_named_find_the_address() {
    let (dns, heard) = dns_server();
    let http = http_server();
    let servers = format!("127.0.0.1:{dns}");
    let url = format!("http://name.test:{http}/");
    let run = curl(&["--dns-servers", &servers, &url]);
    assert_eq!(
        run.stdout,
        b"ok",
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let asked: Vec<_> = heard.try_iter().collect();
    assert!(asked.contains(&(1, "name.test".to_owned())), "{asked:?}");
    assert!(asked.contains(&(28, "name.test".to_owned())), "{asked:?}");
}

#[test]
fn a_name_that_does_not_exist_is_said_as_c_ares_says_it() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    let run = curl(&["--dns-servers", &servers, "http://nx.test:1/"]);
    assert_eq!(run.status.code(), Some(6));
    let said = String::from_utf8_lossy(&run.stderr);
    assert!(
        said.contains("Could not resolve host: nx.test (Domain name not found)"),
        "{said}"
    );
}

#[test]
fn an_https_origins_record_is_asked_for_under_its_port() {
    let (dns, heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    let run = curl(&[
        "-v",
        "-k",
        "--dns-servers",
        &servers,
        "https://name.test:1/",
    ]);
    assert_eq!(run.status.code(), Some(7), "{:?}", run.status);
    let asked: Vec<_> = heard.try_iter().collect();
    assert!(
        asked.contains(&(65, "_1._https.name.test".to_owned())),
        "{asked:?}"
    );
}

#[test]
fn a_bad_setting_fails_the_resolve_as_c_does() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    for (option, value) in [
        ("--dns-ipv4-addr", "nope"),
        ("--dns-ipv6-addr", "nope"),
        ("--dns-servers", "not a server"),
    ] {
        let servers = if option == "--dns-servers" {
            value
        } else {
            &servers
        };
        let run = curl(&[
            option,
            value,
            "--dns-servers",
            servers,
            "http://name.test:1/",
        ]);
        assert_eq!(run.status.code(), Some(43), "{option}");
        let said = String::from_utf8_lossy(&run.stderr);
        assert!(
            said.contains("Error 43 resolving name.test:1"),
            "{option}: {said}"
        );
    }
}
