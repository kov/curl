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
/// for a name under `nx`; a name under `silent` gets no answer, and one
/// under `slowa` its A late. Each query's type and name is sent on the channel.
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
            if name.starts_with("silent") {
                continue;
            }
            if name.starts_with("slowa") && kind == 1 {
                thread::sleep(Duration::from_millis(300));
            }
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

#[test]
fn an_interface_named_by_host_is_resolved_by_the_servers_named() {
    let (dns, heard) = dns_server();
    let http = http_server();
    let servers = format!("127.0.0.1:{dns}");
    let url = format!("http://127.0.0.1:{http}/");
    let run = curl(&[
        "--dns-servers",
        &servers,
        "--interface",
        "host!bind.test",
        &url,
    ]);
    assert_eq!(
        run.stdout,
        b"ok",
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let asked: Vec<_> = heard.try_iter().collect();
    assert!(asked.contains(&(1, "bind.test".to_owned())), "{asked:?}");
}

#[test]
fn an_interface_name_that_does_not_exist_is_said_as_c_ares_says_it() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    let run = curl(&[
        "-v",
        "--dns-servers",
        &servers,
        "--interface",
        "host!nx.test",
        "http://127.0.0.1:1/",
    ]);
    assert_eq!(run.status.code(), Some(45));
    let said = String::from_utf8_lossy(&run.stderr);
    assert!(
        said.contains("Could not resolve host: nx.test (Domain name not found)"),
        "{said}"
    );
    assert!(said.contains("Could not bind to 'nx.test'"), "{said}");
}

#[test]
fn an_interface_name_is_waited_for_no_longer_than_the_transfer_may_take() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    let started = std::time::Instant::now();
    let run = curl(&[
        "-v",
        "--connect-timeout",
        "1",
        "--dns-servers",
        &servers,
        "--interface",
        "host!silent.test",
        "http://127.0.0.1:1/",
    ]);
    let said = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(45), "{said}");
    assert!(said.contains("Could not bind to 'silent.test'"), "{said}");
    // Before c-ares would give up on its own, its first try taking 2 s.
    let took = started.elapsed();
    assert!(took < Duration::from_millis(1900), "{took:?}");
}

#[test]
fn a_socket_c_ares_closes_is_said_to_close() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    let run = curl(&[
        "-v",
        "--trace-config",
        "multi",
        "--dns-servers",
        &servers,
        "http://nx.test:1/",
    ]);
    assert_eq!(run.status.code(), Some(6));
    let said = String::from_utf8_lossy(&run.stderr);
    // No connection was made, whose socket this could be.
    assert!(said.contains("Curl_multi_will_close fd="), "{said}");
    assert!(!said.contains("Trying"), "{said}");
}

#[test]
fn the_race_begins_before_a_late_a_as_aaaa_has_answered() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    let run = curl(&[
        "-v",
        "--trace-config",
        "dns,happy-eyeballs",
        "--dns-servers",
        &servers,
        "http://slowa.test:1/",
    ]);
    assert_eq!(run.status.code(), Some(7));
    let said = String::from_utf8_lossy(&run.stderr);
    let at = |needle: &str| {
        said.find(needle)
            .unwrap_or_else(|| panic!("{needle}: {said}"))
    };
    assert!(at("init ip ballers") < at("resolve complete"), "{said}");
    assert!(said.contains("family=2, dns=0"), "{said}");
    assert!(said.contains("family=2, dns=1"), "{said}");
}

#[test]
fn a_resolve_that_does_not_end_times_out_as_resolving() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    let run = curl(&[
        "--max-time",
        "1",
        "--dns-servers",
        &servers,
        "http://silent.test:1/",
    ]);
    assert_eq!(run.status.code(), Some(28));
    let said = String::from_utf8_lossy(&run.stderr);
    assert!(said.contains("Resolving timed out"), "{said}");
}

#[test]
fn a_resolve_is_looked_at_as_soon_as_it_starts() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    let run = curl(&[
        "-v",
        "--trace-config",
        "dns",
        "--dns-servers",
        &servers,
        "http://nx.test:1/",
    ]);
    let said = String::from_utf8_lossy(&run.stderr);
    let lines: Vec<_> = said.lines().collect();
    let started = lines
        .iter()
        .position(|l| l.contains("hostip_resolv started -> 81"))
        .unwrap_or_else(|| panic!("{said}"));
    assert!(
        lines[started - 1].contains("resolve incomplete, responses=-"),
        "{said}"
    );
    assert!(
        lines[started + 1].contains("cache lookup nx.test:1"),
        "{said}"
    );
    assert!(lines[started + 2].contains("resolve incomplete"), "{said}");
}

/// A debug build says what it refused, as C's does.
#[cfg(feature = "debug-hooks")]
#[test]
fn a_debug_build_names_the_bad_setting() {
    for (option, value, words) in [
        ("--dns-ipv4-addr", "nope", "* bad DNS IPv4 address"),
        ("--dns-ipv6-addr", "nope", "* bad DNS IPv6 address"),
        ("--dns-servers", "not a server", "* bad servers set"),
    ] {
        let run = curl(&["-v", option, value, "http://name.test:1/"]);
        let said = String::from_utf8_lossy(&run.stderr);
        assert!(said.contains(words), "{said}");
    }
}
