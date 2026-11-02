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
/// for a name under `nx`. A name under `silent` gets no answer, one under
/// `slowa` its A late and one under `slowv6` its AAAA; one with `norec` in
/// it gets no answer for its HTTPS record, one with `h3rec` `alpn=h3`, and
/// one with `emptyrr` an answer without a record. Each query's type and
/// name is sent on the channel.
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
            if name.starts_with("silent") || (name.contains("norec") && kind == 65) {
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
            if !nx && kind == 65 && name.contains("h3rec") {
                answer.extend_from_slice(b"\xc0\x0c\x00\x41\x00\x01\x00\x00\x00\x37\x00\x0a");
                answer.extend_from_slice(b"\x00\x01\x00\x00\x01\x00\x03\x02h3");
            } else if !nx && kind == 65 && !name.contains("emptyrr") {
                answer.extend_from_slice(b"\xc0\x0c\x00\x41\x00\x01\x00\x00\x00\x37\x00\x10");
                answer.extend_from_slice(b"\x00\x01\x00\x00\x01\x00\x09\x08http/1.1");
            }
            let mut reply = vec![q[0], q[1], 0x81, if nx { 0x83 } else { 0x80 }, 0, 1, 0];
            reply.push(u8::from(!answer.is_empty()));
            reply.extend_from_slice(&[0, 0, 0, 0]);
            reply.extend_from_slice(&q[12..i + 5]);
            reply.extend_from_slice(&answer);
            if name.starts_with("slowv6") && kind == 28 {
                // Late, while the other queries are answered.
                let late = socket.try_clone().unwrap();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(300));
                    let _sent = late.send_to(&reply, peer);
                });
            } else {
                socket.send_to(&reply, peer).unwrap();
            }
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
        "--trace-config",
        "dns",
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
    // Each look at the record is said, as it starts and as the connect
    // looks again for its answer: C says three.
    let said = String::from_utf8_lossy(&run.stderr);
    let looks = said
        .matches("cache lookup name.test:1 queries=HTTPS -> 0 not found")
        .count();
    assert!(looks >= 2, "{said}");
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
    // The failure counts the wait, as C's does.
    let after = said
        .split("Failed to connect to 127.0.0.1:1 after ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .and_then(|ms| ms.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("{said}"));
    assert!(after >= 900, "{said}");
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
    // Still going on, or answered already where the server was quick.
    let next = lines[started + 2];
    assert!(
        next.contains("resolve incomplete") || next.contains("Could not resolve host: nx.test"),
        "{said}"
    );
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

#[test]
fn a_record_never_answered_says_its_socket_closed() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    let run = curl(&[
        "-v",
        "-k",
        "--trace-config",
        "multi",
        "--dns-servers",
        &servers,
        "https://norec.test:1/",
    ]);
    assert_eq!(run.status.code(), Some(7));
    let said = String::from_utf8_lossy(&run.stderr);
    // The addresses' resolve's socket, the record's, and the attempt's, as C
    // says them.
    let closes = said.matches("Curl_multi_will_close fd=").count();
    assert_eq!(closes, 3, "{said}");
}

#[test]
fn a_second_attempt_started_during_a_resolve_takes_what_it_finds() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    // HTTP/3 leads, as the record says; HTTP/2 starts after it while the A
    // is still to come, and both go on to the address it brings.
    let run = curl(&[
        "-v",
        "-k",
        "--http3",
        "--max-time",
        "3",
        "--trace-config",
        "dns,happy-eyeballs",
        "--dns-servers",
        &servers,
        "https://slowa-h3rec.test:1/",
    ]);
    let said = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(7), "{said}");
    assert_eq!(said.matches("Trying 127.0.0.1:1...").count(), 2, "{said}");
    // The QUIC one's refusal said, however far it got before the end.
    assert!(said.contains("QUIC: connection to 127.0.0.1"), "{said}");
}

/// Where `needle` first is in `said`, which must have it.
fn at(said: &str, needle: &str) -> usize {
    said.find(needle)
        .unwrap_or_else(|| panic!("{needle}: {said}"))
}

#[test]
fn a_socket_closed_is_said_before_the_answer_is_taken() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    for (interface, url, queries) in [
        (None, "http://plain.test:1/", "A+AAAA"),
        (Some("host!bind.test"), "http://127.0.0.1:1/", "A"),
    ] {
        let mut args = vec![
            "-v",
            "--trace-config",
            "dns,multi",
            "--dns-servers",
            &servers,
        ];
        if let Some(interface) = interface {
            args.extend(["--interface", interface]);
        }
        args.push(url);
        let run = curl(&args);
        assert_eq!(run.status.code(), Some(7));
        let said = String::from_utf8_lossy(&run.stderr);
        // As C's `sock_state_cb` tells it, in the call that answers.
        let taken = format!(
            "[{queries}] ares_take_result, result=0, ares_result=0, ares_status=0, dns=found"
        );
        assert!(
            at(&said, "Curl_multi_will_close fd=") < at(&said, &taken),
            "{said}"
        );
    }
}

#[test]
fn a_record_s_http_3_is_not_taken_where_it_is_not_allowed() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    // The record offers HTTP/3 alone, which `--http2` does not allow: the
    // attempts are what is wanted, as if it offered nothing. The record is
    // known as the second attempt is chosen.
    let run = curl(&[
        "-v",
        "-k",
        "--http2",
        "--trace-config",
        "https-connect",
        "--dns-servers",
        &servers,
        "https://h3rec.test:1/",
    ]);
    let said = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(7), "{said}");
    assert!(
        said.contains("HTTPS-RR h3rec.test:1: 1 . alpn=h3"),
        "{said}"
    );
    assert!(!said.contains("uses h3"), "{said}");
    assert!(!said.contains("QUIC"), "{said}");
}

#[test]
fn a_record_answered_empty_is_not_available() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    // The debug build waits for the record before the first attempt is
    // chosen, which the answer then chose; what it has is no record.
    let run = Command::new(env!("CARGO_BIN_EXE_curl"))
        .env("CURL_DBG_AWAIT_HTTPSRR", "1")
        .args(["-sS", "--max-time", "20", "-v", "-k", "--trace-config"])
        .args(["https-connect", "--dns-servers", &servers])
        .arg("https://emptyrr.test:1/")
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(7), "{said}");
    assert!(said.contains("HTTPS-RR not available"), "{said}");
    assert!(!said.contains("HTTPS-RR available"), "{said}");
}

#[test]
fn an_attempt_dials_as_the_record_awaited_chooses() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    // HTTP/3 is wanted and the record offers HTTP/1.1 alone. The debug
    // build waits for the record, which comes after the setup was planned:
    // the first attempt is HTTP/1.1's, over TCP, not the plan's QUIC.
    let run = Command::new(env!("CARGO_BIN_EXE_curl"))
        .env("CURL_DBG_AWAIT_HTTPSRR", "1")
        .args(["-sS", "--max-time", "20", "-v", "-k", "--http3"])
        .args(["--trace-config", "https-connect", "--dns-servers", &servers])
        .arg("https://rr.test:1/")
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(7), "{said}");
    if said.contains("1st attempt uses h1 from HTTPS-RR") {
        // HTTP/3 is the second's, started once the first failed over TCP.
        let quic = said.find("QUIC").unwrap_or(said.len());
        assert!(at(&said, "h1 baller failed, starting h3") < quic, "{said}");
    } else {
        // A build that does not wait chooses before the record comes.
        assert!(
            said.contains("1st attempt uses h3 from wanted versions"),
            "{said}"
        );
    }
}

#[test]
fn a_record_come_before_the_first_attempt_chooses_it() {
    let (dns, _heard) = dns_server();
    let servers = format!("127.0.0.1:{dns}");
    // The record is answered at once, AAAA late: the attempts begin once
    // AAAA is waited for no longer, the record taken, and the first is
    // chosen by it, as C's `connect, init` asks the DNS filter for it.
    let run = curl(&[
        "-v",
        "-k",
        "--trace-config",
        "https-connect",
        "--dns-servers",
        &servers,
        "https://slowv6.test:1/",
    ]);
    let said = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(7), "{said}");
    assert!(
        at(&said, "HTTPS-RR available") < at(&said, "1st attempt uses h1 from HTTPS-RR"),
        "{said}"
    );
}
