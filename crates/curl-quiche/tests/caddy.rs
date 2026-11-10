//! The connection against a real HTTP/3 server: caddy, which the test
//! starts with certificates it makes, on a port it finds free, over the
//! OpenSSL backend's session on the BoringSSL quiche runs over. caddy must
//! be installed; a run without it fails rather than skips.

#![cfg(boringssl)]
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

mod common;

use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant as StdInstant};

use common::{Dir, Over, Told, UNTRUSTED, VERIFIED, certs, run, with_client, with_client_qlog};
use curl_core::error::ErrorKind;
use curl_core::http3::{Connection, H3Error, StreamId};
use curl_core::tls::TlsCx;

const BODY: &[u8] = b"hello h3\n";

/// A field of 2000 bytes caddy sends with `BODY`: more than quiche takes
/// in a head of its own, less than curl's limit it is set to.
fn big_field() -> String {
    "x".repeat(2000)
}

/// A body larger than the eight chunks C's filter reads at a time.
fn big() -> Vec<u8> {
    (0..300_000u32).map(|i| (i % 251) as u8).collect()
}

/// The server, killed as this goes.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// caddy serving `BODY` as `/data.txt` and `big()` as `/big.bin` over
/// HTTP/3 on a free port of 127.0.0.1, from `dir`. A port found free may
/// be taken before caddy binds it: caddy then fails, and is started again
/// on other ports.
fn caddy(dir: &Path) -> (Server, SocketAddr) {
    for _ in 0..10 {
        let (mut server, port) = caddy_once(dir);
        if wait_bound(&mut server, port) {
            return (server, SocketAddr::from(([127, 0, 0, 1], port)));
        }
    }
    panic!("caddy bound no UDP port in ten tries");
}

/// caddy started on ports free as they were looked for, and its HTTP/3
/// one.
fn caddy_once(dir: &Path) -> (Server, u16) {
    let port = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let docs = dir.join("docs");
    std::fs::create_dir_all(&docs).unwrap();
    std::fs::write(docs.join("data.txt"), BODY).unwrap();
    std::fs::write(docs.join("big.bin"), big()).unwrap();
    let d = dir.display();
    let conf = format!(
        "{{\n  http_port {tcp}\n  https_port {port}\n  admin off\n  log default {{\n    level ERROR\n  }}\n  \
         servers :{port} {{\n    protocols h3 h2 h1\n  }}\n}}\n\
         localhost:{port} {{\n  file_server * {{\n    root {d}/docs\n  }}\n  tls {d}/cert.pem {d}/key.pem\n  header /data.txt X-Big {big}\n}}\n",
        big = big_field()
    );
    std::fs::write(dir.join("Caddyfile"), conf).unwrap();
    let child = Command::new("caddy")
        .args(["run", "--adapter", "caddyfile", "--config"])
        .arg(dir.join("Caddyfile"))
        .env("HOME", dir)
        .env("XDG_DATA_HOME", dir)
        .env("XDG_CONFIG_HOME", dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("caddy, installed, to serve HTTP/3");
    (Server(child), port)
}

/// Wait until `server` itself has a UDP socket bound to `port`: one of
/// another process's on it does not count. False if it ends first.
fn wait_bound(server: &mut Server, port: u16) -> bool {
    let deadline = StdInstant::now() + Duration::from_secs(20);
    let needle = format!(":{port:04X}");
    let fds = format!("/proc/{}/fd", server.0.id());
    while StdInstant::now() < deadline {
        if server.0.try_wait().unwrap().is_some() {
            return false;
        }
        let mut inodes = Vec::new();
        for table in ["/proc/net/udp", "/proc/net/udp6"] {
            let udp = std::fs::read_to_string(table).unwrap_or_default();
            for l in udp.lines() {
                let cols: Vec<&str> = l.split_whitespace().collect();
                if cols.get(1).is_some_and(|a| a.ends_with(&needle)) {
                    inodes.extend(cols.get(9).map(|i| format!("socket:[{i}]")));
                }
            }
        }
        let owned = std::fs::read_dir(&fds)
            .into_iter()
            .flatten()
            .flatten()
            .any(|fd| {
                std::fs::read_link(fd.path())
                    .is_ok_and(|link| inodes.iter().any(|i| link.as_os_str() == i.as_str()))
            });
        if owned {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Start caddy in a directory of `test`'s own, and run `f` with a
/// connection to it that trusts the CA file `ca` names there: what `f`
/// returns, and the notes the transfer was given.
fn with_conn<R>(
    test: &str,
    ca: &str,
    f: impl FnOnce(&mut dyn Connection, &mut TlsCx<'_>, &Over<'_>, SocketAddr) -> R,
) -> (R, Vec<String>) {
    let dir = Dir::new(test);
    certs(&dir.0);
    let (_server, addr) = caddy(&dir.0);
    with_client(&dir.0, ca, addr, f)
}

/// A GET of `path` on a connection whose handshake completed, its peer
/// checked: what the connection told.
fn get(test: &str, path: &str) -> (Told, Vec<String>) {
    with_conn(test, "ca.pem", |conn, cx, over, addr| {
        let mut told = Told::default();
        run(conn, cx, over, &mut told, |t| t.checked.is_some()).unwrap();
        assert_eq!(told.checked, Some(Ok(())));
        assert!(
            conn.handshake_done(),
            "HTTP/3 set up once the peer is checked"
        );
        let authority = format!("localhost:{}", addr.port());
        let fields: [(&[u8], &[u8]); 4] = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", authority.as_bytes()),
            (b":path", path.as_bytes()),
        ];
        let stream = conn.submit_request(&fields, false).unwrap();
        assert_eq!(stream, StreamId(0));
        run(conn, cx, over, &mut told, |t| t.closed).unwrap();
        told
    })
}

/// With a directory for qlogs, the connection has quiche write its qlog
/// to a file in it named after its source id, in hex, under C's title
/// and description (`Curl_qlogdir`, `quiche_conn_set_qlog_fd`).
#[test]
fn a_connection_writes_its_qlog_to_the_directory_given() {
    let qlogs = Dir::new("qlogs");
    let dir = Dir::new("qlog");
    certs(&dir.0);
    let (_server, addr) = caddy(&dir.0);
    let ((), _) = with_client_qlog(
        &dir.0,
        "ca.pem",
        addr,
        Some(&qlogs.0),
        |conn, cx, over, _| {
            let mut told = Told::default();
            run(conn, cx, over, &mut told, |t| t.checked.is_some()).unwrap();
            assert_eq!(told.checked, Some(Ok(())));
        },
    );
    let files: Vec<_> = std::fs::read_dir(&qlogs.0)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    let name = files[0].file_name().unwrap().to_str().unwrap();
    let id = name
        .strip_suffix(".sqlog")
        .unwrap_or_else(|| panic!("{name}"));
    assert_eq!(id.len(), 40, "{name}");
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{name}"
    );
    let qlog = std::fs::read(&files[0]).unwrap();
    let has = |what: &[u8]| qlog.windows(what.len()).any(|w| w == what);
    assert!(qlog.starts_with(b"\x1e{"), "{}", qlog.escape_ascii());
    assert!(has(b"\"title\":\"qlog title\""), "{}", qlog.escape_ascii());
    assert!(
        has(b"\"description\":\"curl qlog id="),
        "{}",
        qlog.escape_ascii()
    );
    assert!(has(b"packet_sent"), "{}", qlog.escape_ascii());
    assert!(has(b"packet_received"), "{}", qlog.escape_ascii());
}

/// A connection's handshake with caddy completes with its certificate
/// checked, then HTTP/3 is set up, and a GET on it is answered: the
/// status, the fields and the body arrive on the request's stream, which
/// closes.
#[test]
fn a_get_over_http3_is_answered() {
    let (told, notes) = get("get", "/data.txt");
    assert_eq!(told.status.as_deref(), Some(&b"200"[..]));
    assert!(
        told.headers
            .iter()
            .any(|(n, v)| n == b"content-length" && v == b"9"),
        "{:?}",
        told.headers
    );
    assert!(
        told.headers
            .iter()
            .any(|(n, v)| n == b"x-big" && *v == big_field().as_bytes()),
        "a field over quiche's own limit"
    );
    assert_eq!(told.body, BODY);
    assert!(notes.iter().any(|n| n.contains(VERIFIED)), "{notes:?}");
    assert!(
        notes.iter().any(|n| n.contains("handshake complete after")),
        "{notes:?}"
    );
}

/// A body larger than C's buffer of eight 16 KiB chunks arrives whole, in
/// order, handed on no more than a chunk at a time
/// (`cf_quiche_recv_body`, `cf_quiche_flush_body`).
#[test]
fn a_large_body_is_handed_on_a_chunk_at_a_time() {
    let (told, _) = get("big", "/big.bin");
    assert_eq!(told.status.as_deref(), Some(&b"200"[..]));
    assert!(told.body == big(), "{} bytes", told.body.len());
    assert!(
        told.pieces.iter().all(|&n| n <= 16 * 1024),
        "{:?}",
        told.pieces
    );
    assert!(told.pieces.contains(&(16 * 1024)), "{:?}", told.pieces);
}

/// A peer whose certificate the CA trusted did not sign fails as quiche's
/// filter fails it: the connection is established, then the check's
/// verdict is told, and no HTTP/3 is set up over it.
#[test]
fn an_untrusted_peer_fails_its_check_once_established() {
    let (told, notes) = with_conn("untrusted", "other-ca.pem", |conn, cx, over, _| {
        let mut told = Told::default();
        let r = run(conn, cx, over, &mut told, |t| t.checked.is_some());
        assert!(!conn.handshake_done(), "no HTTP/3 over an unchecked peer");
        r.map(|()| told)
    });
    let told = told.unwrap_or_else(|e| panic!("{e:?}: {notes:#?}"));
    assert_eq!(told.checked, Some(Err(ErrorKind::PeerFailedVerification)));
    assert!(notes.iter().any(|n| n.contains(UNTRUSTED)), "{notes:?}");
}

/// Two GETs on one connection, open at once, are each answered on a
/// stream of its own: the second quiche's stream 4. The streams the peer
/// allows are told counting those opened, so the room each opened takes
/// does not shrink it: caddy allows 100 (`cf_quiche_query`'s
/// `CF_QUERY_MAX_CONCURRENT`).
#[test]
fn two_gets_on_one_connection_are_answered_each_on_its_stream() {
    let (told, _) = with_conn("two", "ca.pem", |conn, cx, over, addr| {
        let mut told = Told::default();
        run(conn, cx, over, &mut told, |t| t.checked.is_some()).unwrap();
        let authority = format!("localhost:{}", addr.port());
        let mut streams = Vec::new();
        for path in ["/data.txt", "/big.bin"] {
            let fields: [(&[u8], &[u8]); 4] = [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.as_bytes()),
                (b":path", path.as_bytes()),
            ];
            streams.push(conn.submit_request(&fields, false).unwrap());
        }
        assert_eq!(streams, [StreamId(0), StreamId(4)]);
        run(conn, cx, over, &mut told, |t| t.closed_streams.len() == 2).unwrap();
        told
    });
    let body = |id| {
        told.bodies
            .iter()
            .find(|(s, _)| *s == StreamId(id))
            .map(|(_, b)| b.clone())
    };
    assert_eq!(body(0).as_deref(), Some(BODY));
    assert!(body(4) == Some(big()), "the second stream's body");
    assert!(!told.max_streams.is_empty(), "the peer's room told");
    assert!(
        told.max_streams.iter().all(|&n| n >= 100),
        "{:?}",
        told.max_streams
    );
}

/// A GET cancelled as its body arrives is heard of no more: quiche stops
/// reading the stream and the request is gone, while a GET after it on
/// the same connection is answered (`cf_quiche_stream_close`).
#[test]
fn a_cancelled_get_is_heard_of_no_more() {
    let (told, _) = with_conn("cancel", "ca.pem", |conn, cx, over, addr| {
        let mut told = Told::default();
        run(conn, cx, over, &mut told, |t| t.checked.is_some()).unwrap();
        let authority = format!("localhost:{}", addr.port());
        let get = |path: &'static str| -> [(&'static [u8], Vec<u8>); 4] {
            [
                (b":method", b"GET".to_vec()),
                (b":scheme", b"https".to_vec()),
                (b":authority", authority.as_bytes().to_vec()),
                (b":path", path.as_bytes().to_vec()),
            ]
        };
        let fields = get("/big.bin");
        let fields: Vec<(&[u8], &[u8])> = fields.iter().map(|(n, v)| (*n, &v[..])).collect();
        let first = conn.submit_request(&fields, false).unwrap();
        run(conn, cx, over, &mut told, |t| !t.bodies.is_empty()).unwrap();
        conn.cancel(first, H3Error(0x10c));
        let heard = told.body.len();
        let fields = get("/data.txt");
        let fields: Vec<(&[u8], &[u8])> = fields.iter().map(|(n, v)| (*n, &v[..])).collect();
        let second = conn.submit_request(&fields, false).unwrap();
        run(conn, cx, over, &mut told, |t| {
            t.closed_streams.contains(&second)
        })
        .unwrap();
        // What was in flight as it was cancelled has had time to come.
        let until = StdInstant::now() + Duration::from_millis(300);
        run(conn, cx, over, &mut told, |_| StdInstant::now() > until).unwrap();
        (told, first, heard)
    });
    let (told, first, heard) = told;
    let of_first = told
        .bodies
        .iter()
        .find(|(s, _)| *s == first)
        .map_or(0, |(_, b)| b.len());
    assert_eq!(of_first, heard, "nothing of the cancelled stream after");
    assert!(
        !told.closed_streams.contains(&first),
        "{:?}",
        told.closed_streams
    );
}
