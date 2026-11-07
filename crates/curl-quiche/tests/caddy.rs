//! The connection against a real HTTP/3 server: caddy, which the test
//! starts with certificates it makes, on a port it finds free, over the
//! OpenSSL backend's session on the BoringSSL quiche runs over. caddy must
//! be installed; a run without it fails rather than skips.

#![cfg(boringssl)]
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant as StdInstant};

use curl_alloc::TryArc;
use curl_core::error::ErrorKind;
use curl_core::http3::{
    ClientSetup, ConnEvent, Connection, Event, Expiry, H3Error, Heard, Http3, QuicError,
    StreamEvent, StreamId,
};
use curl_core::options::{CaSetting, ColdGroup as _, TlsOptions};
use curl_core::time::SystemClock;
use curl_core::tls::{CaDefaults, Notes, TlsBackend, TlsCx, TlsIdentity, TlsPeer, TlsPeerKind};
use curl_quiche::QUICHE;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509, X509Name};

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

/// What the OpenSSL backend says of a peer it verified, and of one signed
/// by a CA it does not trust.
const VERIFIED: &str = "SSL certificate verified via OpenSSL";
const UNTRUSTED: &str =
    "SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)";

/// A directory of the test's own, removed as this goes.
struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The server, killed as this goes.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn name(cn: &str) -> X509Name {
    let mut n = X509Name::builder().unwrap();
    n.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
    n.build()
}

/// A CA of `cn`, self-signed with `key`.
fn ca(cn: &str, serial: u32, key: &PKey<Private>) -> X509 {
    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    ca.set_subject_name(&name(cn)).unwrap();
    ca.set_issuer_name(&name(cn)).unwrap();
    ca.set_pubkey(key).unwrap();
    ca.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    ca.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.sign(key, MessageDigest::sha256()).unwrap();
    ca.build()
}

/// A CA, and a certificate for `localhost` it signed, written to `dir`;
/// and a CA that signed nothing, `other-ca.pem`.
fn certs(dir: &Path) {
    let ca_key = key();
    let ca = ca("curl-quiche test CA", 1, &ca_key);
    let key = key();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name("localhost")).unwrap();
    cert.set_issuer_name(ca.subject_name()).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&cert.x509v3_context(Some(&ca), None))
        .unwrap();
    cert.append_extension(san).unwrap();
    cert.sign(&ca_key, MessageDigest::sha256()).unwrap();
    std::fs::write(dir.join("ca.pem"), ca.to_pem().unwrap()).unwrap();
    let other = crate::ca("curl-quiche other CA", 3, &crate::key());
    std::fs::write(dir.join("other-ca.pem"), other.to_pem().unwrap()).unwrap();
    std::fs::write(dir.join("cert.pem"), cert.build().to_pem().unwrap()).unwrap();
    std::fs::write(dir.join("key.pem"), key.private_key_to_pem_pkcs8().unwrap()).unwrap();
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

/// What a connection told.
#[derive(Default)]
struct Told {
    checked: Option<Result<(), ErrorKind>>,
    status: Option<Vec<u8>>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    head_done: bool,
    body: Vec<u8>,
    /// The size of each piece of the body, as it was handed on.
    pieces: Vec<usize>,
    closed: bool,
    /// The streams the peer allows, opened ones counted, as each was told.
    max_streams: Vec<u64>,
    /// Each stream's body, and the streams closed, in order.
    bodies: Vec<(StreamId, Vec<u8>)>,
    closed_streams: Vec<StreamId>,
}

impl Told {
    fn hear(&mut self, event: Event<'_>) -> Heard {
        match event {
            Event::Connection(ConnEvent::HandshakeDone { checked, .. }) => {
                self.checked = Some(checked);
            }
            Event::Stream(
                _,
                StreamEvent::Header {
                    name,
                    value,
                    status,
                },
            ) => {
                if status {
                    self.status = Some(value.to_vec());
                } else {
                    self.headers.push((name.to_vec(), value.to_vec()));
                }
            }
            Event::Stream(_, StreamEvent::HeadersDone) => self.head_done = true,
            Event::Stream(stream, StreamEvent::Data(bytes)) => {
                assert!(self.head_done, "the body comes after the head");
                self.body.extend_from_slice(bytes);
                self.pieces.push(bytes.len());
                match self.bodies.iter_mut().find(|(s, _)| *s == stream) {
                    Some((_, body)) => body.extend_from_slice(bytes),
                    None => self.bodies.push((stream, bytes.to_vec())),
                }
            }
            Event::Stream(stream, StreamEvent::Closed(_)) => {
                self.closed = true;
                self.closed_streams.push(stream);
            }
            Event::Connection(ConnEvent::MaxBidiStreams(n)) => self.max_streams.push(n),
            Event::Connection(ConnEvent::H3Failed(failed)) => panic!("{failed}"),
            _ => {}
        }
        Heard::Fine
    }
}

/// What a test drives a connection with.
struct Over<'s> {
    sock: &'s UdpSocket,
    clock: &'s SystemClock,
}

/// Send every packet the connection wants sent, then let it see what
/// that came to, as the core's egress does.
fn flush(
    conn: &mut dyn Connection,
    cx: &mut TlsCx<'_>,
    over: &Over<'_>,
    told: &mut Told,
) -> Result<(), QuicError> {
    let mut buf = [0u8; 1500];
    loop {
        let n = conn.write_packet(cx, over.clock.now(), &mut buf, &mut |_, e| told.hear(e))?;
        let Some(n) = n else { break };
        over.sock.send(&buf[..n]).unwrap();
    }
    conn.egress_done(cx, over.clock.now(), &mut |_, e| told.hear(e))
}

/// Run the connection until `done`, its timers kept and what arrives fed
/// to it, each datagram's events polled once it is read, or until it
/// fails.
fn run(
    conn: &mut dyn Connection,
    cx: &mut TlsCx<'_>,
    over: &Over<'_>,
    told: &mut Told,
    done: impl Fn(&Told) -> bool,
) -> Result<(), QuicError> {
    let deadline = StdInstant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 65536];
    while !done(told) {
        assert!(StdInstant::now() < deadline, "the exchange takes too long");
        flush(conn, cx, over, told)?;
        let wait = match conn.expiry(over.clock.now()) {
            Expiry::Never => Duration::from_millis(100),
            Expiry::Due => Duration::from_millis(1),
            Expiry::In(d) => d.clamp(Duration::from_millis(1), Duration::from_millis(100)),
        };
        over.sock.set_read_timeout(Some(wait)).unwrap();
        conn.before_recv(cx).unwrap();
        match over.sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let now = over.clock.now();
                let packets = buf[..n].chunks(n.max(1));
                conn.read_packets(cx, now, from, 0, packets, &mut |_, e| told.hear(e))?;
                conn.ingress_done(cx, &mut |_, e| told.hear(e))?;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => panic!("recv: {e}"),
        }
        if conn.expiry(over.clock.now()) == Expiry::Due {
            conn.handle_expiry(cx, over.clock.now(), &mut |_, e| told.hear(e))?;
        }
    }
    Ok(())
}

/// Start caddy in a directory of `test`'s own, and run `f` with a
/// connection to it that trusts the CA file `ca` names there: what `f`
/// returns, and the notes the transfer was given.
fn with_conn<R>(
    test: &str,
    ca: &str,
    f: impl FnOnce(&mut dyn Connection, &mut TlsCx<'_>, &Over<'_>, SocketAddr) -> R,
) -> (R, Vec<String>) {
    let dir = Dir(std::env::temp_dir().join(format!("curl-quiche-{test}-{}", std::process::id())));
    std::fs::create_dir_all(&dir.0).unwrap();
    certs(&dir.0);
    let (_server, addr) = caddy(&dir.0);
    let ca = dir.0.join(ca).into_os_string().into_encoded_bytes();
    let identity = TryArc::try_new(TlsIdentity {
        verify_peer: true,
        verify_host: true,
        options: TlsOptions {
            ca_file: CaSetting::Given(ca),
            ..TlsOptions::NONE
        },
        ca_defaults: CaDefaults::NONE,
    })
    .unwrap();
    let peer = TlsPeer {
        name: b"localhost",
        port: addr.port(),
        kind: TlsPeerKind::Name,
        early_data: false,
        ech_configs: None,
    };
    let mut notes = Notes::default();
    let r = TlsCx::testing(&identity, b"localhost", &mut notes, |shared, cx| {
        let clock = SystemClock::new();
        let backend: &dyn TlsBackend = &curl_openssl::OPENSSL;
        let tls = backend
            .quic_session(
                &identity,
                &peer,
                shared,
                &|ctx| QUICHE.setup_tls_context(ctx),
                cx,
            )
            .unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect(addr).unwrap();
        let setup = ClientSetup {
            local: sock.local_addr().unwrap(),
            remote: addr,
            now: clock.now(),
            handshake_timeout: Duration::from_secs(10),
            max_window: 100 * 10 * 1024 * 1024,
            stream_window: 32 * 1024,
            max_streams: 256 * 1024,
        };
        let mut conn = QUICHE.client(&setup, tls).unwrap();
        let over = Over {
            sock: &sock,
            clock: &clock,
        };
        // A failed check is shown with the notes that explain it.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f(&mut *conn, cx, &over, addr)
        }))
    });
    match r {
        Ok(r) => (r, notes.0),
        Err(panic) => {
            eprintln!("notes: {:#?}", notes.0);
            std::panic::resume_unwind(panic)
        }
    }
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
