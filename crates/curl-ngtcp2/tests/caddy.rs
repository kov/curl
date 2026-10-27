//! The connection against a real HTTP/3 server: caddy, which the test
//! starts with certificates it makes, on a port it finds free. caddy must
//! be installed; a run without it fails rather than skips.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant as StdInstant};

use curl_alloc::TryArc;
use curl_core::error::ErrorKind;
use curl_core::http3::{
    ClientSetup, Connection, Event, Expiry, Heard, Http3, Layer, QuicError, StreamId,
};
use curl_core::options::{CaSetting, ColdGroup as _, TlsOptions};
use curl_core::time::{Clock, SystemClock};
use curl_core::tls::{CaDefaults, Notes, TlsBackend, TlsCx, TlsIdentity, TlsPeer, TlsPeerKind};
use curl_ngtcp2::NGTCP2;
use curl_openssl::OPENSSL;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509, X509Name};

const BODY: &[u8] = b"hello h3\n";

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

/// A CA, and a certificate for `localhost` it signed, written to `dir`;
/// and a CA that signed nothing, `other-ca.pem`.
fn certs(dir: &Path) {
    let ca_key = key();
    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    ca.set_subject_name(&name("curl-ngtcp2 test CA")).unwrap();
    ca.set_issuer_name(&name("curl-ngtcp2 test CA")).unwrap();
    ca.set_pubkey(&ca_key).unwrap();
    ca.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    ca.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca = ca.build();
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
    let other_key = crate::key();
    let mut other = X509::builder().unwrap();
    other.set_version(2).unwrap();
    other
        .set_serial_number(&BigNum::from_u32(3).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    other
        .set_subject_name(&name("curl-ngtcp2 other CA"))
        .unwrap();
    other
        .set_issuer_name(&name("curl-ngtcp2 other CA"))
        .unwrap();
    other.set_pubkey(&other_key).unwrap();
    other
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    other
        .set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    other
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    other.sign(&other_key, MessageDigest::sha256()).unwrap();
    std::fs::write(dir.join("other-ca.pem"), other.build().to_pem().unwrap()).unwrap();
    std::fs::write(dir.join("cert.pem"), cert.build().to_pem().unwrap()).unwrap();
    std::fs::write(dir.join("key.pem"), key.private_key_to_pem_pkcs8().unwrap()).unwrap();
}

/// caddy serving `BODY` as `/data.txt` over HTTP/3 on a free port of
/// 127.0.0.1, from `dir`. A port found free may be taken before caddy
/// binds it, by another test or another run on the machine: caddy then
/// fails, and is started again on other ports.
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
    let d = dir.display();
    let conf = format!(
        "{{\n  http_port {tcp}\n  https_port {port}\n  admin off\n  log default {{\n    level ERROR\n  }}\n  \
         servers :{port} {{\n    protocols h3 h2 h1\n  }}\n}}\n\
         localhost:{port} {{\n  file_server * {{\n    root {d}/docs\n  }}\n  tls {d}/cert.pem {d}/key.pem\n}}\n"
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
        // The sockets bound to the port, by inode.
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
    body: Vec<u8>,
    closed: bool,
}

impl Told {
    fn hear(&mut self, event: Event<'_>) -> Heard {
        match event {
            Event::HandshakeDone { checked, .. } => self.checked = Some(checked),
            Event::Header {
                name,
                value,
                status,
                ..
            } => {
                if status {
                    self.status = Some(value.to_vec());
                } else {
                    self.headers.push((name.to_vec(), value.to_vec()));
                }
            }
            Event::Data { bytes, .. } => self.body.extend_from_slice(bytes),
            Event::Closed { .. } => self.closed = true,
            Event::H3Failed { why, .. } => panic!("{why}"),
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

/// Send every packet the connection wants sent.
fn flush(
    conn: &mut dyn Connection,
    cx: &mut TlsCx<'_>,
    over: &Over<'_>,
    told: &mut Told,
) -> Result<(), QuicError> {
    let mut buf = [0u8; 1500];
    loop {
        let n = conn.write_packet(cx, over.clock.now(), &mut buf, &mut |_, e| told.hear(e))?;
        let Some(n) = n else { return Ok(()) };
        over.sock.send(&buf[..n]).unwrap();
        conn.sent_at(over.clock.now());
    }
}

/// Run the connection until `done`, its timers kept and what arrives fed
/// to it, or until it fails.
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
                conn.read_packet(cx, now, from, 0, &buf[..n], &mut |_, e| told.hear(e))?;
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
    let dir = Dir(std::env::temp_dir().join(format!("curl-ngtcp2-{test}-{}", std::process::id())));
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
        ca_defaults: CaDefaults::default(),
    })
    .unwrap();
    let peer = TlsPeer {
        name: b"localhost",
        port: addr.port(),
        kind: TlsPeerKind::Name,
        early_data: false,
    };
    let mut notes = Notes::default();
    let r = TlsCx::testing(&identity, b"localhost", &mut notes, |shared, cx| {
        let clock = SystemClock::new();
        let tls = OPENSSL.quic_session(&identity, &peer, shared, cx).unwrap();
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
        let mut conn = NGTCP2.client(&setup, tls).unwrap();
        let over = Over {
            sock: &sock,
            clock: &clock,
        };
        f(&mut *conn, cx, &over, addr)
    });
    (r, notes.0)
}

/// A connection's handshake with caddy completes with its certificate
/// checked, and a GET on it is answered: the status, the fields and the
/// body arrive on the request's stream, which closes.
#[test]
fn a_get_over_http3_is_answered() {
    let (told, notes) = with_conn("get", "ca.pem", |conn, cx, over, addr| {
        let mut told = Told::default();
        run(conn, cx, over, &mut told, |t| t.checked.is_some()).unwrap();
        assert_eq!(told.checked, Some(Ok(())));
        assert!(conn.handshake_done());
        let authority = format!("localhost:{}", addr.port());
        let fields: [(&[u8], &[u8]); 4] = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", authority.as_bytes()),
            (b":path", b"/data.txt"),
        ];
        let stream = conn.submit_request(&fields, false).unwrap();
        assert_eq!(stream, StreamId(0));
        run(conn, cx, over, &mut told, |t| t.closed).unwrap();
        told
    });
    assert_eq!(told.status.as_deref(), Some(&b"200"[..]));
    assert!(
        told.headers
            .iter()
            .any(|(n, v)| n == b"content-length" && v == b"9"),
        "{:?}",
        told.headers
    );
    assert_eq!(told.body, BODY);
    assert!(
        notes
            .iter()
            .any(|n| n.contains("SSL certificate verified via OpenSSL")),
        "{notes:?}"
    );
}

/// A peer whose certificate the CA trusted did not sign fails the
/// handshake inside ngtcp2's callback: the check's verdict is told, then
/// the packet's reading fails as the callback did, as C's
/// `tls_vrfy_result` is set before `ngtcp2_conn_read_pkt` fails.
#[test]
fn an_untrusted_peer_fails_the_handshake_as_it_completes() {
    let ((told, failed), notes) = with_conn("untrusted", "other-ca.pem", |conn, cx, over, _| {
        let mut told = Told::default();
        let failed = run(conn, cx, over, &mut told, |_| false).unwrap_err();
        (told, failed)
    });
    assert_eq!(told.checked, Some(Err(ErrorKind::PeerFailedVerification)));
    assert_eq!(
        (failed.layer, failed.call),
        (Layer::Quic, "ngtcp2_conn_read_pkt")
    );
    assert_eq!(failed.text, "ERR_CALLBACK_FAILURE");
    assert!(
        notes.iter().any(|n| n.contains(
            "SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)"
        )),
        "{notes:?}"
    );
}
