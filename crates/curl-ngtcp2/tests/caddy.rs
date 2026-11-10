//! The connection against a real HTTP/3 server: caddy, which the test
//! starts with certificates it makes, on a port it finds free. caddy must
//! be installed; a run without it fails rather than skips.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::cell::RefCell;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant as StdInstant};

use curl_alloc::TryArc;
use curl_core::error::ErrorKind;
use curl_core::http3::{
    ClientSetup, ConnEvent, Connection, EarlyStart, Event, Expiry, Heard, Http3, Layer, QlogDir,
    QuicError, StreamEvent, StreamId,
};
use curl_core::options::{CaSetting, ColdGroup as _, FileMode, TlsOptions};
use curl_core::time::SystemClock;
use curl_core::tls::{
    CaDefaults, Kept, Notes, TlsBackend, TlsCx, TlsIdentity, TlsPeer, TlsPeerKind,
};
use curl_ngtcp2::NGTCP2;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::symm::{Cipher, Crypter, Mode as CipherMode, decrypt_aead};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509, X509Name};

const BODY: &[u8] = b"hello h3\n";

/// The TLS library the build has the QUIC crypto of, initialised.
#[cfg(feature = "gnutls")]
fn tls() -> &'static dyn TlsBackend {
    &curl_gnutls::GNUTLS
}
#[cfg(feature = "openssl")]
fn tls() -> &'static dyn TlsBackend {
    &curl_openssl::OPENSSL
}
#[cfg(feature = "wolfssl")]
fn tls() -> &'static dyn TlsBackend {
    static WOLFSSL: curl_wolfssl::WolfSsl = curl_wolfssl::WolfSsl::new();
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| assert!(WOLFSSL.init()));
    &WOLFSSL
}

/// What the library says of a peer it verified, and of one signed by a
/// CA it does not trust.
#[cfg(feature = "gnutls")]
const VERIFIED: &str = "SSL certificate verified by GnuTLS";
#[cfg(feature = "gnutls")]
const UNTRUSTED: &str = "SSL certificate verification failed: certificate signer not trusted.";
#[cfg(feature = "openssl")]
const VERIFIED: &str = "SSL certificate verified via OpenSSL";
#[cfg(feature = "openssl")]
const UNTRUSTED: &str =
    "SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)";
// wolfSSL's check says nothing of a peer it verified, as C's
// (`Curl_vquic_tls_verify_peer`): the handshake is reported alone.
#[cfg(feature = "wolfssl")]
const VERIFIED: &str = "SSL connection using TLSv1.3 / ";

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
/// When the certificates are valid from: 1970, the time of day of the
/// tests' transfer, by which a library that checks the dates itself
/// (GnuTLS's) checks them.
fn since() -> Asn1Time {
    Asn1Time::from_unix(0).unwrap()
}

fn certs(dir: &Path) {
    let ca_key = key();
    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    ca.set_subject_name(&name("curl-ngtcp2 test CA")).unwrap();
    ca.set_issuer_name(&name("curl-ngtcp2 test CA")).unwrap();
    ca.set_pubkey(&ca_key).unwrap();
    ca.set_not_before(&since()).unwrap();
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
    cert.set_not_before(&since()).unwrap();
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
    other.set_not_before(&since()).unwrap();
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
    /// Whether the early data sent was taken, if any was sent.
    early: Option<Option<bool>>,
}

impl Told {
    fn hear(&mut self, event: &Event<'_>) -> Heard {
        match *event {
            Event::Connection(ConnEvent::HandshakeDone {
                checked,
                early_data,
                ..
            }) => {
                self.checked = Some(checked);
                self.early = Some(early_data);
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
            Event::Stream(_, StreamEvent::Data(bytes)) => self.body.extend_from_slice(bytes),
            Event::Stream(_, StreamEvent::Closed(_)) => self.closed = true,
            Event::Connection(ConnEvent::H3Failed(failed)) => panic!("{failed}"),
            _ => {}
        }
        Heard::Fine
    }
}

/// What a test drives a connection with, and the datagrams it sent.
struct Over<'s> {
    sock: &'s UdpSocket,
    clock: &'s SystemClock,
    sent: RefCell<Vec<Vec<u8>>>,
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
        over.sent.borrow_mut().push(buf[..n].to_vec());
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
                let packets = buf[..n].chunks(n.max(1));
                conn.read_packets(cx, now, from, 0, packets, &mut |_, e| told.hear(e))?;
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
    with_conn_qlog(test, ca, None, f)
}

/// `with_conn`, the connection writing its qlog to `qlog` if given.
fn with_conn_qlog<R>(
    test: &str,
    ca: &str,
    qlog: Option<&Path>,
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
        let tls = tls()
            .quic_session(
                &identity,
                &peer,
                shared,
                &|ctx| NGTCP2.setup_tls_context(ctx),
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
            qlog: qlog.map(|d| {
                let dir = d.as_os_str().as_encoded_bytes();
                QlogDir::new(dir, FileMode::default()).unwrap()
            }),
        };
        let mut conn = NGTCP2.client(&setup, tls).unwrap();
        let over = Over {
            sock: &sock,
            clock: &clock,
            sent: RefCell::default(),
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
    assert!(notes.iter().any(|n| n.contains(VERIFIED)), "{notes:?}");
}

/// With a directory for qlogs, the connection writes ngtcp2's qlog of
/// itself to a file in it named after its source id, in hex, as C's
/// `Curl_qlogdir` names it: the trace's start, then the packets.
#[test]
fn a_connection_writes_its_qlog_to_the_directory_given() {
    let qlogs = Dir(std::env::temp_dir().join(format!("curl-ngtcp2-qlogs-{}", std::process::id())));
    std::fs::create_dir_all(&qlogs.0).unwrap();
    let ((), _) = with_conn_qlog("qlog", "ca.pem", Some(&qlogs.0), |conn, cx, over, _| {
        let mut told = Told::default();
        run(conn, cx, over, &mut told, |t| t.checked.is_some()).unwrap();
        assert_eq!(told.checked, Some(Ok(())));
    });
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
    let start = b"\x1e{\"qlog_format\":\"JSON-SEQ\",\"qlog_version\":\"0.3\",";
    assert!(qlog.starts_with(start), "{}", qlog.escape_ascii());
    let has = |what: &[u8]| qlog.windows(what.len()).any(|w| w == what);
    assert!(
        has(b"\"name\":\"transport:packet_sent\""),
        "{}",
        qlog.escape_ascii()
    );
    assert!(
        has(b"\"name\":\"transport:packet_received\""),
        "{}",
        qlog.escape_ascii()
    );
}

/// A directory for qlogs that is not there leaves the connection without
/// one, and the handshake goes on, as C's goes on without its file.
#[test]
fn a_qlog_directory_not_there_writes_none_and_connects() {
    let qlogs = std::env::temp_dir().join(format!("curl-ngtcp2-no-qlogs-{}", std::process::id()));
    let ((), _) = with_conn_qlog("noqlog", "ca.pem", Some(&qlogs), |conn, cx, over, _| {
        let mut told = Told::default();
        run(conn, cx, over, &mut told, |t| t.checked.is_some()).unwrap();
        assert_eq!(told.checked, Some(Ok(())));
    });
    assert!(!qlogs.exists());
}

/// A peer whose certificate the CA trusted did not sign fails the
/// handshake inside ngtcp2's callback: the check's verdict is told, then
/// the packet's reading fails as the callback did, as C's
/// `tls_vrfy_result` is set before `ngtcp2_conn_read_pkt` fails.
#[cfg(not(feature = "wolfssl"))]
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
    assert!(notes.iter().any(|n| n.contains(UNTRUSTED)), "{notes:?}");
}

/// Over wolfSSL, which verifies the peer's chain itself, an untrusted
/// peer fails the handshake inside the library: the packet's reading
/// fails as ngtcp2's crypto says, the handshake is never done, and the
/// check never runs.
#[cfg(feature = "wolfssl")]
#[test]
fn an_untrusted_peer_fails_the_handshake_inside_the_library() {
    let ((told, failed), notes) = with_conn("untrusted", "other-ca.pem", |conn, cx, over, _| {
        let mut told = Told::default();
        let failed = run(conn, cx, over, &mut told, |_| false).unwrap_err();
        assert!(!conn.handshake_done());
        (told, failed)
    });
    assert_eq!(told.checked, None, "{notes:?}");
    assert_eq!(
        (failed.layer, failed.call, failed.text),
        (Layer::Crypto, "ngtcp2_conn_read_pkt", "ERR_CRYPTO")
    );
    assert!(
        !notes
            .iter()
            .any(|n| n.starts_with("info: SSL connection using")),
        "{notes:?}"
    );
}

/// The authority of a request to caddy at `addr`.
fn authority(addr: SocketAddr) -> String {
    format!("localhost:{}", addr.port())
}

/// QUIC version 1's salt for its Initial secrets (RFC 9001, 5.2).
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// The TLS extensions the tests look for (RFC 7301, RFC 8446).
const ALPN: u16 = 16;
const EARLY_DATA: u16 = 42;

fn hmac(key: &[u8], data: &[&[u8]]) -> Vec<u8> {
    let key = PKey::hmac(key).unwrap();
    let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &key).unwrap();
    for d in data {
        signer.update(d).unwrap();
    }
    signer.sign_to_vec().unwrap()
}

/// TLS 1.3's `HKDF-Expand-Label` with no context, for at most one hash's
/// length.
fn expand_label(secret: &[u8], label: &str, len: u8) -> Vec<u8> {
    let label = format!("tls13 {label}");
    let info = [&[0, len, label.len() as u8][..], label.as_bytes(), &[0]].concat();
    let mut out = hmac(secret, &[&info, &[1]]);
    out.truncate(len.into());
    out
}

/// A QUIC variable-length integer at the start of `b`, and what follows.
fn varint(b: &[u8]) -> (u64, &[u8]) {
    let len = 1 << (b[0] >> 6);
    let v = b[1..len]
        .iter()
        .fold(u64::from(b[0] & 0x3f), |v, &x| v << 8 | u64::from(x));
    (v, &b[len..])
}

/// The first `n` bytes of `b`, and what follows.
fn take(b: &[u8], n: impl TryInto<usize>) -> (&[u8], &[u8]) {
    let n = n.try_into().ok().unwrap();
    (&b[..n], &b[n..])
}

/// The ClientHello the client sent in the Initial packets among `sent`,
/// the datagrams of a connection, decrypted with the keys of the
/// Destination Connection ID it first chose (RFC 9001, 5).
fn client_hello(sent: &[Vec<u8>]) -> Vec<u8> {
    let dcid = &sent[0][6..6 + usize::from(sent[0][5])];
    let initial = hmac(&INITIAL_SALT, &[dcid]);
    let secret = expand_label(&initial, "client in", 32);
    let key = expand_label(&secret, "quic key", 16);
    let iv = expand_label(&secret, "quic iv", 12);
    let hp = expand_label(&secret, "quic hp", 16);
    let mut crypto = Vec::new();
    for datagram in sent {
        let mut rest = &datagram[..];
        // Long-header packets, each its length long; a short header ends
        // the datagram.
        while rest.first().is_some_and(|b| b & 0x80 != 0) {
            let initial = rest[0] & 0x30 == 0;
            let (_, after) = take(rest, 5);
            let (_, after) = take(after, after[0] + 1);
            let (_, after) = take(after, after[0] + 1);
            let after = if initial {
                let (token, after) = varint(after);
                take(after, token).1
            } else {
                after
            };
            let (length, after) = varint(after);
            let pn_at = rest.len() - after.len();
            let (packet, next) = take(rest, pn_at + usize::try_from(length).unwrap());
            rest = next;
            // The client's Initial packets are all sealed with the keys
            // of the first Destination Connection ID.
            if !initial {
                continue;
            }
            let mut packet = packet.to_vec();
            let mut ecb =
                Crypter::new(Cipher::aes_128_ecb(), CipherMode::Encrypt, &hp, None).unwrap();
            ecb.pad(false);
            let mut mask = [0u8; 32];
            ecb.update(&packet[pn_at + 4..pn_at + 20], &mut mask)
                .unwrap();
            packet[0] ^= mask[0] & 0x0f;
            let pn_len = usize::from(packet[0] & 3) + 1;
            let mut nonce = iv.clone();
            for i in 0..pn_len {
                packet[pn_at + i] ^= mask[1 + i];
                nonce[12 - pn_len + i] ^= packet[pn_at + i];
            }
            let (header, body) = packet.split_at(pn_at + pn_len);
            let (sealed, tag) = body.split_at(body.len() - 16);
            let plain = decrypt_aead(
                Cipher::aes_128_gcm(),
                &key,
                Some(&nonce),
                header,
                sealed,
                tag,
            )
            .unwrap();
            let mut frames = &plain[..];
            while let Some(&kind) = frames.first() {
                frames = &frames[1..];
                match kind {
                    // PADDING, PING.
                    0 | 1 => {}
                    // ACK, with ECN counts or without.
                    2 | 3 => {
                        let (_, f) = varint(frames);
                        let (_, f) = varint(f);
                        let (ranges, f) = varint(f);
                        let (_, mut f) = varint(f);
                        for _ in 0..2 * ranges + if kind == 3 { 3 } else { 0 } {
                            f = varint(f).1;
                        }
                        frames = f;
                    }
                    // CRYPTO.
                    6 => {
                        let (offset, f) = varint(frames);
                        let (len, f) = varint(f);
                        let (data, f) = take(f, len);
                        let offset = usize::try_from(offset).unwrap();
                        if crypto.len() < offset + data.len() {
                            crypto.resize(offset + data.len(), 0);
                        }
                        crypto[offset..offset + data.len()].copy_from_slice(data);
                        frames = f;
                    }
                    _ => panic!("frame {kind} in a client's Initial"),
                }
            }
        }
    }
    assert_eq!(crypto[0], 1, "a ClientHello");
    let len = crypto[1..4].iter().fold(0, |v, &x| v << 8 | usize::from(x));
    crypto.truncate(4 + len);
    crypto
}

/// The data of the extension `kind` in the ClientHello `hello`.
fn extension(hello: &[u8], kind: u16) -> Option<&[u8]> {
    // The version and the random.
    let (_, b) = take(&hello[4..], 34);
    let (_, b) = take(&b[1..], b[0]);
    let (_, b) = take(&b[2..], u16::from_be_bytes([b[0], b[1]]));
    let (_, b) = take(&b[1..], b[0]);
    let (mut exts, _) = take(&b[2..], u16::from_be_bytes([b[0], b[1]]));
    while !exts.is_empty() {
        let at = u16::from_be_bytes([exts[0], exts[1]]);
        let (data, rest) = take(&exts[4..], u16::from_be_bytes([exts[2], exts[3]]));
        if at == kind {
            return Some(data);
        }
        exts = rest;
    }
    None
}

/// The protocols the ClientHello `hello` offers by ALPN.
fn alpn_offer(hello: &[u8]) -> Vec<&[u8]> {
    let list = extension(hello, ALPN).expect("an ALPN offer");
    let mut names = &list[2..];
    let mut out = Vec::new();
    while !names.is_empty() {
        let (name, rest) = take(&names[1..], names[0]);
        out.push(name);
        names = rest;
    }
    out
}

/// A second connection to caddy resumes the session the first was given
/// and sends its GET as early data, which caddy takes: the session
/// allows early data for a transfer asking for it, the transport
/// parameters kept with it are set, HTTP/3 is set up at once and the
/// TLS library sends early data (`cf_ngtcp2_on_session_reuse`); the
/// handshake's end says the early data was not rejected. Parameters the library cannot
/// read are refused. Read from the ClientHello in each connection's
/// Initial packets, the first offers `h3,h3-29` by ALPN and the second,
/// sending early data, `h3` alone with the early data extension, as C's
/// connections do.
#[test]
fn a_resumed_session_sends_its_get_as_early_data() {
    let dir = Dir(std::env::temp_dir().join(format!("curl-ngtcp2-early-{}", std::process::id())));
    std::fs::create_dir_all(&dir.0).unwrap();
    certs(&dir.0);
    let (_server, addr) = caddy(&dir.0);
    let ca = dir.0.join("ca.pem").into_os_string().into_encoded_bytes();
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
        early_data: true,
        ech_configs: None,
    };
    let authority = authority(addr);
    let fields: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", authority.as_bytes()),
        (b":path", b"/data.txt"),
    ];
    let mut kept = Kept::new();
    let told = TlsCx::testing_kept(&identity, b"localhost", &mut kept, |shared, cx| {
        let clock = SystemClock::new();
        let connect = |cx: &mut TlsCx<'_>, early: bool| {
            let tls = tls()
                .quic_session(
                    &identity,
                    &peer,
                    shared,
                    &|ctx| NGTCP2.setup_tls_context(ctx),
                    cx,
                )
                .unwrap();
            let params = tls.early_data().map(|t| t.quic_params.clone());
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
                qlog: None,
            };
            let mut conn = NGTCP2.client(&setup, tls).unwrap();
            let over = Over {
                sock: &sock,
                clock: &clock,
                sent: RefCell::default(),
            };
            let mut told = Told::default();
            if early {
                let params = params.expect("the session resumed allows early data");
                assert!(conn.set_early_params(b"\xff\xff").is_err());
                conn.set_early_params(&params).unwrap();
                assert!(matches!(conn.start_early(), Ok(EarlyStart::Started)));
                conn.early_data_decided(cx, true).unwrap();
                conn.submit_request(&fields, false).unwrap();
            } else {
                assert!(params.is_none(), "nothing to resume yet");
                run(&mut *conn, cx, &over, &mut told, |t| t.checked.is_some()).unwrap();
                conn.submit_request(&fields, false).unwrap();
            }
            run(&mut *conn, cx, &over, &mut told, |t| t.closed).unwrap();
            (told, client_hello(&over.sent.into_inner()))
        };
        // The first offers every protocol, and no early data.
        let (first, hello) = connect(cx, false);
        assert_eq!(first.early, Some(None));
        assert_eq!(alpn_offer(&hello), [&b"h3"[..], b"h3-29"]);
        assert!(extension(&hello, EARLY_DATA).is_none());
        // Over AWS-LC and BoringSSL the session resumed allows none, as
        // C's build over them sends none (`HAVE_OPENSSL_EARLYDATA` unset).
        let early = !cfg!(crypto = "boringssl");
        let (second, hello) = connect(cx, early);
        // Sending early data, the second offers the ticket's protocol
        // alone (`Curl_alpn_restrict_to` after `sess_reuse_cb`).
        if early {
            assert_eq!(alpn_offer(&hello), [&b"h3"[..]]);
            assert!(extension(&hello, EARLY_DATA).is_some());
        }
        second
    });
    assert_eq!(told.checked, Some(Ok(())));
    let early = (!cfg!(crypto = "boringssl")).then_some(true);
    assert_eq!(told.early, Some(early), "{:?}", kept.notes);
    // The second resumed the first's session, early data or not.
    #[cfg(feature = "openssl")]
    assert!(
        kept.notes
            .0
            .iter()
            .any(|n| n.contains("SSL reusing session")),
        "{:?}",
        kept.notes
    );
    assert_eq!(told.status.as_deref(), Some(&b"200"[..]));
    assert_eq!(told.body, BODY);
}
