//! What the tests against a server share: the certificates they make, a
//! client connection over the OpenSSL backend's session to the server,
//! and the loop that drives it.

// Each test binary uses its own part of it.
#![allow(dead_code)]

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant as StdInstant};

use curl_alloc::TryArc;
use curl_core::error::ErrorKind;
use curl_core::http3::{
    ClientSetup, ConnEvent, Connection, Event, Expiry, Heard, Http3, QuicError, StreamEvent,
    StreamId,
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
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509, X509Name};

/// What the OpenSSL backend says of a peer it verified, and of one signed
/// by a CA it does not trust.
pub const VERIFIED: &str = "SSL certificate verified via OpenSSL";
pub const UNTRUSTED: &str =
    "SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)";

/// A directory of the test's own, removed as this goes.
pub struct Dir(pub PathBuf);

impl Dir {
    /// A new one for `test`, of this process.
    pub fn new(test: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!("curl-quiche-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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

/// A CA, and a certificate for `localhost` it signed, written to `dir`
/// (`ca.pem`, `cert.pem`, `key.pem`); a CA that signed nothing,
/// `other-ca.pem`; and a certificate it signed for an RSA key that says
/// the key may not sign, `ku-cert.pem`, with its key, `ku-key.pem`
/// (BoringSSL refuses to serve an EC key that may not sign; RSA's it
/// serves, which the peer then refuses).
pub fn certs(dir: &Path) {
    let ca_key = key();
    let ca = ca("curl-quiche test CA", 1, &ca_key);
    let key = key();
    let leaf = |serial: u32, key: &PKey<Private>, signs: bool| {
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        let serial = BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap();
        cert.set_serial_number(&serial).unwrap();
        cert.set_subject_name(&name("localhost")).unwrap();
        cert.set_issuer_name(ca.subject_name()).unwrap();
        cert.set_pubkey(key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .build(&cert.x509v3_context(Some(&ca), None))
            .unwrap();
        cert.append_extension(san).unwrap();
        if !signs {
            let usage = KeyUsage::new()
                .critical()
                .key_encipherment()
                .build()
                .unwrap();
            cert.append_extension(usage).unwrap();
        }
        cert.sign(&ca_key, MessageDigest::sha256()).unwrap();
        cert.build().to_pem().unwrap()
    };
    std::fs::write(dir.join("ca.pem"), ca.to_pem().unwrap()).unwrap();
    let other = self::ca("curl-quiche other CA", 3, &self::key());
    std::fs::write(dir.join("other-ca.pem"), other.to_pem().unwrap()).unwrap();
    std::fs::write(dir.join("cert.pem"), leaf(2, &key, true)).unwrap();
    std::fs::write(dir.join("key.pem"), key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    std::fs::write(dir.join("ku-cert.pem"), leaf(4, &rsa, false)).unwrap();
    std::fs::write(
        dir.join("ku-key.pem"),
        rsa.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
}

/// What a connection told.
#[derive(Default)]
pub struct Told {
    pub checked: Option<Result<(), ErrorKind>>,
    pub status: Option<Vec<u8>>,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub head_done: bool,
    pub body: Vec<u8>,
    /// The size of each piece of the body, as it was handed on.
    pub pieces: Vec<usize>,
    pub closed: bool,
    /// The streams the peer allows, opened ones counted, as each was told.
    pub max_streams: Vec<u64>,
    /// Each stream's body, and the streams closed, in order.
    pub bodies: Vec<(StreamId, Vec<u8>)>,
    pub closed_streams: Vec<StreamId>,
    /// The streams told they may send again, in order.
    pub unblocked: Vec<StreamId>,
}

impl Told {
    pub fn hear(&mut self, event: &Event<'_>) -> Heard {
        match *event {
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
            Event::Stream(stream, StreamEvent::Unblocked) => self.unblocked.push(stream),
            Event::Connection(ConnEvent::MaxBidiStreams(n)) => self.max_streams.push(n),
            Event::Connection(ConnEvent::H3Failed(failed)) => panic!("{failed}"),
            _ => {}
        }
        Heard::Fine
    }
}

/// What a test drives a connection with.
pub struct Over<'s> {
    pub sock: &'s UdpSocket,
    pub clock: &'s SystemClock,
}

/// Send every packet the connection wants sent, then let it see what
/// that came to, as the core's egress does.
pub fn flush(
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

/// One datagram, if one comes before the connection's timer is due or
/// a tenth of a second passes, read and its events polled.
pub fn take_one(
    conn: &mut dyn Connection,
    cx: &mut TlsCx<'_>,
    over: &Over<'_>,
    told: &mut Told,
) -> Result<bool, QuicError> {
    let mut buf = [0u8; 65536];
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
            Ok(true)
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(false)
        }
        Err(e) => panic!("recv: {e}"),
    }
}

/// Run the connection until `done`, its timers kept and what arrives fed
/// to it, each datagram's events polled once it is read, or until it
/// fails.
pub fn run(
    conn: &mut dyn Connection,
    cx: &mut TlsCx<'_>,
    over: &Over<'_>,
    told: &mut Told,
    done: impl Fn(&Told) -> bool,
) -> Result<(), QuicError> {
    let deadline = StdInstant::now() + Duration::from_secs(10);
    while !done(told) {
        assert!(StdInstant::now() < deadline, "the exchange takes too long");
        flush(conn, cx, over, told)?;
        take_one(conn, cx, over, told)?;
        if conn.expiry(over.clock.now()) == Expiry::Due {
            conn.handle_expiry(cx, over.clock.now(), &mut |_, e| told.hear(e))?;
        }
    }
    Ok(())
}

/// Run `f` with a connection to the server at `addr` that trusts the CA
/// file `ca` names in `dir`: what `f` returns, and the notes the transfer
/// was given.
pub fn with_client<R>(
    dir: &Path,
    ca: &str,
    addr: SocketAddr,
    f: impl FnOnce(&mut dyn Connection, &mut TlsCx<'_>, &Over<'_>, SocketAddr) -> R,
) -> (R, Vec<String>) {
    let ca = dir.join(ca).into_os_string().into_encoded_bytes();
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

/// A request's fields: `method` of `path`, to `addr`'s port on
/// `localhost`.
pub fn request(method: &str, path: &str, addr: SocketAddr) -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (b":method".to_vec(), method.as_bytes().to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (
            b":authority".to_vec(),
            format!("localhost:{}", addr.port()).into_bytes(),
        ),
        (b":path".to_vec(), path.as_bytes().to_vec()),
    ]
}

/// `fields` as a connection takes them.
pub fn refs(fields: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
    fields.iter().map(|(n, v)| (&n[..], &v[..])).collect()
}
