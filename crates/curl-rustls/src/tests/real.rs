//! The session over the real library against a rustls server in the same
//! thread, the records carried between them by hand: what rustls itself
//! makes of the calls the session makes.

use std::io::{Read as _, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use curl_alloc::TryArc;
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::options::CaSetting;
use curl_core::tls::{
    Alpn, Chosen, Goodbye, Handshake, Kept, TlsIdentity, TlsIo, TlsPeer, TlsPeerKind,
    TlsSession as _,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};

use super::{has, identity, lines};
use crate::fake::Wire;
use crate::library::Rustls as _;
use crate::result::Code;
use crate::rustls::{RUSTLS, Real};
use crate::session::Session;

/// A CA, and a server's certificate and key for `names` it signed.
struct Pki {
    ca: String,
    chain: Vec<CertificateDer<'static>>,
    /// The server's certificate, as PEM.
    cert: String,
    key: String,
}

fn pki(names: &[&str]) -> Pki {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // Each CA a name of its own: one CA's certificate is not taken for
    // another's.
    static CAS: AtomicUsize = AtomicUsize::new(0);
    let n = CAS.fetch_add(1, Ordering::Relaxed);
    params
        .distinguished_name
        .push(DnType::CommonName, format!("test CA {n}"));
    let ca_key = KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(params, ca_key);
    let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(names)
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    Pki {
        ca: ca.pem(),
        chain: vec![cert.der().clone()],
        cert: cert.pem(),
        key: key.serialize_pem(),
    }
}

fn serve(pki: &Pki, alpn: &[&[u8]]) -> ServerConnection {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let key = PrivateKeyDer::from_pem_slice(pki.key.as_bytes()).unwrap();
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.chain.clone(), key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    ServerConnection::new(Arc::new(config)).unwrap()
}

/// Carry the records between the client's wire and the server.
fn carry(wire: &Wire, server: &mut ServerConnection) {
    let sent = std::mem::take(&mut *wire.sent.lock().unwrap());
    let mut from = &sent[..];
    while !from.is_empty() {
        server.read_tls(&mut from).unwrap();
        // A server refusing the client says so in an alert, which the
        // client reads.
        if server.process_new_packets().is_err() {
            break;
        }
    }
    let mut out = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut out).unwrap();
    }
    wire.incoming.lock().unwrap().extend(out);
}

fn session(id: &TryArc<TlsIdentity>, name: &[u8], alpn: Alpn) -> Session<Real> {
    let peer = TlsPeer {
        name,
        port: 443,
        kind: TlsPeerKind::Name,
        early_data: false,
    };
    Session::new(&RUSTLS, id, &peer, alpn, None).unwrap()
}

/// Shake hands with `server` until done or failed.
fn shake(
    s: &mut Session<Real>,
    id: &TryArc<TlsIdentity>,
    kept: &mut Kept,
    wire: &Wire,
    server: &mut ServerConnection,
) -> Result<Handshake, ErrorKind> {
    for _ in 0..10 {
        let r = TlsIo::testing(id, b"localhost", kept, wire, |io| s.handshake(io));
        carry(wire, server);
        if r != Ok(Handshake::Waiting) {
            return r;
        }
    }
    panic!("the handshake does not end")
}

fn trusting(pki: &Pki) -> TryArc<TlsIdentity> {
    let ca = pki.ca.clone().into_bytes();
    identity(move |id| id.options.ca_blob = CaSetting::Given(ca))
}

/// A handshake with a server the CA vouches for, text both ways, and the
/// goodbye.
#[test]
// Calls into aws-lc, which Miri cannot run.
#[cfg_attr(miri, ignore)]
fn a_session_talks_to_a_rustls_server() {
    let pki = pki(&["localhost"]);
    let mut server = serve(&pki, &[b"h2"]);
    let id = trusting(&pki);
    let mut s = session(&id, b"localhost", Alpn::H2Http11);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = shake(&mut s, &id, &mut kept, &wire, &mut server);
    assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept.notes.0);
    assert_eq!(s.chosen(), Some(Chosen::H2));
    let done = lines(&kept.notes.0, "info: rustls: handshake complete");
    assert_eq!(
        done,
        [
            "info: rustls: handshake complete, TLSv1.3, ciphersuite: TLS13_AES_256_GCM_SHA384, key exchange group: X25519MLKEM768"
        ],
        "{:#?}",
        kept.notes.0
    );
    // The client's text reaches the server.
    let sent = TlsIo::testing(&id, b"localhost", &mut kept, &wire, |io| {
        s.send(io, b"GET / HTTP/1.1\r\n\r\n")
    });
    assert_eq!(sent.unwrap(), Sent::Bytes(18.try_into().unwrap()));
    carry(&wire, &mut server);
    let mut got = [0u8; 64];
    let n = server.reader().read(&mut got).unwrap();
    assert_eq!(&got[..n], b"GET / HTTP/1.1\r\n\r\n");
    // The server's reaches the client, perhaps after its tickets.
    server.writer().write_all(b"HTTP/1.1 200 OK\r\n").unwrap();
    carry(&wire, &mut server);
    let mut buf = [0u8; 64];
    let mut text = Vec::new();
    for _ in 0..4 {
        let r = TlsIo::testing(&id, b"localhost", &mut kept, &wire, |io| {
            s.recv(io, &mut buf)
        });
        if let Recv::Data(n) = r.unwrap() {
            text.extend_from_slice(&buf[..n.get()]);
        }
    }
    assert_eq!(text, b"HTTP/1.1 200 OK\r\n");
    // The goodbye: ours goes, the server's comes back.
    let r = TlsIo::testing(&id, b"localhost", &mut kept, &wire, |io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    carry(&wire, &mut server);
    server.send_close_notify();
    carry(&wire, &mut server);
    let mut r = Ok(Handshake::Waiting);
    for _ in 0..3 {
        r = TlsIo::testing(&id, b"localhost", &mut kept, &wire, |io| {
            s.shutdown(io, Goodbye::Mutual)
        });
        if r != Ok(Handshake::Waiting) {
            break;
        }
    }
    assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept.notes.0);
}

/// A server the CA did not vouch for, or vouched for under another name,
/// fails the peer's verification, in rustls-ffi's words.
#[test]
#[cfg_attr(miri, ignore)]
fn a_server_not_vouched_for_fails_verification() {
    let theirs = pki(&["localhost"]);
    let ours = pki(&["localhost"]);
    let mut server = serve(&theirs, &[]);
    let id = trusting(&ours);
    let mut s = session(&id, b"localhost", Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = shake(&mut s, &id, &mut kept, &wire, &mut server);
    assert_eq!(r, Err(ErrorKind::PeerFailedVerification));
    assert!(
        has(
            &kept.notes.0,
            "fail: PeerFailedVerification: rustls_connection_process_new_packets: invalid peer certificate: UnknownIssuer"
        ),
        "{:#?}",
        kept.notes.0
    );
    let pki = pki(&["example.org"]);
    let mut server = serve(&pki, &[]);
    let id = trusting(&pki);
    let mut s = session(&id, b"localhost", Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = shake(&mut s, &id, &mut kept, &wire, &mut server);
    assert_eq!(r, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(
        lines(&kept.notes.0, "fail: "),
        [
            "fail: PeerFailedVerification: rustls_connection_process_new_packets: invalid peer certificate: NotValidForName"
        ]
    );
    // Unchecked, the same server is spoken to.
    let mut server = serve(&pki, &[]);
    let id = identity(|id| id.verify_peer = false);
    let mut s = session(&id, b"localhost", Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = shake(&mut s, &id, &mut kept, &wire, &mut server);
    assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept.notes.0);
}

/// What the library makes of what it is handed, alone.
#[test]
#[cfg_attr(miri, ignore)]
fn the_library_parses_as_rustls_ffi_does() {
    let pki = pki(&["localhost"]);
    let suites = RUSTLS.suites().unwrap();
    assert_eq!(suites.len(), 9);
    assert!(suites[0].tls13 && !suites[8].tls13);
    assert!(RUSTLS.roots(pki.ca.as_bytes()).is_ok());
    assert_eq!(
        RUSTLS.roots(b"no PEM here").err(),
        Some(Code::CertificateParseError)
    );
    assert_eq!(
        RUSTLS
            .roots(b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")
            .err(),
        Some(Code::CertificateParseError)
    );
    assert_eq!(
        RUSTLS.crls(b"no PEM here").err(),
        Some(Code::CertificateRevocationListParseError)
    );
    // A key with a certificate that is not its own does not match.
    let other = self::pki(&["localhost"]);
    let key = RUSTLS
        .certified_key(pki.cert.as_bytes(), other.key.as_bytes())
        .unwrap();
    assert_eq!(
        RUSTLS.keys_match(&key).err(),
        Some(Code::InconsistentKeysKeysMismatch)
    );
    let key = RUSTLS
        .certified_key(pki.cert.as_bytes(), pki.key.as_bytes())
        .unwrap();
    assert_eq!(RUSTLS.keys_match(&key), Ok(()));
    assert_eq!(
        RUSTLS.certified_key(pki.cert.as_bytes(), b"no key").err(),
        Some(Code::PrivateKeyParseError)
    );
    // With no verifier, the configuration does not build.
    let builder = RUSTLS.builder(&suites, &[0x0303, 0x0304]).unwrap();
    assert_eq!(
        RUSTLS.build(builder).err(),
        Some(Code::NoServerCertVerifier)
    );
    // A name that is not one.
    let mut builder = RUSTLS.builder(&suites, &[0x0304]).unwrap();
    RUSTLS.verify_none(&mut builder);
    let config = RUSTLS.build(builder).unwrap();
    assert_eq!(
        RUSTLS.connect(config, b"not a name!").err(),
        Some(Code::InvalidDnsNameError)
    );
}

/// The version string names the rustls the build links, which is the one
/// the rustls-ffi release it names pins.
#[test]
fn the_version_names_the_rustls_linked() {
    let lock = include_str!("../../../../Cargo.lock");
    let needle = "name = \"rustls\"\nversion = \"";
    let at = lock.find(needle).expect("rustls in the lock");
    let version = &lock[at + needle.len()..];
    let version = &version[..version.find('"').unwrap()];
    assert_eq!(version, crate::RUSTLS_VERSION);
    assert_eq!(
        crate::version().to_string(),
        format!("rustls-ffi/0.15.5/rustls/{version}/aws-lc-rs")
    );
}
