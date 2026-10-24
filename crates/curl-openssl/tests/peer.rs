//! OpenSSL as the core's TLS library against a real peer: a server thread
//! speaking TLS through the `openssl` crate on a loopback socket, with a
//! certificate made here and signed by a CA made here. The transfers run
//! through the system's network, as an application's do.
//!
//! The allocation tracker counts per thread, so the server's allocations
//! stay out of the client's budget; OpenSSL's own come from libc and are
//! not counted at all, as C's memory tracker does not count them. Its
//! own binary without the libtest harness, as the tracker is the global
//! allocator.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::io::{Read, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use curl_alloc::track::{self, Tracker};
use curl_alloc::try_box;
use curl_core::components::Components;
use curl_core::conn::io::SystemNet;
use curl_core::easy::Easy;
use curl_core::error::ErrorKind;
use curl_core::handler::{DebugHandler, DebugKind, Handler, Write, WriteHandler};
use curl_core::id::ArenaPolicy;
use curl_core::libraries::Libraries;
use curl_core::multi::{Env, Multi, NoEvents, TransferCx};
use curl_core::options::{CaSetting, IpVersion, Options};
use curl_core::time::SystemClock;
use curl_core::tls::TlsBackend as _;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509, X509Name};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker;

static LIBRARIES: Libraries = Libraries {
    tls: Some(&curl_openssl::OPENSSL),
    ..Libraries::NONE
};

fn main() {
    let wanted: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    curl_openssl::init();
    for (name, test) in [
        (
            "a_verified_get_reads_the_body",
            a_verified_get_reads_the_body as fn(),
        ),
        (
            "a_name_the_certificate_lacks_fails_the_host_check",
            a_name_the_certificate_lacks_fails_the_host_check,
        ),
        (
            "an_unverified_peer_is_not_checked",
            an_unverified_peer_is_not_checked,
        ),
        (
            "an_unknown_issuer_fails_the_verification",
            an_unknown_issuer_fails_the_verification,
        ),
        (
            "a_missing_ca_file_fails_as_a_bad_file_twice_said",
            a_missing_ca_file_fails_as_a_bad_file_twice_said,
        ),
        (
            "no_ca_named_trusts_the_build_s_default",
            no_ca_named_trusts_the_build_s_default,
        ),
        (
            "the_library_reads_no_more_than_it_asks",
            the_library_reads_no_more_than_it_asks,
        ),
        (
            "an_https_get_stays_within_its_allocation_budget",
            an_https_get_stays_within_its_allocation_budget,
        ),
    ] {
        // The tests whose names hold a filter given, if any is, as libtest.
        if !wanted.is_empty() && !wanted.iter().any(|w| name.contains(w.as_str())) {
            continue;
        }
        // Reported as libtest does, the name before the run, so that a run
        // that aborts still shows which test it was in.
        track::untracked(|| {
            use std::io::Write as _;
            print!("test {name} ... ");
            std::io::stdout().flush().unwrap();
        });
        test();
        track::untracked(|| println!("ok"));
    }
    let _ = std::fs::remove_dir_all(certs_dir());
}

/// Where the CA files the tests make are written.
fn certs_dir() -> PathBuf {
    std::env::temp_dir().join(format!("curl-openssl-peer-{}", std::process::id()))
}

/// A certificate authority and a server certificate it signed, the CA
/// written to a file to trust.
struct Certs {
    ca_file: PathBuf,
    cert: X509,
    key: PKey<Private>,
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

/// A server certificate for `cn`, with `alt` as its DNS names, signed by
/// a new CA, which is written to a file of its own (`tag`).
fn certs(tag: &str, cn: &str, alt: &[&str]) -> Certs {
    let ca_key = key();
    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    let ca_name = name(&format!("curl-openssl test CA {tag}"));
    ca.set_subject_name(&ca_name).unwrap();
    ca.set_issuer_name(&ca_name).unwrap();
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
    cert.set_subject_name(&name(cn)).unwrap();
    cert.set_issuer_name(ca.subject_name()).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    if !alt.is_empty() {
        let mut san = SubjectAlternativeName::new();
        for a in alt {
            san.dns(a);
        }
        let ext = san.build(&cert.x509v3_context(Some(&ca), None)).unwrap();
        cert.append_extension(ext).unwrap();
    }
    cert.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let dir = certs_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let ca_file = dir.join(format!("{tag}-ca.pem"));
    std::fs::write(&ca_file, ca.to_pem().unwrap()).unwrap();
    Certs {
        ca_file,
        cert: cert.build(),
        key,
    }
}

const BODY: &[u8] = b"MooMoo";

/// A server for one connection, answering one GET with `BODY`; what it
/// was sent read until the request's end. It ends when the client does,
/// however the handshake went.
fn serve(certs: &Certs) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    serve_with(certs, false)
}

/// A TCP stream that, if told to dribble, writes at most three bytes at
/// a time, each sent on its own: the client's reads then come back
/// shorter than asked.
struct Dribble(std::net::TcpStream, bool);

impl Read for Dribble {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Write for Dribble {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.1 {
            return self.0.write(buf);
        }
        let n = self.0.write(&buf[..buf.len().min(3)])?;
        std::thread::sleep(std::time::Duration::from_micros(200));
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// As `serve`, the server's bytes dribbled out if `dribble`.
fn serve_with(certs: &Certs, dribble: bool) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&certs.key).unwrap();
    acceptor.set_certificate(&certs.cert).unwrap();
    let acceptor = acceptor.build();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_nodelay(dribble).unwrap();
        let Ok(mut tls) = acceptor.accept(Dribble(tcp, dribble)) else {
            return Vec::new();
        };
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => return got,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", BODY.len());
        let _ = tls.write_all(head.as_bytes());
        let _ = tls.write_all(BODY);
        let _ = tls.shutdown();
        got
    });
    (at, server)
}

/// What a transfer said and took.
#[derive(Default)]
struct Seen {
    lines: Vec<String>,
    body: Vec<u8>,
}

struct Taker(Arc<Mutex<Seen>>);

impl DebugHandler for Taker {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text {
            track::untracked(|| {
                let line = String::from_utf8_lossy(data).trim_end().to_owned();
                self.0.lock().unwrap().lines.push(line);
            });
        }
    }
}

impl WriteHandler for Taker {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        track::untracked(|| self.0.lock().unwrap().body.extend_from_slice(body));
        Write::Took(body.len())
    }
}

/// What a GET came to: its result, what the library said of why it
/// failed, and what was seen.
struct Got {
    result: Result<(), ErrorKind>,
    failure: Vec<u8>,
    seen: Seen,
}

/// A GET of `/` at `host` on `at`'s port, through the system's network,
/// with the options `set` makes.
fn get(host: &str, at: SocketAddr, set: impl FnOnce(&mut Options)) -> Got {
    get_traced(host, at, set, false)
}

/// As `get`, with the TLS layer's trace if `ssl`.
fn get_traced(host: &str, at: SocketAddr, set: impl FnOnce(&mut Options), ssl: bool) -> Got {
    get_any("https", host, at, set, ssl)
}

/// As `get`, by `scheme`.
fn get_scheme(scheme: &str, host: &str, at: SocketAddr, set: impl FnOnce(&mut Options)) -> Got {
    get_any(scheme, host, at, set, false)
}

fn get_any(
    scheme: &str,
    host: &str,
    at: SocketAddr,
    set: impl FnOnce(&mut Options),
    ssl: bool,
) -> Got {
    let seen = track::untracked(|| Arc::new(Mutex::new(Seen::default())));
    let (result, failure) = {
        let env = Env {
            clock: try_box(SystemClock::new()).unwrap(),
            net: try_box(SystemNet).unwrap(),
            arena: ArenaPolicy::new(16, 0).unwrap(),
            waker: None,
        };
        let mut m: Multi = Multi::new(env).unwrap();
        let mut easy = Easy::new();
        easy.set_libraries(&LIBRARIES);
        if ssl {
            let components = Components::new().unwrap();
            components.configure(b"ssl");
            easy.set_components(Some(components));
        }
        let o = easy.options_mut();
        let url = track::untracked(|| format!("{scheme}://{host}:{}/", at.port()));
        o.set_url(Some(url.as_bytes())).unwrap();
        o.ip_version = IpVersion::V4;
        o.output.verbose = true;
        o.callbacks.debug = Some(Handler::debug(Taker(seen.clone())).unwrap());
        o.callbacks.write = Some(Handler::write(Taker(seen.clone())).unwrap());
        set(o);
        let id = m.add(try_box(easy).unwrap(), (), &mut NoEvents).unwrap();
        let result = curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        let easy = m.remove(id, &mut NoEvents).unwrap().easy;
        let failure = track::untracked(|| easy.report().failure().unwrap_or_default().to_vec());
        (result, failure)
    };
    let seen = track::untracked(|| std::mem::take(&mut *seen.lock().unwrap()));
    Got {
        result,
        failure,
        seen,
    }
}

fn trusting(certs: &Certs) -> impl FnOnce(&mut Options) + '_ {
    move |o| {
        let path = certs.ca_file.to_str().unwrap().as_bytes().to_vec();
        o.tls.options.make_mut().unwrap().ca_file = CaSetting::Given(path);
    }
}

fn said(got: &Got, line: &str) -> bool {
    got.seen.lines.iter().any(|l| l == line)
}

fn a_verified_get_reads_the_body() {
    let certs = certs("verified", "localhost", &["localhost"]);
    let (at, server) = serve(&certs);
    let got = get("localhost", at, trusting(&certs));
    let request = server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:?}", got.seen.lines);
    assert_eq!(got.seen.body, BODY);
    assert!(
        request.starts_with(b"GET / HTTP/1.1\r\nHost: localhost:"),
        "{request:?}"
    );
    for line in [
        "ALPN: curl offers http/1.1",
        "SSL Trust Anchors:",
        &format!("  CAfile: {}", certs.ca_file.display()),
        "  subjectAltName: \"localhost\" matches cert's \"localhost\"",
        "OpenSSL verify result: 0",
        "SSL certificate verified via OpenSSL.",
        "  subject: CN=localhost",
        "  issuer: CN=curl-openssl test CA verified",
    ] {
        assert!(said(&got, line), "no {line:?} in {:#?}", got.seen.lines);
    }
    assert!(
        got.seen
            .lines
            .iter()
            .any(|l| l.starts_with("SSL connection using TLSv1.3 / ")),
        "{:#?}",
        got.seen.lines
    );
}

/// The certificate must name the host: a name among its alternative
/// names, or none of them the common name (`ossl_verifyhost`).
fn a_name_the_certificate_lacks_fails_the_host_check() {
    let certs = certs("wrongname", "localhost", &["elsewhere.example"]);
    let (at, server) = serve(&certs);
    let got = get("localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(
        got.failure,
        b"SSL: no alternative certificate subject name matches target hostname 'localhost'"
    );
    assert!(said(
        &got,
        " subjectAltName does not match hostname localhost"
    ));
    // With no alternative names, the common name is checked.
    let certs = self::certs("cn", "elsewhere.example", &[]);
    let (at, server) = serve(&certs);
    let got = get("localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(
        got.failure,
        b"SSL: certificate subject name 'elsewhere.example' does not match target hostname 'localhost'"
    );
}

/// `-k`: no CA is loaded, even one named, and OpenSSL's verdict is said
/// and ignored.
fn an_unverified_peer_is_not_checked() {
    let certs = certs("insecure", "elsewhere.example", &["elsewhere.example"]);
    let other = self::certs("insecure-other", "x", &["x"]);
    let (at, server) = serve(&certs);
    let got = get("localhost", at, |o| {
        trusting(&other)(o);
        o.tls.verify_peer = false;
        o.tls.verify_host = false;
    });
    server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert_eq!(got.seen.body, BODY);
    assert!(said(&got, "SSL Trust: peer verification disabled"));
    assert!(said(
        &got,
        " SSL certificate verification failed, continuing anyway!"
    ));
    assert!(!got.seen.lines.iter().any(|l| l.starts_with("  CAfile:")));
}

fn an_unknown_issuer_fails_the_verification() {
    let certs = certs("unknown", "localhost", &["localhost"]);
    let other = self::certs("unknown-other", "localhost", &["localhost"]);
    let (at, server) = serve(&certs);
    let got = get("localhost", at, trusting(&other));
    server.join().unwrap();
    assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(
        got.failure,
        b"SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)"
    );
}

/// A CA file that cannot be read fails the handshake with 77, said as
/// the first read sets the store up and again as the handshake's step
/// does, as C says it.
fn a_missing_ca_file_fails_as_a_bad_file_twice_said() {
    let certs = certs("missing", "localhost", &["localhost"]);
    let (at, server) = serve(&certs);
    let got = get("localhost", at, |o| {
        o.tls.options.make_mut().unwrap().ca_file =
            CaSetting::Given(b"/nonexistent/ca.pem".to_vec());
    });
    server.join().unwrap();
    assert_eq!(got.result, Err(ErrorKind::SslCacertBadfile));
    assert_eq!(
        got.failure,
        b"error adding trust anchors from file: /nonexistent/ca.pem"
    );
    let anchors = got
        .seen
        .lines
        .iter()
        .filter(|l| *l == "SSL Trust Anchors:")
        .count();
    assert_eq!(anchors, 2, "{:#?}", got.seen.lines);
}

/// A transfer naming no CA trusts the bundle the build found.
fn no_ca_named_trusts_the_build_s_default() {
    let certs = certs("default", "localhost", &["localhost"]);
    let (at, server) = serve(&certs);
    let got = get("localhost", at, |_| {});
    server.join().unwrap();
    let default = curl_openssl::OPENSSL.ca_defaults();
    match default.file {
        Some(file) => assert!(
            said(&got, &format!("  CAfile: {file}")),
            "{:#?}",
            got.seen.lines
        ),
        None => assert!(!got.seen.lines.iter().any(|l| l.starts_with("  CAfile:"))),
    }
    // Not this test's CA: the peer does not verify.
    assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
}

/// What the library reads below goes into its own buffer whole: the
/// layers below are asked for no more than it has room for, which the
/// trace of each read says (`ossl_bio_cf_in_read(len=N) -> 0, n`, n at
/// most N), and the library is told what came, which a peer sending in
/// pieces makes less than it asked.
fn the_library_reads_no_more_than_it_asks() {
    let certs = certs("lengths", "localhost", &["localhost"]);
    let (at, server) = serve_with(&certs, true);
    let got = get_traced("localhost", at, trusting(&certs), true);
    server.join().unwrap();
    assert_eq!(got.result, Ok(()));
    assert_eq!(got.seen.body, BODY);
    let (mut reads, mut short) = (0, 0);
    for line in &got.seen.lines {
        let Some(rest) = line.split("ossl_bio_cf_in_read(len=").nth(1) else {
            continue;
        };
        let (len, rest) = rest.split_once(") -> ").unwrap();
        let n: usize = rest.split(", ").nth(1).unwrap().parse().unwrap();
        let len: usize = len.parse().unwrap();
        assert!(n <= len, "{line}");
        reads += 1;
        short += usize::from(n > 0 && n < len);
    }
    assert!(reads > 0, "no read traced in {:#?}", got.seen.lines);
    // The bytes came in pieces, so the library was told of short reads.
    assert!(short > 0, "no short read in {:#?}", got.seen.lines);
}

/// A server for one plain HTTP connection, as `serve` answers.
fn serve_plain() -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            match tcp.read(&mut buf) {
                Ok(0) | Err(_) => return got,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", BODY.len());
        let _ = tcp.write_all(head.as_bytes());
        let _ = tcp.write_all(BODY);
        got
    });
    (at, server)
}

/// The allocations of this file's GET over plain HTTP, its CA file set
/// as the HTTPS one's is: the base the TLS layer's are counted over.
fn plain_get_allocations() -> u64 {
    let (at, server) = serve_plain();
    let path = track::untracked(|| b"/unused/ca.pem".to_vec());
    let (got, n) = track::count_allocations(|| {
        get_scheme("http", "localhost", at, |o| {
            o.tls.options.make_mut().unwrap().ca_file = CaSetting::Given(path);
            o.callbacks.debug = None;
            o.output.verbose = false;
        })
    });
    server.join().unwrap();
    assert_eq!(got.result, Ok(()));
    n
}

/// What an HTTPS GET allocates beyond the same GET over plain HTTP, one
/// by one: the route's `TlsIdentity` (its `TryArc`) and the CA file's
/// copy in the options it holds; the `TlsLayer`'s box; the
/// `LayerStack`'s box and its vector; the handshake's marker; the
/// session's box and the copy of the host name it checks the
/// certificate against; the host name ended
/// by a zero byte for SNI, and the CA file's for OpenSSL, both freed as
/// the call returns. OpenSSL's own allocations are libc's, not counted,
/// as C's memory tracker does not count them.
const HTTPS_GET_EXTRA: u64 = 10;

fn an_https_get_stays_within_its_allocation_budget() {
    let base = plain_get_allocations();
    let certs = certs("budget", "localhost", &["localhost"]);
    let (at, server) = serve(&certs);
    let path = track::untracked(|| certs.ca_file.to_str().unwrap().as_bytes().to_vec());
    let (got, n) = track::count_allocations(|| {
        get("localhost", at, |o| {
            o.tls.options.make_mut().unwrap().ca_file = CaSetting::Given(path);
            o.callbacks.debug = None;
            o.output.verbose = false;
        })
    });
    server.join().unwrap();
    assert_eq!(got.result, Ok(()));
    track::untracked(|| {
        eprintln!("budget: an HTTPS GET over OpenSSL made {n} allocations, the plain GET {base}");
    });
    assert!(
        n <= base + HTTPS_GET_EXTRA,
        "an HTTPS GET over OpenSSL made {n} allocations, over the plain GET's {base} \
         and its {HTTPS_GET_EXTRA}"
    );
}
