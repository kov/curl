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
use curl_core::options::{CaCache, CaSetting, IpVersion, Options, SslOptions};
use curl_core::time::{Clock, ManualClock, SystemClock};
use curl_core::tls::TlsBackend as _;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509, X509Name};

#[path = "peer/chain.rs"]
mod chain;
#[path = "peer/checks.rs"]
mod checks;
#[path = "peer/client.rs"]
mod client;
#[path = "peer/engine.rs"]
mod engine;
#[path = "peer/goodbye.rs"]
mod goodbye;
#[path = "peer/hands.rs"]
mod hands;
#[path = "peer/hello.rs"]
mod hello;
#[path = "peer/names.rs"]
mod names;
#[path = "peer/session.rs"]
mod session;
#[path = "peer/status.rs"]
mod status;

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
            "a_second_connection_takes_the_multi_s_store",
            a_second_connection_takes_the_multi_s_store,
        ),
        (
            "a_handle_s_own_multi_keeps_its_store_between_performs",
            a_handle_s_own_multi_keeps_its_store_between_performs,
        ),
        (
            "the_kept_store_serves_for_the_cache_s_age",
            the_kept_store_serves_for_the_cache_s_age,
        ),
        (
            "another_ca_file_path_or_partial_chain_loads_its_own",
            another_ca_file_path_or_partial_chain_loads_its_own,
        ),
        (
            "an_unverified_peer_a_blob_a_crl_or_the_system_s_store_loads_its_own",
            an_unverified_peer_a_blob_a_crl_or_the_system_s_store_loads_its_own,
        ),
        (
            "an_https_get_stays_within_its_allocation_budget",
            an_https_get_stays_within_its_allocation_budget,
        ),
    ]
    .into_iter()
    .chain(checks::TESTS.iter().copied())
    .chain(client::TESTS.iter().copied())
    .chain(chain::TESTS.iter().copied())
    .chain(engine::TESTS.iter().copied())
    .chain(goodbye::TESTS.iter().copied())
    .chain(hands::TESTS.iter().copied())
    .chain(hello::TESTS.iter().copied())
    .chain(names::TESTS.iter().copied())
    .chain(session::TESTS.iter().copied())
    .chain(status::TESTS.iter().copied())
    {
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
    ca: X509,
    ca_key: PKey<Private>,
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
        ca,
        ca_key,
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
    serve_configured(certs, dribble, |_| {})
}

/// As `serve_with`, the server's TLS set up further by `configure`.
fn serve_configured(
    certs: &Certs,
    dribble: bool,
    configure: impl FnOnce(&mut SslAcceptorBuilder),
) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&certs.key).unwrap();
    acceptor.set_certificate(&certs.cert).unwrap();
    configure(&mut acceptor);
    let acceptor = acceptor.build();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_nodelay(dribble).unwrap();
        let mut tls = match acceptor.accept(Dribble(tcp, dribble)) {
            Ok(tls) => tls,
            // The alert sent, what the client goes on to send is read
            // until it closes: closed with it unread, the socket would be
            // reset, and the client fail on the reset, not the alert.
            Err(openssl::ssl::HandshakeError::Failure(mut mid)) => {
                let tcp = &mut mid.get_mut().0;
                tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .unwrap();
                let mut buf = [0u8; 4096];
                while matches!(tcp.read(&mut buf), Ok(n) if n > 0) {}
                return Vec::new();
            }
            Err(_) => return Vec::new(),
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
    /// The chain the transfer reported, each certificate's lines.
    chain: Option<Vec<Vec<Vec<u8>>>>,
    /// What OpenSSL made of the peer's certificate (`CURLINFO_SSL_VERIFYRESULT`).
    verify: i64,
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
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    get_in(&mut m, scheme, host, at, set, ssl)
}

/// A multi on `clock`, through the system's network.
fn multi(clock: Box<dyn Clock>) -> Multi {
    let env = Env {
        clock,
        net: try_box(SystemNet).unwrap(),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    Multi::new(env).unwrap()
}

/// As `get_any`, in the multi `m`.
fn get_in(
    m: &mut Multi,
    scheme: &str,
    host: &str,
    at: SocketAddr,
    set: impl FnOnce(&mut Options),
    ssl: bool,
) -> Got {
    let seen = track::untracked(|| Arc::new(Mutex::new(Seen::default())));
    let (result, failure, chain, verify) = {
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
        let result = curl_core::multi::drive_to_completion(m, id, &mut NoEvents).unwrap();
        let easy = m.remove(id, &mut NoEvents).unwrap().easy;
        let failure = track::untracked(|| easy.report().failure().unwrap_or_default().to_vec());
        let chain = track::untracked(|| easy.report().certinfo().map(|c| c.certs().to_vec()));
        (result, failure, chain, easy.report().verify_result())
    };
    let seen = track::untracked(|| std::mem::take(&mut *seen.lock().unwrap()));
    Got {
        result,
        failure,
        seen,
        chain,
        verify,
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

/// A verified GET in `m` of a server of its own, on a port of its own,
/// so that it makes a connection of its own: the server shows the
/// certificate `certs` made, and the transfer trusts their CA, with the
/// options `set` makes after. The TLS layer is traced.
fn verified_in(m: &mut Multi, certs: &Certs, set: impl FnOnce(&mut Options)) -> Got {
    let (at, server) = serve(certs);
    let got = get_in(
        m,
        "https",
        "localhost",
        at,
        |o| {
            trusting(certs)(o);
            set(o);
        },
        true,
    );
    server.join().unwrap();
    got
}

/// The times the transfer loaded its trust store, which it traces as it
/// starts to (`ossl_populate_x509_store`); its handshake done, or none of
/// it counts.
fn loads(got: &Got) -> usize {
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert!(
        got.seen
            .lines
            .iter()
            .any(|l| l.starts_with("SSL connection using ")),
        "no handshake in {:#?}",
        got.seen.lines
    );
    got.seen
        .lines
        .iter()
        .filter(|l| l.ends_with("configuring OpenSSL's x509 trust store"))
        .count()
}

fn starts(got: &Got, prefix: &str) -> bool {
    got.seen.lines.iter().any(|l| l.starts_with(prefix))
}

const DAY: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
const SECOND: std::time::Duration = std::time::Duration::from_secs(1);

/// The store a connection loads is kept for the multi's next ones, which
/// verify against it without loading or saying it again
/// (`ossl_get_cached_x509_store`); another multi keeps its own.
fn a_second_connection_takes_the_multi_s_store() {
    let certs = certs("kept", "localhost", &["localhost"]);
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let first = verified_in(&mut m, &certs, |_| {});
    assert_eq!(loads(&first), 1);
    assert!(said(&first, "SSL Trust Anchors:"));
    assert!(said(
        &first,
        &format!("  CAfile: {}", certs.ca_file.display())
    ));
    let second = verified_in(&mut m, &certs, |_| {});
    assert_eq!(loads(&second), 0, "{:#?}", second.seen.lines);
    assert!(said(&second, "SSL certificate verified via OpenSSL."));
    assert!(!starts(&second, "SSL Trust"), "{:#?}", second.seen.lines);
    assert!(!starts(&second, "  CAfile:"), "{:#?}", second.seen.lines);
    let mut other = multi(try_box(SystemClock::new()).unwrap());
    assert_eq!(loads(&verified_in(&mut other, &certs, |_| {})), 1);
    assert_eq!(loads(&verified_in(&mut m, &certs, |_| {})), 0);
}

/// A handle performing on its own does so in a multi of its own, kept
/// from one perform to the next (C's `multi_easy`), and so is its store.
fn a_handle_s_own_multi_keeps_its_store_between_performs() {
    let certs = certs("own", "localhost", &["localhost"]);
    let seen = track::untracked(|| Arc::new(Mutex::new(Seen::default())));
    let mut easy = Easy::new();
    easy.set_libraries(&LIBRARIES);
    let components = Components::new().unwrap();
    components.configure(b"ssl");
    easy.set_components(Some(components));
    let o = easy.options_mut();
    o.ip_version = IpVersion::V4;
    o.output.verbose = true;
    o.callbacks.debug = Some(Handler::debug(Taker(seen.clone())).unwrap());
    o.callbacks.write = Some(Handler::write(Taker(seen.clone())).unwrap());
    trusting(&certs)(o);
    let mut perform = || {
        let (at, server) = serve(&certs);
        let url = track::untracked(|| format!("https://localhost:{}/", at.port()));
        easy.options_mut().set_url(Some(url.as_bytes())).unwrap();
        let result = easy.perform().map_err(|e| e.kind());
        server.join().unwrap();
        let seen = track::untracked(|| std::mem::take(&mut *seen.lock().unwrap()));
        loads(&Got {
            result,
            failure: Vec::new(),
            seen,
            chain: None,
            verify: 0,
        })
    };
    assert_eq!(perform(), 1);
    assert_eq!(perform(), 0);
}

/// A kept store serves while it is younger than the asking transfer's
/// `CURLOPT_CA_CACHE_TIMEOUT`, a day unless it is set, on the multi's
/// clock; one loaded in its place is kept from then.
fn the_kept_store_serves_for_the_cache_s_age() {
    let certs = certs("age", "localhost", &["localhost"]);
    let clock = ManualClock::new().unwrap();
    let mut m = multi(try_box(clock.clone()).unwrap());
    let age = |cache| move |o: &mut Options| o.tls.options.make_mut().unwrap().ca_cache = cache;
    assert_eq!(loads(&verified_in(&mut m, &certs, |_| {})), 1);
    clock.advance(DAY - SECOND);
    assert_eq!(loads(&verified_in(&mut m, &certs, |_| {})), 0);
    // A day old is too old.
    clock.advance(SECOND);
    assert_eq!(loads(&verified_in(&mut m, &certs, |_| {})), 1);
    clock.advance(DAY - SECOND);
    assert_eq!(loads(&verified_in(&mut m, &certs, |_| {})), 0);
    // For ever takes one of any age.
    clock.advance(400 * DAY);
    assert_eq!(
        loads(&verified_in(&mut m, &certs, age(CaCache::Forever))),
        0
    );
    let minute = CaCache::For(60 * SECOND);
    assert_eq!(loads(&verified_in(&mut m, &certs, age(minute))), 1);
    clock.advance(59 * SECOND);
    assert_eq!(loads(&verified_in(&mut m, &certs, age(minute))), 0);
    clock.advance(SECOND);
    assert_eq!(loads(&verified_in(&mut m, &certs, age(minute))), 1);
    // Off takes none and keeps none: the store kept is still the one
    // loaded before, a day old a day after it.
    assert_eq!(loads(&verified_in(&mut m, &certs, age(CaCache::Off))), 1);
    clock.advance(30 * SECOND);
    assert_eq!(loads(&verified_in(&mut m, &certs, age(CaCache::Off))), 1);
    clock.advance(DAY - 30 * SECOND);
    assert_eq!(loads(&verified_in(&mut m, &certs, |_| {})), 1);
}

/// A store is kept for the CA file, the CA path and the partial-chain
/// choice it was loaded with (`ossl_cached_x509_store_different`): a
/// connection naming others loads its own, which is kept in its place.
fn another_ca_file_path_or_partial_chain_loads_its_own() {
    let certs = certs("key", "localhost", &["localhost"]);
    let copy = track::untracked(|| {
        let copy = certs_dir().join("key-copy.pem");
        std::fs::copy(&certs.ca_file, &copy).unwrap();
        copy.to_str().unwrap().as_bytes().to_vec()
    });
    let dir = track::untracked(|| certs_dir().to_str().unwrap().as_bytes().to_vec());
    let file = |o: &mut Options| {
        o.tls.options.make_mut().unwrap().ca_file = CaSetting::Given(copy.clone());
    };
    let whole = |o: &mut Options| {
        file(o);
        o.tls.options.make_mut().unwrap().ssl_options = SslOptions::NO_PARTIALCHAIN;
    };
    let path = |o: &mut Options| {
        whole(o);
        o.tls.options.make_mut().unwrap().ca_path = CaSetting::Given(dir.clone());
    };
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    assert_eq!(loads(&verified_in(&mut m, &certs, |_| {})), 1);
    assert_eq!(loads(&verified_in(&mut m, &certs, file)), 1);
    assert_eq!(loads(&verified_in(&mut m, &certs, file)), 0);
    assert_eq!(loads(&verified_in(&mut m, &certs, whole)), 1);
    assert_eq!(loads(&verified_in(&mut m, &certs, whole)), 0);
    let got = verified_in(&mut m, &certs, path);
    assert_eq!(loads(&got), 1);
    assert!(said(&got, &format!("  CApath: {}", certs_dir().display())));
    assert_eq!(loads(&verified_in(&mut m, &certs, path)), 0);
    // The first one's settings again: the store kept now is another's.
    assert_eq!(loads(&verified_in(&mut m, &certs, |_| {})), 1);
}

/// A connection that does not verify its peer, or verifies it against a
/// blob, with a revocation list or by the system's store, loads its own
/// store, and leaves the kept one as it was
/// (`Curl_ssl_setup_x509_store`'s `cache_criteria_met`).
fn an_unverified_peer_a_blob_a_crl_or_the_system_s_store_loads_its_own() {
    let certs = certs("bypass", "localhost", &["localhost"]);
    let pem = track::untracked(|| std::fs::read(&certs.ca_file).unwrap());
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    assert_eq!(loads(&verified_in(&mut m, &certs, |_| {})), 1);
    let unverified = verified_in(&mut m, &certs, |o| {
        o.tls.verify_peer = false;
        o.tls.verify_host = false;
    });
    assert_eq!(loads(&unverified), 1);
    assert!(said(&unverified, "SSL Trust: peer verification disabled"));
    let blob = verified_in(&mut m, &certs, |o| {
        o.tls.options.make_mut().unwrap().ca_blob = Some(pem);
    });
    assert_eq!(loads(&blob), 1);
    assert!(said(&blob, "  CA Blob from configuration"));
    let list = checks::crl(&certs, "bypass", false);
    let list = list.to_str().unwrap().as_bytes().to_vec();
    let crl = verified_in(&mut m, &certs, |o| {
        o.tls.options.make_mut().unwrap().crl_file = Some(list);
    });
    assert_eq!(loads(&crl), 1);
    let native = verified_in(&mut m, &certs, |o| {
        o.tls.options.make_mut().unwrap().ssl_options = SslOptions::NATIVE_CA;
    });
    assert_eq!(loads(&native), 1);
    assert!(said(&native, "SSL Trust Anchors:"));
    // A store loaded in a provider's library context is not kept past it.
    let provider = verified_in(&mut m, &certs, |o| {
        o.tls.options.make_mut().unwrap().engine = Some(b"default".to_vec());
    });
    assert_eq!(loads(&provider), 1);
    // None of them kept theirs: the unverified one's is empty, and the
    // peer would not verify against it.
    let after = verified_in(&mut m, &certs, |_| {});
    assert_eq!(loads(&after), 0);
    assert!(said(&after, "SSL certificate verified via OpenSSL."));
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
/// the call returns; the multi's `TlsShared` (its `TryArc`), made with
/// its first session, and the box of the CA store cache OpenSSL keeps in
/// it, made as the first store is set up. OpenSSL's own allocations are
/// libc's, not counted, as C's memory tracker does not count them.
const HTTPS_GET_EXTRA: u64 = 12;

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
