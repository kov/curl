//! The session over the scripted library (`fake.rs`): the calls made of
//! rustls-ffi in `rustls.c`'s order, and what is made of each answer, said
//! in C's words.

use curl_alloc::TryArc;
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::options::{
    CaSetting, ColdGroup as _, SslOptions, TlsMaxVersion, TlsMinVersion, TlsOptions,
};
use curl_core::tls::{
    Alpn, CaDefaults, Chosen, Goodbye, Handshake, Kept, SharedKeyLog, TlsIdentity, TlsIo, TlsPeer,
    TlsPeerKind, TlsSession as _, TlsWait,
};

use crate::fake::{Ev, Fake, Wire, World};
use crate::library::{Errno, Plain, TLS1_2};
use crate::result::Code;
use crate::session::Session;

mod ech;
mod real;
mod result;

const HOST: &[u8] = b"example.com";

fn identity(change: impl FnOnce(&mut TlsIdentity)) -> TryArc<TlsIdentity> {
    let mut id = TlsIdentity {
        verify_peer: true,
        verify_host: true,
        options: TlsOptions::NONE,
        ca_defaults: CaDefaults::NONE,
        origin: curl_core::tls::TlsOrigin::First,
    };
    // A peer is checked against certificates of a blob, unless a test
    // says otherwise: a file would be read.
    id.options.ca_blob = CaSetting::Given(b"CA".to_vec());
    change(&mut id);
    TryArc::try_new(id).unwrap()
}

fn plain() -> TryArc<TlsIdentity> {
    identity(|_| {})
}

/// A session of `lib` for `id` to `name`, offering `alpn`.
fn session_to(
    lib: &'static Fake,
    id: &TryArc<TlsIdentity>,
    name: &[u8],
    kind: TlsPeerKind,
    alpn: Alpn,
    keylog: Option<SharedKeyLog>,
) -> Session<Fake> {
    let peer = TlsPeer {
        name,
        port: 443,
        kind,
        early_data: false,
        ech_configs: None,
    };
    Session::new(lib, id, &peer, alpn, keylog).unwrap()
}

fn session(lib: &'static Fake, id: &TryArc<TlsIdentity>, alpn: Alpn) -> Session<Fake> {
    session_to(lib, id, HOST, TlsPeerKind::Name, alpn, None)
}

/// Run `f` on `s` with the I/O over `wire`, noted in `kept`.
fn with_io<R>(
    s: &mut Session<Fake>,
    id: &TryArc<TlsIdentity>,
    kept: &mut Kept,
    wire: &Wire,
    f: impl FnOnce(&mut Session<Fake>, &mut TlsIo<'_>) -> R,
) -> R {
    TlsIo::testing(id, HOST, kept, wire, |io| f(s, io))
}

/// A handshake of a fresh session of `world`'s library for `id`, the
/// peer's reply `reply` waiting: its result, what was noted, and the
/// library's calls.
fn shake_with(
    world: World,
    id: &TryArc<TlsIdentity>,
    reply: &[u8],
) -> (Result<Handshake, ErrorKind>, Vec<String>, Vec<String>) {
    let lib = Fake::new(world);
    let mut s = session(lib, id, Alpn::H2Http11);
    let mut kept = Kept::new();
    let wire = Wire::with(reply);
    let r = with_io(&mut s, id, &mut kept, &wire, |s, io| s.handshake(io));
    let calls = lib.w().calls.clone();
    (r, kept.notes.0, calls)
}

fn shake(
    world: World,
    id: &TryArc<TlsIdentity>,
) -> (Result<Handshake, ErrorKind>, Vec<String>, Vec<String>) {
    shake_with(world, id, b"server-hello")
}

fn has(notes: &[String], line: &str) -> bool {
    notes.iter().any(|n| n == line)
}

fn lines<'a>(notes: &'a [String], prefix: &str) -> Vec<&'a str> {
    notes
        .iter()
        .map(String::as_str)
        .filter(|n| n.starts_with(prefix))
        .collect()
}

/// A handshake builds the configuration and makes the connection in
/// `cr_init_backend`'s order, then writes and reads until the library is
/// done, says what was agreed, and lets it write its Finished.
#[test]
fn a_handshake_goes_as_rustls_c_s() {
    let world = World {
        alpn: Some(b"h2"),
        ..World::one_round()
    };
    let lib = Fake::new(world);
    let id = plain();
    let mut s = session(lib, &id, Alpn::H2Http11);
    let mut kept = Kept::new();
    let wire = Wire::with(b"server-hello");
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    let notes = &kept.notes.0;
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    let calls = lib.w().calls.clone();
    let want = [
        "builder([1302,1301,c02c,c02f], [0303,0304])",
        "alpn(h2,http/1.1)",
        "roots(CA)",
        "webpki(CA, None)",
        "verifier(webpki)",
        "build",
        "connect(example.com)",
        "write_tls",
        "read_tls",
        "process",
        "write_tls",
    ];
    assert_eq!(calls, want);
    assert_eq!(wire.sent(), b"hellofinished");
    assert_eq!(lib.w().pulled, b"server-hello");
    let said = [
        "info: ALPN: curl offers h2,http/1.1",
        "info: ALPN: server accepted h2",
        "info: rustls: handshake complete, TLSv1.3, ciphersuite: TLS13_AES_256_GCM_SHA384, key exchange group: X25519MLKEM768",
    ];
    assert_eq!(lines(notes, "info: "), said, "{notes:#?}");
    let traced = [
        "trace: cr_connect, state=0",
        "trace: cr_connect, init backend -> 0",
        "trace: rustls_connection wants us to write_tls.",
        "trace: cf_send(len=0)",
        "trace: cf->next send(len=5) -> 0, 5",
        "trace: cf_send: wrote 5 TLS bytes",
        "trace: rustls_send(len=0) -> 0, 0",
        "trace: rustls_connection wants us to read_tls.",
        "trace: cf->next recv(len=4096) -> 0, 12",
        "trace: cf_send(len=0)",
        "trace: cf->next send(len=8) -> 0, 8",
        "trace: cf_send: wrote 8 TLS bytes",
        "trace: rustls_send(len=0) -> 0, 0",
    ];
    assert_eq!(lines(notes, "trace: "), traced, "{notes:#?}");
    assert_eq!(s.chosen(), Some(Chosen::H2));
    // Done, it stays done.
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().calls.len(), want.len());
}

/// The versions asked are mapped onto 1.2 and 1.3, as C maps them; a
/// maximum below either is refused.
#[test]
fn the_versions_are_c_s() {
    let versions = |min, max| {
        let id = identity(|id| {
            id.options.min_version = min;
            id.options.max_version = max;
        });
        let (r, notes, calls) = shake(World::one_round(), &id);
        let set = calls.into_iter().find(|c| c.starts_with("builder("));
        (r, notes, set)
    };
    let set = |min, max| versions(min, max).2.unwrap();
    for min in [
        TlsMinVersion::Tls1,
        TlsMinVersion::Tls1_0,
        TlsMinVersion::Tls1_1,
        TlsMinVersion::Tls1_2,
    ] {
        for max in [
            TlsMaxVersion::None,
            TlsMaxVersion::Default,
            TlsMaxVersion::Tls1_3,
        ] {
            assert!(set(min, max).ends_with("[0303,0304])"), "{min:?} {max:?}");
        }
        assert!(set(min, TlsMaxVersion::Tls1_2).ends_with("[0303])"));
    }
    assert!(set(TlsMinVersion::Tls1_3, TlsMaxVersion::None).ends_with("[0304])"));
    assert!(set(TlsMinVersion::Tls1_3, TlsMaxVersion::Tls1_3).ends_with("[0304])"));
    for (min, max) in [
        (TlsMinVersion::Tls1_3, TlsMaxVersion::Tls1_2),
        (TlsMinVersion::Tls1, TlsMaxVersion::Tls1_1),
        (TlsMinVersion::Tls1_2, TlsMaxVersion::Tls1_0),
    ] {
        let (r, notes, set) = versions(min, max);
        assert_eq!(r, Err(ErrorKind::BadFunctionArgument));
        assert!(has(
            &notes,
            "fail: BadFunctionArgument: rustls: unsupported maximum TLS version value"
        ));
        assert!(
            has(&notes, "trace: cr_connect, init backend -> 43"),
            "{notes:#?}"
        );
        assert_eq!(set, None);
    }
}

/// The cipher lists choose of the library's suites as C's
/// `cr_get_selected_ciphers` does: TLS 1.3's first, the library's own for
/// a list not given, what the library lacks and what is named twice said;
/// nothing known fails.
#[test]
fn the_cipher_lists_choose_as_c_chooses() {
    let chosen = |tls12: Option<&[u8]>, tls13: Option<&[u8]>| {
        let id = identity(|id| {
            id.options.ciphers = tls12.map(<[u8]>::to_vec);
            id.options.tls13_ciphers = tls13.map(<[u8]>::to_vec);
        });
        let (r, notes, calls) = shake(World::one_round(), &id);
        let set = calls.into_iter().find(|c| c.starts_with("builder("));
        (r, notes, set)
    };
    let (r, _, set) = chosen(None, None);
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(set.unwrap(), "builder([1302,1301,c02c,c02f], [0303,0304])");
    let (_, notes, set) = chosen(Some(b"ECDHE-RSA-AES128-GCM-SHA256:BOGUS:AES128-SHA"), None);
    assert_eq!(set.unwrap(), "builder([1302,1301,c02f], [0303,0304])");
    assert!(has(
        &notes,
        "info: rustls: unknown cipher in list: \"BOGUS\""
    ));
    // A suite the table knows and the library lacks is unknown to it.
    assert!(has(
        &notes,
        "info: rustls: unknown cipher in list: \"AES128-SHA\""
    ));
    let (_, notes, set) = chosen(
        Some(b"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        Some(b"TLS_AES_128_GCM_SHA256,TLS_AES_128_GCM_SHA256"),
    );
    assert_eq!(set.unwrap(), "builder([1301,c02f], [0303,0304])");
    assert!(has(
        &notes,
        "info: rustls: duplicate cipher in list: \"TLS_AES_128_GCM_SHA256\""
    ));
    // The defaults named again are not said twice.
    let (_, notes, set) = chosen(Some(b"TLS_AES_128_GCM_SHA256"), None);
    assert_eq!(set.unwrap(), "builder([1302,1301], [0303,0304])");
    assert!(
        lines(&notes, "info: rustls: duplicate").is_empty(),
        "{notes:#?}"
    );
    let (r, notes, set) = chosen(Some(b"BOGUS"), Some(b""));
    assert_eq!(r, Err(ErrorKind::SslCipher));
    assert!(has(
        &notes,
        "fail: SslCipher: rustls: no supported cipher in list"
    ));
    assert_eq!(set, None);
}

/// The peer is checked as C checks it: not at all where not asked, by
/// the system's store where asked for, else against the blob, or else the
/// file, with the revocation list; with none of them, the configuration
/// has no verifier and does not build.
#[test]
fn the_verifier_is_c_s() {
    let made = |change: fn(&mut TlsIdentity)| {
        let (r, notes, calls) = shake(World::one_round(), &identity(change));
        let built = calls
            .iter()
            .position(|c| c == "build")
            .map_or(calls.len(), |i| i + 1);
        (r, notes, calls[2..built].to_vec())
    };
    let (r, _, calls) = made(|id| id.verify_peer = false);
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(calls, ["verify_none", "build"]);
    // The host is not checked apart: C reads no `verifyhost`.
    let (_, _, calls) = made(|id| id.verify_host = false);
    assert_eq!(
        calls,
        ["roots(CA)", "webpki(CA, None)", "verifier(webpki)", "build"]
    );
    let (_, _, calls) = made(|id| id.options.ssl_options = SslOptions::NATIVE_CA);
    assert_eq!(calls, ["platform", "verifier(platform)", "build"]);
    let (r, notes, calls) = made(|id| {
        id.options.ssl_options = SslOptions::NATIVE_CA;
        id.options.crl_file = Some(b"crl.pem".to_vec());
    });
    assert_eq!(r, Err(ErrorKind::NotBuiltIn));
    assert!(has(
        &notes,
        "fail: NotBuiltIn: rustls: CRL file not supported with native CA store; the platform verifier has no CRL attachment API"
    ));
    assert_eq!(calls, Vec::<String>::new());
    // The blob in place of the file.
    let (_, _, calls) = made(|id| id.options.ca_file = CaSetting::Given(b"/no/ca.pem".to_vec()));
    assert_eq!(calls[0], "roots(CA)");
    let (r, notes, calls) = made(|id| id.options.ca_blob = CaSetting::Default);
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert_eq!(calls, ["build"]);
    assert_eq!(
        lines(&notes, "fail: "),
        [
            "fail: SslConnectError: failed to build client config: no server certificate verifier was configured on the client config builder"
        ]
    );
}

/// The certificates to trust that do not load fail as C fails them, in
/// rustls-ffi's words: a file that does not open as I/O's.
#[test]
fn the_trust_that_does_not_load_fails_in_c_s_words() {
    let world = World {
        answers: vec![("roots", Code::CertificateParseError)],
        ..World::one_round()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    assert!(has(
        &notes,
        "fail: SslCacertBadfile: failed to parse trusted certificates from blob: error parsing certificate"
    ));
    let id = identity(|id| {
        id.options.ca_blob = CaSetting::Default;
        id.options.ca_file = CaSetting::Given(b"/no/such/ca.pem".to_vec());
    });
    let (r, notes, calls) = shake(World::one_round(), &id);
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    assert!(has(
        &notes,
        "fail: SslCacertBadfile: failed to load trusted certificates: I/O error"
    ));
    assert!(lines(&calls, "roots").is_empty());
    let world = World {
        answers: vec![("webpki", Code::ClientCertVerifierBuilderNoRootAnchors)],
        ..World::one_round()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    assert!(has(
        &notes,
        "fail: SslCacertBadfile: failed to build certificate verifier: no root trust anchors provided"
    ));
    let world = World {
        answers: vec![("platform", Code::General)],
        ..World::one_round()
    };
    let id = identity(|id| id.options.ssl_options = SslOptions::NATIVE_CA);
    let (r, notes, _) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    assert!(has(
        &notes,
        "fail: SslCacertBadfile: failed to create platform certificate verifier: general error"
    ));
}

/// A temporary file of `bytes`, removed when dropped.
struct Temp(std::path::PathBuf);

impl Temp {
    fn new(name: &str, bytes: &[u8]) -> Temp {
        let path = std::env::temp_dir().join(format!("curl-rustls-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        Temp(path)
    }

    fn name(&self) -> Vec<u8> {
        self.0.to_str().unwrap().as_bytes().to_vec()
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

/// The files are read whole and handed over as they are: the CA file to
/// the store, the revocation list to the verifier; a revocation list that
/// does not read or parse fails.
#[test]
// Writes a file, which Miri's isolation keeps out.
#[cfg_attr(miri, ignore)]
fn the_files_are_read_and_handed_over() {
    let ca = Temp::new("ca.pem", b"CA FILE");
    let crl = Temp::new("crl.pem", b"CRL FILE");
    let id = identity(|id| {
        id.options.ca_blob = CaSetting::Default;
        id.options.ca_file = CaSetting::Given(ca.name());
        id.options.crl_file = Some(crl.name());
    });
    let (r, _, calls) = shake(World::one_round(), &id);
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(
        calls[2..5],
        [
            "roots(CA FILE)",
            "crls(CRL FILE)",
            "webpki(CA FILE, Some(\"CRL FILE\"))"
        ]
    );
    let world = World {
        answers: vec![("crls", Code::CertificateRevocationListParseError)],
        ..World::one_round()
    };
    let (r, notes, _) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::SslCrlBadfile));
    assert!(has(
        &notes,
        "fail: SslCrlBadfile: failed to parse revocation list: error parsing certificate revocation list (CRL)"
    ));
    let id = identity(|id| id.options.crl_file = Some(b"/no/such/crl.pem".to_vec()));
    let (r, notes, _) = shake(World::one_round(), &id);
    assert_eq!(r, Err(ErrorKind::SslCrlBadfile));
    assert!(has(
        &notes,
        "fail: SslCrlBadfile: rustls: failed to read revocation list file"
    ));
    // A directory opens, and fails to read.
    let dir = std::env::temp_dir();
    let id = identity(|id| id.options.crl_file = Some(dir.to_str().unwrap().as_bytes().to_vec()));
    let (r, _, _) = shake(World::one_round(), &id);
    assert_eq!(r, Err(ErrorKind::SslCrlBadfile));
}

/// The client's certificate and key come together, in PEM, from blobs or
/// files, and fail as C fails them.
#[test]
// Writes a file, which Miri's isolation keeps out.
#[cfg_attr(miri, ignore)]
fn the_client_s_certificate_and_key_are_c_s() {
    let fails = |change: &dyn Fn(&mut TlsIdentity), world: World| {
        let (r, notes, calls) = shake(world, &identity(change));
        (
            r,
            lines(&notes, "fail: ")
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            calls,
        )
    };
    let (r, notes, _) = fails(
        &|id| id.options.cert = Some(b"me.pem".to_vec()),
        World::one_round(),
    );
    assert_eq!(r, Err(ErrorKind::SslCertproblem));
    assert_eq!(
        notes,
        ["fail: SslCertproblem: rustls: must provide key with certificate"]
    );
    let (_, notes, _) = fails(
        &|id| id.options.key_blob = Some(b"K".to_vec()),
        World::one_round(),
    );
    assert_eq!(
        notes,
        ["fail: SslCertproblem: rustls: must provide certificate with key"]
    );
    let both = |id: &mut TlsIdentity| {
        id.options.cert_blob = Some(b"CERT".to_vec());
        id.options.key_blob = Some(b"KEY".to_vec());
        // C reads no password: a PEM key is not encrypted.
        id.options.key_password = Some(b"secret".to_vec());
    };
    let (r, _, calls) = fails(&both, World::one_round());
    assert_eq!(r, Ok(Handshake::Done));
    let at = calls.iter().position(|c| c == "verifier(webpki)").unwrap();
    assert_eq!(
        calls[at + 1..at + 4],
        [
            "certified_key(CERT, KEY)",
            "keys_match(key)",
            "certify(key)"
        ]
    );
    let (_, notes, _) = fails(
        &|id| {
            both(id);
            id.options.cert_type = Some(b"DER".to_vec());
        },
        World::one_round(),
    );
    assert_eq!(
        notes,
        [
            "fail: SslCertproblem: rustls: unsupported certificate type 'DER', only 'PEM' is supported"
        ]
    );
    let (r, _, _) = fails(
        &|id| {
            both(id);
            id.options.cert_type = Some(b"pem".to_vec());
            id.options.key_type = Some(b"Pem".to_vec());
        },
        World::one_round(),
    );
    assert_eq!(r, Ok(Handshake::Done));
    let (_, notes, _) = fails(
        &|id| {
            both(id);
            id.options.key_type = Some(b"ENG".to_vec());
        },
        World::one_round(),
    );
    assert_eq!(
        notes,
        ["fail: SslCertproblem: rustls: unsupported key type 'ENG', only 'PEM' is supported"]
    );
    let world = World {
        answers: vec![("certified_key", Code::PrivateKeyParseError)],
        ..World::one_round()
    };
    let (_, notes, _) = fails(&both, world);
    assert_eq!(
        notes,
        ["fail: SslCertproblem: rustls: failed to build certified key: error parsing private key"]
    );
    let world = World {
        answers: vec![("keys_match", Code::InconsistentKeysKeysMismatch)],
        ..World::one_round()
    };
    let (_, notes, _) = fails(&both, world);
    assert_eq!(
        notes,
        [
            "fail: SslCertproblem: rustls: client certificate and keypair files do not match:: keys may not be consistent: KeyMismatch"
        ]
    );
    // Blobs fit a buffer of 100 KiB with C's zero byte after them.
    let (r, notes, _) = fails(
        &|id| {
            both(id);
            id.options.cert_blob = Some(vec![b'C'; 100 * 1024]);
        },
        World::one_round(),
    );
    assert_eq!(r, Err(ErrorKind::TooLarge));
    assert_eq!(
        notes,
        ["fail: TooLarge: rustls: failed to copy client certificate blob (too large)"]
    );
    let (r, _, _) = fails(
        &|id| {
            both(id);
            id.options.key_blob = Some(vec![b'K'; 100 * 1024 - 1]);
        },
        World::one_round(),
    );
    assert_eq!(r, Ok(Handshake::Done));
    let (_, notes, _) = fails(
        &|id| {
            both(id);
            id.options.key_blob = Some(vec![b'K'; 100 * 1024]);
        },
        World::one_round(),
    );
    assert_eq!(
        notes,
        ["fail: TooLarge: rustls: failed to copy key blob (too large)"]
    );
    // Files are read whole, and one that does not read fails.
    let cert = Temp::new("cert.pem", b"CERT FILE");
    let key = Temp::new("key.pem", b"KEY FILE");
    let (cn, kn) = (cert.name(), key.name());
    let (r, _, calls) = fails(
        &|id| {
            id.options.cert = Some(cn.clone());
            id.options.key = Some(kn.clone());
        },
        World::one_round(),
    );
    assert_eq!(r, Ok(Handshake::Done));
    assert!(
        calls.contains(&"certified_key(CERT FILE, KEY FILE)".to_owned()),
        "{calls:#?}"
    );
    let (_, notes, _) = fails(
        &|id| {
            id.options.cert = Some(b"/no/cert.pem".to_vec());
            id.options.key = Some(kn.clone());
        },
        World::one_round(),
    );
    assert_eq!(
        notes,
        ["fail: SslCertproblem: rustls: failed to read client certificate file: '/no/cert.pem'"]
    );
    let (_, notes, _) = fails(
        &|id| {
            id.options.cert = Some(cn.clone());
            id.options.key = Some(b"/no/key.pem".to_vec());
        },
        World::one_round(),
    );
    assert_eq!(
        notes,
        ["fail: SslCertproblem: rustls: failed to read key file: '/no/key.pem'"]
    );
    // A file of 100 KiB does not fit.
    let big = Temp::new("big.pem", &vec![b'K'; 100 * 1024]);
    let bn = big.name();
    let (_, notes, _) = fails(
        &|id| {
            id.options.cert = Some(cn.clone());
            id.options.key = Some(bn.clone());
        },
        World::one_round(),
    );
    assert_eq!(notes.len(), 1, "{notes:#?}");
    assert!(notes[0].starts_with("fail: SslCertproblem: rustls: failed to read key file: "));
}

/// A configuration that does not build, and a connection that is not
/// made, fail as C fails them.
#[test]
fn the_configuration_and_the_connection_fail_as_c_s() {
    let world = World {
        answers: vec![("build", Code::General)],
        ..World::one_round()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(has(
        &notes,
        "fail: SslConnectError: failed to build client config: general error"
    ));
    let world = World {
        answers: vec![("connect", Code::InvalidDnsNameError)],
        ..World::one_round()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::CouldntConnect));
    assert!(has(
        &notes,
        "fail: CouldntConnect: rustls_client_connection_new: server name was malformed (not a valid hostname or IP address)"
    ));
    assert!(has(&notes, "trace: cr_connect, init backend -> 7"));
    // The connection is made to the name the URL gives, an address's too.
    let lib = Fake::new(World::one_round());
    let id = plain();
    let mut s = session_to(lib, &id, b"::1", TlsPeerKind::Ipv6, Alpn::None, None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().calls.contains(&"connect(::1)".to_owned()));
    // No offer, no ALPN set; what the peer chose is still said.
    assert!(lib.w().made("alpn").is_empty());
    assert!(has(
        &kept.notes.0,
        "info: ALPN: server did not agree on a protocol. Uses default."
    ));
}

/// The handshake waits on what would block, and fails on what fails as
/// C's `cr_connect` fails it.
#[test]
fn the_handshake_waits_and_fails_as_c_s() {
    let lib = Fake::new(World::one_round());
    let id = plain();
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    // The hello would block.
    let wire = Wire {
        room: Some(0),
        ..Wire::default()
    };
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(s.waits(), TlsWait::Send);
    assert!(has(&kept.notes.0, "trace: cf_send: EAGAIN after 0 bytes"));
    assert!(has(&kept.notes.0, "trace: rustls_send(len=0) -> 81, 0"));
    assert!(has(&kept.notes.0, "trace: writing would block"));
    // Then the reply would.
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(s.waits(), TlsWait::Recv);
    assert!(has(&kept.notes.0, "trace: cr_connect, state=2"));
    assert!(has(
        &kept.notes.0,
        "trace: cf->next recv(len=4096) -> 81, 0"
    ));
    assert!(has(&kept.notes.0, "trace: reading would block"));
    // Then the Finished would: the choice is said again, as the session
    // it now has.
    lib.w().alpn = Some(b"http/1.1");
    let wire = Wire {
        room: Some(0),
        ..Wire::with(b"reply")
    };
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(s.waits(), TlsWait::Send);
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(s.waits(), TlsWait::Nothing);
    assert_eq!(wire.sent(), b"finished");
    assert_eq!(
        lines(&kept.notes.0, "info: ALPN: server"),
        [
            "info: ALPN: server accepted http/1.1",
            "info: ALPN: server confirmed to use 'http/1.1'"
        ]
    );
    // The configuration is made once.
    assert_eq!(lib.w().made("builder(").len(), 1);
}

/// What ends the handshake: the connection's end, the records failing,
/// the socket failing, said in C's words with C's codes.
#[test]
fn the_handshake_s_failures_are_c_s() {
    let fail = |world: World, wire: Wire| {
        let lib = Fake::new(world);
        let id = plain();
        let mut s = session(lib, &id, Alpn::None);
        let mut kept = Kept::new();
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        (
            r,
            lines(&kept.notes.0, "fail: ")
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )
    };
    let closed = Wire {
        closed: true,
        ..Wire::default()
    };
    assert_eq!(
        fail(World::one_round(), closed),
        (
            Err(ErrorKind::SslConnectError),
            vec!["fail: SslConnectError: TLS connect error: Connection closed abruptly".to_owned()]
        )
    );
    // A certificate refused is the peer's verification failing.
    let mut world = World::one_round();
    world.processes[0] = vec![Ev::Fail(Code::CertUnknownIssuer)];
    assert_eq!(
        fail(world, Wire::with(b"x")),
        (
            Err(ErrorKind::PeerFailedVerification),
            vec!["fail: PeerFailedVerification: rustls_connection_process_new_packets: invalid peer certificate: UnknownIssuer".to_owned()]
        )
    );
    // Any other failure of the records, a connect error.
    let mut world = World::one_round();
    world.processes[0] = vec![Ev::Fail(Code::AlertHandshakeFailure)];
    let (r, notes) = fail(world, Wire::with(b"x"));
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert_eq!(
        notes,
        [
            "fail: RecvError: rustls_connection_process_new_packets: received fatal alert: HandshakeFailure"
        ]
    );
    // rustls-ffi's cert errors leave out the expired revocation list.
    let mut world = World::one_round();
    world.processes[0] = vec![Ev::Fail(Code::CertExpiredRevocationList)];
    let (r, _) = fail(world, Wire::with(b"x"));
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    // The socket failing is said as the I/O's EINVAL.
    let refusing = Wire {
        refuses: true,
        ..Wire::default()
    };
    let mut world = World::default();
    world.out.push_back(b"hello".to_vec());
    let (r, notes) = fail(world, refusing);
    assert_eq!(r, Err(ErrorKind::SendError));
    assert_eq!(
        notes,
        ["fail: SendError: writing to socket: Invalid argument"]
    );
    let refusing = Wire {
        refuses: true,
        ..Wire::default()
    };
    let (r, notes) = fail(World::default(), refusing);
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert_eq!(
        notes,
        ["fail: RecvError: reading from socket: Invalid argument"]
    );
    let world = World {
        read_tls_fails: Some(Errno::Io),
        ..World::default()
    };
    let (_, notes) = fail(world, Wire::default());
    assert_eq!(
        notes,
        ["fail: RecvError: reading from socket: Input/output error"]
    );
}

/// Reads give out the library's plain text, reading the records for more
/// while it has none; a record of none ends the read; the peer's
/// close_notify is the end, and its absence an error.
#[test]
fn reads_are_c_s() {
    let lib = Fake::new(World::one_round());
    let id = plain();
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    // The records of the handshake left the library with plain text
    // pending, as C's flag says.
    assert!(s.pending());
    lib.w()
        .processes
        .extend([vec![Ev::Plain(b"hello "), Ev::Plain(b"world")]]);
    let mut buf = [0u8; 64];
    let wire = Wire::with(b"rec");
    let got = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.recv(io, &mut buf));
    // The first read finds nothing pending, which ends the read: none yet.
    assert_eq!(got.unwrap(), Recv::WouldBlock);
    assert!(!s.pending());
    let got = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.recv(io, &mut buf));
    let Recv::Data(n) = got.unwrap() else {
        panic!("data")
    };
    assert_eq!(&buf[..n.get()], b"hello world");
    assert!(has(&kept.notes.0, "trace: rustls_recv(len=64) -> 0, 11"));
    // The close_notify, after more text: the text first, then the end.
    lib.w()
        .processes
        .push_back(vec![Ev::Plain(b"bye"), Ev::CloseNotify]);
    let wire = Wire::with(b"rec");
    let got = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.recv(io, &mut buf));
    let Recv::Data(n) = got.unwrap() else {
        panic!("data")
    };
    assert_eq!(&buf[..n.get()], b"bye");
    let got = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.recv(io, &mut buf));
    assert_eq!(got.unwrap(), Recv::Eof);
    assert!(has(&kept.notes.0, "trace: rustls_recv(len=64) -> 0, 0"));

    // The connection's end without the close_notify.
    let lib = Fake::new(World::one_round());
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    lib.w().read_fails = Some(Plain::Empty);
    let closed = Wire {
        closed: true,
        ..Wire::default()
    };
    let got = with_io(&mut s, &id, &mut kept, &closed, |s, io| {
        s.recv(io, &mut buf)
    });
    assert_eq!(got.unwrap(), Recv::WouldBlock);
    let got = with_io(&mut s, &id, &mut kept, &closed, |s, io| {
        s.recv(io, &mut buf)
    });
    assert!(got.is_err());
    assert!(has(
        &kept.notes.0,
        "fail: RecvError: rustls: peer closed TCP connection without first closing TLS connection"
    ));
    assert!(has(&kept.notes.0, "trace: rustls_recv(len=64) -> 56, 0"));
    // A read that fails otherwise.
    lib.w().read_fails = Some(Plain::Failed(Code::Io));
    let got = with_io(&mut s, &id, &mut kept, &closed, |s, io| {
        s.recv(io, &mut buf)
    });
    assert!(got.is_err());
    assert!(has(
        &kept.notes.0,
        "fail: RecvError: rustls_connection_read: I/O error"
    ));
}

/// A send hands the bytes to the library and writes its records; one that
/// blocks is counted at the next send, which writes what is left first.
#[test]
fn sends_are_c_s() {
    let lib = Fake::new(World::one_round());
    let id = plain();
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    let wire = Wire::default();
    let sent = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"GET /"));
    assert_eq!(sent.unwrap(), Sent::Bytes(5.try_into().unwrap()));
    assert_eq!(wire.sent(), b"E:GET /");
    assert!(has(
        &kept.notes.0,
        "trace: cf_send: adding 5 plain bytes to Rustls"
    ));
    assert!(has(&kept.notes.0, "trace: rustls_send(len=5) -> 0, 5"));
    // The records block: the send waits, the library holding the bytes.
    let blocked = Wire {
        room: Some(0),
        ..Wire::default()
    };
    let sent = with_io(&mut s, &id, &mut kept, &blocked, |s, io| {
        s.send(io, b"body!")
    });
    assert_eq!(sent.unwrap(), Sent::WouldBlock);
    assert!(has(&kept.notes.0, "trace: rustls_send(len=5) -> 81, 0"));
    // The same send again writes what is left and counts the bytes taken,
    // handing the library none of them twice.
    let wire = Wire::default();
    let sent = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"body!"));
    assert_eq!(sent.unwrap(), Sent::Bytes(5.try_into().unwrap()));
    assert_eq!(wire.sent(), b"E:body!");
    assert!(has(
        &kept.notes.0,
        "trace: cf_send: flushing 5 previously added bytes -> 0"
    ));
    assert_eq!(lib.w().made("write(").len(), 2);
    // A longer send counts those first and hands over the rest.
    let blocked = Wire {
        room: Some(0),
        ..Wire::default()
    };
    let sent = with_io(&mut s, &id, &mut kept, &blocked, |s, io| s.send(io, b"abc"));
    assert_eq!(sent.unwrap(), Sent::WouldBlock);
    let wire = Wire::default();
    let sent = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"abcdef"));
    assert_eq!(sent.unwrap(), Sent::Bytes(6.try_into().unwrap()));
    assert_eq!(wire.sent(), b"E:abcE:def");
    // Still blocked, the counted bytes wait too.
    let sent = with_io(&mut s, &id, &mut kept, &blocked, |s, io| s.send(io, b"xyz"));
    assert_eq!(sent.unwrap(), Sent::WouldBlock);
    let sent = with_io(&mut s, &id, &mut kept, &blocked, |s, io| s.send(io, b"xyz"));
    assert_eq!(sent.unwrap(), Sent::WouldBlock);
    assert!(has(
        &kept.notes.0,
        "trace: cf_send: flushing 3 previously added bytes -> 81"
    ));
    // The library taking part: what it took is sent, and the next send
    // its part again.
    let wire = Wire::default();
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"xyz")).unwrap();
    lib.w().write_room = Some(2);
    let sent = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"12345"));
    assert_eq!(sent.unwrap(), Sent::Bytes(2.try_into().unwrap()));
    // Its failures.
    lib.w().write_room = Some(0);
    let sent = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"345"));
    assert!(sent.is_err());
    assert!(has(
        &kept.notes.0,
        "fail: WriteError: rustls_connection_write: EOF"
    ));
    assert!(has(&kept.notes.0, "trace: rustls_send(len=3) -> 23, 0"));
    lib.w().answers.push(("write", Code::Io));
    let sent = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"345"));
    assert!(sent.is_err());
    assert!(has(
        &kept.notes.0,
        "fail: WriteError: rustls_connection_write: I/O error"
    ));
}

/// A send whose blocked bytes are more than it has counts them all.
#[test]
fn a_shorter_send_after_a_block_counts_what_was_taken() {
    let lib = Fake::new(World::one_round());
    let id = plain();
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    let blocked = Wire {
        room: Some(0),
        ..Wire::default()
    };
    let sent = with_io(&mut s, &id, &mut kept, &blocked, |s, io| {
        s.send(io, b"abcdef")
    });
    assert_eq!(sent.unwrap(), Sent::WouldBlock);
    let wire = Wire::default();
    let sent = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"abc"));
    assert_eq!(sent.unwrap(), Sent::Bytes(6.try_into().unwrap()));
    assert_eq!(lib.w().made("write(").len(), 1);
}

/// The goodbye sends the close_notify once, unless only the peer's is
/// waited for, and reads until the peer's.
#[test]
fn the_goodbye_is_c_s() {
    let lib = Fake::new(World::one_round());
    let id = plain();
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    // Before a connection, nothing to say.
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Done));
    let wire = Wire::with(b"x");
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    let blocked = Wire {
        room: Some(0),
        ..Wire::default()
    };
    let r = with_io(&mut s, &id, &mut kept, &blocked, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(s.waits(), TlsWait::Send);
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(s.waits(), TlsWait::Recv);
    assert_eq!(wire.sent(), b"close_notify");
    assert_eq!(lib.w().made("send_close_notify").len(), 1);
    lib.w().processes.push_back(vec![Ev::CloseNotify]);
    let wire = Wire::with(b"notify");
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Done));
    // The end is read ten times over, as C reads it.
    let ends = lines(&kept.notes.0, "trace: rustls_recv(len=1024) -> 0, 0");
    assert_eq!(ends.len(), 10);
    // Over, it stays over.
    let calls = lib.w().calls.len();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().calls.len(), calls);

    // Only the peer's waited for: none is sent.
    let lib = Fake::new(World::one_round());
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    lib.w()
        .processes
        .push_back(vec![Ev::Plain(b"late"), Ev::CloseNotify]);
    let wire = Wire::with(b"notify");
    // The handshake's records left the library's text pending: the first
    // read finds none, and the goodbye waits, as C's does.
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Heard)
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Heard)
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().made("send_close_notify").is_empty());
    assert_eq!(wire.sent(), b"");

    // A read that fails ends it.
    let lib = Fake::new(World::one_round());
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    lib.w().read_fails = Some(Plain::Failed(Code::Io));
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Err(ErrorKind::RecvError));
    assert!(has(&kept.notes.0, "trace: shutdown, error: 56"));
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Done));

    // Data that keeps coming leaves it waiting.
    let lib = Fake::new(World::one_round());
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    lib.w().plain = vec![b'z'; 20 * 1024];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Waiting));

    // A send that fails ends it.
    let lib = Fake::new(World::one_round());
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    let refusing = Wire {
        refuses: true,
        ..Wire::default()
    };
    let r = with_io(&mut s, &id, &mut kept, &refusing, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Err(ErrorKind::SendError));
    assert!(has(&kept.notes.0, "trace: shutdown send failed: 55"));
}

/// The key log is opened as each configuration is built, and given to it
/// only while open.
#[test]
// Writes a file, which Miri's isolation keeps out.
#[cfg_attr(miri, ignore)]
fn the_key_log_is_given_while_open() {
    let id = plain();
    let log = SharedKeyLog::new().unwrap();
    let lib = Fake::new(World::one_round());
    let mut s = session_to(
        lib,
        &id,
        HOST,
        TlsPeerKind::Name,
        Alpn::None,
        Some(log.clone()),
    );
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    // No `SSLKEYLOGFILE` in the tests' environment: it stays closed.
    assert!(lib.w().made("key_log").is_empty());
    let path = std::env::temp_dir().join(format!("curl-rustls-keylog-{}", std::process::id()));
    log.open_named(path.to_str().unwrap().as_bytes());
    let lib = Fake::new(World::one_round());
    let mut s = session_to(
        lib,
        &id,
        HOST,
        TlsPeerKind::Name,
        Alpn::None,
        Some(log.clone()),
    );
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    let w = lib.w();
    assert_eq!(w.made("key_log"), ["key_log"]);
    let given = w.key_log.as_ref().unwrap();
    assert!(given.enabled());
    drop(w);
    log.close();
    std::fs::remove_file(&path).unwrap();
}

/// The library's own objects are not handed out: C's are rustls-ffi's
/// `rustls_connection`, which this build has none of (`DIVERGENCE.md`,
/// `CURLINFO_TLS_SSL_PTR`).
#[test]
fn the_library_s_objects_are_not_handed_out() {
    let lib = Fake::new(World::one_round());
    let id = plain();
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    assert_eq!(s.native(), None);
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    assert_eq!(s.native(), None);
}

/// The version is said as the library says it.
#[test]
fn a_version_unknown_is_said_so() {
    let world = World {
        version: TLS1_2,
        suite_name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        group_name: "X25519",
        ..World::one_round()
    };
    let (_, notes, _) = shake(world, &plain());
    assert!(has(
        &notes,
        "info: rustls: handshake complete, TLSv1.2, ciphersuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, key exchange group: X25519"
    ));
    let world = World {
        version: 0,
        suite_name: "",
        group_name: "",
        ..World::one_round()
    };
    let (_, notes, _) = shake(world, &plain());
    assert!(has(
        &notes,
        "info: rustls: handshake complete, TLS version unknown, ciphersuite: , key exchange group: "
    ));
}

/// The failures of a handshake's configuration, as `shake` makes them.
fn failures(
    change: impl FnOnce(&mut TlsIdentity),
    world: World,
) -> (Result<Handshake, ErrorKind>, Vec<String>) {
    let (r, notes, _) = shake(world, &identity(change));
    let failed = lines(&notes, "fail: ")
        .iter()
        .map(|s| s.to_string())
        .collect();
    (r, failed)
}

/// Each half of the client's pair alone is refused, whichever way given;
/// what fits a buffer with C's zero byte after it is read.
#[test]
// Writes a file, which Miri's isolation keeps out.
#[cfg_attr(miri, ignore)]
fn each_half_of_the_pair_alone_is_refused_and_what_fits_is_read() {
    let (_, notes) = failures(
        |id| id.options.cert_blob = Some(b"C".to_vec()),
        World::one_round(),
    );
    assert_eq!(
        notes,
        ["fail: SslCertproblem: rustls: must provide key with certificate"]
    );
    let (_, notes) = failures(
        |id| id.options.key = Some(b"key.pem".to_vec()),
        World::one_round(),
    );
    assert_eq!(
        notes,
        ["fail: SslCertproblem: rustls: must provide certificate with key"]
    );
    // A certificate blob one byte short of the buffer.
    let (r, _) = failures(
        |id| {
            id.options.cert_blob = Some(vec![b'C'; 100 * 1024 - 1]);
            id.options.key_blob = Some(b"K".to_vec());
        },
        World::one_round(),
    );
    assert_eq!(r, Ok(Handshake::Done));
    // A key file one byte short, read whole.
    let key = Temp::new("short.pem", &vec![b'K'; 100 * 1024 - 1]);
    let kn = key.name();
    let (r, notes, calls) = shake(
        World::one_round(),
        &identity(|id| {
            id.options.cert_blob = Some(b"C".to_vec());
            id.options.key = Some(kn.clone());
        }),
    );
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    let made = calls
        .iter()
        .find(|c| c.starts_with("certified_key("))
        .unwrap();
    assert_eq!(made.len(), "certified_key(C, )".len() + 100 * 1024 - 1);
    // A revocation list past the key's limit, read whole.
    let crl = Temp::new("big-crl.pem", &vec![b'R'; 2 * 1024 * 1024]);
    let cn = crl.name();
    let (r, _, calls) = shake(
        World::one_round(),
        &identity(|id| id.options.crl_file = Some(cn.clone())),
    );
    assert_eq!(r, Ok(Handshake::Done));
    let made = calls.iter().find(|c| c.starts_with("crls(")).unwrap();
    assert_eq!(made.len(), "crls()".len() + 2 * 1024 * 1024);
}

/// A CA file whose name is not UTF-8 is not read: rustls-ffi takes the
/// name as a string, and fails it as I/O.
#[cfg(unix)]
#[test]
#[cfg_attr(miri, ignore)]
fn a_ca_file_named_outside_utf8_fails_as_i_o() {
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    let mut name = std::env::temp_dir()
        .join(format!("curl-rustls-{}-", std::process::id()))
        .into_os_string()
        .into_vec();
    name.extend_from_slice(b"\xff.pem");
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&name));
    std::fs::write(path, b"CA").unwrap();
    let id = identity(|id| {
        id.options.ca_blob = CaSetting::Default;
        id.options.ca_file = CaSetting::Given(name.clone());
    });
    let (r, notes, calls) = shake(World::one_round(), &id);
    std::fs::remove_file(path).unwrap();
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    assert!(has(
        &notes,
        "fail: SslCacertBadfile: failed to load trusted certificates: I/O error"
    ));
    assert!(lines(&calls, "roots").is_empty());
}

/// A read that fills the buffer leaves the library's text pending.
#[test]
fn a_full_read_leaves_the_text_pending() {
    let lib = Fake::new(World::one_round());
    let id = plain();
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    lib.w().plain = b"abcd".to_vec();
    let mut buf = [0u8; 4];
    let got = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.recv(io, &mut buf));
    assert_eq!(got.unwrap(), Recv::Data(4.try_into().unwrap()));
    assert!(s.pending());
    assert_eq!(lib.w().made("read("), ["read(4)"]);
}

/// Records written before one blocks are counted in what is said, and a
/// send whose earlier bytes went out before its own blocked counts those.
#[test]
fn a_send_blocked_part_way_counts_what_went() {
    let lib = Fake::new(World::one_round());
    let id = plain();
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::with(b"x");
    with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io)).unwrap();
    // Two records waiting, the second blocked.
    {
        let mut w = lib.w();
        w.out.push_back(b"first".to_vec());
        w.write_tls_fails.extend([None, Some(Errno::Again)]);
    }
    let sent = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"abc"));
    assert_eq!(sent.unwrap(), Sent::WouldBlock);
    assert!(
        has(&kept.notes.0, "trace: cf_send: EAGAIN after 5 bytes"),
        "{:#?}",
        kept.notes.0
    );
    // Its bytes go out with the next send, whose own then block: the
    // earlier are counted.
    lib.w().write_tls_fails.extend([None, Some(Errno::Again)]);
    let sent = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"abcdef"));
    assert_eq!(sent.unwrap(), Sent::Bytes(3.try_into().unwrap()));
    // Counted, the send is said to have succeeded.
    assert!(
        has(&kept.notes.0, "trace: rustls_send(len=6) -> 0, 3"),
        "{:#?}",
        kept.notes.0
    );
    let sent = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"def"));
    assert_eq!(sent.unwrap(), Sent::Bytes(3.try_into().unwrap()));
    assert_eq!(wire.sent(), b"hellofinishedfirstE:abcE:def");
    assert_eq!(lib.w().made("write("), ["write(3)", "write(3)"]);
}

/// A result rustls-ffi gives for a NULL argument is a bad argument.
#[test]
fn a_null_parameter_is_a_bad_argument() {
    let mut world = World::one_round();
    world.processes[0] = vec![Ev::Fail(Code::NullParameter)];
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::BadFunctionArgument));
    assert!(has(
        &notes,
        "fail: BadFunctionArgument: rustls_connection_process_new_packets: a parameter was NULL"
    ));
}

/// Rustls has no channel binding.
#[test]
fn there_is_no_channel_binding() {
    struct NoNotes;
    impl curl_core::tls::BindingNotes for NoNotes {
        fn info(&mut self, _: core::fmt::Arguments<'_>) {}
        fn fail(&mut self, kind: ErrorKind, _: core::fmt::Arguments<'_>) -> ErrorKind {
            kind
        }
    }
    let lib = Fake::new(World::one_round());
    let id = plain();
    let s = session(lib, &id, Alpn::None);
    assert_eq!(s.channel_binding(&mut NoNotes), Ok(None));
}

/// A chain longer than C reports fails the handshake, counted before
/// any of it is read.
#[test]
fn a_chain_past_c_s_most_fails() {
    use curl_core::tls::ContextHandler;
    let run = |n: usize| {
        let lib = Fake::new(World {
            certs: vec![b"not a certificate"; n],
            ..World::one_round()
        });
        let id = plain();
        let mut s = session(lib, &id, Alpn::None);
        let mut kept = Kept::new();
        kept.context = Some(ContextHandler {
            report: Some(Default::default()),
            ..ContextHandler::default()
        });
        let wire = Wire::with(b"x");
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        let failed: Vec<String> = lines(&kept.notes.0, "fail: ")
            .iter()
            .map(|s| s.to_string())
            .collect();
        (r, failed)
    };
    let (r, notes) = run(101);
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert_eq!(
        notes,
        ["fail: SslConnectError: 101 certificates is more than allowed (100)"]
    );
    // A hundred are read, and the first, not a certificate, fails.
    let (r, notes) = run(100);
    assert!(r.is_err());
    assert!(
        !notes.iter().any(|n| n.contains("more than allowed")),
        "{notes:#?}"
    );
}
