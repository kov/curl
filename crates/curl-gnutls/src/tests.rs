//! The session over the scripted library (`fake.rs`): the calls made of
//! GnuTLS in `gtls.c`'s order, and what is made of each answer, said in
//! C's words.

use std::time::Duration;

use curl_alloc::TryArc;
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::options::{
    CaCache, CaSetting, ColdGroup as _, TlsMaxVersion, TlsMinVersion, TlsOptions,
};
use curl_core::tls::{
    Alpn, CaDefaults, Chosen, DriveCall, Goodbye, Handshake, Kept, QuicContextSetup, QuicTls as _,
    SharedKeyLog, TlsCx, TlsIdentity, TlsIo, TlsNative, TlsPeer, TlsPeerKind, TlsSession as _,
    TlsShared, TlsWait,
};

use crate::fake::{Act, Fake, Wire, World};
use crate::library::Stapled;
use crate::quic::QuicSession;
use crate::session::Session;
use crate::sys;

const HOST: &[u8] = b"example.com";

fn identity(change: impl FnOnce(&mut TlsIdentity)) -> TryArc<TlsIdentity> {
    let mut id = TlsIdentity {
        verify_peer: true,
        verify_host: true,
        options: TlsOptions::NONE,
        ca_defaults: CaDefaults::NONE,
    };
    change(&mut id);
    TryArc::try_new(id).unwrap()
}

fn plain() -> TryArc<TlsIdentity> {
    identity(|_| {})
}

fn peer(name: &[u8], kind: TlsPeerKind, early_data: bool) -> TlsPeer<'_> {
    TlsPeer {
        name,
        port: 443,
        kind,
        early_data,
    }
}

/// A session of `lib` for `id` to `HOST`, offering `alpn`.
fn session(
    lib: &'static Fake,
    id: &TryArc<TlsIdentity>,
    alpn: Alpn,
    shared: &TlsShared,
) -> Session<Fake> {
    Session::new(
        lib,
        id,
        &peer(HOST, TlsPeerKind::Name, false),
        alpn,
        shared,
        None,
    )
    .unwrap()
}

/// Run `f` on `s` with the I/O over `wire`, the sessions kept in `kept`.
fn with_io<R>(
    s: &mut Session<Fake>,
    id: &TryArc<TlsIdentity>,
    kept: &mut Kept,
    wire: &Wire,
    f: impl FnOnce(&mut Session<Fake>, &mut TlsIo<'_>) -> R,
) -> R {
    TlsIo::testing(id, HOST, kept, wire, |io| f(s, io))
}

/// A handshake of a fresh session of `world`'s library for `id`: its
/// result, what was noted, and the library's calls.
fn shake(
    world: World,
    id: &TryArc<TlsIdentity>,
) -> (Result<Handshake, ErrorKind>, Vec<String>, Vec<String>) {
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let mut s = session(lib, id, Alpn::H2Http11, &shared);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, id, &mut kept, &wire, |s, io| s.handshake(io));
    let calls = lib.w().calls.clone();
    (r, kept.notes.0, calls)
}

fn has(notes: &[String], line: &str) -> bool {
    notes.iter().any(|n| n == line)
}

/// Where `call` is among `calls`, which must have it.
fn at(calls: &[String], call: &str) -> usize {
    calls
        .iter()
        .position(|c| c == call)
        .unwrap_or_else(|| panic!("{call}: {calls:#?}"))
}

#[test]
fn a_handshake_makes_the_session_as_gtls_c_does() {
    let (r, notes, calls) = shake(World::default(), &plain());
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    let want = [
        "creds",
        "session(flags=202)",
        "server_name(example.com)",
        "default_priority",
    ];
    assert_eq!(&calls[..4], want);
    assert!(calls[4].starts_with("priority(NORMAL:"), "{calls:#?}");
    assert_eq!(
        &calls[5..10],
        [
            "credentials",
            "alpn(h2,http/1.1)",
            "hook",
            "handshake",
            "verify_peers"
        ]
    );
    assert!(
        calls.contains(&"import(leaf-der, Der)".to_owned()),
        "{calls:#?}"
    );
    assert!(calls.contains(&"matches_host(example.com)".to_owned()));
    for line in [
        "trace: gnutls_init(flags=202), earlydata=0",
        "info: ALPN: curl offers h2,http/1.1",
        "trace: loading trust anchors and CRLs",
        "info: SSL Trust Anchors:",
        "info:   no trust anchors configured",
        "info:   SSL certificate verified by GnuTLS",
        "info:   SSL certificate expiration date OK",
        "info:   SSL certificate activation date OK",
        "info:   SSL certificate status verification SKIPPED",
        "info:   common name: example.com (matched)",
        "info: ALPN: server did not agree on a protocol. Uses default.",
        "trace: gtls_connect_common() -> 0, done=1",
    ] {
        assert!(has(&notes, line), "{line}: {notes:#?}");
    }
}

#[test]
fn the_priority_string_follows_the_versions_and_the_cipher_list() {
    let id = identity(|i| {
        i.options.min_version = TlsMinVersion::Tls1_3;
        i.options.ciphers = Some(b"+AES-128-CBC".to_vec());
    });
    let (_, notes, calls) = shake(World::default(), &id);
    let p = calls.iter().find(|c| c.starts_with("priority(")).unwrap();
    assert!(
        p.ends_with(":-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.3:+AES-128-CBC)"),
        "{p}"
    );
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("info: GnuTLS priority: NORMAL:")),
        "{notes:#?}"
    );
    // A range the library has no string for.
    let id = identity(|i| {
        i.options.min_version = TlsMinVersion::Tls1_3;
        i.options.max_version = TlsMaxVersion::Tls1_2;
    });
    let (r, notes, _) = shake(World::default(), &id);
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(
        has(
            &notes,
            "fail: SslConnectError: GnuTLS: cannot set TLS protocol"
        ),
        "{notes:#?}"
    );
    // One the library refuses, said with where it stopped.
    let world = World {
        answers: vec![("priority", -50)],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("fail: SslConnectError: Error -50 setting GnuTLS priority: ")),
        "{notes:#?}"
    );
}

#[test]
fn the_name_sent_is_the_host_s_lower_case_without_its_dot_and_none_for_an_address() {
    let lib = Fake::new(World::default());
    let shared = TlsShared::testing();
    let id = plain();
    let mut kept = Kept::new();
    let wire = Wire::default();
    let mut s = Session::new(
        lib,
        &id,
        &peer(b"Example.COM.", TlsPeerKind::Name, false),
        Alpn::Http11,
        &shared,
        None,
    )
    .unwrap();
    let _ = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert!(
        lib.w()
            .calls
            .contains(&"server_name(example.com)".to_owned())
    );
    assert!(
        lib.w()
            .calls
            .contains(&"matches_host(example.com)".to_owned())
    );

    let lib = Fake::new(World::default());
    let mut s = Session::new(
        lib,
        &id,
        &peer(b"10.0.0.1", TlsPeerKind::Ipv4, false),
        Alpn::Http11,
        &shared,
        None,
    )
    .unwrap();
    let _ = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    let calls = lib.w().calls.clone();
    assert!(
        !calls.iter().any(|c| c.starts_with("server_name")),
        "{calls:#?}"
    );
    assert!(calls.contains(&"matches_host(10.0.0.1)".to_owned()));
}

#[test]
fn the_trust_is_loaded_at_the_first_read_after_the_client_hello() {
    let world = World {
        answers: vec![("trust_file", 3)],
        scripts: vec![(
            "handshake",
            vec![Act::Push(b"hello"), Act::Pull(5), Act::Return(-28)],
        )],
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = identity(|i| i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec()));
    let mut s = session(lib, &id, Alpn::Http11, &shared);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(s.waits(), TlsWait::Recv);
    assert_eq!(wire.sent(), b"hello");
    let calls = lib.w().calls.clone();
    assert!(
        at(&calls, "handshake") < at(&calls, "trust_file(/ca.pem)"),
        "{calls:#?}"
    );
    assert!(at(&calls, "allow_v1_ca") < at(&calls, "trust_file(/ca.pem)"));
    let notes = &kept.notes.0;
    assert!(has(notes, "trace: gtls_push(len=5) -> 0, 5"), "{notes:#?}");
    assert!(has(notes, "trace: gtls_pull(len=5) -> 81, 0"), "{notes:#?}");
    assert!(
        has(notes, "info:   CAfile: 3 certificates in /ca.pem"),
        "{notes:#?}"
    );
    // Loaded once: the next step reads without loading again.
    lib.w()
        .scripts
        .push(("handshake", vec![Act::Pull(5), Act::Return(-28)]));
    let wire = Wire::with(b"howdy");
    let _ = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(lib.w().made("trust_file").len(), 1);
    assert_eq!(lib.w().pulled, b"howdy");
}

#[test]
fn a_session_waiting_to_write_says_so() {
    let world = World {
        scripts: vec![(
            "handshake",
            vec![Act::WantsWrite(true), Act::Push(b"hello"), Act::Return(-28)],
        )],
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = plain();
    let mut s = session(lib, &id, Alpn::Http11, &shared);
    let mut kept = Kept::new();
    let wire = Wire {
        room: Some(0),
        ..Wire::default()
    };
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(s.waits(), TlsWait::Send);
    assert!(
        has(&kept.notes.0, "trace: gtls_push(len=5) -> 81, 0"),
        "{:#?}",
        kept.notes.0
    );
}

#[test]
fn with_a_client_certificate_the_trust_is_loaded_before_the_client_hello() {
    let world = World {
        answers: vec![("trust_file", 1)],
        ..World::default()
    };
    let id = identity(|i| {
        i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
        i.options.cert = Some(b"/client.pem".to_vec());
        i.options.key = Some(b"/client.key".to_vec());
    });
    let (r, _, calls) = shake(world, &id);
    assert_eq!(r, Ok(Handshake::Done));
    let key = "key_file(/client.pem, /client.key, Pem, None)";
    assert!(
        at(&calls, "trust_file(/ca.pem)") < at(&calls, key),
        "{calls:#?}"
    );
    assert!(at(&calls, key) < at(&calls, "handshake"));
    assert_eq!(
        calls.iter().filter(|c| c.starts_with("trust_file")).count(),
        1
    );
}

#[test]
fn a_client_certificate_is_read_as_its_type_says() {
    let id = identity(|i| {
        i.options.cert = Some(b"/client.p12".to_vec());
        i.options.cert_type = Some(b"p12".to_vec());
        i.options.key_password = Some(b"pw".to_vec());
    });
    let (_, _, calls) = shake(World::default(), &id);
    assert!(
        calls.contains(&"pkcs12_file(/client.p12, pw)".to_owned()),
        "{calls:#?}"
    );
    let id = identity(|i| {
        i.options.cert = Some(b"/client.der".to_vec());
        i.options.cert_type = Some(b"DER".to_vec());
    });
    let (_, _, calls) = shake(World::default(), &id);
    assert!(
        calls.contains(&"key_file(/client.der, /client.der, Der, None)".to_owned()),
        "{calls:#?}"
    );
    // A key that will not read.
    let id = identity(|i| {
        i.options.cert = Some(b"/client.pem".to_vec());
        i.options.key_password = Some(b"pw".to_vec());
    });
    let world = World {
        answers: vec![("key_file", -64)],
        ..World::default()
    };
    let (r, notes, calls) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(calls.contains(&"key_file(/client.pem, /client.pem, Pem, Some(\"pw\"))".to_owned()));
    assert!(
        has(
            &notes,
            "fail: SslConnectError: error reading X.509 potentially-encrypted key file: an error"
        ),
        "{notes:#?}"
    );
    let world = World {
        answers: vec![("pkcs12_file", -64)],
        ..World::default()
    };
    let id = identity(|i| {
        i.options.cert = Some(b"/client.p12".to_vec());
        i.options.cert_type = Some(b"P12".to_vec());
    });
    let (r, notes, calls) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(calls.contains(&"pkcs12_file(/client.p12, )".to_owned()));
    assert!(has(
        &notes,
        "fail: SslConnectError: error reading X.509 potentially-encrypted key or certificate file: an error"
    ));
}

#[test]
fn a_trust_source_that_fails_fails_the_handshake_unless_another_gave_anchors() {
    let file = |i: &mut TlsIdentity| i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
    let world = World {
        answers: vec![("trust_file", -64)],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &identity(file));
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    assert!(
        has(
            &notes,
            "info: error reading CA cert file /ca.pem (an error)"
        ),
        "{notes:#?}"
    );
    // The directory gave none either.
    let world = World {
        answers: vec![("trust_file", 2), ("trust_dir", -64)],
        ..World::default()
    };
    let id = identity(|i| {
        file(i);
        i.options.ca_path = CaSetting::Given(b"/certs".to_vec());
    });
    let (r, notes, _) = shake(world, &id);
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    assert!(
        has(
            &notes,
            "info: error reading CA cert file /certs (an error), continuing anyway"
        ),
        "{notes:#?}"
    );
    assert!(!has(&notes, "info:   no trust anchors configured"));
    // A blob in place of the file.
    let world = World {
        answers: vec![("trust_mem", -64)],
        ..World::default()
    };
    let id = identity(|i| {
        file(i);
        i.options.ca_blob = CaSetting::Given(b"PEM".to_vec());
    });
    let (r, notes, calls) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    assert!(
        !calls.iter().any(|c| c.starts_with("trust_file")),
        "{calls:#?}"
    );
    assert!(
        has(&notes, "info: error reading CA cert blob (an error)"),
        "{notes:#?}"
    );
    // A revocation list that will not read fails whatever else gave.
    let world = World {
        answers: vec![("trust_file", 2), ("crl_file", -64)],
        ..World::default()
    };
    let id = identity(|i| {
        file(i);
        i.options.crl_file = Some(b"/crl.pem".to_vec());
    });
    let (r, notes, _) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::SslCrlBadfile));
    assert!(
        has(
            &notes,
            "fail: SslCrlBadfile: error reading CRL file /crl.pem (an error)"
        ),
        "{notes:#?}"
    );
    let world = World {
        answers: vec![("crl_file", 1)],
        ..World::default()
    };
    let (_, notes, _) = shake(world, &id);
    assert!(
        has(&notes, "info:   CRLfile: 1 CRL in /crl.pem"),
        "{notes:#?}"
    );
}

#[test]
fn the_native_store_is_loaded_where_asked() {
    let id = identity(|i| i.options.ssl_options = curl_core::options::SslOptions::NATIVE_CA);
    let world = World {
        answers: vec![("system_trust", 140)],
        ..World::default()
    };
    let (_, notes, _) = shake(world, &id);
    assert!(
        has(&notes, "info:   Native: 140 certificates from system trust"),
        "{notes:#?}"
    );
    assert!(!has(&notes, "info:   no trust anchors configured"));
    let world = World {
        answers: vec![("system_trust", -64)],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &id);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(
        has(
            &notes,
            "info: error reading native CA store (an error), continuing anyway"
        ),
        "{notes:#?}"
    );
    assert!(has(&notes, "info:   no trust anchors configured"));
}

#[test]
fn an_unverified_peer_loads_no_trust_and_is_not_checked() {
    let id = identity(|i| {
        i.verify_peer = false;
        i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
    });
    let (r, notes, calls) = shake(World::default(), &id);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("trust_file") || c == "verify_peers")
    );
    assert!(has(&notes, "info: SSL Trust: peer verification disabled"));
    assert!(has(&notes, "info:   SSL certificate verification SKIPPED"));
}

#[test]
fn the_multi_s_credentials_are_taken_while_they_may_be() {
    let id = identity(|i| i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec()));
    let world = World {
        answers: vec![("trust_file", 1)],
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let wire = Wire::default();
    let connect = |id: &TryArc<TlsIdentity>| {
        let mut s = session(lib, id, Alpn::Http11, &shared);
        let mut kept = Kept::new();
        let r = with_io(&mut s, id, &mut kept, &wire, |s, io| s.handshake(io));
        assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept.notes.0);
        kept.notes.0
    };
    connect(&id);
    let notes = connect(&id);
    assert!(
        has(&notes, "trace: using shared trust anchors and CRLs"),
        "{notes:#?}"
    );
    assert_eq!(lib.w().made("trust_file").len(), 1);
    // Another file loads its own, and keeps them in place of the first.
    let other = identity(|i| i.options.ca_file = CaSetting::Given(b"/other.pem".to_vec()));
    let notes = connect(&other);
    assert!(
        has(&notes, "trace: loading trust anchors and CRLs"),
        "{notes:#?}"
    );
    let notes = connect(&id);
    assert!(
        has(&notes, "trace: loading trust anchors and CRLs"),
        "{notes:#?}"
    );
    // Kept for no time, they are never taken.
    let now = identity(|i| {
        i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
        i.options.ca_cache = CaCache::For(Duration::ZERO);
    });
    let notes = connect(&now);
    assert!(
        has(&notes, "trace: loading trust anchors and CRLs"),
        "{notes:#?}"
    );
    // Forever, they are.
    let forever = identity(|i| {
        i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
        i.options.ca_cache = CaCache::Forever;
    });
    let notes = connect(&forever);
    assert!(
        has(&notes, "trace: using shared trust anchors and CRLs"),
        "{notes:#?}"
    );
}

#[test]
fn credentials_are_kept_for_the_multi_only_where_they_may_be() {
    let base = |i: &mut TlsIdentity| i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
    assert!(crate::trust::cacheable(&identity(base)));
    let not: [&dyn Fn(&mut TlsIdentity); 7] = [
        &|i| i.options.ca_cache = CaCache::Off,
        &|i| i.verify_peer = false,
        &|i| i.options.ca_path = CaSetting::Given(b"/certs".to_vec()),
        &|i| i.options.ca_blob = CaSetting::Given(b"PEM".to_vec()),
        &|i| i.options.crl_file = Some(b"/crl.pem".to_vec()),
        &|i| i.options.ssl_options = curl_core::options::SslOptions::NATIVE_CA,
        &|i| i.options.cert = Some(b"/client.pem".to_vec()),
    ];
    for (n, change) in not.iter().enumerate() {
        let id = identity(|i| {
            base(i);
            change(i);
        });
        assert!(!crate::trust::cacheable(&id), "{n}");
    }
}

/// A verified handshake's failure, and what was noted, for `world`.
fn fails(world: World, id: &TryArc<TlsIdentity>) -> (ErrorKind, Vec<String>) {
    let (r, notes, _) = shake(world, id);
    (r.expect_err("fails"), notes)
}

#[test]
fn the_chain_s_verdict_is_said_as_c_says_it() {
    let invalid = sys::GNUTLS_CERT_INVALID;
    for (status, kind, cause) in [
        (
            invalid | sys::GNUTLS_CERT_EXPIRED,
            ErrorKind::PeerFailedVerification,
            "certificate has expired",
        ),
        (
            invalid | sys::GNUTLS_CERT_SIGNER_NOT_FOUND,
            ErrorKind::PeerFailedVerification,
            "certificate signer not trusted",
        ),
        (
            invalid | sys::GNUTLS_CERT_INSECURE_ALGORITHM,
            ErrorKind::PeerFailedVerification,
            "certificate uses insecure algorithm",
        ),
        (
            invalid | sys::GNUTLS_CERT_INVALID_OCSP_STATUS,
            ErrorKind::SslInvalidcertstatus,
            "OCSP status response is invalid",
        ),
        (
            invalid,
            ErrorKind::PeerFailedVerification,
            "certificate error, no details available",
        ),
    ] {
        let world = World {
            status: Ok(status),
            ..World::default()
        };
        let (got, notes) = fails(world, &plain());
        assert_eq!(got, kind, "{cause}");
        let line = format!(
            "fail: {kind:?}: SSL certificate verification failed: {cause}. (CAfile: none CRLfile: none)"
        );
        assert!(has(&notes, &line), "{line}: {notes:#?}");
    }
    // Bits without `INVALID` verify.
    let world = World {
        status: Ok(sys::GNUTLS_CERT_EXPIRED),
        ..World::default()
    };
    assert_eq!(shake(world, &plain()).0, Ok(Handshake::Done));
    let world = World {
        status: Err(-49),
        ..World::default()
    };
    let (got, notes) = fails(world, &plain());
    assert_eq!(got, ErrorKind::SslConnectError);
    assert!(has(
        &notes,
        "fail: SslConnectError: server cert verify failed: -49"
    ));
    // The files named, where they are.
    let world = World {
        status: Ok(invalid),
        ..World::default()
    };
    let id = identity(|i| {
        i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
        i.options.crl_file = Some(b"/crl.pem".to_vec());
    });
    let (_, notes) = fails(world, &id);
    assert!(
        notes
            .iter()
            .any(|n| n.ends_with("(CAfile: /ca.pem CRLfile: /crl.pem)"))
    );
}

#[test]
fn a_peer_without_a_certificate_fails_unless_nothing_is_checked() {
    let world = || World {
        chain: None,
        ..World::default()
    };
    let (got, notes) = fails(world(), &plain());
    assert_eq!(got, ErrorKind::PeerFailedVerification);
    assert!(has(
        &notes,
        "fail: PeerFailedVerification: failed to get server cert"
    ));
    for change in [
        (|i: &mut TlsIdentity| i.verify_peer = false) as fn(&mut TlsIdentity),
        |i| i.verify_host = false,
    ] {
        let id = identity(|i| {
            i.verify_peer = false;
            i.verify_host = false;
            i.options.issuer_cert = Some(b"/issuer.pem".to_vec());
            change(i);
        });
        assert_eq!(fails(world(), &id).0, ErrorKind::PeerFailedVerification);
    }
    let id = identity(|i| {
        i.verify_peer = false;
        i.verify_host = false;
    });
    let (r, notes, _) = shake(world(), &id);
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    assert!(has(&notes, "info:  common name: WARNING could not obtain"));
}

#[test]
fn a_certificate_out_of_its_dates_fails_a_verified_peer() {
    let dated = |expiration, activation| World {
        leaf: crate::fake::Leaf {
            expiration,
            activation,
            ..World::default().leaf
        },
        ..World::default()
    };
    // Now is 0: at its last second it has not expired, at its first it
    // has started.
    assert_eq!(shake(dated(0, 0), &plain()).0, Ok(Handshake::Done));
    for (world, kind, line) in [
        (
            dated(-1, 0),
            ErrorKind::SslConnectError,
            "server cert expiration date verify failed",
        ),
        (
            dated(-5, 0),
            ErrorKind::PeerFailedVerification,
            "server certificate expiration date has passed.",
        ),
        (
            dated(10, -1),
            ErrorKind::SslConnectError,
            "server cert activation date verify failed",
        ),
        (
            dated(10, 5),
            ErrorKind::PeerFailedVerification,
            "server certificate not activated yet.",
        ),
    ] {
        let (got, notes) = fails(world, &plain());
        assert_eq!(got, kind, "{line}");
        assert!(
            has(&notes, &format!("fail: {kind:?}: {line}")),
            "{notes:#?}"
        );
    }
    let id = identity(|i| i.verify_peer = false);
    for (world, line) in [
        (
            dated(-1, 0),
            "info:   SSL certificate expiration date verify FAILED",
        ),
        (
            dated(-5, 0),
            "info:   SSL certificate expiration date FAILED",
        ),
        (
            dated(10, -1),
            "info:   SSL certificate activation date verify FAILED",
        ),
        (
            dated(10, 5),
            "info:   SSL certificate activation date FAILED",
        ),
    ] {
        let (r, notes, _) = shake(world, &id);
        assert_eq!(r, Ok(Handshake::Done), "{line}");
        assert!(has(&notes, line), "{line}: {notes:#?}");
    }
}

#[test]
fn the_stapled_status_is_asked_for_and_checked_under_verifystatus() {
    let id = identity(|i| i.options.verify_status = true);
    let (r, _, calls) = shake(World::default(), &id);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(at(&calls, "status_request") < at(&calls, "handshake"));
    assert!(calls.contains(&"stapled_status".to_owned()));
    let (_, _, calls) = shake(World::default(), &plain());
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("stapled_status") || c == "status_request")
    );
    for (stapled, line) in [
        (Stapled::None, "No OCSP response received"),
        (Stapled::Invalid, "Invalid OCSP response received"),
        (Stapled::InitFailed, "failed to init OCSP response parsing"),
        (Stapled::Unparsed, "failed to parse OCSP response"),
        (
            Stapled::NotSuccessful,
            "OCSP response basic part is not successful",
        ),
        (
            Stapled::NotForPeer,
            "OCSP does not carry status for peer cert",
        ),
        (
            Stapled::SingleUnparsed,
            "failed to parse OCSP response for peer cert",
        ),
        (
            Stapled::Status(sys::GNUTLS_OCSP_CERT_REVOKED as u32),
            "peer certificate is revoked",
        ),
        (
            Stapled::Status(2),
            "peer certificate OCSP status is not good: 2",
        ),
    ] {
        let world = World {
            stapled,
            ..World::default()
        };
        let (got, notes) = fails(world, &id);
        assert_eq!(got, ErrorKind::SslInvalidcertstatus, "{line}");
        assert!(
            has(&notes, &format!("fail: SslInvalidcertstatus: {line}")),
            "{notes:#?}"
        );
    }
    let world = World {
        answers: vec![("status_request", -3)],
        ..World::default()
    };
    let (got, notes) = fails(world, &id);
    assert_eq!(got, ErrorKind::SslConnectError);
    assert!(has(
        &notes,
        "fail: SslConnectError: gnutls_ocsp_status_request_enable_client() failed: -3"
    ));
}

#[test]
fn the_host_must_match_where_it_is_checked() {
    let world = || World {
        leaf: crate::fake::Leaf {
            host_ok: false,
            ..World::default().leaf
        },
        ..World::default()
    };
    let (got, notes) = fails(world(), &plain());
    assert_eq!(got, ErrorKind::PeerFailedVerification);
    assert!(has(
        &notes,
        "fail: PeerFailedVerification: SSL: certificate subject name (example.com) does not match target hostname 'example.com'"
    ));
    let id = identity(|i| i.verify_host = false);
    let (r, notes, _) = shake(world(), &id);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(has(
        &notes,
        "info:   common name: example.com (does not match 'example.com')"
    ));
    let world = World {
        leaf: crate::fake::Leaf {
            cn: Err(-56),
            ..World::default().leaf
        },
        ..World::default()
    };
    let (_, notes, _) = shake(world, &plain());
    assert!(
        has(&notes, "info: error fetching CN from cert:an error"),
        "{notes:#?}"
    );
}

#[test]
fn a_pinned_key_must_be_the_certificate_s() {
    let pinned = |key: &[u8]| identity(|i| i.options.pinned_key = Some(key.to_vec()));
    // `spki`'s SHA-256, in base64.
    let ok = pinned(b"sha256//b+7MjBbFVR2f6z61934tp3O/aL2e+cUpJ86yyG5WiSs=");
    assert_eq!(shake(World::default(), &ok).0, Ok(Handshake::Done));
    let (got, notes) = fails(
        World::default(),
        &pinned(b"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    );
    assert_eq!(got, ErrorKind::SslPinnedpubkeynotmatch);
    assert!(has(
        &notes,
        "fail: SslPinnedpubkeynotmatch: SSL: public key does not match pinned public key"
    ));
    let world = World {
        leaf: crate::fake::Leaf {
            public_key: None,
            ..World::default().leaf
        },
        ..World::default()
    };
    assert_eq!(fails(world, &ok).0, ErrorKind::SslPinnedpubkeynotmatch);
}

#[test]
// Reads a file through the system's calls, which Miri cannot run.
#[cfg_attr(miri, ignore)]
fn the_issuer_must_have_issued_the_certificate() {
    // A file that is there; the fake reads any as the issuer.
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let id = identity(|i| i.options.issuer_cert = Some(file.as_bytes().to_vec()));
    let (r, notes, calls) = shake(World::default(), &id);
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("import([package]") && c.ends_with(", Pem)"))
    );
    assert!(calls.contains(&"issued_by".to_owned()));
    assert!(has(
        &notes,
        &format!("info:   SSL certificate issuer check OK (Issuer Cert: {file})")
    ));
    let world = World {
        leaf: crate::fake::Leaf {
            issued: false,
            ..World::default().leaf
        },
        ..World::default()
    };
    let (got, notes) = fails(world, &id);
    assert_eq!(got, ErrorKind::SslIssuerError);
    assert!(has(
        &notes,
        &format!(
            "fail: SslIssuerError: server certificate issuer check failed (Issuer Cert: {file})"
        )
    ));
}

#[test]
fn a_verbose_transfer_is_told_of_the_connection_and_the_certificate() {
    let lib = Fake::new(World::default());
    let shared = TlsShared::testing();
    let id = plain();
    let mut s = session(lib, &id, Alpn::Http11, &shared);
    let mut kept = Kept::new();
    kept.verbose = true;
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    for line in [
        "info: SSL connection using TLS1.3 / ECDHE_RSA_AES_128_GCM_SHA256",
        "info:   certificate public key: RSA",
        "info:   certificate version: #3",
        "info:   subject: CN=example.com",
        "info:   start date: Wed, 31 Dec 1969 23:58:20 GMT",
        "info:   expire date: Thu, 01 Jan 1970 00:01:40 GMT",
        "info:   issuer: CN=Test CA",
    ] {
        assert!(has(&kept.notes.0, line), "{line}: {:#?}", kept.notes.0);
    }
    let (_, notes, _) = shake(World::default(), &id);
    assert!(
        !notes
            .iter()
            .any(|n| n.starts_with("info: SSL connection using"))
    );
    assert!(!notes.iter().any(|n| n.starts_with("info:   subject:")));
}

#[test]
fn the_protocol_the_peer_chose_is_taken_and_said() {
    let world = World {
        alpn: b"h2",
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = plain();
    let mut s = session(lib, &id, Alpn::H2Http11, &shared);
    let mut kept = Kept::new();
    let wire = Wire::default();
    assert_eq!(s.chosen(), None);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(s.chosen(), Some(Chosen::H2));
    assert!(has(&kept.notes.0, "info: ALPN: server accepted h2"));
    let world = World {
        alpn: b"h\0",
        ..World::default()
    };
    let (got, notes) = fails(world, &id);
    assert_eq!(got, ErrorKind::SslConnectError);
    assert!(has(
        &notes,
        "fail: SslConnectError: ALPN: server selected protocol contains NUL. Refusing to continue."
    ));
    // No offer is made with ALPN off.
    let lib = Fake::new(World::default());
    let mut s = session(lib, &id, Alpn::None, &shared);
    let mut kept = Kept::new();
    let _ = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert!(lib.w().made("alpn").is_empty());
    assert!(
        !kept
            .notes
            .0
            .iter()
            .any(|n| n.starts_with("info: ALPN: curl offers"))
    );
}

#[test]
fn a_failed_handshake_says_why() {
    let world = World {
        scripts: vec![("handshake", vec![Act::Return(-12)])],
        ..World::default()
    };
    let (got, notes) = fails(world, &plain());
    assert_eq!(got, ErrorKind::SslConnectError);
    assert!(has(
        &notes,
        "fail: SslConnectError: GnuTLS, handshake failed: Handshake failed"
    ));
    assert!(
        has(&notes, "trace: gtls_connect_common() -> 35, done=0"),
        "{notes:#?}"
    );
    let world = World {
        scripts: vec![("handshake", vec![Act::Return(-9)])],
        ..World::default()
    };
    let (_, notes) = fails(world, &plain());
    assert!(has(
        &notes,
        "fail: SslConnectError: GnuTLS, handshake failed: an error"
    ));
    // A warning goes on.
    let world = World {
        scripts: vec![("handshake", vec![Act::Return(-16)])],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Ok(Handshake::Waiting));
    assert!(
        has(&notes, "info: gnutls_handshake() warning: Handshake failed"),
        "{notes:#?}"
    );
    // A connection that failed below fails as it did.
    let world = World {
        scripts: vec![("handshake", vec![Act::Push(b"hello"), Act::Return(-53)])],
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = plain();
    let mut s = session(lib, &id, Alpn::Http11, &shared);
    let mut kept = Kept::new();
    let wire = Wire {
        refuses: true,
        ..Wire::default()
    };
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Err(ErrorKind::SendError), "{:#?}", kept.notes.0);
    assert!(
        has(&kept.notes.0, "trace: gtls_push(len=5) -> 55, 0"),
        "{:#?}",
        kept.notes.0
    );
}

#[test]
fn the_library_s_failures_to_make_the_session_are_said() {
    for (name, line) in [
        (
            "creds",
            "fail: SslConnectError: gnutls_certificate_allocate_credentials() failed: an error",
        ),
        ("session", "fail: SslConnectError: gnutls_init() failed: -9"),
        ("server_name", "fail: SslConnectError: Failed to set SNI"),
        (
            "credentials",
            "fail: SslConnectError: gnutls_credentials_set() failed: an error",
        ),
        ("alpn", "fail: SslConnectError: failed setting ALPN"),
    ] {
        let world = World {
            answers: vec![(name, -9)],
            ..World::default()
        };
        let (got, notes) = fails(world, &plain());
        assert_eq!(got, ErrorKind::SslConnectError, "{name}");
        assert!(has(&notes, line), "{line}: {notes:#?}");
    }
    let world = World {
        answers: vec![("default_priority", -9)],
        ..World::default()
    };
    assert_eq!(fails(world, &plain()).0, ErrorKind::SslConnectError);
}

/// A session of `world`'s library with its handshake done, and its
/// library.
fn connected(world: World) -> (Session<Fake>, &'static Fake, TryArc<TlsIdentity>) {
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = plain();
    let mut s = session(lib, &id, Alpn::Http11, &shared);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    (s, lib, id)
}

#[test]
fn a_send_takes_what_the_library_took_until_it_would_wait() {
    let (mut s, lib, id) = connected(World::default());
    let wire = Wire::default();
    let send = |s: &mut Session<Fake>, scripts: Vec<Vec<Act>>, bytes: &[u8]| {
        lib.w().scripts = scripts.into_iter().map(|a| ("send", a)).collect();
        let mut kept = Kept::new();
        let r = with_io(s, &id, &mut kept, &wire, |s, io| s.send(io, bytes));
        (r.map_err(|e| e.kind()), kept.notes.0)
    };
    let (r, notes) = send(&mut s, vec![], b"0123456789");
    assert!(matches!(r, Ok(Sent::Bytes(n)) if n.get() == 10));
    assert!(
        has(&notes, "trace: gtls_send(len=10) -> 0, 10"),
        "{notes:#?}"
    );
    let (r, notes) = send(
        &mut s,
        vec![vec![Act::Return(3)], vec![Act::Return(-28)]],
        b"0123456789",
    );
    assert!(matches!(r, Ok(Sent::Bytes(n)) if n.get() == 3), "{r:?}");
    assert!(
        has(&notes, "trace: gtls_send(len=10) -> 0, 3"),
        "{notes:#?}"
    );
    assert_eq!(lib.w().made("send(").last(), Some(&"send(7)"));
    let (r, notes) = send(&mut s, vec![vec![Act::Return(-28)]], b"0123456789");
    assert!(matches!(r, Ok(Sent::WouldBlock)));
    assert!(
        has(&notes, "trace: gtls_send(len=10) -> 81, 0"),
        "{notes:#?}"
    );
    let (r, notes) = send(&mut s, vec![vec![Act::Return(20)]], b"0123456789");
    assert!(r.is_err());
    assert!(
        has(
            &notes,
            "fail: SendError: gnutls_record_send(len=10) returned 20"
        ),
        "{notes:#?}"
    );
    let (r, notes) = send(
        &mut s,
        vec![vec![Act::Return(4)], vec![Act::Return(-9)]],
        b"0123456789",
    );
    assert!(r.is_err(), "{r:?}");
    assert!(
        has(&notes, "trace: gtls_send(len=10) -> 55, 4"),
        "{notes:#?}"
    );
}

#[test]
fn a_receive_hands_on_what_the_library_decrypted() {
    let (mut s, lib, id) = connected(World::default());
    let wire = Wire::default();
    let recv = |s: &mut Session<Fake>, acts: Vec<Act>| {
        lib.w().scripts = vec![("recv", acts)];
        let mut kept = Kept::new();
        let mut buf = [0u8; 16];
        let r = with_io(s, &id, &mut kept, &wire, |s, io| s.recv(io, &mut buf));
        (r.map_err(|e| e.kind()), buf, kept.notes.0)
    };
    let (r, buf, notes) = recv(&mut s, vec![Act::Deliver(b"abc")]);
    assert!(matches!(r, Ok(Recv::Data(n)) if n.get() == 3));
    assert_eq!(&buf[..3], b"abc");
    assert!(
        has(&notes, "trace: gtls_recv(len=16) -> 0, 3"),
        "{notes:#?}"
    );
    let (r, _, _) = recv(&mut s, vec![Act::Return(0)]);
    assert!(matches!(r, Ok(Recv::Eof)));
    let (r, _, notes) = recv(&mut s, vec![Act::Return(-28)]);
    assert!(matches!(r, Ok(Recv::WouldBlock)));
    assert!(
        has(&notes, "trace: gtls_recv(len=16) -> 81, -28"),
        "{notes:#?}"
    );
    let (r, _, notes) = recv(&mut s, vec![Act::Return(-9)]);
    assert!(r.is_err());
    assert!(
        has(&notes, "fail: RecvError: GnuTLS recv error (-9): an error"),
        "{notes:#?}"
    );
    assert!(
        has(&notes, "trace: gtls_recv(len=16) -> 56, -9"),
        "{notes:#?}"
    );
    // A renegotiation's handshake is run, and the read waits.
    let (r, _, _) = recv(&mut s, vec![Act::Return(-37)]);
    assert!(matches!(r, Ok(Recv::WouldBlock)), "{r:?}");
    assert_eq!(lib.w().made("handshake").len(), 2);
}

#[test]
fn a_tls_1_2_session_is_kept_as_it_is_checked_and_resumed() {
    let world = World {
        version: sys::GNUTLS_TLS1_2,
        data: b"ticket-12",
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = identity(|i| i.options.session_cache = true);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let mut s = session(lib, &id, Alpn::H2Http11, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    // Kept before ALPN is negotiated, as C keeps it.
    assert!(
        has(
            &kept.notes.0,
            "trace: get session id (len=9, alpn=-, earlymax=0) and store in cache"
        ),
        "{:#?}",
        kept.notes.0
    );
    let mut s = session(lib, &id, Alpn::H2Http11, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().calls.contains(&"set_data(ticket-12)".to_owned()));
    assert!(
        has(&kept.notes.0, "info: SSL reusing session with ALPN '-'"),
        "{:#?}",
        kept.notes.0
    );
    // A session the library will not take is gone without.
    lib.w().answers.push(("set_data", -9));
    let mut s = session(lib, &id, Alpn::H2Http11, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(has(
        &kept.notes.0,
        "info: SSL session not accepted by GnuTLS, continuing without"
    ));
}

#[test]
fn no_session_is_kept_or_resumed_without_the_cache_nor_resumed_under_verifystatus() {
    let world = || World {
        version: sys::GNUTLS_TLS1_2,
        data: b"ticket-12",
        ..World::default()
    };
    let off = identity(|i| i.options.session_cache = false);
    let (_, notes, calls) = shake(world(), &off);
    assert!(!calls.contains(&"data".to_owned()), "{calls:#?}");
    assert!(!notes.iter().any(|n| n.contains("store in cache")));
    // Kept under VERIFYSTATUS, never taken.
    let lib = Fake::new(world());
    let shared = TlsShared::testing();
    let id = identity(|i| {
        i.options.session_cache = true;
        i.options.verify_status = true;
    });
    let mut kept = Kept::new();
    let wire = Wire::default();
    for _ in 0..2 {
        let mut s = session(lib, &id, Alpn::Http11, &shared);
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        assert_eq!(r, Ok(Handshake::Done));
    }
    assert!(lib.w().made("set_data").is_empty());
}

/// A TLS 1.3 session the peer gave after the handshake, `h2` agreed,
/// allowing `early` bytes of early data: kept in `kept`.
fn ticket_13(lib: &'static Fake, id: &TryArc<TlsIdentity>, kept: &mut Kept, shared: &TlsShared) {
    let wire = Wire::default();
    let mut s = session(lib, id, Alpn::H2Http11, shared);
    let r = with_io(&mut s, id, kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    lib.w().scripts.push((
        "recv",
        vec![
            Act::Hook(sys::GNUTLS_HANDSHAKE_NEW_SESSION_TICKET, true),
            Act::Return(-28),
        ],
    ));
    let mut buf = [0u8; 8];
    let r = with_io(&mut s, id, kept, &wire, |s, io| s.recv(io, &mut buf));
    assert!(matches!(r, Ok(Recv::WouldBlock)));
}

#[test]
fn a_tls_1_3_ticket_is_kept_with_its_protocol_and_early_data_sent_in_it() {
    let world = World {
        alpn: b"h2",
        data: b"ticket-13",
        max_early: 1000,
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = identity(|i| i.options.session_cache = true);
    let mut kept = Kept::new();
    ticket_13(lib, &id, &mut kept, &shared);
    assert!(
        has(
            &kept.notes.0,
            "trace: get session id (len=9, alpn=h2, earlymax=1000) and store in cache"
        ),
        "{:#?}",
        kept.notes.0
    );
    assert!(has(
        &kept.notes.0,
        "trace: handshake: incoming message type 4"
    ));
    // Resumed with early data: the handshake is put off for it.
    lib.w().early_accepted = true;
    let mut s = Session::new(
        lib,
        &id,
        &peer(HOST, TlsPeerKind::Name, true),
        Alpn::H2Http11,
        &shared,
        None,
    )
    .unwrap();
    let wire = Wire::default();
    let mut kept2 = kept;
    kept2.notes.0.clear();
    let r = with_io(&mut s, &id, &mut kept2, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    let calls = lib.w().calls.clone();
    assert!(
        calls.contains(&"session(flags=100202)".to_owned()),
        "{calls:#?}"
    );
    assert!(calls.contains(&"alpn(h2)".to_owned()), "{calls:#?}");
    assert_eq!(calls.iter().filter(|c| *c == "handshake").count(), 1);
    let deferred = s.deferred().expect("put off");
    assert_eq!(deferred.alpn, Chosen::H2);
    assert_eq!(deferred.most, 1000);
    assert_eq!(s.chosen(), Some(Chosen::H2));
    for line in [
        "info: SSL reusing session with ALPN 'h2'",
        "info: SSL session allows 1000 bytes of early data, reusing ALPN 'h2'",
        "info: ALPN: deferred handshake for early data using 'h2'.",
    ] {
        assert!(has(&kept2.notes.0, line), "{line}: {:#?}", kept2.notes.0);
    }
    assert!(
        !kept2
            .notes
            .0
            .iter()
            .any(|n| n.starts_with("info: ALPN: curl offers"))
    );
    let r = with_io(&mut s, &id, &mut kept2, &wire, |s, io| {
        s.handshake_early(io, b"GET /")
    });
    assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept2.notes.0);
    assert!(lib.w().calls.contains(&"send_early(5)".to_owned()));
    assert!(has(
        &kept2.notes.0,
        "info: SSL sending 5 bytes of early data"
    ));
    assert!(has(
        &kept2.notes.0,
        "info: ALPN: server confirmed to use 'h2'"
    ));
    assert!(s.early_accepted());
    assert_eq!(s.deferred(), None);
}

#[test]
fn early_data_waits_where_the_library_does_and_goes_on_from_there() {
    let world = World {
        alpn: b"h2",
        data: b"ticket-13",
        max_early: 1000,
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = identity(|i| i.options.session_cache = true);
    let mut kept = Kept::new();
    ticket_13(lib, &id, &mut kept, &shared);
    let mut s = Session::new(
        lib,
        &id,
        &peer(HOST, TlsPeerKind::Name, true),
        Alpn::H2Http11,
        &shared,
        None,
    )
    .unwrap();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    lib.w().scripts = vec![
        ("send_early", vec![Act::Return(2)]),
        ("send_early", vec![Act::Return(-28)]),
    ];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.handshake_early(io, b"GET /")
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    assert!(has(&kept.notes.0, "trace: gtls_send_earlydata(len=5) -> 2"));
    assert!(has(
        &kept.notes.0,
        "trace: gtls_send_earlydata(len=3) -> -28"
    ));
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.handshake_early(io, b"GET /")
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("send_early").last(), Some(&"send_early(3)"));
    assert!(!s.early_accepted());
    // A server choosing another protocol is refused.
    let mut s = Session::new(
        lib,
        &id,
        &peer(HOST, TlsPeerKind::Name, true),
        Alpn::H2Http11,
        &shared,
        None,
    )
    .unwrap();
    ticket_13(lib, &id, &mut kept, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    lib.w().alpn = b"http/1.1";
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.handshake_early(io, b"GET /")
    });
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(has(
        &kept.notes.0,
        "fail: SslConnectError: ALPN: asked for 'h2' from previous session, but server selected 'http/1.1'. Refusing to continue."
    ));
}

#[test]
fn a_session_that_allows_no_early_data_resumes_without_it() {
    for (most, flags) in [
        (0, "session(flags=202)"),
        (0xFFFF_FFFF, "session(flags=202)"),
    ] {
        let world = World {
            alpn: b"h2",
            data: b"ticket-13",
            max_early: most,
            ..World::default()
        };
        let lib = Fake::new(world);
        let shared = TlsShared::testing();
        let id = identity(|i| i.options.session_cache = true);
        let mut kept = Kept::new();
        ticket_13(lib, &id, &mut kept, &shared);
        lib.w().calls.clear();
        let mut s = Session::new(
            lib,
            &id,
            &peer(HOST, TlsPeerKind::Name, true),
            Alpn::H2Http11,
            &shared,
            None,
        )
        .unwrap();
        let wire = Wire::default();
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        assert_eq!(r, Ok(Handshake::Done));
        assert!(lib.w().calls.contains(&flags.to_owned()), "{most}");
        assert_eq!(s.deferred(), None);
        assert!(
            has(&kept.notes.0, "trace: SSL session does not allow earlydata"),
            "{most}"
        );
    }
}

#[test]
fn a_session_of_a_protocol_not_offered_is_not_resumed() {
    let world = World {
        alpn: b"h2",
        data: b"ticket-13",
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = identity(|i| i.options.session_cache = true);
    let mut kept = Kept::new();
    ticket_13(lib, &id, &mut kept, &shared);
    let mut s = session(lib, &id, Alpn::Http11, &shared);
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().made("set_data").is_empty());
}

#[test]
fn a_ticket_is_not_kept_where_sessions_are_not() {
    let world = World {
        data: b"ticket-13",
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = identity(|i| i.options.session_cache = false);
    let mut kept = Kept::new();
    ticket_13(lib, &id, &mut kept, &shared);
    assert!(has(
        &kept.notes.0,
        "trace: handshake: incoming message type 4"
    ));
    assert!(
        !kept.notes.0.iter().any(|n| n.contains("store in cache")),
        "{:#?}",
        kept.notes.0
    );
}

#[test]
fn the_goodbye_is_sent_then_the_peer_s_read_for() {
    let (mut s, lib, id) = connected(World::default());
    let wire = Wire::default();
    let mut kept = Kept::new();
    lib.w().scripts = vec![("bye", vec![Act::Return(-28)])];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    assert!(has(&kept.notes.0, "trace: SSL shutdown, gnutls_bye EAGAIN"));
    lib.w().scripts = vec![("recv", vec![Act::Return(-28)])];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(lib.w().made("bye").len(), 2);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("bye").len(), 2);
    // Over, it is not done again.
    let calls = lib.w().calls.len();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().calls.len(), calls);
    // Only the peer's read for: none sent.
    let (mut s, lib, id) = connected(World::default());
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Heard)
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().made("bye").is_empty());
    let (mut s, lib, id) = connected(World::default());
    lib.w().scripts = vec![("bye", vec![Act::Return(-9)])];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Err(ErrorKind::RecvError));
    assert!(has(
        &kept.notes.0,
        "trace: SSL shutdown, gnutls_bye error: 'an error'(-9)"
    ));
}

#[test]
// Writes a file, which Miri's isolation refuses.
#[cfg_attr(miri, ignore)]
fn secrets_are_logged_while_the_key_log_is_open() {
    let dir = std::env::temp_dir().join(format!("curl-gnutls-keylog-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("keys");
    let log = SharedKeyLog::new().unwrap();
    log.open_named(file.to_str().unwrap().as_bytes());
    assert!(log.enabled());
    let world = World {
        scripts: vec![(
            "handshake",
            vec![
                Act::Secret(b"CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
                Act::Return(0),
            ],
        )],
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = plain();
    let mut s = Session::new(
        lib,
        &id,
        &peer(HOST, TlsPeerKind::Name, false),
        Alpn::Http11,
        &shared,
        Some(log.clone()),
    )
    .unwrap();
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().calls.contains(&"log_keys".to_owned()));
    let written = std::fs::read_to_string(&file).unwrap();
    assert!(
        written.starts_with("CLIENT_HANDSHAKE_TRAFFIC_SECRET 0707"),
        "{written}"
    );
    let line = format!(
        "info: SSLKEYLOGFILE set, all TLS secrets are logged to '{}'",
        file.display()
    );
    assert!(has(&kept.notes.0, &line), "{:#?}", kept.notes.0);
    // Closed, the library is not asked for them.
    log.close();
    let (r, _, calls) = {
        let lib = Fake::new(World::default());
        let mut s = Session::new(
            lib,
            &id,
            &peer(HOST, TlsPeerKind::Name, false),
            Alpn::Http11,
            &shared,
            Some(log.clone()),
        )
        .unwrap();
        let mut kept = Kept::new();
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        (r, (), lib.w().calls.clone())
    };
    assert_eq!(r, Ok(Handshake::Done));
    assert!(!calls.contains(&"log_keys".to_owned()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
// Calls into C, which Miri cannot run.
#[cfg_attr(miri, ignore)]
fn the_library_is_named_and_initialised_as_c_names_and_initialises_it() {
    use curl_core::tls::TlsBackend as _;
    let named = crate::version().to_string();
    assert!(named.starts_with("GnuTLS/3."), "{named}");
    assert_eq!(crate::GNUTLS.id().to_string(), named);
    assert!(crate::init());
    crate::cleanup();
}

#[test]
fn a_session_s_version_is_kept_as_the_wire_numbers_it() {
    use crate::library::ietf_version;
    assert_eq!(ietf_version(sys::GNUTLS_SSL3), 0x300);
    assert_eq!(ietf_version(sys::GNUTLS_TLS1_0), 0x301);
    assert_eq!(ietf_version(sys::GNUTLS_TLS1_1), 0x302);
    assert_eq!(ietf_version(sys::GNUTLS_TLS1_2), 0x303);
    assert_eq!(ietf_version(sys::GNUTLS_TLS1_3), 0x304);
    assert_eq!(ietf_version(99), 0);
}

#[test]
fn early_data_is_held_to_c_s_most() {
    let world = World {
        alpn: b"h2",
        data: b"ticket-13",
        max_early: 100_000,
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = identity(|i| i.options.session_cache = true);
    let mut kept = Kept::new();
    ticket_13(lib, &id, &mut kept, &shared);
    let mut s = Session::new(
        lib,
        &id,
        &peer(HOST, TlsPeerKind::Name, true),
        Alpn::H2Http11,
        &shared,
        None,
    )
    .unwrap();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(s.deferred().unwrap().most, 64 * 1024);
    assert!(has(
        &kept.notes.0,
        "info: SSL session allows 100000 bytes of early data, reusing ALPN 'h2'"
    ));
    // GnuTLS answers 0 for all it took.
    lib.w().scripts = vec![("send_early", vec![Act::Return(0)])];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.handshake_early(io, b"GET /")
    });
    assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept.notes.0);
    assert_eq!(lib.w().made("send_early").len(), 1);
    assert!(has(
        &kept.notes.0,
        "info: SSL sending 5 bytes of early data"
    ));
}

#[test]
fn a_certificate_of_another_type_is_read_as_pem() {
    let id = identity(|i| {
        i.options.cert = Some(b"/client.pem".to_vec());
        i.options.cert_type = Some(b"PEM".to_vec());
    });
    let (_, _, calls) = shake(World::default(), &id);
    assert!(
        calls.contains(&"key_file(/client.pem, /client.pem, Pem, None)".to_owned()),
        "{calls:#?}"
    );
}

#[test]
fn a_handshake_done_is_done_whatever_its_writes_came_to() {
    let world = World {
        scripts: vec![("handshake", vec![Act::TryPush(b"x"), Act::Return(0)])],
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = plain();
    let mut s = session(lib, &id, Alpn::Http11, &shared);
    let mut kept = Kept::new();
    let wire = Wire {
        refuses: true,
        ..Wire::default()
    };
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept.notes.0);
}

#[test]
fn a_goodbye_waits_for_what_the_library_waits_for_and_reads_what_comes() {
    let (mut s, lib, id) = connected(World::default());
    let wire = Wire::default();
    let mut kept = Kept::new();
    lib.w().scripts = vec![("bye", vec![Act::WantsWrite(true), Act::Return(-28)])];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(s.waits(), TlsWait::Send);
    lib.w().wants_write = false;
    lib.w().scripts = vec![("recv", vec![Act::Return(-28)])];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(s.waits(), TlsWait::Recv);
    // Data still coming after ten reads: it waits for more.
    lib.w().scripts = (0..10)
        .map(|_| ("recv", vec![Act::Deliver(b"x")]))
        .collect();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    assert!(lib.w().scripts.is_empty());
    lib.w().scripts = vec![("recv", vec![Act::Return(-9)])];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Err(ErrorKind::RecvError));
    assert!(
        has(&kept.notes.0, "trace: SSL shutdown, error: 'an error'(-9)"),
        "{:#?}",
        kept.notes.0
    );
}

#[test]
fn the_session_hands_out_what_the_library_has() {
    let (s, lib, _) = connected(World::default());
    assert!(!s.pending());
    lib.w().pending = true;
    assert!(s.pending());
    assert!(s.native().is_some());
    // C's GnuTLS build makes no channel binding.
    struct NoNotes;
    impl curl_core::tls::BindingNotes for NoNotes {
        fn info(&mut self, _: std::fmt::Arguments<'_>) {}
        fn fail(&mut self, kind: ErrorKind, _: std::fmt::Arguments<'_>) -> ErrorKind {
            kind
        }
    }
    assert_eq!(s.channel_binding(&mut NoNotes), Ok(None));
}

#[test]
fn each_trust_source_says_what_it_gave() {
    let shake_with = |answers: Vec<(&'static str, i32)>, change: fn(&mut TlsIdentity)| {
        let world = World {
            answers,
            ..World::default()
        };
        let (r, notes, _) = shake(world, &identity(change));
        assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
        notes
    };
    let native =
        |i: &mut TlsIdentity| i.options.ssl_options = curl_core::options::SslOptions::NATIVE_CA;
    let notes = shake_with(vec![("system_trust", 0)], native);
    assert!(
        has(&notes, "info:   Native: 0 certificates from system trust"),
        "{notes:#?}"
    );
    assert!(has(&notes, "info:   no trust anchors configured"));
    let blob = |i: &mut TlsIdentity| i.options.ca_blob = CaSetting::Given(b"PEM".to_vec());
    let notes = shake_with(vec![("trust_mem", 2)], blob);
    assert!(has(&notes, "info:   CA Blob: 2 certificates"), "{notes:#?}");
    assert!(!has(&notes, "info:   no trust anchors configured"));
    let notes = shake_with(vec![("trust_mem", 0)], blob);
    assert!(has(&notes, "info:   CA Blob: 0 certificates"), "{notes:#?}");
    assert!(has(&notes, "info:   no trust anchors configured"));
    let dir = |i: &mut TlsIdentity| i.options.ca_path = CaSetting::Given(b"/certs".to_vec());
    let notes = shake_with(vec![("trust_dir", 3)], dir);
    assert!(
        has(&notes, "info:   CApath: 3 certificates in /certs"),
        "{notes:#?}"
    );
    assert!(!has(&notes, "info:   no trust anchors configured"));
    let notes = shake_with(vec![("trust_dir", 0)], dir);
    assert!(
        has(&notes, "info:   CApath: 0 certificates in /certs"),
        "{notes:#?}"
    );
    assert!(has(&notes, "info:   no trust anchors configured"));
}

#[test]
fn a_peer_without_a_certificate_fails_whichever_check_wants_one() {
    let world = || World {
        chain: None,
        ..World::default()
    };
    for (peer, host, issuer) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let id = identity(|i| {
            i.verify_peer = peer;
            i.verify_host = host;
            if issuer {
                i.options.issuer_cert = Some(b"/issuer.pem".to_vec());
            }
        });
        let (got, notes) = fails(world(), &id);
        assert_eq!(
            got,
            ErrorKind::PeerFailedVerification,
            "{peer} {host} {issuer}"
        );
        assert!(has(
            &notes,
            "fail: PeerFailedVerification: failed to get server cert"
        ));
    }
}

#[test]
// Makes a file, which Miri's isolation refuses.
#[cfg_attr(miri, ignore)]
fn an_issuer_file_larger_than_c_reads_is_read_as_nothing() {
    let dir = std::env::temp_dir().join(format!("curl-gnutls-issuer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("issuer.pem");
    let name = file.to_str().unwrap().as_bytes().to_vec();
    let issued = |len: u64| {
        std::fs::File::create(&file).unwrap().set_len(len).unwrap();
        let id = identity(|i| i.options.issuer_cert = Some(name.clone()));
        let (_, _, calls) = shake(World::default(), &id);
        calls.contains(&"import(, Pem)".to_owned())
    };
    assert!(issued(8_000_001), "read as nothing");
    // At C's most, it is read.
    assert!(!issued(8_000_000));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_system_store_is_the_default_only_in_the_native_ca_build() {
    use curl_core::tls::TlsBackend as _;
    let defaults = crate::GNUTLS.ca_defaults();
    let id = identity(|i| i.ca_defaults = defaults);
    let (r, notes, calls) = shake(World::default(), &id);
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    let native = cfg!(feature = "native-ca");
    assert_eq!(
        calls.contains(&"system_trust".to_owned()),
        native,
        "{calls:#?}"
    );
    if native {
        // No bundle looked for, as CMake looks for none.
        assert_eq!((defaults.file, defaults.path), (None, None));
    }
}

/// A QUIC session of `lib` for `id` to `HOST`, the transfer sending early
/// data if `early`, its objects handed to `setup`, the sessions kept in
/// `kept`.
fn quic(
    lib: &'static Fake,
    id: &TryArc<TlsIdentity>,
    kept: &mut Kept,
    early: bool,
    setup: QuicContextSetup<'_>,
) -> Result<QuicSession<Fake>, ErrorKind> {
    TlsCx::testing_kept(id, HOST, kept, |shared, cx| {
        QuicSession::new(
            lib,
            id,
            &peer(HOST, TlsPeerKind::Name, early),
            shared,
            None,
            setup,
            cx,
        )
    })
}

/// Drive `s` through one call of the QUIC library, which runs `op`, its
/// transport parameters `params`.
fn drive(
    s: &mut QuicSession<Fake>,
    id: &TryArc<TlsIdentity>,
    kept: &mut Kept,
    params: Option<&'static [u8]>,
    op: &mut dyn FnMut(&mut dyn DriveCall),
) {
    TlsCx::testing_kept(id, HOST, kept, |_, cx| {
        let mut params = || params.map(<[u8]>::to_vec);
        s.drive(cx, &mut params, op);
    });
}

#[test]
fn a_quic_session_is_made_as_vquic_tls_c_makes_it() {
    let lib = Fake::new(World::default());
    let id = identity(|i| i.options.session_cache = false);
    let mut kept = Kept::new();
    let seen = std::cell::Cell::new(None);
    let setup = |native: TlsNative| {
        // The session itself, as soon as it is made, before its hook and
        // its ALPN offer.
        seen.set(Some((native.session(), lib.w().calls.len())));
        Ok(())
    };
    let s = quic(lib, &id, &mut kept, false, &setup).expect("made");
    let calls = lib.w().calls.clone();
    assert_eq!(
        &calls[..5],
        [
            "creds",
            "session(flags=202)",
            "server_name(example.com)",
            "default_priority",
            "priority(NORMAL:%PROFILE_MEDIUM:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:\
             +AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:\
             +GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE)",
        ],
        "{calls:#?}"
    );
    let (session, at_setup) = seen.get().expect("set up");
    assert_eq!(session, Some(s.native().context()));
    assert_eq!(at_setup, at(&calls, "credentials") + 1, "{calls:#?}");
    // No sessions kept, no hook; push and pull, never called.
    assert!(at_setup <= at(&calls, "quic_hook(tickets=false)"));
    let alpn = calls.iter().position(|c| c.starts_with("alpn(h3")).unwrap();
    assert!(at(&calls, "quic_hook(tickets=false)") < alpn, "{calls:#?}");
    // The trust is not loaded until the peer's first bytes are due.
    assert!(lib.w().made("trust_").is_empty());
    assert!(s.early_data().is_none());
}

#[test]
fn a_quic_session_s_versions_must_reach_tls_1_3_whatever_the_least() {
    let lib = Fake::new(World::default());
    let mut kept = Kept::new();
    let capped = identity(|i| i.options.max_version = TlsMaxVersion::Tls1_2);
    let r = quic(lib, &capped, &mut kept, false, &|_| Ok(()));
    assert_eq!(r.err(), Some(ErrorKind::SslConnectError));
    assert!(
        has(
            &kept.notes.0,
            "fail: SslConnectError: QUIC needs at least TLS version 1.3"
        ),
        "{:#?}",
        kept.notes.0
    );
    // A least version above the most a stream session allows is QUIC's
    // own priorities all the same.
    let odd = identity(|i| {
        i.options.min_version = TlsMinVersion::Tls1_3;
        i.options.max_version = TlsMaxVersion::Tls1_3;
    });
    assert!(quic(lib, &odd, &mut kept, false, &|_| Ok(())).is_ok());
}

#[test]
fn the_quic_library_s_failed_setup_fails_the_session_as_c_says_it() {
    let lib = Fake::new(World::default());
    let mut kept = Kept::new();
    let r = quic(lib, &plain(), &mut kept, false, &|_| Err("setup failed"));
    assert_eq!(r.err(), Some(ErrorKind::FailedInit));
    assert!(has(&kept.notes.0, "fail: FailedInit: setup failed"));
    assert!(lib.w().made("alpn").is_empty());
}

/// Each handshake message is named as C's QUIC trace names it
/// (`gtls_hs_msg_name`), any other `Unknown`.
#[test]
fn a_handshake_message_is_named_as_c_names_it() {
    for (kind, name) in [
        (1, "ClientHello"),
        (2, "ServerHello"),
        (4, "SessionTicket"),
        (8, "EncryptedExtensions"),
        (11, "Certificate"),
        (13, "CertificateRequest"),
        (15, "CertificateVerify"),
        (20, "Finished"),
        (24, "KeyUpdate"),
        (254, "MessageHash"),
        (3, "Unknown"),
        (255, "Unknown"),
    ] {
        assert_eq!(crate::library::message_name(kind), name, "{kind}");
    }
}

#[test]
fn a_quic_ticket_is_kept_for_h3_with_its_transport_parameters_and_resumed() {
    let world = World {
        data: b"ticket-q",
        max_early: 0xFFFF_FFFF,
        scripts: vec![(
            "drive",
            vec![
                Act::Hook(2, true),
                Act::Hook(sys::GNUTLS_HANDSHAKE_NEW_SESSION_TICKET, true),
                // A second, for the second session resumed below.
                Act::Hook(sys::GNUTLS_HANDSHAKE_NEW_SESSION_TICKET, true),
            ],
        )],
        ..World::default()
    };
    let lib = Fake::new(world);
    let id = identity(|i| i.options.session_cache = true);
    let mut kept = Kept::new();
    let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    assert!(
        lib.w()
            .calls
            .contains(&"quic_hook(tickets=true)".to_owned())
    );
    drive(&mut s, &id, &mut kept, Some(b"tp"), &mut |_| {});
    for line in [
        "trace: SSL message: <- ServerHello [2]",
        "trace: SSL message: <- SessionTicket [4]",
        "trace: get session id (len=8, alpn=h3, earlymax=4294967295) and store in cache",
    ] {
        assert!(has(&kept.notes.0, line), "{line}: {:#?}", kept.notes.0);
    }
    // Resumed, the library's word on early data is what the QUIC library
    // is told, with the parameters kept: over QUIC, early data is ended
    // by QUIC itself.
    lib.w().max_early = 1000;
    let before = lib.w().calls.len();
    let mut s = quic(lib, &id, &mut kept, true, &|_| Ok(())).unwrap();
    let calls = lib.w().calls.clone();
    // The offer waits for the QUIC library's word on early data.
    assert!(
        !calls[before..].iter().any(|c| c.starts_with("alpn(")),
        "{calls:#?}"
    );
    assert!(
        calls.contains(&"session(flags=500202)".to_owned()),
        "{calls:#?}"
    );
    assert!(calls.contains(&"set_data(ticket-q)".to_owned()));
    assert!(has(
        &kept.notes.0,
        "info: SSL reusing session with ALPN 'h3'"
    ));
    let early = s.early_data().expect("early data may go");
    assert_eq!(early.earlydata_max, 1000);
    assert_eq!(early.chosen(), Some(Chosen::H3));
    assert_eq!(early.quic_params, b"tp");
    // Told early data goes, the offer is the ticket's protocol alone, as
    // C restricts it after `sess_reuse_cb`; told none goes, as where the
    // QUIC library refuses the parameters, it is whole. Made once.
    for (early, offer) in [(true, "alpn(h3)"), (false, "alpn(h3,h3-29)")] {
        if !early {
            s = quic(lib, &id, &mut kept, true, &|_| Ok(())).unwrap();
        }
        let before = lib.w().calls.len();
        TlsCx::testing_kept(&id, HOST, &mut kept, |_, cx| {
            s.early_data_decided(cx, early)
        })
        .unwrap();
        assert_eq!(lib.w().calls[before..], [offer], "{early}");
    }
    // A ticket for the session below, from the last one's handshake.
    lib.w().scripts = vec![(
        "drive",
        vec![Act::Hook(sys::GNUTLS_HANDSHAKE_NEW_SESSION_TICKET, true)],
    )];
    drive(&mut s, &id, &mut kept, Some(b"tp"), &mut |_| {});
    // Where the transfer sends none, the QUIC library is told of none,
    // the session resumed all the same.
    let before = lib.w().calls.len();
    let s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    assert!(lib.w().calls[before..].contains(&"set_data(ticket-q)".to_owned()));
    assert!(s.early_data().is_none());
}

#[test]
fn without_kept_sessions_a_quic_session_resumes_nothing_and_keeps_nothing() {
    let world = World {
        data: b"ticket-q",
        ..World::default()
    };
    let lib = Fake::new(world);
    let id = identity(|i| i.options.session_cache = false);
    let mut kept = Kept::new();
    let _ = quic(lib, &id, &mut kept, true, &|_| Ok(())).unwrap();
    assert!(
        lib.w()
            .calls
            .contains(&"quic_hook(tickets=false)".to_owned())
    );
    assert!(lib.w().made("set_data").is_empty());
}

#[test]
fn the_peer_is_reported_and_checked_as_the_quic_library_says_the_handshake_is_done() {
    let lib = Fake::new(World::default());
    let id = identity(|i| i.options.session_cache = true);
    let mut kept = Kept::new();
    kept.verbose = true;
    let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    let before = lib.w().calls.len();
    let mut done = None;
    drive(&mut s, &id, &mut kept, None, &mut |dc| {
        dc.with_cx(&mut |cx| cx.trace(format_args!("the QUIC library's call")));
        done = Some(dc.handshake_done());
    });
    assert_eq!(done, Some(Ok(())));
    let calls = lib.w().calls[before..].to_vec();
    assert_eq!(calls[0], "drive");
    assert!(calls.contains(&"verify_peers".to_owned()), "{calls:#?}");
    let notes = &kept.notes.0;
    let said = |line: &str| notes.iter().position(|n| n == line);
    let traced = said("trace: the QUIC library's call").expect("the transfer reached");
    let using = notes
        .iter()
        .position(|n| n.starts_with("info: SSL connection using "))
        .expect("reported");
    // Reported, then checked.
    let checked = notes
        .iter()
        .position(|n| n.contains("SSL certificate verified by GnuTLS"))
        .expect("checked");
    assert!(traced < using && using < checked, "{notes:#?}");
    // A peer that fails its check fails the call's callback, and its
    // sessions are forgotten.
    lib.w().leaf.host_ok = false;
    let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    let mut done = None;
    drive(&mut s, &id, &mut kept, None, &mut |dc| {
        done = Some(dc.handshake_done());
    });
    assert_eq!(done, Some(Err(ErrorKind::PeerFailedVerification)));
    // The cache is looked into, after the failure, for the peer's
    // sessions to remove.
    let notes = &kept.notes.0;
    let failed = notes
        .iter()
        .rposition(|n| n.starts_with("fail: PeerFailedVerification"))
        .expect("failed");
    assert!(
        notes[failed..]
            .iter()
            .any(|n| n.starts_with("trace: find peer slot")),
        "{notes:#?}"
    );
}

#[test]
fn a_quic_session_s_trust_is_set_up_once_before_the_peer_s_first_bytes() {
    let world = World {
        answers: vec![("trust_file", 3)],
        ..World::default()
    };
    let lib = Fake::new(world);
    let id = identity(|i| i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec()));
    let mut kept = Kept::new();
    let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    for _ in 0..2 {
        TlsCx::testing_kept(&id, HOST, &mut kept, |_, cx| s.before_recv(cx)).unwrap();
    }
    assert_eq!(lib.w().made("trust_file"), ["trust_file(/ca.pem)"]);
}

#[test]
#[should_panic(expected = "a QUIC session's records are the QUIC library's")]
fn a_quic_session_never_writes_through_the_transport() {
    let world = World {
        scripts: vec![("drive", vec![Act::Push(b"hello")])],
        ..World::default()
    };
    let lib = Fake::new(world);
    let id = plain();
    let mut kept = Kept::new();
    let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    drive(&mut s, &id, &mut kept, None, &mut |_| {});
}
