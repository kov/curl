//! The session over the scripted library (`fake.rs`): the calls made of
//! wolfSSL in `wolfssl.c`'s order, and what is made of each answer, said
//! in C's words.

use std::time::Duration;

use curl_alloc::TryArc;
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::options::{
    CaCache, CaSetting, ColdGroup as _, SslOptions, TlsMaxVersion, TlsMinVersion, TlsOptions,
};
use curl_core::tls::{
    Alpn, CaDefaults, Goodbye, Handshake, Kept, SharedKeyLog, TlsIdentity, TlsIo, TlsPeer,
    TlsPeerKind, TlsSession as _, TlsShared, TlsTicket, TlsWait,
};

use crate::fake::{Act, Fake, SOCKET_ERROR_E, Wire, World};
use crate::library::{
    AlpnGot, Call, IoResult, IoState, Moved, NewSession, NoCtx, PeerCert, Reach, Resume, Tls12Keys,
    Words,
};
use crate::session::Session;
use crate::sys;

mod ech;
mod more;
mod quic;
mod real;

const HOST: &[u8] = b"example.com";

fn identity(change: impl FnOnce(&mut TlsIdentity)) -> TryArc<TlsIdentity> {
    let mut id = TlsIdentity::for_tests(
        true,
        true,
        TlsOptions::NONE,
        CaDefaults::NONE,
        curl_core::tls::TlsOrigin::First,
    );
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
        ech_configs: None,
    }
}

/// A session of `lib` for `id` to `peer`, offering `alpn`.
fn session_to(
    lib: &'static Fake,
    id: &TryArc<TlsIdentity>,
    peer: &TlsPeer<'_>,
    alpn: Alpn,
    shared: &TlsShared,
    keylog: Option<SharedKeyLog>,
) -> Session<Fake> {
    let method = TryArc::try_new(()).unwrap();
    Session::new(lib, method, id, peer, alpn, shared, keylog).unwrap()
}

/// A session of `lib` for `id` to `HOST`, offering `alpn`.
fn session(
    lib: &'static Fake,
    id: &TryArc<TlsIdentity>,
    alpn: Alpn,
    shared: &TlsShared,
) -> Session<Fake> {
    let to = peer(HOST, TlsPeerKind::Name, false);
    session_to(lib, id, &to, alpn, shared, None)
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

/// The notes that start with `prefix`.
fn said<'n>(notes: &'n [String], prefix: &str) -> Vec<&'n str> {
    notes
        .iter()
        .map(String::as_str)
        .filter(|n| n.starts_with(prefix))
        .collect()
}

/// Where `line` is among `lines`, which must have it.
fn at(lines: &[String], line: &str) -> usize {
    lines
        .iter()
        .position(|c| c == line)
        .unwrap_or_else(|| panic!("{line}: {lines:#?}"))
}

#[test]
fn a_handshake_sets_the_library_up_as_wolfssl_c_does() {
    let (r, notes, calls) = shake(World::default(), &plain());
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    let want = [
        "ctx",
        "min_version(0x303)",
        "verify(true)",
        "sni(example.com)",
        "tell_sessions",
        "ssl",
        "alpn(h2,http/1.1)",
        "check_domain(example.com)",
        "bio",
        "connect",
        // The ClientHello went without a read: the store after it, one of
        // the context's own made for the multi.
        "new_store -> 2",
        "set_store(2)",
        "store -> 2",
    ];
    assert_eq!(calls, want);
    assert_eq!(
        said(&notes, "info: "),
        [
            "info: ALPN: curl offers h2,http/1.1",
            "info: ALPN: server did not agree on a protocol. Uses default.",
            "info: SSL connection using TLSv1.3 / TLS13-AES128-GCM-SHA256",
        ],
        "{notes:#?}"
    );
    for line in [
        "trace: set SNI 'example.com'",
        "trace: set ALPN: h2,http/1.1",
        "trace: wssl_populate_x509_store, path=none, blob=0",
        "trace: wolfSSL_connect() -> 1, detail=0",
    ] {
        assert!(has(&notes, line), "{line}: {notes:#?}");
    }
}

#[test]
fn a_context_or_handle_not_made_fails_as_out_of_memory() {
    for (no, line) in [
        (
            NoCtx::Method,
            "fail: OutOfMemory: wolfSSL: could not create a client method",
        ),
        (
            NoCtx::Context,
            "fail: OutOfMemory: wolfSSL: could not create a context",
        ),
    ] {
        let world = World {
            no_ctx: Some(no),
            ..World::default()
        };
        let (r, notes, _) = shake(world, &plain());
        assert_eq!(r, Err(ErrorKind::OutOfMemory));
        assert!(has(&notes, line), "{notes:#?}");
    }
    let world = World {
        no_ssl: true,
        ..World::default()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::OutOfMemory));
    assert!(has(
        &notes,
        "fail: OutOfMemory: SSL: could not create a handle"
    ));
}

#[test]
fn the_versions_are_c_s() {
    let versions = |min: TlsMinVersion, max: TlsMaxVersion| {
        let id = identity(|id| {
            id.options.min_version = min;
            id.options.max_version = max;
        });
        let (r, _, calls) = shake(World::default(), &id);
        assert_eq!(r, Ok(Handshake::Done));
        calls
            .into_iter()
            .filter(|c| c.contains("_version("))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        versions(TlsMinVersion::Tls1, TlsMaxVersion::None),
        ["min_version(0x301)"]
    );
    assert_eq!(
        versions(TlsMinVersion::Tls1_0, TlsMaxVersion::Default),
        ["min_version(0x301)"]
    );
    assert_eq!(
        versions(TlsMinVersion::Tls1_1, TlsMaxVersion::Tls1_1),
        ["min_version(0x302)", "max_version(0x302)"]
    );
    assert_eq!(
        versions(TlsMinVersion::Tls1_2, TlsMaxVersion::Tls1_2),
        ["min_version(0x303)", "max_version(0x303)"]
    );
    assert_eq!(
        versions(TlsMinVersion::Tls1_3, TlsMaxVersion::Tls1_3),
        ["min_version(0x304)", "max_version(0x304)"]
    );
    assert_eq!(
        versions(TlsMinVersion::Tls1, TlsMaxVersion::Tls1_0),
        ["min_version(0x301)", "max_version(0x301)"]
    );
    for (refused, line) in [
        (
            "min_version",
            "fail: SslConnectError: wolfSSL: failed set the minimum TLS version",
        ),
        (
            "max_version",
            "fail: SslConnectError: wolfSSL: failed set the maximum TLS version",
        ),
    ] {
        let id = identity(|id| id.options.max_version = TlsMaxVersion::Tls1_3);
        let world = World {
            refuse: vec![refused],
            ..World::default()
        };
        let (r, notes, _) = shake(world, &id);
        assert_eq!(r, Err(ErrorKind::SslConnectError));
        assert!(has(&notes, line), "{notes:#?}");
    }
}

#[test]
fn the_cipher_list_is_built_as_c_builds_it() {
    let list = |change: &dyn Fn(&mut TlsOptions)| {
        let id = identity(|id| change(&mut id.options));
        let (r, notes, calls) = shake(World::default(), &id);
        let set: Vec<_> = calls
            .into_iter()
            .filter(|c| c.starts_with("cipher_list"))
            .collect();
        (r, set, notes)
    };
    // Neither named: the library's own, untouched.
    let (_, set, _) = list(&|_| {});
    assert!(set.is_empty());
    // Only the older suites named: TLS 1.3's are the library's.
    let (r, set, notes) = list(&|o| o.ciphers = Some(b"AES128-SHA".to_vec()));
    assert_eq!(r, Ok(Handshake::Done));
    let want = "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384:AES128-SHA";
    assert_eq!(set, [format!("cipher_list({want})")]);
    assert!(has(&notes, &format!("info: Cipher selection: {want}")));
    // Only TLS 1.3's named: the older ones are the library's.
    let (_, set, _) = list(&|o| o.tls13_ciphers = Some(b"TLS13-CHACHA20-POLY1305-SHA256".to_vec()));
    assert_eq!(
        set,
        [
            "cipher_list(TLS13-CHACHA20-POLY1305-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384)"
        ]
    );
    // TLS 1.3 alone: its suites alone.
    let (_, set, _) = list(&|o| {
        o.min_version = TlsMinVersion::Tls1_3;
        o.ciphers = Some(b"AES128-SHA".to_vec());
    });
    assert_eq!(
        set,
        ["cipher_list(TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384)"]
    );
    // At most 1.2: the older ones alone.
    let (_, set, _) = list(&|o| {
        o.max_version = TlsMaxVersion::Tls1_2;
        o.tls13_ciphers = Some(b"TLS13-AES128-GCM-SHA256".to_vec());
        o.ciphers = Some(b"AES128-SHA".to_vec());
    });
    assert_eq!(set, ["cipher_list(AES128-SHA)"]);
    // 1.3 alone with only the older ones named, which it never offers,
    // but its default: C hands the list it built.
    let (_, set, _) = list(&|o| {
        o.min_version = TlsMinVersion::Tls1_3;
        o.max_version = TlsMaxVersion::Tls1_2;
        o.ciphers = Some(b"AES128-SHA".to_vec());
    });
    assert_eq!(set, ["cipher_list(null)"]);
    // Refused, in C's words.
    let id = identity(|id| id.options.ciphers = Some(b"BOGUS".to_vec()));
    let world = World {
        refuse: vec!["cipher_list"],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::SslCipher));
    assert!(
        has(
            &notes,
            "fail: SslCipher: failed setting cipher list: \
             TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384:BOGUS"
        ),
        "{notes:#?}"
    );
    // Past C's buffer, the connection fails.
    let id = identity(|id| id.options.ciphers = Some(vec![b'A'; 4096]));
    let (r, _, calls) = shake(World::default(), &id);
    assert_eq!(r, Err(ErrorKind::TooLarge));
    assert!(!calls.iter().any(|c| c.starts_with("cipher_list")));
}

#[test]
fn the_curves_are_the_library_s_groups() {
    let id = identity(|id| id.options.curves = Some(b"X25519:P-256".to_vec()));
    let (r, _, calls) = shake(World::default(), &id);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(calls.iter().any(|c| c == "groups(X25519:P-256)"));
    let world = World {
        refuse: vec!["groups"],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::SslCipher));
    assert!(has(
        &notes,
        "fail: SslCipher: failed setting curves list: 'X25519:P-256'"
    ));
}

#[test]
fn the_client_s_certificate_and_key_are_loaded_as_c_loads_them() {
    let loads = |change: &dyn Fn(&mut TlsOptions), world: World| {
        let id = identity(|id| change(&mut id.options));
        let (r, notes, calls) = shake(world, &id);
        let loaded: Vec<_> = calls
            .into_iter()
            .filter(|c| c.starts_with("cert") || c.starts_with("key"))
            .collect();
        (r, loaded, notes)
    };
    // A PEM file, its key from the same.
    let (r, loaded, _) = loads(
        &|o| o.cert = Some(b"/client.pem".to_vec()),
        World::default(),
    );
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(
        loaded,
        ["cert_chain_file(/client.pem)", "key_file(/client.pem, Pem)"]
    );
    // A DER blob, a key file of its own type.
    let (_, loaded, _) = loads(
        &|o| {
            o.cert_blob = Some(b"der".to_vec());
            o.cert_type = Some(b"DER".to_vec());
            o.key = Some(b"/key.pem".to_vec());
            o.key_type = Some(b"pem".to_vec());
        },
        World::default(),
    );
    assert_eq!(
        loaded,
        ["cert_buffer(der, Asn1)", "key_file(/key.pem, Pem)"]
    );
    // A PEM blob over a file, its key the blob.
    let (_, loaded, _) = loads(
        &|o| {
            o.cert = Some(b"/ignored.pem".to_vec());
            o.cert_blob = Some(b"pem".to_vec());
        },
        World::default(),
    );
    assert_eq!(loaded, ["cert_chain_buffer(pem)", "key_buffer(pem, Pem)"]);
    // A DER file, a key blob of a type the library does not know.
    let (_, loaded, _) = loads(
        &|o| {
            o.cert = Some(b"/c.der".to_vec());
            o.cert_type = Some(b"DER".to_vec());
            o.key_blob = Some(b"k".to_vec());
            o.key_type = Some(b"ENG".to_vec());
        },
        World::default(),
    );
    assert_eq!(
        loaded,
        ["cert_file(/c.der, Asn1)", "key_buffer(k, Unknown)"]
    );
    // A type it does not know for the certificate.
    let (r, loaded, notes) = loads(
        &|o| {
            o.cert = Some(b"/c".to_vec());
            o.cert_type = Some(b"P12".to_vec());
        },
        World::default(),
    );
    assert_eq!(r, Err(ErrorKind::BadFunctionArgument));
    assert!(loaded.is_empty());
    assert!(has(&notes, "fail: BadFunctionArgument: unknown cert type"));
    for (name, line) in [
        (
            "cert",
            "fail: SslConnectError: unable to use client certificate",
        ),
        ("key", "fail: SslConnectError: unable to set private key"),
    ] {
        let world = World {
            answers: vec![(name, -4)],
            ..World::default()
        };
        let (r, _, notes) = loads(&|o| o.cert = Some(b"/c.pem".to_vec()), world);
        assert_eq!(r, Err(ErrorKind::SslConnectError));
        assert!(has(&notes, line), "{notes:#?}");
    }
}

#[test]
fn an_address_gets_no_sni_and_is_checked_after_the_handshake() {
    let id = plain();
    let run = |world: World| {
        let lib = Fake::new(world);
        let shared = TlsShared::testing();
        let to = peer(b"127.0.0.1", TlsPeerKind::Ipv4, false);
        let mut s = session_to(lib, &id, &to, Alpn::None, &shared, None);
        let mut kept = Kept::new();
        let wire = Wire::default();
        let r = TlsIo::testing(&id, b"127.0.0.1", &mut kept, &wire, |io| s.handshake(io));
        let calls = lib.w().calls.clone();
        (r, kept.notes.0, calls)
    };
    let (r, notes, calls) = run(World::default());
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    assert!(!calls.iter().any(|c| c.starts_with("sni(")));
    assert!(!calls.iter().any(|c| c.starts_with("check_domain(")));
    assert!(calls.iter().any(|c| c == "check_ip(127.0.0.1)"));
    assert!(has(
        &notes,
        "trace: check peer certificate for IP match on 127.0.0.1 -> 1"
    ));
    let (r, notes, _) = run(World {
        check_ip: Some(0),
        ..World::default()
    });
    assert_eq!(r, Err(ErrorKind::PeerFailedVerification));
    assert!(has(
        &notes,
        "fail: PeerFailedVerification:  subject alt name(s) or common name do not match \"127.0.0.1\""
    ));
    let (r, notes, _) = run(World {
        check_ip: None,
        ..World::default()
    });
    assert_eq!(r, Err(ErrorKind::PeerFailedVerification));
    assert!(has(
        &notes,
        "fail: PeerFailedVerification: unable to get peer certificate"
    ));
    // Not verified, no check.
    let id = identity(|id| id.verify_host = false);
    let lib = Fake::new(World::default());
    let shared = TlsShared::testing();
    let to = peer(b"127.0.0.1", TlsPeerKind::Ipv4, false);
    let mut s = session_to(lib, &id, &to, Alpn::None, &shared, None);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = TlsIo::testing(&id, b"127.0.0.1", &mut kept, &wire, |io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().made("check_ip").is_empty());
    // A name the library will not check fails the setup.
    let world = World {
        refuse: vec!["check_domain"],
        ..World::default()
    };
    let (r, _, calls) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(!calls.iter().any(|c| c == "bio"));
    let world = World {
        refuse: vec!["sni"],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(has(&notes, "fail: SslConnectError: Failed to set SNI"));
}

/// Each pair of `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST`: a
/// host's name is handed to the library to check, and an address is
/// checked after the handshake, wherever the name is to be checked, the
/// chain checked or not; neither where it is not.
#[test]
fn the_name_is_checked_whether_or_not_the_chain_is() {
    for (verify_peer, verify_host) in [(true, true), (true, false), (false, true), (false, false)] {
        let id = identity(|i| {
            i.verify_peer = verify_peer;
            i.verify_host = verify_host;
        });
        let case = (verify_peer, verify_host);
        let (r, notes, calls) = shake(World::default(), &id);
        assert_eq!(r, Ok(Handshake::Done), "{case:?}: {notes:#?}");
        assert_eq!(
            calls.iter().any(|c| c == "check_domain(example.com)"),
            verify_host,
            "{case:?}: {calls:#?}"
        );
        let lib = Fake::new(World {
            check_ip: Some(0),
            ..World::default()
        });
        let shared = TlsShared::testing();
        let to = peer(b"127.0.0.1", TlsPeerKind::Ipv4, false);
        let mut s = session_to(lib, &id, &to, Alpn::None, &shared, None);
        let mut kept = Kept::new();
        let wire = Wire::default();
        let r = TlsIo::testing(&id, b"127.0.0.1", &mut kept, &wire, |io| s.handshake(io));
        if verify_host {
            assert_eq!(r, Err(ErrorKind::PeerFailedVerification), "{case:?}");
            assert!(has(
                &kept.notes.0,
                "fail: PeerFailedVerification:  subject alt name(s) or common name do not match \"127.0.0.1\""
            ));
        } else {
            assert_eq!(r, Ok(Handshake::Done), "{case:?}");
            assert!(lib.w().made("check_ip").is_empty(), "{case:?}");
        }
    }
}

#[test]
fn the_handshake_waits_and_fails_as_c_s() {
    let detail = |rc: i32, detail: i32, id: &TryArc<TlsIdentity>| {
        let world = World {
            scripts: vec![("connect", vec![Act::Return(rc, detail)])],
            ..World::default()
        };
        let lib = Fake::new(world);
        let shared = TlsShared::testing();
        let mut s = session(lib, id, Alpn::None, &shared);
        let mut kept = Kept::new();
        let wire = Wire::default();
        let r = with_io(&mut s, id, &mut kept, &wire, |s, io| s.handshake(io));
        (r, s.waits(), kept.notes.0)
    };
    let id = plain();
    let (r, waits, notes) = detail(-1, sys::WOLFSSL_ERROR_WANT_READ, &id);
    assert_eq!((r, waits), (Ok(Handshake::Waiting), TlsWait::Recv));
    assert!(has(&notes, "trace: wolfSSL_connect() -> -1, detail=2"));
    let (r, waits, _) = detail(-1, sys::WOLFSSL_ERROR_WANT_WRITE, &id);
    assert_eq!((r, waits), (Ok(Handshake::Waiting), TlsWait::Send));
    let fails = [
        (
            sys::DOMAIN_NAME_MISMATCH,
            ErrorKind::PeerFailedVerification,
            "fail: PeerFailedVerification:  subject alt name(s) or common name do not match \"example.com\"",
        ),
        (
            sys::ASN_NO_SIGNER_E,
            ErrorKind::SslCacertBadfile,
            "fail: SslCacertBadfile:  CA signer not available for verification",
        ),
        (
            sys::ASN_AFTER_DATE_E,
            ErrorKind::PeerFailedVerification,
            "fail: PeerFailedVerification: server verification failed: certificate has expired.",
        ),
        (
            sys::ASN_BEFORE_DATE_E,
            ErrorKind::PeerFailedVerification,
            "fail: PeerFailedVerification: server verification failed: certificate not valid yet.",
        ),
        (
            -313,
            ErrorKind::SslConnectError,
            "fail: SslConnectError: SSL_connect failed with error -313: Unknown error",
        ),
    ];
    for (code, kind, line) in fails {
        let (r, _, notes) = detail(-1, code, &id);
        assert_eq!(r, Err(kind), "{code}");
        assert!(has(&notes, line), "{notes:#?}");
    }
    // A signer missing, not verified: on with a word.
    let lax = identity(|id| id.verify_peer = false);
    let (r, _, notes) = detail(-1, sys::ASN_NO_SIGNER_E, &lax);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(has(
        &notes,
        "info: CA signer not available for verification, continuing anyway"
    ));
    // Failed once, it fails the same again.
    let world = World {
        scripts: vec![("connect", vec![Act::Return(-1, sys::ASN_AFTER_DATE_E)])],
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let mut s = session(lib, &id, Alpn::None, &shared);
    let mut kept = Kept::new();
    let wire = Wire::default();
    for _ in 0..2 {
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        assert_eq!(r, Err(ErrorKind::PeerFailedVerification));
    }
    assert_eq!(lib.w().made("connect").len(), 1);
}

/// The I/O below decides a failure the library details otherwise: a send
/// or a receive failed is a failed connect; a wait, a wait.
#[test]
fn a_failure_below_is_the_handshake_s() {
    let run = |wire: Wire, acts: Vec<Act>| {
        let world = World {
            scripts: vec![("connect", acts)],
            ..World::default()
        };
        let lib = Fake::new(world);
        let id = plain();
        let shared = TlsShared::testing();
        let mut s = session(lib, &id, Alpn::None, &shared);
        let mut kept = Kept::new();
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        (r, kept.notes.0)
    };
    let refusing = Wire {
        refuses: true,
        ..Wire::default()
    };
    let (r, notes) = run(refusing, vec![Act::Push(b"hello")]);
    assert_eq!(r, Err(ErrorKind::SslConnectError), "{notes:#?}");
    assert!(has(&notes, "trace: wolfSSL_connect() -> -1, detail=-308"));
    // A wait below, the library's detail not one of its own waits.
    let full = Wire {
        room: Some(0),
        ..Wire::default()
    };
    let (r, notes) = run(full, vec![Act::Push(b"hello"), Act::Return(-1, -323)]);
    assert_eq!(r, Ok(Handshake::Waiting), "{notes:#?}");
    assert!(has(&notes, "trace: bio_write(len=5) -> 81, 0"));
}

#[test]
fn the_trust_is_loaded_as_c_loads_it() {
    let loads = |change: &dyn Fn(&mut TlsIdentity), world: World| {
        let id = identity(change);
        let (r, notes, calls) = shake(world, &id);
        let loaded: Vec<_> = calls
            .into_iter()
            .filter(|c| c.starts_with("ca_") || c == "system_ca")
            .collect();
        (r, loaded, notes)
    };
    let file = |i: &mut TlsIdentity| i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
    let (r, loaded, notes) = loads(&file, World::default());
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(loaded, ["ca_locations(Some(\"/ca.pem\"), None)"]);
    let lines = said(&notes, "info: ");
    assert_eq!(
        &lines[1..4],
        [
            "info: successfully set certificate verify locations:",
            "info:  CAfile: /ca.pem",
            "info:  CApath: none",
        ]
    );
    assert!(has(
        &notes,
        "trace: wssl_populate_x509_store, path=/ca.pem, blob=0"
    ));
    // A blob in place of the file; the directory still.
    let (_, loaded, notes) = loads(
        &|i| {
            file(i);
            i.options.ca_path = CaSetting::Given(b"/certs".to_vec());
            i.options.ca_blob = CaSetting::Given(b"PEM".to_vec());
        },
        World::default(),
    );
    assert_eq!(
        loaded,
        ["ca_buffer(PEM)", "ca_locations(None, Some(\"/certs\"))"]
    );
    assert!(has(
        &notes,
        "info: successfully imported CA certificate blob"
    ));
    assert!(has(
        &notes,
        "trace: wssl_populate_x509_store, path=none, blob=1"
    ));
    // The system's, asked for.
    let (_, loaded, notes) = loads(
        &|i| i.options.ssl_options = SslOptions::NATIVE_CA,
        World::default(),
    );
    assert_eq!(loaded, ["system_ca"]);
    assert!(has(&notes, "info: successfully imported native CA store"));
    // Failing: a blob fails; the system's goes on; the locations fail a
    // verified peer with nothing else loaded, and only that.
    let (r, _, notes) = loads(
        &|i| i.options.ca_blob = CaSetting::Given(b"PEM".to_vec()),
        World {
            refuse: vec!["ca_buffer"],
            ..World::default()
        },
    );
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    assert!(has(
        &notes,
        "fail: SslCacertBadfile: error importing CA certificate blob"
    ));
    let (r, _, notes) = loads(
        &file,
        World {
            refuse: vec!["ca_locations"],
            ..World::default()
        },
    );
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    assert!(has(
        &notes,
        "fail: SslCacertBadfile: error setting certificate verify locations: CAfile: /ca.pem CApath: none"
    ));
    let (r, _, notes) = loads(
        &|i| {
            file(i);
            i.options.ssl_options = SslOptions::NATIVE_CA;
        },
        World {
            refuse: vec!["ca_locations", "system_ca"],
            ..World::default()
        },
    );
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    assert!(has(
        &notes,
        "info: error importing native CA store, continuing anyway"
    ));
    let (r, _, notes) = loads(
        &|i| {
            file(i);
            i.options.ssl_options = SslOptions::NATIVE_CA;
        },
        World {
            refuse: vec!["ca_locations"],
            ..World::default()
        },
    );
    assert_eq!(r, Ok(Handshake::Done));
    assert!(has(
        &notes,
        "info: error setting certificate verify locations, continuing anyway:"
    ));
    let (r, _, _) = loads(
        &|i| {
            file(i);
            i.verify_peer = false;
        },
        World {
            refuse: vec!["ca_locations"],
            ..World::default()
        },
    );
    assert_eq!(r, Ok(Handshake::Done));
}

/// The store is set up as the handshake's first read is about to be
/// made: after the ClientHello is written, before the answer is read.
#[test]
fn the_store_is_set_up_at_the_handshake_s_first_read() {
    let id = identity(|i| i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec()));
    let world = World {
        scripts: vec![(
            "connect",
            vec![
                Act::Push(b"hello"),
                Act::Pull(5),
                Act::Return(-1, sys::WOLFSSL_ERROR_WANT_READ),
            ],
        )],
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let mut s = session(lib, &id, Alpn::None, &shared);
    let mut kept = Kept::new();
    let wire = Wire::with(b"there");
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Waiting));
    let notes = &kept.notes.0;
    let wrote = at(notes, "trace: bio_write(len=5) -> 0, 5");
    let store = at(
        notes,
        "trace: wssl_populate_x509_store, path=/ca.pem, blob=0",
    );
    let read = at(notes, "trace: bio_read(len=5) -> 0, 5");
    assert!(wrote < store && store < read, "{notes:#?}");
    assert_eq!(lib.w().pulled, b"there");
    // Set up once.
    lib.w().scripts = vec![("connect", vec![Act::Pull(5)])];
    let wire = Wire::with(b"more!");
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept.notes.0);
    assert_eq!(lib.w().made("ca_locations").len(), 1);
    // A store failing in the read fails the handshake, with its trace.
    let world = World {
        scripts: vec![("connect", vec![Act::Pull(5)])],
        refuse: vec!["ca_locations"],
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let mut s = session(lib, &id, Alpn::None, &shared);
    let mut kept = Kept::new();
    let wire = Wire::with(b"there");
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile), "{:#?}", kept.notes.0);
    assert!(has(
        &kept.notes.0,
        "trace: Curl_wssl_setup_x509_store() -> 77"
    ));
    assert!(lib.w().pulled.is_empty());
}

#[test]
fn the_multi_keeps_the_store_while_it_may() {
    let id = identity(|i| i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec()));
    let lib = Fake::new(World::default());
    let shared = TlsShared::testing();
    let wire = Wire::default();
    let connect = |id: &TryArc<TlsIdentity>| {
        let before = lib.w().calls.len();
        let mut s = session(lib, id, Alpn::None, &shared);
        let mut kept = Kept::new();
        let r = with_io(&mut s, id, &mut kept, &wire, |s, io| s.handshake(io));
        assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept.notes.0);
        lib.w().calls[before..].to_vec()
    };
    let first = connect(&id);
    assert!(
        first
            .iter()
            .any(|c| c == "ca_locations(Some(\"/ca.pem\"), None)")
    );
    assert!(first.iter().any(|c| c == "new_store -> 2"));
    // The next takes it, a reference of its own, and loads nothing.
    let next = connect(&id);
    assert!(next.iter().any(|c| c == "up_ref(2)"), "{next:#?}");
    assert!(next.iter().any(|c| c == "set_store(2)"));
    assert!(!next.iter().any(|c| c.starts_with("ca_locations")));
    // Another file loads its own, and keeps it in place of the first.
    let other = identity(|i| i.options.ca_file = CaSetting::Given(b"/other.pem".to_vec()));
    let third = connect(&other);
    assert!(
        third
            .iter()
            .any(|c| c.starts_with("ca_locations(Some(\"/other.pem\")"))
    );
    let again = connect(&id);
    assert!(
        again
            .iter()
            .any(|c| c.starts_with("ca_locations(Some(\"/ca.pem\")"))
    );
    // A directory is never kept: the context's own store is loaded.
    let dir = identity(|i| i.options.ca_path = CaSetting::Given(b"/certs".to_vec()));
    let own = connect(&dir);
    assert!(!own.iter().any(|c| c.starts_with("new_store")), "{own:#?}");
    assert!(own.iter().any(|c| c.starts_with("ca_locations")));
    // Kept for no time: never taken.
    let now = identity(|i| {
        i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
        i.options.ca_cache = CaCache::For(Duration::ZERO);
    });
    let fresh = connect(&now);
    assert!(fresh.iter().any(|c| c.starts_with("ca_locations")));
    // A store whose references are not counted is not taken nor kept.
    let lib = Fake::new(World {
        uncounted: true,
        ..World::default()
    });
    let shared = TlsShared::testing();
    for _ in 0..2 {
        let mut s = session(lib, &id, Alpn::None, &shared);
        let mut kept = Kept::new();
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        assert_eq!(r, Ok(Handshake::Done));
    }
    assert_eq!(lib.w().made("ca_locations").len(), 2);
    // No store made: out of memory, said.
    let world = World {
        refuse: vec!["new_store"],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::OutOfMemory));
    assert!(has(
        &notes,
        "fail: OutOfMemory: SSL: could not create a X509 store"
    ));
}

#[test]
fn credentials_are_kept_for_the_multi_only_where_they_may_be() {
    let base = |i: &mut TlsIdentity| i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
    assert!(crate::trust::cacheable(&identity(base)));
    assert!(crate::trust::cacheable(&plain()));
    let not: [&dyn Fn(&mut TlsIdentity); 6] = [
        &|i| i.options.ca_cache = CaCache::Off,
        &|i| i.verify_peer = false,
        &|i| i.options.ca_path = CaSetting::Given(b"/certs".to_vec()),
        &|i| i.options.ca_blob = CaSetting::Given(b"PEM".to_vec()),
        &|i| i.options.crl_file = Some(b"/crl.pem".to_vec()),
        &|i| i.options.ssl_options = SslOptions::NATIVE_CA,
    ];
    for (n, change) in not.iter().enumerate() {
        let id = identity(|i| {
            base(i);
            change(i);
        });
        assert!(!crate::trust::cacheable(&id), "{n}");
    }
}

#[test]
fn the_pinned_key_needs_the_peer_s_certificate() {
    let pinned = identity(|i| {
        i.options.pinned_key =
            Some(b"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_vec());
    });
    for (peer, line) in [
        (
            PeerCert::None,
            Some("fail: SslPinnedpubkeynotmatch: SSL: failed retrieving server certificate"),
        ),
        (
            PeerCert::NoDer,
            Some("fail: SslPinnedpubkeynotmatch: SSL: failed retrieving ASN.1 server certificate"),
        ),
        // Not a certificate: no key to compare.
        (PeerCert::Der(b"not der".to_vec()), None),
    ] {
        let world = World {
            peer,
            ..World::default()
        };
        let (r, notes, _) = shake(world, &pinned);
        assert_eq!(r, Err(ErrorKind::SslPinnedpubkeynotmatch));
        if let Some(line) = line {
            assert!(has(&notes, line), "{notes:#?}");
        }
        assert!(said(&notes, "info: SSL connection using").is_empty());
    }
    // None pinned, the certificate is not looked at.
    let world = World {
        peer: PeerCert::None,
        ..World::default()
    };
    assert_eq!(shake(world, &plain()).0, Ok(Handshake::Done));
}

#[test]
fn alpn_s_choice_is_taken() {
    let world = World {
        alpn: AlpnGot::Chose(b"h2".to_vec()),
        ..World::default()
    };
    let lib = Fake::new(world);
    let id = plain();
    let shared = TlsShared::testing();
    let mut s = session(lib, &id, Alpn::H2Http11, &shared);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(s.chosen().map(|c| c.name()), Some("h2"));
    assert!(has(&kept.notes.0, "info: ALPN: server accepted h2"));
    // A failure to get it fails, and stays failed.
    let world = World {
        alpn: AlpnGot::Failed(-173),
        ..World::default()
    };
    let lib = Fake::new(world);
    let mut s = session(lib, &id, Alpn::H2Http11, &shared);
    let mut kept = Kept::new();
    for _ in 0..2 {
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        assert_eq!(r, Err(ErrorKind::SslConnectError));
    }
    assert!(has(
        &kept.notes.0,
        "fail: SslConnectError: ALPN, failure getting protocol, error -173"
    ));
    // None offered: none asked for or set.
    let lib = Fake::new(World::default());
    let mut s = session(lib, &id, Alpn::None, &shared);
    let mut kept = Kept::new();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().made("alpn(").is_empty());
    assert!(said(&kept.notes.0, "info: ALPN").is_empty());
    let world = World {
        refuse: vec!["alpn"],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(has(
        &notes,
        "fail: SslConnectError: SSL: failed setting ALPN protocols"
    ));
}

/// A new session the library tells of during a read.
fn ticket(der: &'static [u8], early_max: u32) -> Act {
    Act::Session(NewSession::Made {
        der: der.to_vec(),
        version: 0x0304,
        timeout: 300,
        early_max,
    })
}

#[test]
fn sessions_are_kept_and_resumed() {
    let lib = Fake::new(World {
        alpn: AlpnGot::Chose(b"h2".to_vec()),
        ..World::default()
    });
    let id = plain();
    let shared = TlsShared::testing();
    let mut kept = Kept::new();
    let wire = Wire::default();
    let mut s = session(lib, &id, Alpn::H2Http11, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    // TLS 1.3's ticket comes with a read, and is kept with what ALPN
    // agreed.
    lib.w().scripts = vec![(
        "read",
        vec![
            ticket(b"tick", 0),
            Act::Return(-1, sys::WOLFSSL_ERROR_WANT_READ),
        ],
    )];
    let mut buf = [0u8; 16];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.recv(io, &mut buf));
    assert!(matches!(r, Ok(Recv::WouldBlock)), "{r:?}");
    let mut s = session(lib, &id, Alpn::H2Http11, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("resume("), ["resume(tick)"]);
    assert!(has(
        &kept.notes.0,
        "info: SSL reusing session with ALPN 'h2'"
    ));
    // Resumed before ALPN is offered, after the handle is made.
    let calls = lib.w().calls.clone();
    let resume = calls.iter().rposition(|c| c == "resume(tick)").unwrap();
    assert_eq!(calls[resume - 1], "ssl");
    assert_eq!(calls[resume + 1], "alpn(h2,http/1.1)");
    // Not offering what it agreed: not resumed.
    let mut s = session(lib, &id, Alpn::Http11, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("resume(").len(), 1);
}

#[test]
fn sessions_that_fail_say_so() {
    let id = plain();
    let wire = Wire::default();
    let shared = TlsShared::testing();
    let keep = |lib: &'static Fake, kept: &mut Kept, made: NewSession| {
        lib.w().scripts = vec![("connect", vec![Act::Session(made), Act::Return(1, 0)])];
        let mut s = session(lib, &id, Alpn::None, &shared);
        with_io(&mut s, &id, kept, &wire, |s, io| s.handshake(io))
    };
    // Refused by the library: said, and dropped from the cache.
    let lib = Fake::new(World {
        resume: Resume::Refused(-1),
        ..World::default()
    });
    let mut kept = Kept::new();
    let made = |der: &[u8]| NewSession::Made {
        der: der.to_vec(),
        version: 0x0303,
        timeout: 300,
        early_max: 0,
    };
    assert_eq!(keep(lib, &mut kept, made(b"one")), Ok(Handshake::Done));
    let mut s = session(lib, &id, Alpn::None, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(has(
        &kept.notes.0,
        "info: cached session not accepted (-1), removing from cache"
    ));
    let mut s = session(lib, &id, Alpn::None, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("resume(").len(), 1);
    // Not decoded: a failure said, and the handshake goes on.
    let lib = Fake::new(World {
        resume: Resume::Undecoded,
        ..World::default()
    });
    let mut kept = Kept::new();
    keep(lib, &mut kept, made(b"two")).unwrap();
    let mut s = session(lib, &id, Alpn::None, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(has(
        &kept.notes.0,
        "fail: SslConnectError: could not decode previous session"
    ));
    // Not written out: traced, nothing kept, the handshake on.
    let lib = Fake::new(World::default());
    let mut kept = Kept::new();
    assert_eq!(
        keep(lib, &mut kept, NewSession::Unsized(0)),
        Ok(Handshake::Done)
    );
    assert_eq!(
        keep(lib, &mut kept, NewSession::Unwritten(u32::MAX)),
        Ok(Handshake::Done)
    );
    assert!(has(
        &kept.notes.0,
        "trace: fail to assess session length: 0"
    ));
    assert!(has(
        &kept.notes.0,
        "trace: fail to serialize session: 4294967295"
    ));
    assert_eq!(
        keep(lib, &mut kept, NewSession::NoRoom(7)),
        Ok(Handshake::Done)
    );
    assert!(has(
        &kept.notes.0,
        "fail: OutOfMemory: unable to allocate session buffer of 7 bytes"
    ));
    let mut s = session(lib, &id, Alpn::None, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().made("resume(").is_empty());
}

#[test]
fn no_session_cache_neither_tells_nor_resumes() {
    let id = identity(|id| id.options.session_cache = false);
    let (r, _, calls) = shake(World::default(), &id);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(
        !calls
            .iter()
            .any(|c| c == "tell_sessions" || c.starts_with("resume"))
    );
}

#[test]
fn a_given_session_is_resumed_before_the_cache_s() {
    let lib = Fake::new(World::default());
    let id = plain();
    let shared = TlsShared::testing();
    let mut kept = Kept::new();
    let wire = Wire::default();
    let given = TlsTicket::new(b"given".to_vec(), 0x0304, None, 0, 0);
    let mut s = session(lib, &id, Alpn::None, &shared);
    let r = TlsIo::testing_given(&id, HOST, &mut kept, &wire, Some(given), |io| {
        s.handshake(io)
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("resume("), ["resume(given)"]);
    assert!(has(
        &kept.notes.0,
        "trace: applied SSL session from control connection"
    ));
}

/// A first session of `lib` to `HOST` keeps a TLS 1.3 ticket allowing
/// `early` bytes, having agreed on h2.
fn keep_ticket(lib: &'static Fake, kept: &mut Kept, shared: &TlsShared, early: u32) {
    let id = plain();
    let wire = Wire::default();
    let mut s = session(lib, &id, Alpn::H2Http11, shared);
    let r = with_io(&mut s, &id, kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    lib.w().scripts = vec![(
        "read",
        vec![
            ticket(b"tick", early),
            Act::Return(-1, sys::WOLFSSL_ERROR_WANT_READ),
        ],
    )];
    let mut buf = [0u8; 16];
    let r = with_io(&mut s, &id, kept, &wire, |s, io| s.recv(io, &mut buf));
    assert!(matches!(r, Ok(Recv::WouldBlock)));
}

#[test]
fn a_session_allowing_early_data_puts_the_handshake_off() {
    let lib = Fake::new(World {
        alpn: AlpnGot::Chose(b"h2".to_vec()),
        session_early: 16384,
        ..World::default()
    });
    let shared = TlsShared::testing();
    let mut kept = Kept::new();
    keep_ticket(lib, &mut kept, &shared, 16384);
    let id = plain();
    let to = peer(HOST, TlsPeerKind::Name, true);
    let mut s = session_to(lib, &id, &to, Alpn::H2Http11, &shared, None);
    kept.notes.0.clear();
    let wire = Wire::default();
    let before = lib.w().calls.len();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    let deferred = s.deferred().expect("put off");
    assert_eq!((deferred.most, deferred.alpn.name()), (16384, "h2"));
    assert_eq!(s.chosen().map(|c| c.name()), Some("h2"));
    let calls = lib.w().calls[before..].to_vec();
    assert!(
        calls.iter().any(|c| c == "max_early_data(16384)"),
        "{calls:#?}"
    );
    // Only what the session agreed is offered.
    assert!(calls.iter().any(|c| c == "alpn(h2)"), "{calls:#?}");
    assert!(!calls.iter().any(|c| c == "connect"));
    let notes = &kept.notes.0;
    assert_eq!(
        said(notes, "info: "),
        [
            "info: SSL reusing session with ALPN 'h2'",
            "info: SSL session allows 16384 bytes of early data, reusing ALPN 'h2'",
            "info: ALPN: deferred handshake for early data using 'h2'.",
        ],
        "{notes:#?}"
    );
    // The early data goes, then the handshake.
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.handshake_early(io, b"GET / HTTP/1.1\r\n")
    });
    assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept.notes.0);
    assert!(s.deferred().is_none());
    assert!(s.early_accepted());
    let notes = &kept.notes.0;
    assert!(has(
        notes,
        "trace: wolfSSL_write_early_data(len=16) -> 16, 16"
    ));
    assert!(has(notes, "info: SSL sending 16 bytes of early data"));
    assert!(has(
        notes,
        "info: SSL connection using TLSv1.3 / TLS13-AES128-GCM-SHA256"
    ));
    let calls = lib.w().calls.clone();
    assert!(at(&calls, "write_early(16)") < calls.iter().rposition(|c| c == "connect").unwrap());
}

#[test]
fn early_data_waits_fails_and_is_rejected_as_c_s() {
    let start = |world: World| {
        let lib = Fake::new(world);
        let shared = TlsShared::testing();
        let mut kept = Kept::new();
        keep_ticket(lib, &mut kept, &shared, 100);
        let id = plain();
        let to = peer(HOST, TlsPeerKind::Name, true);
        let mut s = session_to(lib, &id, &to, Alpn::H2Http11, &shared, None);
        let wire = Wire::default();
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        assert_eq!(r, Ok(Handshake::Done));
        assert!(s.deferred().is_some());
        (lib, s, kept, id)
    };
    let early = World {
        alpn: AlpnGot::Chose(b"h2".to_vec()),
        session_early: 100,
        ..World::default()
    };
    // A wait: the bytes taken kept, the rest sent at the next call.
    let (lib, mut s, mut kept, id) = start(World {
        early_rejected: true,
        ..early
    });
    lib.w().scripts = vec![
        (
            "write_early",
            vec![Act::Return(-1, sys::WOLFSSL_ERROR_WANT_WRITE)],
        ),
        ("write_early", vec![Act::Return(3, 0)]),
    ];
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.handshake_early(io, b"early")
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    assert!(s.deferred().is_none());
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.handshake_early(io, b"early")
    });
    assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept.notes.0);
    assert_eq!(
        lib.w().made("write_early"),
        ["write_early(5)", "write_early(5)", "write_early(2)"]
    );
    assert!(!s.early_accepted());
    // A failure: traced in the library's words, a failed send.
    let (lib, mut s, mut kept, id) = start(World {
        alpn: AlpnGot::Chose(b"h2".to_vec()),
        session_early: 100,
        ..World::default()
    });
    lib.w().scripts = vec![("write_early", vec![Act::Return(-1, SOCKET_ERROR_E)])];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.handshake_early(io, b"early")
    });
    assert_eq!(r, Err(ErrorKind::SendError));
    assert!(has(
        &kept.notes.0,
        "trace: SSL send early data, error: 'error state on socket'(-308)"
    ));
    // A session allowing none, or of other ALPN: not put off.
    for (world, line) in [
        (
            World {
                alpn: AlpnGot::Chose(b"h2".to_vec()),
                ..World::default()
            },
            "trace: SSL session does not allow earlydata",
        ),
        (
            World {
                alpn: AlpnGot::NotFound,
                session_early: 100,
                ..World::default()
            },
            "trace: SSL session has different ALPN, no early data",
        ),
    ] {
        let lib = Fake::new(world);
        let shared = TlsShared::testing();
        let mut kept = Kept::new();
        keep_ticket(lib, &mut kept, &shared, 100);
        let id = plain();
        let to = peer(HOST, TlsPeerKind::Name, true);
        let mut s = session_to(lib, &id, &to, Alpn::H2Http11, &shared, None);
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        assert_eq!(r, Ok(Handshake::Done));
        assert!(s.deferred().is_none());
        assert!(has(&kept.notes.0, line), "{:#?}", kept.notes.0);
    }
}

/// A connected session of `world`'s library, and its library.
fn connected(world: World) -> (Session<Fake>, &'static Fake, TryArc<TlsIdentity>) {
    let lib = Fake::new(world);
    let id = plain();
    let shared = TlsShared::testing();
    let mut s = session(lib, &id, Alpn::None, &shared);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    (s, lib, id)
}

#[test]
fn a_read_answers_as_c_s() {
    let (mut s, lib, id) = connected(World::default());
    let read = |s: &mut Session<Fake>, acts: Vec<Act>, wire: &Wire| {
        lib.w().scripts = vec![("read", acts)];
        let mut kept = Kept::new();
        let mut buf = [0u8; 8];
        let r = with_io(s, &id, &mut kept, wire, |s, io| s.recv(io, &mut buf));
        (r.map_err(|e| e.kind()), kept.notes.0)
    };
    let wire = Wire::default();
    let (r, notes) = read(&mut s, vec![Act::Deliver(b"data")], &wire);
    assert!(matches!(r, Ok(Recv::Data(n)) if n.get() == 4));
    assert!(has(&notes, "trace: wssl_recv(len=8) -> 0, 4"));
    let (r, notes) = read(
        &mut s,
        vec![Act::Return(0, sys::WOLFSSL_ERROR_ZERO_RETURN)],
        &wire,
    );
    assert!(matches!(r, Ok(Recv::Eof)));
    assert!(has(&notes, "trace: wssl_recv(len=8) -> CLOSED"));
    // A wait below.
    let (r, notes) = read(&mut s, vec![Act::Pull(5)], &wire);
    assert!(matches!(r, Ok(Recv::WouldBlock)), "{r:?}");
    assert!(has(&notes, "trace: wssl_recv(len=8) -> AGAIN"));
    // The end below, without the peer's goodbye.
    let closed = Wire {
        closed: true,
        ..Wire::default()
    };
    let (r, notes) = read(&mut s, vec![Act::Pull(5)], &closed);
    assert!(r.is_err());
    assert!(has(&notes, "trace: wssl_recv(len=8) -> CLOSED"));
    assert!(has(&notes, "fail: RecvError: Connection closed abruptly"));
    // A failure of the library's own.
    let (mut s, lib, id) = connected(World::default());
    lib.w().scripts = vec![("read", vec![Act::Return(-1, SOCKET_ERROR_E)])];
    let mut kept = Kept::new();
    let mut buf = [0u8; 8];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.recv(io, &mut buf));
    assert!(r.is_err());
    let fail = said(
        &kept.notes.0,
        "fail: RecvError: SSL read: error state on socket, errno ",
    );
    assert_eq!(fail.len(), 1, "{:#?}", kept.notes.0);
}

#[test]
fn a_write_answers_as_c_s() {
    let (mut s, lib, id) = connected(World::default());
    let send = |s: &mut Session<Fake>, acts: Option<Vec<Act>>, wire: &Wire| {
        lib.w().scripts = acts.into_iter().map(|a| ("write", a)).collect();
        let mut kept = Kept::new();
        let r = with_io(s, &id, &mut kept, wire, |s, io| s.send(io, b"0123456789"));
        (r.map_err(|e| e.kind()), kept.notes.0)
    };
    let wire = Wire::default();
    let (r, notes) = send(&mut s, None, &wire);
    assert!(matches!(r, Ok(Sent::Bytes(n)) if n.get() == 10));
    assert!(has(&notes, "trace: wssl_send(len=10) -> 0, 10"));
    let (r, notes) = send(
        &mut s,
        Some(vec![Act::Return(-1, sys::WOLFSSL_ERROR_WANT_WRITE)]),
        &wire,
    );
    assert!(matches!(r, Ok(Sent::WouldBlock)));
    assert!(has(&notes, "trace: wssl_send(len=10) -> 81, 0"));
    // A wait below the library's own error.
    let full = Wire {
        room: Some(0),
        ..Wire::default()
    };
    let (r, _) = send(
        &mut s,
        Some(vec![Act::Push(b"record"), Act::Return(-1, SOCKET_ERROR_E)]),
        &full,
    );
    assert!(matches!(r, Ok(Sent::WouldBlock)), "{r:?}");
    // What the I/O below last came to stands until it moves again, as
    // C's `io_result`: a record written first, the failure is the
    // library's.
    let (r, notes) = send(
        &mut s,
        Some(vec![Act::Push(b"r"), Act::Return(-1, SOCKET_ERROR_E)]),
        &wire,
    );
    assert!(r.is_err());
    assert!(has(&notes, "trace: wssl_send(len=10) -> 55, 0"));
    assert_eq!(
        said(
            &notes,
            "fail: SendError: SSL write: error state on socket, errno "
        )
        .len(),
        1
    );
}

#[test]
fn the_goodbye_is_said_as_c_says_it() {
    let shut = |world: World, goodbye: Goodbye, wire: &Wire| {
        let (mut s, lib, id) = connected(world);
        let mut kept = Kept::new();
        let r = with_io(&mut s, &id, &mut kept, wire, |s, io| {
            s.shutdown(io, goodbye)
        });
        let w = s.waits();
        let r2 = with_io(&mut s, &id, &mut kept, wire, |s, io| {
            s.shutdown(io, goodbye)
        });
        let calls = lib.w().calls.clone();
        (r, w, r2, kept.notes.0, calls)
    };
    let wire = Wire::default();
    // Ours sent and over at once.
    let (r, _, r2, notes, calls) = shut(World::default(), Goodbye::Mutual, &wire);
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(r2, Ok(Handshake::Done));
    assert!(has(&notes, "trace: wolfSSL_read, nread=-1, err=2"));
    assert!(has(&notes, "trace: SSL shutdown finished"));
    assert_eq!(calls.iter().filter(|c| *c == "shutdown").count(), 1);
    // The peer's already come, not sending ours.
    let peers = World {
        scripts: vec![("read", vec![Act::Return(0, sys::WOLFSSL_ERROR_ZERO_RETURN)])],
        ..World::default()
    };
    let (r, _, _, notes, calls) = shut(peers, Goodbye::Heard, &wire);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(has(&notes, "trace: SSL shutdown received, not sending"));
    assert!(!calls.iter().any(|c| c == "shutdown"));
    // Ours waits to be written.
    let blocked = World {
        scripts: vec![(
            "shutdown",
            vec![Act::Return(-1, sys::WOLFSSL_ERROR_WANT_WRITE)],
        )],
        ..World::default()
    };
    let (r, w, _, notes, _) = shut(blocked, Goodbye::Mutual, &wire);
    assert_eq!((r, w), (Ok(Handshake::Waiting), TlsWait::Send));
    assert!(has(&notes, "trace: SSL shutdown still wants to send"));
    // Ours sent, the peer's awaited.
    let sent = World {
        sent_shutdown: true,
        scripts: vec![("shutdown", vec![Act::Return(0, 0)])],
        ..World::default()
    };
    let (r, w, _, notes, _) = shut(sent, Goodbye::Mutual, &wire);
    assert_eq!((r, w), (Ok(Handshake::Waiting), TlsWait::Recv));
    assert!(has(&notes, "trace: SSL shutdown sent, want receive"));
    assert!(!has(&notes, "trace: wolfSSL_read, nread=-1, err=2"));
    // Records still coming are read past, ten at most.
    let mut acts = vec![("shutdown", vec![Act::Return(0, 0)])];
    for _ in 0..12 {
        acts.push(("read", vec![Act::Deliver(b"x")]));
    }
    let more = World {
        sent_shutdown: true,
        scripts: acts,
        ..World::default()
    };
    let (_, _, _, _, calls) = shut(more, Goodbye::Mutual, &wire);
    assert_eq!(calls.iter().filter(|c| c.starts_with("read(")).count(), 10);
    // A failure: traced, and over.
    let failing = World {
        sent_shutdown: true,
        scripts: vec![
            ("shutdown", vec![Act::Return(0, 0)]),
            ("read", vec![Act::Return(-1, SOCKET_ERROR_E)]),
        ],
        ..World::default()
    };
    let (r, _, r2, notes, _) = shut(failing, Goodbye::Mutual, &wire);
    assert_eq!(r, Err(ErrorKind::RecvError));
    assert_eq!(r2, Ok(Handshake::Done));
    assert!(has(
        &notes,
        "trace: SSL shutdown, error: 'error state on socket'(-308)"
    ));
}

#[test]
fn a_session_never_set_up_says_no_goodbye() {
    let lib = Fake::new(World::default());
    let id = plain();
    let shared = TlsShared::testing();
    let mut s = session(lib, &id, Alpn::None, &shared);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().calls.is_empty());
    assert!(s.native().is_none());
}

/// wolfSSL resends a blocked close_notify whole each time (wolfSSL#7784):
/// the goodbye's retried write sends what blocked, and counts the rest.
#[test]
fn a_blocked_goodbye_is_sent_as_it_blocked() {
    let id = plain();
    let mut kept = Kept::new();
    let full = Wire {
        room: Some(0),
        ..Wire::default()
    };
    let mut state = IoState {
        shutting_down: true,
        ..IoState::default()
    };
    TlsIo::testing(&id, HOST, &mut kept, &full, |io| {
        let mut call = Call {
            io: Reach::Stream(io),
            state: &mut state,
            store: None,
            alpn: None,
            quic_params: None,
        };
        assert_eq!(call.send(b"notify"), Moved::Again);
    });
    assert_eq!(state.blocked_len, 6);
    let wire = Wire::default();
    TlsIo::testing(&id, HOST, &mut kept, &wire, |io| {
        let mut call = Call {
            io: Reach::Stream(io),
            state: &mut state,
            store: None,
            alpn: None,
            quic_params: None,
        };
        assert_eq!(call.send(b"notifynotify"), Moved::Bytes(12));
    });
    assert_eq!(wire.sent(), b"notify");
    assert!(has(
        &kept.notes.0,
        "trace: bio_write, shutdown restrict send of 12 to 6 bytes"
    ));
    assert!(has(&kept.notes.0, "trace: bio_write(len=6) -> 0, 6"));
    assert_eq!(state.result, IoResult::Ok);
}

#[test]
// Writes a file, which Miri's isolation refuses.
#[cfg_attr(miri, ignore)]
fn a_tls_1_2_secret_is_logged_while_the_key_log_is_open() {
    let dir = std::env::temp_dir().join(format!("curl-wolfssl-keylog-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("keys");
    let log = SharedKeyLog::new().unwrap();
    log.open_named(file.to_str().unwrap().as_bytes());
    assert!(log.enabled());
    let world = World {
        version: b"TLSv1.2",
        keys: Some(Tls12Keys {
            master: vec![1; 48],
            client_random: vec![7; 32],
        }),
        ..World::default()
    };
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let id = plain();
    let to = peer(HOST, TlsPeerKind::Name, false);
    let mut s = session_to(lib, &id, &to, Alpn::Http11, &shared, Some(log.clone()));
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    let calls = lib.w().calls.clone();
    assert!(at(&calls, "keep_arrays") < at(&calls, "connect"));
    assert!(at(&calls, "connect") < at(&calls, "free_arrays"));
    let written = std::fs::read_to_string(&file).unwrap();
    let want = format!("CLIENT_RANDOM {} {}\n", "07".repeat(32), "01".repeat(48));
    assert_eq!(written, want);
    let line = format!(
        "info: SSLKEYLOGFILE set, all TLS secrets are logged to '{}'",
        file.display()
    );
    assert!(has(&kept.notes.0, &line), "{:#?}", kept.notes.0);
    // TLS 1.3's is not the library's to give: nothing logged, the arrays
    // let go all the same; and none while the handshake waits.
    let world = World {
        keys: Some(Tls12Keys {
            master: vec![2; 48],
            client_random: vec![8; 32],
        }),
        ..World::default()
    };
    let lib = Fake::new(world);
    let mut s = session_to(lib, &id, &to, Alpn::Http11, &shared, Some(log.clone()));
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("free_arrays").len(), 1);
    let waiting = World {
        version: b"TLSv1.2",
        wants: (true, false),
        scripts: vec![(
            "connect",
            vec![Act::Return(-1, sys::WOLFSSL_ERROR_WANT_READ)],
        )],
        ..World::default()
    };
    let lib = Fake::new(waiting);
    let mut s = session_to(lib, &id, &to, Alpn::Http11, &shared, Some(log.clone()));
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Waiting));
    assert!(lib.w().made("free_arrays").is_empty());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), want);
    log.close();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_library_s_words_are_c_s() {
    assert_eq!(Words::new(b"", 5).to_string(), "Unknown error");
    assert_eq!(Words::new(b"", 0).to_string(), "No error");
    assert_eq!(Words::new(b"bad", 5).to_string(), "bad");
    assert_eq!(Words::new(&[b'x'; 300], 1).to_string().len(), 255);
}

#[test]
fn the_session_hands_out_the_library_s_objects() {
    let (s, _, _) = connected(World::default());
    let native = s.native().expect("connected");
    assert!(native.session().is_some());
    assert!(!s.pending());
    let (s, _, _) = connected(World {
        pending: true,
        ..World::default()
    });
    assert!(s.pending());
}
