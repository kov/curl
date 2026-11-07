//! The session over the scripted library (`fake.rs`): the calls made of
//! mbedTLS in `mbedtls.c`'s order, and what is made of each answer, said
//! in C's words.

use curl_alloc::TryArc;
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::options::{CaSetting, ColdGroup as _, TlsMaxVersion, TlsMinVersion, TlsOptions};
use curl_core::tls::{
    Alpn, CaDefaults, Chosen, Goodbye, Handshake, Kept, TlsIdentity, TlsIo, TlsPeer, TlsPeerKind,
    TlsSession as _, TlsWait,
};

use crate::fake::{Act, Fake, Wire, World};
use crate::library::{KeyCopy, Resume, Saved};
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

/// A session of `lib` for `id` to `name`, offering `alpn`.
fn session_to(
    lib: &'static Fake,
    id: &TryArc<TlsIdentity>,
    name: &[u8],
    kind: TlsPeerKind,
    alpn: Alpn,
) -> Session<Fake> {
    let peer = TlsPeer {
        name,
        port: 443,
        kind,
        early_data: false,
    };
    Session::new(lib, TryArc::try_new(()).unwrap(), id, &peer, alpn).unwrap()
}

fn session(lib: &'static Fake, id: &TryArc<TlsIdentity>, alpn: Alpn) -> Session<Fake> {
    session_to(lib, id, HOST, TlsPeerKind::Name, alpn)
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
    let mut s = session(lib, id, Alpn::H2Http11);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, id, &mut kept, &wire, |s, io| s.handshake(io));
    let calls = lib.w().calls.clone();
    (r, kept.notes.0, calls)
}

fn has(notes: &[String], line: &str) -> bool {
    notes.iter().any(|n| n == line)
}

#[test]
fn a_handshake_sets_the_library_up_as_mbedtls_c_does() {
    let (r, notes, calls) = shake(World::default(), &plain());
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    let want = [
        "conn",
        "defaults",
        "signal_tickets",
        "verify_hook",
        "verify_required",
        "profile_next",
        "versions(0x303, 0x304)",
        "use_rng",
        "setup",
        "bio",
        "default_ciphersuites",
        "renegotiation",
        "tickets_off",
        "ca_chain",
        "hostname(example.com)",
        "alpn(h2,http/1.1)",
        "handshake",
    ];
    assert_eq!(calls, want);
    let lines = [
        "info: mbedTLS: Connecting to example.com:443",
        "info: ALPN: curl offers h2,http/1.1",
        "info: mbedTLS: TLSv1.3 Handshake complete, cipher is TLS_AES_128_GCM_SHA256",
        "info: ALPN: server did not agree on a protocol. Uses default.",
        "info: SSL connected",
    ];
    let said: Vec<_> = notes
        .iter()
        .filter(|n| n.starts_with("info: "))
        .cloned()
        .collect();
    assert_eq!(said, lines, "{notes:#?}");
}

/// The CA blob, the file and the directory are loaded as C loads them:
/// the blob in place of the file, the blob and the file only for a peer
/// that is verified, and PEM with a zero byte after it.
#[test]
fn the_trust_is_loaded_as_c_loads_it() {
    let calls = |verify: bool, blob: Option<&[u8]>, der: bool| {
        let id = identity(|id| {
            id.verify_peer = verify;
            id.options.ca_file = CaSetting::Given(b"ca.pem".to_vec());
            id.options.ca_path = CaSetting::Given(b"certs".to_vec());
            if let Some(b) = blob {
                id.options.ca_blob = CaSetting::Given(b.to_vec());
            }
            if der {
                id.options.cert_type = Some(b"DER".to_vec());
            }
        });
        let (r, notes, calls) = shake(World::default(), &id);
        assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
        calls[1..3].to_vec()
    };
    assert_eq!(
        calls(true, None, false),
        ["ca_parse_file(ca.pem)", "ca_parse_path(certs)"]
    );
    assert_eq!(calls(false, None, false)[0], "ca_parse_path(certs)");
    assert_eq!(
        calls(true, Some(b"PEM"), false),
        ["ca_parse([80, 69, 77, 0])", "ca_parse_path(certs)"]
    );
    assert_eq!(
        calls(true, Some(b"PEM\0"), false)[0],
        "ca_parse([80, 69, 77, 0])"
    );
    assert_eq!(calls(true, Some(b"D"), true)[0], "ca_parse([68])");
    assert_eq!(calls(false, Some(b"PEM"), false)[0], "ca_parse_path(certs)");
}

/// A load that fails says the library's number and words; a directory
/// fails only a peer that is verified.
#[test]
fn a_load_that_fails_says_why_in_c_s_words() {
    let fails = |answer: &'static str, change: fn(&mut TlsIdentity)| {
        let world = World {
            answers: vec![(answer, -0x2700)],
            ..World::default()
        };
        let (r, notes, _) = shake(world, &identity(change));
        (r, notes)
    };
    let (r, notes) = fails("ca_parse_file", |id| {
        id.options.ca_file = CaSetting::Given(b"ca.pem".to_vec());
    });
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    assert!(
        has(
            &notes,
            "fail: SslCacertBadfile: mbedTLS: error reading CA cert file ca.pem: (-0x2700) X509 - Certificate verification failed"
        ),
        "{notes:#?}"
    );
    let (r, _) = fails("ca_parse_path", |id| {
        id.options.ca_path = CaSetting::Given(b"certs".to_vec());
    });
    assert_eq!(r, Err(ErrorKind::SslCacertBadfile));
    let (r, notes) = fails("ca_parse_path", |id| {
        id.verify_peer = false;
        id.options.ca_path = CaSetting::Given(b"certs".to_vec());
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert!(
        has(
            &notes,
            "fail: SslCacertBadfile: mbedTLS: error reading CA cert path certs: (-0x2700) X509 - Certificate verification failed"
        ),
        "{notes:#?}"
    );
    let (r, notes) = fails("ca_parse", |id| {
        id.options.ca_blob = CaSetting::Given(b"x".to_vec());
    });
    assert_eq!(r, Err(ErrorKind::SslCertproblem));
    assert!(has(
        &notes,
        "fail: SslCertproblem: mbedTLS: error importing CA cert blob: (-0x2700) X509 - Certificate verification failed"
    ));
    let (r, notes) = fails("cert_parse_file", |id| {
        id.options.cert = Some(b"me.pem".to_vec());
    });
    assert_eq!(r, Err(ErrorKind::SslCertproblem));
    assert!(has(
        &notes,
        "fail: SslCertproblem: mbedTLS: error reading client cert file me.pem: (-0x2700) X509 - Certificate verification failed"
    ));
    let (r, notes) = fails("crl_parse_file", |id| {
        id.options.crl_file = Some(b"crl.pem".to_vec());
    });
    assert_eq!(r, Err(ErrorKind::SslCrlBadfile));
    assert!(has(
        &notes,
        "fail: SslCrlBadfile: mbedTLS: error reading CRL file crl.pem: (-0x2700) X509 - Certificate verification failed"
    ));
}

/// The client's key is loaded with its password, must sign, and is
/// given to the configuration with the certificate.
#[test]
fn the_client_s_key_is_loaded_and_must_sign() {
    let id = identity(|id| {
        id.options.cert = Some(b"me.pem".to_vec());
        id.options.key = Some(b"key.pem".to_vec());
        id.options.key_password = Some(b"secret".to_vec());
    });
    let (r, _, calls) = shake(World::default(), &id);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(calls.contains(&"key_parse_file(key.pem, Some(\"secret\"))".to_owned()));
    let own = calls.iter().position(|c| c == "own_cert").unwrap();
    let chain = calls.iter().position(|c| c == "ca_chain").unwrap();
    assert_eq!(own, chain + 1);
    let world = World {
        key_signs: false,
        ..World::default()
    };
    let (r, notes, _) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::SslCertproblem));
    assert!(
        has(
            &notes,
            "fail: SslCertproblem: mbedTLS: error reading private key key.pem: (-0x3F00) an error"
        ),
        "{notes:#?}"
    );
    // A blob of PEM is read with its zero byte counted; DER without.
    let blob = |der: bool| {
        let id = identity(|id| {
            id.options.key_blob = Some(b"K".to_vec());
            id.options.key_password = Some(b"pw\0junk".to_vec());
            if der {
                id.options.key_type = Some(b"der".to_vec());
            }
        });
        let (r, _, calls) = shake(World::default(), &id);
        assert_eq!(r, Ok(Handshake::Done));
        calls
            .into_iter()
            .find(|c| c.starts_with("key_parse("))
            .unwrap()
    };
    assert_eq!(blob(false), "key_parse([75, 0], Some([112, 119]))");
    assert_eq!(blob(true), "key_parse([75], Some([112, 119]))");
}

/// The versions asked are mapped onto 1.2 and 1.3; a maximum below 1.2
/// is refused.
#[test]
fn the_versions_are_c_s() {
    let versions = |min, max| {
        let id = identity(|id| {
            id.options.min_version = min;
            id.options.max_version = max;
        });
        let (r, notes, calls) = shake(World::default(), &id);
        let set = calls.into_iter().find(|c| c.starts_with("versions("));
        (r, notes, set)
    };
    let set = |min, max| versions(min, max).2.unwrap();
    assert_eq!(
        set(TlsMinVersion::Tls1, TlsMaxVersion::None),
        "versions(0x303, 0x304)"
    );
    assert_eq!(
        set(TlsMinVersion::Tls1_3, TlsMaxVersion::Default),
        "versions(0x304, 0x304)"
    );
    assert_eq!(
        set(TlsMinVersion::Tls1_1, TlsMaxVersion::Tls1_2),
        "versions(0x303, 0x303)"
    );
    for max in [TlsMaxVersion::Tls1_0, TlsMaxVersion::Tls1_1] {
        let (r, notes, set) = versions(TlsMinVersion::Tls1, max);
        assert_eq!(r, Err(ErrorKind::SslConnectError));
        assert!(has(
            &notes,
            "fail: SslConnectError: mbedTLS: unsupported maximum TLS version value"
        ));
        assert_eq!(set, None);
    }
}

/// The cipher lists are walked into the library's numbers, TLS 1.3's
/// first, ended by 0; a list of nothing the library has fails.
#[test]
fn the_cipher_lists_are_the_library_s_numbers() {
    let id = identity(|id| {
        id.options.ciphers = Some(b"ECDHE-RSA-AES128-GCM-SHA256:BOGUS".to_vec());
        id.options.tls13_ciphers = Some(b"TLS_AES_256_GCM_SHA384".to_vec());
    });
    let lib = Fake::new(World::default());
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().suites, [0x1302, 0xC02F, 0]);
    assert!(
        has(
            &kept.notes.0,
            "info: mbedTLS: unknown cipher in list: \"BOGUS\""
        ),
        "{:#?}",
        kept.notes.0
    );
    // One list of nothing known leaves the other's defaults.
    let id = identity(|id| id.options.ciphers = Some(b"BOGUS".to_vec()));
    let (r, _, calls) = shake(World::default(), &id);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(
        calls.contains(&"ciphersuites([1302, 1301, 0])".to_owned()),
        "{calls:#?}"
    );
    let id = identity(|id| {
        id.options.ciphers = Some(b"BOGUS".to_vec());
        id.options.tls13_ciphers = Some(b"BOGUS".to_vec());
    });
    let (r, notes, _) = shake(World::default(), &id);
    assert_eq!(r, Err(ErrorKind::SslCipher));
    assert!(has(
        &notes,
        "fail: SslCipher: mbedTLS: no supported cipher in list"
    ));
    assert!(has(
        &notes,
        "fail: SslCipher: mbedTLS: failed to set cipher suites"
    ));
}

/// The name the certificate is checked against is the host's, an
/// address's too, and a failure to set it fails.
#[test]
fn the_host_name_is_set_and_its_failure_fails() {
    let lib = Fake::new(World::default());
    let id = plain();
    let mut s = session_to(lib, &id, b"127.0.0.1", TlsPeerKind::Ipv4, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().calls.contains(&"hostname(127.0.0.1)".to_owned()));
    assert!(lib.w().made("alpn").is_empty());
    let world = World {
        answers: vec![("hostname", -1)],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(has(&notes, "fail: SslConnectError: Failed to set SNI"));
}

/// The handshake waits as the library wants, and its failures are C's.
#[test]
fn the_handshake_waits_and_fails_as_c_s() {
    let lib = Fake::new(World {
        scripts: vec![
            ("handshake", vec![Act::Pull(5)]),
            ("handshake", vec![Act::Push(b"hello"), Act::Pull(5)]),
        ],
        ..World::default()
    });
    let id = plain();
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(s.waits(), TlsWait::Recv);
    let wire = Wire::with(b"world");
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(wire.sent(), b"hello");
    assert_eq!(lib.w().pulled, b"world");
    assert!(has(
        &kept.notes.0,
        "trace: mbedtls_bio_cf_in_read(len=5) -> 81, 0"
    ));
    assert!(has(
        &kept.notes.0,
        "trace: mbedtls_bio_cf_out_write(len=5) -> 0, 5"
    ));
    // The set-up is made once.
    assert_eq!(lib.w().made("setup").len(), 1);

    let world = World {
        scripts: vec![(
            "handshake",
            vec![Act::Return(sys::MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)],
        )],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::PeerFailedVerification));
    assert!(has(
        &notes,
        "fail: PeerFailedVerification: peer certificate could not be verified"
    ));
    let world = World {
        scripts: vec![("handshake", vec![Act::Return(-0x7780)])],
        ..World::default()
    };
    let (r, notes, _) = shake(world, &plain());
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(has(&notes, "trace: TLS version 0304"), "{notes:#?}");
    assert!(has(
        &notes,
        "fail: SslConnectError: ssl_handshake returned: (-0x7780) an error"
    ));
}

/// The verify callback dumps and reports the leaf, clears the flags of
/// the checks that are off, and says what is left.
#[test]
fn the_verify_callback_clears_what_is_off_and_says_what_is_left() {
    let cn = sys::MBEDTLS_X509_BADCERT_CN_MISMATCH;
    let left = |verify_peer: bool, verify_host: bool, flags: u32| {
        let world = World {
            scripts: vec![("handshake", vec![Act::Verify(0, flags)])],
            ..World::default()
        };
        let lib = Fake::new(world);
        let id = identity(|id| {
            id.verify_peer = verify_peer;
            id.verify_host = verify_host;
        });
        let mut s = session(lib, &id, Alpn::None);
        let mut kept = Kept::new();
        kept.verbose = true;
        let wire = Wire::default();
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        assert_eq!(r, Ok(Handshake::Done));
        let left = lib.w().flags_left[0];
        (left, kept.notes.0)
    };
    let (flags, notes) = left(true, true, 0x8 | cn);
    assert_eq!(flags, 0x8 | cn);
    assert!(
        has(&notes, "fail: PeerFailedVerification: mbedTLS: flags 0xc\n"),
        "{notes:#?}"
    );
    assert!(has(&notes, "info: Server certificate:"), "{notes:#?}");
    assert_eq!(left(false, true, 0x8 | cn).0, cn);
    assert_eq!(left(true, false, 0x8 | cn).0, 0x8);
    let (flags, notes) = left(false, false, 0x8 | cn);
    assert_eq!(flags, 0);
    assert!(!notes.iter().any(|n| n.starts_with("fail: ")), "{notes:#?}");
}

/// The pinned key is the peer's, copied out of its certificate.
#[test]
fn the_pinned_key_is_checked_against_the_peer_s() {
    let pinned = |world: World| {
        let id = identity(|id| {
            id.options.pinned_key = Some(b"sha256//nothing=".to_vec());
        });
        shake(world, &id)
    };
    let (r, _, calls) = pinned(World::default());
    assert_eq!(r, Err(ErrorKind::SslPinnedpubkeynotmatch));
    assert!(calls.contains(&"public_key(leaf-der)".to_owned()));
    let (r, notes, _) = pinned(World {
        peer: None,
        ..World::default()
    });
    assert_eq!(r, Err(ErrorKind::SslPinnedpubkeynotmatch));
    assert!(has(
        &notes,
        "fail: SslPinnedpubkeynotmatch: Failed due to missing peer certificate"
    ));
    let (_, notes, _) = pinned(World {
        public_key: Err(KeyCopy::Key),
        ..World::default()
    });
    assert!(has(
        &notes,
        "fail: SslPinnedpubkeynotmatch: Failed copying public key from peer certificate"
    ));
    let (r, _, _) = pinned(World {
        public_key: Err(KeyCopy::OutOfMemory),
        ..World::default()
    });
    assert_eq!(r, Err(ErrorKind::OutOfMemory));
}

/// What ALPN agreed is the connection's, and is said.
#[test]
fn alpn_s_choice_is_taken() {
    let lib = Fake::new(World {
        alpn: Some(b"h2"),
        ..World::default()
    });
    let id = plain();
    let mut s = session(lib, &id, Alpn::H2Http11);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(s.chosen(), Chosen::named(b"h2"));
    assert!(has(&kept.notes.0, "info: ALPN: server accepted h2"));
}

/// A TLS 1.2 session is kept after the handshake, and resumed by the next
/// connection; TLS 1.3's are kept as their tickets come.
#[test]
fn sessions_are_kept_and_resumed() {
    let lib = Fake::new(World {
        version: sys::MBEDTLS_SSL_VERSION_TLS1_2,
        ..World::default()
    });
    let id = plain();
    let mut kept = Kept::new();
    let wire = Wire::default();
    let mut s = session(lib, &id, Alpn::None);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("saved").len(), 1);
    let mut s = session(lib, &id, Alpn::None);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("resume("), ["resume(saved)"]);
    assert!(has(&kept.notes.0, "info: SSL reusing session ID"));
    // Resumed before the CA chain is set, after the tickets are off.
    let calls = lib.w().calls.clone();
    let resume = calls.iter().position(|c| c == "resume(saved)").unwrap();
    assert_eq!(calls[resume - 1], "tickets_off");
    assert_eq!(calls[resume + 1], "ca_chain");

    // TLS 1.3: nothing kept at the handshake; a ticket while reading
    // keeps one, and the read goes on.
    let lib = Fake::new(World {
        scripts: vec![
            (
                "read",
                vec![Act::Return(
                    sys::MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET,
                )],
            ),
            ("read", vec![Act::Deliver(b"data")]),
        ],
        ..World::default()
    });
    let mut kept = Kept::new();
    let mut s = session(lib, &id, Alpn::None);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().made("saved").is_empty());
    let mut buf = [0u8; 16];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.recv(io, &mut buf));
    assert!(matches!(r, Ok(Recv::Data(n)) if n.get() == 4), "{r:?}");
    assert_eq!(&buf[..4], b"data");
    assert_eq!(lib.w().made("saved").len(), 1);
    assert!(has(
        &kept.notes.0,
        "trace: mbedtls_ssl_read(len=16) -> -0x7B00"
    ));
}

/// A session that would not resume or be saved says so in C's words; only
/// failing to get it fails.
#[test]
fn sessions_that_fail_say_so() {
    let id = plain();
    let wire = Wire::default();
    let mut kept = Kept::new();
    let lib = Fake::new(World {
        version: sys::MBEDTLS_SSL_VERSION_TLS1_2,
        resume: Resume::Load(-0x7100),
        ..World::default()
    });
    for _ in 0..2 {
        let mut s = session(lib, &id, Alpn::None);
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        assert_eq!(r, Ok(Handshake::Done));
    }
    assert!(
        has(
            &kept.notes.0,
            "fail: SslConnectError: SSL session error loading: -0x7100"
        ),
        "{:#?}",
        kept.notes.0
    );
    let saving = |saved: Saved| {
        let world = World {
            version: sys::MBEDTLS_SSL_VERSION_TLS1_2,
            saved,
            ..World::default()
        };
        let (r, notes, _) = shake(world, &id);
        (r, notes)
    };
    let (r, notes) = saving(Saved::GetFailed(-0x7F00));
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(has(
        &notes,
        "fail: SslConnectError: mbedtls_ssl_get_session returned -0x7f00"
    ));
    let (r, notes) = saving(Saved::Empty);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(has(
        &notes,
        "fail: SslConnectError: failed to serialize session: length is 0"
    ));
    let (r, notes) = saving(Saved::SaveFailed(-0x6A00));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(has(
        &notes,
        "fail: SslConnectError: failed to serialize session: -0x6a00"
    ));
}

/// A session that is not to be kept is neither saved nor resumed.
#[test]
fn no_session_cache_neither_saves_nor_resumes() {
    let id = identity(|id| id.options.session_cache = false);
    let world = World {
        version: sys::MBEDTLS_SSL_VERSION_TLS1_2,
        ..World::default()
    };
    let (r, _, calls) = shake(world, &id);
    assert_eq!(r, Ok(Handshake::Done));
    assert!(
        !calls
            .iter()
            .any(|c| c == "saved" || c.starts_with("resume"))
    );
}

/// A connected session of `world`'s library, and its library.
fn connected(world: World) -> (Session<Fake>, &'static Fake, TryArc<TlsIdentity>) {
    let lib = Fake::new(world);
    let id = plain();
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    (s, lib, id)
}

/// A write that would block is made again whole, as the library wants;
/// a shorter one is refused.
#[test]
fn a_blocked_write_is_made_again_whole() {
    let (mut s, lib, id) = connected(World::default());
    let wire = Wire::default();
    let send = |s: &mut Session<Fake>, scripts: Vec<Vec<Act>>, bytes: &[u8]| {
        lib.w().scripts = scripts.into_iter().map(|a| ("write", a)).collect();
        let mut kept = Kept::new();
        let r = with_io(s, &id, &mut kept, &wire, |s, io| s.send(io, bytes));
        (r.map_err(|e| e.kind()), kept.notes.0)
    };
    let (r, notes) = send(&mut s, vec![], b"0123456789");
    assert!(matches!(r, Ok(Sent::Bytes(n)) if n.get() == 10));
    assert!(has(&notes, "trace: mbedtls_ssl_write(len=10) -> 0, 10"));
    let (r, notes) = send(
        &mut s,
        vec![vec![Act::Return(sys::MBEDTLS_ERR_SSL_WANT_WRITE)]],
        b"0123456789",
    );
    assert!(matches!(r, Ok(Sent::WouldBlock)));
    assert_eq!(s.waits(), TlsWait::Send);
    assert!(has(&notes, "trace: mbedtls_ssl_write(len=10) -> -0x6880"));
    assert!(has(&notes, "trace: mbedtls_ssl_write(len=10) -> 81, 0"));
    let (r, notes) = send(&mut s, vec![], b"0123");
    assert!(r.is_err());
    assert!(has(
        &notes,
        "fail: BadFunctionArgument: re-send data shorter than previously"
    ));
    let (r, notes) = send(&mut s, vec![], b"0123456789abc");
    assert!(matches!(r, Ok(Sent::Bytes(n)) if n.get() == 10), "{r:?}");
    assert!(has(
        &notes,
        "trace: mbedtls_ssl_write(len=13) -> previously blocked on 10 bytes"
    ));
    assert_eq!(lib.w().made("write(").last(), Some(&"write(10)"));
    // Unblocked, the next write is as long as asked.
    let (r, _) = send(&mut s, vec![], b"0123456789abc");
    assert!(matches!(r, Ok(Sent::Bytes(n)) if n.get() == 13), "{r:?}");
    assert_eq!(lib.w().made("write(").last(), Some(&"write(13)"));
    let (r, notes) = send(&mut s, vec![vec![Act::Return(-0x7100)]], b"x");
    assert_eq!(r.unwrap_err(), std::io::ErrorKind::Other);
    assert!(has(&notes, "trace: mbedtls_ssl_write(len=1) -> 55, 0"));
}

/// A read answers data, a wait, the end at the peer's goodbye, or C's
/// failure.
#[test]
fn a_read_answers_as_c_s() {
    let (mut s, lib, id) = connected(World::default());
    let wire = Wire::default();
    let read = |s: &mut Session<Fake>, rc: i32| {
        lib.w().scripts = vec![("read", vec![Act::Return(rc)])];
        let mut kept = Kept::new();
        let mut buf = [0u8; 8];
        let r = with_io(s, &id, &mut kept, &wire, |s, io| s.recv(io, &mut buf));
        (r.map_err(|e| e.kind()), kept.notes.0)
    };
    let (r, _) = read(&mut s, sys::MBEDTLS_ERR_SSL_WANT_READ);
    assert!(matches!(r, Ok(Recv::WouldBlock)));
    assert_eq!(s.waits(), TlsWait::Recv);
    let (r, _) = read(&mut s, sys::MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY);
    assert!(matches!(r, Ok(Recv::Eof)));
    let (r, notes) = read(&mut s, 0);
    assert!(r.is_err());
    assert!(has(
        &notes,
        "fail: RecvError: ssl_read returned: (-0x0000) an error"
    ));
}

/// The goodbye is sent once, then the peer's read until it comes.
#[test]
fn the_goodbye_is_said_once_and_the_peer_s_awaited() {
    let (mut s, lib, id) = connected(World::default());
    let wire = Wire::default();
    lib.w().scripts = vec![
        ("read", vec![Act::Return(sys::MBEDTLS_ERR_SSL_WANT_READ)]),
        ("read", vec![Act::Return(sys::MBEDTLS_ERR_SSL_WANT_READ)]),
    ];
    let mut kept = Kept::new();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Waiting));
    assert!(has(&kept.notes.0, "trace: mbedtls_shutdown, need RECV"));
    assert_eq!(s.waits(), TlsWait::Recv);
    lib.w().scripts = vec![(
        "read",
        vec![Act::Return(sys::MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)],
    )];
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert!(has(&kept.notes.0, "trace: mbedtls_shutdown done"));
    assert_eq!(lib.w().made("close_notify").len(), 1);
    // Over, it is not said again.
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("read(").len(), 3);
}

/// A session never set up has nothing to say goodbye in.
#[test]
fn a_session_never_set_up_says_no_goodbye() {
    let lib = Fake::new(World::default());
    let id = plain();
    let mut s = session(lib, &id, Alpn::None);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.shutdown(io, Goodbye::Mutual)
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert!(lib.w().calls.is_empty());
}
