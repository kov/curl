//! A QUIC connection's session over the scripted library: made as
//! `Curl_wssl_ctx_init` makes it for QUIC's transport, its tickets kept
//! for HTTP/3 with the transport parameters, and the peer checked as
//! `Curl_vquic_tls_verify_peer` checks it.

use super::*;
use crate::quic::QuicSession;
use curl_core::tls::{Chosen, DriveCall, QuicContextSetup, QuicTls as _, TlsCx, TlsNative};
use std::ptr::NonNull;

/// A QUIC session of `lib` for `id` to `name`, of `kind`, the transfer
/// sending early data if `early`, its context handed to `setup`, the
/// sessions kept in `kept`.
fn quic_to(
    lib: &'static Fake,
    id: &TryArc<TlsIdentity>,
    kept: &mut Kept,
    name: &[u8],
    kind: TlsPeerKind,
    early: bool,
    setup: QuicContextSetup<'_>,
) -> Result<QuicSession<Fake>, ErrorKind> {
    let method = TryArc::try_new(()).unwrap();
    TlsCx::testing_kept(id, name, kept, |shared, cx| {
        let s = Session::new_quic(lib, method, id, &peer(name, kind, early), shared, None)?;
        QuicSession::new(s, setup, cx)
    })
}

/// The same, to `HOST` by name.
fn quic(
    lib: &'static Fake,
    id: &TryArc<TlsIdentity>,
    kept: &mut Kept,
    early: bool,
    setup: QuicContextSetup<'_>,
) -> Result<QuicSession<Fake>, ErrorKind> {
    quic_to(lib, id, kept, HOST, TlsPeerKind::Name, early, setup)
}

/// Drive `s` through one call of the QUIC library, which runs `op`, its
/// transport parameters `params`.
fn drive(
    s: &mut QuicSession<Fake>,
    id: &TryArc<TlsIdentity>,
    kept: &mut Kept,
    name: &[u8],
    params: Option<&'static [u8]>,
    op: &mut dyn FnMut(&mut dyn DriveCall),
) {
    TlsCx::testing_kept(id, name, kept, |_, cx| {
        let mut params = || params.map(<[u8]>::to_vec);
        s.drive(cx, &mut params, op);
    });
}

/// The QUIC library's word that the handshake is done, during a drive of
/// `s`: what the check came to.
fn done(
    s: &mut QuicSession<Fake>,
    id: &TryArc<TlsIdentity>,
    kept: &mut Kept,
    name: &[u8],
) -> Option<Result<(), ErrorKind>> {
    let mut done = None;
    drive(s, id, kept, name, None, &mut |dc| {
        done = Some(dc.handshake_done());
    });
    done
}

#[test]
fn a_quic_session_is_made_as_vquic_tls_c_makes_it() {
    let lib = Fake::new(World::default());
    let id = plain();
    let mut kept = Kept::new();
    let seen = std::cell::Cell::new(None);
    let setup = |native: TlsNative| {
        // The context alone, before the session's object is made.
        seen.set(Some((native.session(), lib.w().calls.len())));
        Ok(())
    };
    let s = quic(lib, &id, &mut kept, false, &setup).expect("made");
    let calls = lib.w().calls.clone();
    // No name check before the handshake, nor "curl offers", which are
    // the stream's first step's; the QUIC library tells the context of
    // sessions, after its setup.
    assert_eq!(
        calls,
        [
            "ctx",
            "min_version(0x303)",
            "verify(true)",
            "sni(example.com)",
            "tell_sessions",
            "ssl",
            "quic_codepoint",
            "alpn(h3,h3-29)",
            "bio",
        ],
        "{calls:#?}"
    );
    let (session, at_setup) = seen.get().expect("set up");
    assert_eq!(session, None);
    assert_eq!(at_setup, at(&calls, "sni(example.com)") + 1);
    assert_eq!(
        s.native().session(),
        Some(NonNull::<u32>::dangling().cast())
    );
    assert!(has(&kept.notes.0, "trace: set ALPN: h3,h3-29"));
    assert!(said(&kept.notes.0, "info: ALPN").is_empty());
    // The trust is not loaded until the peer's first bytes are due.
    assert!(lib.w().made("ca_").is_empty());
    assert!(s.early_data().is_none());
}

#[test]
fn a_quic_session_takes_the_transfer_s_versions_for_the_quic_library_to_change() {
    // Unlike OpenSSL's and GnuTLS's, wolfSSL's QUIC session refuses no
    // version: ngtcp2's setup of the context sets TLS 1.3 itself.
    let lib = Fake::new(World::default());
    let mut kept = Kept::new();
    let capped = identity(|i| i.options.max_version = TlsMaxVersion::Tls1_2);
    assert!(quic(lib, &capped, &mut kept, false, &|_| Ok(())).is_ok());
    assert_eq!(lib.w().made("max_version"), ["max_version(0x303)"]);
}

#[test]
fn the_quic_library_s_failed_setup_fails_the_session_as_c_says_it() {
    let lib = Fake::new(World::default());
    let mut kept = Kept::new();
    let r = quic(lib, &plain(), &mut kept, false, &|_| Err("setup failed"));
    assert_eq!(r.err(), Some(ErrorKind::FailedInit));
    assert!(has(&kept.notes.0, "fail: FailedInit: setup failed"));
    assert!(lib.w().made("tell_sessions").is_empty());
    assert!(lib.w().made("ssl").is_empty());
}

#[test]
fn without_kept_sessions_a_quic_session_is_told_of_none() {
    let lib = Fake::new(World::default());
    let id = identity(|i| i.options.session_cache = false);
    let mut kept = Kept::new();
    let _ = quic(lib, &id, &mut kept, true, &|_| Ok(())).unwrap();
    assert!(lib.w().made("tell_sessions").is_empty());
    assert!(lib.w().made("resume").is_empty());
}

#[test]
fn a_quic_ticket_is_kept_for_h3_with_its_transport_parameters_and_resumed() {
    let world = World {
        scripts: vec![("drive", vec![ticket(b"ticket-q", 0xFFFF_FFFF)])],
        ..World::default()
    };
    let lib = Fake::new(world);
    let id = plain();
    let mut kept = Kept::new();
    let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    drive(&mut s, &id, &mut kept, HOST, Some(b"tp"), &mut |_| {});
    // Resumed for a transfer sending early data: the offer is h3 alone,
    // the library told the most the ticket allows, and the ticket is the
    // QUIC library's to decide on, with its parameters.
    let before = lib.w().calls.len();
    let s = quic(lib, &id, &mut kept, true, &|_| Ok(())).unwrap();
    let calls = lib.w().calls[before..].to_vec();
    let resume = at(&calls, "resume(ticket-q)");
    assert_eq!(
        &calls[resume - 2..resume + 3],
        [
            "ssl",
            "quic_codepoint",
            "resume(ticket-q)",
            "max_early_data(4294967295)",
            "alpn(h3)",
        ],
        "{calls:#?}"
    );
    assert!(has(
        &kept.notes.0,
        "info: SSL reusing session with ALPN 'h3'"
    ));
    let early = s.early_data().expect("the QUIC library decides");
    assert_eq!(early.earlydata_max, 0xFFFF_FFFF);
    assert_eq!(early.chosen(), Some(Chosen::H3));
    assert_eq!(early.quic_params, b"tp");
}

#[test]
fn a_quic_ticket_without_what_early_data_needs_resumes_without_it() {
    let lib = Fake::new(World::default());
    let id = plain();
    for (early_max, params) in [(0, Some(&b"tp"[..])), (0xFFFF_FFFF, None)] {
        let mut kept = Kept::new();
        lib.w().scripts = vec![("drive", vec![ticket(b"ticket-q", early_max)])];
        let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
        drive(&mut s, &id, &mut kept, HOST, params, &mut |_| {});
        let before = lib.w().calls.len();
        let s = quic(lib, &id, &mut kept, true, &|_| Ok(())).unwrap();
        let calls = lib.w().calls[before..].to_vec();
        // Resumed, the offer whole and no early data asked of the
        // library; the QUIC library is handed the ticket all the same,
        // and says why none goes.
        assert!(calls.contains(&"resume(ticket-q)".to_owned()));
        assert!(calls.contains(&"alpn(h3,h3-29)".to_owned()), "{calls:#?}");
        assert!(!calls.iter().any(|c| c.starts_with("max_early_data")));
        assert!(s.early_data().is_some());
    }
    // A transfer sending none hands the QUIC library no ticket.
    let mut kept = Kept::new();
    lib.w().scripts = vec![("drive", vec![ticket(b"ticket-q", 0xFFFF_FFFF)])];
    let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    drive(&mut s, &id, &mut kept, HOST, Some(b"tp"), &mut |_| {});
    let s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    assert!(s.early_data().is_none());
}

#[test]
fn the_peer_is_reported_and_checked_as_the_quic_library_says_the_handshake_is_done() {
    let lib = Fake::new(World::default());
    let id = plain();
    let mut kept = Kept::new();
    let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    let before = lib.w().calls.len();
    let mut checked = None;
    drive(&mut s, &id, &mut kept, HOST, None, &mut |dc| {
        dc.with_cx(&mut |cx| cx.trace(format_args!("the QUIC library's call")));
        checked = Some(dc.handshake_done());
    });
    assert_eq!(checked, Some(Ok(())));
    let calls = lib.w().calls[before..].to_vec();
    assert_eq!(
        calls,
        ["drive", "handshake_done", "check_host(example.com)"]
    );
    let notes = &kept.notes.0;
    let traced = at(notes, "trace: the QUIC library's call");
    let using = at(
        notes,
        "info: SSL connection using TLSv1.3 / TLS13-AES128-GCM-SHA256",
    );
    assert!(traced < using, "{notes:#?}");
}

#[test]
fn a_peer_fails_its_check_only_where_the_library_says_it_does_not_match() {
    let id = plain();
    // The library's failure, alone of its answers, fails the check, with
    // no words, and the peer's sessions are forgotten.
    for (answer, want) in [
        (Some(0), Some(Err(ErrorKind::PeerFailedVerification))),
        (Some(-1), Some(Ok(()))),
        (None, Some(Err(ErrorKind::OutOfMemory))),
    ] {
        let lib = Fake::new(World {
            check_host: answer,
            ..World::default()
        });
        let mut kept = Kept::new();
        let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
        let from = kept.notes.0.len();
        assert_eq!(done(&mut s, &id, &mut kept, HOST), want, "{answer:?}");
        let notes = &kept.notes.0[from..];
        assert!(said(notes, "fail:").is_empty(), "{notes:#?}");
        let forgot = notes.iter().any(|n| n.starts_with("trace: find peer slot"));
        assert_eq!(forgot, want != Some(Ok(())), "{answer:?}: {notes:#?}");
    }
}

#[test]
fn an_address_is_checked_as_one_and_an_unverified_host_not_at_all() {
    let id = plain();
    let lib = Fake::new(World {
        check_ip: Some(0),
        ..World::default()
    });
    let mut kept = Kept::new();
    let mut s = quic_to(
        lib,
        &id,
        &mut kept,
        b"::1",
        TlsPeerKind::Ipv6,
        false,
        &|_| Ok(()),
    )
    .unwrap();
    assert_eq!(
        done(&mut s, &id, &mut kept, b"::1"),
        Some(Err(ErrorKind::PeerFailedVerification))
    );
    assert_eq!(lib.w().made("check_"), ["check_ip(::1)"]);
    // Not verifying the host, neither is looked at; the pinned key still
    // is.
    let lax = identity(|i| {
        i.verify_host = false;
        i.options.pinned_key = Some(b"sha256//AAAA".to_vec());
    });
    let lib = Fake::new(World {
        check_host: Some(0),
        peer: PeerCert::None,
        ..World::default()
    });
    let mut kept = Kept::new();
    let mut s = quic(lib, &lax, &mut kept, false, &|_| Ok(())).unwrap();
    assert_eq!(
        done(&mut s, &lax, &mut kept, HOST),
        Some(Err(ErrorKind::SslPinnedpubkeynotmatch))
    );
    assert!(lib.w().made("check_").is_empty());
    // Reported first, then checked.
    let notes = &kept.notes.0;
    let using = at(
        notes,
        "info: SSL connection using TLSv1.3 / TLS13-AES128-GCM-SHA256",
    );
    let failed = at(
        notes,
        "fail: SslPinnedpubkeynotmatch: SSL: failed retrieving server certificate",
    );
    assert!(using < failed, "{notes:#?}");
}

#[test]
fn a_quic_session_s_trust_is_set_up_once_before_the_peer_s_first_bytes() {
    let lib = Fake::new(World::default());
    let id = identity(|i| i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec()));
    let mut kept = Kept::new();
    let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    for _ in 0..2 {
        TlsCx::testing_kept(&id, HOST, &mut kept, |_, cx| s.before_recv(cx)).unwrap();
    }
    assert_eq!(
        lib.w().made("ca_locations"),
        ["ca_locations(Some(\"/ca.pem\"), None)"]
    );
}

#[test]
#[should_panic(expected = "a QUIC session's records are the QUIC library's")]
fn a_quic_session_never_writes_through_the_bio() {
    let world = World {
        scripts: vec![("drive", vec![Act::Push(b"hello")])],
        ..World::default()
    };
    let lib = Fake::new(world);
    let id = plain();
    let mut kept = Kept::new();
    let mut s = quic(lib, &id, &mut kept, false, &|_| Ok(())).unwrap();
    drive(&mut s, &id, &mut kept, HOST, None, &mut |_| {});
}
