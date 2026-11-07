//! The paths cargo-mutants found unchecked: the context callback, the
//! sessions given and offered, the key log of a handshake that failed,
//! the goodbye's answers, the cipher list's room, and the I/O below's
//! state.

use super::*;
use crate::session::CipherList;
use curl_core::tls::{Chosen, ContextHandler};

/// The application's context callback gets the context with its trust
/// store set up, before the session object is made; its refusal fails
/// the handshake in C's words.
#[test]
fn the_context_callback_gets_the_store_set_up() {
    let run = |refuses: Option<ErrorKind>| {
        let lib = Fake::new(World::default());
        let id = identity(|i| i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec()));
        let shared = TlsShared::testing();
        let mut s = session(lib, &id, Alpn::None, &shared);
        let mut kept = Kept::new();
        kept.context = Some(ContextHandler { refuses, handed: 0 });
        let wire = Wire::default();
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
        let calls = lib.w().calls.clone();
        let handed = kept.context.as_ref().unwrap().handed;
        (r, kept.notes.0, calls, handed)
    };
    let (r, _, calls, handed) = run(None);
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(handed, 1);
    let loaded = at(&calls, "ca_locations(Some(\"/ca.pem\"), None)");
    assert!(loaded < at(&calls, "ssl"), "{calls:#?}");
    // Set up once: not again at the handshake.
    assert_eq!(
        calls
            .iter()
            .filter(|c| c.starts_with("ca_locations"))
            .count(),
        1
    );
    let (r, notes, calls, _) = run(Some(ErrorKind::SslCertproblem));
    assert_eq!(r, Err(ErrorKind::SslCertproblem));
    assert!(has(
        &notes,
        "fail: SslCertproblem: error signaled by SSL ctx callback"
    ));
    assert!(!calls.iter().any(|c| c == "ssl"));
}

/// The control connection's session, applied, keeps the cache's from
/// being looked at.
#[test]
fn a_given_session_keeps_the_cache_s_untaken() {
    let lib = Fake::new(World::default());
    let id = plain();
    let shared = TlsShared::testing();
    let mut kept = Kept::new();
    let wire = Wire::default();
    lib.w().scripts = vec![(
        "connect",
        vec![
            Act::Session(NewSession::Made {
                der: b"cached".to_vec(),
                version: 0x0303,
                timeout: 300,
                early_max: 0,
            }),
            Act::Return(1, 0),
        ],
    )];
    let mut s = session(lib, &id, Alpn::None, &shared);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    let given = TlsTicket::new(b"given".to_vec(), 0x0304, None, 0, 0);
    let mut s = session(lib, &id, Alpn::None, &shared);
    let r = TlsIo::testing_given(&id, HOST, &mut kept, &wire, Some(given), |io| {
        s.handshake(io)
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("resume("), ["resume(given)"]);
}

/// A session is resumed only if it has data and the transfer offers what
/// it agreed by ALPN.
#[test]
fn a_session_is_resumed_only_where_its_protocol_is_offered() {
    let resumed = |ticket: TlsTicket, alpn: Alpn| {
        let lib = Fake::new(World::default());
        let id = plain();
        let shared = TlsShared::testing();
        let mut kept = Kept::new();
        let wire = Wire::default();
        let mut s = session(lib, &id, alpn, &shared);
        let r = TlsIo::testing_given(&id, HOST, &mut kept, &wire, Some(ticket), |io| {
            s.handshake(io)
        });
        assert_eq!(r, Ok(Handshake::Done));
        lib.w().made("resume(").len()
    };
    let h2 = || Chosen::named(b"h2");
    assert_eq!(
        resumed(
            TlsTicket::new(b"t".to_vec(), 0x0304, h2(), 0, 0),
            Alpn::H2Http11
        ),
        1
    );
    assert_eq!(
        resumed(
            TlsTicket::new(b"t".to_vec(), 0x0304, h2(), 0, 0),
            Alpn::Http11
        ),
        0
    );
    assert_eq!(
        resumed(TlsTicket::new(Vec::new(), 0x0304, None, 0, 0), Alpn::None),
        0
    );
}

/// A transfer that may not send early data does not put its handshake
/// off, though its session allows some.
#[test]
fn no_early_data_without_the_transfer_s_leave() {
    let lib = Fake::new(World {
        alpn: AlpnGot::Chose(b"h2".to_vec()),
        session_early: 100,
        ..World::default()
    });
    let shared = TlsShared::testing();
    let mut kept = Kept::new();
    super::keep_ticket(lib, &mut kept, &shared, 100);
    let id = plain();
    let mut s = session(lib, &id, Alpn::H2Http11, &shared);
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.handshake(io));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(s.deferred().is_none());
    assert!(lib.w().made("max_early_data").is_empty());
}

/// A handshake that failed with nothing more to read or write has its
/// secret logged and its arrays let go, as one that succeeded.
#[test]
// Writes a file, which Miri's isolation refuses.
#[cfg_attr(miri, ignore)]
fn a_failed_handshake_s_secret_is_logged() {
    let dir = std::env::temp_dir().join(format!("curl-wolfssl-keylog-f-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("keys");
    let log = SharedKeyLog::new().unwrap();
    log.open_named(file.to_str().unwrap().as_bytes());
    let world = World {
        version: b"TLSv1.2",
        keys: Some(Tls12Keys {
            master: vec![3; 48],
            client_random: vec![9; 32],
        }),
        scripts: vec![("connect", vec![Act::Return(-1, sys::ASN_AFTER_DATE_E)])],
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
    assert_eq!(r, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(lib.w().made("free_arrays").len(), 1);
    let written = std::fs::read_to_string(&file).unwrap();
    assert!(written.starts_with("CLIENT_RANDOM 0909"), "{written}");
    log.close();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A write the library answers 0 to failed, in C's words.
#[test]
fn a_write_of_nothing_fails() {
    let (mut s, lib, id) = connected(World::default());
    lib.w().scripts = vec![("write", vec![Act::Return(0, SOCKET_ERROR_E)])];
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| s.send(io, b"x"));
    assert!(r.is_err());
    assert!(has(&kept.notes.0, "trace: wssl_send(len=1) -> 55, 0"));
}

/// The goodbye: the peer's read only when the library says so, sent
/// ours to a peer still there, and the last read's answers.
#[test]
fn the_goodbye_answers_each_read_as_c_does() {
    let shut = |world: World, goodbye: Goodbye, wire: &Wire| {
        let (mut s, lib, id) = connected(world);
        let mut kept = Kept::new();
        let r = with_io(&mut s, &id, &mut kept, wire, |s, io| {
            s.shutdown(io, goodbye)
        });
        let calls = lib.w().calls.clone();
        (r, s.waits(), kept.notes.0, calls)
    };
    let wire = Wire::default();
    // Nothing read is not the peer's goodbye.
    let nothing = World {
        scripts: vec![("read", vec![Act::Return(0, sys::WOLFSSL_ERROR_WANT_READ)])],
        ..World::default()
    };
    let (_, _, notes, _) = shut(nothing, Goodbye::Heard, &wire);
    assert!(!has(&notes, "trace: SSL shutdown received, not sending"));
    // The peer's goodbye read, the peer still there: ours is sent.
    let peers = || World {
        scripts: vec![("read", vec![Act::Return(0, sys::WOLFSSL_ERROR_ZERO_RETURN)])],
        ..World::default()
    };
    let (_, _, notes, calls) = shut(peers(), Goodbye::Mutual, &wire);
    assert!(!has(&notes, "trace: peer closed connection"));
    assert!(calls.iter().any(|c| c == "shutdown"));
    // Ours sent, the last read's answers.
    let last = |acts: Vec<Act>| World {
        sent_shutdown: true,
        scripts: vec![("shutdown", vec![Act::Return(0, 0)]), ("read", acts)],
        ..World::default()
    };
    let (r, _, notes, _) = shut(
        last(vec![Act::Return(0, sys::WOLFSSL_ERROR_ZERO_RETURN)]),
        Goodbye::Mutual,
        &wire,
    );
    assert_eq!(r, Ok(Handshake::Done));
    assert!(has(&notes, "trace: SSL shutdown received"));
    let (r, waits, notes, _) = shut(
        last(vec![Act::Return(-1, sys::WOLFSSL_ERROR_WANT_WRITE)]),
        Goodbye::Mutual,
        &wire,
    );
    assert_eq!((r, waits), (Ok(Handshake::Waiting), TlsWait::Send));
    assert!(has(&notes, "trace: SSL shutdown send blocked"));
}

/// The cipher list fits C's buffer of 4096 bytes, its zero byte
/// counted: one byte past fails it.
#[test]
fn the_cipher_list_fits_c_s_buffer() {
    let mut list = CipherList::default();
    assert_eq!(list.add(&[b'A'; 4095]), Ok(()));
    assert_eq!(list.add(b":"), Err(ErrorKind::TooLarge));
    let mut list = CipherList::default();
    assert_eq!(list.add(&[b'A'; 4096]), Err(ErrorKind::TooLarge));
    let mut list = CipherList::default();
    assert_eq!(list.add(&[b'A'; 2000]), Ok(()));
    assert_eq!(list.add(&[b'B'; 2095]), Ok(()));
    assert_eq!(list.add(b":"), Err(ErrorKind::TooLarge));
}

/// A write that would block outside the goodbye leaves nothing for the
/// goodbye to restrict; the end read below is what the BIO says is the
/// end.
#[test]
fn the_io_below_keeps_what_the_goodbye_and_the_bio_ask() {
    let id = plain();
    let mut kept = Kept::new();
    let full = Wire {
        room: Some(0),
        ..Wire::default()
    };
    let mut state = IoState::default();
    TlsIo::testing(&id, HOST, &mut kept, &full, |io| {
        let mut call = Call {
            io: Reach::Stream(io),
            state: &mut state,
            store: None,
            alpn: None,
            quic_params: None,
        };
        assert_eq!(call.send(b"data"), Moved::Again);
    });
    assert_eq!(state.blocked_len, 0);
    let closed = Wire {
        closed: true,
        ..Wire::default()
    };
    TlsIo::testing(&id, HOST, &mut kept, &closed, |io| {
        let mut call = Call {
            io: Reach::Stream(io),
            state: &mut state,
            store: None,
            alpn: None,
            quic_params: None,
        };
        assert!(!call.at_eof());
        let mut buf = [0u8; 4];
        assert_eq!(call.recv(&mut buf), Moved::Bytes(0));
        assert!(call.at_eof());
    });
}

/// No channel binding: C's wolfSSL build makes none.
#[test]
fn the_session_binds_no_channel() {
    struct NoNotes;
    impl curl_core::tls::BindingNotes for NoNotes {
        fn info(&mut self, _: core::fmt::Arguments<'_>) {}
        fn fail(&mut self, kind: ErrorKind, _: core::fmt::Arguments<'_>) -> ErrorKind {
            kind
        }
    }
    let (s, _, _) = connected(World::default());
    assert_eq!(s.channel_binding(&mut NoNotes), Ok(None));
}
