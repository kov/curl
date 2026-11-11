//! The session's paths the first tests leave: blobs that fail, a given
//! session, the goodbye's reads, writes past tickets and waits, what the
//! session says of the library, the cipher lists' skips, the leaf's dump,
//! the chain's count, the callbacks' answers and the backend over the
//! real library.

use super::*;

/// The client's certificate blob and a key blob that cannot sign fail as
/// C's do.
#[test]
fn a_client_blob_that_fails_says_why() {
    let world = World {
        answers: vec![("cert_parse", -0x2180)],
        ..World::default()
    };
    let id = identity(|id| id.options.cert_blob = Some(b"C".to_vec()));
    let (r, notes, _) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::SslCertproblem));
    assert!(
        has(
            &notes,
            "fail: SslCertproblem: mbedTLS: error reading client cert blob: (-0x2180) an error"
        ),
        "{notes:#?}"
    );
    let world = World {
        key_signs: false,
        ..World::default()
    };
    let id = identity(|id| id.options.key_blob = Some(b"K".to_vec()));
    let (r, notes, _) = shake(world, &id);
    assert_eq!(r, Err(ErrorKind::SslCertproblem));
    assert!(
        has(
            &notes,
            "fail: SslCertproblem: mbedTLS: error parsing private key: (-0x3F00) an error"
        ),
        "{notes:#?}"
    );
}

/// The control connection's session, given, is resumed in place of the
/// cache's, which is then not looked at.
#[test]
fn a_given_session_is_resumed_before_the_cache_s() {
    let lib = Fake::new(World {
        version: sys::MBEDTLS_SSL_VERSION_TLS1_2,
        ..World::default()
    });
    let id = plain();
    let mut kept = Kept::new();
    let wire = Wire::default();
    // A session in the cache first.
    let mut s = session(lib, &id, Alpn::None);
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.handshake(io).map(|shaken| shaken.as_handshake())
    });
    assert_eq!(r, Ok(Handshake::Done));
    let given = curl_core::tls::TlsTicket::new(b"given".to_vec(), 0x0304, None, 0, 0);
    let mut s = session(lib, &id, Alpn::None);
    let r = TlsIo::testing_given(&id, HOST, &mut kept, &wire, Some(given), |io| {
        s.handshake(io).map(|shaken| shaken.as_handshake())
    });
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(lib.w().made("resume("), ["resume(given)"]);
    assert!(has(
        &kept.notes.0,
        "trace: applied SSL session from control connection"
    ));
}

/// The goodbye reads what the peer still sends, up to ten records, and
/// waits as the library says.
#[test]
fn the_goodbye_reads_past_what_still_comes() {
    let shut = |scripts: Vec<Vec<Act>>| {
        let (mut s, lib, id) = connected(World::default());
        lib.w().scripts = scripts.into_iter().map(|a| ("read", a)).collect();
        let wire = Wire::default();
        let mut kept = Kept::new();
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
            s.shutdown(io, Goodbye::Mutual)
        });
        let reads = lib.w().made("read(").len();
        (r, kept.notes.0, reads, s.waits())
    };
    // Data, ten times over: it is still coming.
    let (r, notes, reads, _) = shut(vec![vec![Act::Deliver(b"x")]; 10]);
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(reads, 10);
    assert!(has(&notes, "trace: mbedtls_shutdown, still getting data"));
    // Data, then the end.
    let (r, notes, reads, _) = shut(vec![vec![Act::Deliver(b"x")], vec![Act::Return(0)]]);
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(reads, 2);
    assert!(has(&notes, "trace: mbedtls_shutdown done"));
    // A wait to read is asked again at once; a wait to write waits.
    let (r, _, reads, _) = shut(vec![
        vec![Act::Return(sys::MBEDTLS_ERR_SSL_WANT_READ)],
        vec![Act::Return(sys::MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)],
    ]);
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(reads, 2);
    let (r, notes, reads, waits) = shut(vec![vec![Act::Return(sys::MBEDTLS_ERR_SSL_WANT_WRITE)]]);
    assert_eq!(r, Ok(Handshake::Waiting));
    assert_eq!(reads, 1);
    assert_eq!(waits, TlsWait::Send);
    assert!(has(&notes, "trace: mbedtls_shutdown, need SEND"));
    // Any other answer fails it.
    let (r, notes, _, _) = shut(vec![vec![Act::Return(-0x7100)]]);
    assert_eq!(r, Err(ErrorKind::RecvError));
    assert!(has(&notes, "trace: mbedtls_shutdown error -0x7100"));
}

/// A write blocked is made again with as many bytes, the same length
/// taken; a ticket met while writing is kept and the write made again;
/// a wait to read is the read's.
#[test]
fn a_write_moves_on_past_tickets_and_waits() {
    let (mut s, lib, id) = connected(World::default());
    let wire = Wire::default();
    let send = |s: &mut Session<Fake>, scripts: Vec<Vec<Act>>, bytes: &[u8]| {
        lib.w().scripts = scripts.into_iter().map(|a| ("write", a)).collect();
        let mut kept = Kept::new();
        let r = with_io(s, &id, &mut kept, &wire, |s, io| s.send(io, bytes));
        (r.map_err(|e| e.kind()), kept.notes.0)
    };
    let (r, _) = send(
        &mut s,
        vec![vec![Act::Return(sys::MBEDTLS_ERR_SSL_WANT_READ)]],
        b"0123",
    );
    assert!(matches!(r, Ok(Sent::WouldBlock)));
    assert_eq!(s.waits(), TlsWait::Recv);
    let (r, notes) = send(&mut s, vec![], b"0123");
    assert!(matches!(r, Ok(Sent::Bytes(n)) if n.get() == 4), "{r:?}");
    assert!(has(
        &notes,
        "trace: mbedtls_ssl_write(len=4) -> previously blocked on 4 bytes"
    ));
    let (r, _) = send(
        &mut s,
        vec![vec![Act::Return(
            sys::MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET,
        )]],
        b"abc",
    );
    assert!(matches!(r, Ok(Sent::Bytes(n)) if n.get() == 3), "{r:?}");
    assert_eq!(lib.w().made("saved").len(), 1);
    assert_eq!(lib.w().made("write(").len(), 4);
}

/// What the session says of the library: bytes it holds, its context for
/// the application as both objects, and no channel binding.
#[test]
fn the_session_says_what_the_library_has() {
    struct NoNotes;
    impl curl_core::tls::BindingNotes for NoNotes {
        fn info(&mut self, _: core::fmt::Arguments<'_>) {}
        fn fail(&mut self, kind: ErrorKind, _: core::fmt::Arguments<'_>) -> ErrorKind {
            kind
        }
    }
    let (s, lib, _) = connected(World::default());
    assert!(!s.pending());
    lib.w().pending = true;
    assert!(s.pending());
    let native = s.native().expect("made");
    assert_eq!(native.session(), Some(native.context()));
    assert_eq!(s.channel_binding(&mut NoNotes), Ok(None));
}

/// The cipher lists' names the library lacks are said and skipped, as
/// are those named twice, past the library's own; the walk stops once
/// every suite is chosen; a list of TLS 1.3's alone keeps the library's
/// others.
#[test]
fn the_cipher_lists_skip_what_the_library_lacks() {
    let suites = |tls12: Option<&[u8]>, tls13: Option<&[u8]>| {
        let id = identity(|id| {
            id.options.ciphers = tls12.map(<[u8]>::to_vec);
            id.options.tls13_ciphers = tls13.map(<[u8]>::to_vec);
        });
        let lib = Fake::new(World::default());
        let mut s = session(lib, &id, Alpn::None);
        let mut kept = Kept::new();
        let wire = Wire::default();
        let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
            s.handshake(io).map(|shaken| shaken.as_handshake())
        });
        assert_eq!(r, Ok(Handshake::Done), "{:#?}", kept.notes.0);
        let suites = lib.w().suites.clone();
        let said: Vec<_> = kept
            .notes
            .0
            .into_iter()
            .filter(|n| n.contains("cipher in list"))
            .collect();
        (suites, said)
    };
    // Known to the table, not to the library.
    let (got, said) = suites(Some(b"NULL-MD5:ECDHE-RSA-AES128-GCM-SHA256"), None);
    assert_eq!(got, [0x1302, 0x1301, 0xC02F, 0]);
    assert_eq!(
        said,
        ["info: mbedTLS: unknown cipher in list: \"NULL-MD5\""]
    );
    // A default named again is not said; one of the list's named twice
    // is.
    let (_, said) = suites(
        Some(b"TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"),
        None,
    );
    assert_eq!(
        said,
        ["info: mbedTLS: duplicate cipher in list: \"ECDHE-RSA-AES128-GCM-SHA256\""]
    );
    // Every suite chosen, the rest of the list is not read.
    let (got, said) = suites(
        Some(b"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:BOGUS"),
        Some(b"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"),
    );
    assert_eq!(got, [0x1302, 0x1301, 0xC02B, 0xC02F, 0]);
    assert!(said.is_empty(), "{said:?}");
    // TLS 1.3's list alone: the library's others after it.
    let (got, _) = suites(None, Some(b"TLS_AES_256_GCM_SHA384"));
    assert_eq!(got, [0x1302, 0xC02B, 0xC02F, 0]);
}

/// The leaf's text is said line by line, empty lines among them, up to a
/// zero byte; without one, that it could not be.
#[test]
fn the_leaf_is_dumped_line_by_line() {
    let dumped = |info: Option<&'static [u8]>| {
        let chain = crate::fake::FakeChain {
            ders: vec![b"leaf"],
            info,
        };
        let mut notes = curl_core::tls::Notes::default();
        curl_core::tls::TlsCx::testing(&plain(), HOST, &mut notes, |_, cx| {
            crate::verify::dump(cx, &chain);
        });
        notes.0
    };
    assert_eq!(
        dumped(Some(b"a\n\nbc\nd\0e\n")),
        [
            "info: Server certificate:",
            "info: a",
            "info: ",
            "info: bc",
            "info: d"
        ]
    );
    assert_eq!(
        dumped(Some(b"a\nlast")),
        ["info: Server certificate:", "info: a", "info: last"]
    );
    assert_eq!(
        dumped(None),
        ["info: Unable to dump certificate information"]
    );
}

/// A chain of more than a hundred certificates is not reported.
#[test]
fn a_chain_past_a_hundred_is_not_reported() {
    let reported = |n: usize| {
        let chain = crate::fake::FakeChain {
            ders: vec![b"der"; n],
            info: None,
        };
        let mut notes = curl_core::tls::Notes::default();
        curl_core::tls::TlsCx::testing(&plain(), HOST, &mut notes, |_, cx| {
            crate::verify::certinfo(cx, &chain);
        });
        notes.0
    };
    assert_eq!(
        reported(101),
        ["info: More certificates than allowed (100), skipping certinfo"]
    );
    let hundred = reported(100);
    assert!(
        !hundred.iter().any(|n| n.contains("More certificates")),
        "{hundred:#?}"
    );
}

/// What a callback answers the library: a count, the wait it names, or
/// -1.
#[test]
fn a_callback_answers_as_c_s_bio() {
    use crate::library::Moved;
    assert_eq!(Moved::Bytes(5).rc(-7), 5);
    assert_eq!(Moved::Again.rc(-7), -7);
    assert_eq!(Moved::Failed.rc(-7), -1);
}
