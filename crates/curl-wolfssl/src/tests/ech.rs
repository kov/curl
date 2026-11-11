//! Encrypted Client Hello as `wssl_init_ech` sets it up on the session's
//! object, and the handshake's failure it traces the retry
//! configurations of.

use super::*;
use curl_core::options::{Ech, EchMode};

/// A handshake of a session for `HOST` with `ech`, the origin's HTTPS
/// record holding `record` if any, over `world`'s library.
fn ech_shake(
    world: World,
    ech: Ech,
    record: Option<&[u8]>,
) -> (Result<Handshake, ErrorKind>, Vec<String>, Vec<String>) {
    let id = identity(|i| i.options.ech = ech);
    let lib = Fake::new(world);
    let shared = TlsShared::testing();
    let to = TlsPeer {
        ech_configs: record,
        ..peer(HOST, TlsPeerKind::Name, false)
    };
    let mut s = session_to(lib, &id, &to, Alpn::H2Http11, &shared, None);
    let mut kept = Kept::new();
    let wire = Wire::default();
    let r = with_io(&mut s, &id, &mut kept, &wire, |s, io| {
        s.handshake(io).map(|shaken| shaken.as_handshake())
    });
    let calls = lib.w().calls.clone();
    (r, kept.notes.0, calls)
}

fn ech(mode: EchMode, config: Option<&str>, public_name: Option<&str>) -> Ech {
    Ech {
        mode,
        config: config.map(|c| c.as_bytes().to_vec()),
        public_name: public_name.map(|n| n.as_bytes().to_vec()),
    }
}

/// The ECH lines and calls, in order.
fn ech_lines(notes: &[String]) -> Vec<&str> {
    said(notes, "info: ECH:")
}

/// ECH off sets nothing up.
#[test]
fn ech_off_sets_nothing_up() {
    let (r, notes, calls) = ech_shake(World::default(), Ech::NONE, Some(b"\xfe\x0d"));
    assert_eq!(r, Ok(Handshake::Done));
    assert!(ech_lines(&notes).is_empty(), "{notes:#?}");
    assert!(!calls.iter().any(|c| c.contains("ech")), "{calls:#?}");
}

/// GREASE is the library's own: said, and asked for of nothing.
#[test]
fn ech_grease_is_the_library_s_own() {
    let (r, notes, calls) = ech_shake(World::default(), ech(EchMode::Grease, None, None), None);
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(
        ech_lines(&notes),
        ["info: ECH: GREASE is done by default by wolfSSL: no need to ask"]
    );
    assert!(
        !calls
            .iter()
            .any(|c| c.contains("ech") || c.starts_with("ssl_min"))
    );
}

/// The transfer's list goes to the library in base64, after the handle is
/// set up, and the handshake is held to TLS 1.3; the record's is not
/// looked at.
#[test]
fn ech_takes_the_transfer_s_list_in_base64() {
    for mode in [EchMode::Try, EchMode::Hard] {
        let (r, notes, calls) = ech_shake(
            World::default(),
            ech(mode, Some("QUJD"), None),
            Some(b"\x00"),
        );
        assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
        assert_eq!(
            ech_lines(&notes),
            ["info: ECH: ECHConfig from command line"]
        );
        let set = at(&calls, "ech_configs_base64(QUJD)");
        assert!(at(&calls, "alpn(h2,http/1.1)") < set, "{calls:#?}");
        assert_eq!(calls[set + 1], "ssl_min_version(0x304)", "{calls:#?}");
        assert!(!calls.iter().any(|c| c.starts_with("set_ech_configs")));
    }
}

/// A list the library refuses fails the handshake only where ECH is
/// hard; otherwise it goes on without ECH, at the versions it had.
#[test]
fn a_refused_list_fails_only_hard_ech() {
    let refusing = || World {
        refuse: vec!["ech_configs_base64"],
        ..World::default()
    };
    let (r, notes, calls) = ech_shake(refusing(), ech(EchMode::Try, Some("QUJD"), None), None);
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    assert!(ech_lines(&notes).is_empty(), "{notes:#?}");
    assert!(
        !calls.iter().any(|c| c.starts_with("ssl_min")),
        "{calls:#?}"
    );
    let (r, notes, calls) = ech_shake(refusing(), ech(EchMode::Hard, Some("QUJD"), None), None);
    assert_eq!(r, Err(ErrorKind::SslConnectError), "{notes:#?}");
    assert!(!calls.iter().any(|c| c == "connect"), "{calls:#?}");
}

/// Without a list of the transfer's, the record's is imported, said so
/// with its length.
#[test]
fn ech_takes_the_record_s_list() {
    let (r, notes, calls) = ech_shake(
        World::default(),
        ech(EchMode::Try, None, None),
        Some(b"\xfe\x0d\x00\x01"),
    );
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    assert_eq!(
        ech_lines(&notes),
        [
            "info: ECH: ECHConfig from HTTPS RR",
            "info: ECH: imported ECHConfigList of length 4"
        ]
    );
    let set = at(&calls, "set_ech_configs(4 bytes)");
    assert_eq!(calls[set + 1], "ssl_min_version(0x304)", "{calls:#?}");
}

/// A record's list the library refuses, or none at all, is said, and fails
/// the handshake only where ECH is hard.
#[test]
fn no_list_fails_only_hard_ech() {
    let refusing = || World {
        refuse: vec!["set_ech_configs"],
        ..World::default()
    };
    for (mode, ok) in [(EchMode::Try, true), (EchMode::Hard, false)] {
        let (r, notes, _) = ech_shake(refusing(), ech(mode, None, None), Some(b"\x01"));
        assert_eq!(r.is_ok(), ok, "{mode:?} {notes:#?}");
        assert_eq!(
            ech_lines(&notes),
            [
                "info: ECH: ECHConfig from HTTPS RR",
                "info: ECH: wolfSSL_SetEchConfigs failed"
            ]
        );
        let (r, notes, _) = ech_shake(World::default(), ech(mode, None, None), None);
        assert_eq!(r.is_ok(), ok, "{mode:?} {notes:#?}");
        assert_eq!(
            ech_lines(&notes),
            ["info: ECH: requested but no ECHConfig available"]
        );
    }
}

/// An outer name fails the handshake whatever the mode: wolfSSL cannot
/// set one.
#[test]
fn an_outer_name_fails_the_handshake() {
    for mode in [EchMode::Grease, EchMode::Try, EchMode::Hard] {
        let (r, notes, _) = ech_shake(
            World::default(),
            ech(mode, Some("QUJD"), Some("p.example")),
            None,
        );
        assert_eq!(r, Err(ErrorKind::SslConnectError), "{mode:?}");
        assert_eq!(
            ech_lines(&notes),
            ["info: ECH: outername not supported with wolfSSL"]
        );
    }
}

/// A list taken whose TLS 1.3 cannot be forced fails the handshake.
#[test]
fn ech_fails_where_tls_1_3_cannot_be_forced() {
    let world = World {
        refuse: vec!["ssl_min_version"],
        ..World::default()
    };
    let (r, notes, _) = ech_shake(world, ech(EchMode::Try, Some("QUJD"), None), None);
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(
        has(&notes, "info: ECH: cannot force TLSv1.3 [ERROR]"),
        "{notes:#?}"
    );
}

/// A handshake the library fails with a detail of -1, which ECH's refusal
/// comes to, traces the session's list in base64 in place of the retry
/// configurations and fails as a TLS connect, unsaid; one with no list to
/// give says so.
#[test]
fn a_failure_of_minus_one_traces_the_session_s_list() {
    let failing = |list: Option<Vec<u8>>| World {
        scripts: vec![("connect", vec![Act::Return(-1, -1)])],
        ech_configs: list,
        ..World::default()
    };
    let (r, notes, _) = ech_shake(failing(Some(b"ABC".to_vec())), Ech::NONE, None);
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(
        has(&notes, "info: ECH: (not yet) retry_configs QUJD"),
        "{notes:#?}"
    );
    assert!(!notes.iter().any(|n| n.starts_with("fail:")), "{notes:#?}");
    let (r, notes, _) = ech_shake(failing(None), Ech::NONE, None);
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert!(has(&notes, "info: Failed to get ECHConfigs"), "{notes:#?}");
}
