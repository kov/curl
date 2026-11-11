//! Encrypted Client Hello as `init_config_builder_ech` sets it up on the
//! configuration, and the TLS 1.3 it holds the handshake to.

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
    let peer = TlsPeer {
        name: HOST,
        port: 443,
        kind: TlsPeerKind::Name,
        early_data: false,
        ech_configs: record,
    };
    let mut s = Session::new(lib, &id, &peer, Alpn::H2Http11, None).unwrap();
    let mut kept = Kept::new();
    let wire = Wire::with(b"server-hello");
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

/// The calls that set ECH up, and the builder's versions.
fn ech_calls(calls: &[String]) -> Vec<&str> {
    calls
        .iter()
        .map(String::as_str)
        .filter(|c| c.starts_with("ech") || c.starts_with("builder("))
        .collect()
}

/// The lines rustls's ECH said.
fn ech_lines(notes: &[String]) -> Vec<&str> {
    notes
        .iter()
        .map(String::as_str)
        .filter(|n| n.contains("rustls: ECH") || n.contains("ECHConfig"))
        .collect()
}

const BUILDER_13: &str = "builder([1302,1301,c02c,c02f], [0304])";

/// ECH off sets nothing up, and the versions are the transfer's.
#[test]
fn ech_off_sets_nothing_up() {
    let (r, notes, calls) = ech_shake(World::one_round(), Ech::NONE, Some(b"\xfe\x0d"));
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    assert_eq!(
        ech_calls(&calls),
        ["builder([1302,1301,c02c,c02f], [0303,0304])"]
    );
    assert!(ech_lines(&notes).is_empty(), "{notes:#?}");
}

/// GREASE holds the handshake to TLS 1.3 and asks for GREASE, the
/// record not looked at; set up after the client's certificate, before
/// the configuration is built.
#[test]
fn ech_grease_is_asked_for_over_tls_1_3() {
    let (r, notes, calls) = ech_shake(
        World::one_round(),
        ech(EchMode::Grease, None, None),
        Some(b"\xfe\x0d"),
    );
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    assert_eq!(ech_calls(&calls), [BUILDER_13, "ech_grease"]);
    let grease = calls.iter().position(|c| c == "ech_grease").unwrap();
    let build = calls.iter().position(|c| c == "build").unwrap();
    let verifier = calls.iter().position(|c| c == "verifier(webpki)").unwrap();
    assert!(verifier < grease && grease < build, "{calls:#?}");
    assert_eq!(
        ech_lines(&notes),
        ["info: rustls: ECH enabled, forcing TLSv1.3"]
    );
}

/// The forcing comes after the versions are checked: a most of TLS 1.2
/// below a least of 1.3 is refused as C refuses it.
#[test]
fn ech_forces_tls_1_3_after_the_versions_are_checked() {
    let id = identity(|i| {
        i.options.ech = ech(EchMode::Try, Some("QUJD"), None);
        i.options.min_version = TlsMinVersion::Tls1_3;
        i.options.max_version = TlsMaxVersion::Tls1_2;
    });
    let (r, notes, _) = shake(World::one_round(), &id);
    assert_eq!(r, Err(ErrorKind::BadFunctionArgument));
    assert!(ech_lines(&notes).is_empty(), "{notes:#?}");
    // A most of TLS 1.2 alone gives way to it.
    let id = identity(|i| {
        i.options.ech = ech(EchMode::Grease, None, None);
        i.options.max_version = TlsMaxVersion::Tls1_2;
    });
    let (r, _, calls) = shake(World::one_round(), &id);
    assert_eq!(r, Ok(Handshake::Done));
    assert_eq!(ech_calls(&calls), [BUILDER_13, "ech_grease"]);
}

/// The transfer's list is decoded from base64 and given to the library
/// in place of the record's.
#[test]
fn ech_takes_the_transfer_s_list_decoded() {
    for mode in [EchMode::Try, EchMode::Hard] {
        let (r, notes, calls) = ech_shake(
            World::one_round(),
            ech(mode, Some("QUJDRA=="), None),
            Some(b"\x01"),
        );
        assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
        assert_eq!(ech_calls(&calls), [BUILDER_13, "ech(4 bytes)"]);
    }
}

/// Without a list of the transfer's, the record's is given.
#[test]
fn ech_takes_the_record_s_list() {
    let (r, notes, calls) = ech_shake(
        World::one_round(),
        ech(EchMode::Try, None, None),
        Some(b"\xfe\x0d\x00\x01\x02"),
    );
    assert_eq!(r, Ok(Handshake::Done), "{notes:#?}");
    assert_eq!(ech_calls(&calls), [BUILDER_13, "ech(5 bytes)"]);
}

/// What cannot be set up is said, and fails the handshake only where ECH
/// is hard; otherwise the handshake goes on over TLS 1.3 without ECH.
#[test]
fn what_cannot_be_set_up_fails_only_hard_ech() {
    type Case = (
        Option<&'static str>,
        bool,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static [u8]>,
        &'static str,
    );
    // The call refused, GREASE, the list, the outer name, the record, and
    // what is said.
    let cases: [Case; 5] = [
        (
            None,
            false,
            Some("not base64"),
            None,
            None,
            "info: rustls: cannot base64 decode ECHConfig from command line",
        ),
        (
            None,
            false,
            None,
            None,
            None,
            "fail: SslConnectError: rustls: ECH requested but no ECHConfig available",
        ),
        (
            Some("ech"),
            false,
            None,
            None,
            Some(b"\x01"),
            "fail: SslConnectError: rustls: failed to configure ECH: ",
        ),
        (
            None,
            false,
            Some("QUJD"),
            Some("p.example"),
            None,
            "fail: SslConnectError: rustls: ECH outername not supported",
        ),
        (
            Some("ech_grease"),
            true,
            None,
            None,
            None,
            "fail: SslConnectError: rustls: failed to configure ECH GREASE: ",
        ),
    ];
    for (refused, grease, config, name, record, line) in cases {
        let world = || World {
            answers: refused
                .map(|c| (c, Code::InvalidEncryptedClientHelloInvalidConfigList))
                .into_iter()
                .collect(),
            ..World::one_round()
        };
        let modes: &[EchMode] = if grease {
            // GREASE is never hard.
            &[EchMode::Grease]
        } else {
            &[EchMode::Try, EchMode::Hard]
        };
        for &mode in modes {
            let (r, notes, calls) = ech_shake(world(), ech(mode, config, name), record);
            assert!(
                notes.iter().any(|n| n.starts_with(line)),
                "{line}: {notes:#?}"
            );
            assert_eq!(calls[0], BUILDER_13);
            if mode == EchMode::Hard {
                assert_eq!(r, Err(ErrorKind::SslConnectError), "{line}");
                assert!(!calls.iter().any(|c| c == "build"), "{calls:#?}");
            } else {
                assert_eq!(r, Ok(Handshake::Done), "{line}: {notes:#?}");
                assert!(calls.iter().any(|c| c == "connect(example.com)"));
            }
        }
    }
}
