use super::*;
use crate::options::{ColdGroup as _, TlsOptions};
use crate::tls::hostcheck::{self, CertName};
use crate::tls::pin::{self, Pin};
use crate::tls::{CaDefaults, ContextHandler, Kept, Notes, TlsOrigin};

fn identity(verify_peer: bool, verify_host: bool, pinned: Option<&[u8]>) -> TryArc<TlsIdentity> {
    let mut options = TlsOptions::NONE;
    options.pinned_key = pinned.map(<[u8]>::to_vec);
    let id = TlsIdentity::for_tests(
        verify_peer,
        verify_host,
        options,
        CaDefaults::NONE,
        TlsOrigin::First,
    );
    TryArc::try_new(id).unwrap()
}

/// Run `f` with a context for a session to `host` made with `id`.
fn with<R>(id: &TryArc<TlsIdentity>, host: &[u8], f: impl FnOnce(&mut TlsCx<'_>) -> R) -> R {
    let mut notes = Notes::default();
    TlsCx::testing(id, host, &mut notes, |_, cx| f(cx))
}

fn not_asked(cx: &TlsCx<'_>) -> Pinned {
    match pin::of(cx) {
        Pin::NotAsked(p) => p,
        Pin::Asked(_) => panic!("nothing pinned"),
    }
}

/// The pin is the identity's: none asks for no key, one asks for the
/// peer's, which must match it.
#[test]
fn the_pin_is_read_from_the_session_s_identity() {
    let id = identity(true, true, None);
    with(&id, b"example.com", |cx| {
        let p = not_asked(cx);
        assert!(!p.matched());
        let c = Checked::new(cx, p, Residuals::NONE).unwrap();
        assert!(!c.pinned());
    });
    // The SHA-256 of `spki`, in base64.
    let spki = b"a key";
    let mut sha = crate::hash::Sha256::default();
    crate::hash::Hash::update(&mut sha, spki);
    let mut hash = b"sha256//".to_vec();
    crate::base64::encode(&crate::hash::Hash::finish(sha), &mut hash).unwrap();
    let id = identity(false, false, Some(&hash));
    with(&id, b"example.com", |cx| {
        let Pin::Asked(ask) = pin::of(cx) else {
            panic!("a key pinned")
        };
        let p = ask.check(cx, spki).unwrap();
        let c = Checked::new(cx, p, Residuals::NONE).unwrap();
        assert!(c.pinned());
        let Pin::Asked(ask) = pin::of(cx) else {
            panic!("a key pinned")
        };
        assert_eq!(
            ask.check(cx, b"another key").unwrap_err(),
            ErrorKind::SslPinnedpubkeynotmatch
        );
    });
}

/// A token made for another session's identity, even an equal one,
/// fails the check closed, said as an internal failure.
#[test]
fn a_token_of_another_session_fails_closed() {
    let other = identity(true, true, None);
    let theirs = with(&other, b"example.com", |cx| {
        (
            not_asked(cx),
            hostcheck::check(cx, CertName::Dns(b"example.com")).unwrap(),
        )
    });
    let ours = identity(true, true, None);
    let mut notes = Notes::default();
    TlsCx::testing(&ours, b"example.com", &mut notes, |_, cx| {
        assert_eq!(
            Checked::new(cx, theirs.0, Residuals::NONE).unwrap_err(),
            ErrorKind::PeerFailedVerification
        );
        let pin = not_asked(cx);
        assert_eq!(
            Checked::named(cx, pin, Some(theirs.1), Residuals::NONE).unwrap_err(),
            ErrorKind::PeerFailedVerification
        );
    });
    assert!(
        notes
            .0
            .iter()
            .any(|n| n
                == "fail: PeerFailedVerification: internal: a pin checked for another session"),
        "{notes:?}"
    );
    assert!(
        notes
            .0
            .iter()
            .any(|n| n
                == "fail: PeerFailedVerification: internal: a name matched for another session"),
        "{notes:?}"
    );
}

/// Where curl-core matches the name, a check without a match fails
/// closed if the name is to be checked, whether the peer is or not; not
/// otherwise.
#[test]
fn a_name_checked_in_core_cannot_be_left_out() {
    for (verify_peer, verify_host) in [(true, true), (false, true), (true, false), (false, false)] {
        let id = identity(verify_peer, verify_host, None);
        with(&id, b"example.com", |cx| {
            let pin = not_asked(cx);
            let r = Checked::named(cx, pin, None, Residuals::NONE);
            assert_eq!(r.is_ok(), !verify_host, "{verify_peer} {verify_host}");
            let pin = not_asked(cx);
            let name = hostcheck::check(cx, CertName::Dns(b"*.com"));
            assert!(name.is_none(), "a wildcard covers no whole domain");
            let name = hostcheck::check(cx, CertName::Dns(b"EXAMPLE.com."));
            assert!(Checked::named(cx, pin, name, Residuals::NONE).is_ok());
        });
    }
}

/// The name matched is the session's peer's: a DNS name or a common name
/// a host's, a wildcard never an address's; an IP address an address's,
/// byte for byte.
#[test]
fn the_name_matched_is_the_session_s_peer_s() {
    let id = identity(true, true, None);
    let matches = |host: &[u8], name: CertName<'_>| {
        with(&id, host, |cx| hostcheck::check(cx, name).is_some())
    };
    assert!(matches(b"www.example.com", CertName::Dns(b"*.example.com")));
    assert!(!matches(
        b"www.example.org",
        CertName::Dns(b"*.example.com")
    ));
    assert!(matches(
        b"example.com",
        CertName::CommonName(b"example.com")
    ));
    assert!(!matches(b"127.0.0.1", CertName::Dns(b"127.0.0.1")));
    assert!(matches(b"127.0.0.1", CertName::Ip(&[127, 0, 0, 1])));
    assert!(!matches(b"127.0.0.1", CertName::Ip(&[127, 0, 0, 2])));
    assert!(!matches(b"127.0.0.1", CertName::CommonName(b"*.0.0.1")));
    assert!(matches(b"127.0.0.1", CertName::CommonName(b"127.0.0.1")));
    let mut one = [0u8; 16];
    one[15] = 1;
    assert!(matches(b"[::1]", CertName::Ip(&one)));
    assert!(!matches(b"[::1]", CertName::Ip(&[0, 0, 0, 1])));
    assert!(!matches(b"example.com", CertName::Ip(&[127, 0, 0, 1])));
}

/// A name checked only with the chain is a residual where the name is
/// to be checked and the peer is not; the application's context handler
/// one whenever it is set.
#[test]
fn residuals_are_kept_where_they_weaken_the_check() {
    for (verify_peer, verify_host) in [(true, true), (false, true), (true, false), (false, false)] {
        let id = identity(verify_peer, verify_host, None);
        with(&id, b"example.com", |cx| {
            let r = Residuals::NONE.host_check_follows_chain(cx);
            assert_eq!(
                r.has(Residual::HostCheckFollowsChain),
                verify_host && !verify_peer
            );
            let pin = not_asked(cx);
            let c = Checked::new(cx, pin, r).unwrap();
            assert!(!c.residuals().has(Residual::AppHadContext));
            assert!(!c.residuals().has(Residual::Testing));
        });
    }
    let id = identity(true, true, None);
    let mut kept = Kept::new();
    kept.context = Some(ContextHandler::default());
    TlsCx::testing_kept(&id, b"example.com", &mut kept, |_, cx| {
        let pin = not_asked(cx);
        let c = Checked::new(cx, pin, Residuals::NONE).unwrap();
        assert!(c.residuals().has(Residual::AppHadContext));
        assert!(Checked::testing(cx).residuals().has(Residual::Testing));
    });
}

/// A check is for the connection whose identity made it, not another
/// whose identity is equal.
#[test]
fn a_check_is_for_its_own_identity() {
    let id = identity(true, true, None);
    let origin = crate::conn::Peer::new(
        crate::proto::http::HTTPS,
        b"example.com".to_vec(),
        443,
        None,
    );
    let mine = SessionPeer::new(&id, &origin, None, &"test", crate::conn::Dial::Stream).unwrap();
    let equal = identity(true, true, None);
    let theirs =
        SessionPeer::new(&equal, &origin, None, &"test", crate::conn::Dial::Stream).unwrap();
    let c = with(&id, b"example.com", |cx| {
        let pin = not_asked(cx);
        Checked::new(cx, pin, Residuals::NONE).unwrap()
    });
    assert!(c.is_for(&mine));
    assert!(!c.is_for(&theirs));
}

/// `test-util`, which makes [`Checked::testing`] public, is enabled by no
/// crate's own dependencies: only for tests.
#[test]
fn test_util_is_enabled_only_for_tests() {
    let crates = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let mut seen = 0;
    for entry in std::fs::read_dir(crates).unwrap() {
        let manifest = entry.unwrap().path().join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        seen += 1;
        let mut section = String::new();
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                section = line.to_owned();
                continue;
            }
            if line.starts_with('#') || !line.contains("test-util") {
                continue;
            }
            let own_feature = section == "[features]" && line.starts_with("test-util");
            let dev = section.ends_with("dev-dependencies]");
            assert!(
                own_feature || dev,
                "{}: {section} {line}",
                manifest.display()
            );
        }
    }
    assert!(seen > 20, "the crates' manifests were read: {seen}");
}
