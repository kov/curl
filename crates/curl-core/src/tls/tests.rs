use super::*;
use crate::options::{CaSetting, ColdGroup as _, SslOptions, TlsMaxVersion, TlsMinVersion};

fn identity(change: impl FnOnce(&mut TlsIdentity)) -> TlsIdentity {
    let mut id = TlsIdentity {
        verify_peer: true,
        verify_host: true,
        options: TlsOptions::NONE,
        ca_defaults: CaDefaults {
            file: Some("/default/ca.pem"),
            path: None,
        },
    };
    change(&mut id);
    id
}

fn text(t: &str) -> Option<Vec<u8>> {
    Some(t.as_bytes().to_vec())
}

/// Two identities match only if every setting does, as
/// `match_ssl_primary_config` compares them: a change to any one makes
/// a connection serve no transfer that has the other.
#[test]
fn every_setting_tells_two_identities_apart() {
    type Change = fn(&mut TlsIdentity);
    let changes: &[(&str, Change)] = &[
        ("verify_peer", |i| i.verify_peer = false),
        ("verify_host", |i| i.verify_host = false),
        ("min_version", |i| {
            i.options.min_version = TlsMinVersion::Tls1_3
        }),
        ("max_version", |i| {
            i.options.max_version = TlsMaxVersion::Default
        }),
        ("ssl_options", |i| {
            i.options.ssl_options = SslOptions::NO_REVOKE
        }),
        ("verify_status", |i| i.options.verify_status = true),
        ("ca_file", |i| i.options.ca_file = CaSetting::Unset),
        ("ca_path", |i| {
            i.options.ca_path = CaSetting::Given(b"/etc/ssl/certs".to_vec());
        }),
        ("ca_blob", |i| i.options.ca_blob = text("pem")),
        ("crl_file", |i| i.options.crl_file = text("crl")),
        ("issuer_cert", |i| i.options.issuer_cert = text("issuer")),
        ("issuer_cert_blob", |i| {
            i.options.issuer_cert_blob = text("i")
        }),
        ("cert", |i| i.options.cert = text("client.crt")),
        ("cert_blob", |i| i.options.cert_blob = text("c")),
        ("cert_type", |i| i.options.cert_type = text("DER")),
        ("key", |i| i.options.key = text("client.key")),
        ("key_blob", |i| i.options.key_blob = text("k")),
        ("key_type", |i| i.options.key_type = text("PEM")),
        ("key_password", |i| i.options.key_password = text("secret")),
        ("ciphers", |i| i.options.ciphers = text("AES128-SHA")),
        ("tls13_ciphers", |i| {
            i.options.tls13_ciphers = text("TLS_AES_128_GCM_SHA256")
        }),
        ("curves", |i| i.options.curves = text("X25519")),
        ("signature_algorithms", |i| {
            i.options.signature_algorithms = text("ed25519");
        }),
        ("pinned_key", |i| {
            i.options.pinned_key = text("sha256//AAAA")
        }),
    ];
    let plain = identity(|_| {});
    assert_eq!(plain, identity(|_| {}));
    for (name, change) in changes {
        let changed = identity(change);
        assert_ne!(plain, changed, "{name}");
        assert_ne!(changed, plain, "{name}");
        assert_eq!(changed, identity(change), "{name}");
    }
}

/// The lists and the formats match in any case (`curl_strequal`); the
/// paths, the keys and the password only exactly (`Curl_safecmp`,
/// `Curl_timestrcmp`).
#[test]
fn lists_match_in_any_case_and_paths_exactly() {
    let lists = identity(|i| {
        i.options.ciphers = text("aes128-sha");
        i.options.tls13_ciphers = text("tls_aes_128_gcm_sha256");
        i.options.curves = text("x25519");
        i.options.signature_algorithms = text("ED25519");
        i.options.cert_type = text("der");
        i.options.key_type = text("pem");
    });
    let shouted = identity(|i| {
        i.options.ciphers = text("AES128-SHA");
        i.options.tls13_ciphers = text("TLS_AES_128_GCM_SHA256");
        i.options.curves = text("X25519");
        i.options.signature_algorithms = text("ed25519");
        i.options.cert_type = text("DER");
        i.options.key_type = text("PEM");
    });
    assert_eq!(lists, shouted);
    let paths = |t: &str| {
        identity(|i| {
            i.options.ca_file = CaSetting::Given(t.as_bytes().to_vec());
            i.options.key = text(t);
        })
    };
    assert_ne!(paths("/certs/ca.pem"), paths("/certs/CA.pem"));
    let password = |t: &str| identity(|i| i.options.key_password = text(t));
    assert_ne!(password("secret"), password("SECRET"));
    assert_ne!(password("secret"), password("secre"));
    assert_eq!(password("secret"), password("secret"));
}

/// The CA file and path compare as they apply: a transfer that names
/// the library's default file matches one that keeps the default, as in
/// C, which copies the default into the setting; one that sets none
/// matches neither. Defaults the library does not have resolve to none.
#[test]
fn the_ca_default_compares_as_the_file_it_names() {
    let kept = identity(|_| {});
    let named = identity(|i| i.options.ca_file = CaSetting::Given(b"/default/ca.pem".to_vec()));
    let none = identity(|i| i.options.ca_file = CaSetting::Unset);
    assert_eq!(kept, named);
    assert_ne!(kept, none);
    assert_ne!(named, none);
    assert_eq!(kept.ca_file(), Some(&b"/default/ca.pem"[..]));
    assert_eq!(none.ca_file(), None);
    // No default path: keeping it is having none.
    let no_path = identity(|i| i.options.ca_path = CaSetting::Unset);
    assert_eq!(kept, no_path);
    assert_eq!(kept.ca_path(), None);
    let other_default = identity(|i| i.ca_defaults.file = Some("/other/ca.pem"));
    assert_ne!(kept, other_default);
}

/// Whether ALPN is offered is the handle's, not the connection's: C
/// matches no connection by it.
#[test]
fn alpn_does_not_tell_identities_apart() {
    assert_eq!(identity(|i| i.options.alpn = false), identity(|_| {}));
}

/// A transfer's identity is its options', copied, so a change to the
/// options after does not change a connection made with it.
#[test]
fn an_identity_copies_the_options() {
    let mut tls = Tls::default();
    tls.options.make_mut().unwrap().ca_blob = text("pem");
    let id = TlsIdentity::of(&tls, CaDefaults::default()).unwrap();
    tls.options.make_mut().unwrap().ca_blob = text("other");
    tls.verify_peer = false;
    assert_eq!(id.options.ca_blob, text("pem"));
    assert!(id.verify_peer);
}

/// A copy of a handle's options (`curl_easy_duphandle`) keeps its TLS
/// settings: the verify bits, the options few transfers set, and each CA
/// setting as it was, named, none or the default.
#[test]
fn a_copy_of_the_options_keeps_the_tls_settings() {
    let mut o = crate::options::Options::default();
    o.tls.verify_peer = false;
    o.tls.verify_host = false;
    let tls = o.tls.options.make_mut().unwrap();
    tls.ca_file = CaSetting::Given(b"/certs/ca.pem".to_vec());
    tls.ca_path = CaSetting::Unset;
    tls.ssl_options = SslOptions::NO_REVOKE;
    tls.key_password = text("secret");
    let copy = o.try_clone().unwrap();
    assert!(!copy.tls.verify_peer);
    assert!(!copy.tls.verify_host);
    assert_eq!(*copy.tls.options, *o.tls.options);
    assert_eq!(
        copy.tls.options.ca_file,
        CaSetting::Given(b"/certs/ca.pem".to_vec())
    );
    assert_eq!(copy.tls.options.ca_path, CaSetting::Unset);
    // One left at the default stays the default.
    let kept = crate::options::Options::default().try_clone().unwrap();
    assert_eq!(kept.tls.options.ca_file, CaSetting::Default);
    assert!(kept.tls.verify_peer && kept.tls.verify_host);
}

/// The bits of `CURLOPT_SSL_OPTIONS` are a set: each one apart from the
/// others and from none, and a set holds what was put in it.
#[test]
fn ssl_options_are_sets() {
    use SslOptions as S;
    let bits = [
        S::ALLOW_BEAST,
        S::NO_REVOKE,
        S::NO_PARTIALCHAIN,
        S::REVOKE_BEST_EFFORT,
        S::NATIVE_CA,
        S::AUTO_CLIENT_CERT,
        S::EARLYDATA,
    ];
    assert!(S::NONE.contains(S::NONE));
    for (i, &a) in bits.iter().enumerate() {
        assert!(a.contains(a), "{i}");
        assert!(a.contains(S::NONE), "{i}");
        assert!(!S::NONE.contains(a), "{i}");
        assert_eq!(a | a, a, "{i}");
        assert_eq!(a | S::NONE, a, "{i}");
        for (j, &b) in bits.iter().enumerate().filter(|&(j, _)| j != i) {
            assert!(!a.contains(b), "{i} {j}");
            let both = a | b;
            assert!(both.contains(a) && both.contains(b), "{i} {j}");
            assert!(!a.contains(both), "{i} {j}");
        }
    }
}

/// The ALPN offer as the handshake puts it on the wire, each name after
/// its length (`Curl_alpn_to_proto_buf`), and as C traces it, the names
/// between commas (`Curl_alpn_to_proto_str`); with ALPN off, none.
#[test]
fn an_alpn_offer_is_put_as_c_puts_it() {
    assert_eq!(Alpn::None.wire(), b"");
    assert_eq!(Alpn::None.offer(), None);
    assert_eq!(Alpn::Http11.wire(), b"\x08http/1.1");
    assert_eq!(Alpn::Http11.offer(), Some("http/1.1"));
    assert_eq!(Alpn::Http10.wire(), b"\x08http/1.0\x08http/1.1");
    assert_eq!(Alpn::Http10.offer(), Some("http/1.0,http/1.1"));
}
