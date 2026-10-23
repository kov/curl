use super::*;
use crate::options::{CaSetting, ColdGroup as _, SslOptions, TlsMaxVersion, TlsMinVersion};

fn identity(change: impl FnOnce(&mut TlsIdentity)) -> TlsIdentity {
    let mut id = TlsIdentity {
        verify_peer: true,
        verify_host: true,
        options: TlsOptions::NONE,
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
            i.options.min_version = TlsMinVersion::Tls1_2
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
    let id = TlsIdentity::of(&tls).unwrap();
    tls.options.make_mut().unwrap().ca_blob = text("other");
    tls.verify_peer = false;
    assert_eq!(id.options.ca_blob, text("pem"));
    assert!(id.verify_peer);
}
