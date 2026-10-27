#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use super::*;
use crate::options::{CaSetting, ColdGroup as _, SslOptions};
use crate::tls::CaDefaults;

const CA: &str = "/home/kov/Projects/curl/build/c/tests/certs/test-ca.cacert";

fn identity(change: impl FnOnce(&mut TlsIdentity)) -> TryArc<TlsIdentity> {
    let mut id = TlsIdentity {
        verify_peer: true,
        verify_host: true,
        options: TlsOptions::NONE,
        ca_defaults: CaDefaults {
            file: Some("/etc/ssl/certs/ca-certificates.crt"),
            path: None,
        },
    };
    id.options.ca_file = CaSetting::Given(CA.as_bytes().to_vec());
    change(&mut id);
    TryArc::try_new(id).unwrap()
}

fn origin(host: &str, port: u16) -> Peer {
    Peer::new(
        crate::proto::http::HTTPS,
        host.as_bytes().to_vec(),
        port,
        None,
    )
}

fn peer(change: impl FnOnce(&mut TlsIdentity)) -> SessionPeer {
    let o = origin("localhost", 18443);
    SessionPeer::new(&identity(change), &o, None, &"OpenSSL/3.5.9", Dial::Tcp).unwrap()
}

fn key(p: &SessionPeer) -> &str {
    std::str::from_utf8(p.key()).unwrap()
}

/// The key of a verified peer with a CA file, as C's build traces it
/// against stunnel (`[SSLS] find peer slot for ...`, the step 43
/// captures).
#[test]
fn a_key_is_c_s_for_the_same_settings() {
    assert_eq!(
        key(&peer(|_| {})),
        format!("https:localhost:18443:KEY-V3:TLSVER-6-0:CA-58:{CA}:IMPL-13:OpenSSL/3.5.9:G")
    );
    // Unverified: no CA, and the verify bits said.
    let p = peer(|i| {
        i.verify_peer = false;
        i.verify_host = false;
    });
    assert_eq!(
        key(&p),
        "https:localhost:18443:KEY-V3:NO-VRFY-PEER:NO-VRFY-HOST:TLSVER-6-0:IMPL-13:OpenSSL/3.5.9:G"
    );
    // Unverified through a connect-to's peer: it is named.
    let id = identity(|i| i.verify_host = false);
    let o = origin("localhost", 18443);
    let via = origin("127.0.0.1", 9);
    let p = SessionPeer::new(&id, &o, Some(&via), &"OpenSSL/3.5.9", Dial::Tcp).unwrap();
    assert_eq!(
        key(&p),
        format!(
            "https:localhost:18443:KEY-V3:NO-VRFY-HOST:CHOST-9:127.0.0.1:CPORT-9:\
             TLSVER-6-0:CA-58:{CA}:IMPL-13:OpenSSL/3.5.9:G"
        )
    );
    // Verified, the connect-to's peer is not.
    let p = SessionPeer::new(
        &identity(|_| {}),
        &o,
        Some(&via),
        &"OpenSSL/3.5.9",
        Dial::Tcp,
    )
    .unwrap();
    assert_eq!(key(&p), key(&peer(|_| {})));
}

/// A session over QUIC is kept apart from one over TCP to the same
/// peer: its key names the transport after the port
/// (`ssl_peer_key_add_transport`).
#[test]
fn a_quic_session_s_key_names_its_transport() {
    let o = origin("localhost", 18443);
    let p = SessionPeer::new(&identity(|_| {}), &o, None, &"OpenSSL/3.5.9", Dial::Quic).unwrap();
    assert_eq!(
        key(&p),
        format!("https:localhost:18443:KEY-V3:QUIC:TLSVER-6-0:CA-58:{CA}:IMPL-13:OpenSSL/3.5.9:G")
    );
}

/// Every setting C's key holds is in it, each text after its length, a
/// blob by its SHA-256, the formats in upper case.
#[test]
fn a_key_holds_every_setting_a_session_must_share() {
    let p = peer(|i| {
        let o = &mut i.options;
        o.verify_status = true;
        o.min_version = crate::options::TlsMinVersion::Tls1_3;
        o.max_version = crate::options::TlsMaxVersion::Tls1_3;
        o.ssl_options = SslOptions::ALLOW_BEAST | SslOptions::NO_REVOKE;
        o.ciphers = Some(b"AES".to_vec());
        o.tls13_ciphers = Some(b"TLS_AES_128_GCM_SHA256".to_vec());
        o.curves = Some(b"X25519".to_vec());
        o.signature_algorithms = Some(b"ed25519".to_vec());
        o.ca_path = CaSetting::Given(b"/ca/dir".to_vec());
        o.crl_file = Some(b"/crl.pem".to_vec());
        o.issuer_cert = Some(b"/issuer.pem".to_vec());
        o.ca_blob = Some(b"abc".to_vec());
        o.cert_blob = Some(b"abc".to_vec());
        o.pinned_key = Some(b"sha256//x".to_vec());
        o.cert = Some(b"/client.pem".to_vec());
        o.key = Some(b"/client.key".to_vec());
        o.cert_type = Some(b"pem".to_vec());
        o.key_type = Some(b"der".to_vec());
    });
    let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(
        key(&p),
        format!(
            "https:localhost:18443:KEY-V3:VRFY-STATUS:TLSVER-7-7:TLSOPT-3:CIPHER-3:AES:\
             CIPHER13-22:TLS_AES_128_GCM_SHA256:CURVES-6:X25519:SIGALGS-7:ed25519:\
             CA-58:{CA}:CApath-7:/ca/dir:CRL-8:/crl.pem:Issuer-11:/issuer.pem:\
             CAInfoBlob-{abc}:CertBlob-{abc}:Pinned-9:sha256//x:CCERT-11:/client.pem:\
             KEY-11:/client.key:CT-3:PEM:KT-3:DER:IMPL-13:OpenSSL/3.5.9:G"
        )
    );
}

/// A relative path is made absolute; one that cannot be is kept as it is
/// and makes the key this directory's alone (`:L`).
#[test]
#[cfg_attr(miri, ignore = "Miri has no realpath")]
fn a_relative_path_is_made_absolute_or_the_key_local() {
    let p = peer(|i| i.options.ca_file = CaSetting::Given(b"no/such/ca.pem".to_vec()));
    assert!(key(&p).contains(":CA-14:no/such/ca.pem:"), "{}", key(&p));
    assert!(key(&p).ends_with(":L"), "{}", key(&p));
    let p = peer(|i| i.options.ca_file = CaSetting::Given(b"Cargo.toml".to_vec()));
    let abs = std::fs::canonicalize("Cargo.toml").unwrap();
    let abs = abs.to_str().unwrap();
    assert!(
        key(&p).contains(&format!(":CA-{}:{abs}:", abs.len())),
        "{}",
        key(&p)
    );
    assert!(key(&p).ends_with(":G"), "{}", key(&p));
}

/// The default CA, which a verified transfer keeps, is the file in its
/// key; a CA set to nothing is no file.
#[test]
fn the_default_ca_is_keyed_as_the_file_it_resolves_to() {
    let p = peer(|i| i.options.ca_file = CaSetting::Default);
    assert!(
        key(&p).contains(":CA-34:/etc/ssl/certs/ca-certificates.crt:"),
        "{}",
        key(&p)
    );
    let p = peer(|i| i.options.ca_file = CaSetting::Unset);
    assert!(!key(&p).contains(":CA-"), "{}", key(&p));
}

/// Two transfers whose settings differ keep their sessions apart: a key
/// holds what tells their settings apart, so neither takes the other's.
#[test]
fn a_session_serves_only_the_settings_it_was_made_with() {
    let mut cache = SessionCache::new(25);
    let mut lines = Vec::new();
    let mut trace = |l: fmt::Arguments<'_>| lines.push(l.to_string());
    let one = peer(|_| {});
    let other = peer(|i| i.options.ciphers = Some(b"AES".to_vec()));
    cache
        .put(&one, ticket(TLS1_3, 0), 1000, &mut trace)
        .unwrap();
    assert!(cache.take(&other, 1000, &mut trace).is_none());
    assert!(cache.take(&one, 1000, &mut trace).is_some());
}

fn ticket(version: u16, valid_until: i64) -> TlsTicket {
    TlsTicket::new(b"der".to_vec(), version, None, 0, valid_until)
}

/// What the cache does is traced as C traces it.
#[test]
fn the_cache_traces_as_c_does() {
    let mut cache = SessionCache::new(25);
    let mut lines = Vec::new();
    let mut trace = |l: fmt::Arguments<'_>| lines.push(l.to_string());
    let p = peer(|_| {});
    let k = key(&p).to_owned();
    assert!(cache.take(&p, 1000, &mut trace).is_none());
    cache
        .put(&p, ticket(TLS1_3, 1000 + 7200), 1000, &mut trace)
        .unwrap();
    cache
        .put(&p, ticket(TLS1_3, 1000 + 7200), 1000, &mut trace)
        .unwrap();
    assert!(cache.take(&p, 1000, &mut trace).is_some());
    assert_eq!(
        lines,
        [
            format!("find peer slot for {k} among 25 slots"),
            format!("peer not found for {k}"),
            format!("no cached session for {k}"),
            format!("find peer slot for {k} among 25 slots"),
            format!("peer not found for {k}"),
            format!(
                "added session for {k} [proto=0x304, valid_secs=7200, alpn=(nil), \
                 earlydata=0, quic_tp=no], peer has 1 sessions now"
            ),
            format!("find peer slot for {k} among 25 slots"),
            format!(
                "added session for {k} [proto=0x304, valid_secs=7200, alpn=(nil), \
                 earlydata=0, quic_tp=no], peer has 2 sessions now"
            ),
            format!("find peer slot for {k} among 25 slots"),
            format!(
                "took session for {k} [proto=0x304, alpn=(nil), earlydata=0, quic_tp=no], \
                 1 sessions remain"
            ),
        ]
    );
}

/// A QUIC session's lines say it keeps its transport parameters.
#[test]
fn a_quic_session_is_traced_with_its_transport_parameters() {
    let mut cache = SessionCache::new(25);
    let mut lines = Vec::new();
    let mut trace = |l: fmt::Arguments<'_>| lines.push(l.to_string());
    let p = peer(|_| {});
    let quic = ticket(TLS1_3, 1000 + 7200).with_quic_params(b"tp".to_vec());
    cache.put(&p, quic, 1000, &mut trace).unwrap();
    assert!(cache.take(&p, 1000, &mut trace).is_some());
    let said: Vec<_> = lines.iter().filter(|l| l.contains("quic_tp=")).collect();
    assert_eq!(said.len(), 2, "{lines:?}");
    assert!(said.iter().all(|l| l.contains("quic_tp=yes]")), "{said:?}");
}

/// A peer keeps two TLS 1.3 tickets, the oldest dropped for a third and
/// taken first; one out of date is dropped as it is found.
#[test]
fn a_peer_keeps_its_two_newest_tickets_while_they_are_good() {
    let mut cache = SessionCache::new(25);
    let mut trace = |_: fmt::Arguments<'_>| {};
    let p = peer(|_| {});
    for until in [2000, 3000, 4000] {
        let mut t = ticket(TLS1_3, until);
        t.earlydata_max = usize::try_from(until).unwrap();
        cache.put(&p, t, 1000, &mut trace).unwrap();
    }
    let first = cache.take(&p, 1000, &mut trace).unwrap();
    assert_eq!(first.earlydata_max, 3000, "the oldest of the two kept");
    cache
        .put(&p, ticket(TLS1_3, 5000), 1000, &mut trace)
        .unwrap();
    // At 4500 the one good until 4000 is out of date.
    let next = cache.take(&p, 4500, &mut trace).unwrap();
    assert_eq!(next.valid_until, 5000);
    assert!(cache.take(&p, 4500, &mut trace).is_none());
}

/// A session before TLS 1.3 replaces every other, and a TLS 1.3 ticket
/// every one before it.
#[test]
fn versions_do_not_mix() {
    let mut cache = SessionCache::new(25);
    let mut trace = |_: fmt::Arguments<'_>| {};
    let p = peer(|_| {});
    cache.put(&p, ticket(TLS1_3, 0), 1000, &mut trace).unwrap();
    cache.put(&p, ticket(TLS1_3, 0), 1000, &mut trace).unwrap();
    cache.put(&p, ticket(0x303, 0), 1000, &mut trace).unwrap();
    assert_eq!(cache.take(&p, 1000, &mut trace).unwrap().version, 0x303);
    assert!(cache.take(&p, 1000, &mut trace).is_none(), "one left");
    cache.put(&p, ticket(0x303, 0), 1000, &mut trace).unwrap();
    cache.put(&p, ticket(TLS1_3, 0), 1000, &mut trace).unwrap();
    assert_eq!(cache.take(&p, 1000, &mut trace).unwrap().version, TLS1_3);
    assert!(
        cache.take(&p, 1000, &mut trace).is_none(),
        "the 1.2 one gone"
    );
}

/// A session with no lifetime lives a day; none lives more than a week
/// for TLS 1.3, a day before it; one out of date already is not kept.
#[test]
fn lifetimes_are_cut_to_the_most_a_version_is_kept() {
    let mut cache = SessionCache::new(25);
    let mut lines = Vec::new();
    let mut trace = |l: fmt::Arguments<'_>| lines.push(l.to_string());
    let p = peer(|_| {});
    let now = 1_000_000;
    cache.put(&p, ticket(TLS1_3, 0), now, &mut trace).unwrap();
    cache
        .put(&p, ticket(TLS1_3, now + 30 * 86400), now, &mut trace)
        .unwrap();
    cache
        .put(&p, ticket(0x303, now + 30 * 86400), now, &mut trace)
        .unwrap();
    cache
        .put(&p, ticket(TLS1_3, now - 1), now, &mut trace)
        .unwrap();
    let valid: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.split("valid_secs=").nth(1))
        .map(|v| v.split(',').next().unwrap())
        .collect();
    assert_eq!(valid, ["86400", "604800", "86400"]);
    assert_eq!(lines.last().unwrap(), "add, session already expired");
}

/// With every slot holding sessions, a new peer takes the slot of the
/// one used least recently; an empty slot goes first.
#[test]
fn a_new_peer_takes_the_least_recently_used_slot() {
    let mut cache = SessionCache::new(3);
    let mut trace = |_: fmt::Arguments<'_>| {};
    let at = |port| {
        let o = origin("localhost", port);
        SessionPeer::new(&identity(|_| {}), &o, None, &"OpenSSL/3.5.9", Dial::Tcp).unwrap()
    };
    let (a, b, c, d) = (at(1), at(2), at(3), at(4));
    for p in [&a, &b, &c] {
        cache.put(p, ticket(0x303, 0), 1000, &mut trace).unwrap();
    }
    // Taken from and given back: `a` and `c` are used, `b` is not.
    for p in [&a, &c] {
        let t = cache.take(p, 1000, &mut trace).unwrap();
        cache.put(p, t, 1000, &mut trace).unwrap();
    }
    cache.put(&d, ticket(0x303, 0), 1000, &mut trace).unwrap();
    assert!(cache.take(&b, 1000, &mut trace).is_none(), "b's slot went");
    for p in [&a, &c, &d] {
        assert!(cache.take(p, 1000, &mut trace).is_some());
    }
    // All empty now: the first empty slot is reused, no fourth made.
    cache.put(&b, ticket(0x303, 0), 1000, &mut trace).unwrap();
    assert_eq!(cache.peers.len(), 3);
}

/// A peer's sessions serve only the client certificate and key password
/// it was added with; one added with a certificate blob serves none, as
/// C names it by its address; a cache of no slot keeps nothing.
#[test]
fn a_session_serves_only_its_client() {
    let mut trace = |_: fmt::Arguments<'_>| {};
    let mut cache = SessionCache::new(25);
    let with = |cert: Option<&str>, password: Option<&str>| {
        let o = origin("localhost", 1);
        let id = identity(|i| {
            i.options.cert = cert.map(|c| c.as_bytes().to_vec());
            i.options.key_password = password.map(|p| p.as_bytes().to_vec());
        });
        let mut p = SessionPeer::new(&id, &o, None, &"X", Dial::Tcp).unwrap();
        // The same key for all, so the client alone tells them apart.
        p.key = b"same".to_vec();
        p
    };
    let plain = with(None, None);
    let cert = with(Some("/c.pem"), Some("pw"));
    cache
        .put(&cert, ticket(0x303, 0), 1000, &mut trace)
        .unwrap();
    assert!(cache.take(&plain, 1000, &mut trace).is_none());
    assert!(
        cache
            .take(&with(Some("/c.pem"), Some("other")), 1000, &mut trace)
            .is_none()
    );
    assert!(
        cache
            .take(&with(Some("/c.pem"), Some("pw")), 1000, &mut trace)
            .is_some()
    );
    let o = origin("localhost", 1);
    let blob = identity(|i| i.options.cert_blob = Some(b"blob".to_vec()));
    let blob = SessionPeer::new(&blob, &o, None, &"X", Dial::Tcp).unwrap();
    cache
        .put(&blob, ticket(0x303, 0), 1000, &mut trace)
        .unwrap();
    assert!(cache.take(&blob, 1000, &mut trace).is_none());
    let mut none = SessionCache::new(0);
    none.put(&plain, ticket(0x303, 0), 1000, &mut trace)
        .unwrap();
    assert!(none.peers.is_empty());
}

/// A peer's sessions are forgotten all at once, as a failed check does.
#[test]
fn every_session_of_a_peer_is_forgotten_at_once() {
    let mut cache = SessionCache::new(25);
    let mut trace = |_: fmt::Arguments<'_>| {};
    let p = peer(|_| {});
    cache.put(&p, ticket(TLS1_3, 0), 1000, &mut trace).unwrap();
    cache.put(&p, ticket(TLS1_3, 0), 1000, &mut trace).unwrap();
    cache.remove_all(&p, &mut trace);
    assert!(cache.take(&p, 1000, &mut trace).is_none());
}
