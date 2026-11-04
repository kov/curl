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
    SessionPeer::new(&identity(change), &o, None, &"OpenSSL/3.5.9", Dial::Stream).unwrap()
}

fn key(p: &SessionPeer) -> &str {
    std::str::from_utf8(p.key()).unwrap()
}

/// A path as a key holds it, after its name and length: as given, or on
/// Windows made absolute as `_fullpath` makes it, a drive and
/// backslashes given it.
fn keyed(name: &str, path: &str) -> String {
    #[cfg(windows)]
    let path = std::path::absolute(path).unwrap().display().to_string();
    format!("{name}-{}:{path}", path.len())
}

/// The key of a verified peer with a CA file, as C's build traces it
/// against stunnel (`[SSLS] find peer slot for ...`, the step 43
/// captures).
#[test]
fn a_key_is_c_s_for_the_same_settings() {
    let ca = keyed("CA", CA);
    assert_eq!(
        key(&peer(|_| {})),
        format!("https:localhost:18443:KEY-V3:TLSVER-6-0:{ca}:IMPL-13:OpenSSL/3.5.9:G")
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
    let p = SessionPeer::new(&id, &o, Some(&via), &"OpenSSL/3.5.9", Dial::Stream).unwrap();
    assert_eq!(
        key(&p),
        format!(
            "https:localhost:18443:KEY-V3:NO-VRFY-HOST:CHOST-9:127.0.0.1:CPORT-9:\
             TLSVER-6-0:{ca}:IMPL-13:OpenSSL/3.5.9:G"
        )
    );
    // Verified, the connect-to's peer is not.
    let p = SessionPeer::new(
        &identity(|_| {}),
        &o,
        Some(&via),
        &"OpenSSL/3.5.9",
        Dial::Stream,
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
    let ca = keyed("CA", CA);
    assert_eq!(
        key(&p),
        format!("https:localhost:18443:KEY-V3:QUIC:TLSVER-6-0:{ca}:IMPL-13:OpenSSL/3.5.9:G")
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
    let (ca, ca_path, crl) = (
        keyed("CA", CA),
        keyed("CApath", "/ca/dir"),
        keyed("CRL", "/crl.pem"),
    );
    let issuer = keyed("Issuer", "/issuer.pem");
    let (cert, cert_key) = (keyed("CCERT", "/client.pem"), keyed("KEY", "/client.key"));
    assert_eq!(
        key(&p),
        format!(
            "https:localhost:18443:KEY-V3:VRFY-STATUS:TLSVER-7-7:TLSOPT-3:CIPHER-3:AES:\
             CIPHER13-22:TLS_AES_128_GCM_SHA256:CURVES-6:X25519:SIGALGS-7:ed25519:\
             {ca}:{ca_path}:{crl}:{issuer}:\
             CAInfoBlob-{abc}:CertBlob-{abc}:Pinned-9:sha256//x:{cert}:\
             {cert_key}:CT-3:PEM:KT-3:DER:IMPL-13:OpenSSL/3.5.9:G"
        )
    );
}

/// A relative path is made absolute; one that cannot be is kept as it is
/// and makes the key this directory's alone (`:L`).
#[test]
#[cfg_attr(miri, ignore = "Miri has no realpath")]
fn a_relative_path_is_made_absolute_or_the_key_local() {
    let p = peer(|i| i.options.ca_file = CaSetting::Given(b"no/such/ca.pem".to_vec()));
    // Windows makes a path absolute whether or not it is there.
    #[cfg(unix)]
    {
        assert!(key(&p).contains(":CA-14:no/such/ca.pem:"), "{}", key(&p));
        assert!(key(&p).ends_with(":L"), "{}", key(&p));
    }
    #[cfg(windows)]
    {
        let ca = keyed("CA", "no/such/ca.pem");
        assert!(key(&p).contains(&format!(":{ca}:")), "{}", key(&p));
        assert!(key(&p).ends_with(":G"), "{}", key(&p));
    }
    let p = peer(|i| i.options.ca_file = CaSetting::Given(b"Cargo.toml".to_vec()));
    #[cfg(unix)]
    let abs = std::fs::canonicalize("Cargo.toml").unwrap();
    // `canonicalize` names it in Windows' extended form, `_fullpath` not.
    #[cfg(windows)]
    let abs = std::path::absolute("Cargo.toml").unwrap();
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
    let ca = keyed("CA", "/etc/ssl/certs/ca-certificates.crt");
    assert!(key(&p).contains(&format!(":{ca}:")), "{}", key(&p));
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
        SessionPeer::new(&identity(|_| {}), &o, None, &"OpenSSL/3.5.9", Dial::Stream).unwrap()
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
        let mut p = SessionPeer::new(&id, &o, None, &"X", Dial::Stream).unwrap();
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
    let blob = SessionPeer::new(&blob, &o, None, &"X", Dial::Stream).unwrap();
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

/// C's key for the session in `c_session.txt`, which C's build exported.
const C_KEY: &[u8] = b"https:localhost:28443:KEY-V3:TLSVER-6-0:CA-55:\
/home/kov/Projects/curl/build/c/tests/certs/test-ca.crt:IMPL-13:OpenSSL/3.5.9:G";

/// A line of the file C's `--ssl-sessions` wrote: the salted HMAC of
/// `C_KEY`, and the session.
pub(crate) fn c_made_session() -> (Vec<u8>, Vec<u8>) {
    let line = include_str!("c_session.txt").trim_end();
    let (hmac, session) = line.split_once(':').unwrap();
    let decode = |t: &str| crate::base64::decode(t.as_bytes()).unwrap().unwrap();
    (decode(hmac), decode(session))
}

/// A session of `valid_until`, of `version`, for the import tests.
fn imported(version: u16, valid_until: i64) -> TlsTicket {
    TlsTicket::new(b"ticket".to_vec(), version, None, 0, valid_until)
}

fn say_nothing() -> impl FnMut(fmt::Arguments<'_>) {
    |_| {}
}

/// A peer of `key` with default settings, as the cache looks one up.
fn import_by_key(cache: &mut SessionCache, key: &[u8], s: TlsTicket) {
    cache
        .import(SessionFor::Key(key), s, NOW, &mut say_nothing())
        .unwrap();
}

const NOW: i64 = 1000;

fn no_salt(_: &mut [u8]) -> Result<(), ErrorKind> {
    panic!("no salt wanted");
}

fn exported(cache: &mut SessionCache) -> Exported {
    cache.export(NOW, &mut |b: &mut [u8]| {
        b.fill(7);
        Ok(())
    })
}

/// C's salted HMAC of C's key is what this build's HMAC makes: a connection
/// with C's key finds what C exported, and takes it.
#[test]
fn a_connection_finds_what_c_exported_by_its_key() {
    let (hmac, blob) = c_made_session();
    let mut cache = SessionCache::new(5);
    let s = spack::unpack(&blob).unwrap();
    let mut lines = Vec::new();
    let mut trace = |l: fmt::Arguments<'_>| lines.push(l.to_string());
    cache
        .import(SessionFor::SaltedHmac(&hmac), s, NOW, &mut trace)
        .unwrap();
    assert_eq!(
        lines,
        ["successfully imported ticket for peer without key, now with 1 tickets"]
    );
    lines.clear();
    let mut trace = |l: fmt::Arguments<'_>| lines.push(l.to_string());
    let found = cache.find(C_KEY, Auth::NONE, &mut trace).unwrap();
    assert_eq!(found, Some(0));
    let key = std::str::from_utf8(C_KEY).unwrap();
    assert_eq!(
        lines,
        [
            format!("find peer slot for {key} among 5 slots"),
            format!("peer entry 0 key recovered: {key}"),
        ]
    );
    assert_eq!(cache.peers[0].key.as_deref(), Some(C_KEY));
}

/// A key of anything else, or a connection with a client certificate,
/// finds nothing of an imported peer, which stays without a key.
#[test]
fn another_key_finds_nothing_of_an_imported_peer() {
    let (hmac, blob) = c_made_session();
    let mut cache = SessionCache::new(5);
    let s = spack::unpack(&blob).unwrap();
    cache
        .import(SessionFor::SaltedHmac(&hmac), s, NOW, &mut say_nothing())
        .unwrap();
    let other = cache.find(b"https:other:443:G", Auth::NONE, &mut say_nothing());
    assert_eq!(other.unwrap(), None);
    let with_cert = Auth {
        cert: Some(b"client.pem"),
        ..Auth::NONE
    };
    assert_eq!(
        cache.find(C_KEY, with_cert, &mut say_nothing()).unwrap(),
        None
    );
    assert!(cache.peers[0].key.is_none());
}

/// A peer known only by its salted HMAC holds its slot: the next peer goes
/// beside it, not over it.
#[test]
fn an_imported_peer_is_not_a_free_slot() {
    let mut cache = SessionCache::new(5);
    let both = [3; 64];
    let s = imported(TLS1_3, 0);
    cache
        .import(SessionFor::SaltedHmac(&both), s, NOW, &mut say_nothing())
        .unwrap();
    import_by_key(&mut cache, b"other:G", imported(TLS1_3, 0));
    assert_eq!(cache.peers.len(), 2);
    assert_eq!(cache.peers[0].hmac.unwrap().bytes(), both);
    assert_eq!(cache.peers[0].sessions.len(), 1);
}

/// A salted HMAC of any but 64 bytes is refused; the same one twice is one
/// peer, with two sessions.
#[test]
fn a_salted_hmac_is_64_bytes() {
    let mut cache = SessionCache::new(5);
    for bad in [&[0u8; 63][..], &[0; 65], &[]] {
        let s = imported(TLS1_3, 0);
        let got = cache.import(SessionFor::SaltedHmac(bad), s, NOW, &mut say_nothing());
        assert_eq!(got, Err(ErrorKind::BadFunctionArgument), "{}", bad.len());
    }
    assert!(cache.peers.is_empty());
    for _ in 0..2 {
        let s = imported(TLS1_3, 0);
        cache
            .import(SessionFor::SaltedHmac(&[1; 64]), s, NOW, &mut say_nothing())
            .unwrap();
    }
    assert_eq!(cache.peers.len(), 1);
    assert_eq!(cache.peers[0].sessions.len(), 2);
}

/// An import naming a peer by a salted HMAC of a key the cache knows joins
/// that peer, which takes the salt if it has none, keeps its own if it has.
#[test]
fn a_salted_hmac_of_a_known_key_joins_its_peer() {
    let mut cache = SessionCache::new(5);
    import_by_key(&mut cache, b"known:G", imported(TLS1_3, 0));
    let first = SaltedHmac::of_key([1; 32], b"known:G");
    let s = imported(TLS1_3, 0);
    cache
        .import(
            SessionFor::SaltedHmac(&first.bytes()),
            s,
            NOW,
            &mut say_nothing(),
        )
        .unwrap();
    assert_eq!(cache.peers.len(), 1, "one peer");
    assert_eq!(cache.peers[0].hmac, Some(first), "the salt taken");
    let second = SaltedHmac::of_key([2; 32], b"known:G");
    let s = imported(TLS1_3, 0);
    cache
        .import(
            SessionFor::SaltedHmac(&second.bytes()),
            s,
            NOW,
            &mut say_nothing(),
        )
        .unwrap();
    assert_eq!(cache.peers.len(), 1, "still one");
    assert_eq!(cache.peers[0].hmac, Some(first), "its own kept");
}

/// An import keeps a session as it came, where `put` makes up a lifetime,
/// cuts it, or drops one out of date. What is out of date does not go out.
#[test]
fn an_import_leaves_the_lifetime_alone() {
    let far = NOW + 100 * MOST_13;
    let mut cache = SessionCache::new(5);
    import_by_key(&mut cache, b"far:G", imported(TLS1_3, far));
    assert_eq!(cache.peers[0].sessions[0].valid_until, far);
    import_by_key(&mut cache, b"none:G", imported(TLS1_3, 0));
    assert_eq!(cache.peers[1].sessions[0].valid_until, 0);
    import_by_key(&mut cache, b"old:G", imported(TLS1_3, NOW - 1));
    assert_eq!(cache.peers[2].sessions.len(), 1);
    let out = exported(&mut cache);
    assert_eq!(out.tickets.len(), 2, "out of date, dropped");
    assert!(cache.peers[2].sessions.is_empty());
}

/// Past a peer's two sessions the oldest goes; one not of TLS 1.3 replaces
/// all, as a session a connection made does.
#[test]
fn an_import_keeps_what_a_peer_keeps() {
    let mut cache = SessionCache::new(5);
    for at in [1, 2, 3] {
        import_by_key(&mut cache, b"k:G", imported(TLS1_3, NOW + at));
    }
    let until = |c: &SessionCache| {
        c.peers[0]
            .sessions
            .iter()
            .map(|s| s.valid_until)
            .collect::<Vec<_>>()
    };
    assert_eq!(until(&cache), [NOW + 2, NOW + 3]);
    import_by_key(&mut cache, b"k:G", imported(0x303, NOW + 4));
    assert_eq!(until(&cache), [NOW + 4]);
}

/// A cache of no slot keeps nothing, and is no error.
#[test]
fn a_cache_of_no_slot_keeps_nothing() {
    let mut cache = SessionCache::new(0);
    import_by_key(&mut cache, b"k:G", imported(TLS1_3, 0));
    let s = imported(TLS1_3, 0);
    cache
        .import(SessionFor::SaltedHmac(&[0; 64]), s, NOW, &mut say_nothing())
        .unwrap();
    assert!(cache.peers.is_empty());
    assert!(cache.export(NOW, &mut no_salt).tickets.is_empty());
}

/// What goes out: the key, a salt and the HMAC of the key under it, the
/// session packed and its facts; the salt kept for the next export.
#[test]
fn an_export_says_what_an_import_takes() {
    let mut cache = SessionCache::new(5);
    let early = TlsTicket::new(b"der".to_vec(), TLS1_3, Some(Chosen::H2), 9, NOW + 5);
    import_by_key(&mut cache, b"k:G", early);
    let out = exported(&mut cache);
    assert_eq!((out.peers, out.tickets.len(), out.failed), (1, 1, None));
    let t = out.tickets[0].view();
    assert_eq!(t.key, Some(&b"k:G"[..]));
    assert_eq!(t.salted_hmac[..32], [7; 32]);
    assert_eq!(t.salted_hmac[32..], hmac_sha256(&[7; 32], &[b"k:G"]));
    assert_eq!(
        (t.valid_until, t.version, t.earlydata_max),
        (NOW + 5, TLS1_3, 9)
    );
    assert_eq!(t.alpn, Some(&b"h2"[..]));
    let packed = t.packed.to_vec();
    let salted = *t.salted_hmac;

    let mut other = SessionCache::new(5);
    let s = spack::unpack(&packed).unwrap();
    other
        .import(SessionFor::SaltedHmac(&salted), s, NOW, &mut say_nothing())
        .unwrap();
    let found = other.find(b"k:G", Auth::NONE, &mut say_nothing()).unwrap();
    assert_eq!(found, Some(0), "found by its key");
    assert_eq!(other.peers[0].sessions[0].data, b"der");

    let again = cache.export(NOW, &mut no_salt);
    assert_eq!(
        again.tickets[0].view().salted_hmac,
        &salted,
        "the same salt"
    );
}

/// A peer with a client certificate, a blob as one, a password or a key
/// that holds only here does not go out. A peer imported without a key
/// does, its key none.
#[test]
fn what_is_confidential_or_local_stays() {
    let mut cache = SessionCache::new(9);
    let puts: [&dyn Fn(&mut TlsIdentity); 3] = [
        &|i| i.options.cert = Some(b"/client.pem".to_vec()),
        &|i| i.options.cert_blob = Some(b"blob".to_vec()),
        &|i| i.options.key_password = Some(b"secret".to_vec()),
    ];
    for change in puts {
        let p = peer(|i| change(i));
        cache
            .put(&p, imported(TLS1_3, NOW + 5), NOW, &mut say_nothing())
            .unwrap();
    }
    assert_eq!(cache.peers.len(), 3);
    assert_eq!(exported(&mut cache).tickets.len(), 0);
    import_by_key(&mut cache, b"here:L", imported(TLS1_3, 0));
    import_by_key(&mut cache, b":G", imported(TLS1_3, 0));
    assert_eq!(
        exported(&mut cache).tickets.len(),
        0,
        "`:G` alone is no key"
    );
    let s = imported(TLS1_3, 0);
    cache
        .import(SessionFor::SaltedHmac(&[1; 64]), s, NOW, &mut say_nothing())
        .unwrap();
    import_by_key(&mut cache, b"there:G", imported(TLS1_3, 0));
    let out = exported(&mut cache);
    let keys: Vec<_> = out.tickets.iter().map(|t| t.view().key).collect();
    assert_eq!(keys, [None, Some(&b"there:G"[..])]);
    assert_eq!(out.peers, 2);
}

/// One that will not pack ends the export there, those before it going out.
/// A date before 1970 is a bad argument with nothing said, too large is
/// said.
#[test]
fn an_export_stops_at_what_will_not_pack() {
    let mut cache = SessionCache::new(5);
    let before_1970 = spack::unpack(&[1, 3, 255, 255, 255, 255, 255, 255, 255, 255]).unwrap();
    import_by_key(&mut cache, b"a:G", imported(TLS1_3, 0));
    import_by_key(&mut cache, b"b:G", before_1970);
    import_by_key(&mut cache, b"c:G", imported(TLS1_3, 0));
    let out = exported(&mut cache);
    assert_eq!(out.tickets.len(), 1);
    assert_eq!(
        out.failed,
        Some(ExportStop::Other(ErrorKind::BadFunctionArgument))
    );

    let mut cache = SessionCache::new(5);
    import_by_key(&mut cache, b"a:G", imported(TLS1_3, 0));
    let big = TlsTicket::new(vec![0; 20000], TLS1_3, None, 0, 0);
    import_by_key(&mut cache, b"b:G", big);
    let out = exported(&mut cache);
    assert_eq!(out.tickets.len(), 1);
    assert_eq!(out.failed, Some(ExportStop::Packing(ErrorKind::TooLarge)));
}
