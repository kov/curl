//! The channel binding a TLS session gives Negotiate over HTTPS
//! (`ossl_get_channel_binding`): `tls-server-end-point:` and the hash of
//! the server's certificate by the digest its signature names, SHA-256
//! for MD5 and SHA-1 (RFC 5929 4.1), and nothing for a signature that
//! names no digest, as Ed25519's does. A GSS-API library of the test's
//! own keeps the binding each step is given.

use super::*;
use curl_core::gss::{
    Flags, Gss, GssContext, GssFailure, GssStatus, Mech, Progress, Step, StepSink, Style, Target,
    TooLong,
};
use curl_core::options::{AuthMethods, HttpAuth};
use openssl::x509::X509Builder;

pub(super) const TESTS: &[(&str, fn())] = &[
    (
        "a_step_is_bound_to_the_certificate_s_hash",
        a_step_is_bound_to_the_certificate_s_hash,
    ),
    (
        "a_certificate_signed_with_sha_1_is_bound_by_sha_256",
        a_certificate_signed_with_sha_1_is_bound_by_sha_256,
    ),
    (
        "an_ed25519_certificate_binds_nothing",
        an_ed25519_certificate_binds_nothing,
    ),
    (
        "a_certificate_signed_by_another_kind_of_key_binds_nothing",
        a_certificate_signed_by_another_kind_of_key_binds_nothing,
    ),
];

/// The bindings the steps were given, in order.
static BOUND: Mutex<Vec<Option<Vec<u8>>>> = Mutex::new(Vec::new());

/// A library whose contexts send one token, `t`, and are then done.
struct Keeping;

impl Gss for Keeping {
    fn context(&self, _: Target<'_>, _: Mech, _: Flags) -> Result<Box<dyn GssContext>, GssFailure> {
        Ok(Box::new(Kept))
    }

    fn describe(&self, _: &GssStatus, _: Style, _: &mut dyn FnMut(&[u8])) -> Result<(), TooLong> {
        Ok(())
    }
}

struct Kept;

impl GssContext for Kept {
    fn step(
        &mut self,
        _: Option<&[u8]>,
        binding: Option<&[u8]>,
        sink: &mut dyn StepSink,
    ) -> Result<Step, GssFailure> {
        track::untracked(|| BOUND.lock().unwrap().push(binding.map(<[u8]>::to_vec)));
        sink.token(b"t").unwrap();
        Ok(Step {
            progress: Progress::Complete,
            confidentiality: false,
            integrity: false,
        })
    }

    fn wrap(
        &mut self,
        _: &[u8],
        _: &mut dyn FnMut(&[u8]) -> Result<(), curl_alloc::OutOfMemory>,
    ) -> Result<(), GssFailure> {
        unreachable!("HTTP wraps nothing")
    }

    fn unwrap(
        &mut self,
        _: &[u8],
        _: &mut dyn FnMut(&[u8]) -> Result<(), curl_alloc::OutOfMemory>,
    ) -> Result<(), GssFailure> {
        unreachable!("HTTP unwraps nothing")
    }

    fn initiator(
        &mut self,
        _: &mut dyn FnMut(&[u8]) -> Result<(), curl_alloc::OutOfMemory>,
    ) -> Result<(), GssFailure> {
        unreachable!("HTTP asks no name")
    }
}

static KEEPING: Keeping = Keeping;

static BINDING_LIBRARIES: Libraries = Libraries {
    tls: Some(Library::Static(&curl_openssl::OPENSSL)),
    gss: Some(&KEEPING),
    ..Libraries::NONE
};

/// A server certificate for `localhost` with `key`, signed by itself
/// with `digest`.
fn self_signed(key: &PKey<Private>, digest: MessageDigest) -> X509 {
    let mut cert = X509Builder::new().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name("localhost")).unwrap();
    cert.set_issuer_name(&name("localhost")).unwrap();
    cert.set_pubkey(key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    cert.sign(key, digest).unwrap();
    cert.build()
}

/// What a Negotiate GET of the server with `cert` and `key` binds its
/// one step to, and what it says, its peer not verified.
fn bound(tag: &str, cert: X509, key: PKey<Private>) -> (Option<Vec<u8>>, Got) {
    let mut certs = certs(tag, "localhost", &["localhost"]);
    certs.cert = cert;
    certs.key = key;
    // At level 0, a server takes a certificate signed with SHA-1.
    let (at, server) = serve_configured(&certs, false, |a| {
        a.set_security_level(0);
    });
    track::untracked(|| BOUND.lock().unwrap().clear());
    let seen = track::untracked(|| Arc::new(Mutex::new(Seen::default())));
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let mut easy = Easy::new();
    easy.set_libraries(SharedLibraries::of_static(&BINDING_LIBRARIES));
    let o = easy.options_mut();
    let url = track::untracked(|| format!("https://localhost:{}/", at.port()));
    o.set_url(Some(url.as_bytes())).unwrap();
    o.ip_version = IpVersion::V4;
    o.output.verbose = true;
    o.tls.verify_peer = false;
    o.tls.verify_host = false;
    o.http.auth = HttpAuth(AuthMethods::NEGOTIATE);
    o.callbacks.debug = Some(Handler::debug(Taker(seen.clone())).unwrap());
    o.callbacks.write = Some(Handler::write(Taker(seen.clone())).unwrap());
    let id = m.add(try_box(easy).unwrap(), (), &mut NoEvents).unwrap();
    let result = curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    m.remove(id, &mut NoEvents).unwrap();
    // Its connection closed, a server sent nothing goes.
    drop(m);
    let request = server.join().unwrap();
    assert!(
        request
            .windows(b"Authorization: Negotiate dA==".len())
            .any(|w| w == b"Authorization: Negotiate dA=="),
        "{request:?}"
    );
    let seen = track::untracked(|| std::mem::take(&mut *seen.lock().unwrap()));
    let mut steps = track::untracked(|| std::mem::take(&mut *BOUND.lock().unwrap()));
    assert_eq!(steps.len(), 1, "one step");
    let got = Got {
        result,
        failure: Vec::new(),
        seen,
        chain: None,
        verify: 0,
    };
    (steps.pop().unwrap(), got)
}

/// `tls-server-end-point:` and the certificate's hash by `digest`.
fn binding(cert: &X509, digest: MessageDigest) -> Vec<u8> {
    [&b"tls-server-end-point:"[..], &cert.digest(digest).unwrap()].concat()
}

fn a_step_is_bound_to_the_certificate_s_hash() {
    for (tag, digest) in [
        ("bind-256", MessageDigest::sha256()),
        ("bind-384", MessageDigest::sha384()),
    ] {
        let key = key();
        let cert = self_signed(&key, digest);
        let want = binding(&cert, digest);
        let (got, ran) = bound(tag, cert, key);
        assert_eq!(ran.result, Ok(()), "{tag}: {:#?}", ran.seen.lines);
        assert_eq!(got, Some(want), "{tag}");
    }
}

/// A certificate for `localhost` signed by itself with SHA-1, made by
/// the `openssl` command, as the library lets no program here sign with
/// it under a system's policy: first with no configuration, then with
/// Red Hat's key that lifts its policy's ban.
fn signed_with_sha_1() -> (X509, PKey<Private>) {
    let dir = certs_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key, conf) = (
        dir.join("sha1.pem"),
        dir.join("sha1.key"),
        dir.join("sha1.cnf"),
    );
    std::fs::write(
        &conf,
        "openssl_conf = c\n[c]\nalg_section = a\n[a]\nrh-allow-sha1-signatures = yes\n",
    )
    .unwrap();
    let mut tried = Vec::new();
    for config in [std::path::Path::new("/dev/null"), &conf] {
        let out = std::process::Command::new("openssl")
            .env("OPENSSL_CONF", config)
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha1"])
            .args(["-subj", "/CN=localhost", "-days", "2", "-keyout"])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .output()
            .unwrap();
        if out.status.success() {
            let cert = X509::from_pem(&std::fs::read(cert).unwrap()).unwrap();
            let key = PKey::private_key_from_pem(&std::fs::read(key).unwrap()).unwrap();
            return (cert, key);
        }
        tried.push(out);
    }
    panic!("no SHA-1 certificate made: {tried:?}")
}

fn a_certificate_signed_with_sha_1_is_bound_by_sha_256() {
    let (cert, key) = track::untracked(signed_with_sha_1);
    assert_eq!(
        cert.signature_algorithm().object().nid(),
        Nid::SHA1WITHRSAENCRYPTION
    );
    let want = binding(&cert, MessageDigest::sha256());
    let (got, ran) = bound("bind-sha1", cert, key);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.lines);
    assert_eq!(got, Some(want));
}

fn an_ed25519_certificate_binds_nothing() {
    let key = PKey::generate_ed25519().unwrap();
    let cert = self_signed(&key, MessageDigest::null());
    let (got, ran) = bound("bind-ed25519", cert, key);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.lines);
    assert_eq!(got, None);
    assert!(said(
        &ran,
        "certificate exposes no signing digest algorithm, nothing to add to channel binding"
    ));
}

/// A certificate whose key is not of its signer's kind, and whose
/// signature names no digest, binds nothing, said so, though its own key
/// has a digest (C's post-quantum case): here a P-256 key signed by
/// Ed25519.
fn a_certificate_signed_by_another_kind_of_key_binds_nothing() {
    let signer = PKey::generate_ed25519().unwrap();
    let key = key();
    let mut cert = X509Builder::new().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(8).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name("localhost")).unwrap();
    cert.set_issuer_name(&name("curl-openssl test Ed25519 CA"))
        .unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    cert.sign(&signer, MessageDigest::null()).unwrap();
    let (got, ran) = bound("bind-mixed", cert.build(), key);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.lines);
    assert_eq!(got, None);
    assert!(said(
        &ran,
        "certificate exposes no signing digest algorithm, nothing to add to channel binding"
    ));
}
