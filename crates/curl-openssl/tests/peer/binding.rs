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
    // LibreSSL's server cannot show an Ed25519 certificate, and the forks'
    // clients offer no Ed25519 signature: their handshake fails, as C's
    // build over them fails it, before a binding is asked for.
    #[cfg(not(any(libressl, boringssl_like)))]
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
    security: Some(curl_core::libraries::Security::Gss(&KEEPING)),
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
    let (request, mut steps, got) = negotiated(tag, cert, key);
    assert!(
        request
            .windows(b"Authorization: Negotiate dA==".len())
            .any(|w| w == b"Authorization: Negotiate dA=="),
        "{request:?}"
    );
    assert_eq!(steps.len(), 1, "one step");
    (steps.pop().unwrap(), got)
}

/// The bindings steps were given, in order.
type Steps = Vec<Option<Vec<u8>>>;

/// A Negotiate GET of the server with `cert` and `key`, its peer not
/// verified: what the server was sent, the bindings the steps were given,
/// and what the GET came to.
fn negotiated(tag: &str, cert: X509, key: PKey<Private>) -> (Vec<u8>, Steps, Got) {
    let mut certs = certs(tag, "localhost", &["localhost"]);
    certs.cert = cert;
    certs.key = key;
    // At level 0, a server takes a certificate signed with SHA-1.
    let (at, server) = serve_configured(&certs, false, |a| {
        // The forks have no levels, and take it as it is.
        #[cfg(not(boringssl_like))]
        a.set_security_level(0);
        let _ = a;
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
    let seen = track::untracked(|| std::mem::take(&mut *seen.lock().unwrap()));
    let steps = track::untracked(|| std::mem::take(&mut *BOUND.lock().unwrap()));
    let got = Got {
        result,
        failure: Vec::new(),
        seen,
        chain: None,
        verify: 0,
        early: 0,
    };
    (request, steps, got)
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

/// A certificate for `localhost` signed by Ed25519, with its key: its own
/// key Ed25519 too, or else P-256's under an Ed25519 CA. The forks sign
/// with Ed25519 only given no digest, which the `openssl` crate cannot
/// give: there the `openssl` command makes it.
fn signed_by_ed25519(own_ed25519: bool) -> (X509, PKey<Private>) {
    #[cfg(not(boringssl_like))]
    {
        let signer = PKey::generate_ed25519().unwrap();
        let key = if own_ed25519 { signer.clone() } else { key() };
        let mut cert = X509Builder::new().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(8).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&name("localhost")).unwrap();
        let issuer = if own_ed25519 {
            "localhost"
        } else {
            "curl-openssl test Ed25519 CA"
        };
        cert.set_issuer_name(&name(issuer)).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        cert.sign(&signer, MessageDigest::null()).unwrap();
        (cert.build(), key)
    }
    #[cfg(boringssl_like)]
    track::untracked(|| {
        let dir = certs_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let tag = if own_ed25519 { "ed25519" } else { "mixed" };
        let path = |what: &str| dir.join(format!("{tag}-{what}"));
        let run = |args: &[&std::ffi::OsStr]| {
            let out = std::process::Command::new("openssl")
                .env("OPENSSL_CONF", "/dev/null")
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "{args:?}: {out:?}");
        };
        let (cert, key) = (path("cert.pem"), path("key.pem"));
        let common = ["-subj", "/CN=localhost", "-days", "2", "-nodes"];
        if own_ed25519 {
            let mut args: Vec<&std::ffi::OsStr> = ["req", "-x509", "-newkey", "ed25519"]
                .iter()
                .chain(&common)
                .map(|a| a.as_ref())
                .collect();
            args.extend(["-keyout".as_ref(), key.as_os_str()]);
            args.extend(["-out".as_ref(), cert.as_os_str()]);
            run(&args);
        } else {
            let (ca, ca_key, csr) = (path("ca.pem"), path("ca.key"), path("req.pem"));
            let mut args: Vec<&std::ffi::OsStr> = ["req", "-x509", "-newkey", "ed25519"]
                .iter()
                .chain(&["-subj", "/CN=curl-openssl test Ed25519 CA"])
                .chain(&["-days", "2", "-nodes"])
                .map(|a| a.as_ref())
                .collect();
            args.extend(["-keyout".as_ref(), ca_key.as_os_str()]);
            args.extend(["-out".as_ref(), ca.as_os_str()]);
            run(&args);
            let mut args: Vec<&std::ffi::OsStr> = ["req", "-new", "-newkey", "ec"]
                .iter()
                .chain(&["-pkeyopt", "ec_paramgen_curve:prime256v1"])
                .chain(&common)
                .map(|a| a.as_ref())
                .collect();
            args.extend(["-keyout".as_ref(), key.as_os_str()]);
            args.extend(["-out".as_ref(), csr.as_os_str()]);
            run(&args);
            run(&[
                "x509".as_ref(),
                "-req".as_ref(),
                "-in".as_ref(),
                csr.as_os_str(),
                "-CA".as_ref(),
                ca.as_os_str(),
                "-CAkey".as_ref(),
                ca_key.as_os_str(),
                "-set_serial".as_ref(),
                "8".as_ref(),
                "-days".as_ref(),
                "2".as_ref(),
                "-out".as_ref(),
                cert.as_os_str(),
            ]);
        }
        let cert = X509::from_pem(&std::fs::read(cert).unwrap()).unwrap();
        let key = PKey::private_key_from_pem(&std::fs::read(key).unwrap()).unwrap();
        (cert, key)
    })
}

/// What a certificate signed by Ed25519 comes to: with OpenSSL 3, nothing
/// bound, said so.
#[cfg(ossl3)]
fn binds_nothing(tag: &str, cert: X509, key: PKey<Private>) {
    let (got, ran) = bound(tag, cert, key);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.lines);
    assert_eq!(got, None);
    assert!(said(
        &ran,
        "certificate exposes no signing digest algorithm, nothing to add to channel binding"
    ));
}

/// Without OpenSSL 3, C asks for the digest the signature pairs with,
/// which for Ed25519 is none, and fails the transfer before its request
/// (`ossl_get_channel_binding`'s `#else`).
#[cfg(not(ossl3))]
fn binds_nothing(tag: &str, cert: X509, key: PKey<Private>) {
    let (request, steps, ran) = negotiated(tag, cert, key);
    assert_eq!(
        ran.result,
        Err(ErrorKind::SslInvalidcertstatus),
        "{:#?}",
        ran.seen.lines
    );
    assert!(
        said(&ran, "Could not find digest algorithm UNDEF (NID 0)"),
        "{:#?}",
        ran.seen.lines
    );
    assert!(steps.is_empty(), "{steps:?}");
    assert!(request.is_empty(), "{request:?}");
}

#[cfg(not(any(libressl, boringssl_like)))]
fn an_ed25519_certificate_binds_nothing() {
    let (cert, key) = signed_by_ed25519(true);
    binds_nothing("bind-ed25519", cert, key);
}

/// A certificate whose key is not of its signer's kind, and whose
/// signature names no digest, binds nothing, said so, though its own key
/// has a digest (C's post-quantum case): here a P-256 key signed by
/// Ed25519.
fn a_certificate_signed_by_another_kind_of_key_binds_nothing() {
    let (cert, key) = signed_by_ed25519(false);
    binds_nothing("bind-mixed", cert, key);
}
