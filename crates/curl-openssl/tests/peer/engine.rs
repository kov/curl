//! The crypto engine or provider a transfer names (`CURLOPT_SSLENGINE`,
//! `ossl_set_engine`), and the client's certificate and key read from a
//! provider's store (`providerload`, `providercheck`).

use super::client::{bytes, client, serve_asking};
use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "an_engine_or_provider_that_cannot_be_had_fails_as_c_says",
        an_engine_or_provider_that_cannot_be_had_fails_as_c_says,
    ),
    (
        "a_provider_s_store_gives_the_client_certificate_and_key",
        a_provider_s_store_gives_the_client_certificate_and_key,
    ),
    (
        "an_engine_made_the_default_is_said",
        an_engine_made_the_default_is_said,
    ),
    (
        "a_pkcs11_uri_loads_the_pkcs11_provider_when_none_is_loaded",
        a_pkcs11_uri_loads_the_pkcs11_provider_when_none_is_loaded,
    ),
    (
        "an_engine_that_cannot_load_fails_as_c_says",
        an_engine_that_cannot_load_fails_as_c_says,
    ),
    (
        "an_engine_s_certificate_and_key_serve_the_client",
        an_engine_s_certificate_and_key_serve_the_client,
    ),
];

/// Set in the child `an_engine_s_certificate_and_key_serve_the_client`
/// runs, which runs `engine_child` alone; OpenSSL looks for engines it
/// does not have in `OPENSSL_ENGINES`, read as each is looked for.
pub(crate) const CHILD: &str = "CURL_OPENSSL_PEER_ENGINE_CHILD";

type Set<'a> = Box<dyn Fn(&mut curl_core::options::TlsOptions) + 'a>;

/// A GET from a server asking for `client`'s certificate, with the
/// engine `engine` selected and the options `set` makes.
fn with_engine(certs: &Certs, client: &client::Client, engine: &[u8], set: Set<'_>) -> Got {
    let (at, server) = serve_asking(certs, client);
    let got = get("localhost", at, |o| {
        trusting(certs)(o);
        let t = o.tls.options.make_mut().unwrap();
        t.engine = Some(engine.to_vec());
        set(t);
    });
    server.join().unwrap();
    got
}

/// `afalg` and `loader_attic` start, but neither loads a certificate or
/// a key: the certificate is asked for by `LOAD_CERT_CTRL`, which an
/// engine without commands takes as optional and leaves undone, and the
/// key by `ENGINE_load_private_key`, which they lack. Both fail as C's
/// build fails them here, 58.
fn an_engine_that_cannot_load_fails_as_c_says() {
    let certs = certs("engineless", "localhost", &["localhost"]);
    let client = client("engineless");
    for engine in [&b"afalg"[..], b"loader_attic"] {
        let got = with_engine(
            &certs,
            &client,
            engine,
            Box::new(|t| {
                t.cert = Some(bytes(&client.cert_pem));
                t.cert_type = Some(b"ENG".to_vec());
            }),
        );
        assert_eq!(got.result, Err(ErrorKind::SslCertproblem));
        assert_eq!(
            String::from_utf8(got.failure).unwrap(),
            "SSL engine did not initialize the certificate properly."
        );
        let got = with_engine(
            &certs,
            &client,
            engine,
            Box::new(|t| {
                t.cert = Some(bytes(&client.cert_pem));
                t.key = Some(bytes(&client.key_pem));
                t.key_type = Some(b"ENG".to_vec());
            }),
        );
        assert_eq!(got.result, Err(ErrorKind::SslCertproblem));
        assert_eq!(
            String::from_utf8(got.failure).unwrap(),
            "failed to load private key from crypto engine"
        );
    }
}

/// `curltest_engine.c`, an engine of the kind C's path is for (libp11's
/// pkcs11 is one): built here, and found by OpenSSL by its name, in a
/// child with `OPENSSL_ENGINES` naming where it is.
fn an_engine_s_certificate_and_key_serve_the_client() {
    track::untracked(|| {
        let dir = certs_dir().join("engines");
        std::fs::create_dir_all(&dir).unwrap();
        let source = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/peer/curltest_engine.c");
        let built = std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(dir.join("curltest.so"))
            .arg(source)
            .arg("-lcrypto")
            .status()
            .unwrap();
        assert!(built.success(), "cc: {built}");
        let ran = std::process::Command::new(std::env::current_exe().unwrap())
            .env("OPENSSL_ENGINES", &dir)
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            ran.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
        assert_eq!(ran.stdout, b"engine_child ... ok\n");
    });
}

/// The child's run: the certificate and key from `curltest`, the key's
/// password given to the engine's prompt for the default one, as C's
/// build does with the same engine.
pub(crate) fn engine_child() {
    let certs = certs("engine", "localhost", &["localhost"]);
    let client = client("engine");
    let cert = bytes(&client.cert_pem);
    let key = bytes(&client.key_pem);
    let eng = |t: &mut curl_core::options::TlsOptions, cert: &[u8], key: &[u8]| {
        t.cert = Some(cert.to_vec());
        t.cert_type = Some(b"ENG".to_vec());
        t.key = Some(key.to_vec());
        t.key_type = Some(b"ENG".to_vec());
    };
    let got = with_engine(
        &certs,
        &client,
        b"curltest",
        Box::new(|t| eng(t, &cert, &key)),
    );
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert_eq!(got.seen.body, BODY);
    // The certificate alone of the engine, the key a file.
    let got = with_engine(
        &certs,
        &client,
        b"curltest",
        Box::new(|t| {
            eng(t, &cert, &key);
            t.key_type = None;
        }),
    );
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    // An encrypted key, its password given or wrong.
    let enc = bytes(&client.key_enc);
    for (password, ok) in [(&b"secret"[..], true), (b"wrong", false)] {
        let got = with_engine(
            &certs,
            &client,
            b"curltest",
            Box::new(|t| {
                eng(t, &cert, &enc);
                t.key_password = Some(password.to_vec());
            }),
        );
        if ok {
            assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
        } else {
            assert_eq!(got.result, Err(ErrorKind::SslCertproblem));
            assert_eq!(
                got.failure,
                b"failed to load private key from crypto engine"
            );
        }
    }
    // A certificate the engine cannot find, its error said.
    let got = with_engine(
        &certs,
        &client,
        b"curltest",
        Box::new(|t| eng(t, b"/nonexistent/cert", &key)),
    );
    assert_eq!(got.result, Err(ErrorKind::SslCertproblem));
    assert_eq!(
        String::from_utf8(got.failure).unwrap(),
        "SSL engine cannot load client cert with id '/nonexistent/cert' \
         [error:80000002:system library::No such file or directory]"
    );
    // A key that is not the certificate's, which OpenSSL will not set.
    let other = self::client("engine-other");
    let got = with_engine(
        &certs,
        &client,
        b"curltest",
        Box::new(|t| eng(t, &cert, &bytes(&other.key_pem))),
    );
    assert_eq!(got.result, Err(ErrorKind::SslCertproblem));
    assert_eq!(got.failure, b"unable to set private key");
}

/// An engine that will not start is 66; a name that is neither an engine
/// nor a provider 53, OpenSSL's error said; a provider with no name, or a
/// name too long, 43 and nothing said. A provider loaded serves the
/// transfer, made the default engine of no engine, as C makes it.
fn an_engine_or_provider_that_cannot_be_had_fails_as_c_says() {
    let certs = certs("engines", "localhost", &["localhost"]);
    let with = |engine: &[u8], default: bool| {
        let (at, server) = serve(&certs);
        let engine = engine.to_vec();
        let got = get("localhost", at, |o| {
            trusting(&certs)(o);
            let t = o.tls.options.make_mut().unwrap();
            t.engine = Some(engine);
            t.engine_default = default;
        });
        server.join().unwrap();
        got
    };
    let got = with(b"dynamic", false);
    assert_eq!(got.result, Err(ErrorKind::SslEngineInitfailed));
    let failure = String::from_utf8(got.failure).unwrap();
    assert!(
        failure.starts_with("Failed to initialize SSL Engine 'dynamic': error:"),
        "{failure}"
    );
    let got = with(b"nosuch:prop", false);
    assert_eq!(got.result, Err(ErrorKind::SslEngineNotfound));
    let failure = String::from_utf8(got.failure).unwrap();
    assert!(
        failure.starts_with("Failed to initialize provider: error:"),
        "{failure}"
    );
    for name in [&b":prop"[..], &[b'x'; 129]] {
        let got = with(name, false);
        assert_eq!(got.result, Err(ErrorKind::BadFunctionArgument));
        assert_eq!(got.failure, b"");
    }
    // `MAX_PROVIDER_LEN` is the longest name looked for.
    let got = with(&[b'x'; 128], false);
    assert_eq!(got.result, Err(ErrorKind::SslEngineNotfound));
    // The properties after the colon are the context's: a provider they
    // name that cannot be had fails it, as C says it (27).
    let got = with(b"default:provider=nosuch", false);
    assert_eq!(got.result, Err(ErrorKind::OutOfMemory));
    let failure = String::from_utf8(got.failure).unwrap();
    assert!(
        failure.starts_with("SSL: could not create a context: error:"),
        "{failure}"
    );
    for (name, default) in [
        (&b"default"[..], true),
        (b"default:?provider=default", false),
    ] {
        let got = with(name, default);
        assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
        assert_eq!(got.seen.body, BODY);
        assert!(!said(&got, "set default crypto engine"));
        // The library's configuration loads into the provider's context.
        assert!(!said(
            &got,
            "Failed to load default openssl config. Proceeding."
        ));
    }
}

/// `--cert-type PROV` and `--key-type PROV` with the default provider:
/// both read from its store; a key that is not the certificate's fails,
/// and a certificate from a store with none in it says so.
fn a_provider_s_store_gives_the_client_certificate_and_key() {
    let certs = certs("store", "localhost", &["localhost"]);
    let client = client("store");
    let other = self::client("store-other");
    let from_store = |cert: &std::path::Path, key: &std::path::Path| -> Set<'_> {
        let (cert, key) = (bytes(cert), bytes(key));
        Box::new(move |t| {
            t.engine = Some(b"default".to_vec());
            t.cert = Some(cert.clone());
            t.cert_type = Some(b"PROV".to_vec());
            t.key = Some(key.clone());
            t.key_type = Some(b"PROV".to_vec());
        })
    };
    let run = |set: Set<'_>| {
        let (at, server) = serve_asking(&certs, &client);
        let got = get("localhost", at, |o| {
            trusting(&certs)(o);
            set(o.tls.options.make_mut().unwrap());
        });
        server.join().unwrap();
        got
    };
    let got = run(from_store(&client.cert_pem, &client.key_pem));
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert_eq!(got.seen.body, BODY);

    let got = run(from_store(&client.cert_pem, &other.key_pem));
    assert_eq!(got.result, Err(ErrorKind::SslCertproblem));
    let failure = String::from_utf8(got.failure).unwrap();
    // The earliest error queued, as C says it: here the one left by
    // looking for an engine named `default`, as C's build says too.
    assert!(
        failure.starts_with("unable to set private key [error:"),
        "{failure}"
    );

    let got = run(from_store(&client.key_pem, &client.key_pem));
    assert_eq!(got.result, Err(ErrorKind::SslCertproblem));
    let failure = String::from_utf8(got.failure).unwrap();
    assert!(
        failure.starts_with("No cert found in the openssl store: "),
        "{failure}"
    );

    // Without a provider loaded, as C says.
    let got = run(Box::new(|t| {
        t.cert = Some(bytes(&client.cert_pem));
        t.cert_type = Some(b"PROV".to_vec());
    }));
    assert_eq!(got.result, Err(ErrorKind::SslCertproblem));
    assert_eq!(
        got.failure,
        b"crypto provider not set, cannot load certificate"
    );
}

/// `CURLOPT_SSLENGINE_DEFAULT`: the engine selected is made the default
/// for every algorithm, said (`ossl_set_engine_default`); not without
/// the option. `loader_attic` is an engine every OpenSSL 3 build starts.
fn an_engine_made_the_default_is_said() {
    let certs = certs("enginedefault", "localhost", &["localhost"]);
    for default in [true, false] {
        let (at, server) = serve(&certs);
        let got = get("localhost", at, |o| {
            trusting(&certs)(o);
            let t = o.tls.options.make_mut().unwrap();
            t.engine = Some(b"loader_attic".to_vec());
            t.engine_default = default;
        });
        server.join().unwrap();
        assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
        assert_eq!(
            said(&got, "set default crypto engine 'loader_attic'"),
            default,
            "{:#?}",
            got.seen.lines
        );
    }
}

/// `--cert-type PROV` with a PKCS#11 URI and no provider loaded loads
/// `pkcs11`, as C does, whether or not an engine is selected, and opens
/// the URI's store with it: with no token there, that fails, said as C
/// says it. Without it, the failure would be that no provider was set.
fn a_pkcs11_uri_loads_the_pkcs11_provider_when_none_is_loaded() {
    let certs = certs("pkcs11uri", "localhost", &["localhost"]);
    let client = client("pkcs11uri");
    for engine in [None, Some(b"loader_attic".to_vec())] {
        let (at, server) = serve_asking(&certs, &client);
        let got = get("localhost", at, |o| {
            trusting(&certs)(o);
            let t = o.tls.options.make_mut().unwrap();
            t.engine = engine.clone();
            t.cert = Some(b"pkcs11:object=nosuch".to_vec());
            t.cert_type = Some(b"PROV".to_vec());
            t.key = Some(bytes(&client.key_pem));
        });
        server.join().unwrap();
        assert_eq!(got.result, Err(ErrorKind::SslCertproblem), "{engine:?}");
        let failure = String::from_utf8(got.failure).unwrap();
        assert!(
            failure.starts_with("Failed to open OpenSSL store: error:"),
            "{engine:?}: {failure}"
        );
    }
}
