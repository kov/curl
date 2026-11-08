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
    // The engine is built by the system's C compiler as a shared object;
    // LibreSSL has no engines.
    #[cfg(all(unix, ossl3))]
    (
        "an_engine_s_certificate_and_key_serve_the_client",
        an_engine_s_certificate_and_key_serve_the_client,
    ),
];

/// Engines that start but load neither a certificate nor a key: on Linux
/// `afalg` and `loader_attic`, which OpenSSL 3 builds; on macOS
/// `loader_attic` alone, `afalg` being Linux's (`AF_ALG`), and the
/// `padlock` (VIA's x86) and `capi` (Windows') Homebrew also ships
/// failing to start;
/// on Windows the built-in `rdrand`, as vcpkg's OpenSSL has no engine of
/// its own to load.
#[cfg(all(not(any(windows, target_os = "macos")), ossl3))]
const ENGINES_THAT_LOAD_NOTHING: &[&[u8]] = &[b"afalg", b"loader_attic"];
#[cfg(all(target_os = "macos", ossl3))]
const ENGINES_THAT_LOAD_NOTHING: &[&[u8]] = &[b"loader_attic"];
#[cfg(all(windows, ossl3))]
const ENGINES_THAT_LOAD_NOTHING: &[&[u8]] = &[b"rdrand"];

/// What LibreSSL, which has no engines, says of any engine named, as C's
/// build over it says it (53).
#[cfg(not(ossl3))]
fn no_engine(got: &Got) {
    assert_eq!(got.result, Err(ErrorKind::SslEngineNotfound));
    assert_eq!(got.failure, b"OpenSSL engine not found");
}

/// Whether OpenSSL has a configuration file to load: the one
/// `OPENSSL_CONF` names, or the default in its directory. vcpkg's build
/// on Windows has none, and C's build there says so as a provider loads.
#[cfg(ossl3)]
fn a_configuration_loads() -> bool {
    if let Some(file) = std::env::var_os("OPENSSL_CONF") {
        return std::path::Path::new(&file).exists();
    }
    // `OPENSSLDIR: "<dir>"`.
    let dir = openssl::version::dir();
    let dir = dir
        .split_once('"')
        .and_then(|(_, rest)| rest.rsplit_once('"'))
        .map_or("", |(dir, _)| dir);
    std::path::Path::new(dir).join("openssl.cnf").exists()
}

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

/// `afalg` and `loader_attic` start (on macOS `loader_attic` alone), but
/// neither loads a certificate or a key: the certificate is asked for by `LOAD_CERT_CTRL`, which an
/// engine without commands takes as optional and leaves undone, and the
/// key by `ENGINE_load_private_key`, which they lack. Both fail as C's
/// build fails them here, 58. On Windows `rdrand` fails both as C's build
/// there does. Over LibreSSL, naming an engine fails the transfer.
fn an_engine_that_cannot_load_fails_as_c_says() {
    let certs = certs("engineless", "localhost", &["localhost"]);
    let client = client("engineless");
    #[cfg(not(ossl3))]
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
        no_engine(&got);
    }
    #[cfg(ossl3)]
    for &engine in ENGINES_THAT_LOAD_NOTHING {
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
#[cfg(all(unix, ossl3))]
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

/// A transfer naming an engine or a provider, as `with` makes it.
fn with_named(certs: &Certs, engine: &[u8], default: bool) -> Got {
    let (at, server) = serve(certs);
    let engine = engine.to_vec();
    let got = get("localhost", at, |o| {
        trusting(certs)(o);
        let t = o.tls.options.make_mut().unwrap();
        t.engine = Some(engine);
        t.engine_default = default;
    });
    server.join().unwrap();
    got
}

/// LibreSSL has neither engines nor providers: every name fails, the
/// empty and the long ones too, as C's build over it fails them.
#[cfg(not(ossl3))]
fn an_engine_or_provider_that_cannot_be_had_fails_as_c_says() {
    let certs = certs("engines", "localhost", &["localhost"]);
    for (name, default) in [
        (&b"dynamic"[..], false),
        (b"nosuch:prop", false),
        (b":prop", false),
        (&[b'x'; 129][..], false),
        (b"default:provider=nosuch", false),
        (b"default", true),
        (b"default:?provider=default", false),
    ] {
        no_engine(&with_named(&certs, name, default));
    }
}

/// An engine that will not start is 66; a name that is neither an engine
/// nor a provider 53, OpenSSL's error said; a provider with no name, or a
/// name too long, 43 and nothing said. A provider loaded serves the
/// transfer, made the default engine of no engine, as C makes it.
#[cfg(ossl3)]
fn an_engine_or_provider_that_cannot_be_had_fails_as_c_says() {
    let certs = certs("engines", "localhost", &["localhost"]);
    let with = |engine: &[u8], default: bool| with_named(&certs, engine, default);
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
        // The library's configuration loads into the provider's context;
        // where there is none to load, that is said.
        assert_eq!(
            said(&got, "Failed to load default openssl config. Proceeding."),
            !a_configuration_loads(),
            "{:#?}",
            got.seen.lines
        );
    }
}

/// LibreSSL has no provider to read a store with: naming one fails, and a
/// certificate from a store is refused, as C's build over it says.
#[cfg(not(ossl3))]
fn a_provider_s_store_gives_the_client_certificate_and_key() {
    let certs = certs("store", "localhost", &["localhost"]);
    let client = client("store");
    let run = |engine: Option<&[u8]>| {
        let (at, server) = serve_asking(&certs, &client);
        let got = get("localhost", at, |o| {
            trusting(&certs)(o);
            let t = o.tls.options.make_mut().unwrap();
            t.engine = engine.map(<[u8]>::to_vec);
            t.cert = Some(bytes(&client.cert_pem));
            t.cert_type = Some(b"PROV".to_vec());
            t.key = Some(bytes(&client.key_pem));
            t.key_type = Some(b"PROV".to_vec());
        });
        server.join().unwrap();
        got
    };
    no_engine(&run(Some(b"default")));
    let got = run(None);
    assert_eq!(got.result, Err(ErrorKind::SslCertproblem));
    assert_eq!(
        got.failure,
        b"SSL_FILETYPE_PROVIDER not supported for certificate"
    );
}

/// `--cert-type PROV` and `--key-type PROV` with the default provider:
/// both read from its store; a key that is not the certificate's fails,
/// and a certificate from a store with none in it says so.
#[cfg(ossl3)]
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
/// the option. `loader_attic` is an engine every OpenSSL 3 build starts
/// where it can load engines; on Windows, the built-in `rdrand`. Over
/// LibreSSL, which has none, the engine fails the transfer, nothing said.
fn an_engine_made_the_default_is_said() {
    let certs = certs("enginedefault", "localhost", &["localhost"]);
    #[cfg(not(windows))]
    let engine = "loader_attic";
    #[cfg(windows)]
    let engine = "rdrand";
    for default in [true, false] {
        let got = with_named(&certs, engine.as_bytes(), default);
        let line = format!("set default crypto engine '{engine}'");
        #[cfg(ossl3)]
        {
            assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
            assert_eq!(said(&got, &line), default, "{:#?}", got.seen.lines);
        }
        #[cfg(not(ossl3))]
        {
            no_engine(&got);
            assert!(!said(&got, &line), "{:#?}", got.seen.lines);
        }
    }
}

/// `--cert-type PROV` with a PKCS#11 URI and no provider loaded loads
/// `pkcs11`, as C does, whether or not an engine is selected, and opens
/// the URI's store with it: with no token there, that fails, said as C
/// says it. Without it, the failure would be that no provider was set.
/// Where the provider is not installed, as with vcpkg's OpenSSL on
/// Windows, loading it fails, said as C says it there. LibreSSL has no
/// providers: the URI is a certificate type it refuses, and an engine
/// fails the transfer before.
fn a_pkcs11_uri_loads_the_pkcs11_provider_when_none_is_loaded() {
    let certs = certs("pkcs11uri", "localhost", &["localhost"]);
    let client = client("pkcs11uri");
    #[cfg(not(windows))]
    let engine = b"loader_attic";
    #[cfg(windows)]
    let engine = b"rdrand";
    #[cfg(all(not(windows), ossl3))]
    let failed = "Failed to open OpenSSL store: error:";
    #[cfg(all(windows, ossl3))]
    let failed = "Failed to initialize provider: error:";
    for engine in [None, Some(engine.to_vec())] {
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
        #[cfg(not(ossl3))]
        if engine.is_some() {
            no_engine(&got);
            continue;
        }
        assert_eq!(got.result, Err(ErrorKind::SslCertproblem), "{engine:?}");
        let failure = String::from_utf8(got.failure).unwrap();
        #[cfg(not(ossl3))]
        assert_eq!(
            failure,
            "SSL_FILETYPE_PROVIDER not supported for certificate"
        );
        #[cfg(ossl3)]
        assert!(failure.starts_with(failed), "{engine:?}: {failure}");
    }
}
