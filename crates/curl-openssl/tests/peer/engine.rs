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
];

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
    for (name, default) in [
        (&b"default"[..], true),
        (b"default:?provider=default", false),
    ] {
        let got = with(name, default);
        assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
        assert_eq!(got.seen.body, BODY);
        assert!(!said(&got, "set default crypto engine"));
    }
}

/// `--cert-type PROV` and `--key-type PROV` with the default provider:
/// both read from its store; a key that is not the certificate's fails,
/// and a certificate from a store with none in it says so.
fn a_provider_s_store_gives_the_client_certificate_and_key() {
    let certs = certs("store", "localhost", &["localhost"]);
    let client = client("store");
    let other = self::client("store-other");
    type Set<'a> = Box<dyn Fn(&mut curl_core::options::TlsOptions) + 'a>;
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
