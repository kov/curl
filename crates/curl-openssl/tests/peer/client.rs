//! Who the client says it is: its certificate and key, in PEM, DER or
//! PKCS#12, from files or memory, with a password, against a server that
//! asks for one signed by a CA of its own (`client_cert`).

use std::path::PathBuf;

use openssl::pkcs12::Pkcs12;
use openssl::ssl::SslVerifyMode;
use openssl::symm::Cipher;

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "a_client_certificate_in_pem_files_is_shown",
        a_client_certificate_in_pem_files_is_shown,
    ),
    (
        "a_client_certificate_in_der_or_in_memory_is_shown",
        a_client_certificate_in_der_or_in_memory_is_shown,
    ),
    (
        "a_pkcs12_file_is_opened_with_its_password",
        a_pkcs12_file_is_opened_with_its_password,
    ),
    (
        "an_encrypted_key_is_read_with_the_password",
        an_encrypted_key_is_read_with_the_password,
    ),
    (
        "no_client_certificate_fails_as_the_server_alerts",
        no_client_certificate_fails_as_the_server_alerts,
    ),
    (
        "a_certificate_or_key_that_cannot_be_used_fails_as_c_says",
        a_certificate_or_key_that_cannot_be_used_fails_as_c_says,
    ),
];

/// The client's credentials, each written to a file of its own.
struct Client {
    /// The certificate, in PEM and DER; the key, in PEM, DER and PEM
    /// encrypted with `secret`; both in one PEM file; a PKCS#12 file
    /// with `secret`.
    cert_pem: PathBuf,
    cert_der: PathBuf,
    key_pem: PathBuf,
    key_der: PathBuf,
    key_enc: PathBuf,
    both: PathBuf,
    p12: PathBuf,
    /// The CA the server checks the client against.
    ca: X509,
}

/// Credentials for a client certificate a CA of their own signed.
fn client(tag: &str) -> Client {
    let made = certs(&format!("{tag}-client"), "client", &[]);
    let dir = certs_dir();
    let write = |name: &str, bytes: &[u8]| {
        let path = dir.join(format!("{tag}-{name}"));
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let cert_pem = made.cert.to_pem().unwrap();
    let key_pem = made.key.private_key_to_pem_pkcs8().unwrap();
    let p12 = Pkcs12::builder()
        .name("client")
        .pkey(&made.key)
        .cert(&made.cert)
        .build2("secret")
        .unwrap();
    Client {
        cert_pem: write("cert.pem", &cert_pem),
        cert_der: write("cert.der", &made.cert.to_der().unwrap()),
        key_pem: write("key.pem", &key_pem),
        key_der: write("key.der", &made.key.private_key_to_der().unwrap()),
        key_enc: write(
            "key.enc.pem",
            &made
                .key
                .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"secret")
                .unwrap(),
        ),
        both: write("both.pem", &[cert_pem.as_slice(), &key_pem].concat()),
        p12: write("cert.p12", &p12.to_der().unwrap()),
        ca: made.ca,
    }
}

/// A server for `certs` that asks for a client certificate the CA of
/// `client` signed, and fails without one.
fn serve_asking(certs: &Certs, client: &Client) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let ca = client.ca.clone();
    serve_configured(certs, false, move |a| {
        a.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        a.cert_store_mut().add_cert(ca).unwrap();
    })
}

fn bytes(path: &std::path::Path) -> Vec<u8> {
    path.to_str().unwrap().as_bytes().to_vec()
}

/// A GET from a server asking for `client`'s certificate, the options as
/// `set` makes them besides the trust in the server's CA.
fn get_as(
    certs: &Certs,
    client: &Client,
    set: impl FnOnce(&mut curl_core::options::TlsOptions),
) -> Got {
    let (at, server) = serve_asking(certs, client);
    let got = get("localhost", at, |o| {
        trusting(certs)(o);
        set(o.tls.options.make_mut().unwrap());
    });
    let request = server.join().unwrap();
    if got.result.is_ok() {
        assert!(request.starts_with(b"GET / HTTP/1.1\r\n"), "{request:?}");
    }
    got
}

/// `--cert` and `--key` (2088): the certificate from a PEM file and the
/// key from another, or both from one, which is then the key's too.
fn a_client_certificate_in_pem_files_is_shown() {
    let certs = certs("mtls-pem", "localhost", &["localhost"]);
    let client = client("mtls-pem");
    let got = get_as(&certs, &client, |t| {
        t.cert = Some(bytes(&client.cert_pem));
        t.key = Some(bytes(&client.key_pem));
    });
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert_eq!(got.seen.body, BODY);
    let got = get_as(&certs, &client, |t| t.cert = Some(bytes(&client.both)));
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
}

/// `--cert-type DER`, `--key-type DER`; and `CURLOPT_SSLCERT_BLOB` with
/// `CURLOPT_SSLKEY_BLOB` (2095), or a blob holding both.
fn a_client_certificate_in_der_or_in_memory_is_shown() {
    let certs = certs("mtls-der", "localhost", &["localhost"]);
    let client = client("mtls-der");
    let got = get_as(&certs, &client, |t| {
        t.cert = Some(bytes(&client.cert_der));
        t.cert_type = Some(b"DER".to_vec());
        t.key = Some(bytes(&client.key_der));
        t.key_type = Some(b"der".to_vec());
    });
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let got = get_as(&certs, &client, |t| {
        t.cert_blob = Some(std::fs::read(&client.cert_pem).unwrap());
        t.key_blob = Some(std::fs::read(&client.key_pem).unwrap());
    });
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let got = get_as(&certs, &client, |t| {
        t.cert_blob = Some(std::fs::read(&client.both).unwrap());
    });
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
}

/// `--cert-type P12` (`pkcs12load`): the file's key and certificate, with
/// the password; a wrong password fails as OpenSSL says.
fn a_pkcs12_file_is_opened_with_its_password() {
    let certs = certs("mtls-p12", "localhost", &["localhost"]);
    let client = client("mtls-p12");
    let got = get_as(&certs, &client, |t| {
        t.cert = Some(bytes(&client.p12));
        t.cert_type = Some(b"P12".to_vec());
        t.key_password = Some(b"secret".to_vec());
    });
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let got = get_as(&certs, &client, |t| {
        t.cert_blob = Some(std::fs::read(&client.p12).unwrap());
        t.cert_type = Some(b"p12".to_vec());
        t.key_password = Some(b"secret".to_vec());
    });
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let got = get_as(&certs, &client, |t| {
        t.cert = Some(bytes(&client.p12));
        t.cert_type = Some(b"P12".to_vec());
        t.key_password = Some(b"wrong".to_vec());
    });
    assert_eq!(got.result, Err(ErrorKind::SslCertproblem));
    let failure = String::from_utf8(got.failure).unwrap();
    assert!(
        failure.starts_with("could not parse PKCS12 file, check password, OpenSSL error error:")
            && failure.ends_with("mac verify failure"),
        "{failure}"
    );
}

/// `--pass` (`passwd_callback`): the key's PEM decrypted with it; with
/// another, the key cannot be set (43, as C).
fn an_encrypted_key_is_read_with_the_password() {
    let certs = certs("mtls-enc", "localhost", &["localhost"]);
    let client = client("mtls-enc");
    let got = get_as(&certs, &client, |t| {
        t.cert = Some(bytes(&client.cert_pem));
        t.key = Some(bytes(&client.key_enc));
        t.key_password = Some(b"secret".to_vec());
    });
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let got = get_as(&certs, &client, |t| {
        t.cert = Some(bytes(&client.cert_pem));
        t.key = Some(bytes(&client.key_enc));
        t.key_password = Some(b"wrong".to_vec());
    });
    assert_eq!(got.result, Err(ErrorKind::BadFunctionArgument));
    assert_eq!(
        got.failure,
        format!(
            "unable to set private key file: '{}' type PEM",
            client.key_enc.display()
        )
        .as_bytes()
    );
}

/// The failures C says, each as it says it: a certificate whose type is
/// wrong or unknown, a key that is not the certificate's, an engine's
/// certificate or a provider's key with none set.
fn a_certificate_or_key_that_cannot_be_used_fails_as_c_says() {
    let certs = certs("mtls-bad", "localhost", &["localhost"]);
    let client = client("mtls-bad");
    let other = self::client("mtls-bad-other");
    type Set<'a> = Box<dyn Fn(&mut curl_core::options::TlsOptions) + 'a>;
    let cases: Vec<(Set<'_>, ErrorKind, String)> = vec![
        (
            Box::new(|t| {
                t.cert = Some(bytes(&client.cert_pem));
                t.key = Some(bytes(&other.key_pem));
            }),
            ErrorKind::BadFunctionArgument,
            format!(
                "unable to set private key file: '{}' type PEM",
                other.key_pem.display()
            ),
        ),
        (
            Box::new(|t| {
                t.cert = Some(bytes(&client.cert_pem));
                t.cert_type = Some(b"FOO".to_vec());
            }),
            ErrorKind::BadFunctionArgument,
            "not supported file type 'FOO' for certificate".into(),
        ),
        (
            Box::new(|t| {
                t.cert = Some(bytes(&client.cert_pem));
                t.key = Some(bytes(&client.key_pem));
                t.key_type = Some(b"FOO".to_vec());
            }),
            ErrorKind::BadFunctionArgument,
            "not supported file type for private key".into(),
        ),
        (
            Box::new(|t| {
                t.cert = Some(bytes(&client.cert_pem));
                t.key = Some(bytes(&client.key_pem));
                t.key_type = Some(b"P12".to_vec());
            }),
            ErrorKind::SslCertproblem,
            "file type P12 for private key not supported".into(),
        ),
        (
            Box::new(|t| {
                t.cert = Some(b"foo".to_vec());
                t.cert_type = Some(b"ENG".to_vec());
            }),
            ErrorKind::SslCertproblem,
            "crypto engine not set, cannot load certificate".into(),
        ),
        (
            Box::new(|t| {
                t.cert = Some(bytes(&client.cert_pem));
                t.key = Some(b"foo".to_vec());
                t.key_type = Some(b"PROV".to_vec());
            }),
            ErrorKind::SslCertproblem,
            "crypto provider not set, cannot load private key".into(),
        ),
        (
            Box::new(|t| t.cert = Some(b"/nonexistent/cert.p12".to_vec())),
            ErrorKind::SslCertproblem,
            "could not load PEM client certificate from /nonexistent/cert.p12, OpenSSL error \
             error:80000002:system library::No such file or directory, (no key found, wrong \
             passphrase, or wrong file format?)"
                .into(),
        ),
    ];
    for (set, kind, failure) in cases {
        let (at, server) = serve_asking(&certs, &client);
        let got = get("localhost", at, |o| {
            trusting(&certs)(o);
            set(o.tls.options.make_mut().unwrap());
        });
        server.join().unwrap();
        assert_eq!(got.result, Err(kind), "{failure}");
        assert_eq!(String::from_utf8(got.failure).unwrap(), failure);
    }
}

/// Without a certificate, the server's alert ends the transfer once the
/// request is sent (TLS 1.3 ends the handshake before the server checks):
/// the failure reads as C's, the library's version before its error, as
/// `ossl_strerror` leaves its buffer.
fn no_client_certificate_fails_as_the_server_alerts() {
    let certs = certs("mtls-none", "localhost", &["localhost"]);
    let client = client("mtls-none");
    let (at, server) = serve_asking(&certs, &client);
    let got = get("localhost", at, trusting(&certs));
    server.join().unwrap();
    let failure = String::from_utf8(got.failure).unwrap();
    let version = openssl::version::version().split(' ').nth(1).unwrap();
    assert_eq!(got.result, Err(ErrorKind::RecvError), "{failure}");
    assert_eq!(
        failure,
        format!(
            "OpenSSL SSL_read: OpenSSL/{version}: error:0A00045C:SSL routines::tlsv13 alert \
             certificate required, errno 0"
        )
    );
}
