//! The peer's chain as a transfer that asks reports it (`CURLOPT_CERTINFO`,
//! `ossl_certchain`): each field worded as C words it.

use openssl::dh::Dh;
use openssl::dsa::Dsa;
use openssl::rsa::Rsa;

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "the_chain_is_reported_as_c_words_it_when_asked",
        the_chain_is_reported_as_c_words_it_when_asked,
    ),
    (
        "a_chain_of_c_s_hundred_is_reported_and_a_longer_one_fails",
        a_chain_of_c_s_hundred_is_reported_and_a_longer_one_fails,
    ),
];

/// A self-signed RSA certificate for `localhost`, serial 2.
fn rsa_certs(tag: &str) -> Certs {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name("localhost")).unwrap();
    cert.set_issuer_name(&name("localhost")).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    let mut san = SubjectAlternativeName::new();
    san.dns("localhost");
    let san = san.build(&cert.x509v3_context(None, None)).unwrap();
    cert.append_extension(san).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = cert.build();
    let ca_file = certs_dir().join(format!("{tag}-ca.pem"));
    std::fs::create_dir_all(certs_dir()).unwrap();
    std::fs::write(&ca_file, cert.to_pem().unwrap()).unwrap();
    Certs {
        ca_file,
        cert: cert.clone(),
        key: key.clone(),
        ca: cert,
        ca_key: key,
    }
}

/// The lines C gives an RSA certificate (`ossl_certchain`,
/// `get_pkey_rsa`).
fn expected(cert: &X509, key: &PKey<Private>) -> Vec<Vec<u8>> {
    let rsa = key.rsa().unwrap();
    let signature = cert
        .signature()
        .as_slice()
        .iter()
        .map(|b| format!("{b:02x}:"))
        .collect::<String>();
    let text = [
        "Subject:CN = localhost".to_owned(),
        "Issuer:CN = localhost".to_owned(),
        "Version:2".to_owned(),
        "Serial Number:02".to_owned(),
        "Signature Algorithm:sha256WithRSAEncryption".to_owned(),
        "Public Key Algorithm:rsaEncryption".to_owned(),
        "X509v3 Subject Alternative Name:DNS:localhost".to_owned(),
        format!("Start date:{}", cert.not_before()),
        format!("Expire date:{}", cert.not_after()),
        "RSA Public Key:2048".to_owned(),
        // `BN_print`'s hex has no leading zeros.
        format!(
            "rsa(n):{}",
            rsa.n().to_hex_str().unwrap().trim_start_matches('0')
        ),
        format!(
            "rsa(e):{}",
            rsa.e().to_hex_str().unwrap().trim_start_matches('0')
        ),
        format!("Signature:{signature}"),
        format!(
            "Cert:{}",
            String::from_utf8(cert.to_pem().unwrap()).unwrap()
        ),
    ];
    text.into_iter().map(String::into_bytes).collect()
}

/// `CURLOPT_CERTINFO` (3102, 417): the peer's certificate, its fields
/// each a line as C words it; nothing reported for a transfer that did
/// not ask; a peer that fails to verify reported all the same, its chain
/// read first, as C reads it.
fn the_chain_is_reported_as_c_words_it_when_asked() {
    let certs = rsa_certs("chain");
    let (at, server) = serve(&certs);
    let got = get("localhost", at, |o| {
        trusting(&certs)(o);
        o.tls.certinfo = true;
    });
    server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let chain = got.chain.expect("a chain reported");
    assert_eq!(chain.len(), 1);
    let want = expected(&certs.cert, &certs.key);
    for (got, want) in chain[0].iter().zip(&want) {
        assert_eq!(String::from_utf8_lossy(got), String::from_utf8_lossy(want));
    }
    assert_eq!(chain[0].len(), want.len());

    let (at, server) = serve(&certs);
    let got = get("localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(got.result, Ok(()));
    assert_eq!(got.chain, None);

    // A peer that fails its check has had its chain reported already.
    let (at, server) = serve(&certs);
    let got = get("localhost", at, |o| o.tls.certinfo = true);
    server.join().unwrap();
    assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(got.chain.map(|c| c.len()), Some(1));
}

/// A certificate for `key`, named `cn`, that the CA of `certs` signed.
fn extra<T: openssl::pkey::HasPublic>(certs: &Certs, cn: &str, serial: u32, key: &PKey<T>) -> X509 {
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name(cn)).unwrap();
    cert.set_issuer_name(certs.ca.subject_name()).unwrap();
    cert.set_pubkey(key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    cert.sign(&certs.ca_key, MessageDigest::sha256()).unwrap();
    cert.build()
}

/// `BN_print`'s hex: no leading zeros.
fn bn(n: &openssl::bn::BigNumRef) -> String {
    n.to_hex_str().unwrap().trim_start_matches('0').to_owned()
}

/// The lines of a certificate's key in the chain, `dsa(p)` and the like.
fn key_lines(cert: &[Vec<u8>], kind: &str) -> Vec<String> {
    cert.iter()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .filter(|l| l.starts_with(&format!("{kind}(")))
        .collect()
}

/// `MAX_ALLOWED_CERT_AMOUNT`: a chain of 100 certificates is reported
/// whole, a DSA and a DH key among them said by their numbers
/// (`get_pkey_dsa`, `get_pkey_dh`); one of 101 fails the handshake with
/// 35, said as C says it.
fn a_chain_of_c_s_hundred_is_reported_and_a_longer_one_fails() {
    let certs = super::certs("hundred", "localhost", &["localhost"]);
    let dsa = PKey::from_dsa(Dsa::generate(2048).unwrap()).unwrap();
    // PKCS#3 parameters of its own: a group the library knows (RFC 5114's,
    // RFC 7919's) makes the key X9.42's (`EVP_PKEY_DHX`), which C does not
    // name.
    let dh = Dh::generate_params(512, 2).unwrap();
    let dh = PKey::from_dh(dh.generate_key().unwrap()).unwrap();
    let ec = key();
    let mut extras = vec![extra(&certs, "dsa", 10, &dsa), extra(&certs, "dh", 11, &dh)];
    for i in 0..97 {
        extras.push(extra(&certs, &format!("extra {i}"), 100 + i, &ec));
    }
    let with = |extras: Vec<X509>| {
        let (at, server) = serve_configured(&certs, false, move |a| {
            // The DH key's 512 bits pass the server's checks of its chain.
            a.set_security_level(0);
            for x in extras {
                a.add_extra_chain_cert(x).unwrap();
            }
        });
        let got = get("localhost", at, |o| {
            trusting(&certs)(o);
            o.tls.certinfo = true;
        });
        server.join().unwrap();
        got
    };
    let got = with(extras.clone());
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let chain = got.chain.expect("a chain reported");
    assert_eq!(chain.len(), 100);
    let dsa = dsa.dsa().unwrap();
    assert_eq!(
        key_lines(&chain[1], "dsa"),
        [
            format!("dsa(p):{}", bn(dsa.p())),
            format!("dsa(q):{}", bn(dsa.q())),
            format!("dsa(g):{}", bn(dsa.g())),
            format!("dsa(pub_key):{}", bn(dsa.pub_key())),
        ]
    );
    let dh = dh.dh().unwrap();
    let q = dh.prime_q().map(bn).unwrap_or_default();
    assert_eq!(
        key_lines(&chain[2], "dh"),
        [
            format!("dh(p):{}", bn(dh.prime_p())),
            format!("dh(q):{q}"),
            format!("dh(g):{}", bn(dh.generator())),
            format!("dh(pub_key):{}", bn(dh.public_key())),
        ]
    );
    extras.push(extra(&certs, "one more", 99, &key()));
    let got = with(extras);
    assert_eq!(got.result, Err(ErrorKind::SslConnectError));
    assert_eq!(got.failure, b"101 certificates is more than allowed (100)");
    assert_eq!(got.chain, None);
}
