//! The peer's chain as a transfer that asks reports it (`CURLOPT_CERTINFO`,
//! `ossl_certchain`): each field worded as C words it.

use openssl::rsa::Rsa;

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[(
    "the_chain_is_reported_as_c_words_it_when_asked",
    the_chain_is_reported_as_c_words_it_when_asked,
)];

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
