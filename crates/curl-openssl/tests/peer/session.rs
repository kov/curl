//! What a handshake done says (`Curl_ossl_report_handshake`,
//! `Curl_alpn_set_negotiated`, `infof_certstack`): the protocol the peer
//! chose of the ALPN offer, and each certificate of the chain.

use openssl::rsa::Rsa;
use openssl::ssl::AlpnError;

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "the_protocol_the_server_accepts_is_said",
        the_protocol_the_server_accepts_is_said,
    ),
    (
        "each_certificate_of_the_chain_is_said_by_its_level",
        each_certificate_of_the_chain_is_said_by_its_level,
    ),
];

/// A server choosing `http/1.1` of the offer says so; one that chooses
/// none is said to have not agreed.
fn the_protocol_the_server_accepts_is_said() {
    let certs = certs("alpn", "localhost", &["localhost"]);
    let (at, server) = serve_configured(&certs, false, |a| {
        a.set_alpn_select_callback(|_, offer| {
            openssl::ssl::select_next_proto(b"\x08http/1.1", offer).ok_or(AlpnError::NOACK)
        });
    });
    let got = get("localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert!(
        said(&got, "ALPN: server accepted http/1.1"),
        "{:#?}",
        got.seen.lines
    );
    assert!(!starts(&got, "ALPN: server did not agree"));
    let (at, server) = serve(&certs);
    let got = get("localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert!(said(
        &got,
        "ALPN: server did not agree on a protocol. Uses default."
    ));
}

fn level_lines(got: &Got) -> Vec<&str> {
    got.seen
        .lines
        .iter()
        .filter(|l| l.starts_with("  Certificate level "))
        .map(String::as_str)
        .collect()
}

/// A verified chain is said whole, the CA that verified it included; an
/// unverified one as the peer sent it. An EC key is said with its group,
/// an RSA key without.
fn each_certificate_of_the_chain_is_said_by_its_level() {
    let certs = certs("levels", "localhost", &["localhost"]);
    let ec = "Public key type EC/prime256v1 (256/128 Bits/secBits), signed using \
              ecdsa-with-SHA256";
    let got = verified_get(&certs, trusting(&certs));
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert_eq!(
        level_lines(&got),
        [
            format!("  Certificate level 0: {ec}"),
            format!("  Certificate level 1: {ec}")
        ]
    );
    let got = verified_get(&certs, |o| {
        o.tls.verify_peer = false;
    });
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert_eq!(level_lines(&got), [format!("  Certificate level 0: {ec}")]);
    // A self-signed RSA certificate, trusted as its own CA.
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
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = cert.build();
    let ca_file = certs_dir().join("levels-rsa.pem");
    std::fs::write(&ca_file, cert.to_pem().unwrap()).unwrap();
    let rsa = Certs {
        ca_file,
        cert: cert.clone(),
        key: key.clone(),
        ca: cert,
        ca_key: key,
    };
    let got = verified_get(&rsa, trusting(&rsa));
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert_eq!(
        level_lines(&got),
        [
            "  Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using \
          sha256WithRSAEncryption"
        ]
    );
}

/// A GET of `localhost` from a server showing `certs`, with the options
/// `set` makes.
fn verified_get(certs: &Certs, set: impl FnOnce(&mut Options)) -> Got {
    let (at, server) = serve(certs);
    let got = get("localhost", at, set);
    server.join().unwrap();
    got
}
