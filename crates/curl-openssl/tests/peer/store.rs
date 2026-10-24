//! What the trust store is made of (`ossl_populate_x509_store`,
//! `ossl_load_trust_anchors`, `load_cacert_from_memory`): a CA that is
//! itself issued, a directory of CAs, a blob of CAs and lists; and a peer
//! that shows no certificate at all (`Curl_ossl_check_peer_cert`).

use curl_core::options::SslOptions;
use openssl::dh::Dh;
use openssl::ssl::SslVersion;

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "a_trusted_intermediate_is_an_anchor_unless_asked_not_to",
        a_trusted_intermediate_is_an_anchor_unless_asked_not_to,
    ),
    (
        "a_ca_directory_alone_is_trusted",
        a_ca_directory_alone_is_trusted,
    ),
    (
        "a_ca_blob_s_certificates_and_lists_are_all_taken",
        a_ca_blob_s_certificates_and_lists_are_all_taken,
    ),
    (
        "a_peer_without_a_certificate_passes_only_unchecked",
        a_peer_without_a_certificate_passes_only_unchecked,
    ),
];

/// A server certificate an intermediate CA issued, the server sending
/// the intermediate after it: the `Certs` of the intermediate, its file
/// the intermediate alone, the root nowhere.
fn issued_by_intermediate(tag: &str) -> Certs {
    let root = certs(&format!("{tag}-root"), "unused", &[]);
    let inter_key = key();
    let mut inter = X509::builder().unwrap();
    inter.set_version(2).unwrap();
    inter
        .set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    inter
        .set_subject_name(&name(&format!("{tag} intermediate")))
        .unwrap();
    inter.set_issuer_name(root.ca.subject_name()).unwrap();
    inter.set_pubkey(&inter_key).unwrap();
    inter
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    inter
        .set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    inter
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    inter.sign(&root.ca_key, MessageDigest::sha256()).unwrap();
    let inter = inter.build();
    let key = key();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name("localhost")).unwrap();
    cert.set_issuer_name(inter.subject_name()).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    let mut san = SubjectAlternativeName::new();
    san.dns("localhost");
    let san = san.build(&cert.x509v3_context(Some(&inter), None)).unwrap();
    cert.append_extension(san).unwrap();
    cert.sign(&inter_key, MessageDigest::sha256()).unwrap();
    let ca_file = certs_dir().join(format!("{tag}-intermediate.pem"));
    std::fs::write(&ca_file, inter.to_pem().unwrap()).unwrap();
    Certs {
        ca_file,
        cert: cert.build(),
        key,
        ca: inter,
        ca_key: inter_key,
    }
}

/// A CA file holding only an intermediate is trusted as an anchor
/// (`X509_V_FLAG_PARTIAL_CHAIN`), unless `CURLSSLOPT_NO_PARTIALCHAIN` is
/// set or a revocation list is checked, which then want the root.
fn a_trusted_intermediate_is_an_anchor_unless_asked_not_to() {
    let certs = issued_by_intermediate("partial");
    let crl = super::checks::crl(&certs, "partial", false);
    let crl = crl.to_str().unwrap().as_bytes().to_vec();
    // As C says it, checked against its build: the handshake passes, the
    // result after does not.
    let refused = "SSL certificate OpenSSL verify result: unable to get issuer certificate (2)";
    for (set, failure) in [
        (
            &(|_: &mut curl_core::options::TlsOptions| {}) as &dyn Fn(&mut _),
            None,
        ),
        (
            &|t: &mut curl_core::options::TlsOptions| {
                t.ssl_options = SslOptions::NO_PARTIALCHAIN;
            },
            Some(refused),
        ),
        (
            &|t: &mut curl_core::options::TlsOptions| t.crl_file = Some(crl.clone()),
            Some(refused),
        ),
    ] {
        let inter = certs.ca.clone();
        let (at, server) = serve_configured(&certs, false, move |a| {
            a.add_extra_chain_cert(inter).unwrap();
        });
        let got = get("localhost", at, |o| {
            trusting(&certs)(o);
            set(o.tls.options.make_mut().unwrap());
        });
        server.join().unwrap();
        match failure {
            None => assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines),
            Some(failure) => {
                assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
                assert_eq!(String::from_utf8(got.failure).unwrap(), failure);
            }
        }
    }
}

/// `CURLOPT_CAPATH` with no CA file: the directory's CAs, named by their
/// subjects' hashes, are trusted, and it is said.
fn a_ca_directory_alone_is_trusted() {
    let certs = certs("capath", "localhost", &["localhost"]);
    let dir = certs_dir().join("capath-dir");
    std::fs::create_dir_all(&dir).unwrap();
    let hash = certs.ca.subject_name_hash();
    std::fs::write(
        dir.join(format!("{hash:08x}.0")),
        certs.ca.to_pem().unwrap(),
    )
    .unwrap();
    let path = dir.to_str().unwrap().as_bytes().to_vec();
    let (at, server) = serve(&certs);
    let got = get("localhost", at, |o| {
        let t = o.tls.options.make_mut().unwrap();
        t.ca_file = CaSetting::Unset;
        t.ca_path = CaSetting::Given(path);
    });
    server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let line = format!("  CApath: {}", dir.display());
    assert!(said(&got, &line), "{line:?} in {:#?}", got.seen.lines);
    assert!(!starts(&got, "  CAfile:"), "{:#?}", got.seen.lines);
}

/// `CURLOPT_CAINFO_BLOB`: each certificate and each revocation list in it
/// is added; one holding only a list loads, and leaves the peer
/// unverified; one holding neither fails, said as C says it (77).
fn a_ca_blob_s_certificates_and_lists_are_all_taken() {
    let certs = certs("cablob", "localhost", &["localhost"]);
    let crl = std::fs::read(super::checks::crl(&certs, "cablob", false)).unwrap();
    let ca = certs.ca.to_pem().unwrap();
    let with = |blob: Vec<u8>| {
        let (at, server) = serve(&certs);
        let got = get("localhost", at, |o| {
            o.tls.options.make_mut().unwrap().ca_blob = Some(blob);
        });
        server.join().unwrap();
        got
    };
    let got = with([ca.clone(), crl.clone()].concat());
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert!(said(&got, "  CA Blob from configuration"));
    let got = with([crl.clone(), ca].concat());
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let got = with(crl);
    assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(
        got.failure,
        b"SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)"
    );
    let got = with(certs.key.private_key_to_pem_pkcs8().unwrap());
    assert_eq!(got.result, Err(ErrorKind::SslCacertBadfile));
    assert_eq!(
        got.failure,
        b"error adding trust anchors from certificate blob: 77"
    );
}

/// An anonymous key exchange, the server showing no certificate: passes
/// when nothing of the peer is checked, and fails, said, when its name
/// is, or a key is pinned.
fn a_peer_without_a_certificate_passes_only_unchecked() {
    let certs = certs("anonymous", "localhost", &["localhost"]);
    let suite = "ADH-AES128-GCM-SHA256:@SECLEVEL=0";
    let cases: [(bool, bool, bool, bool); 4] = [
        // Verify the peer, its name, a key pinned; whether it passes.
        (false, false, false, true),
        (false, true, false, false),
        (true, false, false, false),
        (false, false, true, false),
    ];
    for (verify_peer, verify_host, pinned, passes) in cases {
        let (at, server) = serve_configured(&certs, false, |a| {
            a.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
            a.set_cipher_list(suite).unwrap();
            a.set_tmp_dh(&Dh::get_2048_256().unwrap()).unwrap();
        });
        let got = get("localhost", at, |o| {
            o.tls.verify_peer = verify_peer;
            o.tls.verify_host = verify_host;
            let t = o.tls.options.make_mut().unwrap();
            t.max_version = curl_core::options::TlsMaxVersion::Tls1_2;
            t.ciphers = Some(suite.as_bytes().to_vec());
            if pinned {
                t.pinned_key =
                    Some(b"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_vec());
            }
        });
        server.join().unwrap();
        let case = (verify_peer, verify_host, pinned);
        if passes {
            assert_eq!(got.result, Ok(()), "{case:?}: {:#?}", got.seen.lines);
            assert_eq!(got.seen.body, BODY);
        } else {
            assert_eq!(
                got.result,
                Err(ErrorKind::PeerFailedVerification),
                "{case:?}: {:#?}",
                got.seen.lines
            );
            assert_eq!(
                got.failure, b"SSL: could not get peer certificate",
                "{case:?}"
            );
        }
    }
}
