//! What a session checks of its peer past the chain, and who it says it
//! is: the revocation list.

use std::path::PathBuf;

use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::hash::MessageDigest;
use openssl::x509::{X509Crl, X509CrlBuilder, X509Extension, X509Revoked};

use super::*;

/// The tests of this file, as `main` runs them.
pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "a_revoked_certificate_fails_the_verification",
        a_revoked_certificate_fails_the_verification,
    ),
    (
        "a_crl_that_revokes_nothing_lets_the_peer_verify",
        a_crl_that_revokes_nothing_lets_the_peer_verify,
    ),
    (
        "a_crl_file_that_cannot_be_read_fails_as_a_bad_crl",
        a_crl_file_that_cannot_be_read_fails_as_a_bad_crl,
    ),
];

/// A revocation list the CA of `certs` signed, revoking the server's
/// certificate if `revoke` (else another), written to a file of its own
/// (`tag`).
pub(crate) fn crl(certs: &Certs, tag: &str, revoke: bool) -> PathBuf {
    let mut crl = X509CrlBuilder::new().unwrap();
    crl.set_issuer_name(certs.ca.subject_name()).unwrap();
    crl.set_last_update(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    crl.set_next_update(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    // The extensions the builder insists on, as DER: a key identifier
    // (the CA has none of its own to match), and the list's number, 1.
    for (oid, der) in [
        ("2.5.29.35", &b"\x30\x06\x80\x04\x01\x02\x03\x04"[..]),
        ("2.5.29.20", b"\x02\x01\x01"),
    ] {
        let oid = Asn1Object::from_str(oid).unwrap();
        let der = Asn1OctetString::new_from_bytes(der).unwrap();
        crl.append_extension(X509Extension::new_from_der(&oid, false, &der).unwrap())
            .unwrap();
    }
    // The entry as DER: the serial number revoked (the server's is 2),
    // and when.
    let serial = if revoke { 2 } else { 99 };
    let entry = [
        &b"\x30\x12\x02\x01"[..],
        &[serial],
        b"\x17\x0d260101000000Z",
    ]
    .concat();
    crl.add_revoked(X509Revoked::from_der(&entry).unwrap())
        .unwrap();
    crl.sign(&certs.ca_key, MessageDigest::sha256()).unwrap();
    let crl: X509Crl = crl.build().unwrap();
    let file = certs_dir().join(format!("{tag}.crl"));
    std::fs::write(&file, crl.to_pem().unwrap()).unwrap();
    file
}

/// Trust the CA of `certs` and check against the list in `file`.
fn checking<'a>(certs: &'a Certs, file: &std::path::Path) -> impl FnOnce(&mut Options) + 'a {
    let file = file.to_str().unwrap().as_bytes().to_vec();
    move |o| {
        trusting(certs)(o);
        o.tls.options.make_mut().unwrap().crl_file = Some(file);
    }
}

/// `--crlfile` (`ossl_populate_x509_store`): the list is loaded beside
/// the CA, said, and a certificate it revokes fails as OpenSSL says (60,
/// as test 313).
fn a_revoked_certificate_fails_the_verification() {
    let certs = certs("revoked", "localhost", &["localhost"]);
    let file = crl(&certs, "revoked", true);
    let (at, server) = serve(&certs);
    let got = get("localhost", at, checking(&certs, &file));
    server.join().unwrap();
    assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(
        got.failure,
        b"SSL certificate OpenSSL verify result: certificate revoked (23)"
    );
    assert!(
        said(&got, &format!(" CRLfile: {}", file.display())),
        "{:#?}",
        got.seen.lines
    );
}

/// A list that revokes nothing is checked, and the peer verifies.
fn a_crl_that_revokes_nothing_lets_the_peer_verify() {
    let certs = certs("unrevoked", "localhost", &["localhost"]);
    let file = crl(&certs, "unrevoked", false);
    let (at, server) = serve(&certs);
    let got = get("localhost", at, checking(&certs, &file));
    server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert!(said(&got, "OpenSSL verify result: 0"));
}

/// A file that is no list fails the store's setup with 82, as C says it.
fn a_crl_file_that_cannot_be_read_fails_as_a_bad_crl() {
    let certs = certs("badcrl", "localhost", &["localhost"]);
    let (at, server) = serve(&certs);
    // The CA file: a certificate, not a list.
    let got = get("localhost", at, checking(&certs, &certs.ca_file));
    server.join().unwrap();
    assert_eq!(got.result, Err(ErrorKind::SslCrlBadfile));
    assert_eq!(
        got.failure,
        format!("error loading CRL file: {}", certs.ca_file.display()).as_bytes()
    );
}
