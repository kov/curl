//! The names in the peer's certificate (`ossl_verifyhost`,
//! `ossl_infof_cert`): an alternative name of the host's kind, or without
//! any the last common name, as it matches the host; and the subject and
//! issuer as the trace shows them, within C's buffer.

use openssl::asn1::Asn1Type;
use openssl::x509::X509NameBuilder;

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "an_address_alternative_name_names_the_address_alone",
        an_address_alternative_name_names_the_address_alone,
    ),
    (
        "without_alternative_names_the_last_common_name_is_matched",
        without_alternative_names_the_last_common_name_is_matched,
    ),
    (
        "a_common_name_with_a_zero_byte_is_refused",
        a_common_name_with_a_zero_byte_is_refused,
    ),
    (
        "a_name_too_long_for_c_s_buffer_is_not_shown",
        a_name_too_long_for_c_s_buffer_is_not_shown,
    ),
];

/// A certificate the CA of `certs` issued for `subject`, with the
/// alternative names `san` adds, if any; the server shows it.
fn issued(
    certs: &Certs,
    subject: &X509Name,
    san: Option<&dyn Fn(&mut SubjectAlternativeName)>,
) -> Certs {
    let key = key();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(3).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(subject).unwrap();
    cert.set_issuer_name(certs.ca.subject_name()).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    if let Some(san) = san {
        let mut names = SubjectAlternativeName::new();
        san(&mut names);
        let ext = names
            .build(&cert.x509v3_context(Some(&certs.ca), None))
            .unwrap();
        cert.append_extension(ext).unwrap();
    }
    cert.sign(&certs.ca_key, MessageDigest::sha256()).unwrap();
    Certs {
        ca_file: certs.ca_file.clone(),
        cert: cert.build(),
        key,
        ca: certs.ca.clone(),
        ca_key: certs.ca_key.clone(),
    }
}

/// A name of entries, each a field and its value as the type says.
fn entries(list: &[(&str, &str, Asn1Type)]) -> X509Name {
    let mut n = X509NameBuilder::new().unwrap();
    for (field, value, kind) in list {
        n.append_entry_by_text_with_type(field, value, *kind)
            .unwrap();
    }
    n.build()
}

/// A verified GET of `host` from a server showing `certs`.
fn verified(certs: &Certs, host: &str) -> Got {
    let (at, server) = serve(certs);
    let got = get(host, at, trusting(certs));
    server.join().unwrap();
    got
}

/// A certificate naming the address 127.0.0.1 names it, said so; it names
/// no host name, and its common name is not looked at.
fn an_address_alternative_name_names_the_address_alone() {
    let ca = certs("ipaddress", "unused", &[]);
    let certs = issued(
        &ca,
        &name("localhost"),
        Some(&|s: &mut SubjectAlternativeName| {
            s.ip("127.0.0.1");
        }),
    );
    let got = verified(&certs, "127.0.0.1");
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert!(
        said(
            &got,
            "  subjectAltName: \"127.0.0.1\" matches cert's IP address!"
        ),
        "{:#?}",
        got.seen.lines
    );
    let got = verified(&certs, "localhost");
    assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(
        got.failure,
        b"SSL: no alternative certificate subject name matches target hostname 'localhost'"
    );
    let other = issued(
        &ca,
        &name("localhost"),
        Some(&|s: &mut SubjectAlternativeName| {
            s.ip("127.0.0.2");
        }),
    );
    let got = verified(&other, "127.0.0.1");
    assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(
        got.failure,
        b"SSL: no alternative certificate subject name matches target IPv4 address '127.0.0.1'"
    );
}

/// The last common name is the one matched, whatever its string type: a
/// BMPString's is converted to UTF-8 first.
fn without_alternative_names_the_last_common_name_is_matched() {
    let ca = certs("commonname", "unused", &[]);
    // A BMPString is given as its bytes, UTF-16BE.
    let bmp: String = "localhost".chars().flat_map(|c| ['\0', c]).collect();
    for subject in [
        entries(&[("CN", "localhost", Asn1Type::UTF8STRING)]),
        entries(&[("CN", &bmp, Asn1Type::BMPSTRING)]),
        entries(&[
            ("CN", "elsewhere", Asn1Type::UTF8STRING),
            ("CN", "localhost", Asn1Type::PRINTABLESTRING),
        ]),
    ] {
        let got = verified(&issued(&ca, &subject, None), "localhost");
        assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
        assert!(
            said(&got, " common name: localhost (matched)"),
            "{:#?}",
            got.seen.lines
        );
    }
    let subject = entries(&[
        ("CN", "localhost", Asn1Type::UTF8STRING),
        ("CN", "elsewhere", Asn1Type::UTF8STRING),
    ]);
    let got = verified(&issued(&ca, &subject, None), "localhost");
    assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(
        got.failure,
        b"SSL: certificate subject name 'elsewhere' does not match target hostname 'localhost'"
    );
}

/// A common name with a zero byte inside cannot be the host's, which C
/// sees ending there: refused as illegal. An empty one fails as C's
/// does, out of memory (27) and nothing said, whatever its string type.
fn a_common_name_with_a_zero_byte_is_refused() {
    let ca = certs("nulname", "unused", &[]);
    let subject = entries(&[("CN", "localhost\0.example", Asn1Type::UTF8STRING)]);
    let got = verified(&issued(&ca, &subject, None), "localhost");
    assert_eq!(got.result, Err(ErrorKind::PeerFailedVerification));
    assert_eq!(got.failure, b"SSL: illegal cert name field");
    for kind in [Asn1Type::UTF8STRING, Asn1Type::BMPSTRING] {
        let subject = entries(&[("CN", "", kind)]);
        let got = verified(&issued(&ca, &subject, None), "localhost");
        assert_eq!(got.result, Err(ErrorKind::OutOfMemory), "{kind:?}");
        assert_eq!(got.failure, b"", "{kind:?}");
    }
}

/// The subject and issuer lines (`x509_name_oneline`) hold a name that,
/// with its zero byte, fits C's 2048 bytes: a subject that does not is
/// shown as `[NONE]`, an issuer that does not fails a verbose transfer
/// (100) and no other; an empty one is shown empty.
fn a_name_too_long_for_c_s_buffer_is_not_shown() {
    let ca = certs("longname", "unused", &[]);
    let localhost = |s: &mut SubjectAlternativeName| {
        s.dns("localhost");
    };
    // `1.2.3.4=` and the value.
    let long = |len: usize| "x".repeat(len - "1.2.3.4=".len());
    let at_most = long(2047);
    let subject = entries(&[("1.2.3.4", &at_most, Asn1Type::UTF8STRING)]);
    let got = verified(&issued(&ca, &subject, Some(&localhost)), "localhost");
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    // Shown, as far as the trace's line holds it (C's `infof` cuts it).
    assert!(
        starts(&got, "  subject: 1.2.3.4=xxxxxxxx"),
        "{:#?}",
        got.seen.lines
    );
    let subject = entries(&[("1.2.3.4", &long(2048), Asn1Type::UTF8STRING)]);
    let got = verified(&issued(&ca, &subject, Some(&localhost)), "localhost");
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert!(said(&got, "  subject: [NONE]"), "{:#?}", got.seen.lines);
    let got = verified(
        &issued(
            &ca,
            &X509NameBuilder::new().unwrap().build(),
            Some(&localhost),
        ),
        "localhost",
    );
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert!(said(&got, "  subject:"), "{:#?}", got.seen.lines);
    // An issuer of that length: a CA of its own, written to be trusted.
    let issuer = entries(&[("1.2.3.4", &long(2048), Asn1Type::UTF8STRING)]);
    let mut long_ca = X509::builder().unwrap();
    long_ca.set_version(2).unwrap();
    long_ca
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    long_ca.set_subject_name(&issuer).unwrap();
    long_ca.set_issuer_name(&issuer).unwrap();
    long_ca.set_pubkey(&ca.ca_key).unwrap();
    long_ca
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    long_ca
        .set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    long_ca
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    long_ca.sign(&ca.ca_key, MessageDigest::sha256()).unwrap();
    let long_ca = long_ca.build();
    let ca_file = certs_dir().join("longname-issuer-ca.pem");
    std::fs::write(&ca_file, long_ca.to_pem().unwrap()).unwrap();
    let by_long = Certs {
        ca_file,
        ca: long_ca,
        ..issued(&ca, &name("localhost"), Some(&localhost))
    };
    let by_long = issued(&by_long, &name("localhost"), Some(&localhost));
    let got = verified(&by_long, "localhost");
    assert_eq!(
        got.result,
        Err(ErrorKind::TooLarge),
        "{:#?}",
        got.seen.lines
    );
    // A transfer that is not verbose prints no names, and so the issuer
    // does not fail it, as C prints them only when verbose.
    let (at, server) = serve(&by_long);
    let got = get("localhost", at, |o| {
        trusting(&by_long)(o);
        o.output.verbose = false;
    });
    server.join().unwrap();
    assert_eq!(got.result, Ok(()));
}
