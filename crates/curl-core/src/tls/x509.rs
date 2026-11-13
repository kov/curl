//! A certificate read as C's own light ASN.1 reader reads it
//! (`lib/vtls/x509asn1.c`), for the TLS libraries that hand a peer's
//! certificate over whole: its parts found, not checked, so that the
//! public key can be pinned. A certificate is the peer's, and so read at
//! the trust boundary: what does not read is refused, never trusted.

mod info;

pub use info::certinfo;

/// The most bytes an element may span (`CURL_ASN1_MAX`).
const MOST: usize = 0x40000;
/// The deepest an element of unspecified length may nest
/// (`CURL_ASN1_MAX_RECURSIONS`).
const DEEPEST: usize = 16;

/// One ASN.1 element (`Curl_asn1Element`): its whole encoding, header
/// included, and its content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Element<'a> {
    /// From its header to its end.
    pub whole: &'a [u8],
    pub content: &'a [u8],
    pub class: u8,
    pub tag: u8,
    pub constructed: bool,
}

/// The element at the start of `der`, and what follows it
/// (`getASN1Element`); none if it does not read.
pub fn element(der: &[u8]) -> Option<(Element<'_>, &[u8])> {
    element_at(der, 0)
}

fn element_at(der: &[u8], depth: usize) -> Option<(Element<'_>, &[u8])> {
    if der.is_empty() || der[0] == 0 || der.len() > MOST || depth >= DEEPEST {
        return None;
    }
    let b = der[0];
    let constructed = b & 0x20 != 0;
    let class = (b >> 6) & 3;
    let tag = b & 0x1f;
    if tag == 0x1f {
        // Long tags are not read.
        return None;
    }
    let rest = &der[1..];
    let (&first, mut rest) = rest.split_first()?;
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 {
            // Unspecified: the content runs to an end-of-contents element,
            // found by reading the elements inside.
            if !constructed {
                return None;
            }
            let start = rest;
            let mut at = rest;
            while !at.is_empty() && at[0] != 0 {
                at = element_at(at, depth + 1)?.1;
            }
            if at.len() < 2 || at[1] != 0 {
                return None;
            }
            let content_len = start.len() - at.len();
            let whole_len = der.len() - at.len();
            return Some((
                Element {
                    whole: &der[..whole_len],
                    content: &start[..content_len],
                    class,
                    tag,
                    constructed,
                },
                &at[2..],
            ));
        }
        if n > rest.len() {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            if len & 0xff00_0000 != 0 {
                return None;
            }
            len = (len << 8) | usize::from(rest[0]);
            rest = &rest[1..];
        }
        len
    };
    if len > rest.len() {
        return None;
    }
    let header = der.len() - rest.len();
    Some((
        Element {
            whole: &der[..header + len],
            content: &rest[..len],
            class,
            tag,
            constructed,
        },
        &rest[len..],
    ))
}

/// The parts of a certificate (`Curl_X509certificate`), as
/// `Curl_parseX509` finds them.
#[derive(Clone, Copy, Debug)]
pub struct Certificate<'a> {
    /// Its version's content: v1's zero where it gives none.
    pub version: &'a [u8],
    pub serial: Element<'a>,
    /// The algorithm it is signed with, the outer one.
    pub signature_algorithm: Element<'a>,
    pub signature: Element<'a>,
    pub issuer: Element<'a>,
    pub not_before: Element<'a>,
    pub not_after: Element<'a>,
    pub subject: Element<'a>,
    pub public_key_info: Element<'a>,
    pub public_key_algorithm: Element<'a>,
    pub public_key: Element<'a>,
    /// Its extensions' list, if it has any.
    pub extensions: Option<Element<'a>>,
}

/// The parts of the DER certificate `der` (`Curl_parseX509`); none if it
/// does not read as one.
pub fn parse(der: &[u8]) -> Option<Certificate<'_>> {
    let (outer, _) = element(der)?;
    let (tbs, rest) = element(outer.content)?;
    let (signature_algorithm, rest) = element(rest)?;
    let (signature, _) = element(rest)?;

    let (mut elem, mut rest) = element(tbs.content)?;
    let mut version: &[u8] = &[0];
    if elem.tag == 0 {
        version = element(elem.content)?.0.content;
        (elem, rest) = element(rest)?;
    }
    let serial = elem;
    // The inner signature algorithm: C reads it into the same field and
    // checks nothing of it.
    let rest = match element(rest) {
        Some((_, r)) => r,
        None => return None,
    };
    let (issuer, rest) = element(rest)?;
    let (validity, rest) = element(rest)?;
    let (not_before, after) = element(validity.content)?;
    // The two dates end where the validity does: `notAfter` ends at its
    // content's end, which an unspecified length's end-of-contents
    // octets follow (`elem.end != cert->notAfter.end`).
    let (not_after, _) = element(after)?;
    if not_after.whole.len() != after.len() {
        return None;
    }
    let (subject, rest) = element(rest)?;
    let (public_key_info, mut rest) = element(rest)?;
    let (public_key_algorithm, key) = element(public_key_info.content)?;
    let (public_key, _) = element(key)?;
    let mut extensions = None;
    let mut tag = 0;
    let mut elem = None;
    if !rest.is_empty() {
        let (e, r) = element(rest)?;
        tag = e.tag;
        elem = Some(e);
        rest = r;
    }
    for unique in [1, 2] {
        if tag == unique {
            tag = 0;
            if !rest.is_empty() {
                let (e, r) = element(rest)?;
                tag = e.tag;
                elem = Some(e);
                rest = r;
            }
        }
    }
    if tag == 3 {
        let e = elem.expect("read with its tag");
        extensions = Some(element(e.content)?.0);
    }
    Some(Certificate {
        version,
        serial,
        signature_algorithm,
        signature,
        issuer,
        not_before,
        not_after,
        subject,
        public_key_info,
        public_key_algorithm,
        public_key,
        extensions,
    })
}

/// The elements one after another in `content`, as far as they read.
fn elements(mut content: &[u8]) -> impl Iterator<Item = Option<Element<'_>>> {
    core::iter::from_fn(move || {
        if content.is_empty() {
            return None;
        }
        match element(content) {
            Some((e, rest)) => {
                content = rest;
                Some(Some(e))
            }
            None => {
                content = &[];
                Some(None)
            }
        }
    })
}

/// The common name's identifier, 2.5.4.3.
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// The subject alternative names' identifier, 2.5.29.17.
const ALT_NAMES: &[u8] = &[0x55, 0x1d, 0x11];

/// Whether a string's characters include a zero: a two-byte one in a
/// `BMPString`, a four-byte one in a `UniversalString`, a byte in the
/// others.
fn has_zero_char(e: &Element<'_>) -> bool {
    let width = match e.tag {
        0x1e => 2,
        0x1c => 4,
        _ => 1,
    };
    e.content.chunks(width).any(|c| c.iter().all(|&b| b == 0))
}

/// Whether a name the certificate `der` gives its host by holds a zero
/// character: a `dNSName` among its subject alternative names, or a common
/// name of its subject. Such a name is not one a host can have, and is
/// never to be matched in part. None if the certificate does not read.
pub fn host_name_holds_zero(der: &[u8]) -> Option<bool> {
    let cert = parse(der)?;
    for rdn in elements(cert.subject.content) {
        for attribute in elements(rdn?.content) {
            let attribute = attribute?;
            let (oid, value) = element(attribute.content)?;
            if oid.tag == 6 && oid.content == COMMON_NAME && has_zero_char(&element(value)?.0) {
                return Some(true);
            }
        }
    }
    let Some(extensions) = cert.extensions else {
        return Some(false);
    };
    for extension in elements(extensions.content) {
        let mut parts = elements(extension?.content);
        let oid = parts.next()??;
        if oid.tag != 6 || oid.content != ALT_NAMES {
            continue;
        }
        // An optional `critical` flag, then the value.
        let mut value = parts.next()??;
        if value.tag == 1 {
            value = parts.next()??;
        }
        let (names, _) = element(value.content)?;
        for name in elements(names.content) {
            let name = name?;
            // `dNSName`, `[2] IMPLICIT IA5String`.
            if name.class == 2 && name.tag == 2 && !name.constructed && name.content.contains(&0) {
                return Some(true);
            }
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// unit1657's tables, read from its source: elements nested `n`
    /// deep, each of an unknown length, read whole to 16 deep and refused
    /// deeper; and a certificate parsed, and refused with its validity's
    /// length too long.
    #[test]
    fn unit1657_nesting_and_certificates() {
        let specs = crate::c_source::table("tests/unit/unit1657.c", "test1657_specs[]", |c| {
            panic!("{c}")
        });
        assert_eq!(specs.len(), 4, "the nestings were read");
        for spec in specs {
            let [make, n, code] = spec.group() else {
                panic!("{spec:?}")
            };
            assert_eq!(make.word(), "make1657_nested");
            let n = usize::try_from(n.int()).unwrap();
            let der = [[0x32, 0x80].repeat(n), [0, 0].repeat(n)].concat();
            let read = element(&der).map(|(_, rest)| rest.is_empty());
            let want = match code.word() {
                "CURLE_OK" => Some(true),
                "CURLE_BAD_FUNCTION_ARGUMENT" => None,
                other => panic!("{other}"),
            };
            assert_eq!(read, want, "{n} deep");
        }
        let certs = crate::c_source::table("tests/unit/unit1657.c", "test1657_certs[]", |c| {
            panic!("{c}")
        });
        assert_eq!(certs.len(), 2, "the certificates were read");
        for cert in certs {
            let [pem, ok] = cert.group() else {
                panic!("{cert:?}")
            };
            let der = crate::base64::decode(pem.str()).unwrap().unwrap();
            assert_eq!(parse(&der).is_some(), ok.word() == "TRUE", "{}", ok.word());
        }
    }

    /// A certificate's public key info is found whole, its header with
    /// it, as pinning hashes it.
    #[test]
    fn the_public_key_info_is_found_whole() {
        // SEQUENCE { SEQUENCE { [0] { INTEGER 2 } INTEGER 1 SEQUENCE {}
        //   SEQUENCE {} SEQUENCE { UTCTime UTCTime } SEQUENCE {}
        //   SEQUENCE { SEQUENCE { OID } BIT STRING } } SEQUENCE {} BIT STRING }
        let spki = [
            0x30, 0x09, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x02, 0x00, 0x01,
        ];
        let mut tbs = vec![0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x00];
        tbs.extend_from_slice(&[0x30, 0x00, 0x30, 0x04, 0x17, 0x00, 0x17, 0x00, 0x30, 0x00]);
        tbs.extend_from_slice(&spki);
        let mut cert = vec![0x30, u8::try_from(tbs.len()).unwrap()];
        cert.extend_from_slice(&tbs);
        cert.extend_from_slice(&[0x30, 0x00, 0x03, 0x01, 0x00]);
        let mut der = vec![0x30, u8::try_from(cert.len()).unwrap()];
        der.extend_from_slice(&cert);
        let c = parse(&der).expect("reads");
        assert_eq!(c.public_key_info.whole, &spki);
        assert_eq!(c.version, &[2]);
        assert_eq!(c.serial.content, &[1]);
        assert!(c.extensions.is_none());
        // Cut short, it reads as none.
        assert!(parse(&der[..der.len() - 1]).is_none());
    }

    /// The validity's dates must end where it ends: a `notAfter` of
    /// unspecified length, its end-of-contents octets after it, does not,
    /// and the certificate is refused (`elem.end != cert->notAfter.end`),
    /// as one with a definite `notAfter` is read. C's `Curl_parseX509`
    /// gives 0 and -1 for these same two certificates.
    #[test]
    fn the_validity_ends_with_its_not_after() {
        let cert = |validity: &[u8]| {
            let mut tbs = vec![0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x00];
            tbs.extend_from_slice(&[0x30, 0x00]);
            tbs.extend_from_slice(validity);
            tbs.extend_from_slice(&[0x30, 0x00]);
            tbs.extend_from_slice(&[
                0x30, 0x09, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x02, 0x00, 0x01,
            ]);
            let mut cert = vec![0x30, u8::try_from(tbs.len()).unwrap()];
            cert.extend_from_slice(&tbs);
            cert.extend_from_slice(&[0x30, 0x00, 0x03, 0x01, 0x00]);
            let mut der = vec![0x30, u8::try_from(cert.len()).unwrap()];
            der.extend_from_slice(&cert);
            der
        };
        let definite = cert(&[0x30, 0x04, 0x17, 0x00, 0x17, 0x00]);
        assert_eq!(
            definite,
            hex("3026301fa0030201020201013000300030041700170030003009300306012a030200013000030100")
        );
        assert!(parse(&definite).is_some());
        // A constructed UTCTime of unspecified length, holding an empty
        // octet string, then its end-of-contents.
        let indefinite = cert(&[0x30, 0x08, 0x17, 0x00, 0x37, 0x80, 0x04, 0x00, 0x00, 0x00]);
        assert_eq!(
            indefinite,
            hex(
                "302a3023a003020102020101300030003008170037800400000030003009300306012a030200013000030100"
            )
        );
        // Nothing follows the date in the validity: only its
        // end-of-contents octets stand between them.
        let (validity, _) = element(&indefinite[16..]).unwrap();
        assert_eq!(validity.tag, 0x10);
        let (_, after) = element(validity.content).unwrap();
        assert!(element(after).unwrap().1.is_empty());
        assert!(parse(&indefinite).is_none());
    }

    /// One element: `tag`, a short length, `content`.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut e = vec![tag, u8::try_from(content.len()).unwrap()];
        e.extend_from_slice(content);
        e
    }

    /// A certificate whose subject is one attribute, `oid` of `value`
    /// (an element), and whose extensions, if any, are `extensions`.
    fn cert_with(oid: &[u8], value: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
        let attribute = tlv(0x30, &[tlv(0x06, oid), value.to_vec()].concat());
        let subject = tlv(0x30, &tlv(0x31, &attribute));
        let mut tbs = vec![0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x00];
        tbs.extend_from_slice(&[0x30, 0x00, 0x30, 0x04, 0x17, 0x00, 0x17, 0x00]);
        tbs.extend_from_slice(&subject);
        tbs.extend_from_slice(&[
            0x30, 0x09, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x02, 0x00, 0x01,
        ]);
        if !extensions.is_empty() {
            tbs.extend_from_slice(&tlv(0xa3, &tlv(0x30, &extensions.concat())));
        }
        let cert = tlv(
            0x30,
            &[tlv(0x30, &tbs), vec![0x30, 0x00, 0x03, 0x01, 0x00]].concat(),
        );
        assert!(parse(&cert).is_some());
        cert
    }

    /// A subject alternative names extension of `names` (each an
    /// element), marked critical if `critical`.
    fn alt_names(names: &[Vec<u8>], critical: bool) -> Vec<u8> {
        let flag = if critical {
            vec![0x01, 0x01, 0xff]
        } else {
            vec![]
        };
        let value = tlv(0x04, &tlv(0x30, &names.concat()));
        tlv(
            0x30,
            &[tlv(0x06, &[0x55, 0x1d, 0x11]), flag, value].concat(),
        )
    }

    /// A host name with a zero byte in it, in a subject alternative
    /// `dNSName` or a common name, is found, whichever string type the
    /// name is written in; a zero in an address or another kind of name,
    /// or another attribute, is not a host name's.
    #[test]
    fn a_host_name_holding_a_zero_is_found() {
        let cn = [0x55, 0x04, 0x03];
        let org = [0x55, 0x04, 0x0a];
        let utf8 = |s: &[u8]| tlv(0x0c, s);
        let dns = |s: &[u8]| tlv(0x82, s);
        let plain = utf8(b"localhost");
        for (cert, zero) in [
            (cert_with(&cn, &plain, &[]), false),
            (
                cert_with(&cn, &utf8(b"localhost\0.evil.example"), &[]),
                true,
            ),
            (cert_with(&cn, &tlv(0x13, b"local\0host"), &[]), true),
            (cert_with(&cn, &tlv(0x1e, &[0, b'l', 0, b'o']), &[]), false),
            (
                cert_with(&cn, &tlv(0x1e, &[0, b'l', 0, 0, 0, b'o']), &[]),
                true,
            ),
            (cert_with(&cn, &tlv(0x1c, &[0, 0, 0, b'l']), &[]), false),
            (
                cert_with(&cn, &tlv(0x1c, &[0, 0, 0, b'l', 0, 0, 0, 0]), &[]),
                true,
            ),
            (cert_with(&org, &utf8(b"org\0anisation"), &[]), false),
            (
                cert_with(&cn, &plain, &[alt_names(&[dns(b"localhost")], false)]),
                false,
            ),
            (
                cert_with(
                    &cn,
                    &plain,
                    &[alt_names(&[dns(b"localhost\0.evil.example")], false)],
                ),
                true,
            ),
            (
                cert_with(
                    &cn,
                    &plain,
                    &[alt_names(
                        &[dns(b"a.example"), dns(b"localhost\0.evil")],
                        true,
                    )],
                ),
                true,
            ),
            (
                cert_with(
                    &cn,
                    &plain,
                    &[alt_names(&[tlv(0x87, &[127, 0, 0, 1])], false)],
                ),
                false,
            ),
            (
                cert_with(
                    &cn,
                    &plain,
                    &[alt_names(&[tlv(0x81, b"a\0@example")], false)],
                ),
                false,
            ),
            (
                cert_with(
                    &cn,
                    &plain,
                    &[tlv(
                        0x30,
                        &[tlv(0x06, &[0x55, 0x1d, 0x13]), tlv(0x04, &[0x30, 0x00])].concat(),
                    )],
                ),
                false,
            ),
            // The issuer's alternative names are not the host's: a zero
            // in one of their DNS names says nothing of it.
            (
                cert_with(
                    &cn,
                    &plain,
                    &[tlv(
                        0x30,
                        &[
                            tlv(0x06, &[0x55, 0x1d, 0x12]),
                            tlv(0x04, &tlv(0x30, &tlv(0x82, b"a\0b.example"))),
                        ]
                        .concat(),
                    )],
                ),
                false,
            ),
        ] {
            assert_eq!(host_name_holds_zero(&cert), Some(zero), "{cert:02x?}");
        }
        assert_eq!(host_name_holds_zero(&[0x30, 0x00]), None);
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// An element of unspecified length runs to its end-of-contents; a
    /// zero header byte, a long tag or a length past the data reads as
    /// none.
    #[test]
    fn elements_read_as_c_reads_them() {
        let (e, rest) = element(&[0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, 0xff]).unwrap();
        assert_eq!(e.content, &[0x02, 0x01, 0x05]);
        assert_eq!(rest, &[0xff]);
        assert!(element(&[0x00, 0x00]).is_none());
        assert!(element(&[0x1f, 0x01, 0x00]).is_none());
        assert!(element(&[0x04, 0x02, 0x00]).is_none());
        assert!(element(&[0x04, 0x80]).is_none());
    }
}
