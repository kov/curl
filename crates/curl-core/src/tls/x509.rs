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
    let (not_after, left) = element(after)?;
    if !left.is_empty() {
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
