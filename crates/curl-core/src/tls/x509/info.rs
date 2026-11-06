//! A certificate's fields as text, for `CURLINFO_CERTINFO` and the
//! verbose lines of the leaf (`Curl_extract_certinfo` and the
//! converters it uses).

use core::fmt::{self, Write as _};

use curl_alloc::{OutOfMemory, TryVec as _};

use super::{Element, element, parse};
use crate::error::ErrorKind;
use crate::report::CertInfo;
use crate::tls::TlsCx;

/// The longest a field's text may grow (`CURL_X509_STR_MAX`).
const MOST: usize = 100_000;

/// The names of the identifiers C knows (`OIDtable`).
const OIDS: &[(&[u8], &[u8])] = &[
    (b"1.2.840.10040.4.1", b"dsa"),
    (b"1.2.840.10040.4.3", b"dsa-with-sha1"),
    (b"1.2.840.10045.2.1", b"ecPublicKey"),
    (b"1.2.840.10045.3.0.1", b"c2pnb163v1"),
    (b"1.2.840.10045.4.1", b"ecdsa-with-SHA1"),
    (b"1.2.840.10045.4.3.1", b"ecdsa-with-SHA224"),
    (b"1.2.840.10045.4.3.2", b"ecdsa-with-SHA256"),
    (b"1.2.840.10045.4.3.3", b"ecdsa-with-SHA384"),
    (b"1.2.840.10045.4.3.4", b"ecdsa-with-SHA512"),
    (b"1.2.840.10046.2.1", b"dhpublicnumber"),
    (b"1.2.840.113549.1.1.1", b"rsaEncryption"),
    (b"1.2.840.113549.1.1.2", b"md2WithRSAEncryption"),
    (b"1.2.840.113549.1.1.4", b"md5WithRSAEncryption"),
    (b"1.2.840.113549.1.1.5", b"sha1WithRSAEncryption"),
    (b"1.2.840.113549.1.1.10", b"RSASSA-PSS"),
    (b"1.2.840.113549.1.1.14", b"sha224WithRSAEncryption"),
    (b"1.2.840.113549.1.1.11", b"sha256WithRSAEncryption"),
    (b"1.2.840.113549.1.1.12", b"sha384WithRSAEncryption"),
    (b"1.2.840.113549.1.1.13", b"sha512WithRSAEncryption"),
    (b"1.2.840.113549.2.2", b"md2"),
    (b"1.2.840.113549.2.5", b"md5"),
    (b"1.3.14.3.2.26", b"sha1"),
    (b"2.5.4.3", b"CN"),
    (b"2.5.4.4", b"SN"),
    (b"2.5.4.5", b"serialNumber"),
    (b"2.5.4.6", b"C"),
    (b"2.5.4.7", b"L"),
    (b"2.5.4.8", b"ST"),
    (b"2.5.4.9", b"streetAddress"),
    (b"2.5.4.10", b"O"),
    (b"2.5.4.11", b"OU"),
    (b"2.5.4.12", b"title"),
    (b"2.5.4.13", b"description"),
    (b"2.5.4.17", b"postalCode"),
    (b"2.5.4.41", b"name"),
    (b"2.5.4.42", b"givenName"),
    (b"2.5.4.43", b"initials"),
    (b"2.5.4.44", b"generationQualifier"),
    (b"2.5.4.45", b"X500UniqueIdentifier"),
    (b"2.5.4.46", b"dnQualifier"),
    (b"2.5.4.65", b"pseudonym"),
    (b"1.2.840.113549.1.9.1", b"emailAddress"),
    (b"2.5.4.72", b"role"),
    (b"2.5.29.17", b"subjectAltName"),
    (b"2.5.29.18", b"issuerAltName"),
    (b"2.5.29.19", b"basicConstraints"),
    (b"2.16.840.1.101.3.4.2.4", b"sha224"),
    (b"2.16.840.1.101.3.4.2.1", b"sha256"),
    (b"2.16.840.1.101.3.4.2.2", b"sha384"),
    (b"2.16.840.1.101.3.4.2.3", b"sha512"),
    (b"1.2.840.113549.1.9.2", b"unstructuredName"),
];

const BOOLEAN: u8 = 1;
const INTEGER: u8 = 2;
const BIT_STRING: u8 = 3;
const OCTET_STRING: u8 = 4;
const NULL: u8 = 5;
const OBJECT_IDENTIFIER: u8 = 6;
const ENUMERATED: u8 = 10;
const UTF8_STRING: u8 = 12;
const NUMERIC_STRING: u8 = 18;
const PRINTABLE_STRING: u8 = 19;
const TELETEX_STRING: u8 = 20;
const IA5_STRING: u8 = 22;
const UTC_TIME: u8 = 23;
const GENERALIZED_TIME: u8 = 24;
const VISIBLE_STRING: u8 = 26;
const UNIVERSAL_STRING: u8 = 28;
const BMP_STRING: u8 = 30;

/// Text grown no longer than `most`, `MOST` but in tests (C's `dynbuf`
/// of that size).
struct Out {
    text: Vec<u8>,
    /// Why a write failed, `fmt::Write` saying only that it did.
    failed: Option<ErrorKind>,
    most: usize,
}

impl Default for Out {
    fn default() -> Out {
        Out {
            text: Vec::new(),
            failed: None,
            most: MOST,
        }
    }
}

type Res = Result<(), ErrorKind>;

const BAD: ErrorKind = ErrorKind::BadFunctionArgument;

impl Out {
    fn add(&mut self, bytes: &[u8]) -> Res {
        if self.text.len() + bytes.len() + 1 > self.most {
            return Err(ErrorKind::TooLarge);
        }
        self.text
            .try_extend_from_slice(bytes)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)
    }

    fn addf(&mut self, args: fmt::Arguments<'_>) -> Res {
        match self.write_fmt(args) {
            Ok(()) => Ok(()),
            Err(fmt::Error) => Err(self.failed.take().unwrap_or(ErrorKind::OutOfMemory)),
        }
    }

    fn reset(&mut self) {
        self.text.clear();
    }
}

impl fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.add(s.as_bytes()).map_err(|kind| {
            self.failed = Some(kind);
            fmt::Error
        })
    }
}

/// `bool2str`.
fn boolean(out: &mut Out, b: &[u8]) -> Res {
    match b {
        [0xff] => out.add(b"TRUE"),
        [0x00] => out.add(b"FALSE"),
        _ => Err(BAD),
    }
}

/// `octet2str`: each byte in hex, a colon after it.
fn octets(out: &mut Out, b: &[u8]) -> Res {
    for &byte in b {
        out.addf(format_args!("{byte:02x}:"))?;
    }
    Ok(())
}

/// `bit2str`: the bytes after the count of unused bits.
fn bits(out: &mut Out, b: &[u8]) -> Res {
    match b.split_first() {
        Some((&unused, rest)) if unused <= 7 => octets(out, rest),
        _ => Err(BAD),
    }
}

/// `int2str`: small values in decimal, larger ones in hex, more than
/// four bytes as octets.
fn integer(out: &mut Out, b: &[u8]) -> Res {
    if b.is_empty() {
        return Err(BAD);
    }
    if b.len() > 4 {
        return octets(out, b);
    }
    let mut u: u32 = if b[0] & 0x80 != 0 { !0 } else { 0 };
    for &byte in b {
        u = (u << 8) | u32::from(byte);
    }
    let s = u.cast_signed();
    if s > -10000 && s < 10000 {
        out.addf(format_args!("{s}"))
    } else {
        out.addf(format_args!("0x{u:x}"))
    }
}

/// `utf8asn1str`: a string of the type's characters, as UTF-8.
fn string(out: &mut Out, tag: u8, b: &[u8]) -> Res {
    let size = match tag {
        BMP_STRING => 2,
        UNIVERSAL_STRING => 4,
        NUMERIC_STRING | PRINTABLE_STRING | TELETEX_STRING | IA5_STRING | VISIBLE_STRING
        | UTF8_STRING => 1,
        _ => return Err(BAD),
    };
    if !b.len().is_multiple_of(size) {
        return Err(BAD);
    }
    if tag == UTF8_STRING {
        return out.add(b);
    }
    for ch in b.chunks_exact(size) {
        let mut wc = ch.iter().fold(0u32, |w, &c| (w << 8) | u32::from(c));
        let mut buf = [0u8; 4];
        let mut n = 1;
        // C's arithmetic, kept: it writes surrogates as they come.
        if wc >= 0x80 {
            if wc >= 0x800 {
                if wc >= 0x1_0000 {
                    if wc >= 0x20_0000 {
                        return Err(ErrorKind::WeirdServerReply);
                    }
                    buf[3] = 0x80 | (wc & 0x3f) as u8;
                    wc = (wc >> 6) | 0x1_0000;
                    n += 1;
                }
                buf[2] = 0x80 | (wc & 0x3f) as u8;
                wc = (wc >> 6) | 0x800;
                n += 1;
            }
            buf[1] = 0x80 | (wc & 0x3f) as u8;
            wc = (wc >> 6) | 0xc0;
            n += 1;
        }
        buf[0] = wc as u8;
        out.add(&buf[..n])?;
    }
    Ok(())
}

/// `encodeOID`: an identifier's numbers, dotted.
fn encode_oid(out: &mut Out, b: &[u8]) -> Res {
    let Some((&first, mut rest)) = b.split_first() else {
        return Err(BAD);
    };
    let mut y = u32::from(first);
    let x = if y <= 80 { y / 40 } else { 2 };
    out.addf(format_args!("{x}"))?;
    if y & 0x80 != 0 {
        let mut t = y & 0x7f;
        if t == 0 {
            return Err(BAD);
        }
        loop {
            let Some((&next, r)) = rest.split_first() else {
                return Err(BAD);
            };
            if t & 0xfe00_0000 != 0 {
                return Err(BAD);
            }
            rest = r;
            y = u32::from(next);
            t = (t << 7) | (y & 0x7f);
            if y & 0x80 == 0 {
                break;
            }
        }
        y = t;
    }
    out.addf(format_args!(".{}", y.wrapping_sub(x * 40)))?;
    while !rest.is_empty() {
        let mut x: u32 = 0;
        let mut y: u32 = 0;
        loop {
            if y & 0x80 != 0 && x == 0 {
                return Err(BAD);
            }
            let Some((&next, r)) = rest.split_first() else {
                return Err(BAD);
            };
            if x & 0xfe00_0000 != 0 {
                return Err(BAD);
            }
            rest = r;
            y = u32::from(next);
            x = (x << 7) | (y & 0x7f);
            if y & 0x80 == 0 {
                break;
            }
        }
        out.addf(format_args!(".{x}"))?;
    }
    Ok(())
}

/// `OID2str`: an identifier's name, or its numbers where C knows none.
fn oid(out: &mut Out, b: &[u8]) -> Res {
    if b.is_empty() {
        return Ok(());
    }
    let mut dotted = Out::default();
    encode_oid(&mut dotted, b)?;
    let d = &dotted.text[..];
    match OIDS
        .iter()
        .find(|(num, name)| *num == d || name.eq_ignore_ascii_case(d))
    {
        Some((_, name)) => out.add(name),
        None => out.add(d),
    }
}

/// The bytes before the first zero, as C's `%.*s` writes them.
fn c_str(b: &[u8]) -> &[u8] {
    b.iter().position(|&c| c == 0).map_or(b, |z| &b[..z])
}

/// `GTime2str`: a generalized time as `YYYY-MM-DD hh:mm:ss[.f] zone`.
fn gtime(out: &mut Out, b: &[u8]) -> Res {
    let digits = b.iter().take_while(|c| c.is_ascii_digit()).count();
    let (sec1, sec2) = match digits.checked_sub(12) {
        Some(0) => (b'0', b'0'),
        Some(1) => (b'0', b[digits - 1]),
        Some(2) => (b[digits - 2], b[digits - 1]),
        _ => return Err(BAD),
    };
    let mut tzp = digits;
    let mut frac: &[u8] = &[];
    if matches!(b.get(digits), Some(b'.' | b',')) {
        let start = digits + 1;
        let n = b[start..].iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return Err(BAD);
        }
        tzp = start + n;
        frac = &b[start..tzp];
        while let [rest @ .., b'0'] = frac {
            frac = rest;
        }
    }
    let (sep, tz): (&[u8], &[u8]) = match b.get(tzp) {
        None => (b"", b""),
        Some(b'Z') => (b" ", b"GMT"),
        Some(b'+' | b'-') => (b" UTC", &b[tzp..]),
        Some(_) => (b" ", &b[tzp..]),
    };
    out.add(&b[..4])?;
    out.add(b"-")?;
    out.add(&b[4..6])?;
    out.add(b"-")?;
    out.add(&b[6..8])?;
    out.add(b" ")?;
    out.add(&b[8..10])?;
    out.add(b":")?;
    out.add(&b[10..12])?;
    out.add(b":")?;
    out.add(&[sec1, sec2])?;
    if !frac.is_empty() {
        out.add(b".")?;
        out.add(frac)?;
    }
    out.add(sep)?;
    out.add(c_str(tz))
}

/// `UTime2str`: a UTC time as `YYYY-MM-DD hh:mm:ss zone`, its two-digit
/// year in 1950 to 2049.
fn utime(out: &mut Out, b: &[u8]) -> Res {
    let digits = b.iter().take_while(|c| c.is_ascii_digit()).count();
    let sec: &[u8] = match digits.checked_sub(10) {
        Some(0) => b"00",
        Some(2) => &b[10..12],
        _ => return Err(BAD),
    };
    let tz: &[u8] = match b.get(digits) {
        None => return Err(BAD),
        Some(b'Z') => b"GMT",
        Some(_) => &b[digits..],
    };
    let century = if b[0] >= b'5' { 19 } else { 20 };
    out.addf(format_args!("{century}"))?;
    out.add(&b[..2])?;
    out.add(b"-")?;
    out.add(&b[2..4])?;
    out.add(b"-")?;
    out.add(&b[4..6])?;
    out.add(b" ")?;
    out.add(&b[6..8])?;
    out.add(b":")?;
    out.add(&b[8..10])?;
    out.add(b":")?;
    out.add(sec)?;
    out.add(b" ")?;
    out.add(c_str(tz))
}

/// `ASN1tostr`: an element of a simple type as text.
fn text(out: &mut Out, e: &Element<'_>) -> Res {
    if e.constructed {
        return Err(BAD);
    }
    let b = e.content;
    match e.tag {
        BOOLEAN => boolean(out, b),
        INTEGER | ENUMERATED => integer(out, b),
        BIT_STRING => bits(out, b),
        OCTET_STRING => octets(out, b),
        NULL => out.add(&[0]),
        OBJECT_IDENTIFIER => oid(out, b),
        UTC_TIME => utime(out, b),
        GENERALIZED_TIME => gtime(out, b),
        UTF8_STRING | NUMERIC_STRING | PRINTABLE_STRING | TELETEX_STRING | IA5_STRING
        | VISIBLE_STRING | UNIVERSAL_STRING | BMP_STRING => string(out, e.tag, b),
        _ => Err(BAD),
    }
}

/// `encodeDN`: a distinguished name as `CN=a, O=b` (`/` before a long
/// name).
fn name(out: &mut Out, dn: &Element<'_>) -> Res {
    let mut added = false;
    let mut rdns = dn.content;
    while !rdns.is_empty() {
        let (rdn, r) = element(rdns).ok_or(BAD)?;
        rdns = r;
        let mut atvs = rdn.content;
        while !atvs.is_empty() {
            let (atv, r) = element(atvs).ok_or(BAD)?;
            atvs = r;
            let (id, r) = element(atv.content).ok_or(BAD)?;
            let (value, _) = element(r).ok_or(BAD)?;
            let mut label = Out::default();
            text(&mut label, &id)?;
            if label.text.is_empty() {
                return Err(BAD);
            }
            let label = c_str(&label.text);
            if added {
                let upper = label.iter().take_while(|c| c.is_ascii_uppercase()).count();
                out.add(if upper > 2 { b"/" } else { b", " })?;
            }
            out.add(label)?;
            out.add(b"=")?;
            text(out, &value)?;
            added = true;
        }
    }
    Ok(())
}

/// `dumpAlgo`: an algorithm identifier's name, and its parameters.
fn algorithm<'a>(out: &mut Out, b: &'a [u8]) -> Result<Option<Element<'a>>, ErrorKind> {
    let (id, rest) = element(b).ok_or(BAD)?;
    let param = if rest.is_empty() {
        None
    } else {
        Some(element(rest).ok_or(BAD)?.0)
    };
    oid(out, id.content)?;
    Ok(param)
}

/// Where a certificate's lines go: the transfer's chain, and for the
/// leaf the verbose lines too (`ssl_push_certinfo_dyn`).
struct Sink<'c, 'x> {
    cx: &'c mut TlsCx<'x>,
    info: &'c mut CertInfo,
    cert: usize,
}

impl Sink<'_, '_> {
    fn push(&mut self, label: &str, value: &[u8]) -> Res {
        self.info
            .push(self.cert, label.as_bytes(), value)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        if self.cert == 0 {
            let shown = Shown(c_str(value));
            self.cx.info(format_args!("   {label}: {shown}"));
        }
        Ok(())
    }

    /// `ssl_push_certinfo`: the line alone, said nowhere.
    fn push_quiet(&mut self, label: &str, value: &[u8]) -> Res {
        self.info
            .push(self.cert, label.as_bytes(), value)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)
    }

    /// `do_pubkey_field`.
    fn field(&mut self, label: &str, e: &Element<'_>) -> Res {
        let mut out = Out::default();
        text(&mut out, e)?;
        self.push(label, &out.text)
    }

    /// `do_pubkey`: the key's lines, as its algorithm has them.
    fn key(&mut self, algo: &[u8], param: Option<Element<'_>>, key: &Element<'_>) -> Option<()> {
        let param = param.map_or(&[][..], |p| p.content);
        if algo.eq_ignore_ascii_case(b"ecPublicKey") {
            let n = key.content.len();
            if n < 2 {
                return None;
            }
            let bits = (n - 2) * 4;
            if self.cert == 0 {
                self.cx
                    .info(format_args!("   ECC Public Key ({bits} bits)"));
            }
            let mut v = Out::default();
            v.addf(format_args!("{bits}")).ok()?;
            self.push_quiet("ECC Public Key", &v.text).ok()?;
            return self.field("ecPublicKey", key).ok();
        }
        let (pk, _) = element(key.content.get(1..)?)?;
        if algo.eq_ignore_ascii_case(b"rsaEncryption") {
            let (mut n, after) = element(pk.content)?;
            let zeros = n.content.iter().take_while(|&&b| b == 0).count();
            let stripped = &n.content[zeros..];
            let mut len = stripped.len() * 8;
            if let Some(&top) = stripped.first() {
                let mut i = u32::from(top);
                while i & 0x80 == 0 {
                    len -= 1;
                    i <<= 1;
                }
            }
            if len > 32 {
                n.content = stripped;
            }
            if self.cert == 0 {
                self.cx.info(format_args!("   RSA Public Key ({len} bits)"));
            }
            let mut v = Out::default();
            v.addf(format_args!("{len}")).ok()?;
            self.push_quiet("RSA Public Key", &v.text).ok()?;
            self.field("rsa(n)", &n).ok()?;
            let (e, _) = element(after)?;
            self.field("rsa(e)", &e).ok()?;
        } else if algo.eq_ignore_ascii_case(b"dsa") {
            if let Some((p, r)) = element(param) {
                self.field("dsa(p)", &p).ok()?;
                if let Some((q, r)) = element(r) {
                    self.field("dsa(q)", &q).ok()?;
                    if let Some((g, _)) = element(r) {
                        self.field("dsa(g)", &g).ok()?;
                        self.field("dsa(pub_key)", &pk).ok()?;
                    }
                }
            }
        } else if algo.eq_ignore_ascii_case(b"dhpublicnumber")
            && let Some((p, r)) = element(param)
        {
            self.field("dh(p)", &p).ok()?;
            if let Some((g, _)) = element(r) {
                self.field("dh(g)", &g).ok()?;
                self.field("dh(pub_key)", &pk).ok()?;
            }
        }
        Some(())
    }
}

/// Bytes in a verbose line, as C's `%s` writes them.
struct Shown<'a>(&'a [u8]);

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            for &b in chunk.invalid() {
                f.write_char(char::from(b))?;
            }
        }
        Ok(())
    }
}

/// The fields of the DER certificate `der`, put in `info` as certificate
/// `cert` of the chain, the leaf's said in the verbose lines too
/// (`Curl_extract_certinfo`). A certificate that does not read is
/// `PeerFailedVerification`, said by no line; a field that does not
/// convert fails the chain, as C says.
pub fn certinfo(cx: &mut TlsCx<'_>, info: &mut CertInfo, cert: usize, der: &[u8]) -> Res {
    let Some(c) = parse(der) else {
        return Err(ErrorKind::PeerFailedVerification);
    };
    let mut sink = Sink { cx, info, cert };
    fields(&mut sink, &c, der).map_err(|kind| {
        sink.cx
            .fail(kind, format_args!("Failed extracting certificate chain"))
    })
}

fn fields(sink: &mut Sink<'_, '_>, c: &super::Certificate<'_>, der: &[u8]) -> Res {
    let mut out = Out::default();
    name(&mut out, &c.subject)?;
    sink.push("Subject", &out.text)?;
    out.reset();
    name(&mut out, &c.issuer)?;
    sink.push("Issuer", &out.text)?;
    out.reset();
    let version = c.version.iter().fold(0u32, |v, &b| (v << 8) | u32::from(b));
    out.addf(format_args!("{version:x}"))?;
    sink.push("Version", &out.text)?;
    out.reset();
    text(&mut out, &c.serial)?;
    sink.push("Serial Number", &out.text)?;
    out.reset();
    algorithm(&mut out, c.signature_algorithm.content)?;
    sink.push("Signature Algorithm", &out.text)?;
    out.reset();
    text(&mut out, &c.not_before)?;
    sink.push("Start Date", &out.text)?;
    out.reset();
    text(&mut out, &c.not_after)?;
    sink.push("Expire Date", &out.text)?;
    out.reset();
    let param = algorithm(&mut out, c.public_key_algorithm.content)?;
    sink.push("Public Key Algorithm", &out.text)?;
    // C reads the name as a C string.
    let algo = c_str(&out.text);
    if sink.key(algo, param, &c.public_key).is_none() {
        return Err(ErrorKind::OutOfMemory);
    }
    out.reset();
    text(&mut out, &c.signature)?;
    sink.push("Signature", &out.text)?;
    out.reset();
    let mut b64 = Vec::new();
    crate::base64::encode(der, &mut b64).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    out.add(b"-----BEGIN CERTIFICATE-----\n")?;
    for line in b64.chunks(64) {
        out.add(line)?;
        out.add(b"\n")?;
    }
    out.add(b"-----END CERTIFICATE-----\n")?;
    sink.push("Cert", &out.text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conv(f: impl FnOnce(&mut Out) -> Res) -> Result<String, ErrorKind> {
        let mut out = Out::default();
        f(&mut out)?;
        Ok(String::from_utf8(out.text).unwrap())
    }

    /// The result a C unit test's row expects, by its `CURLE_*` name.
    fn expected(code: &crate::c_source::Value) -> Result<(), ErrorKind> {
        match code.word() {
            "CURLE_OK" => Ok(()),
            "CURLE_BAD_FUNCTION_ARGUMENT" => Err(BAD),
            "CURLE_WEIRD_SERVER_REPLY" => Err(ErrorKind::WeirdServerReply),
            "CURLE_TOO_LARGE" => Err(ErrorKind::TooLarge),
            other => panic!("{other}"),
        }
    }

    /// What `f` writes into a buffer of `most` bytes, to its first zero
    /// byte as C's test reads it, or why it failed.
    fn written(most: usize, f: impl FnOnce(&mut Out) -> Res) -> Result<Vec<u8>, ErrorKind> {
        let mut out = Out {
            most,
            ..Out::default()
        };
        f(&mut out)?;
        let end = out
            .text
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(out.text.len());
        out.text.truncate(end);
        Ok(out.text)
    }

    /// unit1656's table, read from its source: generalized times as
    /// `GTime2str` writes them, or refused.
    #[test]
    fn unit1656_generalized_times() {
        let rows =
            crate::c_source::table("tests/unit/unit1656.c", "test_specs[]", |c| panic!("{c}"));
        assert!(rows.len() > 20, "the rows were read");
        for row in rows {
            let [input, want, code] = row.group() else {
                panic!("{row:?}")
            };
            let got = written(MOST, |o| gtime(o, input.str()));
            let want = expected(code).map(|()| want.str().to_vec());
            assert_eq!(got, want, "{}", input.str().escape_ascii());
        }
    }

    /// unit1666's table, read from its source: identifiers dotted as
    /// `encodeOID` writes them into C's buffer of 100 bytes, or refused.
    #[test]
    fn unit1666_identifiers() {
        let rows =
            crate::c_source::table("tests/unit/unit1666.c", "test_specs[]", |c| panic!("{c}"));
        assert!(rows.len() > 60, "the rows were read");
        for row in rows {
            let (oid, dotted, code) = match row.group() {
                // `OID(x)`: the string, its length.
                [oid, dotted, code] => (oid.call("OID")[0].str().to_vec(), dotted, code),
                [oid, size, dotted, code] => (oid.sized(size), dotted, code),
                other => panic!("{other:?}"),
            };
            let oid = &oid[..];
            let got = written(100, |o| encode_oid(o, oid));
            let want = expected(code).map(|()| dotted.str().to_vec());
            assert_eq!(got, want, "{}", oid.escape_ascii());
        }
    }

    /// unit1667's table, read from its source: an element of each simple
    /// type, by its tag, as `ASN1tostr` writes it into C's buffer of 40
    /// bytes, or refused. The tags are lib/vtls/x509asn1.h's.
    #[test]
    fn unit1667_simple_types() {
        let header = crate::c_source::source("lib/vtls/x509asn1.h");
        let tag = |w: &crate::c_source::Value| -> u8 {
            let w = w.word();
            let Some(name) = w.strip_prefix("CURL_ASN1_") else {
                return u8::try_from(w.parse::<u32>().unwrap()).unwrap();
            };
            let line = header
                .lines()
                .find_map(|l| {
                    let rest = l.strip_prefix("#define CURL_ASN1_")?.strip_prefix(name)?;
                    rest.starts_with(' ').then(|| rest.trim().to_owned())
                })
                .unwrap_or_else(|| panic!("no CURL_ASN1_{name}"));
            line.parse().unwrap()
        };
        let rows =
            crate::c_source::table("tests/unit/unit1667.c", "test_specs[]", |c| panic!("{c}"));
        assert!(rows.len() > 90, "the rows were read");
        for row in rows {
            let [t, asn1, size, want, code] = row.group() else {
                panic!("{row:?}")
            };
            let content = &asn1.sized(size)[..];
            let e = Element {
                whole: content,
                content,
                class: 0,
                tag: tag(t),
                constructed: false,
            };
            let got = written(40, |o| text(o, &e));
            let want = expected(code).map(|()| want.str().to_vec());
            assert_eq!(got, want, "tag {} {}", e.tag, content.escape_ascii());
        }
    }

    /// unit1676: a certificate of a Diffie-Hellman key, read from its
    /// source, gives its prime, its generator and its public value each
    /// its own line: g read after p, not p again.
    #[test]
    fn unit1676_dh_key() {
        let bytes = crate::c_source::table("tests/unit/unit1676.c", "cert[]", |c| panic!("{c}"));
        let der: Vec<u8> = bytes
            .iter()
            .map(|b| u8::try_from(b.int()).unwrap())
            .collect();
        assert_eq!(der.len(), 136, "the certificate was read");
        let identity = curl_alloc::TryArc::try_new(crate::tls::tests::identity(|_| {})).unwrap();
        let mut notes = crate::tls::Notes::default();
        let mut info = CertInfo::new(1).unwrap();
        TlsCx::testing(&identity, b"localhost", &mut notes, |_, cx| {
            certinfo(cx, &mut info, 0, &der)
        })
        .unwrap();
        let value = |label: &str| {
            let label = format!("{label}:");
            let lines = &info.certs()[0];
            let line = lines.iter().find(|l| l.starts_with(label.as_bytes()));
            line.map(|l| String::from_utf8(l[label.len()..].to_vec()).unwrap())
        };
        assert_eq!(value("dh(p)").as_deref(), Some("17"));
        assert_eq!(value("dh(g)").as_deref(), Some("34"));
        assert_eq!(value("dh(pub_key)").as_deref(), Some("51"));
    }

    /// unit1651: curl.se's certificate of 2018 is read whole, each of its
    /// first 45 bytes set in turn to every 17th value is read without a
    /// crash, and a key whose exponent is a UniversalString holding
    /// 0x200000, no Unicode code point, fails the read.
    #[test]
    fn unit1651_certinfo_survives_bad_bytes() {
        let read = |name: &str| -> Vec<u8> {
            crate::c_source::table("tests/unit/unit1651.c", name, |c| panic!("{c}"))
                .iter()
                .map(|b| u8::try_from(b.int()).unwrap())
                .collect()
        };
        let mut cert = read("cert[] =");
        let badkey = read("badkey[] =");
        assert_eq!(cert.len(), 0x0F5B + 4, "the certificate was read");
        assert_eq!(badkey.len(), 0x019B + 4, "the bad key was read");
        let identity = curl_alloc::TryArc::try_new(crate::tls::tests::identity(|_| {})).unwrap();
        let mut notes = crate::tls::Notes::default();
        let extract = |der: &[u8], notes: &mut crate::tls::Notes| {
            let mut info = CertInfo::new(1).unwrap();
            TlsCx::testing(&identity, b"localhost", notes, |_, cx| {
                certinfo(cx, &mut info, 0, der)
            })
        };
        extract(&cert, &mut notes).unwrap();
        for byte in (1..255).step_by(17) {
            for i in 0..45 {
                let backup = cert[i];
                cert[i] = byte;
                // Whether it reads is not asked, as C's `(void)` says.
                let _ = extract(&cert, &mut notes);
                cert[i] = backup;
            }
        }
        assert!(extract(&badkey, &mut notes).is_err());
    }

    /// Identifiers are dotted, named where C names them; padding is
    /// refused (C's unit test 1666).
    #[test]
    fn identifiers_read_as_c_reads_them() {
        assert_eq!(
            conv(|o| oid(o, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])).unwrap(),
            "sha256WithRSAEncryption"
        );
        assert_eq!(
            conv(|o| encode_oid(o, &[0x55, 0x04, 0x03])).unwrap(),
            "2.5.4.3"
        );
        assert_eq!(conv(|o| encode_oid(o, &[0x2b, 0x80, 0x01])), Err(BAD));
        assert_eq!(conv(|o| encode_oid(o, &[0x80, 0x01])), Err(BAD));
        assert_eq!(conv(|o| encode_oid(o, &[0x81, 0x00])).unwrap(), "2.48");
    }

    /// Times are written as C writes them (C's unit test 1656).
    #[test]
    fn times_read_as_c_reads_them() {
        assert_eq!(
            conv(|o| gtime(o, b"20190102030405.500Z")).unwrap(),
            "2019-01-02 03:04:05.5 GMT"
        );
        assert_eq!(
            conv(|o| gtime(o, b"201901020304+0100")).unwrap(),
            "2019-01-02 03:04:00 UTC+0100"
        );
        assert_eq!(conv(|o| gtime(o, b"2019010203")), Err(BAD));
        assert_eq!(
            conv(|o| utime(o, b"491231235959Z")).unwrap(),
            "2049-12-31 23:59:59 GMT"
        );
        assert_eq!(
            conv(|o| utime(o, b"5001010000Z")).unwrap(),
            "1950-01-01 00:00:00 GMT"
        );
        assert_eq!(conv(|o| utime(o, b"500101000000")), Err(BAD));
    }

    /// Integers, strings and booleans convert as C converts them.
    #[test]
    fn values_read_as_c_reads_them() {
        assert_eq!(conv(|o| integer(o, &[0x01, 0x00])).unwrap(), "256");
        assert_eq!(conv(|o| integer(o, &[0xff])).unwrap(), "-1");
        assert_eq!(
            conv(|o| integer(o, &[0x01, 0x00, 0x00])).unwrap(),
            "0x10000"
        );
        assert_eq!(
            conv(|o| integer(o, &[1, 2, 3, 4, 5])).unwrap(),
            "01:02:03:04:05:"
        );
        assert_eq!(
            conv(|o| string(o, BMP_STRING, &[0x20, 0xac])).unwrap(),
            "\u{20ac}"
        );
        assert_eq!(conv(|o| string(o, IA5_STRING, &[0xe9])).unwrap(), "\u{e9}");
        assert_eq!(conv(|o| string(o, BMP_STRING, &[0x20])), Err(BAD));
        assert_eq!(conv(|o| boolean(o, &[0x01])), Err(BAD));
    }
}
