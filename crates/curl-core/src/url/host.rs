//! Host names and numeric addresses in URLs, as `lib/urlapi.c` checks and
//! normalises them, with the address parsing and formatting of
//! `lib/curlx/inet_pton.c` and `inet_ntop.c`, whose output URLs show.

use super::Bytes;
use super::encode::{copy, push};
use crate::error::UrlErrorKind;

/// Bytes never allowed in a host name: `" \r\n\t/:#?!@{}[]\$'"^`*<>=;,+&()%|`
/// and the other control bytes. Bytes from 0x80 are allowed, for IDN.
fn invalid_host_byte(b: u8) -> bool {
    b < 0x80 && (b <= b' ' || b"/:#?!@{}[]\\$'\"^`*<>=;,+&()%|\x7f".contains(&b))
}

/// Check a host name that is not an IPv6 address (`hostname_check`).
pub(super) fn check_name(host: &[u8]) -> Result<(), UrlErrorKind> {
    if host.iter().any(|&b| invalid_host_byte(b)) || host.ends_with(b"..") || host == b"." {
        return Err(UrlErrorKind::BadHostname);
    }
    Ok(())
}

/// A number at the start of `s` in `base`, at most `max`, as
/// `curlx_str_number`, `_hex` and `_octal` read it.
fn number(s: &[u8], base: u32, max: u64) -> Result<(u64, &[u8]), Number> {
    let digits = s
        .iter()
        .take_while(|b| (**b as char).is_digit(base))
        .count();
    if digits == 0 {
        return Err(Number::None);
    }
    let mut n: u64 = 0;
    for &d in &s[..digits] {
        n = n * u64::from(base) + u64::from((d as char).to_digit(base).expect("a digit"));
        if n > max {
            return Err(Number::Overflow);
        }
    }
    Ok((n, &s[digits..]))
}

enum Number {
    None,
    Overflow,
}

/// `host` as a dotted IPv4 address if it is one in any of the forms C
/// accepts: one to four parts, each decimal, octal (`0` prefix) or hex
/// (`0x`), the last filling the remaining bytes, and one trailing dot
/// (`ipv4_normalize`).
pub(super) fn ipv4(host: &[u8]) -> Option<[u8; 4]> {
    if !host.first()?.is_ascii_digit() {
        return None;
    }
    let mut parts = [0u32; 4];
    let mut n = 0;
    let mut c = host;
    loop {
        let parsed = match c {
            [b'0', x, rest @ ..] if x.eq_ignore_ascii_case(&b'x') => {
                Some(number(rest, 16, u32::MAX.into()).ok()?)
            }
            [b'0', ..] => number(c, 8, u32::MAX.into()).ok(),
            _ => number(c, 10, u32::MAX.into()).ok(),
        };
        match parsed {
            Some((v, rest)) => {
                parts[n] = u32::try_from(v).expect("at most u32::MAX");
                c = rest;
            }
            // Nothing after a dot at the end: the dot is swallowed.
            None if n > 0 && c.is_empty() && number(c, 10, 0).is_err() => n -= 1,
            None => return None,
        }
        match c {
            [b'.', rest @ ..] if n == 3 => {
                if !rest.is_empty() {
                    return None;
                }
                break;
            }
            [b'.', rest @ ..] => {
                n += 1;
                c = rest;
            }
            [] => break,
            _ => return None,
        }
    }
    let [a, b, c, d] = parts;
    let fits = |v: u32, bits: u32| v < (1 << bits);
    let quad = match n {
        0 => a,
        1 if fits(a, 8) && fits(b, 24) => a << 24 | b,
        2 if fits(a, 8) && fits(b, 8) && fits(c, 16) => a << 24 | b << 16 | c,
        3 if [a, b, c, d].iter().all(|&p| fits(p, 8)) => a << 24 | b << 16 | c << 8 | d,
        _ => return None,
    };
    Some(quad.to_be_bytes())
}

/// Dotted decimal, as `inet_ntop4` and `ipv4_normalize` print it.
pub(super) fn ipv4_text(out: &mut Bytes, a: [u8; 4]) -> Result<(), UrlErrorKind> {
    let mut buf = [0u8; 3];
    for (i, octet) in a.into_iter().enumerate() {
        if i > 0 {
            push(out, b".")?;
        }
        push(out, decimal(&mut buf, octet))?;
    }
    Ok(())
}

fn decimal(buf: &mut [u8; 3], mut v: u8) -> &[u8] {
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + v % 10;
        v /= 10;
        if v == 0 {
            return &buf[at..];
        }
    }
}

/// Whether `host` is an IPv4 or IPv6 address, not a name
/// (`Curl_host_is_ipnum`).
pub(crate) fn is_ip_address(host: &[u8]) -> bool {
    pton4(host).is_some() || pton6(host).is_some()
}

/// An IPv4 address of exactly four decimal octets (`inet_pton4`).
pub(crate) fn pton4(s: &[u8]) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    // The octet being read, and how many have started.
    let mut at = 0;
    let mut octets = 0;
    let mut saw_digit = false;
    for &ch in s {
        if ch.is_ascii_digit() {
            if saw_digit && out[at] == 0 {
                // A leading zero.
                return None;
            }
            out[at] = u8::try_from(u32::from(out[at]) * 10 + u32::from(ch - b'0')).ok()?;
            if !saw_digit {
                octets += 1;
                if octets > 4 {
                    return None;
                }
                saw_digit = true;
            }
        } else if ch == b'.' && saw_digit {
            if octets == 4 {
                return None;
            }
            at += 1;
            saw_digit = false;
        } else {
            return None;
        }
    }
    (octets == 4).then_some(out)
}

/// An IPv6 address (`inet_pton6`).
pub(crate) fn pton6(s: &[u8]) -> Option<[u8; 16]> {
    let mut tmp = [0u8; 16];
    let mut tp = 0;
    let mut colon: Option<usize> = None;
    let mut src = s;
    if let [b':', rest @ ..] = src {
        if rest.first() != Some(&b':') {
            return None;
        }
        src = rest;
    }
    let mut token = src;
    let mut saw_xdigit = 0;
    let mut val: u32 = 0;
    let mut i = 0;
    while i < src.len() {
        let ch = src[i];
        i += 1;
        if let Some(d) = (ch as char).to_digit(16) {
            val = val << 4 | d;
            saw_xdigit += 1;
            if saw_xdigit > 4 {
                return None;
            }
            continue;
        }
        if ch == b':' {
            token = &src[i..];
            if saw_xdigit == 0 {
                if colon.is_some() {
                    return None;
                }
                colon = Some(tp);
                continue;
            }
            // Every word is two bytes, so a full address is exactly 16.
            if i == src.len() || tp == 16 {
                return None;
            }
            tmp[tp..tp + 2].copy_from_slice(&(val as u16).to_be_bytes());
            tp += 2;
            saw_xdigit = 0;
            val = 0;
            continue;
        }
        if ch == b'.'
            && tp + 4 <= 16
            && let Some(v4) = pton4(token)
        {
            tmp[tp..tp + 4].copy_from_slice(&v4);
            tp += 4;
            saw_xdigit = 0;
            break;
        }
        return None;
    }
    if saw_xdigit > 0 {
        if tp + 2 > 16 {
            return None;
        }
        tmp[tp..tp + 2].copy_from_slice(&(val as u16).to_be_bytes());
        tp += 2;
    }
    if let Some(at) = colon {
        if tp == 16 {
            return None;
        }
        let n = tp - at;
        tmp.copy_within(at..tp, 16 - n);
        tmp[at..16 - n].fill(0);
        tp = 16;
    }
    (tp == 16).then_some(tmp)
}

/// An IPv6 address as `inet_ntop6` prints it: lowercase hex, the longest
/// run of two or more zero words as `::`, and an embedded IPv4 address for
/// the mapped and compatible forms.
fn ntop6(out: &mut Bytes, a: [u8; 16]) -> Result<(), UrlErrorKind> {
    let words: [u16; 8] = std::array::from_fn(|i| u16::from_be_bytes([a[2 * i], a[2 * i + 1]]));
    let mut best: Option<(usize, usize)> = None;
    let mut cur: Option<(usize, usize)> = None;
    for (i, &w) in words.iter().enumerate() {
        if w == 0 {
            cur = Some(cur.map_or((i, 1), |(b, l)| (b, l + 1)));
        } else if let Some(c) = cur.take()
            && best.is_none_or(|b| c.1 > b.1)
        {
            best = Some(c);
        }
    }
    if let Some(c) = cur
        && best.is_none_or(|b| c.1 > b.1)
    {
        best = Some(c);
    }
    let best = best.filter(|b| b.1 >= 2);
    for (i, &w) in words.iter().enumerate() {
        if let Some((base, len)) = best
            && (base..base + len).contains(&i)
        {
            if i == base {
                push(out, b":")?;
            }
            continue;
        }
        if i > 0 {
            push(out, b":")?;
        }
        if i == 6
            && best.is_some_and(|(base, len)| {
                base == 0 && (len == 6 || (len == 5 && words[5] == 0xffff))
            })
        {
            return ipv4_text(out, [a[12], a[13], a[14], a[15]]);
        }
        const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
        let digits =
            [w >> 12, (w >> 8) & 0xf, (w >> 4) & 0xf, w & 0xf].map(|d| LOWER_HEX[usize::from(d)]);
        let skip = match w {
            0x1000.. => 0,
            0x100.. => 1,
            0x10.. => 2,
            _ => 3,
        };
        push(out, &digits[skip..])?;
    }
    if best.is_some_and(|(base, len)| base + len == 8) {
        push(out, b":")?;
    }
    Ok(())
}

/// The length C allows a zone id, its terminating zero excluded.
const MAX_ZONE: usize = 15;

/// Normalise a bracketed IPv6 host in place, taking out its zone id
/// (`ipv6_parse`).
pub(super) fn ipv6(host: &mut Bytes) -> Result<Option<Bytes>, UrlErrorKind> {
    if host.len() < 4 {
        return Err(UrlErrorKind::BadIpv6);
    }
    let inner = &host[1..host.len() - 1];
    let mut len = inner
        .iter()
        .take_while(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
        .count();
    let mut zone = None;
    if len != inner.len() {
        if inner[len] != b'%' {
            return Err(UrlErrorKind::BadIpv6);
        }
        // A zone id, after its `%` or an encoded `%25`.
        let mut z = &host[1 + len + 1..];
        if z.starts_with(b"25") && z.get(2).is_some_and(|&b| b != b']') {
            z = &z[2..];
        }
        let id = z
            .iter()
            .take_while(|&&b| !invalid_host_byte(b) && b != b']')
            .take(MAX_ZONE)
            .count();
        if id == 0 || z.get(id) != Some(&b']') {
            return Err(UrlErrorKind::BadIpv6);
        }
        zone = Some(copy(&z[..id])?);
        host.truncate(1 + len);
        push(host, b"]")?;
        len = host.len() - 2;
    }
    let addr = pton6(&host[1..1 + len]).ok_or(UrlErrorKind::BadIpv6)?;
    let mut text = Bytes::new();
    ntop6(&mut text, addr)?;
    // C formats into the space the address had, and keeps it as written
    // when the normal form is longer.
    if text.len() <= len {
        host.truncate(1);
        push(host, &text)?;
        push(host, b"]")?;
    }
    Ok(zone)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Option<String> {
        ipv4(s.as_bytes()).map(|a| {
            let mut out = Vec::new();
            ipv4_text(&mut out, a).unwrap();
            String::from_utf8(out).unwrap()
        })
    }

    /// The hosts C's `curl_url_get(CURLUPART_HOST)` returns; `None` where C
    /// keeps the host as a name.
    #[test]
    fn ipv4_in_c_forms() {
        assert_eq!(v4("127.0.0.1").as_deref(), Some("127.0.0.1"));
        assert_eq!(v4("0x7f.1").as_deref(), Some("127.0.0.1"));
        assert_eq!(v4("0177.1.1.1").as_deref(), Some("127.1.1.1"));
        assert_eq!(v4("16843009").as_deref(), Some("1.1.1.1"));
        assert_eq!(v4("1.2.3.").as_deref(), Some("1.2.0.3"));
        assert_eq!(v4("1.2.3.4."), Some("1.2.3.4".into()));
        assert_eq!(v4("1.2.3.4.5"), None);
        assert_eq!(v4("256.1.1.1"), None);
        assert_eq!(v4("0x"), None);
        assert_eq!(v4("example.com"), None);
        // A part too large for the bytes it fills.
        for name in ["256.1", "1.16777216", "256.1.1", "1.256.1", "1.1.65536"] {
            assert_eq!(v4(name), None, "{name}");
        }
        assert_eq!(v4("1.16777215").as_deref(), Some("1.255.255.255"));
        assert_eq!(v4("1.1.65535").as_deref(), Some("1.1.255.255"));
    }

    fn v6(s: &str) -> Result<(String, Option<String>), UrlErrorKind> {
        let mut host = s.as_bytes().to_vec();
        let zone = ipv6(&mut host)?;
        Ok((
            String::from_utf8(host).unwrap(),
            zone.map(|z| String::from_utf8(z).unwrap()),
        ))
    }

    /// The hosts C's `curl_url_get(CURLUPART_HOST)` returns.
    #[test]
    fn ipv6_as_c_prints_it() {
        assert_eq!(
            v6("[0:0:0:0:0:FFFF:129.144.52.38]").unwrap().0,
            "[::ffff:129.144.52.38]"
        );
        assert_eq!(v6("[0:0:0:0:0:0:0d01:4403]").unwrap().0, "[::13.1.68.3]");
        assert_eq!(
            v6("[fe80::1%25eth0]").unwrap(),
            ("[fe80::1]".into(), Some("eth0".into()))
        );
        assert_eq!(v6("[1:0:0:2::3:0]").unwrap().0, "[1::2:0:0:3:0]");
        // A single zero word is not shortened.
        assert_eq!(v6("[1:0:2:3:4:5:6:7]").unwrap().0, "[1:0:2:3:4:5:6:7]");
        // Longer once normalised: kept as written.
        assert_eq!(v6("[::ffff:a0a:a0a]").unwrap().0, "[::ffff:a0a:a0a]");
        assert_eq!(v6("[::1%]"), Err(UrlErrorKind::BadIpv6));
        assert_eq!(v6("[1:2:3]"), Err(UrlErrorKind::BadIpv6));
        for bad in [
            "[::1..2.3]",
            "[::.1.2.3.4]",
            "[::1.2.3.4x]",
            "[::1.2.3x4]",
            "[1::2:]",
            "[1:2:3:4:5:6:7:8:9:0]",
        ] {
            assert_eq!(v6(bad), Err(UrlErrorKind::BadIpv6), "{bad}");
        }
    }

    /// `inet_ntop6` itself, below the URL's rule that keeps an address as
    /// written when the normal form is no shorter.
    #[test]
    fn ntop6_as_c_prints_it() {
        let ntop = |s: &str| {
            let mut out = Vec::new();
            ntop6(&mut out, pton6(s.as_bytes()).unwrap()).unwrap();
            String::from_utf8(out).unwrap()
        };
        // The longest run of zero words, the first of equal ones.
        assert_eq!(ntop("1:0:0:2:0:0:0:3"), "1:0:0:2::3");
        assert_eq!(ntop("1:0:0:0:2:0:0:3"), "1::2:0:0:3");
        assert_eq!(ntop("1:0:0:2:0:0:3:4"), "1::2:0:0:3:4");
        // An embedded IPv4 address only for the mapped and compatible forms.
        assert_eq!(ntop("0:0:1:2:3:4:5:6"), "::1:2:3:4:5:6");
        assert_eq!(ntop("::1:2:3"), "::1:2:3");
        assert_eq!(ntop("::ffff:1:2"), "::ffff:0.1.0.2");
    }
}
