//! The proxy a transfer goes through, if any (`lib/proxy.c`): the one the
//! options name, or the one the environment does; none for a host the
//! no-proxy list names. No I/O: the environment is read through the
//! function given.

use std::num::NonZeroU16;

use curl_alloc::OutOfMemory;

use super::{Peer, Scheme};
use crate::error::UrlErrorKind;
use crate::options::ProxyType;
use crate::url::{GetOptions, ParseOptions, Part, Url, pton4, pton6};

/// Whether the no-proxy list `list` names the host `name`, which then goes
/// direct (`proxy_check_noproxy`): `*` names every host; otherwise each
/// name, separated by commas and blanks, names itself and the hosts below
/// it, a leading or trailing dot aside, and each address, with or without
/// a `/bits` prefix length, the addresses in it. The list ends at the
/// first name not followed by a comma.
pub(crate) fn excluded(name: &[u8], list: &[u8]) -> bool {
    if name.is_empty() || list.is_empty() {
        return false;
    }
    if list == b"*" {
        return true;
    }
    enum Kind {
        Host,
        V4,
        V6,
    }
    let kind = if pton4(name).is_some() {
        Kind::V4
    } else if pton6(name).is_some() {
        Kind::V6
    } else {
        Kind::Host
    };
    let name = match kind {
        Kind::Host => name.strip_suffix(b".").unwrap_or(name),
        Kind::V4 | Kind::V6 => name,
    };
    let blank = |b: &u8| *b == b' ' || *b == b'\t';
    let mut p = list;
    while !p.is_empty() {
        p = &p[p.iter().take_while(|b| blank(b)).count()..];
        let len = p.iter().take_while(|&&b| !blank(&b) && b != b',').count();
        let (token, rest) = p.split_at(len);
        if !token.is_empty() {
            let matched = match kind {
                Kind::Host => match_host(token, name),
                Kind::V4 => match_ip(false, token, name),
                Kind::V6 => match_ip(true, token, name),
            };
            if matched {
                return true;
            }
        }
        p = &rest[rest.iter().take_while(|b| blank(b)).count()..];
        if p.first() != Some(&b',') {
            break;
        }
        p = &p[p.iter().take_while(|&&b| b == b',').count()..];
    }
    false
}

/// Whether the name `token` names `name` or a host below it
/// (`match_host`).
fn match_host(token: &[u8], name: &[u8]) -> bool {
    let token = token.strip_suffix(b".").unwrap_or(token);
    let token = token.strip_prefix(b".").unwrap_or(token);
    if token.len() == name.len() {
        return token.eq_ignore_ascii_case(name);
    }
    token.len() < name.len()
        && name[name.len() - token.len() - 1] == b'.'
        && token.eq_ignore_ascii_case(&name[name.len() - token.len()..])
}

/// Whether the address `token`, with its prefix length if it has one,
/// holds the address `name` (`match_ip`).
fn match_ip(v6: bool, token: &[u8], name: &[u8]) -> bool {
    // C copies it to a buffer of 128 bytes first.
    if token.len() >= 128 {
        return false;
    }
    let (net, bits) = match token.iter().position(|&b| b == b'/') {
        Some(at) => match number(&token[at + 1..], 128) {
            Some(bits) => (&token[..at], Some(bits)),
            None => return false,
        },
        None => (token, None),
    };
    if v6 {
        cidr6(name, net, bits)
    } else {
        cidr4(name, net, bits)
    }
}

/// A decimal number of one digit or more and nothing else, no greater
/// than `max` (`curlx_str_number`).
fn number(s: &[u8], max: u32) -> Option<u32> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut n: u32 = 0;
    for &d in s {
        n = n.checked_mul(10)?.checked_add(u32::from(d - b'0'))?;
        if n > max {
            return None;
        }
    }
    Some(n)
}

/// Whether the IPv4 address `ip` is in `net`, of `bits` leading bits, all
/// of them if none (`cidr4_match`).
fn cidr4(ip: &[u8], net: &[u8], bits: Option<u32>) -> bool {
    if bits.is_some_and(|b| b > 32) {
        return false;
    }
    let (Some(ip), Some(net)) = (pton4(ip), pton4(net)) else {
        return false;
    };
    let (ip, net) = (u32::from_be_bytes(ip), u32::from_be_bytes(net));
    match bits {
        Some(bits @ 1..=31) => {
            let mask = u32::MAX << (32 - bits);
            (ip ^ net) & mask == 0
        }
        // 0.0.0.0/0 holds every address; another /0 only itself.
        Some(0) if net == 0 => true,
        _ => ip == net,
    }
}

/// Whether the IPv6 address `ip` is in `net`, of `bits` leading bits, all
/// of them if none (`cidr6_match`).
fn cidr6(ip: &[u8], net: &[u8], bits: Option<u32>) -> bool {
    let bits = bits.unwrap_or(128);
    let (bytes, rest) = ((bits / 8) as usize, bits & 7);
    if bytes > 16 || (bytes == 16 && rest != 0) {
        return false;
    }
    let (Some(ip), Some(net)) = (pton6(ip), pton6(net)) else {
        return false;
    };
    if ip[..bytes] != net[..bytes] {
        return false;
    }
    rest == 0 || (ip[bytes] ^ net[bytes]) & (0xff << (8 - rest)) == 0
}

/// An environment variable that names a proxy, and what it says.
#[derive(Debug)]
pub(crate) struct Variable {
    /// Its name, in a buffer of C's size.
    name: [u8; 20],
    len: usize,
    pub(crate) value: Vec<u8>,
}

impl Variable {
    pub(crate) fn name(&self) -> &[u8] {
        &self.name[..self.len]
    }
}

/// The environment variable that names a proxy for `scheme`, and what it
/// says (`proxy_detect_proxy`): `SCHEME_proxy` for a scheme other than
/// HTTP's, `https_proxy` for `https` and `wss`, `http_proxy` for `http`
/// and `ws`, then `all_proxy`; each in lower case, then upper, but for
/// `http_proxy`, which a CGI program's `Proxy:` header could set as
/// `HTTP_PROXY`.
pub(crate) fn detect(
    scheme: &[u8],
    env: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<Variable> {
    let http = matches!(scheme, b"http" | b"ws");
    let https = matches!(scheme, b"https" | b"wss");
    let mut found = None;
    if !http && !https {
        // C's buffer is of 20 bytes, its name cut to fit.
        let mut name = [0u8; 20];
        let len = scheme.len().min(19);
        name[..len].copy_from_slice(&scheme[..len]);
        let suffix = &b"_proxy"[..6.min(19 - len)];
        name[len..len + suffix.len()].copy_from_slice(suffix);
        found = lower_then_upper(name, len + suffix.len(), env);
    }
    if found.is_none() && https {
        found = lower_then_upper(named(b"https_proxy"), 11, env);
    } else if found.is_none() && http {
        found = looked_up(named(b"http_proxy"), 10, env);
    }
    if found.is_none() {
        found = lower_then_upper(named(b"all_proxy"), 9, env);
    }
    found
}

fn named(name: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[..name.len()].copy_from_slice(name);
    buf
}

fn looked_up(
    name: [u8; 20],
    len: usize,
    env: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<Variable> {
    let value = env(&name[..len])?;
    Some(Variable { name, len, value })
}

/// The variable `name`, or else the one named in upper case.
fn lower_then_upper(
    name: [u8; 20],
    len: usize,
    env: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<Variable> {
    looked_up(name, len, env).or_else(|| {
        let mut upper = name;
        upper.make_ascii_uppercase();
        looked_up(upper, len, env)
    })
}

/// A proxy, as its URL names it.
#[derive(Debug)]
pub(crate) struct Parsed {
    pub(crate) kind: ProxyType,
    pub(crate) peer: Peer,
    /// The user and password in the URL, decoded.
    pub(crate) user: Option<Vec<u8>>,
    pub(crate) password: Option<Vec<u8>>,
}

/// Why a proxy's URL names no proxy this build can use.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    OutOfMemory,
    /// It is no URL: "Unsupported proxy syntax in '…': …".
    Syntax(UrlErrorKind),
    /// Its scheme is no proxy's: "Unsupported proxy scheme for '…'".
    Scheme,
    /// It is an HTTPS proxy, which needs TLS: "Unsupported proxy '…',
    /// libcurl is built without the HTTPS-proxy support."
    Https,
    /// Its user or password does not decode, which C fails with the
    /// URL's error and says nothing of.
    Credentials(UrlErrorKind),
}

impl From<OutOfMemory> for Refused {
    fn from(OutOfMemory: OutOfMemory) -> Refused {
        Refused::OutOfMemory
    }
}

/// The proxy the URL `text` names, of type `kind` and on port `port`
/// unless it says otherwise (`parse_proxy`, `Curl_peer_from_proxy_url`):
/// a URL without a scheme is one of `kind`'s, and one without a port is
/// on `port`, or else its scheme's.
pub(crate) fn parse(
    text: &[u8],
    kind: ProxyType,
    port: Option<NonZeroU16>,
) -> Result<Parsed, Refused> {
    let opts = ParseOptions {
        guess_scheme: true,
        non_support_scheme: true,
        ..ParseOptions::NONE
    };
    let url = match Url::parse(text, opts) {
        Ok(url) => url,
        Err(UrlErrorKind::OutOfMemory) => return Err(Refused::OutOfMemory),
        Err(e) => return Err(Refused::Syntax(e)),
    };
    let named = GetOptions {
        no_guess_scheme: true,
        ..GetOptions::NONE
    };
    let (kind, scheme) = match url.get(Part::Scheme, named) {
        Ok(scheme) => {
            let kind = of_scheme(&scheme, kind).ok_or(Refused::Scheme)?;
            (kind, scheme_named(&scheme))
        }
        Err(UrlErrorKind::NoScheme) => (kind, scheme_of(kind)),
        // A parsed URL's scheme or host not read back is out of memory,
        // whatever the reason, as C's `parse_proxy` and
        // `Curl_peer_from_proxy_url` report it.
        Err(_) => return Err(Refused::OutOfMemory),
    };
    if matches!(
        kind,
        ProxyType::Https | ProxyType::Https2 | ProxyType::Https3
    ) {
        return Err(Refused::Https);
    }
    let decoded = GetOptions {
        url_decode: true,
        ..GetOptions::NONE
    };
    let given = GetOptions {
        no_default_port: true,
        ..GetOptions::NONE
    };
    let port = match url.get(Part::Port, given) {
        // The parser read it as a port already.
        Ok(p) => std::str::from_utf8(&p)
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_PORT),
        Err(UrlErrorKind::OutOfMemory) => return Err(Refused::OutOfMemory),
        Err(_) => port.map_or(default_port(kind), NonZeroU16::get),
    };
    let host = match url.get(Part::Host, decoded) {
        Ok(host) => host,
        // As for the scheme.
        Err(_) => return Err(Refused::OutOfMemory),
    };
    let zone = match url.get(Part::ZoneId, GetOptions::NONE) {
        Ok(zone) => Some(zone),
        Err(UrlErrorKind::OutOfMemory) => return Err(Refused::OutOfMemory),
        Err(_) => None,
    };
    let part = |what, missing| match url.get(what, decoded) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e == missing => Ok(None),
        Err(UrlErrorKind::OutOfMemory) => Err(Refused::OutOfMemory),
        Err(e) => Err(Refused::Credentials(e)),
    };
    let user = part(Part::User, UrlErrorKind::NoUser)?;
    let password = part(Part::Password, UrlErrorKind::NoPassword)?;
    Ok(Parsed {
        kind,
        peer: Peer::new(scheme, host, port, zone),
        user,
        password,
    })
}

/// The port C falls back on where the URL's cannot be read
/// (`CURL_DEFAULT_PROXY_PORT`).
const DEFAULT_PORT: u16 = 1080;

/// The type a proxy URL's scheme names, given `kind` was asked for
/// (`Curl_scheme_to_proxytype`): `http` and `https` keep the HTTP version
/// asked for.
fn of_scheme(scheme: &[u8], kind: ProxyType) -> Option<ProxyType> {
    let is = |name: &[u8]| scheme.eq_ignore_ascii_case(name);
    Some(if is(b"https") {
        match kind {
            ProxyType::Https2 | ProxyType::Https3 => kind,
            _ => ProxyType::Https,
        }
    } else if is(b"socks5h") {
        ProxyType::Socks5Hostname
    } else if is(b"socks5") {
        ProxyType::Socks5
    } else if is(b"socks4a") {
        ProxyType::Socks4a
    } else if is(b"socks4") || is(b"socks") {
        ProxyType::Socks4
    } else if is(b"http") {
        match kind {
            ProxyType::Http10 => kind,
            _ => ProxyType::Http,
        }
    } else {
        return None;
    })
}

const fn scheme(name: &'static str) -> Scheme {
    Scheme { name, reuse: true }
}

/// The scheme of a proxy of type `kind`.
fn scheme_of(kind: ProxyType) -> Scheme {
    match kind {
        ProxyType::Http | ProxyType::Http10 => scheme("http"),
        ProxyType::Https | ProxyType::Https2 | ProxyType::Https3 => scheme("https"),
        ProxyType::Socks4 => scheme("socks4"),
        ProxyType::Socks4a => scheme("socks4a"),
        ProxyType::Socks5 => scheme("socks5"),
        ProxyType::Socks5Hostname => scheme("socks5h"),
    }
}

/// The scheme a proxy URL names, one `of_scheme` takes.
fn scheme_named(name: &[u8]) -> Scheme {
    let is = |n: &[u8]| name.eq_ignore_ascii_case(n);
    if is(b"https") {
        scheme("https")
    } else if is(b"http") {
        scheme("http")
    } else if is(b"socks5h") {
        scheme("socks5h")
    } else if is(b"socks5") {
        scheme("socks5")
    } else if is(b"socks4a") {
        scheme("socks4a")
    } else if is(b"socks") {
        scheme("socks")
    } else {
        scheme("socks4")
    }
}

/// The port of a proxy of type `kind` whose URL names none.
fn default_port(kind: ProxyType) -> u16 {
    match kind {
        ProxyType::Http | ProxyType::Http10 => 80,
        ProxyType::Https | ProxyType::Https2 | ProxyType::Https3 => 443,
        ProxyType::Socks4 | ProxyType::Socks4a | ProxyType::Socks5 | ProxyType::Socks5Hostname => {
            1080
        }
    }
}

#[cfg(test)]
mod tests;
