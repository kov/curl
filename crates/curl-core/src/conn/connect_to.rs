//! The peer a connect-to entry sends a connection to in place of the URL's
//! (`url_set_conn_peer`, `parse_connect_to_string`,
//! `Curl_peer_from_connect_to`).

use curl_alloc::{OutOfMemory, TryVec as _};

use super::Peer;
use crate::error::ErrorKind;

/// An entry that matched but does not name a peer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BadVia<'a> {
    OutOfMemory,
    /// Why, and the part of the entry it is about: "{why} in '{text}'".
    Syntax {
        kind: ErrorKind,
        why: &'static str,
        text: &'a [u8],
    },
}

impl From<OutOfMemory> for BadVia<'_> {
    fn from(OutOfMemory: OutOfMemory) -> Self {
        BadVia::OutOfMemory
    }
}

/// The peer the first entry matching `origin` names, if it names one
/// other than `origin`. An entry is `HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT`;
/// an empty `HOST` or `PORT` matches any, an empty `CONNECT-TO-HOST` or
/// `CONNECT-TO-PORT` keeps the origin's, and an entry naming nothing is
/// passed over.
pub(crate) fn via<'a>(
    origin: &Peer,
    entries: impl Iterator<Item = &'a [u8]>,
) -> Result<Option<Peer>, BadVia<'a>> {
    for entry in entries {
        let Some(to) = matching(origin, entry) else {
            continue;
        };
        let peer = connect_to(origin, to)?;
        // The origin's own peer is no detour (`Curl_peer_equal`).
        return Ok(Some(peer).filter(|p| p != origin));
    }
    Ok(None)
}

/// What `entry` connects `origin` to, if it matches it and names
/// something.
fn matching<'a>(origin: &Peer, entry: &'a [u8]) -> Option<&'a [u8]> {
    let rest = match entry.strip_prefix(b":") {
        Some(rest) => rest,
        // The host as resolved, or as the URL gives it (an IPv6 address
        // in brackets), in any case.
        None => [origin.name(), origin.shown()]
            .into_iter()
            .find_map(|host| {
                let after = entry.get(host.len()..)?;
                let same = entry[..host.len()].eq_ignore_ascii_case(host);
                (same && after.first() == Some(&b':')).then(|| &after[1..])
            })?,
    };
    let rest = match rest.strip_prefix(b":") {
        Some(rest) => rest,
        None => {
            let colon = rest.iter().position(|&b| b == b':')?;
            if port_number(&rest[..colon]) != Some(origin.port()) {
                return None;
            }
            &rest[colon + 1..]
        }
    };
    Some(rest).filter(|to| !to.is_empty())
}

/// The peer `to` names, `CONNECT-TO-HOST:CONNECT-TO-PORT`, either part
/// left empty to keep the origin's.
fn connect_to<'a>(origin: &Peer, to: &'a [u8]) -> Result<Peer, BadVia<'a>> {
    let syntax = |kind, why, text| BadVia::Syntax { kind, why, text };
    let (host, port) = if to.first() == Some(&b'[') {
        let Some(close) = to.iter().position(|&b| b == b']') else {
            let why = "Invalid IPv6 address format";
            return Err(syntax(ErrorKind::SetoptOptionSyntax, why, to));
        };
        let port = to[close..]
            .iter()
            .position(|&b| b == b':')
            .map(|c| close + c);
        (&to[..=close], port)
    } else {
        let port = to.iter().position(|&b| b == b':');
        (&to[..port.unwrap_or(to.len())], port)
    };
    let port = match port.map(|p| &to[p + 1..]).filter(|p| !p.is_empty()) {
        Some(digits) => port_number(digits)
            .ok_or_else(|| syntax(ErrorKind::SetoptOptionSyntax, "No valid port number", to))?,
        None => origin.port(),
    };
    let mut name = Vec::new();
    let zone = if host.is_empty() {
        // The origin's host, its zone with it.
        name.try_extend_from_slice(origin.shown())?;
        match origin.zone() {
            Some(zone) => {
                let mut copy = Vec::new();
                copy.try_extend_from_slice(zone)?;
                Some(copy)
            }
            None => None,
        }
    } else if let Some(inner) = host.strip_prefix(b"[") {
        let inner = &inner[..inner.len() - 1];
        let Some((address, zone)) = ipv6(inner) else {
            let why = "Invalid IPv6 address format";
            return Err(syntax(ErrorKind::UrlMalformat, why, host));
        };
        name.try_extend_from_slice(b"[")?;
        name.try_extend_from_slice(address)?;
        name.try_extend_from_slice(b"]")?;
        match zone {
            Some(zone) => {
                let mut copy = Vec::new();
                copy.try_extend_from_slice(zone)?;
                Some(copy)
            }
            None => None,
        }
    } else {
        name.try_extend_from_slice(host)?;
        None
    };
    Ok(Peer::new(origin.scheme(), name, port, zone))
}

/// An IPv6 address and its zone, as `Curl_looks_like_ipv6` lets one
/// through: hex digits, colons and dots, then perhaps `%` (or `%25`)
/// and a zone of unreserved characters.
fn ipv6(text: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    let len = text
        .iter()
        .take_while(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
        .count();
    let (address, rest) = text.split_at(len);
    let Some(zone) = rest.strip_prefix(b"%") else {
        return rest.is_empty().then_some((address, None));
    };
    let zone = zone.strip_prefix(b"25").unwrap_or(zone);
    let unreserved = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
    zone.iter()
        .all(unreserved)
        .then_some((address, Some(zone).filter(|z| !z.is_empty())))
}

/// The port the digits `text` starts with make, what follows them
/// ignored (`curlx_str_number` with 0xffff).
fn port_number(text: &[u8]) -> Option<u16> {
    let digits = text.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mut n: u32 = 0;
    for &d in &text[..digits] {
        n = n * 10 + u32::from(d - b'0');
        if n > 0xffff {
            return None;
        }
    }
    u16::try_from(n).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::Scheme;

    const HTTP: Scheme = Scheme {
        name: "http",
        reuse: true,
    };

    fn peer(host: &str, port: u16) -> Peer {
        Peer::new(HTTP, host.as_bytes().to_vec(), port, None)
    }

    fn via_of(origin: &Peer, entries: &[&str]) -> Result<Option<(String, u16)>, BadVia<'static>> {
        let entries: Vec<&'static [u8]> = entries
            .iter()
            .map(|e| &*Box::leak(e.as_bytes().to_vec().into_boxed_slice()))
            .collect();
        via(origin, entries.into_iter())
            .map(|p| p.map(|p| (String::from_utf8(p.shown().to_vec()).unwrap(), p.port())))
    }

    fn to(host: &str, port: u16) -> Result<Option<(String, u16)>, BadVia<'static>> {
        Ok(Some((host.to_string(), port)))
    }

    /// Entries match and name peers as `parse_connect_to_string` and
    /// `Curl_peer_from_connect_to` have them.
    #[test]
    fn entries_match_as_c_matches_them() {
        let foo = peer("foo.test", 1);
        assert_eq!(
            via_of(&foo, &["foo.test:1:127.0.0.1:2"]),
            to("127.0.0.1", 2)
        );
        assert_eq!(
            via_of(&foo, &["Foo.TEST:1:127.0.0.1:2"]),
            to("127.0.0.1", 2)
        );
        assert_eq!(via_of(&foo, &["::localhost:9"]), to("localhost", 9));
        assert_eq!(via_of(&foo, &["foo.test::localhost:"]), to("localhost", 1));
        assert_eq!(via_of(&foo, &[":1::7"]), to("foo.test", 7), "a port switch");
        assert_eq!(via_of(&foo, &["::[::1]:2"]), to("[::1]", 2));
        assert_eq!(via_of(&foo, &["::[::1]"]), to("[::1]", 1));
        // No match: another host, a host the name only starts, another
        // port, a port not a number, nothing to connect to.
        for miss in [
            "bar.test:1:x:2",
            "foo:1:x:2",
            "foo.test:2:x:2",
            "foo.test:x:127.0.0.1:2",
            "foo.test:1",
            "foo.test:1:",
            "bad",
        ] {
            assert_eq!(via_of(&foo, &[miss]), Ok(None), "{miss}");
        }
        // The first match decides, even when it names the origin.
        assert_eq!(
            via_of(&foo, &["x:1:y:2", "foo.test:1:127.0.0.1:1", "::z:3"]),
            to("127.0.0.1", 1)
        );
        assert_eq!(via_of(&foo, &["foo.test:1:foo.test:1", "::z:3"]), Ok(None));
        assert_eq!(
            via_of(&foo, &["foo.test:1:", "::z:3"]),
            to("z", 3),
            "an entry naming nothing is passed over"
        );
        assert_eq!(via_of(&foo, &["foo.test:1:FOO.test:"]), Ok(None));
        // An IPv6 origin matches by its address with brackets or without.
        let v6 = peer("[::1]", 1);
        assert_eq!(via_of(&v6, &["[::1]:1::2"]), to("[::1]", 2));
        assert_eq!(via_of(&v6, &["::1:1:x:2"]), to("1", 1), "any host and port");
        assert_eq!(via_of(&v6, &[":1:localhost:2"]), to("localhost", 2));
    }

    /// A matching entry that names no peer is refused, as C refuses it.
    #[test]
    fn bad_entries_are_refused_as_c_refuses_them() {
        let foo = peer("foo.test", 1);
        let bad = |kind, why, text: &'static str| {
            Err(BadVia::Syntax {
                kind,
                why,
                text: text.as_bytes(),
            })
        };
        let ipv6 = "Invalid IPv6 address format";
        let port = "No valid port number";
        assert_eq!(
            via_of(&foo, &["::[::1"]),
            bad(ErrorKind::SetoptOptionSyntax, ipv6, "[::1")
        );
        assert_eq!(
            via_of(&foo, &["::[zz]:1"]),
            bad(ErrorKind::UrlMalformat, ipv6, "[zz]")
        );
        assert_eq!(
            via_of(&foo, &["::localhost:99999"]),
            bad(ErrorKind::SetoptOptionSyntax, port, "localhost:99999")
        );
        assert_eq!(
            via_of(&foo, &["::example.com:example.com"]),
            bad(
                ErrorKind::SetoptOptionSyntax,
                port,
                "example.com:example.com"
            )
        );
        assert_eq!(
            via_of(&foo, &["::localhost:4294967296999"]),
            bad(
                ErrorKind::SetoptOptionSyntax,
                port,
                "localhost:4294967296999"
            )
        );
        assert_eq!(via_of(&foo, &["::[fe80::1%25eth0]:2"]), to("[fe80::1]", 2));
    }
}
