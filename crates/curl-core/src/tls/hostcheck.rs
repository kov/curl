//! Whether a name a certificate gives names the host (`lib/vtls/hostcheck.c`):
//! the same name in any case, or a wildcard for the leftmost label alone
//! (RFC 6125, 6.4.3), trailing dots ignored, never for an address.

use std::net::{Ipv4Addr, Ipv6Addr};

use curl_alloc::TryArc;

use super::{TlsCx, TlsIdentity, TlsPeerKind};

/// A name a certificate gives, as a library reads it: an alternative
/// DNS name, an alternative IP address (its bytes, four or sixteen), or a
/// common name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertName<'a> {
    Dns(&'a [u8]),
    Ip(&'a [u8]),
    CommonName(&'a [u8]),
}

/// The certificate names the peer a session works for: made by
/// [`check`] alone, which reads the peer's name from the session's own
/// context, for that session's identity. `Checked` takes it.
#[derive(Debug)]
pub struct NameMatch {
    identity: TryArc<TlsIdentity>,
}

impl NameMatch {
    /// Made for `identity`.
    pub(crate) fn is_for(&self, identity: &TryArc<TlsIdentity>) -> bool {
        TryArc::ptr_eq(&self.identity, identity)
    }
}

/// `name` names the peer the session `io` works for: a DNS name or a
/// common name the host by RFC 6125, a wildcard never for an address; an
/// IP address the peer's address, byte for byte, where the peer is one.
/// A DNS name is no address's, nor an IP address a host name's.
pub fn check(io: &TlsCx<'_>, name: CertName<'_>) -> Option<NameMatch> {
    let (host, kind) = io.peer_name();
    let matched = match name {
        CertName::Dns(pattern) => kind == TlsPeerKind::Name && names(pattern, host),
        CertName::CommonName(pattern) => names(pattern, host),
        CertName::Ip(bytes) => {
            let text = std::str::from_utf8(host).ok();
            match kind {
                TlsPeerKind::Name => false,
                TlsPeerKind::Ipv4 => text
                    .and_then(|t| t.parse::<Ipv4Addr>().ok())
                    .is_some_and(|a| a.octets() == bytes),
                TlsPeerKind::Ipv6 => text
                    .and_then(|t| t.parse::<Ipv6Addr>().ok())
                    .is_some_and(|a| a.octets() == bytes),
            }
        }
    };
    matched.then(|| NameMatch {
        identity: io.identity().clone(),
    })
}

/// The certificate's name `pattern` names `host` (`Curl_cert_hostcheck`).
/// Neither is taken to end at a zero byte: a pattern with one inside
/// names no host.
pub fn names(pattern: &[u8], host: &[u8]) -> bool {
    !pattern.is_empty() && !host.is_empty() && host_matches(host, pattern)
}

/// `hostmatch`.
fn host_matches(host: &[u8], pattern: &[u8]) -> bool {
    let host = host.strip_suffix(b".").unwrap_or(host);
    let pattern = pattern.strip_suffix(b".").unwrap_or(pattern);
    if pattern.len() > 2 && !pattern.starts_with(b"*.") {
        return same(host, pattern);
    }
    // No wildcard for an address, nor for a name that starts with a dot.
    if is_address(host) || host.first() == Some(&b'.') {
        return false;
    }
    // A wildcard needs two dots in the pattern, so it cannot cover a
    // whole domain.
    let Some(first_dot) = pattern.iter().position(|&b| b == b'.') else {
        return same(host, pattern);
    };
    if pattern.iter().rposition(|&b| b == b'.') == Some(first_dot) {
        return same(host, pattern);
    }
    match host.iter().position(|&b| b == b'.') {
        Some(host_dot) => same(&host[host_dot..], &pattern[first_dot..]),
        None => false,
    }
}

/// The same bytes, letters in any case (`pmatch`).
fn same(host: &[u8], pattern: &[u8]) -> bool {
    host.eq_ignore_ascii_case(pattern)
}

/// The host is an IPv4 or IPv6 address (`Curl_host_is_ipnum`).
fn is_address(host: &[u8]) -> bool {
    std::str::from_utf8(host)
        .is_ok_and(|h| h.parse::<Ipv4Addr>().is_ok() || h.parse::<Ipv6Addr>().is_ok())
}

#[cfg(test)]
mod c_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// unit1397: C's table of hosts and patterns, each checked as C
    /// checks it, and the patterns with a zero byte inside, which match
    /// neither host.
    #[test]
    fn unit1397_host_checks() {
        for &(host, pattern, matches) in c_tests::UNIT1397 {
            assert_eq!(
                names(pattern, host),
                matches,
                "{:?} for {:?}",
                String::from_utf8_lossy(pattern),
                String::from_utf8_lossy(host)
            );
        }
        for &(pattern, host) in c_tests::UNIT1397_NUL {
            assert!(!names(pattern, host), "{pattern:?} for {host:?}");
        }
    }

    /// A pattern of two bytes is never taken as a plain name, wildcard or
    /// not (`hostmatch`'s `patternlen > 2`): an address, or a host that
    /// starts with a dot, matches none, even the same.
    #[test]
    fn a_two_byte_pattern_names_no_address_or_dotted_host() {
        for (pattern, host, matches) in [
            (&b"::"[..], &b"::"[..], false),
            (b".a", b".a", false),
            (b"ab", b"ab", true),
            (b"AB", b"ab", true),
            (b"::1", b"::1", true),
        ] {
            assert_eq!(names(pattern, host), matches, "{pattern:?} for {host:?}");
        }
    }
}
