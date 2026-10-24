//! Whether a name a certificate gives names the host (`lib/vtls/hostcheck.c`):
//! the same name in any case, or a wildcard for the leftmost label alone
//! (RFC 6125, 6.4.3), trailing dots ignored, never for an address.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The certificate's name `pattern` names `host` (`Curl_cert_hostcheck`).
/// Neither is taken to end at a zero byte: a pattern with one inside
/// names no host.
pub(crate) fn names(pattern: &[u8], host: &[u8]) -> bool {
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
    fn unit1397() {
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
}
