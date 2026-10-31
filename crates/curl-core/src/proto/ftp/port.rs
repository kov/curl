//! Where an active data connection is offered (`CURLOPT_FTPPORT`): an
//! address, an interface or a host, then a port or a range of ports, any
//! of them left out (`ftp_port_parse_string`).

use std::net::Ipv6Addr;

/// What the option names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PortSpec<'a> {
    /// The address, interface or host; none for the control connection's
    /// own address.
    pub(crate) addr: Option<&'a [u8]>,
    /// The ports to bind to, the lowest first: 0 for any.
    pub(crate) min: u16,
    pub(crate) max: u16,
}

/// The option's text read as C reads it: `[v6]:port`, `:port`,
/// `host:port` or a bare IPv6 address or host, the port `N` or `N-M`;
/// a range that runs backwards is any port. One byte or none names
/// nothing (`-`, the default).
pub(crate) fn parse(spec: &[u8]) -> PortSpec<'_> {
    let mut parsed = PortSpec {
        addr: None,
        min: 0,
        max: 0,
    };
    if spec.len() <= 1 {
        return parsed;
    }
    // Where the address ends, the port after it.
    let ip_end;
    if spec[0] == b'[' {
        ip_end = spec.iter().position(|&b| b == b']');
        if let Some(end) = ip_end {
            parsed.addr = Some(&spec[1..end]);
        }
    } else if spec[0] == b':' {
        ip_end = Some(0);
    } else {
        match spec.iter().position(|&b| b == b':') {
            Some(colon) if !is_ipv6(spec) => {
                parsed.addr = Some(&spec[..colon]);
                ip_end = Some(colon);
            }
            // An IPv6 address, which has no port.
            _ => {
                parsed.addr = Some(spec);
                ip_end = None;
            }
        }
    }
    if let Some(end) = ip_end
        && let Some(colon) = spec[end..].iter().position(|&b| b == b':')
    {
        let rest = &spec[end + colon + 1..];
        if let Some((start, rest)) = number(rest) {
            parsed.min = start;
            parsed.max = match rest.strip_prefix(b"-").and_then(number) {
                Some((end, _)) => end,
                None => start,
            };
        }
    }
    if parsed.min > parsed.max {
        parsed.min = 0;
        parsed.max = 0;
    }
    if parsed.addr.is_some_and(<[u8]>::is_empty) {
        parsed.addr = None;
    }
    parsed
}

/// Whether `text` is an IPv6 address.
fn is_ipv6(text: &[u8]) -> bool {
    std::str::from_utf8(text).is_ok_and(|t| t.parse::<Ipv6Addr>().is_ok())
}

/// The decimal number `text` starts with, at most 65535, and what follows
/// it (`curlx_str_number`).
fn number(text: &[u8]) -> Option<(u16, &[u8])> {
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
    Some((
        u16::try_from(n).expect("no more than 65535"),
        &text[digits..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(addr: Option<&[u8]>, min: u16, max: u16) -> PortSpec<'_> {
        PortSpec { addr, min, max }
    }

    #[test]
    fn a_dash_or_nothing_names_nothing() {
        assert_eq!(parse(b"-"), spec(None, 0, 0));
        assert_eq!(parse(b""), spec(None, 0, 0));
        assert_eq!(parse(b"x"), spec(None, 0, 0));
    }

    #[test]
    fn an_address_or_a_host_alone_takes_any_port() {
        assert_eq!(parse(b"127.0.0.1"), spec(Some(b"127.0.0.1"), 0, 0));
        assert_eq!(parse(b"eth0"), spec(Some(b"eth0"), 0, 0));
        assert_eq!(parse(b"fe80::1"), spec(Some(b"fe80::1"), 0, 0));
        // One that starts with a colon is a port, as C reads it.
        assert_eq!(parse(b"::1"), spec(None, 0, 0));
    }

    #[test]
    fn a_port_or_a_range_follows_a_colon() {
        assert_eq!(parse(b"1.2.3.4:5000"), spec(Some(b"1.2.3.4"), 5000, 5000));
        assert_eq!(parse(b"host:5000-5010"), spec(Some(b"host"), 5000, 5010));
        assert_eq!(parse(b":7000"), spec(None, 7000, 7000));
        assert_eq!(parse(b":65535"), spec(None, 65535, 65535));
        assert_eq!(parse(b":65536"), spec(None, 0, 0));
        assert_eq!(parse(b"[::1]:7000-7001"), spec(Some(b"::1"), 7000, 7001));
    }

    #[test]
    fn a_backward_range_or_a_bad_number_is_any_port() {
        assert_eq!(parse(b":1234-1230"), spec(None, 0, 0));
        assert_eq!(parse(b":-4711"), spec(None, 0, 0));
        assert_eq!(parse(b"h:70000"), spec(Some(b"h"), 0, 0));
        assert_eq!(parse(b"h:80-x"), spec(Some(b"h"), 80, 80));
    }

    #[test]
    fn an_unclosed_bracket_names_nothing() {
        assert_eq!(parse(b"[::1:80"), spec(None, 0, 0));
    }
}
