use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn dest(name: &[u8], resolved: Resolved) -> Dest<'_> {
    Dest {
        name,
        port: 8990,
        resolved,
    }
}

fn creds<'a>(user: &'a [u8], password: &'a [u8]) -> Option<Creds<'a>> {
    Some(Creds { user, password })
}

/// Send what is to be sent, and return it.
fn send(h: &mut Handshake) -> Vec<u8> {
    let out = h.to_send().to_vec();
    h.sent(out.len());
    out
}

fn said(e: &SocksError) -> String {
    e.said().map(|s| s.to_string()).unwrap_or_default()
}

/// SOCKS4: the destination's port and address, the user and its NUL,
/// then the 8 bytes granting it.
#[test]
fn socks4_asks_for_the_address_resolved_here() {
    let d = dest(b"localhost", Resolved::Address(LOOPBACK));
    let mut h = Handshake::new(Version::V4, d, creds(b"u", b"p"), Socks5Auth::default()).unwrap();
    assert_eq!(send(&mut h), b"\x04\x01\x23\x1e\x7f\x00\x00\x01u\x00");
    assert_eq!(h.take(b"\x00\x5a\x00"), Ok(Took::Need(8)));
    assert_eq!(
        h.take(b"\x00\x5a\x00\x00\x00\x00\x00\x00rest"),
        Ok(Took::Read(8))
    );
    assert!(h.done());
    let d = dest(b"v6.example", Resolved::NoAddress);
    let e = Handshake::new(Version::V4, d, None, Socks5Auth::default()).unwrap_err();
    assert_eq!(said(&e), "SOCKS4 connection to v6.example not supported");
    assert_eq!(e.code(), Some(ProxyError::ResolveHost));
}

/// SOCKS4a: the invalid address 0.0.0.1, the user, then the name, each
/// with its NUL; a name of 255 bytes with its NUL is too long.
#[test]
fn socks4a_sends_the_name() {
    let d = dest(b"host.example", Resolved::Remote);
    let mut h = Handshake::new(Version::V4a, d, None, Socks5Auth::default()).unwrap();
    assert_eq!(
        send(&mut h),
        b"\x04\x01\x23\x1e\x00\x00\x00\x01\x00host.example\x00"
    );
    let name = [b'h'; 254];
    assert!(
        Handshake::new(
            Version::V4a,
            dest(&name, Resolved::Remote),
            None,
            Socks5Auth::default()
        )
        .is_ok()
    );
    let name = [b'h'; 255];
    let e = Handshake::new(
        Version::V4a,
        dest(&name, Resolved::Remote),
        None,
        Socks5Auth::default(),
    )
    .unwrap_err();
    assert_eq!(
        (said(&e).as_str(), e.code()),
        ("SOCKS4: too long hostname", Some(ProxyError::LongHostname))
    );
    let user = [b'a'; 256];
    let d = dest(b"h", Resolved::Remote);
    let e = Handshake::new(Version::V4a, d, creds(&user, b""), Socks5Auth::default()).unwrap_err();
    assert_eq!(
        (said(&e).as_str(), e.code()),
        ("Too long SOCKS proxy username", Some(ProxyError::LongUser))
    );
}

/// A SOCKS4 proxy's refusals, in C's words and codes.
#[test]
fn socks4_refusals_are_said_as_c() {
    let refused = |reply: &[u8]| {
        let d = dest(b"127.0.0.1", Resolved::Address(LOOPBACK));
        let mut h = Handshake::new(Version::V4, d, None, Socks5Auth::default()).unwrap();
        send(&mut h);
        h.take(reply).unwrap_err()
    };
    let e = refused(b"\x00\x5b\x23\x1e\x7f\x00\x00\x01");
    assert_eq!(
        said(&e),
        "[SOCKS] cannot complete SOCKS4 connection to 127.0.0.1:8990. (91), request rejected or failed."
    );
    assert_eq!(e.code(), Some(ProxyError::RequestFailed));
    assert_eq!(
        refused(b"\x00\x5c\0\0\0\0\0\0").code(),
        Some(ProxyError::Identd)
    );
    assert_eq!(
        refused(b"\x00\x5d\0\0\0\0\0\0").code(),
        Some(ProxyError::IdentdDiffer)
    );
    assert_eq!(
        refused(b"\x00\x01\0\0\0\0\0\0").code(),
        Some(ProxyError::UnknownFail)
    );
    let e = refused(b"\x04\x5a\0\0\0\0\0\0");
    assert_eq!(
        said(&e),
        "SOCKS4 reply has wrong version, version should be 0."
    );
}

/// SOCKS5 without credentials: no authentication offered, then the
/// name for the proxy to resolve, then an answer whose length its address
/// type gives.
#[test]
fn socks5_sends_the_name_and_reads_the_whole_answer() {
    let d = dest(b"host.example", Resolved::Remote);
    let mut h = Handshake::new(Version::V5Hostname, d, None, Socks5Auth::default()).unwrap();
    assert_eq!(send(&mut h), b"\x05\x01\x00");
    assert_eq!(h.take(b"\x05\x00"), Ok(Took::Read(2)));
    assert_eq!(send(&mut h), b"\x05\x01\x00\x03\x0chost.example\x23\x1e");
    // A name in the answer: 4 + 1 + 3 + 2 bytes.
    assert_eq!(h.take(b"\x05\x00\x00\x03\x03abc"), Ok(Took::Need(10)));
    assert_eq!(
        h.take(b"\x05\x00\x00\x03\x03abc\x00\x50more"),
        Ok(Took::Read(10))
    );
    assert!(h.done() && !h.authenticated());
}

/// SOCKS5 with credentials: both methods offered; the user and password
/// sent when picked; addresses the URL names sent as addresses.
#[test]
fn socks5_logs_in_when_asked() {
    let d = dest(b"2200::33", Resolved::Remote);
    let mut h = Handshake::new(
        Version::V5Hostname,
        d,
        creds(b"uz3r", b"p4ss"),
        Socks5Auth::default(),
    )
    .unwrap();
    assert_eq!(send(&mut h), b"\x05\x02\x00\x02");
    assert_eq!(h.take(b"\x05\x02"), Ok(Took::Read(2)));
    assert_eq!(send(&mut h), b"\x01\x04uz3r\x04p4ss");
    assert_eq!(h.take(b"\x01\x00"), Ok(Took::Read(2)));
    let mut want = b"\x05\x01\x00\x04".to_vec();
    want.extend_from_slice(&"2200::33".parse::<Ipv6Addr>().unwrap().octets());
    want.extend_from_slice(b"\x23\x1e");
    assert_eq!(send(&mut h), want);
    assert!(h.authenticated());
    let d = dest(b"12.34.56.78", Resolved::Remote);
    let mut h = Handshake::new(Version::V5Hostname, d, None, Socks5Auth::default()).unwrap();
    send(&mut h);
    h.take(b"\x05\x00").unwrap();
    assert_eq!(send(&mut h), b"\x05\x01\x00\x01\x0c\x22\x38\x4e\x23\x1e");
    let mut h = Handshake::new(
        Version::V5Hostname,
        d,
        creds(b"u", b"p"),
        Socks5Auth::default(),
    )
    .unwrap();
    send(&mut h);
    send(&mut h);
    let e = h.take(b"\x05\x02").and_then(|_| {
        send(&mut h);
        h.take(b"\x01\x01")
    });
    let e = e.unwrap_err();
    assert_eq!(
        (said(&e).as_str(), e.code()),
        (
            "User was rejected by the SOCKS5 server (1 1).",
            Some(ProxyError::UserRejected)
        )
    );
}

/// SOCKS5 resolved here: the address, IPv6 or IPv4.
#[test]
fn socks5_asks_for_the_address_resolved_here() {
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert_eq!(
        Resolved::pick(Version::V5, &[LOOPBACK, v6], IpVersion::Any),
        Resolved::Address(v6)
    );
    assert_eq!(
        Resolved::pick(Version::V5, &[LOOPBACK, v6], IpVersion::V4),
        Resolved::Address(LOOPBACK)
    );
    assert_eq!(
        Resolved::pick(Version::V4, &[v6], IpVersion::Any),
        Resolved::NoAddress
    );
    let d = dest(b"localhost", Resolved::Address(LOOPBACK));
    let mut h = Handshake::new(Version::V5, d, None, Socks5Auth::default()).unwrap();
    send(&mut h);
    h.take(b"\x05\x00").unwrap();
    assert_eq!(send(&mut h), b"\x05\x01\x00\x01\x7f\x00\x00\x01\x23\x1e");
    let d = dest(b"nowhere", Resolved::NoAddress);
    let mut h = Handshake::new(Version::V5, d, None, Socks5Auth::default()).unwrap();
    send(&mut h);
    let e = h.take(b"\x05\x00").unwrap_err();
    assert_eq!(
        said(&e),
        "Failed to resolve \"nowhere\" for SOCKS5 connect."
    );
}

/// What a SOCKS5 proxy may refuse, and what may be refused of it.
#[test]
fn socks5_refusals_are_said_as_c() {
    let only = Socks5Auth {
        only: true,
        ..Socks5Auth::default()
    };
    let d = dest(b"h", Resolved::Remote);
    let e = Handshake::new(Version::V5Hostname, d, None, only).unwrap_err();
    assert_eq!(
        said(&e),
        "SOCKS5: no acceptable authentication method is available."
    );
    let mut h = Handshake::new(Version::V5Hostname, d, creds(b"u", b"p"), only).unwrap();
    assert_eq!(send(&mut h), b"\x05\x01\x02");
    let e = h.take(b"\x05\x00").unwrap_err();
    assert_eq!(
        (said(&e).as_str(), e.code()),
        (
            "SOCKS5 proxy selected no authentication.",
            Some(ProxyError::NoAuth)
        )
    );
    let method = |reply: &[u8]| {
        let mut h = Handshake::new(Version::V5Hostname, d, None, Socks5Auth::default()).unwrap();
        send(&mut h);
        h.take(reply).unwrap_err()
    };
    assert_eq!(
        said(&method(b"\x04\x00")),
        "Received invalid version in initial SOCKS5 response."
    );
    assert_eq!(
        said(&method(b"\x05\xff")),
        "No authentication method was acceptable."
    );
    assert_eq!(method(b"\x05\x07").code(), Some(ProxyError::UnknownMode));
    assert_eq!(method(b"\x05\x01").code(), Some(ProxyError::GssapiPermsg));
    let user = [b'A'; 256];
    let mut h = Handshake::new(
        Version::V5Hostname,
        d,
        creds(&user, b"b"),
        Socks5Auth::default(),
    )
    .unwrap();
    send(&mut h);
    let e = h.take(b"\x05\x02").unwrap_err();
    assert_eq!(
        (said(&e).as_str(), e.code()),
        (
            "Excessive username length for proxy auth",
            Some(ProxyError::LongUser)
        )
    );
    let name = [b'c'; 256];
    let e = Handshake::new(
        Version::V5Hostname,
        dest(&name, Resolved::Remote),
        None,
        Socks5Auth::default(),
    )
    .unwrap_err();
    assert_eq!(e.code(), Some(ProxyError::LongHostname));
    let mut h = Handshake::new(
        Version::V5Hostname,
        dest(b"host", Resolved::Remote),
        None,
        Socks5Auth::default(),
    )
    .unwrap();
    send(&mut h);
    h.take(b"\x05\x00").unwrap();
    send(&mut h);
    let e = h.take(b"\x05\x05\x00\x01\0\0\0\0\0\0").unwrap_err();
    assert_eq!(
        (said(&e).as_str(), e.code()),
        (
            "cannot complete SOCKS5 connection to host. (5)",
            Some(ProxyError::ReplyConnectionRefused)
        )
    );
}
