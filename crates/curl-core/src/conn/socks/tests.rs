use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;

use super::*;

mod gss;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn dest(name: &[u8], resolved: Resolved) -> Dest<'_> {
    Dest {
        name,
        port: 8990,
        resolved,
    }
}

fn creds<'a>(user: &'a [u8], password: &'a [u8]) -> Option<Creds<'a>> {
    Some(Creds {
        user,
        password,
        service: b"",
    })
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
    let mut h = Handshake::new(
        Version::V4,
        d,
        creds(b"u", b"p"),
        Socks5Auth::default(),
        None,
    )
    .unwrap();
    assert_eq!(send(&mut h), b"\x04\x01\x23\x1e\x7f\x00\x00\x01u\x00");
    assert_eq!(h.take(b"\x00\x5a\x00"), Ok(Took::Need(8)));
    assert_eq!(
        h.take(b"\x00\x5a\x00\x00\x00\x00\x00\x00rest"),
        Ok(Took::Read(8))
    );
    assert!(h.done());
    let d = dest(b"v6.example", Resolved::NoAddress);
    let e = Handshake::new(Version::V4, d, None, Socks5Auth::default(), None).unwrap_err();
    assert_eq!(said(&e), "SOCKS4 connection to v6.example not supported");
    assert_eq!(e.code(), Some(ProxyError::ResolveHost));
}

/// SOCKS4a: the invalid address 0.0.0.1, the user, then the name, each
/// with its NUL; a name of 255 bytes with its NUL is too long.
#[test]
fn socks4a_sends_the_name() {
    let d = dest(b"host.example", Resolved::Remote);
    let mut h = Handshake::new(Version::V4a, d, None, Socks5Auth::default(), None).unwrap();
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
            Socks5Auth::default(),
            None
        )
        .is_ok()
    );
    let name = [b'h'; 255];
    let e = Handshake::new(
        Version::V4a,
        dest(&name, Resolved::Remote),
        None,
        Socks5Auth::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(
        (said(&e).as_str(), e.code()),
        ("SOCKS4: too long hostname", Some(ProxyError::LongHostname))
    );
    let user = [b'a'; 256];
    let d = dest(b"h", Resolved::Remote);
    let e = Handshake::new(
        Version::V4a,
        d,
        creds(&user, b""),
        Socks5Auth::default(),
        None,
    )
    .unwrap_err();
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
        let mut h = Handshake::new(Version::V4, d, None, Socks5Auth::default(), None).unwrap();
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
    let mut h = Handshake::new(Version::V5Hostname, d, None, Socks5Auth::default(), None).unwrap();
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
        None,
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
    let mut h = Handshake::new(Version::V5Hostname, d, None, Socks5Auth::default(), None).unwrap();
    send(&mut h);
    h.take(b"\x05\x00").unwrap();
    assert_eq!(send(&mut h), b"\x05\x01\x00\x01\x0c\x22\x38\x4e\x23\x1e");
    let mut h = Handshake::new(
        Version::V5Hostname,
        d,
        creds(b"u", b"p"),
        Socks5Auth::default(),
        None,
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
    let mut h = Handshake::new(Version::V5, d, None, Socks5Auth::default(), None).unwrap();
    send(&mut h);
    h.take(b"\x05\x00").unwrap();
    assert_eq!(send(&mut h), b"\x05\x01\x00\x01\x7f\x00\x00\x01\x23\x1e");
    let d = dest(b"nowhere", Resolved::NoAddress);
    let mut h = Handshake::new(Version::V5, d, None, Socks5Auth::default(), None).unwrap();
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
    let e = Handshake::new(Version::V5Hostname, d, None, only, None).unwrap_err();
    assert_eq!(
        said(&e),
        "SOCKS5: no acceptable authentication method is available."
    );
    let mut h = Handshake::new(Version::V5Hostname, d, creds(b"u", b"p"), only, None).unwrap();
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
        let mut h =
            Handshake::new(Version::V5Hostname, d, None, Socks5Auth::default(), None).unwrap();
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
        None,
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
        None,
    )
    .unwrap_err();
    assert_eq!(e.code(), Some(ProxyError::LongHostname));
    let mut h = Handshake::new(
        Version::V5Hostname,
        dest(b"host", Resolved::Remote),
        None,
        Socks5Auth::default(),
        None,
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

/// SOCKS4 resolves the destination in IPv4 alone; the others in the
/// families asked for.
#[test]
fn only_socks4_insists_on_ipv4() {
    for (version, want) in [
        (Version::V4, IpVersion::V4),
        (Version::V4a, IpVersion::V6),
        (Version::V5, IpVersion::V6),
        (Version::V5Hostname, IpVersion::V6),
    ] {
        assert_eq!(version.ip(IpVersion::V6), want, "{version:?}");
    }
}

/// A SOCKS5 proxy's reply codes, each as its `CURLproxycode`; and a
/// SOCKS4 proxy's identd refusals, in C's words.
#[test]
fn reply_codes_are_c_s() {
    for (code, want) in [
        (1, ProxyError::ReplyGeneralServerFailure),
        (2, ProxyError::ReplyNotAllowed),
        (3, ProxyError::ReplyNetworkUnreachable),
        (4, ProxyError::ReplyHostUnreachable),
        (5, ProxyError::ReplyConnectionRefused),
        (6, ProxyError::ReplyTtlExpired),
        (7, ProxyError::ReplyCommandNotSupported),
        (8, ProxyError::ReplyAddressTypeNotSupported),
        (9, ProxyError::ReplyUnassigned),
    ] {
        let e = SocksError::Refused5(b"h".to_vec(), code);
        assert_eq!(e.code(), Some(want), "{code}");
        assert_eq!(
            said(&e),
            format!("cannot complete SOCKS5 connection to h. ({code})")
        );
    }
    let refused4 = |code| SocksError::Refused4 {
        code,
        port: 80,
        ip: [10, 0, 0, 1],
    };
    let head = "[SOCKS] cannot complete SOCKS4 connection to 10.0.0.1:80.";
    assert_eq!(
        said(&refused4(92)),
        format!(
            "{head} (92), request rejected because SOCKS server cannot connect to identd on the \
             client."
        )
    );
    assert_eq!(
        said(&refused4(93)),
        format!(
            "{head} (93), request rejected because the client program and identd report \
             different user-ids."
        )
    );
    assert_eq!(said(&refused4(94)), format!("{head} (94), Unknown."));
}

/// The longest user, password and name each request carries is 255
/// bytes; a password one longer is refused as C refuses it.
#[test]
fn fields_of_255_bytes_go() {
    let long = [b'x'; 255];
    let d = dest(b"h", Resolved::Remote);
    let mut h = Handshake::new(
        Version::V4a,
        d,
        creds(&long, b""),
        Socks5Auth::default(),
        None,
    )
    .unwrap();
    assert_eq!(send(&mut h).len(), 8 + 256 + 2);
    let d = dest(&long, Resolved::Remote);
    let mut h = Handshake::new(Version::V5Hostname, d, None, Socks5Auth::default(), None).unwrap();
    send(&mut h);
    h.take(b"\x05\x00").unwrap();
    assert_eq!(send(&mut h).len(), 5 + 255 + 2);
    let login = |user: &[u8], password: &[u8]| {
        let d = dest(b"h", Resolved::Remote);
        let auth = Socks5Auth::default();
        let mut h =
            Handshake::new(Version::V5Hostname, d, creds(user, password), auth, None).unwrap();
        send(&mut h);
        h.take(b"\x05\x02").map(|_| send(&mut h).len())
    };
    assert_eq!(login(&long, &long), Ok(3 + 255 + 255));
    let e = login(b"u", &[b'p'; 256]).unwrap_err();
    assert_eq!(
        (said(&e).as_str(), e.code()),
        (
            "Excessive password length for proxy auth",
            Some(ProxyError::LongPasswd)
        )
    );
}

/// The method a SOCKS5 proxy picks must be one allowed: GSS-API, never
/// built in, fails either way; basic authentication only if allowed.
#[test]
fn a_socks5_proxy_s_pick_is_checked_against_what_is_allowed() {
    let pick = |reply: &[u8], auth: Socks5Auth| {
        let d = dest(b"h", Resolved::Remote);
        let mut h = Handshake::new(Version::V5Hostname, d, creds(b"u", b"p"), auth, None).unwrap();
        send(&mut h);
        let e = h.take(reply).unwrap_err();
        (said(&e), e.code(), h.authenticated())
    };
    let allowed = Socks5Auth::default();
    let gssapi = |gssapi| Socks5Auth { gssapi, ..allowed };
    let basic = |basic| Socks5Auth { basic, ..allowed };
    let permsg = Some(ProxyError::GssapiPermsg);
    assert_eq!(
        pick(b"\x05\x01", gssapi(true)),
        (
            "SOCKS5 GSSAPI per-message authentication is not supported.".to_owned(),
            permsg,
            true
        )
    );
    assert_eq!(
        pick(b"\x05\x01", gssapi(false)),
        (
            "SOCKS5 GSSAPI per-message authentication is not enabled.".to_owned(),
            permsg,
            false
        )
    );
    assert_eq!(
        pick(b"\x05\x02", basic(false)),
        (
            "BASIC authentication proposed but not enabled.".to_owned(),
            Some(ProxyError::NoAuth),
            false
        )
    );
}

/// A SOCKS5 answer is as long as its address: an IPv6 one 22 bytes, an
/// IPv4 one 10; an address with a colon that is no IPv6 address is
/// refused with nothing said (`CURLPX_BAD_ADDRESS_TYPE`).
#[test]
fn a_socks5_answer_is_read_by_its_address_type() {
    let connecting = |name: &[u8]| {
        let d = dest(name, Resolved::Remote);
        let mut h =
            Handshake::new(Version::V5Hostname, d, None, Socks5Auth::default(), None).unwrap();
        send(&mut h);
        h.take(b"\x05\x00").map(|_| {
            send(&mut h);
            h
        })
    };
    let mut h = connecting(b"h").unwrap();
    let mut v6 = b"\x05\x00\x00\x04".to_vec();
    v6.extend_from_slice(&[0; 16 + 2]);
    assert_eq!(h.take(&v6[..8]), Ok(Took::Need(22)));
    assert_eq!(h.take(&v6), Ok(Took::Read(22)));
    assert!(h.done());
    let mut h = connecting(b"h").unwrap();
    assert_eq!(
        h.take(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50more"),
        Ok(Took::Read(10))
    );
    let e = connecting(b"not:v6").unwrap_err();
    assert_eq!(
        (e.said().is_none(), e.code()),
        (true, Some(ProxyError::BadAddressType))
    );
}

/// What a handshake came to: what was sent, the reply bytes used, and
/// how it ended.
#[derive(Debug, PartialEq, Eq)]
struct Shook {
    sent: Vec<u8>,
    used: usize,
    done: bool,
    error: Option<SocksError>,
}

/// Run a handshake against the proxy's `pieces`, as the connection does:
/// each request sent, then its reply read once enough of it came.
fn shake(start: impl Fn() -> Result<Handshake, SocksError>, pieces: &[&[u8]]) -> Shook {
    let mut got = Shook {
        sent: Vec::new(),
        used: 0,
        done: false,
        error: None,
    };
    let mut h = match start() {
        Ok(h) => h,
        Err(e) => {
            got.error = Some(e);
            return got;
        }
    };
    let mut received = Vec::new();
    let mut pieces = pieces.iter();
    while !h.done() {
        got.sent.extend_from_slice(&send(&mut h));
        match h.take(&received) {
            Ok(Took::Need(n)) => {
                assert!(n > received.len(), "asked for what it has");
                let Some(piece) = pieces.next() else { break };
                received.extend_from_slice(piece);
            }
            Ok(Took::Read(n)) => {
                assert!(
                    n > 0 && n <= received.len(),
                    "read {n} of {}",
                    received.len()
                );
                received.drain(..n);
                got.used += n;
                if h.gss_starts()
                    && let Err(e) = h.start_gss(b"proxy.example", &mut |_| {})
                {
                    got.error = Some(e);
                    break;
                }
            }
            Err(e) => {
                got.error = Some(e);
                break;
            }
        }
    }
    got.done = h.done();
    got
}

const REPLY_WORDS: &[&[u8]] = &[
    b"\x00",
    b"\x01",
    b"\x02",
    b"\x03",
    b"\x04",
    b"\x05",
    b"\x5a",
    b"\xff",
    b"\x05\x00",
    b"\x05\x02",
    b"\x01\x00",
    b"\x00\x5a\x00\x00\x00\x00\x00\x00",
    b"\x05\x00\x00\x01",
    b"\x05\x00\x00\x03\xff",
    b"\x05\x00\x00\x04",
    b"\x7f\x00\x00\x01\x00\x50",
    b"\x05\x01",
    b"\x01\x01\x00\x01",
    b"\x01\x02\x00\x01",
    b"\x01\x02\x00\x02",
];
const REPLIES: &[&[u8]] = &[
    b"\x00\x5a\x00\x00\x00\x00\x00\x00rest",
    b"\x05\x00\x05\x00\x00\x03\x03abc\x00\x50more",
    b"\x05\x02\x01\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50",
    b"\x05\x00\x05\x00\x00\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\x00\x50",
];

const GSS_WORDS: &[&[u8]] = &[
    b"\x00",
    b"\x01",
    b"\x02",
    b"\xff",
    b"\x05\x01",
    b"\x01\x01\x00\x01",
    b"\x01\x02\x00\x01",
    b"\x01\x02\x00\x02",
    b"\x01\x01\x00\x00",
    b"\x05\x00\x00\x01",
    b"\x7f\x00\x00\x01\x00\x50",
];
const GSS_REPLIES: &[&[u8]] = &[
    b"\x05\x01\x01\x01\x00\x01x\x01\x02\x00\x01\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50",
    b"\x05\x01\x01\x01\x00\x02xy\x01\x02\x00\x01\x01\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50",
];

fn version() -> impl Strategy<Value = Version> {
    prop_oneof![
        Just(Version::V4),
        Just(Version::V4a),
        Just(Version::V5),
        Just(Version::V5Hostname),
    ]
}

fn resolved() -> impl Strategy<Value = Resolved> {
    prop_oneof![
        Just(Resolved::Remote),
        Just(Resolved::NoAddress),
        Just(Resolved::Failed),
        any::<[u8; 4]>().prop_map(|a| Resolved::Address(IpAddr::from(a))),
        any::<[u8; 16]>().prop_map(|a| Resolved::Address(IpAddr::from(a))),
    ]
}

/// A field from the options: short, or about as long as SOCKS allows.
fn field() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..8),
        proptest::collection::vec(any::<u8>(), 250..260),
    ]
}

proptest! {
    #![proptest_config(crate::untrusted::config(256))]

    /// Any proxy's replies, to any handshake the options can ask for, are
    /// read or refused as they are whole, whatever pieces they come in;
    /// no reply is read from bytes not there, and none waits for bytes
    /// already in.
    #[test]
    fn any_reply_is_read_alike_in_any_pieces(
        reply in crate::untrusted::input(REPLY_WORDS, REPLIES, 16),
        cuts in crate::untrusted::cuts(),
        version in version(),
        name in field(),
        port in any::<u16>(),
        resolved in resolved(),
        creds in proptest::option::of((field(), field())),
        [basic, gssapi, only] in any::<[bool; 3]>(),
        library in proptest::option::of(any::<bool>()),
    ) {
        let start = || {
            let creds = creds.as_ref().map(|(user, password)| Creds { user, password, service: b"" });
            let d = Dest { name: &name, port, resolved };
            let library = library.map(|nec| GssMethod {
                library: &gss::ECHO,
                nec,
                delegation: crate::options::Delegation::default(),
            });
            Handshake::new(version, d, creds, Socks5Auth { basic, gssapi, only }, library)
        };
        let whole = shake(start, &[&reply]);
        let pieces = crate::untrusted::pieces(&reply, &cuts);
        prop_assert_eq!(shake(start, &pieces), whole);
    }

    /// Likewise for a SOCKS5 proxy offered GSS-API, its messages whole or
    /// in any pieces, wrapped or in NEC's way.
    #[test]
    fn any_gss_api_reply_is_read_alike_in_any_pieces(
        reply in crate::untrusted::input(GSS_WORDS, GSS_REPLIES, 16),
        cuts in crate::untrusted::cuts(),
        nec in any::<bool>(),
        basic in any::<bool>(),
    ) {
        let start = || {
            let d = Dest { name: b"h", port: 80, resolved: Resolved::Remote };
            let library = Some(GssMethod {
                library: &gss::ECHO,
                nec,
                delegation: crate::options::Delegation::default(),
            });
            let auth = Socks5Auth { basic, ..Socks5Auth::default() };
            Handshake::new(Version::V5Hostname, d, None, auth, library)
        };
        let whole = shake(start, &[&reply]);
        let pieces = crate::untrusted::pieces(&reply, &cuts);
        prop_assert_eq!(shake(start, &pieces), whole);
    }
}
