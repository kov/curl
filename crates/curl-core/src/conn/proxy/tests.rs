use proptest::prelude::*;

use super::*;

/// unit1614's table `name`, read from its source, its IPv6 rows kept:
/// each row's values, the end marker left out.
fn unit1614_rows(name: &str) -> Vec<Vec<crate::c_source::Value>> {
    let rows = crate::c_source::table("tests/unit/unit1614.c", name, |c| match c {
        "defined(USE_IPV6)" => true,
        other => panic!("{other}"),
    });
    rows.iter()
        .map(|row| row.group().to_vec())
        .filter(|row| row[0].bytes().is_some())
        .collect()
}

/// A C `bool` in a table.
fn truth(v: &crate::c_source::Value) -> bool {
    match v.word() {
        "TRUE" => true,
        "FALSE" => false,
        other => panic!("{other}"),
    }
}

/// unit1614's cases for the address ranges, IPv4 and IPv6.
#[test]
fn unit1614_ranges_hold_addresses() {
    let bits = |b: &crate::c_source::Value| u32::try_from(b.int()).ok();
    let list4 = unit1614_rows("list4[] =");
    assert_eq!(list4.len(), 17);
    for row in &list4 {
        let (ip, net, want) = (row[0].str(), row[1].str(), truth(&row[3]));
        let got = cidr4(ip, net, bits(&row[2]));
        assert_eq!(got, want, "{row:?}");
    }
    let list6 = unit1614_rows("list6[] =");
    assert_eq!(list6.len(), 8);
    for row in &list6 {
        let (ip, net, want) = (row[0].str(), row[1].str(), truth(&row[3]));
        let got = cidr6(ip, net, bits(&row[2]));
        assert_eq!(got, want, "{row:?}");
    }
}

/// A prefix that ends inside a byte holds that byte's leading bits.
#[test]
fn an_ipv6_prefix_ends_inside_a_byte() {
    for (ip, net, b, want) in [
        ("2001:db8::8000:0:0:1", "2001:db8:0:0:8000::", 65, true),
        ("2001:db8::7fff:0:0:1", "2001:db8::", 65, true),
        ("2001:db8::8000:0:0:1", "2001:db8::", 65, false),
        ("2001:db8::200:0:0:1", "2001:db8::", 70, true),
        ("2001:db8::400:0:0:1", "2001:db8::", 70, false),
        ("2001:db8::200:0:0:1", "2001:db8::", 71, false),
    ] {
        let got = cidr6(ip.as_bytes(), net.as_bytes(), Some(b));
        assert_eq!(got, want, "{ip} in {net}/{b}");
    }
}

/// unit1614's cases for the no-proxy list.
#[test]
fn unit1614_no_proxy_names_hosts() {
    let list = unit1614_rows("list[] =");
    assert_eq!(list.len(), 83);
    for row in &list {
        let (name, names, want) = (row[0].str(), row[1].str(), truth(&row[2]));
        assert_eq!(excluded(name, names), want, "{row:?}");
    }
}

/// No list, no name, and a star.
#[test]
fn no_proxy_without_a_list_or_a_name() {
    for (name, list, want) in [
        ("example.com", "", false),
        ("", "*", false),
        ("example.com", "*", true),
    ] {
        let got = excluded(name.as_bytes(), list.as_bytes());
        assert_eq!(got, want, "{name} in {list}");
    }
}

fn env_of<'a>(
    vars: &'a [(&str, &str)],
) -> impl FnMut(&[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> + 'a {
    move |name| {
        Ok(vars
            .iter()
            .find(|(n, _)| n.as_bytes() == name)
            .map(|(_, v)| v.as_bytes().to_vec()))
    }
}

fn detected(scheme: &str, vars: &[(&str, &str)]) -> Option<(String, String)> {
    let found = detect(scheme.as_bytes(), &mut env_of(vars)).unwrap();
    found.map(|v| {
        let name = String::from_utf8(v.name().to_vec()).unwrap();
        (name, String::from_utf8(v.value).unwrap())
    })
}

/// The environment names a proxy per scheme, lower case before upper, and
/// never `HTTP_PROXY`.
#[test]
fn the_environment_names_proxies_as_c() {
    let some = |n: &str, v: &str| Some((n.to_owned(), v.to_owned()));
    assert_eq!(detected("http", &[("HTTP_PROXY", "a")]), None);
    assert_eq!(
        detected("http", &[("HTTP_PROXY", "a"), ("ALL_PROXY", "b")]),
        some("ALL_PROXY", "b")
    );
    assert_eq!(
        detected("http", &[("http_proxy", "a"), ("all_proxy", "b")]),
        some("http_proxy", "a")
    );
    assert_eq!(
        detected("https", &[("HTTPS_PROXY", "a"), ("http_proxy", "b")]),
        some("HTTPS_PROXY", "a")
    );
    assert_eq!(
        detected("https", &[("https_proxy", "a"), ("HTTPS_PROXY", "b")]),
        some("https_proxy", "a")
    );
    assert_eq!(
        detected("ws", &[("http_proxy", "a")]),
        some("http_proxy", "a")
    );
    assert_eq!(
        detected("ftp", &[("FTP_PROXY", "a"), ("all_proxy", "b")]),
        some("FTP_PROXY", "a")
    );
    assert_eq!(detected("ftp", &[("http_proxy", "a")]), None);
    assert_eq!(
        detected("ftp", &[("all_proxy", "b"), ("ALL_PROXY", "c")]),
        some("all_proxy", "b")
    );
    // C's name is cut to 19 bytes: a long scheme's suffix is cut short,
    // a longer one's left off.
    let long = "abcdefghijklmn";
    assert_eq!(
        detected(
            long,
            &[("abcdefghijklmn_proxy", "a"), ("abcdefghijklmn_prox", "b")]
        ),
        some("abcdefghijklmn_prox", "b")
    );
    let longer = "abcdefghijklmnopqrstu";
    assert_eq!(
        detected(
            longer,
            &[("abcdefghijklmnopqrs_", "a"), ("ABCDEFGHIJKLMNOPQRS", "b")]
        ),
        some("ABCDEFGHIJKLMNOPQRS", "b")
    );
}

fn parsed(text: &str, kind: ProxyType, port: u16) -> Result<(ProxyType, String, u16), Refused> {
    parsed_by(text, kind, port, true)
}

/// As `parsed`, by a build with a TLS library or, `tls` false, without.
fn parsed_by(
    text: &str,
    kind: ProxyType,
    port: u16,
    tls: bool,
) -> Result<(ProxyType, String, u16), Refused> {
    let p = parse(text.as_bytes(), kind, NonZeroU16::new(port), tls)?;
    let host = String::from_utf8(p.peer.shown().to_vec()).unwrap();
    Ok((
        p.kind,
        format!("{}://{host}", p.peer.scheme().name()),
        p.peer.port(),
    ))
}

/// A proxy's URL gives its type by its scheme, or the type asked for, and
/// its port, or the one asked for, or its scheme's.
#[test]
fn proxy_urls_read_as_c() {
    use ProxyType::*;
    let ok = |k, h: &str, p| Ok((k, h.to_owned(), p));
    assert_eq!(
        parsed("127.0.0.1:8990", Http, 0),
        ok(Http, "http://127.0.0.1", 8990)
    );
    assert_eq!(
        parsed("example.com", Http, 0),
        ok(Http, "http://example.com", 80)
    );
    assert_eq!(
        parsed("example.com", Http, 3128),
        ok(Http, "http://example.com", 3128)
    );
    assert_eq!(
        parsed("http://example.com:81", Http, 3128),
        ok(Http, "http://example.com", 81)
    );
    assert_eq!(
        parsed("example.com", Http10, 0),
        ok(Http10, "http://example.com", 80)
    );
    assert_eq!(
        parsed("http://example.com", Http10, 0),
        ok(Http10, "http://example.com", 80)
    );
    assert_eq!(
        parsed("socks5h://example.com", Http, 0),
        ok(Socks5Hostname, "socks5h://example.com", 1080)
    );
    assert_eq!(
        parsed("example.com", Socks4a, 0),
        ok(Socks4a, "socks4a://example.com", 1080)
    );
    assert_eq!(
        parsed("[::1]:3128", Http, 0),
        ok(Http, "http://[::1]", 3128)
    );
    // A port the scheme has anyway is no port given (`CURLU_NO_DEFAULT_PORT`).
    assert_eq!(
        parsed("http://example.com:80", Http, 3128),
        ok(Http, "http://example.com", 3128)
    );
    assert_eq!(parsed("ftp://example.com", Http, 0), Err(Refused::Scheme));
    // A scheme no URL knows is still read, then refused as no proxy's.
    assert_eq!(
        parsed("gopherz://example.com", Http, 0),
        Err(Refused::Scheme)
    );
    // An HTTPS proxy, on 443 unless it says, of the HTTP version asked
    // for; refused by a build without TLS.
    assert_eq!(
        parsed("https://example.com", Http, 0),
        ok(Https, "https://example.com", 443)
    );
    assert_eq!(
        parsed("https://example.com:3129", Https2, 0),
        ok(Https2, "https://example.com", 3129)
    );
    assert_eq!(
        parsed("example.com", Https, 0),
        ok(Https, "https://example.com", 443)
    );
    assert_eq!(
        parsed_by("https://example.com", Http, 0, false),
        Err(Refused::Https)
    );
    assert_eq!(
        parsed_by("example.com", Https, 0, false),
        Err(Refused::Https)
    );
    assert!(matches!(
        parsed("http://exa mple", Http, 0),
        Err(Refused::Syntax(_))
    ));
    let p = parse(
        b"http://us%3Aer:p%40ss@example.com",
        ProxyType::Http,
        None,
        true,
    )
    .unwrap();
    assert_eq!(p.user.as_deref(), Some(&b"us:er"[..]));
    assert_eq!(p.password.as_deref(), Some(&b"p@ss"[..]));
    let p = parse(b"example.com", ProxyType::Http, None, true).unwrap();
    assert_eq!((p.user, p.password), (None, None));
}

/// A SOCKS proxy at `localhost` with a path is at the Unix socket of the
/// path, decoded; at `localhost` without one, or an HTTP proxy, is not
/// (`Curl_peer_from_proxy_url`).
#[test]
fn a_socks_proxy_at_localhost_with_a_path_is_a_unix_socket() {
    use crate::conn::PeerAt;
    let peer = |text: &str, kind| parse(text.as_bytes(), kind, None, true).unwrap().peer;
    let unix = peer(
        "socks5h://LocalHost/tmp/s%20ocks",
        ProxyType::Socks5Hostname,
    );
    assert_eq!(
        (unix.at(), unix.name(), unix.port()),
        (PeerAt::Unix, &b"/tmp/s ocks"[..], 1080)
    );
    for (text, kind) in [
        ("socks5://localhost/", ProxyType::Socks5),
        ("socks4://localhost", ProxyType::Socks4),
        ("http://localhost/tmp/s", ProxyType::Http),
        ("socks5://127.0.0.1/tmp/s", ProxyType::Socks5),
    ] {
        assert_eq!(peer(text, kind).at(), PeerAt::Network, "{text}");
    }
}

/// A user or password that decodes to a control byte fails with the
/// URL's error, not as the proxy's syntax (`parse_proxy`).
#[test]
fn undecodable_credentials_are_the_url_s_error() {
    for url in ["http://u%01@example.com", "http://u:p%01@example.com"] {
        assert_eq!(
            parse(url.as_bytes(), ProxyType::Http, None, true).unwrap_err(),
            Refused::Credentials(UrlErrorKind::Urldecode),
            "{url}"
        );
    }
}

const PROXY_WORDS: &[&[u8]] = &[
    b"http://",
    b"https://",
    b"socks4://",
    b"socks4a://",
    b"socks5://",
    b"socks5h://",
    b"ftp://",
    b"user",
    b":",
    b"@",
    b"%00",
    b"%41",
    b"%",
    b"host",
    b"proxy.example",
    b"[::1]",
    b"[fe80::1%25eth0]",
    b"1.2.3.4",
    b"8080",
    b"99999",
    b"/",
    b"?",
    b"#",
    b" ",
    b",",
    b"*",
    b".",
    b"/24",
    b"/129",
];
const PROXIES: &[&[u8]] = &[
    b"http://user:pass@proxy.example:8080/",
    b"socks5h://[::1]:1080",
    b"proxy.example",
    b"localhost, .example.com, 10.0.0.0/8, ::1/128",
];

fn proxy_type() -> impl Strategy<Value = ProxyType> {
    proptest::sample::select(vec![
        ProxyType::Http,
        ProxyType::Http10,
        ProxyType::Https,
        ProxyType::Https2,
        ProxyType::Https3,
        ProxyType::Socks4,
        ProxyType::Socks4a,
        ProxyType::Socks5,
        ProxyType::Socks5Hostname,
    ])
}

proptest! {
    #![proptest_config(crate::untrusted::config(256))]

    /// Any proxy URL names a proxy or is refused, and any no-proxy list
    /// is read for any host, without a panic.
    #[test]
    fn any_proxy_and_no_proxy_list_is_read(
        text in crate::untrusted::input(PROXY_WORDS, PROXIES, 12),
        kind in proxy_type(),
        port in proptest::option::of(any::<NonZeroU16>()),
        name in crate::untrusted::input(PROXY_WORDS, PROXIES, 4),
    ) {
        if let Ok(parsed) = parse(&text, kind, port, false) {
            prop_assert!(!matches!(
                parsed.kind,
                ProxyType::Https | ProxyType::Https2 | ProxyType::Https3
            ));
        }
        // With TLS, an HTTPS proxy is one by its scheme.
        if let Ok(parsed) = parse(&text, kind, port, true) {
            prop_assert_eq!(
                parsed.peer.scheme().name() == "https",
                matches!(
                    parsed.kind,
                    ProxyType::Https | ProxyType::Https2 | ProxyType::Https3
                )
            );
        }
        excluded(&name, &text);
    }
}
