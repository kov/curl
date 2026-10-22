use super::*;

/// Unit 1614's cases for the address ranges.
#[test]
fn ranges_hold_addresses_as_c() {
    let bits = |b: i32| u32::try_from(b).ok();
    for (ip, net, b, want) in [
        ("192.160.0.1", "192.160.0.1", 33, false),
        ("192.160.0.1", "192.160.0.1", 32, true),
        ("192.160.0.1", "192.160.0.1", 0, true),
        ("192.160.0.1", "192.160.0.1", 24, true),
        ("192.160.0.1", "192.160.0.1", 26, true),
        ("192.160.0.1", "192.160.0.1", 20, true),
        ("192.160.0.1", "192.160.0.1", 18, true),
        ("192.160.0.1", "192.160.0.1", 12, true),
        ("192.160.0.1", "192.160.0.1", 8, true),
        ("192.160.0.1", "10.0.0.1", 8, false),
        ("192.160.0.1", "10.0.0.1", 32, false),
        ("192.160.0.1", "10.0.0.1", 0, false),
        ("192.160.0.1", "0.0.0.0", 0, true),
        ("0.0.0.1", "0.0.0.0", 0, true),
        ("127.0.0.1", "0.0.0.0", 0, true),
        ("0.0.0.1", "0.0.0.0", -1, false),
        ("127.0.0.1", "0.0.0.0", -1, false),
    ] {
        let got = cidr4(ip.as_bytes(), net.as_bytes(), bits(b));
        assert_eq!(got, want, "{ip} in {net}/{b}");
    }
    for (ip, net, b, want) in [
        ("::1", "::1", 0, true),
        ("::1", "::1", 128, true),
        ("::1", "0:0::1", 128, true),
        ("::1", "0:0::1", 129, false),
        (
            "fe80::ab47:4396:55c9:8474",
            "fe80::ab47:4396:55c9:8474",
            64,
            true,
        ),
        ("fe80::ab47:4396:55c9:8474", "::", 0, true),
        ("::1", "::", 0, true),
        ("::1", "::", -1, false),
    ] {
        let got = cidr6(ip.as_bytes(), net.as_bytes(), bits(b));
        assert_eq!(got, want, "{ip} in {net}/{b}");
    }
}

/// Unit 1614's cases for the no-proxy list.
#[test]
fn the_no_proxy_list_names_hosts_as_c() {
    let long128 = "localhost,127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.\
                   127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.\
                   0.0.1.127.0.0.1.127.0.0.";
    let long127 = &long128[..long128.len() - 1];
    for (name, list, want) in [
        (
            "www.example.com",
            "localhost .example.com .example.de",
            false,
        ),
        (
            "www.example.com",
            "localhost,.example.com,.example.de",
            true,
        ),
        (
            "www.example.com.",
            "localhost,.example.com,.example.de",
            true,
        ),
        ("example.com", "localhost,.example.com,.example.de", true),
        ("example.com.", "localhost,.example.com,.example.de", true),
        (
            "www.example.com",
            "localhost,.example.com.,.example.de",
            true,
        ),
        (
            "www.example.com",
            "localhost,www.example.com.,.example.de",
            true,
        ),
        ("example.com", "localhost,example.com,.example.de", true),
        ("example.com.", "localhost,example.com,.example.de", true),
        ("nexample.com", "localhost,example.com,.example.de", false),
        ("www.example.com", "localhost,example.com,.example.de", true),
        ("127.0.0.1", "127.0.0.1,localhost", true),
        ("127.0.0.1", "127.0.0.1,localhost,", true),
        ("127.0.0.1", "127.0.0.1/8,localhost,", true),
        ("127.0.0.1", "127.0.0.1/28,localhost,", true),
        ("127.0.0.1", "127.0.0.1/31,localhost,", true),
        ("127.0.0.1", "localhost,127.0.0.1", true),
        ("127.0.0.1", long128, false),
        ("127.0.0.1", long127, false),
        ("localhost", "localhost,127.0.0.1", true),
        ("localhost", "127.0.0.1,localhost", true),
        ("foobar", "barfoo", false),
        ("foobar", "foobar", true),
        ("192.168.0.1", "foobar", false),
        ("192.168.0.1", "192.168.0.0/16", true),
        ("192.168.0.1", "192.168.0.0/16a", false),
        ("192.168.0.1", "192.168.0.0/16 ", true),
        ("192.168.0.1", "192.168.0.0/a16", false),
        ("192.168.0.1", "192.168.0.0/ 16", false),
        ("192.168.0.1", "192.168.0.0/24", true),
        ("192.168.0.1", "192.168.0.0/32", false),
        ("192.168.0.1", "192.168.0.1/32", true),
        ("192.168.0.1", "192.168.0.1/33", false),
        ("192.168.0.1", "192.168.0.0", false),
        ("192.168.1.1", "192.168.0.0/24", false),
        ("192.168.1.1", "192.168.0.0/33", false),
        ("192.168.1.1", "foo, bar, 192.168.0.0/24", false),
        ("192.168.1.1", "foo, bar, 192.168.0.0/16", true),
        ("192.168.1.1", "0.0.0.0/0", true),
        ("192.168.1.1", "0.0.0.0", false),
        ("::1", "::/0", true),
        ("::1", "::", false),
        ("::1", "::/128", false),
        ("::1", "foo, bar, 192.168.0.0/16", false),
        ("::1", "foo, bar, ::1/64", true),
        ("::1", "::1/64", true),
        ("::1", "::1/96", true),
        ("::1", "::1/129", false),
        ("::1", "::1/128", true),
        ("::1", "::1/127", true),
        ("::1", "::1/a127", false),
        ("::1", "::1/127a", false),
        ("::1", "::1/ 127", false),
        ("::1", "::1/127 ", true),
        ("::1", "::1/126", true),
        ("::1", "::1/125", true),
        ("::1", "::1/124", true),
        ("::1", "::1/123", true),
        ("::1", "::1/122", true),
        ("2001:db8:8000::1", "2001:db8::/65", false),
        ("2001:db8:8000::1", "2001:db8::/66", false),
        ("2001:db8:8000::1", "2001:db8::/67", false),
        ("2001:db8:8000::1", "2001:db8::/68", false),
        ("2001:db8:8000::1", "2001:db8::/69", false),
        ("2001:db8:8000::1", "2001:db8::/70", false),
        ("2001:db8:8000::1", "2001:db8::/71", false),
        ("2001:db8:8000::1", "2001:db8::/72", false),
        ("2001:db8::1", "2001:db8::/65", true),
        ("2001:db8::1", "2001:db8::/66", true),
        ("2001:db8::1", "2001:db8::/67", true),
        ("2001:db8::1", "2001:db8::/68", true),
        ("2001:db8::1", "2001:db8::/69", true),
        ("2001:db8::1", "2001:db8::/70", true),
        ("2001:db8::1", "2001:db8::/71", true),
        ("2001:db8::1", "2001:db8::/72", true),
        ("bar", "foo, bar, ::1/64", true),
        ("BAr", "foo, bar, ::1/64", true),
        ("BAr", "foo,,,,,              bar, ::1/64", true),
        ("www.example.com", "foo, .example.com", true),
        ("www.example.com", "www2.example.com, .example.net", false),
        ("example.com", ".example.com, .example.net", true),
        ("nonexample.com", ".example.com, .example.net", false),
        // And without a list or a name.
        ("example.com", "", false),
        ("", "*", false),
        ("example.com", "*", true),
    ] {
        let got = excluded(name.as_bytes(), list.as_bytes());
        assert_eq!(got, want, "{name} in {list}");
    }
}

fn env_of<'a>(vars: &'a [(&str, &str)]) -> impl FnMut(&[u8]) -> Option<Vec<u8>> + 'a {
    move |name| {
        vars.iter()
            .find(|(n, _)| n.as_bytes() == name)
            .map(|(_, v)| v.as_bytes().to_vec())
    }
}

fn detected(scheme: &str, vars: &[(&str, &str)]) -> Option<(String, String)> {
    let found = detect(scheme.as_bytes(), &mut env_of(vars));
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
}

fn parsed(text: &str, kind: ProxyType, port: u16) -> Result<(ProxyType, String, u16), Refused> {
    let p = parse(text.as_bytes(), kind, NonZeroU16::new(port))?;
    let host = String::from_utf8(p.peer.shown().to_vec()).unwrap();
    Ok((
        p.kind,
        format!("{}://{host}", p.peer.scheme().name),
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
    assert_eq!(parsed("ftp://example.com", Http, 0), Err(Refused::Scheme));
    assert_eq!(parsed("https://example.com", Http, 0), Err(Refused::Https));
    assert_eq!(parsed("example.com", Https, 0), Err(Refused::Https));
    assert!(matches!(
        parsed("http://exa mple", Http, 0),
        Err(Refused::Syntax(_))
    ));
    let p = parse(b"http://us%3Aer:p%40ss@example.com", ProxyType::Http, None).unwrap();
    assert_eq!(p.user.as_deref(), Some(&b"us:er"[..]));
    assert_eq!(p.password.as_deref(), Some(&b"p@ss"[..]));
    let p = parse(b"example.com", ProxyType::Http, None).unwrap();
    assert_eq!((p.user, p.password), (None, None));
}
