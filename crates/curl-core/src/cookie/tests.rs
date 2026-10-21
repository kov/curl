use super::*;

const NOW: i64 = 1_700_000_000;

fn server<'a>(host: &'a [u8], path: &'a [u8]) -> Source<'a> {
    Source::Server {
        host,
        path,
        secure: false,
    }
}

/// Store `value` as `host` sets it for `path`, and what the jar said.
fn set(jar: &mut Jar, host: &[u8], path: &[u8], value: &[u8]) -> Option<String> {
    let mut n = 0;
    let said = jar
        .set_by(value, server(host, path), None, NOW, &mut n)
        .unwrap();
    said.map(|s| said_text(&s))
}

/// What the jar said, its lines joined by newlines.
fn said_text(said: &Said<'_>) -> String {
    let mut lines = Vec::new();
    said.lines(|parts| lines.push(String::from_utf8_lossy(&parts.concat()).into_owned()));
    lines.join("\n")
}

fn lines(jar: &Jar) -> Vec<String> {
    jar.listed()
        .map(|co| {
            let mut out = Vec::new();
            co.netscape(&mut out).unwrap();
            String::from_utf8(out).unwrap()
        })
        .collect()
}

fn sent(jar: &Jar, host: &[u8], path: &[u8], secure: bool) -> Vec<String> {
    jar.matching(host, path, secure)
        .unwrap()
        .cookies
        .iter()
        .map(|co| String::from_utf8([co.name(), b"=", co.value()].concat()).unwrap())
        .collect()
}

fn running() -> Jar {
    let mut jar = Jar::default();
    jar.start();
    jar
}

#[test]
fn hashes_as_c() {
    // From `cookie_hash_domain` and `get_top_domain`, compiled.
    for (domain, want) in [
        (&b"example.com"[..], 56),
        (b"www.example.com", 56),
        (b"a.b.EXAMPLE.com", 56),
        (b"localhost", 53),
        (b"domain..tld", 20),
        (b"www.loser.com", 27),
        (b".com", 29),
    ] {
        assert_eq!(bucket(Some(domain)), want, "{}", domain.escape_ascii());
    }
    assert_eq!(bucket(None), 0);
    assert_eq!(bucket(Some(b"127.0.0.1")), 0);
    assert_eq!(bucket(Some(b"::1")), 0);
}

#[test]
fn takes_defaults_from_the_request() {
    let mut jar = running();
    let said = set(&mut jar, b"example.com", b"/a/b/c", b" n=v\r\n");
    assert_eq!(
        said.as_deref(),
        Some("Added cookie n=\"v\" for domain example.com, path /a/b, expire 0")
    );
    assert_eq!(lines(&jar), ["example.com\tFALSE\t/a/b\tFALSE\t0\tn\tv"]);
}

#[test]
fn reads_attributes_as_c() {
    let mut jar = running();
    let secure = Source::Server {
        host: b"www.example.com",
        path: b"/",
        secure: true,
    };
    let mut n = 0;
    jar.set_by(
        b" a = b ; Path=\"/x/\"; DOMAIN=.example.com;HttpOnly; secure; Max-Age=60\r\n",
        secure,
        None,
        NOW,
        &mut n,
    )
    .unwrap();
    assert_eq!(
        lines(&jar),
        [format!(
            "#HttpOnly_.example.com\tTRUE\t/x\tTRUE\t{}\ta\tb",
            NOW + 60
        )]
    );
    // `secure` from a host that is not secure drops it.
    let said = set(&mut jar, b"h.example.com", b"/", b"s=1; secure");
    assert_eq!(said.as_deref(), Some("skipped cookie because not 'secure'"));
}

#[test]
fn drops_what_c_drops() {
    let mut jar = running();
    for (value, says) in [
        (&b"novalue"[..], "invalid cookie, dropped"),
        (b"=v", "invalid cookie, dropped"),
        (b"a\x01=v", "invalid octets in name, cookie dropped"),
        (b"a=v\x7f", "invalid octets in value, cookie dropped"),
        (
            b"a=b; domain=other.com",
            "skipped cookie with bad tailmatch domain: other.com",
        ),
        // Without a list of public suffixes, a domain needs a dot.
        (
            b"a=b; domain=.com",
            "skipped cookie with bad tailmatch domain: com",
        ),
    ] {
        assert_eq!(
            set(&mut jar, b"www.example.com", b"/", value).as_deref(),
            Some(says),
            "{}",
            value.escape_ascii()
        );
    }
    let mut big = b"n=".to_vec();
    big.resize(2 + 4096, b'v');
    assert_eq!(
        set(&mut jar, b"example.com", b"/", &big).as_deref(),
        Some("oversized cookie dropped, name/val 1 + 4096 bytes")
    );
    big.pop();
    assert!(set(&mut jar, b"example.com", b"/", &big).is_some_and(|s| s.starts_with("Added")));
    // Past 5000 bytes, a line is passed over without a word.
    let mut long = b"n=v; path=/".to_vec();
    long.resize(5001, b'x');
    assert_eq!(set(&mut jar, b"example.com", b"/", &long), None);
    assert_eq!(jar.len(), 1);
}

#[test]
fn caps_expiry_at_400_days() {
    let mut jar = running();
    set(&mut jar, b"example.com", b"/", b"a=b; max-age=99999999999");
    set(
        &mut jar,
        b"example.com",
        b"/",
        b"c=d; expires=Fri, 13-Feb-2525 11:56:27 GMT",
    );
    // `Max-Age` goes before `Expires`; one that cannot be read expires it.
    set(
        &mut jar,
        b"example.com",
        b"/",
        b"e=f; max-age=-1; expires=Fri, 13-Feb-2525 11:56:27 GMT",
    );
    let cap = (NOW + 400 * 24 * 3600 + 30) / 60 * 60;
    let want: Vec<_> = [("a", "b", cap), ("c", "d", cap), ("e", "f", 1)]
        .iter()
        .map(|(n, v, e)| format!("example.com\tFALSE\t/\tFALSE\t{e}\t{n}\t{v}"))
        .collect();
    assert_eq!(lines(&jar), want);
}

#[test]
fn reads_netscape_lines_as_c() {
    let mut jar = Jar::default();
    let file = b"# a comment\n\
        .example.com\tTRUE\t/p/\tFALSE\t0\tfull\tv\n\
        #HttpOnly_example.com\tFALSE\t/\tFALSE\t2000000000\th\tw\n\
        example.com\tT\t\t0\tempty\n\
        example.com\tFALSE\t\tFALSE\t0\tshifted\tv\n\
        example.com\tFALSE\tFALSE\t0\tnopath\tx\n\
        example.com\tFALSE\t/\tTRUE\t0\tsec\ty\n\
        example.com\tFALSE\t/\tFALSE\tsoon\tbad\tz\n\
        example.com\tFALSE\t/\tFALSE\t0\tctl\t\x01\n\
        example.com\tFALSE\t/\tFALSE\t0\ttoo\tmany\tfields\n\
        \n";
    jar.load(file, false, false, None, NOW).unwrap();
    assert!(jar.running());
    let mut got = lines(&jar);
    got.sort();
    assert_eq!(
        got,
        [
            "#HttpOnly_example.com\tFALSE\t/\tFALSE\t2000000000\th\tw",
            // An empty path reads as the secure field, and the fields
            // after it move up one: a line that wrote one is lost.
            ".example.com\tTRUE\t/\tTRUE\t0\tempty\t",
            ".example.com\tTRUE\t/p\tFALSE\t0\tfull\tv",
            "example.com\tFALSE\t/\tFALSE\t0\tnopath\tx",
            "example.com\tFALSE\t/\tTRUE\t0\tsec\ty",
        ]
    );
}

#[test]
fn passes_over_session_cookies_in_a_new_session() {
    let mut jar = Jar::default();
    let file = b"example.com\tFALSE\t/\tFALSE\t0\tsession\tv\n\
        example.com\tFALSE\t/\tFALSE\t2000000000\tkept\tw\n\
        Set-Cookie: hdr=x; domain=example.com\n";
    jar.load(file, true, false, None, NOW).unwrap();
    assert_eq!(
        lines(&jar),
        ["example.com\tFALSE\t/\tFALSE\t2000000000\tkept\tw"]
    );
    jar.load(file, false, false, None, NOW).unwrap();
    assert_eq!(jar.len(), 3);
}

#[test]
fn replaces_in_place_of_time_and_keeps_live_cookies() {
    let mut jar = Jar::default();
    jar.load(
        b"example.com\tFALSE\t/\tFALSE\t0\ta\tfile\n",
        false,
        false,
        None,
        NOW,
    )
    .unwrap();
    set(&mut jar, b"example.com", b"/", b"b=1");
    // The server's replaces the file's, keeping its creation time: older
    // than `b`, it goes after it.
    let said = set(&mut jar, b"example.com", b"/", b"a=live");
    assert_eq!(
        said.as_deref(),
        Some("Replaced cookie a=\"live\" for domain example.com, path /, expire 0")
    );
    assert_eq!(jar.len(), 2);
    assert_eq!(sent(&jar, b"example.com", b"/", false), ["b=1", "a=live"]);
    // A file read again does not replace what a server set.
    jar.load(
        b"example.com\tFALSE\t/\tFALSE\t0\ta\tfile\n",
        false,
        false,
        None,
        NOW,
    )
    .unwrap();
    assert_eq!(sent(&jar, b"example.com", b"/", false), ["b=1", "a=live"]);
}

#[test]
fn refuses_to_overlay_a_secure_cookie() {
    let mut jar = running();
    let mut n = 0;
    let secure = Source::Server {
        host: b"example.com",
        path: b"/",
        secure: true,
    };
    jar.set_by(b"a=s; secure; path=/login", secure, None, NOW, &mut n)
        .unwrap();
    let said = set(&mut jar, b"example.com", b"/", b"a=plain; path=/login/en");
    assert_eq!(
        said.as_deref(),
        Some("cookie 'a' for domain 'example.com' dropped, would overlay an existing cookie")
    );
    // Though C's comment says `/loginhelper` may, it compares the old
    // path's first segment as a prefix.
    assert!(
        set(
            &mut jar,
            b"example.com",
            b"/",
            b"a=plain; path=/loginhelper"
        )
        .is_some_and(|s| s.contains("overlay"))
    );
    assert!(
        set(&mut jar, b"example.com", b"/", b"a=plain; path=/other")
            .is_some_and(|s| s.starts_with("Added"))
    );
}

#[test]
fn matches_hosts_paths_and_security_as_c() {
    let mut jar = running();
    let mut n = 0;
    let secure = Source::Server {
        host: b"www.example.com",
        path: b"/",
        secure: true,
    };
    jar.set_by(b"s=1; secure", secure, None, NOW, &mut n)
        .unwrap();
    set(
        &mut jar,
        b"www.example.com",
        b"/",
        b"d=1; domain=example.com",
    );
    set(&mut jar, b"www.example.com", b"/", b"h=1");
    set(&mut jar, b"www.example.com", b"/", b"p=1; path=/dir");
    set(
        &mut jar,
        b"www.example.com",
        b"/",
        b"longer=1; path=/dir/sub",
    );
    assert_eq!(
        sent(&jar, b"www.example.com", b"/dir/sub/x", false),
        ["longer=1", "p=1", "h=1", "d=1"]
    );
    // A longer domain goes first, then the newer.
    assert_eq!(
        sent(&jar, b"www.example.com", b"/dirt", true),
        ["h=1", "s=1", "d=1"]
    );
    assert_eq!(sent(&jar, b"a.example.com", b"/", true), ["d=1"]);
    assert_eq!(sent(&jar, b"WWW.EXAMPLE.COM", b"", false), ["h=1", "d=1"]);
    assert!(sent(&jar, b"badexample.com", b"/", true).is_empty());
    // A host that ends in the domain, but not after a dot, is not in it;
    // it hashes with the domain, so the jar looks at the cookie.
    set(
        &mut jar,
        b"www.example.com",
        b"/",
        b"w=1; domain=www.example.com",
    );
    assert_eq!(sent(&jar, b"awww.example.com", b"/", true), ["d=1"]);
}

#[test]
fn caps_the_cookies_a_request_sends() {
    let mut jar = Jar::default();
    let mut file = Vec::new();
    for i in 0..200 {
        file.extend_from_slice(format!("example.com\tFALSE\t/\tFALSE\t0\tc{i}\tv\n").as_bytes());
    }
    jar.load(&file, false, false, None, NOW).unwrap();
    let m = jar.matching(b"example.com", b"/", false).unwrap();
    assert!(m.capped);
    assert_eq!(m.cookies.len(), 150);
    assert_eq!(
        m.capped_line(|p| p.concat()),
        b"Included max number of cookies (150) in request!"
    );
}

#[test]
fn stores_50_set_cookie_lines_a_request() {
    let mut jar = running();
    let mut n = 0;
    for i in 0..60 {
        let line = format!("c{i}=v");
        jar.set_by(
            line.as_bytes(),
            server(b"example.com", b"/"),
            None,
            NOW,
            &mut n,
        )
        .unwrap();
    }
    assert_eq!((jar.len(), n), (50, 50));
}

#[test]
fn sweeps_expired_cookies() {
    let mut jar = running();
    set(&mut jar, b"example.com", b"/", b"a=1; max-age=10");
    set(&mut jar, b"example.com", b"/", b"b=1");
    jar.sweep(NOW + 10);
    assert_eq!(jar.len(), 2);
    jar.sweep(NOW + 11);
    assert_eq!(sent(&jar, b"example.com", b"/", false), ["b=1"]);
    assert_eq!(jar.len(), 1);
}

#[test]
fn writes_a_file_newest_first() {
    let mut jar = running();
    set(&mut jar, b"example.com", b"/", b"old=1");
    set(&mut jar, b"other.org", b"/", b"new=2; domain=other.org");
    let mut out = Vec::new();
    jar.file(NOW, &mut out).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "# Netscape HTTP Cookie File\n\
         # https://curl.se/docs/http-cookies.html\n\
         # This file was generated by libcurl! Edit at your own risk.\n\n\
         .other.org\tTRUE\t/\tFALSE\t0\tnew\t2\n\
         example.com\tFALSE\t/\tFALSE\t0\told\t1\n"
    );
}

#[test]
fn clears_all_or_the_session() {
    let mut jar = running();
    set(&mut jar, b"example.com", b"/", b"a=1; max-age=100");
    set(&mut jar, b"example.com", b"/", b"b=1");
    jar.clear_session();
    assert_eq!(sent(&jar, b"example.com", b"/", false), ["a=1"]);
    jar.clear();
    assert_eq!(jar.len(), 0);
    assert!(jar.listed().next().is_none());
}

#[test]
fn takes_application_lines_of_both_forms() {
    let mut jar = Jar::default();
    let mut n = 0;
    jar.add_line(b"Set-Cookie: a=1; domain=example.com", None, NOW, &mut n)
        .unwrap();
    jar.add_line(b"example.com\tFALSE\t/\tTRUE\t0\tb\t2", None, NOW, &mut n)
        .unwrap();
    // A `Set-Cookie:` line counts against the request's.
    assert_eq!(n, 1);
    let mut got = lines(&jar);
    got.sort();
    assert_eq!(
        got,
        [
            // No path: written as `/`.
            ".example.com\tTRUE\t/\tFALSE\t0\ta\t1",
            "example.com\tFALSE\t/\tTRUE\t0\tb\t2",
        ]
    );
}

/// A list naming `com` and `co.uk` alone.
struct Two;

impl PublicSuffixes for Two {
    fn is_public_suffix(&self, domain: &[u8]) -> bool {
        domain == b"com" || domain == b"co.uk"
    }

    fn accepts(&self, host: &[u8], domain: &[u8]) -> bool {
        !self.is_public_suffix(domain) || host == domain
    }
}

#[test]
fn checks_public_suffixes() {
    let mut jar = running();
    let mut n = 0;
    let said = jar
        .set_by(
            b"a=1; domain=com",
            server(b"x.com", b"/"),
            Some(&Two),
            NOW,
            &mut n,
        )
        .unwrap()
        .map(|s| said_text(&s));
    assert_eq!(
        said.as_deref(),
        Some("cookie 'a' dropped, domain 'x.com' must not set cookies for 'com'")
    );
    // A suffix may set one for itself alone.
    jar.set_by(
        b"b=1; domain=co.uk",
        server(b"CO.UK", b"/"),
        Some(&Two),
        NOW,
        &mut n,
    )
    .unwrap();
    assert_eq!(lines(&jar), ["co.uk\tFALSE\t/\tFALSE\t0\tb\t1"]);
    // With a list, a domain needs no dot.
    jar.set_by(
        b"c=1; domain=localhost",
        server(b"localhost", b"/"),
        Some(&Two),
        NOW,
        &mut n,
    )
    .unwrap();
    assert_eq!(jar.len(), 2);
    // A file's cookie on a suffix goes to that domain alone.
    jar.load(
        b".com\tTRUE\t/\tFALSE\t0\tf\t1\n",
        false,
        false,
        Some(&Two),
        NOW,
    )
    .unwrap();
    assert!(lines(&jar).contains(&"com\tFALSE\t/\tFALSE\t0\tf\t1".into()));
}

#[test]
fn requires_what_prefixes_promise() {
    let mut jar = running();
    let mut n = 0;
    let secure = Source::Server {
        host: b"example.com",
        path: b"/",
        secure: true,
    };
    for line in [
        &b"__Secure-a=1"[..],
        b"__Host-b=1; secure; path=/x",
        b"__Host-c=1; secure; domain=example.com",
    ] {
        assert!(
            jar.set_by(line, secure, None, NOW, &mut n)
                .unwrap()
                .is_none()
        );
    }
    for line in [&b"__Secure-a=1; secure"[..], b"__Host-b=1; secure; path=/"] {
        assert!(
            jar.set_by(line, secure, None, NOW, &mut n)
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(jar.len(), 2);
}

#[test]
fn writes_negative_expiry_with_its_sign() {
    let mut buf = [0u8; 20];
    assert_eq!(signed(-12, &mut buf), b"-12");
    assert_eq!(signed(i64::MIN, &mut buf), b"-9223372036854775808");
    assert_eq!(signed(0, &mut buf), b"0");
}

/// A list that could not be had.
struct Missing;

impl PublicSuffixes for Missing {
    fn is_public_suffix(&self, _: &[u8]) -> bool {
        unreachable!("not asked without the list")
    }

    fn accepts(&self, _: &[u8], _: &[u8]) -> bool {
        unreachable!("not asked without the list")
    }

    fn available(&self) -> bool {
        false
    }
}

#[test]
fn without_the_list_every_domain_is_refused() {
    let mut jar = running();
    let mut n = 0;
    let said = jar
        .set_by(
            b"a=1",
            server(b"example.com", b"/"),
            Some(&Missing),
            NOW,
            &mut n,
        )
        .unwrap()
        .map(|s| said_text(&s));
    assert_eq!(
        said.as_deref(),
        Some(
            "libpsl problem, rejecting cookie for safety\n\
             cookie 'a' dropped, domain 'example.com' must not set cookies for 'example.com'"
        )
    );
    // An address needs no list.
    jar.set_by(
        b"b=1",
        server(b"127.0.0.1", b"/"),
        Some(&Missing),
        NOW,
        &mut n,
    )
    .unwrap();
    assert_eq!(jar.len(), 1);
}
