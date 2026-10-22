use proptest::prelude::*;

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

/// Store `value` as `host` sets it at `now`, over a connection that is not
/// secure; what the jar said.
fn set_at(jar: &mut Jar, host: &[u8], value: &[u8], now: i64) -> Option<String> {
    let mut n = 0;
    let said = jar
        .set_by(value, server(host, b"/"), None, now, &mut n)
        .unwrap();
    said.map(|s| said_text(&s))
}

fn names(jar: &Jar) -> Vec<String> {
    let mut names: Vec<_> = jar
        .listed()
        .map(|co| String::from_utf8(co.name().to_vec()).unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn sweeps_from_the_earliest_expiry() {
    // A cookie that expires before those stored earlier is swept when it
    // does; one that expires later does not delay that.
    let mut jar = running();
    for value in [
        &b"a=1; max-age=10"[..],
        b"b=1; max-age=5",
        b"c=1; max-age=20",
    ] {
        set(&mut jar, b"example.com", b"/", value);
    }
    jar.sweep(NOW + 6);
    assert_eq!(names(&jar), ["a", "c"]);
    assert_eq!(jar.len(), 2);

    // A sweep finds the earliest of those left, not the last it looked
    // at.
    let mut jar = running();
    for value in [
        &b"x=1; max-age=1"[..],
        b"b=1; max-age=5",
        b"a=1; max-age=10",
    ] {
        set(&mut jar, b"example.com", b"/", value);
    }
    jar.sweep(NOW + 2);
    assert_eq!(names(&jar), ["a", "b"]);
    jar.sweep(NOW + 6);
    assert_eq!(names(&jar), ["a"]);
}

#[test]
fn a_server_s_cookie_sweeps_and_a_file_s_line_does_not() {
    // Storing what a server sets sweeps first.
    let mut jar = running();
    set_at(&mut jar, b"example.com", b"a=1; max-age=10", NOW);
    set_at(&mut jar, b"example.com", b"b=1", NOW + 20);
    assert_eq!(jar.len(), 1);
    assert_eq!(names(&jar), ["b"]);

    // A file is swept once it is read: an expired cookie a later line
    // replaces gives it its creation time, older than the line between.
    let mut jar = Jar::default();
    jar.load(
        b"example.com\tFALSE\t/\tFALSE\t5\ta\told\n\
          example.com\tFALSE\t/\tFALSE\t0\tb\t1\n\
          example.com\tFALSE\t/\tFALSE\t0\ta\tnew\n",
        false,
        false,
        None,
        NOW,
    )
    .unwrap();
    let mut out = Vec::new();
    jar.file(NOW, &mut out).unwrap();
    assert!(
        out.ends_with(
            b"\n\nexample.com\tFALSE\t/\tFALSE\t0\tb\t1\n\
              example.com\tFALSE\t/\tFALSE\t0\ta\tnew\n"
        ),
        "{}",
        out.escape_ascii()
    );
}

#[test]
fn files_and_the_application_are_not_checked_against_suffixes() {
    // Without the list a server's cookie is refused; the application's
    // lines and a reload's are taken all the same.
    let mut jar = Jar::default();
    let mut n = 0;
    jar.add_line(
        b"example.com\tFALSE\t/\tFALSE\t0\tapp\t1",
        Some(&Missing),
        NOW,
        &mut n,
    )
    .unwrap();
    jar.load(
        b"example.com\tFALSE\t/\tFALSE\t0\treload\t1\n",
        false,
        true,
        Some(&Missing),
        NOW,
    )
    .unwrap();
    assert_eq!(names(&jar), ["app", "reload"]);
    // A file read untrusted is checked.
    jar.load(
        b"example.com\tFALSE\t/\tFALSE\t0\tfile\t1\n",
        false,
        false,
        Some(&Missing),
        NOW,
    )
    .unwrap();
    assert_eq!(names(&jar), ["app", "reload"]);
}

#[test]
fn replaces_only_the_same_domain_and_path() {
    let mut jar = running();
    set(&mut jar, b"example.com", b"/", b"a=1");
    // A server replaces its own.
    assert!(set(&mut jar, b"example.com", b"/", b"a=2").is_some_and(|s| s.starts_with("Replaced")));
    // The same domain for the hosts below it is another cookie.
    assert!(
        set(&mut jar, b"example.com", b"/", b"a=3; domain=example.com")
            .is_some_and(|s| s.starts_with("Added"))
    );
    assert_eq!(jar.len(), 2);

    // Lines without a domain replace one another.
    let mut jar = Jar::default();
    jar.load(
        b"Set-Cookie: a=1\nSet-Cookie: a=2\n",
        false,
        false,
        None,
        NOW,
    )
    .unwrap();
    assert_eq!(jar.len(), 1);
}

#[test]
fn a_secure_cookie_is_not_overlaid_from_a_domain_it_covers() {
    let mut jar = running();
    let mut n = 0;
    let secure = Source::Server {
        host: b"www.example.com",
        path: b"/",
        secure: true,
    };
    jar.set_by(
        b"a=s; secure; domain=example.com; path=/login/en",
        secure,
        None,
        NOW,
        &mut n,
    )
    .unwrap();
    // The host's own domain is below the secure cookie's.
    assert!(
        set(
            &mut jar,
            b"www.example.com",
            b"/",
            b"a=plain; path=/login/fr"
        )
        .is_some_and(|s| s.contains("overlay"))
    );
    // Only the old path's first segment is compared.
    assert!(
        set(&mut jar, b"www.example.com", b"/", b"a=plain; path=/logi")
            .is_some_and(|s| s.starts_with("Added"))
    );
    // A cookie for a sibling host, hashed with it, overlays nothing.
    jar.set_by(b"b=s; secure; path=/login", secure, None, NOW, &mut n)
        .unwrap();
    assert!(
        set(&mut jar, b"api.example.com", b"/", b"b=plain; path=/login")
            .is_some_and(|s| s.starts_with("Added"))
    );
}

#[test]
fn a_cookie_for_its_host_alone_goes_to_no_other() {
    let mut jar = running();
    set(&mut jar, b"example.com", b"/", b"h=1");
    assert_eq!(sent(&jar, b"example.com", b"/", false), ["h=1"]);
    assert!(sent(&jar, b"www.example.com", b"/", false).is_empty());
}

#[test]
fn clearing_the_session_counts_what_is_left() {
    let mut jar = running();
    set(&mut jar, b"example.com", b"/", b"a=1; max-age=100");
    set(&mut jar, b"example.com", b"/", b"b=1");
    set(&mut jar, b"example.com", b"/", b"c=1");
    jar.clear_session();
    assert_eq!(jar.len(), 1);
}

#[test]
fn reads_lines_and_dates_up_to_their_limits() {
    // A line of 5000 bytes is read.
    let mut jar = running();
    let mut long = b"n=v; path=/".to_vec();
    long.resize(5000, b'x');
    assert!(set(&mut jar, b"example.com", b"/", &long).is_some_and(|s| s.starts_with("Added")));

    // An `Expires` of 80 bytes is not read as a date; one of 79 is.
    let date = |len: usize| {
        let mut v = b"Mon,".to_vec();
        v.resize(len - 25, b' ');
        v.extend_from_slice(b"01 Jan 2024 00:00:00 GMT");
        v.insert(4, b' ');
        assert_eq!(v.len(), len);
        v
    };
    let mut jar = running();
    for (name, len) in [("long", 80), ("short", 79)] {
        let mut value = format!("{name}=1; expires=").into_bytes();
        value.extend_from_slice(&date(len));
        set(&mut jar, b"example.com", b"/", &value);
    }
    let mut got = lines(&jar);
    got.sort();
    assert_eq!(
        got,
        [
            "example.com\tFALSE\t/\tFALSE\t0\tlong\t1",
            "example.com\tFALSE\t/\tFALSE\t1704067200\tshort\t1",
        ]
    );
}

#[test]
fn an_address_sets_a_domain_only_for_itself() {
    let mut jar = running();
    assert!(
        set(&mut jar, b"127.0.0.1", b"/", b"a=1; domain=127.0.0.1")
            .is_some_and(|s| s.starts_with("Added"))
    );
    assert_eq!(
        set(&mut jar, b"127.0.0.1", b"/", b"b=1; domain=127.0.0.2").as_deref(),
        Some("skipped cookie with bad tailmatch domain: 127.0.0.2")
    );
    assert_eq!(lines(&jar), ["127.0.0.1\tFALSE\t/\tFALSE\t0\ta\t1"]);
}

#[test]
fn without_a_list_a_domain_s_dot_is_not_its_last_byte() {
    let mut jar = running();
    assert_eq!(
        set(&mut jar, b"example.", b"/", b"a=1; domain=example.").as_deref(),
        Some("skipped cookie with bad tailmatch domain: example.")
    );
    assert!(set(&mut jar, b"localhost", b"/", b"a=1; domain=localhost").is_some());
    assert_eq!(jar.len(), 1);
}

/// A list where `foo.ck` is a public suffix only by a wildcard rule, which
/// libpsl does not hold against a cookie's domain: `www.foo.ck` may set
/// one for `foo.ck`.
struct Wildcard;

impl PublicSuffixes for Wildcard {
    fn is_public_suffix(&self, domain: &[u8]) -> bool {
        domain == b"foo.ck"
    }

    fn accepts(&self, _: &[u8], _: &[u8]) -> bool {
        true
    }
}

#[test]
fn only_a_suffix_s_own_cookie_is_for_it_alone() {
    let mut jar = running();
    let mut n = 0;
    for (host, value) in [
        // A suffix allowed from a host below it goes to the hosts below.
        (&b"www.foo.ck"[..], &b"a=1; domain=foo.ck"[..]),
        // A domain that is no suffix set by its own host goes below it.
        (b"example.com", b"b=1; domain=example.com"),
        // A suffix set by itself is for it alone.
        (b"foo.ck", b"c=1; domain=foo.ck"),
    ] {
        jar.set_by(value, server(host, b"/"), Some(&Wildcard), NOW, &mut n)
            .unwrap();
    }
    let mut got = lines(&jar);
    got.sort();
    assert_eq!(
        got,
        [
            ".example.com\tTRUE\t/\tFALSE\t0\tb\t1",
            ".foo.ck\tTRUE\t/\tFALSE\t0\ta\t1",
            "foo.ck\tFALSE\t/\tFALSE\t0\tc\t1",
        ]
    );
}

#[test]
fn expiry_is_capped_without_overflowing() {
    const MAX: i64 = i64::MAX;
    let rounded = |now: i64| (now + MAX_AGE + 30) / 60 * 60;
    let far = "max-age=99999999999999999999";
    for (value, now, want) in [
        // Exactly 400 days is not rounded.
        ("max-age=34560000", NOW, NOW + MAX_AGE),
        // Past the largest time from now: capped.
        ("max-age=9223372036854775000", NOW, rounded(NOW)),
        // Far in the future, still capped where 400 days fit.
        ("max-age=10000000", 1_000_000_000_000, 1_000_010_000_000),
        (
            far,
            (MAX - MAX_AGE) / 30 + 1,
            rounded((MAX - MAX_AGE) / 30 + 1),
        ),
        // Where they do not, not capped.
        (far, MAX - MAX_AGE - 30, MAX),
        ("max-age=5", MAX - 10, MAX - 5),
    ] {
        let mut jar = running();
        set_at(
            &mut jar,
            b"example.com",
            format!("a=1; {value}").as_bytes(),
            now,
        );
        let co = jar.listed().next().unwrap();
        assert_eq!(co.expires, want, "{value} at {now}");
    }
}

#[test]
fn suffixes_debug_as_a_name() {
    let list = Suffixes::new(Box::new(Two)).unwrap();
    assert_eq!(format!("{list:?}"), "Suffixes");
}

const COOKIE_WORDS: &[&[u8]] = &[
    b"a=b",
    b"name=value",
    b"; ",
    b";",
    b"=",
    b"Domain=",
    b"domain=.example.com",
    b"domain=com",
    b"Path=/",
    b"path=/x/",
    b"Secure",
    b"HttpOnly",
    b"SameSite=Lax",
    b"Expires=Tue, 09 Nov 2010 14:49:00 GMT",
    b"expires=",
    b"Max-Age=",
    b"-1",
    b"0",
    b"99999999999999999999",
    b"__Secure-",
    b"__Host-",
    b"\t",
    b"TRUE",
    b"FALSE",
    b"#HttpOnly_",
    b".example.com",
    b"example.com",
    b"www.example.com",
    b"com",
    b"co.uk",
    b"\n",
    b"\r\n",
    b"\"",
    b"\0",
    b"\x7f",
    b" ",
    b"Set-Cookie: ",
    b"#",
];
const COOKIE_LINES: &[&[u8]] = &[
    b"a=1; Domain=.example.com; Path=/; Secure; Max-Age=60",
    b"__Host-x=y; Secure; Path=/",
    b"Set-Cookie: b=2; expires=Tue, 09 Nov 2010 14:49:00 GMT; HttpOnly\n",
    b".example.com\tTRUE\t/\tFALSE\t0\ta\t1\n",
    b"#HttpOnly_example.com\tFALSE\t/x\tTRUE\t2000000000\tb\t2\n",
    b"www.example.com\tFALSE\t/\tFALSE\t0\tempty\t\n",
];
const HOSTS: &[&[u8]] = &[
    b"example.com",
    b"www.example.com",
    b"com",
    b"127.0.0.1",
    b"[::1]",
];
const PATHS: &[&[u8]] = &[b"/", b"/x/y", b"", b"/x"];

#[derive(Clone, Debug)]
enum JarOp {
    /// A file's text read in.
    Load {
        text: Vec<u8>,
        new_session: bool,
        trusted: bool,
    },
    /// A server's `Set-Cookie:`.
    Set {
        value: Vec<u8>,
        host: &'static [u8],
        path: &'static [u8],
        secure: bool,
    },
    /// The application's line.
    Add(Vec<u8>),
    Start,
    /// Time passes.
    Later(i64),
    ClearSession,
    /// Another request: its count of cookies set starts over.
    NextRequest,
}

fn jar_op() -> impl Strategy<Value = JarOp> {
    use proptest::sample::select;
    let line = || crate::untrusted::input(COOKIE_WORDS, COOKIE_LINES, 16);
    prop_oneof![
        1 => (
            proptest::collection::vec(line(), 0..4),
            any::<bool>(),
            any::<bool>()
        )
            .prop_map(|(lines, new_session, trusted)| JarOp::Load {
                text: lines.join(&b'\n'),
                new_session,
                trusted
            }),
        4 => (line(), select(HOSTS), select(PATHS), any::<bool>()).prop_map(
            |(value, host, path, secure)| JarOp::Set {
                value,
                host,
                path,
                secure
            }
        ),
        1 => line().prop_map(JarOp::Add),
        1 => Just(JarOp::Start),
        1 => prop_oneof![0..100i64, 0..1_000_000_000i64].prop_map(JarOp::Later),
        1 => Just(JarOp::ClearSession),
        1 => Just(JarOp::NextRequest),
    ]
}

proptest! {
    #![proptest_config(crate::untrusted::config(256))]

    /// Any lines, from servers, files and the application, are stored or
    /// passed over without a panic; a request stores at most C's count
    /// of them and sends at most C's count, and the jar is written out.
    #[test]
    fn any_cookie_lines_are_stored_or_passed_over(
        ops in proptest::collection::vec(jar_op(), 1..12),
        listed in any::<bool>(),
    ) {
        let suffixes: Option<&dyn PublicSuffixes> = listed.then_some(&Two);
        let mut jar = Jar::default();
        let (mut now, mut set) = (NOW, 0u8);
        for op in &ops {
            match op {
                JarOp::Load { text, new_session, trusted } => {
                    jar.load(text, *new_session, *trusted, suffixes, now).unwrap();
                }
                JarOp::Set { value, host, path, secure } => {
                    let source = Source::Server { host, path, secure: *secure };
                    if let Some(said) = jar.set_by(value, source, suffixes, now, &mut set).unwrap() {
                        said_text(&said);
                    }
                }
                JarOp::Add(line) => jar.add_line(line, suffixes, now, &mut set).unwrap(),
                JarOp::Start => jar.start(),
                JarOp::Later(by) => now += by,
                JarOp::ClearSession => jar.clear_session(),
                JarOp::NextRequest => set = 0,
            }
            prop_assert!(set <= MAX_SET_PER_REQUEST);
            jar.sweep(now);
            for host in HOSTS {
                for path in PATHS {
                    let m = jar.matching(host, path, true).unwrap();
                    prop_assert!(m.cookies.len() <= MAX_SEND);
                    m.capped_line(|_| ());
                }
            }
            prop_assert!(jar.listed().count() <= jar.len());
            let mut out = Vec::new();
            jar.file(now, &mut out).unwrap();
        }
    }
}
