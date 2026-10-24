//! The HTTPS connect filter's trace (`cf-https-connect.c`), with the
//! chain it heads, the lookup of the origin's HTTPS record and the timer
//! it arms while the record is to come (`EXPIRE_ALPN_EYEBALLS`). Each
//! expected sequence is the C build's with `--http1.1`, which offers
//! HTTP/1.1 alone, as this build does; its ports the test's.

use super::*;
use crate::components::Components;
use crate::libraries::Libraries;
use crate::options::IpVersion;
use crate::tls::fake::{self, FakeTls, WELCOME};

/// A handle with the test's fake TLS library, tracing `components`.
fn tracing(components: &[u8]) -> Easy {
    let (_, libraries) = super::tls::tls();
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let c = Components::new().unwrap();
    c.configure(components);
    e.set_components(Some(c));
    e
}

/// The lines a run traced that start with one of `starts`, the times
/// and the multi's waits left out.
fn lines(ran: &Ran, starts: &[&str]) -> Vec<String> {
    ran.seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| starts.iter().any(|s| l.starts_with(s)))
        .filter(|l| !l.contains("] pollset[") && !l.contains("] multi_wait("))
        .filter(|l| !l.contains("[PGRS-") && !l.contains("expires in"))
        .filter(|l| !l.contains("gives multi timeout"))
        .collect()
}

fn expect(lines: &str) -> Vec<String> {
    lines
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A GET of `url` by `e` over `m`, its server answering through the fake
/// TLS library, over IPv4 alone.
fn https_get(m: &mut Multi, e: Easy, url: &str, set: impl FnOnce(&mut Options)) -> Ran {
    let url = url.to_owned();
    get_with(m, e, "/", Conversation::replies(&[], false), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.ip_version = IpVersion::V4;
        set(o);
    })
}

/// A server at `PORT` that answers a TLS handshake and then `OK` on each
/// of `n` connections, closing after it.
fn tls_server(n: usize) -> Multi {
    let response = fake::records(OK).unwrap();
    let talks: Vec<Conversation> = (0..n)
        .map(|_| Conversation::replies(&[WELCOME, &response], true))
        .collect();
    let talks: Vec<&Conversation> = talks.iter().collect();
    serving(Peer::Accepts, &talks)
}

/// For an address, no record is asked for: the chain has one DNS filter,
/// and the filter knows at once there is none, says so for its second
/// attempt and arms no timer.
#[test]
fn an_https_setup_to_an_address_asks_for_no_record() {
    let mut m = tls_server(1);
    let e = tracing(b"multi,setup,https-connect,timer");
    let ran = https_get(&mut m, e, &format!("https://127.0.0.1:{PORT}/"), |_| {});
    assert_eq!(ran.result, Ok(()));
    let got = lines(
        &ran,
        &["[HTTPS-CONNECT]", "[TIMER] [ALPN", "[MULTI] [CONNECTING] c"],
    );
    // The fake's handshake is answered whole as the connect is seen.
    let want = expect(
        "[HTTPS-CONNECT] added
        [HTTPS-CONNECT] connect, init
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] 1st attempt uses h1 from wanted versions
        [HTTPS-CONNECT] HTTPS-RR not available
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [HTTPS-CONNECT] connect -> 0, done=0
        [HTTPS-CONNECT] adjust_pollset -> 0, 1 socks
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP][!SSL][HAPPY-EYEBALLS][TCP]
        [HTTPS-CONNECT] connect -> 0, done=1
        [MULTI] [CONNECTING] connected [0][DNS][HTTPS-CONNECT][SETUP][SSL][HAPPY-EYEBALLS][TCP]
        [HTTPS-CONNECT] removing connected setup filter
        [HTTPS-CONNECT] destroy",
    );
    assert_eq!(got, want);
}

/// For a name, the record is asked for as the setup's first connect
/// starts, and the timer armed as the attempt starts, with half the
/// happy eyeballs delay; the answer, none, comes at the next connect and
/// is kept, and the timer stays until the transfer completes. The next
/// setup for the name finds the record kept and arms nothing.
#[test]
fn an_https_setup_to_a_name_waits_for_its_record_once() {
    let mut m = tls_server(2);
    let url = format!("https://localhost:{PORT}/");
    let e = tracing(b"multi,https-connect,timer,dns");
    let first = https_get(&mut m, e, &url, |_| {});
    assert_eq!(first.result, Ok(()));
    let starts = [
        "[HTTPS-CONNECT]",
        "[TIMER] [ALPN",
        "[DNS] c",
        "Hostname",
        "HTTPS-RR",
    ];
    let got = lines(&first, &starts);
    let want = expect(&format!(
        "[HTTPS-CONNECT] added
        [DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 not found
        [DNS] cache lookup localhost:{PORT} queries=A -> 0 not found
        [DNS] cached entry for localhost:{PORT} queries=A
        [HTTPS-CONNECT] connect, init
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] 1st attempt uses h1 from wanted versions
        [TIMER] [ALPN_EYEBALLS] set for 100000us
        [HTTPS-CONNECT] connect -> 0, done=0
        [HTTPS-CONNECT] adjust_pollset -> 0, 1 socks
        [DNS] cache negative name resolve for localhost:{PORT} type=HTTPS
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] connect -> 0, done=1
        [HTTPS-CONNECT] removing connected setup filter
        [HTTPS-CONNECT] destroy"
    ));
    assert_eq!(got, want);
    let text = first.seen.text();
    let chain = text.iter().find(|l| l.contains("connected [")).unwrap();
    assert_eq!(
        chain,
        "[MULTI] [CONNECTING] connected [0][DNS][DNS][HTTPS-CONNECT][SETUP][SSL][HAPPY-EYEBALLS][TCP]\n"
    );
    assert!(
        text.iter()
            .any(|l| l == "[MULTI] [COMPLETED] [TIMEOUT] all cleared\n"),
        "the timer stays to the end"
    );
    let e = tracing(b"https-connect,timer,dns");
    let second = https_get(&mut m, e, &url, |_| {});
    assert_eq!(second.result, Ok(()));
    let got = lines(&second, &starts);
    let want = expect(&format!(
        "[HTTPS-CONNECT] added
        [DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 found
        Hostname localhost was found in DNS cache
        HTTPS-RR localhost:{PORT}: -
        [DNS] cache lookup localhost:{PORT} queries=A -> 0 found
        Hostname localhost was found in DNS cache
        [HTTPS-CONNECT] connect, init
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] 1st attempt uses h1 from wanted versions
        [HTTPS-CONNECT] HTTPS-RR not available"
    ));
    assert_eq!(got[..want.len()], want);
    assert!(
        !got.iter().any(|l| l.starts_with("[TIMER] [ALPN")),
        "{got:?}"
    );
}

/// Without ALPN there is no HTTPS connect filter: the setup filter heads
/// the chain, as for plain HTTP (`Curl_cf_https_setup`).
#[test]
fn an_https_setup_without_alpn_has_no_https_connect_filter() {
    let mut m = tls_server(1);
    let e = tracing(b"multi,setup,https-connect,timer");
    let url = format!("https://localhost:{PORT}/");
    let ran = https_get(&mut m, e, &url, |o| {
        o.tls.options.make_mut().unwrap().alpn = false;
    });
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text();
    assert!(
        !text
            .iter()
            .any(|l| l.contains("HTTPS-CONNECT") || l.contains("ALPN_")),
        "{text:?}"
    );
    assert_eq!(
        text.iter()
            .find(|l| l.ends_with("] added\n"))
            .map(String::as_str),
        Some("[SETUP] added\n")
    );
}

/// A failed attempt fails the filter, which says so, and the chain the
/// failure names ends with it, as it holds its attempt apart.
#[test]
fn a_failed_https_setup_names_the_chain_to_its_filter() {
    let mut m = serving(Peer::Refuses, &[]);
    let e = tracing(b"multi,https-connect");
    let ran = https_get(&mut m, e, &format!("https://localhost:{PORT}/"), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let got = lines(
        &ran,
        &["[HTTPS-CONNECT] connect", "[MULTI] [CONNECTING] failed"],
    );
    assert_eq!(
        got,
        expect(
            "[HTTPS-CONNECT] connect, init
            [HTTPS-CONNECT] connect -> 0, done=0
            [HTTPS-CONNECT] connect, all attempts failed
            [HTTPS-CONNECT] connect -> 7, done=0
            [MULTI] [CONNECTING] failed to connect [0][!DNS][!DNS][!HTTPS-CONNECT]"
        )
    );
}

/// What was agreed by ALPN is asked of a new connection twice: by the
/// HTTPS connect filter, from the setup filter, as its attempt wins
/// (`baller_connected`), and by HTTP, from the top of the chain, before
/// its first request (`http_check_new_conn`); the TLS filter answers with
/// what its peer chose. A reused connection is not asked.
#[test]
fn what_alpn_agreed_is_asked_of_a_new_connection_only() {
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    let libraries: &'static Libraries = Box::leak(Box::new(Libraries {
        tls: Some(backend),
        ..Libraries::NONE
    }));
    let response = fake::records(OK).unwrap();
    let talk = Conversation::replies(&[WELCOME, &response, &response], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let url = format!("https://127.0.0.1:{PORT}/");
    let e = || {
        let mut e = tracing(b"setup,ssl,https-connect");
        e.set_libraries(libraries);
        e
    };
    let starts = [
        "[SETUP] query",
        "[SSL] query",
        "[HTTPS-CONNECT] connect ->",
        "using",
    ];
    let first = https_get(&mut m, e(), &url, |_| {});
    assert_eq!(first.result, Ok(()));
    assert_eq!(
        lines(&first, &starts),
        expect(
            "[HTTPS-CONNECT] connect -> 0, done=0
            [SETUP] query ALPN
            [SSL] query ALPN: returning 'http/1.1'
            [HTTPS-CONNECT] connect -> 0, done=1
            [SSL] query ALPN
            [SSL] query ALPN: returning 'http/1.1'
            using HTTP/1.x"
        )
    );
    let again = https_get(&mut m, e(), &url, |_| {});
    assert_eq!(again.result, Ok(()));
    assert_eq!(lines(&again, &starts), Vec::<String>::new());
}

/// Each call of the chain's connect is traced by its top filter as it
/// ends, and each of the TLS filter's by it as it begins and ends; the
/// TLS filter puts its socket in the pollset for what its session waits
/// for.
#[test]
fn the_connect_calls_and_the_tls_filter_s_wait_are_traced() {
    let response = fake::records(OK).unwrap();
    let talk = Conversation::replies(&[WELCOME, &response], true).late_replies();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let e = tracing(b"ssl,dns");
    let ran = https_get(&mut m, e, &format!("https://127.0.0.1:{PORT}/"), |_| {});
    assert_eq!(ran.result, Ok(()));
    let starts = [
        "[SSL] cf_connect",
        "[SSL] adjust",
        "[DNS] Curl_conn_connect",
    ];
    assert_eq!(
        lines(&ran, &starts),
        expect(
            "[DNS] Curl_conn_connect(block=0) -> 0, done=0
            [SSL] cf_connect()
            [SSL] cf_connect() -> 0, done=0
            [DNS] Curl_conn_connect(block=0) -> 0, done=0
            [SSL] adjust_pollset, POLLIN fd=1000
            [SSL] cf_connect()
            [SSL] cf_connect() -> 0, done=1
            [DNS] Curl_conn_connect(block=0) -> 0, done=1
            [SSL] adjust_pollset, POLLIN fd=1000"
        )
    );
}

/// A newest version allowed older than the oldest fails the TLS filter's
/// first connect, before its session's handshake starts
/// (`ssl_prefs_check`), and the chain's connect with it.
#[test]
fn versions_that_allow_none_fail_the_tls_filter_s_connect() {
    let talk = Conversation::replies(&[WELCOME], true);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let e = tracing(b"ssl,dns");
    let ran = https_get(&mut m, e, &format!("https://127.0.0.1:{PORT}/"), |o| {
        let tls = o.tls.options.make_mut().unwrap();
        tls.min_version = crate::options::TlsMinVersion::Tls1_3;
        tls.max_version = crate::options::TlsMaxVersion::Tls1_2;
    });
    assert_eq!(ran.result, Err(ErrorKind::SslConnectError));
    let starts = [
        "[SSL] cf_connect",
        "CURL_SSLVERSION",
        "[DNS] Curl_conn_connect",
    ];
    let got = lines(&ran, &starts);
    assert_eq!(
        got[got.len() - 5..],
        expect(
            "[SSL] cf_connect()
            CURL_SSLVERSION_MAX incompatible with CURL_SSLVERSION
            [SSL] cf_connect() -> 35, done=0
            [DNS] Curl_conn_connect(block=0) -> 35, done=0
            [DNS] Curl_conn_connect(), filter returned 35"
        )
    );
    assert_eq!(talk.received(), b"", "no hello sent");
}

/// The replies of an HTTPS proxy that tunnels, its handshake first; and
/// through the tunnel, the origin's: with TLS if `tls`, else in the
/// clear.
fn https_proxy_tunnel(tls: bool) -> Conversation {
    let established = fake::records(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
    if tls {
        let inner_welcome = fake::records(WELCOME).unwrap();
        let response = fake::records(&fake::records(OK).unwrap()).unwrap();
        Conversation::replies(&[WELCOME, &established, &inner_welcome, &response], true)
    } else {
        let response = fake::records(OK).unwrap();
        Conversation::replies(&[WELCOME, &established, &response], true)
    }
}

/// A GET of `url` through an HTTPS proxy that tunnels, by a handle of
/// the fake library `libraries` tracing all, the lines it traced, each
/// without its transfer's and connection's numbers.
fn through_https_proxy(
    libraries: &'static Libraries,
    url: &str,
    talk: &Conversation,
    set: impl FnOnce(&mut Options),
) -> Vec<String> {
    let mut m = serving(Peer::Accepts, &[talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let c = Components::new().unwrap();
    c.configure(b"all");
    e.set_components(Some(c));
    let ran = https_get(&mut m, e, url, |o| {
        let proxy = format!("https://127.0.0.1:{PORT}");
        o.proxy.make_mut().unwrap().url = Some(proxy.into_bytes());
        set(o);
    });
    assert_eq!(ran.result, Ok(()));
    ran.seen
        .text()
        .into_iter()
        .map(|l| {
            l.trim_end()
                .split_once("] ")
                .map_or(&*l, |(_, l)| l)
                .to_owned()
        })
        .collect()
}

/// HTTPS through an HTTPS proxy, as C traces its setup: the proxy's TLS
/// and the tunnel's filter added together, the TLS made before the
/// CONNECT, the origin's TLS added once the tunnel is up; the tunnel's
/// answer read a byte at a time through the proxy's TLS
/// (`recv_CONNECT_resp`), so that nothing past it leaves the session.
#[test]
fn tls_in_tls_sets_up_as_c() {
    let (backend, libraries) = super::tls::tls();
    let talk = https_proxy_tunnel(true);
    let got = through_https_proxy(libraries, "https://origin.example/", &talk, |_| {});
    let picked: Vec<&str> = got
        .iter()
        .map(String::as_str)
        .filter(|l| {
            l.starts_with("[SETUP] added ")
                || l.starts_with("[SSL-PROXY] cf_connect()")
                || l.starts_with("[SSL] cf_connect()")
                || l.starts_with("Establishing")
                || l.contains("query ALPN")
                || l.starts_with("using")
                || l.starts_with("CONNECT")
        })
        .collect();
    assert_eq!(
        picked,
        [
            "[SETUP] added SSL filter for HTTP proxy",
            "[SETUP] added HTTP proxy tunnel filter",
            "[SSL-PROXY] cf_connect()",
            "[SSL-PROXY] cf_connect() -> 0, done=1",
            "[SSL-PROXY] query ALPN",
            "[SSL-PROXY] query ALPN: returning '(nil)'",
            "CONNECT: no ALPN negotiated",
            "Establishing HTTP proxy tunnel to origin.example:443",
            "CONNECT phase completed for HTTP proxy",
            "CONNECT tunnel established, response 200",
            "[SETUP] added SSL filter for origin",
            "[SSL] cf_connect()",
            "[SSL] cf_connect() -> 0, done=1",
            "[SETUP] query ALPN",
            "[SSL] query ALPN: returning '(nil)'",
            "[SSL] query ALPN",
            "[SSL] query ALPN: returning '(nil)'",
            "using HTTP/1.x",
        ],
        "{got:#?}"
    );
    // The answer's bytes, each asked of the proxy's session alone, the
    // first reads made of a session (the log keeps 32).
    assert_eq!(backend.log().asked(), [1; 32]);
}

/// Plain HTTP tunneled through an HTTPS proxy: the tunnel's filter,
/// asked what ALPN agreed, keeps the question (`cf_h1_proxy_query`), so
/// the proxy's TLS below it, which answered for the CONNECT, says
/// nothing.
#[test]
fn a_tunnel_through_an_https_proxy_keeps_the_alpn_question() {
    let (_, libraries) = super::tls::tls();
    let talk = https_proxy_tunnel(false);
    let url = format!("http://127.0.0.1:{PORT}/");
    let got = through_https_proxy(libraries, &url, &talk, |o| {
        o.proxy.make_mut().unwrap().tunnel = true
    });
    let picked: Vec<&str> = got
        .iter()
        .map(String::as_str)
        .filter(|l| {
            l.contains("query ALPN") || l.starts_with("using") || l.starts_with("[SETUP] added ")
        })
        .collect();
    assert_eq!(
        picked,
        [
            "[SETUP] added SSL filter for HTTP proxy",
            "[SETUP] added HTTP proxy tunnel filter",
            "[SSL-PROXY] query ALPN",
            "[SSL-PROXY] query ALPN: returning '(nil)'",
            "[H1-PROXY] query ALPN",
            "using HTTP/1.x",
        ],
        "{got:#?}"
    );
}
