//! The connection setup filter's trace and the chain C's multi traces
//! from a connect (`cf_setup_connect`, `connected`, `reduced to`, `failed
//! to connect`), with the lines of the setup filters going. Each expected
//! sequence is the C build's for the same setup, its ports the test's.

use super::*;
use crate::components::Components;

/// A handle tracing the chain and the setup filters.
fn tracing_setup() -> Easy {
    let mut e = Easy::new();
    let components = Components::new().unwrap();
    components.configure(b"multi,setup,http-proxy,haproxy");
    e.set_components(Some(components));
    e
}

/// The lines of a run about the chain: SETUP's, the chain's and the setup
/// filters' going.
fn setup_lines(ran: &Ran) -> Vec<String> {
    ran.seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| {
            let chain = [
                "cf_setup_connect ",
                "connected [",
                "reduced to ",
                "failed to connect ",
            ];
            l.starts_with("[SETUP] ")
                || l.starts_with("[HTTP-PROXY] ")
                || l.starts_with("[HAPROXY] ")
                || (l.starts_with("[MULTI] [CONNECTING] ")
                    && chain.iter().any(|c| l[21..].starts_with(c)))
        })
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

/// The setup until its attempt to `first` is under way, then its next
/// call, which finds it connected.
fn raced(to: &str, first: &str) -> String {
    format!(
        "[SETUP] added
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP]
        [SETUP] happy eyeballing to {to} {first}
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP][!HAPPY-EYEBALLS]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP][!HAPPY-EYEBALLS]"
    )
}

/// A direct connection: the chain over the race, then reduced to the
/// socket's filter.
#[test]
fn a_direct_setup_is_traced_as_c() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, tracing_setup(), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    let mut want = expect(&raced("origin", &format!("127.0.0.1:{PORT}")));
    want.extend(expect(
        "[MULTI] [CONNECTING] connected [0][DNS][SETUP][HAPPY-EYEBALLS][TCP]
        [SETUP] removing connected setup filter
        [SETUP] destroy
        [MULTI] [CONNECTING] reduced to [0][TCP]",
    ));
    assert_eq!(setup_lines(&ran), want);
}

/// A refused connect names the chain it failed with.
#[test]
fn a_refused_setup_names_the_chain_that_failed() {
    let mut m = serving(Peer::Refuses, &[]);
    let talk = Conversation::replies(&[], false);
    let ran = get_with(&mut m, tracing_setup(), "/", talk, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let mut want = expect(&raced("origin", &format!("127.0.0.1:{PORT}")));
    want.extend(expect(
        "[MULTI] [CONNECTING] failed to connect [0][!DNS][!SETUP][!HAPPY-EYEBALLS]",
    ));
    assert_eq!(setup_lines(&ran), want);
}

/// The PROXY protocol's filter is added once the socket is connected,
/// and goes with the setup filter.
#[test]
fn the_proxy_protocol_s_filter_is_added_and_goes() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, tracing_setup(), "/", talk, |o| {
        o.proxy.make_mut().unwrap().haproxy = true;
    });
    assert_eq!(ran.result, Ok(()));
    let mut want = expect(&raced("origin", &format!("127.0.0.1:{PORT}")));
    want.extend(expect(
        "[SETUP] added HAPROXY filter
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP][!HAPROXY][HAPPY-EYEBALLS][TCP]
        [MULTI] [CONNECTING] connected [0][DNS][SETUP][HAPROXY][HAPPY-EYEBALLS][TCP]
        [SETUP] removing connected setup filter
        [SETUP] destroy
        [HAPROXY] removing connected setup filter
        [HAPROXY] destroy
        [MULTI] [CONNECTING] reduced to [0][TCP]",
    ));
    assert_eq!(setup_lines(&ran), want);
}

/// The tunnel's filters: the HTTP proxy's, its HTTP/1.1 one installed as
/// it first connects; the first goes with the setup, the second stays.
const TUNNEL: &str = "[SETUP] added HTTP proxy tunnel filter
    [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP][!HTTP-PROXY][HAPPY-EYEBALLS][TCP]
    [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP][!HTTP-PROXY][!H1-PROXY][HAPPY-EYEBALLS][TCP]";

const TUNNEL_UP_TRACE: &str =
    "[MULTI] [CONNECTING] connected [0][DNS][SETUP][HTTP-PROXY][H1-PROXY][HAPPY-EYEBALLS][TCP]
    [SETUP] removing connected setup filter
    [SETUP] destroy
    [HTTP-PROXY] removing connected setup filter
    [HTTP-PROXY] destroy
    [MULTI] [CONNECTING] reduced to [0][H1-PROXY][TCP]";

/// Through an HTTP proxy's tunnel, its answer read in the call after the
/// one that sent the `CONNECT`.
#[test]
fn a_tunnel_s_setup_is_traced_as_c() {
    let talk = Conversation::replies(&[TUNNEL_UP, OK], false).late_replies();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get_with(&mut m, tracing_setup(), "/", talk, tunneled);
    assert_eq!(ran.result, Ok(()));
    let mut want = expect(&raced("proxy", &format!("127.0.0.1:{PORT}")));
    want.extend(expect(TUNNEL));
    want.extend(expect(TUNNEL_UP_TRACE));
    assert_eq!(setup_lines(&ran), want);
}

/// A proxy that closes on its 407 has the setup start over: said, and the
/// chain traced from the setup filter again.
#[test]
fn a_redial_starts_the_chain_over() {
    let challenge: &[u8] = b"HTTP/1.1 407 Who\r\n\
        Proxy-Authenticate: Basic realm=\"p\"\r\nConnection: close\r\n\
        Content-Length: 0\r\n\r\n";
    let first = Conversation::replies(&[challenge], true).late_replies();
    let second = Conversation::replies(&[TUNNEL_UP, OK], false).late_replies();
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let ran = get_with(&mut m, tracing_setup(), "/", second, |o| {
        tunneled(o);
        o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
        o.proxy.make_mut().unwrap().auth = crate::options::HttpAuth(AuthMethods::ANY);
    });
    assert_eq!(ran.result, Ok(()));
    let proxy = format!("127.0.0.1:{PORT}");
    let mut want = expect(&raced("proxy", &proxy));
    want.extend(expect(TUNNEL));
    want.extend(expect(&format!(
        "[SETUP] retrying connect, 1. time
        [HTTP-PROXY] destroy
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP]
        [SETUP] happy eyeballing to proxy {proxy}
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP][!HAPPY-EYEBALLS]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP][!HAPPY-EYEBALLS]"
    )));
    want.extend(expect(TUNNEL));
    want.extend(expect(TUNNEL_UP_TRACE));
    assert_eq!(setup_lines(&ran), want);
}

/// Through a SOCKS5 proxy that is given the name, each call of its
/// handshake traces the chain.
#[test]
fn a_socks_proxy_s_setup_is_traced_as_c() {
    let replies: [&[u8]; 3] = [b"\x05\x00", SOCKS5_GRANTED, OK];
    let talk = Conversation::replies(&replies, false)
        .per_send()
        .late_replies();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get_with(&mut m, tracing_setup(), "/", talk, |o| {
        through_socks(o, "socks5h", b"http://origin.example/a");
    });
    assert_eq!(ran.result, Ok(()));
    let mut want = expect(&raced("origin", &format!("127.0.0.1:{PORT}")));
    let socks =
        "[MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP][!SOCKS][HAPPY-EYEBALLS][TCP]";
    want.extend(expect(&format!(
        "[SETUP] added SOCKS filter to origin.example:80
        {socks}
        {socks}
        {socks}
        [MULTI] [CONNECTING] connected [0][DNS][SETUP][SOCKS][HAPPY-EYEBALLS][TCP]
        [SETUP] removing connected setup filter
        [SETUP] destroy
        [MULTI] [CONNECTING] reduced to [0][SOCKS][TCP]"
    )));
    assert_eq!(setup_lines(&ran), want);
}

/// A SOCKS pre-proxy given an address, in front of an HTTP proxy that
/// tunnels: C adds a DNS filter for the address, and the tunnel's filters
/// go above the SOCKS one.
#[test]
fn a_pre_proxy_s_and_a_tunnel_s_setup_is_traced_as_c() {
    let replies: [&[u8]; 4] = [b"\x05\x00", SOCKS5_GRANTED, TUNNEL_UP, OK];
    let talk = Conversation::replies(&replies, false)
        .per_send()
        .late_replies();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get_with(&mut m, tracing_setup(), "/", talk, |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(b"http://127.0.0.2:3128".to_vec());
        o.proxy.make_mut().unwrap().tunnel = true;
        o.proxy.make_mut().unwrap().pre_proxy =
            Some(format!("socks5://127.0.0.1:{PORT}").into_bytes());
    });
    assert_eq!(ran.result, Ok(()));
    let mut want = expect(&raced("proxy", &format!("127.0.0.1:{PORT}")));
    // C's DNS filter for the proxy's address makes a call of its own
    // before the SOCKS handshake's second, which is not made here: its
    // lookup is not traced (ENGINE.md 2.5).
    let socks = "[MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!SETUP][!SOCKS][HAPPY-EYEBALLS][TCP]";
    want.extend(expect(&format!(
        "[SETUP] added SOCKS filter to 127.0.0.2:3128
        {socks}
        {socks}
        {socks}
        [SETUP] added HTTP proxy tunnel filter
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!SETUP][!HTTP-PROXY][SOCKS][HAPPY-EYEBALLS][TCP]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!DNS][!SETUP][!HTTP-PROXY][!H1-PROXY][SOCKS][HAPPY-EYEBALLS][TCP]
        [MULTI] [CONNECTING] connected [0][DNS][DNS][SETUP][HTTP-PROXY][H1-PROXY][SOCKS][HAPPY-EYEBALLS][TCP]
        [SETUP] removing connected setup filter
        [SETUP] destroy
        [HTTP-PROXY] removing connected setup filter
        [HTTP-PROXY] destroy
        [MULTI] [CONNECTING] reduced to [0][H1-PROXY][SOCKS][TCP]"
    )));
    assert_eq!(setup_lines(&ran), want);
}

/// A reused connection is not set up: no chain, no setup filter.
#[test]
fn a_reused_connection_traces_no_setup() {
    let (mut m, talk, _) = server(&[OK, OK], false);
    let first = get_with(&mut m, tracing_setup(), "/", talk.clone(), |_| {});
    assert_eq!(first.result, Ok(()));
    let again = get_with(&mut m, tracing_setup(), "/", talk, |_| {});
    assert_eq!(again.result, Ok(()));
    assert_eq!(setup_lines(&again), Vec::<String>::new());
}

/// A tunnel the proxy refuses fails the setup with the chain it had,
/// its tunnel's filters among it.
#[test]
fn a_refused_tunnel_names_the_chain_that_failed() {
    let challenge: &[u8] = b"HTTP/1.1 407 Who\r\n\
        Proxy-Authenticate: Basic realm=\"p\"\r\nConnection: close\r\n\
        Content-Length: 0\r\n\r\n";
    let talk = Conversation::replies(&[challenge], true).late_replies();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get_with(&mut m, tracing_setup(), "/", talk, tunneled);
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let mut want = expect(&raced("proxy", &format!("127.0.0.1:{PORT}")));
    want.extend(expect(TUNNEL));
    want.extend(expect(
        "[MULTI] [CONNECTING] failed to connect [0][!DNS][!SETUP][!HTTP-PROXY][!H1-PROXY][HAPPY-EYEBALLS][TCP]",
    ));
    assert_eq!(setup_lines(&ran), want);
    let connect_failed = "[MULTI] [CONNECTING] connect failed -> 7\n";
    assert!(ran.seen.text().iter().any(|l| l == connect_failed));
}

/// A tunnel whose `CONNECT` cannot be sent fails in the call that added
/// its filter, which the chain it failed with holds.
#[test]
fn a_tunnel_failing_as_it_starts_names_its_filter() {
    let talk = Conversation::replies(&[TUNNEL_UP], false).breaking_after(0);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get_with(&mut m, tracing_setup(), "/", talk, tunneled);
    assert!(ran.result.is_err());
    let mut want = expect(&raced("proxy", &format!("127.0.0.1:{PORT}")));
    want.extend(expect(
        "[SETUP] added HTTP proxy tunnel filter
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP][!HTTP-PROXY][HAPPY-EYEBALLS][TCP]
        [MULTI] [CONNECTING] failed to connect [0][!DNS][!SETUP][!HTTP-PROXY][!H1-PROXY][HAPPY-EYEBALLS][TCP]",
    ));
    assert_eq!(setup_lines(&ran), want);
}

/// A SOCKS5 handshake refused as it starts, the name too long for the
/// proxy to be given, names the chain with its filter.
#[test]
fn a_socks_handshake_refused_as_it_starts_names_its_filter() {
    let talk = Conversation::replies(&[], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let name = "a".repeat(256);
    let url = format!("http://{name}/a");
    let ran = get_with(&mut m, tracing_setup(), "/", talk, |o| {
        through_socks(o, "socks5h", url.as_bytes());
    });
    assert_eq!(ran.result, Err(ErrorKind::Proxy));
    let mut want = expect(&raced("origin", &format!("127.0.0.1:{PORT}")));
    want.extend(expect(&format!(
        "[SETUP] added SOCKS filter to {name}:80
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!SETUP][!SOCKS][HAPPY-EYEBALLS][TCP]
        [MULTI] [CONNECTING] failed to connect [0][!DNS][!SETUP][!SOCKS][HAPPY-EYEBALLS][TCP]"
    )));
    assert_eq!(setup_lines(&ran), want);
}
