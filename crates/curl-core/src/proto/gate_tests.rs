//! A request of each protocol that goes through an HTTP proxy's tunnel,
//! made after a redirect to another host, asks for that tunnel without
//! the `Authorization:` and `Cookie:` lines meant for the first host
//! (`Curl_auth_allowed_to_host` in `dynhds_add_custom`, the
//! CVE-2022-27776 rule): its own credential gate, not an always-trusted
//! one, decides what the `CONNECT` carries. FTP's is in its own tests,
//! as its data connection tunnels too; SSH's and LDAP's are in theirs,
//! with their fake libraries.

use std::net::SocketAddr;

use crate::conn::io::{Conversation, FakeNet, Peer};
use crate::easy::Easy;
use crate::id::ArenaPolicy;
use crate::libraries::SharedLibraries;
use crate::multi::{Env, Multi, NoEvents, drive_to_completion};
use crate::options::{Follow, Protocols, UserHeaders};
use crate::time::ManualClock;

const PROXY_PORT: u16 = 8080;

const TUNNELED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

/// The second tunnel is refused: only its `CONNECT` is looked at.
const REFUSED: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";

/// The `CONNECT` heads a transfer of `http://first.example/` sends
/// through a proxy tunnelling every transfer, with an `Authorization:`
/// and a `Cookie:` of its own, when the first host redirects to `to`;
/// the handle given `libraries` if any.
fn connects_redirected_to(to: &str, libraries: Option<SharedLibraries>) -> [String; 2] {
    let moved = format!("HTTP/1.1 302 Moved\r\nLocation: {to}\r\nContent-Length: 0\r\n\r\n");
    let first = Conversation::replies(&[TUNNELED, moved.as_bytes()], false).per_send();
    let second = Conversation::replies(&[REFUSED], false).per_send();
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PROXY_PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, first.clone())
        .with_conversation(at, second.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::with_env(env).unwrap();
    let mut e = Easy::new();
    if let Some(libraries) = libraries {
        e.set_libraries(libraries);
    }
    let o = e.options_mut();
    o.set_url(Some(b"http://first.example/")).unwrap();
    o.http.follow = Follow::All;
    o.schemes.make_mut().unwrap().redirect = Protocols::ALL;
    o.set_proxy_url(Some(format!("http://127.0.0.1:{PROXY_PORT}").into_bytes()))
        .unwrap();
    let proxy = o.proxy.make_mut().unwrap();
    proxy.tunnel = true;
    let lines: [&[u8]; 2] = [b"Authorization: Bearer tunnel", b"Cookie: crumb=1"];
    proxy.headers = UserHeaders::new(lines).unwrap();
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert!(result.is_err(), "{to}: the second tunnel is refused");
    let head = |talk: &Conversation| {
        let text = String::from_utf8_lossy(&talk.received()).into_owned();
        match text.split_once("\r\n\r\n") {
            Some((head, _)) => head.to_owned(),
            None => text,
        }
    };
    [head(&first), head(&second)]
}

/// A redirect to `to`, a URL on `authority`, through the tunnel: the
/// first host's `CONNECT` carries the lines, the second's asks for
/// `authority` without them, as the C tool sends them (`-L -p -x
/// --proxy-header ... --proto-redir all` against a proxy refusing the
/// second tunnel); the handle given `libraries` if any.
pub(super) fn a_redirect_s_tunnel_is_gated(
    to: &str,
    authority: &str,
    libraries: Option<SharedLibraries>,
) {
    let [first, second] = connects_redirected_to(to, libraries);
    assert!(
        first.starts_with("CONNECT first.example:80 "),
        "{to}: {first}"
    );
    assert!(
        second.starts_with(&format!("CONNECT {authority} ")),
        "{to}: {second}"
    );
    for line in ["\r\nAuthorization: Bearer tunnel", "\r\nCookie: crumb=1"] {
        assert!(first.contains(line), "{to}, to the first host: {first}");
        assert!(!second.contains(line), "{to}, to the second: {second}");
    }
}

/// Each protocol that needs no library of its own.
#[test]
fn a_tunnel_to_a_redirected_to_host_carries_no_first_host_lines() {
    for (to, authority) in [
        ("dict://other.example:2628/d:x", "other.example:2628"),
        ("gopher://other.example:7070/1", "other.example:7070"),
        ("imap://other.example:1143/INBOX", "other.example:1143"),
        ("pop3://other.example:1110/1", "other.example:1110"),
        ("smtp://other.example:1025/x", "other.example:1025"),
        ("telnet://other.example:2323", "other.example:2323"),
        ("mqtt://other.example:1883/t", "other.example:1883"),
        ("rtsp://other.example:5554/x", "other.example:5554"),
    ] {
        a_redirect_s_tunnel_is_gated(to, authority, None);
    }
}

/// TFTP's tunnel is asked for with HTTP/1.1's `CONNECT-UDP` upgrade, as
/// test 3700 has it, gated as a `CONNECT` is: the C tool's request for
/// it carries none of the first host's lines either.
#[test]
fn a_udp_tunnel_to_a_redirected_to_host_carries_no_first_host_lines() {
    let [first, second] = connects_redirected_to("tftp://other.example:6969/f", None);
    assert!(first.starts_with("CONNECT first.example:80 "), "{first}");
    let asked = format!(
        "GET http://127.0.0.1:{PROXY_PORT}/.well-known/masque/udp/other.example/6969/ HTTP/1.1\r\n"
    );
    assert!(second.starts_with(&asked), "{second}");
    assert!(second.contains("\r\nUpgrade: connect-udp"), "{second}");
    for line in ["\r\nAuthorization: Bearer tunnel", "\r\nCookie: crumb=1"] {
        assert!(first.contains(line), "to the first host: {first}");
        assert!(!second.contains(line), "to the second: {second}");
    }
}
