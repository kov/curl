//! Host names in Unicode (`lib/idn.c`, `peer_parse_host`): looked up, sent
//! and matched by their ASCII form where the handle's IDN library makes
//! one, with a fake library standing in for libidn2.

use super::*;
use crate::idn::FakeIdn;
use crate::libraries::{Libraries, SharedLibraries};

/// A handle converting names with the fake library.
fn converting() -> Easy {
    static CONVERTING: Libraries = Libraries {
        idn: Some(&FakeIdn),
        ..Libraries::NONE
    };
    let mut e = Easy::new();
    e.set_libraries(SharedLibraries::of_static(&CONVERTING));
    e
}

/// Through a proxy that sends it on, a request to a host in Unicode
/// names it in ASCII, in its target and in `Host:` (test 165); without
/// an IDN library it goes as the URL has it, as from a C build without
/// one.
#[test]
fn a_host_in_unicode_is_sent_in_ascii() {
    for (e, host) in [
        (converting(), "www.xn--4cab6c.se"),
        (Easy::new(), "www.åäö.se"),
    ] {
        let (mut m, talk, _) = server(&[OK], false);
        let ran = get_with(&mut m, e, "/", talk, |o| {
            o.set_url(Some("http://www.åäö.se/page".as_bytes()))
                .unwrap();
            o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        });
        assert_eq!(ran.result, Ok(()));
        let want = format!("GET http://{host}/page HTTP/1.1\r\nHost: {host}\r\n");
        assert!(
            ran.request.starts_with(want.as_bytes()),
            "{}",
            String::from_utf8_lossy(&ran.request)
        );
    }
}

/// A name the library cannot convert, or that converts to nothing, is a
/// malformed URL's (tests 1034 and 763); nothing is connected.
#[test]
fn a_name_that_does_not_convert_fails_the_transfer() {
    for url in ["http://bad-\u{2400}.local/", "http://\u{200b}\u{200c}/"] {
        let (mut m, talk, _) = server(&[OK], false);
        let ran = get_with(&mut m, converting(), "/", talk, |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
            o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        });
        assert_eq!(ran.result, Err(ErrorKind::UrlMalformat), "{url}");
        assert!(ran.request.is_empty(), "{url}");
    }
}

/// A proxy and a connect-to entry named in Unicode are looked up by
/// their ASCII names, as the origin is (`Curl_peer_from_proxy_url`,
/// `Curl_peer_from_connect_to`).
#[test]
fn a_proxy_and_a_connect_to_host_are_looked_up_in_ascii() {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    for set in [
        (|o: &mut Options| {
            o.set_url(Some(b"http://origin.example/")).unwrap();
            o.proxy.make_mut().unwrap().url = Some(format!("åäö.test:{PORT}").into_bytes());
        }) as fn(&mut Options),
        |o: &mut Options| {
            o.set_url(Some(format!("http://origin.example:{PORT}/").as_bytes()))
                .unwrap();
            let entry = format!("origin.example:{PORT}:åäö.test:{PORT}");
            o.connect_to.set([entry.as_bytes()]).unwrap();
        },
    ] {
        let talk = Conversation::replies(&[OK], false);
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone())
            .with_name("xn--4cab6c.test", &[[127, 0, 0, 1].into()]);
        let env = Env {
            clock: Box::new(clock.clone()),
            net: Box::new(net),
            arena: ArenaPolicy::new(16, 0).unwrap(),
            waker: None,
        };
        let mut m = Multi::new(env).unwrap();
        let ran = get_with(&mut m, converting(), "/", talk, set);
        assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    }
}

/// A `.netrc` entry names a host in Unicode by its ASCII name, as C looks
/// one up by `hostname`.
#[test]
fn a_netrc_entry_names_a_host_in_unicode_in_ascii() {
    use crate::options::NetrcMode;
    let path = std::env::temp_dir().join(format!("curl-core-netrc-idn-{}", std::process::id()));
    std::fs::write(&path, b"machine www.xn--4cab6c.se login a password b\n").unwrap();
    let file = path.as_os_str().as_encoded_bytes().to_vec();
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, converting(), "/", talk, |o| {
        o.set_url(Some("http://www.åäö.se/".as_bytes())).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        o.netrc.make_mut().unwrap().mode = NetrcMode::Optional;
        o.netrc.make_mut().unwrap().file = Some(file);
    });
    std::fs::remove_file(&path).unwrap();
    assert_eq!(ran.result, Ok(()));
    let line = b"\r\nAuthorization: Basic YTpi\r\n";
    assert!(
        fixture::find(&ran.request, line).is_some(),
        "{}",
        String::from_utf8_lossy(&ran.request)
    );
}

/// A tunnel's `CONNECT` names a host in Unicode in ASCII, and the
/// request through it its `Host:` (`CONNECT_host`).
#[test]
fn a_tunnel_names_a_host_in_unicode_in_ascii() {
    let (mut m, talk, _) = server(&[TUNNEL_UP, OK], false);
    let ran = get_with(&mut m, converting(), "/", talk, |o| {
        o.set_url(Some("http://www.åäö.se/a".as_bytes())).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        o.proxy.make_mut().unwrap().tunnel = true;
    });
    assert_eq!(ran.result, Ok(()));
    let request = String::from_utf8_lossy(&ran.request);
    assert!(
        request
            .starts_with("CONNECT www.xn--4cab6c.se:80 HTTP/1.1\r\nHost: www.xn--4cab6c.se:80\r\n"),
        "{request}"
    );
    assert!(
        request.contains("GET /a HTTP/1.1\r\nHost: www.xn--4cab6c.se\r\n"),
        "{request}"
    );
}
