//! Requests over HTTP/2, with the fake library and prior knowledge: the
//! head turned into the stream's fields, the response's fields handed on
//! as HTTP/1 lines, the body as it comes, and the stream's end.

use super::*;
use crate::http2::fake::FakeH2;
use crate::libraries::{Libraries, SharedLibraries};
use crate::multi::TransferId;
use crate::options::HttpVersion;

/// Libraries with the fake HTTP/2 library.
fn with_h2() -> SharedLibraries {
    static FAKE: FakeH2 = FakeH2;
    SharedLibraries::new(Libraries {
        h2: Some(&FAKE),
        ..Libraries::NONE
    })
    .unwrap()
}

/// A verbose GET of `path` by prior knowledge, its server answering
/// each send with the next of `replies`.
fn h2_get(replies: &[&[u8]], path: &str, set: impl FnOnce(&mut Options)) -> (Ran, Conversation) {
    let talk = Conversation::replies(replies, false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let ran = get_with(&mut m, e, path, talk.clone(), |o| {
        o.http.version = HttpVersion::Http2Prior;
        set(o);
    });
    (ran, talk)
}

const RESPONSE: &[u8] = b"S\nH 1 0\n:status: 200\ncontent-length: 5\nx-a: b\n\nD 1 5 1\nhello";

/// A GET by prior knowledge goes as the stream's fields, after the
/// client's SETTINGS; the response's fields come to the header handler
/// and the trace as HTTP/1 lines, `HTTP/2 200 ` first, and its body to
/// the write handler; the stream's end ends the transfer.
#[test]
fn a_get_goes_as_fields_and_its_response_comes_as_lines() {
    let (ran, _) = h2_get(&[RESPONSE], "/x?y", |_| {});
    assert_eq!(ran.result, Ok(()));
    let sent = String::from_utf8(ran.request.clone()).unwrap();
    assert_eq!(
        sent,
        format!(
            "S MCS=100;IWS=65536;EP=0;\nH 1 1\n:method: GET\n:scheme: http\n:authority: 127.0.0.1:{PORT}\n\
             :path: /x?y\nuser-agent: curl/test\naccept: */*\n\n"
        )
    );
    assert_eq!(
        ran.seen.of("header"),
        [
            &b"HTTP/2 200 \r\n"[..],
            b"content-length: 5\r\n",
            b"x-a: b\r\n",
            b"\r\n",
        ]
    );
    assert_eq!(ran.seen.of("in"), ran.seen.of("header"), "each line traced");
    assert_eq!(ran.seen.body(), b"hello");
    assert_eq!(
        ran.seen.of("out").concat(),
        format!(
            "GET /x?y HTTP/2\r\nHost: 127.0.0.1:{PORT}\r\nUser-Agent: curl/test\r\n\
             Accept: */*\r\n\r\n"
        )
        .as_bytes(),
        "the head is traced as it was made"
    );
    let text = ran.seen.text();
    let opened = text.iter().position(|l| l == "using HTTP/2\n").unwrap();
    assert_eq!(
        text[opened + 1..opened + 9],
        [
            format!("[HTTP/2] [1] OPENED stream for http://127.0.0.1:{PORT}/x?y\n"),
            "[HTTP/2] [1] [:method: GET]\n".to_owned(),
            "[HTTP/2] [1] [:scheme: http]\n".to_owned(),
            format!("[HTTP/2] [1] [:authority: 127.0.0.1:{PORT}]\n"),
            "[HTTP/2] [1] [:path: /x?y]\n".to_owned(),
            "[HTTP/2] [1] [user-agent: curl/test]\n".to_owned(),
            "[HTTP/2] [1] [accept: */*]\n".to_owned(),
            "Request completely sent off\n".to_owned(),
        ]
    );
    let report = ran.easy.report();
    assert_eq!(
        report.response_version(),
        Some(crate::report::ResponseVersion::Http2)
    );
    assert_eq!(report.response_code(), Some(200));
    assert_eq!(report.sizes().download(), 5);
}

/// A POST's body goes in the stream's DATA frames, the last ending it;
/// no `Expect:` and no chunked framing, which HTTP/2 has no use for.
#[test]
fn a_body_goes_as_data_ending_the_stream() {
    let reply: &[u8] = b"S\nH 1 1\n:status: 201\n\n";
    let (ran, _) = h2_get(&[reply], "/up", |o| {
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"abc".to_vec()).unwrap(),
        );
        o.method = Method::Post;
    });
    assert_eq!(ran.result, Ok(()));
    let sent = String::from_utf8(ran.request.clone()).unwrap();
    assert!(
        sent.contains(":method: POST\n") && sent.ends_with("\n\nD 1 3 1\nabc"),
        "{sent}"
    );
    assert!(sent.contains("content-length: 3\n"), "{sent}");
    assert_eq!(ran.easy.report().response_code(), Some(201));
}

/// A stream the server resets fails the transfer as C says it, with
/// the code's name.
#[test]
fn a_reset_stream_fails_the_transfer() {
    let reply: &[u8] = b"S\nR 1 2\n";
    let (ran, _) = h2_get(&[reply], "/", |_| {});
    assert_eq!(ran.result, Err(ErrorKind::Http2Stream));
    assert!(
        ran.seen
            .text()
            .iter()
            .any(|l| l == "HTTP/2 stream 1 reset by server (error 0x2 INTERNAL_ERROR)\n"),
        "{:?}",
        ran.seen.text()
    );
}

/// A stream that closes before its head is whole fails, as C fails it.
#[test]
fn a_stream_closed_before_its_head_fails() {
    let reply: &[u8] = b"S\nH 1 1\n:status: 100\n\n";
    let (ran, _) = h2_get(&[reply], "/", |_| {});
    assert_eq!(ran.result, Err(ErrorKind::Http2Stream));
    assert!(
        ran.seen.text().iter().any(|l| l
            == "HTTP/2 stream 1 was closed cleanly, but before getting all response header \
                fields, treated as error\n"),
        "{:?}",
        ran.seen.text()
    );
}

/// Trailers come once the stream closes, as trailers.
#[test]
fn trailers_come_as_the_stream_closes() {
    let reply: &[u8] = b"S\nH 1 0\n:status: 200\n\nD 1 2 0\nokH 1 1\nx-t: 1\n\n";
    let (ran, _) = h2_get(&[reply], "/", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok");
    assert_eq!(ran.seen.of("header"), [&b"HTTP/2 200 \r\n"[..], b"\r\n"]);
    assert_eq!(ran.seen.of("trailer"), [b"x-t: 1\r\n"]);
}

/// Trailers are held to C's limits as each arrives: 5000 fields, and a
/// MiB of names and values; one past either fails the stream as memory
/// running out would (`Curl_dynhds_add`, `cf_h2_header_error`). Within
/// them, what is held still meets the response's size limit as it is
/// handed on.
#[test]
fn trailers_past_c_s_limits_fail_the_stream() {
    let reply = |trailers: &[u8]| {
        let mut r = b"S\nH 1 0\n:status: 200\n\nD 1 2 0\nokH 1 1\n".to_vec();
        r.extend_from_slice(trailers);
        r.extend_from_slice(b"\n");
        r
    };
    let many = |n: usize| {
        (0..n)
            .flat_map(|i| format!("x-{i}: 1\n").into_bytes())
            .collect()
    };
    let wide = |n: usize| {
        let mut t = b"x: ".to_vec();
        t.extend(std::iter::repeat_n(b'v', n));
        t.push(b'\n');
        t
    };
    let held = "Error receiving HTTP2 header: 27(Out of memory)\n";
    let large = "Too large response headers: 1048595 > 307200\n";
    // A MiB less the name's one byte is a value that fills it.
    let fills = 1024 * 1024 - 1;
    for (trailers, said) in [
        (many(5000), None),
        (many(5001), Some(held)),
        (wide(fills), Some(large)),
        (wide(fills + 1), Some(held)),
    ] {
        let (ran, _) = h2_get(&[&reply(&trailers)], "/", |_| {});
        let text = ran.seen.text();
        let n = trailers.len();
        match said {
            None => assert_eq!(ran.result, Ok(()), "{n} bytes"),
            Some(said) => {
                assert!(ran.result.is_err(), "{n} bytes");
                assert!(text.iter().any(|l| l == said), "{n} bytes");
            }
        }
        assert_eq!(
            text.iter().any(|l| l == held),
            said == Some(held),
            "{n} bytes"
        );
    }
}

/// A server that closes the connection with the stream open cuts the
/// response short.
#[test]
fn a_connection_closed_under_a_stream_fails_it() {
    let talk = Conversation::replies(&[b"S\nH 1 0\n:status: 200\n\nD 1 2 0\nok"], true).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.http.version = HttpVersion::Http2Prior;
    });
    assert_eq!(ran.result, Err(ErrorKind::PartialFile));
}

/// Without an HTTP/2 library, prior knowledge speaks HTTP/1.1, as a C
/// build without nghttp2 has no such option.
#[test]
fn without_a_library_http_1_is_spoken() {
    let ran = run("/", OK, false, |o| o.http.version = HttpVersion::Http2Prior);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.request, request_of("/"));
}

/// An origin whose alternative is in HTTP/2 is reached by it in HTTP/2:
/// one looked up from HTTP/1 switches the request to HTTP/2 alone, ALPN
/// offering `h2` only; one from HTTP/2, looked up first, leaves what the
/// request offers as it was. What the response says comes in HTTP/2, and
/// is kept as an alternative of the origin's HTTP/2 (`url_set_conn_peer`,
/// `http_header_a`).
#[test]
fn an_alternative_in_http_2_is_reached_in_http_2() {
    use crate::libraries::Library;
    use crate::tls::Alpn;
    use crate::tls::fake::{self, FakeTls, WELCOME};
    static FAKE: FakeH2 = FakeH2;
    for (src, offer) in [("h1", Alpn::H2), ("h2", Alpn::H2Http11)] {
        let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
        let libraries = SharedLibraries::new(Libraries {
            tls: Some(Library::Static(backend)),
            h2: Some(&FAKE as &dyn crate::http2::Http2),
            ..Libraries::NONE
        })
        .unwrap();
        let file =
            std::env::temp_dir().join(format!("curl-core-alt-{src}-h2-{}", std::process::id()));
        let mut entries =
            format!("{src} 127.0.0.1 1 h2 127.0.0.1 {PORT} \"20991231 00:00:00\" 0 0\n");
        if src == "h2" {
            // HTTP/2's is looked up first: HTTP/1's, which leads nowhere,
            // is passed over.
            entries += "h1 127.0.0.1 1 h2 nowhere.example 2 \"20991231 00:00:00\" 0 0\n";
        }
        std::fs::write(&file, entries).unwrap();
        let said = b"S\nH 1 0\n:status: 200\ncontent-length: 5\n\
            alt-svc: h2=\"next.example:443\"; ma=60\n\nD 1 5 1\nhello";
        let response = fake::records(said).unwrap();
        let talk = Conversation::replies(&[WELCOME, &response], false).per_send();
        let mut m = serving(Peer::Accepts, &[&talk]);
        let mut e = Easy::new();
        e.set_libraries(libraries);
        e.add_alt_svc_file(Some(file.as_os_str().as_encoded_bytes()))
            .unwrap();
        let mut ran = get_with(&mut m, e, "/", talk.clone(), |o| {
            o.set_url(Some(b"https://127.0.0.1:1/")).unwrap();
        });
        assert_eq!(ran.result, Ok(()), "{src}: {:?}", ran.seen.text());
        assert_eq!(ran.seen.body(), b"hello");
        assert_eq!(backend.log().alpn, Some(offer), "{src}");
        let text = ran.seen.text();
        let connecting =
            format!("Alt-svc connecting from [{src}]127.0.0.1:1 to [h2]127.0.0.1:{PORT}\n");
        assert!(text.contains(&connecting), "{text:?}");
        assert!(text.iter().any(|l| l == "using HTTP/2\n"), "{text:?}");
        ran.easy.save_alt_svc().unwrap();
        let kept = std::fs::read_to_string(&file).unwrap();
        std::fs::remove_file(&file).unwrap();
        assert!(
            kept.contains("\nh2 127.0.0.1 1 h2 next.example 443 "),
            "{kept}"
        );
    }
}

/// Over TLS with an HTTP/2 library, ALPN offers `h2` first, which the
/// fake's peer takes, and the connection speaks HTTP/2; `h2` alone by
/// prior knowledge. Without one, or with HTTP/1 asked for, HTTP/1 is
/// offered, which it takes (`alpn_get_spec`). The HTTPS connect filter's
/// one attempt is named for the first it offers (`cf_hc_get_first_alpn`):
/// C's `1st attempt uses h2` at the default version.
#[test]
fn alpn_offers_h2_where_a_library_speaks_it() {
    use crate::libraries::Library;
    use crate::tls::fake::{self, FakeTls, WELCOME};
    static FAKE: FakeH2 = FakeH2;
    use crate::tls::Alpn;
    for (h2, version, offer) in [
        (true, HttpVersion::Any, Alpn::H2Http11),
        (true, HttpVersion::Http2Tls, Alpn::H2Http11),
        (true, HttpVersion::Http2Prior, Alpn::H2),
        (true, HttpVersion::Http11, Alpn::Http11),
        (true, HttpVersion::Http10, Alpn::Http10),
        (false, HttpVersion::Any, Alpn::Http11),
    ] {
        let h2_spoken = matches!(offer, Alpn::H2Http11 | Alpn::H2);
        let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
        let libraries = SharedLibraries::new(Libraries {
            tls: Some(Library::Static(backend)),
            h2: h2.then_some(&FAKE as &dyn crate::http2::Http2),
            ..Libraries::NONE
        })
        .unwrap();
        let response = if h2_spoken {
            fake::records(RESPONSE).unwrap()
        } else {
            fake::records(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").unwrap()
        };
        let talk = Conversation::replies(&[WELCOME, &response], false).per_send();
        let mut m = serving(Peer::Accepts, &[&talk]);
        let mut e = Easy::new();
        e.set_libraries(libraries);
        let components = crate::components::Components::new().unwrap();
        components.configure(b"https-connect");
        e.set_components(Some(components));
        let url = format!("https://127.0.0.1:{PORT}/");
        let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
            o.http.version = version;
            o.output.verbose = true;
        });
        assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
        assert_eq!(ran.seen.body(), b"hello");
        let text = ran.seen.text();
        let using = if h2_spoken {
            "using HTTP/2\n"
        } else {
            "using HTTP/1.x\n"
        };
        assert_eq!(backend.log().alpn, Some(offer), "{version:?}");
        assert!(text.iter().any(|l| l == using), "{text:?}");
        let first = if h2_spoken { "h2" } else { "h1" };
        let line = format!("[HTTPS-CONNECT] 1st attempt uses {first} from wanted versions\n");
        assert!(text.contains(&line), "{version:?} {text:?}");
    }
}

/// The application's `Transfer-Encoding: chunked` is dropped over
/// HTTP/2, which frames the body itself, and C says so once the head is
/// made.
#[test]
fn an_asked_chunked_body_goes_plain() {
    let reply: &[u8] = b"S\nH 1 1\n:status: 200\n\n";
    let (ran, _) = h2_get(&[reply], "/up", |o| {
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"abc".to_vec()).unwrap(),
        );
        o.method = Method::Post;
        o.http.headers =
            crate::options::UserHeaders::new([&b"Transfer-Encoding: chunked"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let sent = String::from_utf8(ran.request.clone()).unwrap();
    assert!(sent.ends_with("\n\nD 1 3 1\nabc"), "{sent}");
    assert!(!sent.contains("transfer-encoding"), "{sent}");
    let out = String::from_utf8(ran.seen.of("out").concat()).unwrap();
    assert!(!out.contains("Transfer-Encoding"), "{out}");
    assert!(
        ran.seen.text().iter().any(|l| l
            == "suppressing chunked transfer encoding on connection using HTTP version 2 or \
                higher\n"),
        "{:?}",
        ran.seen.text()
    );
}

/// `--http2` over clear text asks for an upgrade with the client's
/// settings in base64url, and no `Expect:`; a 101 switches the
/// connection, its head handed on as an interim one, and the response
/// comes on stream 1 in HTTP/2, with what followed the 101 read as
/// HTTP/2 (`Curl_http2_upgrade`).
#[test]
fn a_101_switches_an_upgrade_to_http2() {
    let reply: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n\
                         S\nH 1 0\n:status: 200\ncontent-length: 2\n\nD 1 2 1\nok";
    let talk = Conversation::new(reply, false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let ran = get_with(&mut m, e, "/u", talk.clone(), |o| {
        o.http.version = HttpVersion::Http2;
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    let sent = String::from_utf8(ran.request.clone()).unwrap();
    assert!(
        sent.starts_with(&format!(
            "GET /u HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUser-Agent: curl/test\r\n\
             Accept: */*\r\nUpgrade: h2c\r\nHTTP2-Settings: TUNTPTEwMDtJV1M9NjU1MzY7RVA9MDs\r\n\
             Connection: Upgrade, HTTP2-Settings\r\n\r\n"
        )),
        "{sent}"
    );
    assert_eq!(
        ran.seen.of("interim"),
        [
            &b"HTTP/1.1 101 Switching Protocols\r\n"[..],
            b"Upgrade: h2c\r\n",
            b"\r\n"
        ]
    );
    assert_eq!(
        ran.seen.of("header"),
        [&b"HTTP/2 200 \r\n"[..], b"content-length: 2\r\n", b"\r\n"]
    );
    assert_eq!(ran.seen.body(), b"ok");
    let text = ran.seen.text();
    assert!(
        text.iter()
            .any(|l| l == "Received 101, Switching to HTTP/2\n"),
        "{text:?}"
    );
    assert_eq!(ran.easy.report().response_code(), Some(200));
}

/// A body of unknown size asks for a 100 over HTTP/1.1, but not with an
/// upgrade (`addexpect`): it goes chunked, unannounced.
#[test]
fn an_upgrade_asks_for_no_100() {
    let talk = Conversation::new(OK, false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let ran = get_with(&mut m, e, "/up", talk.clone(), |o| {
        o.http.version = HttpVersion::Http2;
        o.upload = crate::options::UploadSource::Read {
            handler: Handler::read(super::Stream::new(b"abc")).unwrap(),
            rewind: None,
            size: None,
        };
        o.method = Method::Post;
    });
    assert_eq!(ran.result, Ok(()));
    let sent = String::from_utf8(ran.request.clone()).unwrap();
    assert!(sent.contains("Upgrade: h2c\r\n"), "{sent}");
    assert!(sent.contains("Transfer-Encoding: chunked\r\n"), "{sent}");
    assert!(!sent.contains("Expect"), "{sent}");
}

/// A server that does not take the upgrade answers in HTTP/1.1, and the
/// connection stays HTTP/1.
#[test]
fn an_upgrade_not_taken_is_answered_in_http_1() {
    let talk = Conversation::new(OK, false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.http.version = HttpVersion::Http2;
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok\n");
}

/// An idle HTTP/2 connection with frames to read is not taken for dead
/// as an HTTP/1 one with input waiting is: its session reads them, and
/// the next transfer, a second later, when its health is looked at again,
/// reuses it (`http2_connisalive`).
#[test]
fn an_idle_connection_s_frames_are_read_and_it_is_reused() {
    let mut first = RESPONSE.to_vec();
    for _ in 0..600 {
        first.extend_from_slice(b"P\n");
    }
    let second: &[u8] = b"H 3 0\n:status: 200\n\nD 3 2 1\nok";
    let talk = Conversation::replies(&[&first, second], false).per_send();
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    for (path, body) in [("/1", &b"hello"[..]), ("/2", b"ok")] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let ran = get_with(&mut m, e, path, talk.clone(), |o| {
            o.http.version = HttpVersion::Http2Prior;
            // The first read leaves frames behind the response.
            o.limits.buffer_size = crate::options::BufferSize::clamped(1024);
        });
        assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
        assert_eq!(ran.seen.body(), body);
        if path == "/2" {
            let text = ran.seen.text();
            assert!(
                text.iter().any(|l| l.starts_with("Reusing existing")),
                "{text:?}"
            );
        }
        clock.advance(std::time::Duration::from_millis(1000));
    }
}

/// A body the application refuses resets its stream with what C resets
/// it with, nghttp2's callback failure as an unsigned code, which no RFC
/// defines (`on_data_chunk_recv`'s `NGHTTP2_ERR_CALLBACK_FAILURE`).
#[test]
fn a_refused_body_resets_its_stream_as_c_does() {
    struct Refuses;
    impl WriteHandler for Refuses {
        fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
            Write::Fail
        }
    }
    let reply: &[u8] = b"S\nH 1 0\n:status: 200\n\nD 1 5 0\nhello";
    let talk = Conversation::replies(&[reply], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.http.version = HttpVersion::Http2Prior;
        o.callbacks.write = Some(Handler::write(Refuses).unwrap());
    });
    assert_eq!(ran.result, Err(ErrorKind::WriteError));
    let sent = String::from_utf8(talk.received()).unwrap();
    assert!(sent.contains("R 1 4294966394\n"), "{sent}");
}

/// A multi with a manual clock, its server answering on `talks`.
fn clocked(talks: &[&Conversation]) -> (Multi, ManualClock) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let mut net = FakeNet::new(clock.clone()).with_peer(at, Peer::Accepts);
    for talk in talks {
        net = net.with_conversation(at, (*talk).clone());
    }
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), clock)
}

/// An idle HTTP/2 connection is sent a PING by the upkeep once the
/// calling handle's interval has passed since it was given back, 60
/// seconds unless set, and not a millisecond before; the PING starts the
/// interval again (`conn_upkeep`, `cf_h2_keep_alive`).
#[test]
fn an_idle_connection_is_pinged_once_its_upkeep_interval_passed() {
    for interval in [None, Some(5000), Some(0)] {
        let talk = Conversation::replies(&[RESPONSE], false).per_send();
        let (mut m, clock) = clocked(&[&talk]);
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
            o.http.version = HttpVersion::Http2Prior;
            if let Some(ms) = interval {
                o.limits.reuse.upkeep = crate::options::UpkeepInterval(Duration::from_millis(ms));
            }
        });
        assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
        let pings = || talk.received().windows(2).filter(|w| w == b"P\n").count();
        let request = talk.received().len();
        let ms = interval.unwrap_or(60_000);
        let upkeep = |m: &mut Multi| m.upkeep_for(&ran.easy, &mut NoEvents).unwrap();
        if ms > 0 {
            clock.advance(Duration::from_millis(ms - 1));
            upkeep(&mut m);
            assert_eq!(talk.received().len(), request, "{ms} ms: early");
            clock.advance(Duration::from_millis(1));
        }
        upkeep(&mut m);
        assert_eq!(&talk.received()[request..], b"P\n", "{ms} ms: due");
        if ms > 0 {
            upkeep(&mut m);
            clock.advance(Duration::from_millis(ms - 1));
            upkeep(&mut m);
            assert_eq!(pings(), 1, "{ms} ms: the interval starts again");
            clock.advance(Duration::from_millis(1));
        }
        upkeep(&mut m);
        assert_eq!(pings(), 2, "{ms} ms: due again");
    }
}

/// An idle HTTP/1 connection is sent nothing by the upkeep: it has no
/// keep-alive of its own to send (`Curl_cf_def_conn_keep_alive`).
#[test]
fn an_idle_http1_connection_is_sent_nothing_by_the_upkeep() {
    let talk = Conversation::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", false);
    let (mut m, clock) = clocked(&[&talk]);
    let ran = get_with(&mut m, Easy::new(), "/", talk.clone(), |_| {});
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    let request = talk.received();
    clock.advance(Duration::from_secs(60));
    m.upkeep_for(&ran.easy, &mut NoEvents).unwrap();
    assert_eq!(talk.received(), request);
}

/// A connection in use is due its PING an interval after it was found
/// connected, as an idle one is after it was given back; with a stream
/// open, the PING goes with the transfer's next send, which alone can
/// frame the stream's body. A share's connection lent to the multi is
/// reached through the multi, for a handle on that share; a handle on
/// another share reaches that one's, which does not have it.
#[test]
fn a_connection_in_use_is_pinged_with_its_transfer_s_next_send() {
    use crate::share::{Kind, Share};
    #[derive(Debug, PartialEq)]
    enum On {
        Multi,
        Share,
        ShareAskedByAnother,
    }
    for on in [On::Multi, On::Share, On::ShareAskedByAnother] {
        let talk = Conversation::replies(&[RESPONSE], false).per_send().held();
        let (mut m, clock) = clocked(&[&talk]);
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        if on != On::Multi {
            let share = Share::new().unwrap();
            share.keep(Kind::Connections).unwrap();
            e.set_share(Some(share));
        }
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.version = HttpVersion::Http2Prior;
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        for _ in 0..3 {
            m.perform(&mut NoEvents).unwrap();
        }
        let request = talk.received();
        assert!(
            request.ends_with(b"U 1 10420224\n"),
            "{on:?}: the request and its window went: {:?}",
            String::from_utf8_lossy(&request)
        );
        let lent = usize::from(on != On::Multi);
        assert_eq!(m.lent_connections(), lent, "{on:?}");
        clock.advance(Duration::from_secs(60));
        match on {
            On::Multi | On::Share => m.upkeep(id, &mut NoEvents).unwrap().unwrap(),
            On::ShareAskedByAnother => {
                let mut other = Easy::new();
                let share = Share::new().unwrap();
                share.keep(Kind::Connections).unwrap();
                other.set_share(Some(share));
                m.upkeep_for(&other, &mut NoEvents).unwrap();
            }
        }
        assert_eq!(
            talk.received(),
            request,
            "{on:?}: not sent beside the transfer"
        );
        talk.allow(1);
        assert_eq!(
            drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
            Ok(())
        );
        let ping: &[u8] = match on {
            On::Multi | On::Share => b"P\n",
            On::ShareAskedByAnother => b"",
        };
        assert_eq!(&talk.received()[request.len()..], ping, "{on:?}");
        m.remove(id, &mut NoEvents).unwrap();
    }
}

/// An idle connection whose PING cannot be sent is closed by the upkeep
/// (`conn_upkeep`'s `cpool_conn_close`): the next transfer makes another.
#[test]
fn an_idle_connection_whose_ping_fails_is_closed() {
    // The sends of the first transfer, which all go.
    const SENDS: usize = 1;
    for breaks in [false, true] {
        let mut talk = Conversation::replies(&[RESPONSE], false).per_send();
        if breaks {
            talk = talk.breaking_after(SENDS);
        }
        let fresh =
            Conversation::replies(&[b"S\nH 1 0\n:status: 200\n\nD 1 2 1\nok"], false).per_send();
        let (mut m, clock) = clocked(&[&talk, &fresh]);
        let mut texts = Vec::new();
        for (path, talk) in [("/1", &talk), ("/2", &fresh)] {
            let mut e = Easy::new();
            e.set_libraries(with_h2());
            let ran = get_with(&mut m, e, path, talk.clone(), |o| {
                o.http.version = HttpVersion::Http2Prior;
            });
            // The first connection has no answer for a second request.
            if path == "/1" || breaks {
                assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
            }
            texts.push(ran.seen.text());
            if path == "/1" {
                clock.advance(Duration::from_secs(60));
                m.upkeep_for(&ran.easy, &mut NoEvents).unwrap();
            }
        }
        let reused = texts[1].iter().any(|l| l.starts_with("Reusing existing"));
        assert_eq!(reused, !breaks, "{:?}", texts[1]);
        assert_eq!(fresh.received().is_empty(), !breaks);
    }
}

/// The interval starts again as each transfer gives its connection back,
/// another still on it (`Curl_cpool_return`): one interval less a
/// millisecond after the first is done, the second's next send carries
/// no PING. A share's connection lent to the multi starts it again as
/// one of its own does.
#[test]
fn the_upkeep_interval_starts_as_one_of_two_transfers_is_done() {
    use crate::share::{Kind, Share};
    for shared in [false, true] {
        let replies: [&[u8]; 4] = [
            b"S\nH 1 0\n:status: 200\n\n",
            b"",
            b"D 1 2 1\naa",
            b"H 3 0\n:status: 200\n\nD 3 1 1\nc",
        ];
        let talk = Conversation::replies(&replies, false).per_send().held();
        talk.allow(2);
        let (mut m, clock) = clocked(&[&talk]);
        let share = Share::new().unwrap();
        share.keep(Kind::Connections).unwrap();
        let mut ids = Vec::new();
        for path in ["/a", "/b"] {
            let mut e = Easy::new();
            e.set_libraries(with_h2());
            if shared {
                e.set_share(Some(share.clone()));
            }
            let o = e.options_mut();
            let url = format!("http://127.0.0.1:{PORT}{path}");
            o.set_url(Some(url.as_bytes())).unwrap();
            o.limits.total = crate::time::TimeLimit::from_millis(200_000);
            o.http.version = HttpVersion::Http2Prior;
            ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
            for _ in 0..3 {
                m.perform(&mut NoEvents).unwrap();
            }
        }
        assert_eq!(m.lent_connections(), usize::from(shared));
        clock.advance(Duration::from_secs(30));
        talk.allow(3);
        assert_eq!(
            drive_to_completion(&mut m, ids[0], &mut NoEvents).unwrap(),
            Ok(())
        );
        m.remove(ids[0], &mut NoEvents).unwrap();
        clock.advance(Duration::from_millis(59_999));
        m.upkeep(ids[1], &mut NoEvents).unwrap().unwrap();
        talk.allow(4);
        assert_eq!(
            drive_to_completion(&mut m, ids[1], &mut NoEvents).unwrap(),
            Ok(())
        );
        let sent = String::from_utf8(talk.received()).unwrap();
        assert!(sent.contains("H 3 1\n"), "shared {shared}: {sent}");
        assert!(!sent.contains("P\n"), "shared {shared}: {sent}");
        m.remove(ids[1], &mut NoEvents).unwrap();
    }
}

/// The interval starts again as a transfer gives its connection back,
/// however long it was found connected before (`Curl_cpool_return`).
#[test]
fn the_upkeep_interval_starts_as_the_connection_is_given_back() {
    let talk = Conversation::replies(&[RESPONSE], false).per_send().held();
    let (mut m, clock) = clocked(&[&talk]);
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let o = e.options_mut();
    let url = format!("http://127.0.0.1:{PORT}/");
    o.set_url(Some(url.as_bytes())).unwrap();
    o.http.version = HttpVersion::Http2Prior;
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    for _ in 0..3 {
        m.perform(&mut NoEvents).unwrap();
    }
    clock.advance(Duration::from_secs(30));
    talk.allow(1);
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    let easy = m.remove(id, &mut NoEvents).unwrap().easy;
    let request = talk.received();
    clock.advance(Duration::from_millis(59_999));
    m.upkeep_for(&easy, &mut NoEvents).unwrap();
    assert_eq!(talk.received(), request, "given back 59999 ms ago");
    clock.advance(Duration::from_millis(1));
    m.upkeep_for(&easy, &mut NoEvents).unwrap();
    assert_eq!(&talk.received()[request.len()..], b"P\n");
}

/// An idle HTTP/2 connection is looked at once a second at most: a
/// GOAWAY waiting on it goes unread by a reuse within a second of its
/// return, whose stream the GOAWAY then refuses, and is read a second on,
/// when the connection is let go and a new one made
/// (`Curl_cpool_conn_seems_healthy`'s `lastchecked_ms`).
#[test]
fn an_idle_connection_s_health_is_looked_at_once_a_second() {
    for (after_ms, reused) in [(999, true), (1000, false)] {
        let mut first = RESPONSE.to_vec();
        for _ in 0..600 {
            first.extend_from_slice(b"P\n");
        }
        first.extend_from_slice(b"G 1 0\n");
        let second: &[u8] = b"S\nH 1 0\n:status: 200\n\nD 1 2 1\nok";
        let talk = Conversation::replies(&[&first], false).per_send();
        let fresh = Conversation::replies(&[second], false).per_send();
        let clock = ManualClock::new().unwrap();
        let at = SocketAddr::from(([127, 0, 0, 1], PORT));
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone())
            .with_conversation(at, fresh.clone());
        let env = Env {
            clock: Box::new(clock.clone()),
            net: Box::new(net),
            arena: ArenaPolicy::new(16, 0).unwrap(),
            waker: None,
        };
        let mut m = Multi::new(env).unwrap();
        for (path, body, talk) in [("/1", &b"hello"[..], &talk), ("/2", b"ok", &fresh)] {
            let mut e = Easy::new();
            e.set_libraries(with_h2());
            let ran = get_with(&mut m, e, path, talk.clone(), |o| {
                o.http.version = HttpVersion::Http2Prior;
                // The first read leaves the frames behind the response.
                o.limits.buffer_size = crate::options::BufferSize::clamped(1024);
            });
            assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
            assert_eq!(ran.seen.body(), body);
            if path == "/2" {
                let text = ran.seen.text();
                let was = text.iter().any(|l| l.starts_with("Reusing existing"));
                assert_eq!(was, reused, "{after_ms} ms: {text:?}");
            }
            clock.advance(std::time::Duration::from_millis(after_ms));
        }
    }
}

/// An HTTP/2 connection that shuts down says GOAWAY first, no stream of
/// the server's served (`cf_h2_shutdown`).
#[test]
fn a_connection_shutting_down_says_goaway() {
    let (ran, talk) = h2_get(&[RESPONSE], "/", |o| o.limits.reuse.forbid = true);
    assert_eq!(ran.result, Ok(()));
    let sent = String::from_utf8(talk.received()).unwrap();
    assert!(sent.ends_with("\n\nG 0 0\n"), "{sent}");
}

/// A stream reset with HTTP_1_1_REQUIRED is made again in HTTP/1.1, on a
/// fresh connection whose TLS offers HTTP/1.1 alone, its failure let go
/// (`Curl_h2_http_1_1_error`, "Downgrades to HTTP/1.1").
#[test]
fn http_1_1_required_downgrades_the_request() {
    use crate::libraries::Library;
    use crate::tls::fake::{self, FakeTls, WELCOME};
    static FAKE: FakeH2 = FakeH2;
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        h2: Some(&FAKE),
        ..Libraries::NONE
    })
    .unwrap();
    let refused = fake::records(b"S\nR 1 13\n").unwrap();
    let ok = fake::records(OK).unwrap();
    let first = Conversation::replies(&[WELCOME, &refused], false).per_send();
    let second = Conversation::replies(&[WELCOME, &ok], false).per_send();
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let url = format!("https://127.0.0.1:{PORT}/");
    let ran = get_with(&mut m, e, "/", second.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"ok\n");
    assert_eq!(backend.log().alpn, Some(crate::tls::Alpn::Http11));
    assert_eq!(backend.log().sessions, 2);
    let text = ran.seen.text();
    assert!(
        text.iter().any(|l| l == "Downgrades to HTTP/1.1\n"),
        "{text:?}"
    );
    assert_eq!(ran.easy.report().failure(), None, "the failure let go");
}

/// A transfer that speaks HTTP/1.1 only does not reuse a connection
/// that speaks HTTP/2, nor one that wants HTTP/2 alone one that speaks
/// HTTP/1 (`url_match_http_version`).
#[test]
fn a_connection_is_reused_only_by_a_transfer_that_speaks_its_version() {
    let h2 = Conversation::replies(&[RESPONSE], false).per_send();
    let h1 = Conversation::new(OK, false);
    let mut m = serving(Peer::Accepts, &[&h2, &h1]);
    for (version, body) in [
        (HttpVersion::Http2Prior, &b"hello"[..]),
        (HttpVersion::Http11, b"ok\n"),
    ] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let ran = get_with(&mut m, e, "/", h1.clone(), |o| o.http.version = version);
        assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
        assert_eq!(ran.seen.body(), body);
        assert!(
            !ran.seen.text().iter().any(|l| l.starts_with("Reusing")),
            "{:?}",
            ran.seen.text()
        );
    }
}

/// A stream's failure leaves its HTTP/2 connection to the next
/// transfer, as any other failure does not.
#[test]
fn a_stream_s_failure_keeps_the_connection() {
    let second: &[u8] = b"H 3 0\n:status: 200\n\nD 3 2 1\nok";
    let talk = Conversation::replies(&[b"S\nR 1 2\n", second], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    for (path, result) in [("/1", Err(ErrorKind::Http2Stream)), ("/2", Ok(()))] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let ran = get_with(&mut m, e, path, talk.clone(), |o| {
            o.http.version = HttpVersion::Http2Prior;
        });
        assert_eq!(ran.result, result, "{:?}", ran.seen.text());
        if path == "/2" {
            assert_eq!(ran.seen.body(), b"ok");
            assert!(
                ran.seen.text().iter().any(|l| l.starts_with("Reusing")),
                "{:?}",
                ran.seen.text()
            );
        }
    }
}

/// A refusal that ends the stream while the body still goes is the
/// response: the body stops by a reset, which does not fail the
/// response already whole (`on_stream_frame`'s END_STREAM, test 07_43).
#[test]
fn a_refusal_mid_upload_is_the_response() {
    let reply: &[u8] = b"S\nH 1 1\n:status: 413\n\n";
    let (ran, _) = h2_get(&[reply], "/up", |o| {
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(vec![b'x'; 200_000]).unwrap(),
        );
        o.method = Method::Post;
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    assert_eq!(ran.easy.report().response_code(), Some(413));
    let sent = String::from_utf8(ran.request.clone()).unwrap();
    assert!(sent.contains("R 1 5\n"), "the body stopped by a reset");
}

/// A success that ends the stream while the body still goes does not
/// stop the body by a reset, as a refusal does (`on_stream_frame`'s
/// END_STREAM resets only for a status outside 2xx and 3xx).
#[test]
fn a_success_mid_upload_does_not_reset_the_stream() {
    let reply: &[u8] = b"S\nH 1 1\n:status: 201\n\n";
    let (ran, _) = h2_get(&[reply], "/up", |o| {
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(vec![b'x'; 200_000]).unwrap(),
        );
        o.method = Method::Post;
    });
    assert_eq!(ran.easy.report().response_code(), Some(201));
    let sent = String::from_utf8(ran.request.clone()).unwrap();
    assert!(!sent.contains("R 1 "), "{sent}");
}

/// A stream a GOAWAY refuses is made again on a new connection, unless
/// the GOAWAY said an error, which the stream then fails with
/// (`on_stream_close`'s `goaway_error`).
#[test]
fn a_stream_refused_by_a_goaway_with_an_error_fails_with_it() {
    let (ran, _) = h2_get(&[b"S\nG 0 2\n"], "/", |_| {});
    assert_eq!(
        ran.result,
        Err(ErrorKind::Http2Stream),
        "{:?}",
        ran.seen.text()
    );
    let text = ran.seen.text();
    assert!(
        !text.iter().any(|l| l.contains("refused by server")),
        "{text:?}"
    );
    assert!(
        text.iter().any(|l| l.contains("INTERNAL_ERROR")),
        "{text:?}"
    );
}

/// Under a receive limit, a stream's reads take no more than the limit
/// allows, each second's bytes delivered in it, and the transfer waits
/// for it (`sendrecv_dl`'s
/// `rate_limited`, test 02_24).
#[test]
fn a_receive_limit_paces_a_stream() {
    use std::num::NonZeroU64;
    let mut reply = b"S\nH 1 0\n:status: 200\n\n".to_vec();
    for i in 0..60 {
        let end = u8::from(i == 59);
        reply.extend_from_slice(format!("D 1 1000 {end}\n").as_bytes());
        reply.extend_from_slice(&[b'x'; 1000]);
    }
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::replies(&[&reply], false).per_send();
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    let start = clock.now();
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let delivered = DeliveredBy {
        clock: clock.clone(),
        start,
        seen: Arc::default(),
    };
    let ran = get_with(&mut m, e, "/", talk, |o| {
        o.http.version = HttpVersion::Http2Prior;
        o.flow.make_mut().unwrap().max_recv_speed = NonZeroU64::new(20000);
        o.callbacks.write = Some(Handler::write(delivered.clone()).unwrap());
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    // Each second's reads take no more than its allowance: what one read
    // past the limit took would come at once, the rate's wait after it.
    let seen = delivered.seen.lock().unwrap().clone();
    assert_eq!(seen.last().map(|s| s.1), Some(60000));
    for &(at, total) in &seen {
        assert!(total as u64 <= 20000 * (at.as_secs() + 1), "{seen:?}");
    }
    assert!(
        clock.now().since(start) >= std::time::Duration::from_secs(2),
        "{:?}",
        clock.now().since(start)
    );
}

/// How much of the body was delivered by when, from `start`.
#[derive(Clone)]
struct DeliveredBy {
    clock: ManualClock,
    start: crate::time::Instant,
    seen: Arc<Mutex<Vec<(std::time::Duration, usize)>>>,
}

impl WriteHandler for DeliveredBy {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        let mut seen = self.seen.lock().unwrap();
        let total = seen.last().map_or(0, |s| s.1) + body.len();
        seen.push((self.clock.now().since(self.start), total));
        Write::Accepted
    }
}

/// The client's SETTINGS let the server open as many streams as the
/// multi says (`CURLMOPT_MAX_CONCURRENT_STREAMS`).
#[test]
fn the_settings_say_the_multi_s_streams() {
    let talk = Conversation::replies(&[RESPONSE], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    m.conn_limits_mut().max_streams = std::num::NonZeroU32::new(7).unwrap();
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let ran = get_with(&mut m, e, "/", talk, |o| {
        o.http.version = HttpVersion::Http2Prior
    });
    assert_eq!(ran.result, Ok(()));
    assert!(ran.request.starts_with(b"S MCS=7;IWS=65536;EP=0;\n"));
}

/// The stream asks the weight the application set, as its priority
/// (`h2_pri_spec`).
#[test]
fn a_stream_asks_its_weight() {
    let (ran, _) = h2_get(&[RESPONSE], "/", |o| {
        o.http.stream_weight = std::num::NonZeroU16::new(200);
    });
    assert_eq!(ran.result, Ok(()));
    let sent = String::from_utf8(ran.request.clone()).unwrap();
    assert!(
        sent.contains("\nH 1 1\nweight: 200\n:method: GET\n"),
        "{sent}"
    );
}

/// A transfer's outcome, and what it saw.
type Outcome = (Result<(), ErrorKind>, Seen);

/// Two transfers to one origin, set up on one multi, the second added
/// once the first is under way, `set` making each's options, the second
/// driven to its end first: each's outcome and what it saw, and what the server read on each connection,
/// the connections answering each send with the next of their replies,
/// `talks` in turn.
fn h2_pair(
    talks: &[&[&[u8]]],
    multi: impl FnOnce(&mut Multi),
    set: impl Fn(usize, &mut Options),
) -> ([Outcome; 2], Vec<String>) {
    h2_pair_added(talks, false, multi, set)
}

/// As `h2_pair`, both added before either runs if `together`.
fn h2_pair_added(
    talks: &[&[&[u8]]],
    together: bool,
    multi: impl FnOnce(&mut Multi),
    set: impl Fn(usize, &mut Options),
) -> ([Outcome; 2], Vec<String>) {
    h2_pair_of(talks, together, multi, set, |_| {})
}

/// As `h2_pair_added`, `handle` making each handle's own settings.
fn h2_pair_of(
    talks: &[&[&[u8]]],
    together: bool,
    multi: impl FnOnce(&mut Multi),
    set: impl Fn(usize, &mut Options),
    handle: impl Fn(&mut Easy),
) -> ([Outcome; 2], Vec<String>) {
    let talks: Vec<Conversation> = talks
        .iter()
        .map(|r| Conversation::replies(r, false).per_send())
        .collect();
    let mut m = serving(Peer::Accepts, &talks.iter().collect::<Vec<_>>());
    multi(&mut m);
    let mut ids = Vec::new();
    let mut seen = Vec::new();
    for (i, path) in ["/a", "/b"].into_iter().enumerate() {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let s = Seen::default();
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.output.verbose = true;
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.http.user_agent = Some(b"curl/test".to_vec());
        o.http.version = HttpVersion::Http2Prior;
        o.callbacks.write = Some(Handler::write(s.clone()).unwrap());
        o.callbacks.header = Some(Handler::header(s.clone()).unwrap());
        o.callbacks.debug = Some(Handler::debug(s.clone()).unwrap());
        set(i, o);
        handle(&mut e);
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
        seen.push(s);
        // The first is under way before the second looks for a
        // connection.
        for _ in 0..3 {
            if !together {
                m.perform(&mut NoEvents).unwrap();
            }
        }
    }
    let b = drive_to_completion(&mut m, ids[1], &mut NoEvents).unwrap();
    let a = drive_to_completion(&mut m, ids[0], &mut NoEvents).unwrap();
    for id in ids {
        m.remove(id, &mut NoEvents).unwrap();
    }
    let mut seen = seen.into_iter();
    let sent = talks
        .iter()
        .map(|t| String::from_utf8(t.received()).unwrap())
        .collect();
    ([(a, seen.next().unwrap()), (b, seen.next().unwrap())], sent)
}

/// The second of two replies on a connection that answers both
/// transfers' streams, the first's response coming first.
/// Nothing, in reply to the WINDOW_UPDATE a stream's head draws as its
/// window grows to the most (`cf_h2_update_local_win`).
const WINDOW_SENT: &[u8] = b"";

const SECOND: &[u8] = b"H 3 0\n:status: 201\n\nD 3 2 0\nb1D 1 2 1\naaD 3 1 1\nc";

/// A second transfer to the origin joins the first's HTTP/2 connection,
/// on a stream of its own: what the session reads for either stream goes
/// to its own transfer, as it is read, whichever transfer read it
/// (`on_data_chunk_recv`).
#[test]
fn two_transfers_share_a_connection() {
    let ([(a, sa), (b, sb)], sent) = h2_pair(
        &[&[b"S\nH 1 0\n:status: 200\n\n", WINDOW_SENT, SECOND]],
        |_| {},
        |_, _| {},
    );
    let sent = &sent[0];
    assert_eq!(
        (a, b),
        (Ok(()), Ok(())),
        "{:#?}\n{:#?}\n{sent}",
        sa.text(),
        sb.text()
    );
    let sent = sent.clone();
    assert!(
        sent.contains("H 1 1\n") && sent.contains("H 3 1\n"),
        "{sent}"
    );
    assert_eq!(sa.body(), b"aa");
    assert_eq!(sb.body(), b"b1c");
    assert_eq!(sb.of("header")[0], b"HTTP/2 201 \r\n");
    let text = sb.text();
    assert!(
        text.iter().any(|l| l == "Multiplexed connection found\n"),
        "{text:?}"
    );
}

/// A transfer taken out of the multi with its stream still open resets
/// the stream, and the reset goes as it is taken out, not with whichever
/// transfer next steps on the connection (`http2_data_done`): a server
/// would otherwise go on sending what no one reads.
#[test]
fn a_transfer_removed_mid_body_resets_its_stream_at_once() {
    let talk = Conversation::replies(
        &[
            b"S\nH 1 0\n:status: 200\n\nD 1 2 0\naaH 3 0\n:status: 200\n\nD 3 2 0\nbb",
            WINDOW_SENT,
        ],
        false,
    )
    .per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut ids = Vec::new();
    for path in ["/a", "/b"] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.http.version = HttpVersion::Http2Prior;
        o.callbacks.write = Some(Handler::write(Seen::default()).unwrap());
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
        for _ in 0..3 {
            m.perform(&mut NoEvents).unwrap();
        }
    }
    let sent = || String::from_utf8(talk.received()).unwrap();
    assert!(sent().contains("H 3 1\n"), "both requests sent: {}", sent());
    assert!(!sent().contains("R 1 "), "{}", sent());
    m.remove(ids[0], &mut NoEvents).unwrap();
    assert!(sent().contains("R 1 5\n"), "{}", sent());
    m.remove(ids[1], &mut NoEvents).unwrap();
}

/// The transfer done first on a connection another is still on says so,
/// and leaves the connection to it; the last says it used it alone
/// (`multi_done_locked`).
#[test]
fn a_transfer_done_on_a_shared_connection_says_it_is_still_in_use() {
    let ([(a, sa), (b, sb)], _) = h2_pair_of(
        &[&[b"S\nH 1 0\n:status: 200\n\n", WINDOW_SENT, SECOND]],
        false,
        |_| {},
        |_, _| {},
        |e| {
            let components = crate::components::Components::new().unwrap();
            components.configure(b"multi");
            e.set_components(Some(components));
        },
    );
    assert_eq!((a, b), (Ok(()), Ok(())));
    let said = |s: &Seen, line: &str| s.text().iter().any(|l| l.ends_with(line));
    let still = "] Connection still in use 1, no more multi_done now!\n";
    // The second is driven to its end first, the first still on.
    assert!(
        said(&sb, "] multi_done_locked, in use=1\n"),
        "{:#?}",
        sb.text()
    );
    assert!(said(&sb, still), "{:#?}", sb.text());
    assert!(
        said(&sa, "] multi_done_locked, in use=0\n"),
        "{:#?}",
        sa.text()
    );
    assert!(!sa.text().iter().any(|l| l.contains("still in use")));
}

/// Transfers of one multi whose handles share connections
/// (`CURL_LOCK_DATA_CONNECT`) multiplex on one as the multi's own do: the
/// share's connection, found to speak HTTP/2, takes the second transfer
/// on a stream of its own (`url_match_multiplex_needs`, the connection
/// the share's while the multi has it, `attached_multi`). Each transfer
/// uses the share's pool as C locks it: as it joins, searches and is
/// done, and the first as it adds the connection (`Curl_cpool_return`
/// locks for a transfer done with one others are still on).
#[test]
fn transfers_on_a_share_share_its_connection() {
    use crate::share::{Kind, Share, Told};
    let share = Share::new().unwrap();
    share.keep(Kind::Connections).unwrap();
    let told = Told::new(&share);
    let ([(a, sa), (b, sb)], sent) = h2_pair_of(
        &[&[b"S\nH 1 0\n:status: 200\n\n", WINDOW_SENT, SECOND]],
        false,
        |_| {},
        // Not kept once both are done: no connection outlives the
        // multi's network in the share.
        |_, o| o.limits.reuse.forbid = true,
        |e| e.set_share_watched(share.clone(), told.handler()),
    );
    assert_eq!(sent.len(), 1, "one connection: {sent:#?}");
    let sent = &sent[0];
    assert_eq!(
        (a, b),
        (Ok(()), Ok(())),
        "{:#?}\n{:#?}\n{sent}",
        sa.text(),
        sb.text()
    );
    assert!(
        sent.contains("H 1 1\n") && sent.contains("H 3 1\n"),
        "{sent}"
    );
    assert_eq!(sa.body(), b"aa");
    assert_eq!(sb.body(), b"b1c");
    let text = sb.text();
    assert!(
        text.iter().any(|l| l == "Multiplexed connection found\n"),
        "{text:?}"
    );
    assert_eq!(told.uses(), [Kind::Connections; 7]);
    assert_eq!(share.pool().len(), 0, "closed as the last is done");
}

/// A multi dropped with two transfers under way on a share's connection
/// lent to it gives the connection back to the share as the last of them
/// is taken out (`curl_multi_cleanup`): the share's pool leases nothing
/// after, and the connection, forbidden its reuse, is closed.
#[test]
fn a_multi_dropped_gives_a_share_s_lent_connection_back() {
    use crate::share::{Kind, Share};
    let share = Share::new().unwrap();
    share.keep(Kind::Connections).unwrap();
    // Neither stream ends.
    let talk =
        Conversation::replies(&[b"S\nH 1 0\n:status: 200\n\n", WINDOW_SENT], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut seen = Vec::new();
    for path in ["/a", "/b"] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let s = Seen::default();
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.output.verbose = true;
        o.http.version = HttpVersion::Http2Prior;
        o.limits.reuse.forbid = true;
        o.callbacks.debug = Some(Handler::debug(s.clone()).unwrap());
        e.set_share(Some(share.clone()));
        m.add(Box::new(e), (), &mut NoEvents).unwrap();
        seen.push(s);
        for _ in 0..3 {
            m.perform(&mut NoEvents).unwrap();
        }
    }
    let text = seen[1].text();
    assert!(
        text.iter().any(|l| l == "Multiplexed connection found\n"),
        "{text:?}"
    );
    assert_eq!(share.pool().leased(), 1, "lent, its place leased");
    drop(m);
    assert_eq!(share.pool().leased(), 0);
    assert_eq!(share.pool().len(), 0, "closed, forbidden its reuse");
}

/// A connection with as many streams on it as the server's
/// MAX_CONCURRENT_STREAMS takes no more: the second transfer makes a
/// connection of its own (`url_match_multiplex_limits`), saying so as C
/// says it, with no space before "reached".
#[test]
fn a_connection_at_the_servers_limit_takes_no_more() {
    let ([(a, sa), (b, sb)], sent) = h2_pair(
        &[
            &[b"S 1\nH 1 0\n:status: 200\n\n"],
            &[b"S\nH 1 0\n:status: 200\n\nD 1 2 1\nbb"],
        ],
        |_| {},
        |_, _| {},
    );
    // The first's stream never ends: it is on its connection throughout.
    assert_eq!(
        (a, b),
        (Err(ErrorKind::OperationTimedout), Ok(())),
        "{:#?}\n{:#?}\n{sent:#?}",
        sa.text(),
        sb.text()
    );
    assert_eq!(sb.body(), b"bb");
    let text = sb.text();
    assert!(
        text.iter()
            .any(|l| l == "connection #0reached MAX_CONCURRENT_STREAMS(1), skip\n"),
        "{text:?}"
    );
}

/// A multi that does not multiplex has each transfer make its own
/// connection, HTTP/2 or not (`CURLMOPT_PIPELINING` off).
#[test]
fn a_multi_that_does_not_multiplex_shares_no_connection() {
    let ([(a, _), (b, sb)], _) = h2_pair(
        &[
            &[b"S\nH 1 0\n:status: 200\n\n"],
            &[b"S\nH 1 0\n:status: 200\n\nD 1 2 1\nbb"],
        ],
        |m| m.conn_limits_mut().multiplex = false,
        |_, _| {},
    );
    // The first's stream never ends: it is on its connection throughout.
    assert_eq!((a, b), (Err(ErrorKind::OperationTimedout), Ok(())));
    assert_eq!(sb.body(), b"bb");
    let text = sb.text();
    assert!(text.iter().any(|l| l.contains("Trying")), "{text:?}");
    assert!(!text.iter().any(|l| l.contains("Multiplexed")), "{text:?}");
}

/// A connection with as many transfers on it as the multi's
/// `CURLMOPT_MAX_CONCURRENT_STREAMS` takes no more, whatever the server's
/// limit.
#[test]
fn a_connection_at_the_multis_limit_takes_no_more() {
    let ([(a, _), (b, sb)], _) = h2_pair(
        &[
            &[b"S\nH 1 0\n:status: 200\n\n"],
            &[b"S\nH 1 0\n:status: 200\n\nD 1 2 1\nbb"],
        ],
        |m| m.conn_limits_mut().max_streams = std::num::NonZeroU32::new(1).unwrap(),
        |_, _| {},
    );
    assert_eq!((a, b), (Err(ErrorKind::OperationTimedout), Ok(())));
    assert_eq!(sb.body(), b"bb");
    let text = sb.text();
    assert!(
        text.iter()
            .any(|l| l == "connection #0 reached MAX_CONCURRENT_STREAMS(1), skip\n"),
        "{text:?}"
    );
}

/// With `CURLOPT_PIPEWAIT`, a transfer finding a connection to its origin
/// still being set up waits for it to say whether it multiplexes, and
/// joins it once it does, with C's lines (`url_match_result`): the
/// server sees one connection.
#[test]
fn a_transfer_that_pipewaits_joins_the_connection_being_set_up() {
    let ([(a, sa), (b, sb)], sent) = h2_pair_added(
        &[&[b"S\nH 1 0\n:status: 200\n\n", WINDOW_SENT, SECOND]],
        true,
        |_| {},
        |_, o| o.http.pipewait = true,
    );
    assert_eq!((a, b), (Ok(()), Ok(())), "{:#?}\n{sent:#?}", sb.text());
    assert_eq!((sa.body(), sb.body()), (b"aa".to_vec(), b"b1c".to_vec()));
    let text = sb.text();
    assert_eq!(
        text[..4],
        [
            "Connection #0 is not open enough, cannot reuse\n",
            "Found pending candidate for reuse and CURLOPT_PIPEWAIT is set\n",
            "Waiting on connection to negotiate possible multiplexing.\n",
            "Multiplexed connection found\n",
        ],
        "{text:#?}"
    );
}

/// Without `CURLOPT_PIPEWAIT`, a transfer finding a connection to its
/// origin still being set up says so, and makes its own.
#[test]
fn a_transfer_that_does_not_pipewait_makes_its_own_connection() {
    let ([(a, sa), (b, sb)], _) = h2_pair_added(
        &[
            &[b"S\nH 1 0\n:status: 200\n\nD 1 2 1\naa"],
            &[b"S\nH 1 0\n:status: 200\n\nD 1 2 1\nbb"],
        ],
        true,
        |_| {},
        |_, _| {},
    );
    assert_eq!((a, b), (Ok(()), Ok(())));
    assert_eq!((sa.body(), sb.body()), (b"aa".to_vec(), b"bb".to_vec()));
    let text = sb.text();
    assert_eq!(text[0], "Connection #0 is not open enough, cannot reuse\n");
    assert!(text.iter().any(|l| l.contains("Trying")), "{text:#?}");
    assert!(!text.iter().any(|l| l.contains("Waiting")), "{text:#?}");
}

/// A transfer that pipewaits on a connection that turns out to take one
/// request at a time makes its own once it is known, without waiting for
/// the first transfer to end (`seen_single_use_conn`).
#[test]
fn a_pipewait_on_a_connection_that_does_not_multiplex_ends_once_known() {
    pipewait_on_http_1(|_| {});
}

/// The pass in which the first request finds its connection speaks
/// HTTP/1 is the one that lets the transfer pipewaiting on it go
/// (`Curl_multi_connchanged` as the connection settles), not a later one.
#[test]
fn a_pipewait_ends_in_the_pass_its_connection_settles() {
    let first = Conversation::new(OK, false).held();
    let second = Conversation::new(OK, false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let mut ids = Vec::new();
    for path in ["/a", "/b"] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.http.pipewait = true;
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
    }
    let mut passes = 0;
    loop {
        m.perform(&mut NoEvents).unwrap();
        passes += 1;
        if first.received().ends_with(b"\r\n\r\n") {
            break;
        }
        assert!(
            matches!(
                m.state_of(ids[1]),
                crate::multi::state::TransferState::Pending(_)
            ),
            "let go before its connection settled"
        );
        assert!(passes < 20, "the first never sent");
    }
    assert!(
        !matches!(
            m.state_of(ids[1]),
            crate::multi::state::TransferState::Pending(_)
        ),
        "still waiting after the pass its connection settled in"
    );
    first.allow(1);
    for id in ids {
        assert_eq!(
            drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
            Ok(())
        );
        m.remove(id, &mut NoEvents).unwrap();
    }
}

/// As a connection of the multi's own, a share's (`CURL_LOCK_DATA_CONNECT`)
/// is pending until its first request finds what it speaks, and a
/// transfer that pipewaits on it waits until then.
#[test]
fn a_pipewait_on_a_share_s_connection_ends_once_known() {
    use crate::share::{Kind, Share};
    let share = Share::new().unwrap();
    share.keep(Kind::Connections).unwrap();
    pipewait_on_http_1(|e| e.set_share(Some(share.clone())));
}

/// Two transfers that pipewait, `handle` making each handle's own
/// settings, to an origin whose connections take one request at a time,
/// the first's answer held: the second waits for the first's connection
/// to say what it speaks, then makes its own.
fn pipewait_on_http_1(handle: impl Fn(&mut Easy)) {
    let first = Conversation::new(OK, false).held();
    let second = Conversation::new(OK, false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let mut ids = Vec::new();
    let mut seen = Vec::new();
    for path in ["/a", "/b"] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let s = Seen::default();
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.output.verbose = true;
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.http.pipewait = true;
        o.callbacks.write = Some(Handler::write(s.clone()).unwrap());
        o.callbacks.debug = Some(Handler::debug(s.clone()).unwrap());
        handle(&mut e);
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
        seen.push(s);
    }
    let b = drive_to_completion(&mut m, ids[1], &mut NoEvents).unwrap();
    assert_eq!(b, Ok(()));
    assert!(first.received().ends_with(b"\r\n\r\n"), "the first sent");
    let text = seen[1].text();
    assert_eq!(
        text[..3],
        [
            "Connection #0 is not open enough, cannot reuse\n",
            "Found pending candidate for reuse and CURLOPT_PIPEWAIT is set\n",
            "Waiting on connection to negotiate possible multiplexing.\n",
        ],
        "{text:#?}"
    );
    assert!(text.iter().any(|l| l.contains("Trying")), "{text:#?}");
    assert_eq!(seen[1].body(), b"ok\n");
    first.allow(1);
    let a = drive_to_completion(&mut m, ids[0], &mut NoEvents).unwrap();
    assert_eq!(a, Ok(()));
    for id in ids {
        m.remove(id, &mut NoEvents).unwrap();
    }
}

/// A connection whose upgrade to HTTP/2 the server answers in HTTP/1.1
/// is known not to multiplex from that answer on: a transfer that
/// pipewaits on it makes its own then, while the first's body still
/// comes (`bits.upgrade_in_progress`).
#[test]
fn a_pipewait_on_a_refused_upgrade_ends_with_its_answer() {
    let first = Conversation::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab", false);
    let second = Conversation::new(OK, false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let mut ids = Vec::new();
    let mut seen = Vec::new();
    for path in ["/a", "/b"] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let s = Seen::default();
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.output.verbose = true;
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.http.version = HttpVersion::Http2;
        o.http.pipewait = true;
        o.callbacks.write = Some(Handler::write(s.clone()).unwrap());
        o.callbacks.debug = Some(Handler::debug(s.clone()).unwrap());
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
        seen.push(s);
    }
    let b = drive_to_completion(&mut m, ids[1], &mut NoEvents).unwrap();
    let text = seen[1].text();
    assert_eq!(b, Ok(()), "{text:#?}");
    assert!(
        String::from_utf8(first.received())
            .unwrap()
            .contains("Upgrade: h2c"),
        "the first asked to upgrade"
    );
    assert_eq!(
        text[2], "Waiting on connection to negotiate possible multiplexing.\n",
        "{text:#?}"
    );
    assert!(text.iter().any(|l| l.contains("Trying")), "{text:#?}");
    assert_eq!(seen[1].body(), b"ok\n");
    assert_eq!(seen[0].body(), b"ab", "the first's body still comes");
    for id in ids {
        m.remove(id, &mut NoEvents).unwrap();
    }
}

/// A connection to the origin that takes one request at a time, and none
/// seen that takes more, says the server does not multiplex: a transfer
/// that pipewaits makes its own then, though another is still being set
/// up (`url_match_result`).
#[test]
fn a_single_use_connection_ends_a_pipewait_over_another_set_up() {
    let first = Conversation::new(OK, false).held();
    let mut m = serving(
        Peer::Accepts,
        &[
            &first,
            &Conversation::new(OK, false),
            &Conversation::new(OK, false),
        ],
    );
    let mut ids = Vec::new();
    let mut seen = Vec::new();
    for path in ["/a", "/b", "/c"] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let s = Seen::default();
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.output.verbose = true;
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.http.pipewait = true;
        o.callbacks.write = Some(Handler::write(s.clone()).unwrap());
        o.callbacks.debug = Some(Handler::debug(s.clone()).unwrap());
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
        seen.push(s);
    }
    let c = drive_to_completion(&mut m, ids[2], &mut NoEvents).unwrap();
    let text = seen[2].text();
    assert_eq!(c, Ok(()), "{text:#?}");
    let waits = text.iter().filter(|l| l.starts_with("Waiting on")).count();
    assert_eq!(waits, 1, "{text:#?}");
    assert!(
        text.iter()
            .any(|l| l == "Connection #1 is not open enough, cannot reuse\n"),
        "{text:#?}"
    );
    first.allow(1);
    for id in ids {
        drive_to_completion(&mut m, id, &mut NoEvents)
            .unwrap()
            .unwrap();
        m.remove(id, &mut NoEvents).unwrap();
    }
}

/// Two transfers on one connection between performs: the multi's checks
/// count each as a lease on it, and both end once the server answers.
#[test]
fn two_transfers_stay_on_a_connection_between_performs() {
    let talk = Conversation::replies(&[b"S\nH 1 0\n:status: 200\n\n", WINDOW_SENT, SECOND], false)
        .per_send()
        .held();
    talk.allow(2);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut ids = Vec::new();
    let mut seen = Vec::new();
    for path in ["/a", "/b"] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let s = Seen::default();
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.http.version = HttpVersion::Http2Prior;
        o.callbacks.write = Some(Handler::write(s.clone()).unwrap());
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
        seen.push(s);
        for _ in 0..3 {
            m.perform(&mut NoEvents).unwrap();
        }
    }
    // Both are on it, the second's request sent, its answer held.
    assert_eq!(m.perform(&mut NoEvents).unwrap(), 2);
    assert!(
        String::from_utf8(talk.received())
            .unwrap()
            .contains("H 3 1\n")
    );
    talk.allow(3);
    for &id in &ids {
        assert_eq!(
            drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
            Ok(())
        );
    }
    assert_eq!(
        (seen[0].body(), seen[1].body()),
        (b"aa".to_vec(), b"b1c".to_vec())
    );
    for id in ids {
        m.remove(id, &mut NoEvents).unwrap();
    }
}

/// The most a transfer's progress handler was told it downloaded.
#[derive(Clone, Default)]
struct MostDownloaded(Arc<Mutex<u64>>);

impl crate::handler::ProgressHandler for MostDownloaded {
    fn progress(
        &self,
        _: &mut crate::multi::TransferCx<'_>,
        now: crate::handler::ProgressNow,
    ) -> crate::handler::ProgressVerdict {
        let mut most = self.0.lock().unwrap();
        *most = (*most).max(now.downloaded);
        crate::handler::ProgressVerdict::Continue
    }
}

/// A transfer whose body another's step read is told of it by its
/// progress handler, as each transfer's progress is updated as it runs
/// (`multi_runsingle`'s `Curl_pgrsUpdate`).
#[test]
fn a_body_read_by_a_sibling_is_told_to_its_progress_handler() {
    let most = [MostDownloaded::default(), MostDownloaded::default()];
    let ([(a, _), (b, _)], _) = h2_pair(
        &[&[b"S\nH 1 0\n:status: 200\n\n", WINDOW_SENT, SECOND]],
        |_| {},
        |i, o| {
            o.progress =
                crate::options::Progress::Handler(Handler::progress(most[i].clone()).unwrap());
        },
    );
    assert_eq!((a, b), (Ok(()), Ok(())));
    let seen = |i: usize| *most[i].0.lock().unwrap();
    assert_eq!((seen(0), seen(1)), (2, 3));
}

/// Takes the first piece of the body, and pauses at the next.
#[derive(Clone, Default)]
struct PausesSecond(Arc<Mutex<u32>>);

impl WriteHandler for PausesSecond {
    fn write(&self, _: &mut crate::multi::TransferCx<'_>, _: &[u8]) -> Write {
        let mut n = self.0.lock().unwrap();
        *n += 1;
        if *n == 1 {
            Write::Accepted
        } else {
            Write::Pause
        }
    }
}

/// A transfer that pauses as a sibling's step delivers its body is still
/// told of what it took by its progress handler, as C updates a paused
/// transfer's progress as it runs (`multi_runsingle`).
#[test]
fn a_transfer_paused_by_a_siblings_delivery_is_told_its_progress() {
    let talk = Conversation::replies(
        &[
            b"S\nH 1 0\n:status: 200\n\n",
            WINDOW_SENT,
            b"H 3 0\n:status: 200\n\nD 1 2 0\naaD 1 2 0\nbbD 3 1 1\nc",
        ],
        false,
    )
    .per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let most = MostDownloaded::default();
    let mut ids = Vec::new();
    for path in ["/a", "/b"] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.http.version = HttpVersion::Http2Prior;
        if path == "/a" {
            o.callbacks.write = Some(Handler::write(PausesSecond::default()).unwrap());
            o.progress =
                crate::options::Progress::Handler(Handler::progress(most.clone()).unwrap());
        } else {
            o.callbacks.write = Some(Handler::write(Seen::default()).unwrap());
        }
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
        for _ in 0..3 {
            m.perform(&mut NoEvents).unwrap();
        }
    }
    assert_eq!(
        drive_to_completion(&mut m, ids[1], &mut NoEvents).unwrap(),
        Ok(())
    );
    for _ in 0..3 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(*most.0.lock().unwrap() >= 2, "{}", *most.0.lock().unwrap());
    for id in ids {
        m.remove(id, &mut NoEvents).unwrap();
    }
}

/// A step reads at most a buffer's worth of the connection, as C's
/// `h2_progress_ingress` reads no more than the receive it serves: the
/// rest waits for the transfer's next run, so that a transfer on a
/// shared connection does not take all its siblings' input in its step.
#[test]
fn a_step_reads_a_buffer_of_the_connection_at_most() {
    let mut reply = b"S\nH 1 0\n:status: 200\ncontent-length: 3000\n\n".to_vec();
    for last in [0, 0, 1] {
        reply.extend_from_slice(format!("D 1 1000 {last}\n").as_bytes());
        reply.extend_from_slice(&[b'x'; 1000]);
    }
    let talk = Conversation::replies(&[&reply], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let s = Seen::default();
    let o = e.options_mut();
    let url = format!("http://127.0.0.1:{PORT}/");
    o.set_url(Some(url.as_bytes())).unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.limits.buffer_size = crate::options::BufferSize::clamped(1024);
    o.http.version = HttpVersion::Http2Prior;
    o.callbacks.write = Some(Handler::write(s.clone()).unwrap());
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    // The run that reads the first of the body reads no more than a
    // buffer of the connection.
    let mut first = 0;
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
        first = s.body().len();
        if first > 0 {
            break;
        }
    }
    assert!(first > 0 && first < 1024, "{first} bytes in the first run");
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    assert_eq!(s.body().len(), 3000);
    m.remove(id, &mut NoEvents).unwrap();
}

/// Pauses at the first piece of the body, and takes what comes after.
#[derive(Clone, Default)]
struct PausesFirst(Arc<Mutex<Vec<u8>>>);

impl WriteHandler for PausesFirst {
    fn write(&self, _: &mut crate::multi::TransferCx<'_>, bytes: &[u8]) -> Write {
        let mut got = self.0.lock().unwrap();
        if got.is_empty() {
            got.push(0);
            return Write::Pause;
        }
        got.extend_from_slice(bytes);
        Write::Accepted
    }
}

/// A stream's receive window grows to the most once its head is in, is
/// closed while its transfer's output is paused, so that the server holds
/// back what would only be buffered, and opens again as it is unpaused,
/// the peer told by how much (`cf_h2_update_local_win`,
/// `http2_data_pause`).
#[test]
fn a_paused_streams_window_closes_until_it_is_unpaused() {
    let talk = Conversation::replies(
        &[
            b"S\nH 1 0\n:status: 200\n\nD 1 2 0\naa",
            WINDOW_SENT,
            b"D 1 2 1\nbb",
        ],
        false,
    )
    .per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let w = PausesFirst::default();
    let o = e.options_mut();
    let url = format!("http://127.0.0.1:{PORT}/");
    o.set_url(Some(url.as_bytes())).unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.http.version = HttpVersion::Http2Prior;
    o.callbacks.write = Some(Handler::write(w.clone()).unwrap());
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
    }
    let sent = String::from_utf8(talk.received()).unwrap();
    assert!(sent.ends_with("\n\nU 1 10420224\n"), "{sent}");
    m.pause(id, crate::deliver::PauseRequest::CONT, &mut NoEvents)
        .unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    let sent = String::from_utf8(talk.received()).unwrap();
    assert!(sent.ends_with("\n\nU 1 10420224\nU 1 10485760\n"), "{sent}");
    assert_eq!(&w.0.lock().unwrap()[1..], b"aabb");
    m.remove(id, &mut NoEvents).unwrap();
}

/// Pauses once, at its `n`th write, and takes every other.
#[derive(Clone)]
struct PausesOnceAt(u32, Arc<Mutex<u32>>);

impl WriteHandler for PausesOnceAt {
    fn write(&self, _: &mut crate::multi::TransferCx<'_>, _: &[u8]) -> Write {
        let mut n = self.1.lock().unwrap();
        *n += 1;
        if *n == self.0 {
            Write::Pause
        } else {
            Write::Accepted
        }
    }
}

/// A stream whose window the library fails to set in a sibling's step,
/// as nghttp2 fails out of memory, is reset there with C's code, and its
/// transfer learns so as the reset goes, failing once it next reads; the
/// sibling goes on (`cf_h2_update_local_win`'s failure).
#[test]
fn a_stream_whose_window_cannot_be_set_in_a_siblings_step_fails() {
    let talk = Conversation::replies(
        &[
            b"S\nH 1 0\n:status: 200\n\n",
            WINDOW_SENT,
            b"H 3 0\n:status: 200\n\nXW 1\nD 1 2 0\naaD 1 2 0\nbbD 3 1 1\nc",
        ],
        false,
    )
    .per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut ids = Vec::new();
    let a_seen = Seen::default();
    for path in ["/a", "/b"] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.http.version = HttpVersion::Http2Prior;
        o.output.verbose = true;
        let w = if path == "/a" {
            o.callbacks.debug = Some(Handler::debug(a_seen.clone()).unwrap());
            Handler::write(PausesOnceAt(2, Arc::default())).unwrap()
        } else {
            Handler::write(Seen::default()).unwrap()
        };
        o.callbacks.write = Some(w);
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
        for _ in 0..3 {
            m.perform(&mut NoEvents).unwrap();
        }
    }
    assert_eq!(
        drive_to_completion(&mut m, ids[1], &mut NoEvents).unwrap(),
        Ok(())
    );
    let sent = String::from_utf8(talk.received()).unwrap();
    assert!(sent.contains("R 1 4294966394\n"), "{sent}");
    m.pause(ids[0], crate::deliver::PauseRequest::CONT, &mut NoEvents)
        .unwrap();
    let done = drive_to_completion(&mut m, ids[0], &mut NoEvents).unwrap();
    assert_eq!(done, Err(ErrorKind::Http2Stream), "{:?}", a_seen.text());
    let said = "HTTP/2 stream 1 reset by curl (error 0xfffffc7a unknown)\n";
    assert!(
        a_seen.text().iter().any(|l| l == said),
        "{:?}",
        a_seen.text()
    );
    for id in ids {
        m.remove(id, &mut NoEvents).unwrap();
    }
}

/// A stream paused by a delivery in a sibling's step has its window
/// closed there, nothing told the peer, and reopened as its own transfer
/// runs once unpaused.
#[test]
fn a_stream_paused_in_a_siblings_step_reopens_its_window_in_its_own() {
    let talk = Conversation::replies(
        &[
            b"S\nH 1 0\n:status: 200\n\n",
            WINDOW_SENT,
            // b's own update is not sent: its stream ends in what it reads.
            b"H 3 0\n:status: 200\n\nD 1 2 0\naaD 1 2 0\nbbD 3 1 1\nc",
            b"D 1 1 1\nd",
        ],
        false,
    )
    .per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut ids = Vec::new();
    for path in ["/a", "/b"] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.http.version = HttpVersion::Http2Prior;
        let w = if path == "/a" {
            Handler::write(PausesOnceAt(2, Arc::default())).unwrap()
        } else {
            Handler::write(Seen::default()).unwrap()
        };
        o.callbacks.write = Some(w);
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
        for _ in 0..3 {
            m.perform(&mut NoEvents).unwrap();
        }
    }
    assert_eq!(
        drive_to_completion(&mut m, ids[1], &mut NoEvents).unwrap(),
        Ok(())
    );
    let sent = String::from_utf8(talk.received()).unwrap();
    assert_eq!(sent.matches("U 1 ").count(), 1, "{sent}");
    m.pause(ids[0], crate::deliver::PauseRequest::CONT, &mut NoEvents)
        .unwrap();
    let done = drive_to_completion(&mut m, ids[0], &mut NoEvents).unwrap();
    let sent = String::from_utf8(talk.received()).unwrap();
    assert_eq!(done, Ok(()), "{sent}");
    assert!(sent.ends_with("U 1 10485760\n"), "{sent}");
    for id in ids {
        m.remove(id, &mut NoEvents).unwrap();
    }
}

/// What a test's application does with a push.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    Take,
    Deny,
    Fail,
}

/// A push offered: its fields, and the URL its handle was given.
type Offer = (Vec<Vec<u8>>, Option<Vec<u8>>);

/// Each transfer's result, by id.
type Results = Vec<(TransferId, Result<(), ErrorKind>)>;

/// An application that takes pushes, or not, keeping what it was offered
/// and writing what it takes to `seen`.
struct Pushes {
    answer: Answer,
    offers: Vec<Offer>,
    seen: Seen,
}

impl Pushes {
    fn answering(answer: Answer) -> Pushes {
        Pushes {
            answer,
            offers: Vec::new(),
            seen: Seen::default(),
        }
    }
}

impl crate::multi::MultiEvents<crate::multi::NoHost> for Pushes {
    fn wants_push(&self) -> bool {
        true
    }

    fn push(
        &mut self,
        cx: &mut crate::multi::EventCx<'_, crate::multi::NoHost>,
        offer: &crate::multi::PushOffer<'_>,
        mut easy: Box<Easy>,
    ) -> crate::multi::Pushed<crate::multi::NoHost> {
        // The parent is reached through the context.
        assert!(cx.info(offer.parent).is_some_and(|r| r.url().is_some()));
        let fields = (0..offer.fields.len())
            .map(|n| offer.fields.get(n).unwrap().to_vec())
            .collect();
        self.offers
            .push((fields, easy.report().url().map(<[u8]>::to_vec)));
        match self.answer {
            Answer::Take => {
                easy.options_mut().callbacks.write =
                    Some(Handler::write(self.seen.clone()).unwrap());
                crate::multi::Pushed::Accepted { easy, owner: () }
            }
            Answer::Deny => crate::multi::Pushed::Denied,
            Answer::Fail => crate::multi::Pushed::Failed,
        }
    }
}

/// A response with a promise of `/pushed` on stream 2, at `authority`
/// over `scheme`, the pushed response's body `abc`, then the request's.
fn promising(scheme: &str, authority: &str) -> Vec<u8> {
    format!(
        "S\nH 1 0\n:status: 200\n\nPP 1 2\n:method: GET\n:scheme: {scheme}\n\
         :authority: {authority}\n:path: /pushed\n\nH 2 0\n:status: 200\n\n\
         D 2 3 1\nabcD 1 2 1\nok"
    )
    .into_bytes()
}

/// Run a GET whose response promises `reply`'s push, the application
/// answering it with `ev`: each transfer's result, by id, and what went
/// on the wire.
fn pushed_get(
    reply: &[u8],
    ev: &mut dyn crate::multi::MultiEvents<crate::multi::NoHost>,
) -> (Results, String) {
    pushed_get_with(reply, ev, |_| {})
}

/// As `pushed_get`, the request's handle given to `setup` first.
fn pushed_get_with(
    reply: &[u8],
    ev: &mut dyn crate::multi::MultiEvents<crate::multi::NoHost>,
    setup: impl FnOnce(&mut Easy),
) -> (Results, String) {
    let talk = Conversation::replies(&[reply, WINDOW_SENT], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    setup(&mut e);
    let o = e.options_mut();
    let url = format!("http://127.0.0.1:{PORT}/");
    o.set_url(Some(url.as_bytes())).unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.http.version = HttpVersion::Http2Prior;
    o.callbacks.write = Some(Handler::write(Seen::default()).unwrap());
    let id = m.add(Box::new(e), (), ev).unwrap();
    let mut done = Vec::new();
    for _ in 0..20 {
        m.perform(ev).unwrap();
        while let Some(msg) = m.info_read() {
            done.push((msg.id, msg.result));
        }
    }
    let mut ids: Vec<TransferId> =
        std::iter::successors(m.next_transfer(None), |&t| m.next_transfer(Some(t))).collect();
    ids.retain(|&t| t != id);
    done.sort_by_key(|&(t, _)| t != id);
    for t in std::iter::once(id).chain(ids) {
        m.remove(t, ev).unwrap();
    }
    (done, String::from_utf8(talk.received()).unwrap())
}

/// A response the server promises is offered to the application with the
/// promise's fields and its URL set, and once taken is a transfer of the
/// multi's, on the same connection, its response written where the
/// application said; the client says it takes pushes
/// (`SETTINGS_ENABLE_PUSH`).
#[test]
fn a_pushed_response_becomes_a_transfer_of_its_own() {
    let mut ev = Pushes::answering(Answer::Take);
    let reply = promising("http", &format!("127.0.0.1:{PORT}"));
    let (done, sent) = pushed_get(&reply, &mut ev);
    assert_eq!(done.len(), 2, "{done:?}\n{sent}");
    assert!(done.iter().all(|(_, r)| r.is_ok()), "{done:?}\n{sent}");
    assert!(sent.starts_with("S MCS=100;IWS=65536;EP=1;\n"), "{sent}");
    assert!(!sent.contains("R 2 "), "{sent}");
    let fields: Vec<&[u8]> = ev.offers[0].0.iter().map(Vec::as_slice).collect();
    assert_eq!(
        fields,
        [
            &b":method:GET"[..],
            b":scheme:http",
            format!(":authority:127.0.0.1:{PORT}").as_bytes(),
            b":path:/pushed",
        ]
    );
    let url = format!("http://127.0.0.1:{PORT}/pushed");
    assert_eq!(ev.offers[0].1.as_deref(), Some(url.as_bytes()));
    assert_eq!(ev.seen.body(), b"abc");
}

/// A push on a share's connection (`CURL_LOCK_DATA_CONNECT`) is taken as
/// on the multi's own: the pushed transfer, linked to the parent's share
/// (`h2_duphandle`), runs on the connection lent to the multi. The promise
/// comes in the parent's first read, before its step lends the connection;
/// the connection goes back to the share's pool, idle, with the pushed
/// transfer, the last on it, whose options do not forbid its reuse. The
/// pushed handle's cookies stay off though the parent's and the share's
/// are on, as C's (`cookie_engine` is not copied): its response's cookie
/// is not stored.
#[test]
fn a_push_on_a_share_s_connection_is_taken() {
    use crate::share::{Kind, Share};
    let share = Share::new().unwrap();
    share.keep(Kind::Connections).unwrap();
    share.keep(Kind::Cookies).unwrap();
    let mut ev = Pushes::answering(Answer::Take);
    let reply = format!(
        "S\nH 1 0\n:status: 200\n\nPP 1 2\n:method: GET\n:scheme: http\n\
         :authority: 127.0.0.1:{PORT}\n:path: /pushed\n\nH 2 0\n:status: 200\n\
         set-cookie: pushed=1\n\nD 2 3 1\nabcD 1 2 1\nok"
    );
    let (done, sent) = pushed_get_with(reply.as_bytes(), &mut ev, |e| {
        e.options_mut().limits.reuse.forbid = true;
        e.set_share(Some(share.clone()));
        e.enable_cookies().unwrap();
    });
    assert_eq!(done.len(), 2, "{done:?}\n{sent}");
    assert!(done.iter().all(|(_, r)| r.is_ok()), "{done:?}\n{sent}");
    assert!(!sent.contains("R 2 "), "{sent}");
    assert_eq!(ev.seen.body(), b"abc");
    let stored = share.cookies().as_ref().unwrap().len();
    assert_eq!(stored, 0, "the pushed transfer's cookies are off");
    let (leased, kept) = {
        let pool = share.pool();
        (pool.leased(), pool.len())
    };
    assert_eq!((leased, kept), (0, 1), "given back to the share, idle");
}

/// A push the application refuses is cancelled, and the request goes on.
#[test]
fn a_refused_push_cancels_its_stream() {
    let mut ev = Pushes::answering(Answer::Deny);
    let reply = promising("http", &format!("127.0.0.1:{PORT}"));
    let (done, sent) = pushed_get(&reply, &mut ev);
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(done[0].1, Ok(()), "{sent}");
    assert!(sent.contains("R 2 8\n"), "{sent}");
    assert_eq!(ev.offers.len(), 1);
}

/// A push the application fails fails its parent (`CURL_PUSH_ERROROUT`).
#[test]
fn a_failed_push_fails_its_parent() {
    let mut ev = Pushes::answering(Answer::Fail);
    let reply = promising("http", &format!("127.0.0.1:{PORT}"));
    let (done, sent) = pushed_get(&reply, &mut ev);
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(done[0].1, Err(ErrorKind::RecvError), "{sent}");
}

/// Without an application that takes pushes, the client says so, and a
/// push the server sends anyway is cancelled.
#[test]
fn without_a_push_handler_a_push_is_cancelled() {
    let reply = promising("http", &format!("127.0.0.1:{PORT}"));
    let (done, sent) = pushed_get(&reply, &mut NoEvents);
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(done[0].1, Ok(()), "{sent}");
    assert!(sent.starts_with("S MCS=100;IWS=65536;EP=0;\n"), "{sent}");
    assert!(sent.contains("R 2 8\n"), "{sent}");
}

/// A promise naming another authority than the request's resets the
/// request's stream and fails the read (RFC 9113 §8.4), unoffered.
#[test]
fn a_promise_for_another_authority_fails_the_read() {
    let mut ev = Pushes::answering(Answer::Take);
    let reply = promising("http", "elsewhere.example");
    let (done, sent) = pushed_get(&reply, &mut ev);
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(done[0].1, Err(ErrorKind::RecvError), "{sent}");
    assert!(sent.contains("R 1 1\n"), "{sent}");
    assert!(ev.offers.is_empty());
}

/// A promise of another origin than the request's, here by its scheme,
/// is refused unoffered (`set_transfer_url`).
#[test]
fn a_promise_of_another_origin_is_refused_unoffered() {
    let mut ev = Pushes::answering(Answer::Take);
    let reply = promising("https", &format!("127.0.0.1:{PORT}"));
    let (done, sent) = pushed_get(&reply, &mut ev);
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(done[0].1, Ok(()), "{sent}");
    assert!(sent.contains("R 2 8\n"), "{sent}");
    assert!(ev.offers.is_empty());
}

/// A connection whose server went away after the response is not kept:
/// it takes no more transfers, which C asks as it gives the connection
/// back (`multi_done_locked`'s `Curl_conn_get_max_concurrent`), nothing
/// else having marked it to close.
#[test]
fn a_connection_gone_away_is_not_kept() {
    let talk =
        Conversation::replies(&[b"S\nH 1 0\n:status: 200\n\nD 1 2 1\nokG 1 0\n"], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let c = crate::components::Components::new().unwrap();
    c.configure(b"all");
    e.set_components(Some(c));
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.http.version = HttpVersion::Http2Prior;
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok");
    let text = ran.seen.text();
    let from = text
        .iter()
        .position(|l| l.contains("multi_done_locked"))
        .expect("given back");
    let said: Vec<_> = text[from..from + 3]
        .iter()
        .map(|l| l.trim_end().split_once("] ").map_or(l.as_str(), |(_, r)| r))
        .collect();
    assert_eq!(
        said,
        [
            "[MULTI] [DONE] multi_done_locked, in use=0",
            &format!(
                "[MULTI] [DONE] multi_done, conn #0 to 127.0.0.1:{PORT} was shutdown by server, not reusing"
            ),
            "shutting down connection #0",
        ]
    );
}

/// A connection whose server is going away takes no more transfers than
/// it has (`cf_h2_query`): a second transfer looking for one while the
/// first's stream is still open on it finds it full and makes its own.
#[test]
fn a_connection_going_away_takes_no_one_new() {
    let first = Conversation::replies(
        &[b"S\nG 1 0\n", b"H 1 0\n:status: 200\n\nD 1 2 1\naa"],
        false,
    )
    .per_send()
    .held();
    let second =
        Conversation::replies(&[b"S\nH 1 0\n:status: 201\n\nD 1 1 1\nb"], false).per_send();
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let mut ids = Vec::new();
    let mut seen = Vec::new();
    for path in ["/a", "/b"] {
        let mut e = Easy::new();
        e.set_libraries(with_h2());
        let s = Seen::default();
        let o = e.options_mut();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.output.verbose = true;
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.http.version = HttpVersion::Http2Prior;
        o.callbacks.write = Some(Handler::write(s.clone()).unwrap());
        o.callbacks.debug = Some(Handler::debug(s.clone()).unwrap());
        seen.push(s);
        if path == "/b" {
            // The first heard its server is going away, its stream open.
            first.allow(1);
            for _ in 0..3 {
                m.perform(&mut NoEvents).unwrap();
            }
            assert!(
                seen[0]
                    .text()
                    .iter()
                    .any(|l| l.starts_with("received GOAWAY")),
                "{:?}",
                seen[0].text()
            );
        }
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
    }
    let b = drive_to_completion(&mut m, ids[1], &mut NoEvents).unwrap();
    first.allow(2);
    let a = drive_to_completion(&mut m, ids[0], &mut NoEvents).unwrap();
    for id in ids {
        m.remove(id, &mut NoEvents).unwrap();
    }
    assert_eq!((a, b), (Ok(()), Ok(())), "{:#?}", seen[1].text());
    assert_eq!(seen[0].body(), b"aa");
    assert_eq!(seen[1].body(), b"b");
    let text = seen[1].text();
    assert!(
        text.iter()
            .any(|l| l == "connection #0reached MAX_CONCURRENT_STREAMS(1), skip\n"),
        "{text:?}"
    );
}

/// An alternative service for the origin itself in HTTP/1.1 has a
/// transfer at the default version try HTTP/1.1 first, as the version
/// preferred, offering it alone though a library speaks HTTP/2
/// (`cf_hc_set_baller1` taking HTTP/2 from the wanted versions); no
/// second attempt follows, HTTP/2 offering HTTP/1.1 itself.
#[test]
fn an_alternative_here_in_http1_offers_http1_alone() {
    use crate::libraries::Library;
    use crate::tls::Alpn;
    use crate::tls::fake::{self, FakeTls, WELCOME};
    static FAKE: FakeH2 = FakeH2;
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        h2: Some(&FAKE as &dyn crate::http2::Http2),
        ..Libraries::NONE
    })
    .unwrap();
    let file = std::env::temp_dir().join(format!("curl-core-alt-here-h1-{}", std::process::id()));
    let entry =
        format!("h2 127.0.0.1 {PORT} http/1.1 127.0.0.1 {PORT} \"20991231 00:00:00\" 0 0\n");
    std::fs::write(&file, entry).unwrap();
    let response = fake::records(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").unwrap();
    let talk = Conversation::replies(&[WELCOME, &response], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    e.add_alt_svc_file(Some(file.as_os_str().as_encoded_bytes()))
        .unwrap();
    std::fs::remove_file(&file).unwrap();
    let components = crate::components::Components::new().unwrap();
    components.configure(b"https-connect");
    e.set_components(Some(components));
    let url = format!("https://127.0.0.1:{PORT}/");
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.output.verbose = true;
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"hello");
    assert_eq!(backend.log().alpn, Some(Alpn::Http11));
    let text = ran.seen.text();
    let said = |s: &str| text.iter().any(|l| l.contains(s));
    assert!(
        said("1st attempt uses h1 from preferred version"),
        "{text:#?}"
    );
    assert!(!said("2nd attempt"), "{text:#?}");
}
