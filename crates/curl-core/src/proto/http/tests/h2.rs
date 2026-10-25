//! Requests over HTTP/2, with the fake library and prior knowledge: the
//! head turned into the stream's fields, the response's fields handed on
//! as HTTP/1 lines, the body as it comes, and the stream's end.

use super::*;
use crate::http2::fake::FakeH2;
use crate::libraries::{Libraries, SharedLibraries};
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
            "S\nH 1 1\n:method: GET\n:scheme: http\n:authority: 127.0.0.1:{PORT}\n\
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

/// Over TLS with an HTTP/2 library, ALPN offers `h2` first, which the
/// fake's peer takes, and the connection speaks HTTP/2; `h2` alone by
/// prior knowledge. Without one, or with HTTP/1 asked for, HTTP/1 is
/// offered, which it takes (`alpn_get_spec`).
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
        let url = format!("https://127.0.0.1:{PORT}/");
        let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
            o.http.version = version;
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
/// the next transfer reuses it (`http2_connisalive`).
#[test]
fn an_idle_connection_s_frames_are_read_and_it_is_reused() {
    let mut first = RESPONSE.to_vec();
    for _ in 0..600 {
        first.extend_from_slice(b"P\n");
    }
    let second: &[u8] = b"H 3 0\n:status: 200\n\nD 3 2 1\nok";
    let talk = Conversation::replies(&[&first, second], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
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
    }
}
