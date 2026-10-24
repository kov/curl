//! HTTP Negotiate with the origin over a scripted GSS-API library: the
//! token sent at once or after a 401 asks, the challenges taken as the
//! head is read, what the connection remembers, and which transfers it
//! then serves (`lib/http_negotiate.c`, `lib/http.c`, `lib/url.c`).

use super::*;
use crate::gss::testing::{Answer, Asked, Scripted};
use crate::gss::{Flags, GssCall, GssFailure, GssStatus, Mech, Progress};
use crate::libraries::Libraries;
use crate::options::{Delegation, HttpAuth};

/// A scripted library, and the libraries naming it, kept to the test's
/// end as a handle's are.
fn scripted() -> (&'static Scripted, &'static Libraries) {
    let gss = Scripted::leaked();
    let libraries = Box::leak(Box::new(Libraries {
        gss: Some(gss),
        ..Libraries::NONE
    }));
    (gss, libraries)
}

/// `bytes` in base64.
fn b64(bytes: &[u8]) -> String {
    let mut out = Vec::new();
    crate::proto::http1::auth::base64(bytes.iter().copied(), bytes.len(), &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// A GET of `path` asking `Authorization: Negotiate <token>`.
fn negotiated_get(path: &str, token: &[u8]) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nAuthorization: Negotiate {}\r\n\
         User-Agent: curl/test\r\nAccept: */*\r\n\r\n",
        b64(token)
    )
}

fn plain_get(path: &str) -> String {
    String::from_utf8(request_of(path)).unwrap()
}

/// A handle with the scripted library, negotiating with the origin.
fn negotiating(libraries: &'static Libraries) -> Easy {
    let mut e = Easy::new();
    e.set_libraries(libraries);
    e.options_mut().http.auth = HttpAuth(AuthMethods::NEGOTIATE);
    e
}

/// The context the requests to the test's server make.
fn context() -> Asked {
    Asked::Context {
        service: b"HTTP".to_vec(),
        host: b"127.0.0.1".to_vec(),
        mech: Mech::Spnego,
        flags: Flags {
            mutual: true,
            ..Flags::default()
        },
    }
}

const OK_200: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";

fn text_has(ran: &Ran, line: &str) -> bool {
    ran.seen.text().iter().any(|l| l == line)
}

/// Asked only for Negotiate, a request sends its first token at once,
/// with no credentials, said as C says it (tests 2056 and 2094); the
/// context is with `HTTP@host`, mutual, and the response that follows
/// leaves the connection authenticated.
#[test]
fn the_first_token_goes_at_once() {
    let (gss, libraries) = scripted();
    gss.then_token(b"first");
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_get("/", b"first")
    );
    assert!(text_has(&ran, "Server auth using Negotiate with user ''\n"));
    assert_eq!(gss.asked(), [context(), Asked::Step(None)]);
    assert_eq!(ran.easy.report().auth_used(), AuthMethods::NEGOTIATE);
}

/// The service and delegation the options name are the context's: the
/// service from the credentials, which have it only for the origin the
/// options go to (`Curl_creds_has_sasl_service`).
#[test]
fn the_context_takes_the_service_and_the_delegation() {
    let (gss, libraries) = scripted();
    gss.then_token(b"t");
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |o| {
        o.login.make_mut().unwrap().service = Some(b"web".to_vec());
        o.login.make_mut().unwrap().delegation = Delegation {
            by_policy: true,
            always: false,
        };
    });
    assert_eq!(ran.result, Ok(()));
    let Asked::Context { service, flags, .. } = &gss.asked()[0] else {
        panic!("a context first");
    };
    assert_eq!(service, b"web");
    assert!(flags.mutual && flags.delegate_by_policy && !flags.delegate);
}

/// A library that cannot make the first token leaves the request to go
/// unauthenticated, said before the method is (tests 2077, 2078, 2057);
/// one failing otherwise fails the request.
#[test]
fn a_first_token_not_made_goes_without() {
    let (gss, libraries) = scripted();
    gss.then(Answer::Fails(GssFailure::status(
        GssCall::AcquireCred,
        GssStatus::new(7 << 16, 3),
    )));
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        plain_get("/")
    );
    let text = ran.seen.text();
    let failed = text
        .iter()
        .position(|l| l == "gss_acquire_cred() failed: status 458752.3. \n")
        .expect("said");
    assert_eq!(
        text[failed + 1],
        "Server auth using Negotiate with user ''\n"
    );
    // Its context dropped with the failure.
    assert_eq!(gss.asked(), [context(), Asked::Step(None), Asked::Dropped]);
    // No token at all, the same.
    let (gss, libraries) = scripted();
    gss.then(Answer::Fails(GssFailure {
        call: GssCall::InitSecContext,
        kind: crate::gss::GssFailureKind::EmptyToken,
    }));
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        plain_get("/")
    );
    assert!(!ran.seen.text().iter().any(|l| l.contains("failed")));
    // Out of memory fails it.
    let (gss, libraries) = scripted();
    gss.then(Answer::Fails(GssFailure::out_of_memory(
        GssCall::InitSecContext,
    )));
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::OutOfMemory));
}

/// A request that takes any method, with credentials, empty ones too,
/// picks Negotiate first of what a 401 offers and makes the request
/// again with its token; the 200's `Persistent-Auth` is read as C reads
/// it.
#[test]
fn a_401_offering_negotiate_has_it_picked() {
    let (gss, libraries) = scripted();
    gss.then_token(b"tok");
    let unauthorized = b"HTTP/1.1 401 Who\r\nWWW-Authenticate: Basic\r\n\
        WWW-Authenticate: Negotiate\r\nContent-Length: 4\r\n\r\nno!\n";
    let ok = b"HTTP/1.1 200 OK\r\nPersistent-Auth: true\r\nContent-Length: 3\r\n\r\nok\n";
    let (mut m, talk, _) = server(&[unauthorized, ok], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| {
        o.http.auth = HttpAuth(AuthMethods::ANY);
        o.login.make_mut().unwrap().user = Some(Vec::new());
        o.login.make_mut().unwrap().password = Some(Vec::new());
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        plain_get("/") + &negotiated_get("/", b"tok")
    );
    let text = ran.seen.text();
    assert!(text_has(
        &ran,
        "Negotiate: noauthpersist -> 0, header part: true\n"
    ));
    // Said as its line is handled, before it is traced.
    let said = text
        .iter()
        .position(|l| l.starts_with("Negotiate: noauthpersist"))
        .unwrap();
    assert!(
        text[..said]
            .iter()
            .any(|l| l.starts_with("Server auth using Negotiate"))
    );
    let report = ran.easy.report();
    assert_eq!(
        report.auth_offered(),
        AuthMethods::BASIC | AuthMethods::NEGOTIATE
    );
    assert_eq!(report.auth_used(), AuthMethods::NEGOTIATE);
    // Without credentials, nothing is picked (`Curl_http_auth_act`).
    let (_, libraries) = scripted();
    let (mut m, talk, _) = server(&[unauthorized], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| {
        o.http.auth = HttpAuth(AuthMethods::ANY);
    });
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        plain_get("/")
    );
}

/// The 401's challenge is taken into the context as its line is read,
/// decoded; the request goes again with what the context made of it,
/// with no method to pick and no credentials (`auth_spnego`'s `newurl`).
#[test]
fn a_challenge_is_taken_and_answered() {
    let (gss, libraries) = scripted();
    gss.then_token(b"first").then_token(b"second");
    let unauthorized = format!(
        "HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate {}\r\nContent-Length: 4\r\n\r\nno!\n",
        b64(b"challenge")
    );
    let (mut m, talk, _) = server(&[unauthorized.as_bytes(), OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_get("/", b"first") + &negotiated_get("/", b"second")
    );
    assert_eq!(
        gss.asked(),
        [
            context(),
            Asked::Step(None),
            Asked::Step(Some(b"challenge".to_vec()))
        ]
    );
    assert!(text_has(
        &ran,
        &format!("Issue another request to this URL: 'http://127.0.0.1:{PORT}/'\n")
    ));
}

/// A challenge the context fails on is said as its line is handled,
/// before the line is traced, and leaves the 401 the response; failing
/// on errors, it fails the transfer.
#[test]
fn a_challenge_refused_ends_with_the_401() {
    let unauthorized = format!(
        "HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate {}\r\nContent-Length: 4\r\n\r\nno!\n",
        b64(b"C")
    );
    for fail in [false, true] {
        let (gss, libraries) = scripted();
        gss.then_token(b"first")
            .then(Answer::Fails(GssFailure::status(
                GssCall::InitSecContext,
                GssStatus::new(13 << 16, 0),
            )));
        let (mut m, talk, _) = server(&[unauthorized.as_bytes()], false);
        let ran = get_with(&mut m, negotiating(libraries), "/", talk, |o| {
            o.http.fail_on_error = fail;
        });
        let want = if fail {
            Err(ErrorKind::HttpReturnedError)
        } else {
            Ok(())
        };
        assert_eq!(ran.result, want);
        assert_eq!(
            String::from_utf8(ran.request.clone()).unwrap(),
            negotiated_get("/", b"first")
        );
        let lines: Vec<Vec<u8>> = ran
            .seen
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(w, _)| *w == "text" || *w == "in")
            .map(|(_, b)| b.clone())
            .collect();
        let said = lines
            .iter()
            .position(|l| l == b"gss_init_sec_context() failed: status 851968.0. \n")
            .expect("said");
        assert!(
            lines[said - 1].starts_with(b"HTTP/1.1 401"),
            "after the status line"
        );
        assert!(
            lines[said + 1].starts_with(b"WWW-Authenticate"),
            "before its line"
        );
        assert_eq!(gss.asked().last(), Some(&Asked::Dropped), "started over");
    }
}

/// A challenge that is not base64, or decodes to nothing, is refused as
/// C refuses it, the latter said.
#[test]
fn a_challenge_not_decoded_is_refused() {
    for (challenge, said) in [("!!!!", false), ("=", true)] {
        let (gss, libraries) = scripted();
        gss.then_token(b"first");
        let unauthorized = format!(
            "HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate {challenge}\r\nContent-Length: 0\r\n\r\n"
        );
        let (mut m, talk, _) = server(&[unauthorized.as_bytes()], false);
        let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
        assert_eq!(ran.result, Ok(()));
        assert_eq!(
            String::from_utf8(ran.request.clone()).unwrap(),
            negotiated_get("/", b"first")
        );
        assert_eq!(
            text_has(&ran, "SPNEGO handshake failure (empty challenge message)\n"),
            said,
            "{challenge}"
        );
        assert_eq!(gss.unused(), 0);
    }
}

/// A 401 with an empty `Negotiate` after a token went refuses it: the
/// request is not made again (`CURLE_LOGIN_DENIED`, an auth problem).
#[test]
fn an_empty_challenge_after_a_token_is_a_refusal() {
    let (gss, libraries) = scripted();
    gss.then_token(b"first");
    let unauthorized =
        b"HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[unauthorized], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_get("/", b"first")
    );
    assert_eq!(gss.asked(), [context(), Asked::Step(None), Asked::Dropped]);
}

/// A context complete on our side, asked again, is refused without a
/// step (`Curl_auth_decode_spnego_message`).
#[test]
fn a_complete_context_asked_again_is_refused() {
    let (gss, libraries) = scripted();
    gss.then(Answer::Token(Progress::Complete, b"all".to_vec()));
    let unauthorized = format!(
        "HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate {}\r\nContent-Length: 0\r\n\r\n",
        b64(b"more")
    );
    let (mut m, talk, _) = server(&[unauthorized.as_bytes()], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(gss.asked(), [context(), Asked::Step(None), Asked::Dropped]);
}

/// Two requests over one connection: after a 200, the next makes a new
/// context and token unless the server said it persists, the old one
/// cleaned up as C says it (`noauthpersist`).
#[test]
fn the_next_request_authenticates_again_unless_it_persists() {
    for persists in [false, true] {
        let (gss, libraries) = scripted();
        gss.then_token(b"one").then_token(b"two");
        let first = if persists {
            &b"HTTP/1.1 200 OK\r\nPersistent-Auth: true\r\nContent-Length: 3\r\n\r\nok\n"[..]
        } else {
            OK_200
        };
        let talk = Conversation::replies(&[first, OK_200], false);
        let mut m = serving(Peer::Accepts, &[&talk]);
        let ran = get_with(&mut m, negotiating(libraries), "/a", talk.clone(), |_| {});
        assert_eq!(ran.result, Ok(()));
        let ran = get_with(&mut m, negotiating(libraries), "/b", talk.clone(), |_| {});
        assert_eq!(ran.result, Ok(()));
        let sent = String::from_utf8(talk.received()).unwrap();
        let cleaned =
            "Curl_output_negotiate, no persistent authentication: cleanup existing context\n";
        if persists {
            assert_eq!(sent, negotiated_get("/a", b"one") + &plain_get("/b"));
            assert!(!text_has(&ran, cleaned));
            assert_eq!(gss.unused(), 1);
        } else {
            assert_eq!(
                sent,
                negotiated_get("/a", b"one") + &negotiated_get("/b", b"two")
            );
            assert!(text_has(&ran, cleaned));
            assert_eq!(
                gss.asked(),
                [
                    context(),
                    Asked::Step(None),
                    Asked::Dropped,
                    context(),
                    Asked::Step(None)
                ]
            );
        }
        // Either way the method is said in use.
        assert!(text_has(&ran, "Server auth using Negotiate with user ''\n"));
    }
}

/// A connection Negotiate authenticated serves only a transfer
/// negotiating with the same credentials and origin; one delegating
/// otherwise is not served by any (`url_match_auth`,
/// `url_match_auth_nego`).
#[test]
fn a_negotiated_connection_serves_only_its_own() {
    let reused = "Reusing existing http: connection with host 127.0.0.1\n";
    type Case = (&'static str, fn(&mut Options), bool);
    let cases: [Case; 6] = [
        (
            "same credentials",
            |o| o.login.make_mut().unwrap().user = Some(b"u".to_vec()),
            true,
        ),
        (
            "other credentials",
            |o| o.login.make_mut().unwrap().user = Some(b"v".to_vec()),
            false,
        ),
        ("none", |_| {}, false),
        (
            "not negotiating",
            |o| {
                o.login.make_mut().unwrap().user = Some(b"u".to_vec());
                o.http.auth = HttpAuth(AuthMethods::BASIC);
            },
            false,
        ),
        (
            "other credentials, not negotiating",
            |o| {
                o.login.make_mut().unwrap().user = Some(b"v".to_vec());
                o.http.auth = HttpAuth(AuthMethods::BASIC);
            },
            false,
        ),
        (
            "delegating",
            |o| {
                o.login.make_mut().unwrap().user = Some(b"u".to_vec());
                o.login.make_mut().unwrap().delegation.always = true;
            },
            false,
        ),
    ];
    for (what, set, serves) in cases {
        let (gss, libraries) = scripted();
        gss.then_token(b"one")
            .then_token(b"two")
            .then_token(b"three");
        let first = Conversation::replies(&[OK_200, OK_200], false);
        let second = Conversation::replies(&[OK_200], false);
        let mut m = serving(Peer::Accepts, &[&first, &second]);
        let ran = get_with(&mut m, negotiating(libraries), "/a", first.clone(), |o| {
            o.login.make_mut().unwrap().user = Some(b"u".to_vec());
        });
        assert_eq!(ran.result, Ok(()), "{what}");
        let ran = get_with(&mut m, negotiating(libraries), "/b", first.clone(), set);
        assert_eq!(ran.result, Ok(()), "{what}");
        assert_eq!(
            text_has(&ran, reused),
            serves,
            "{what}: {:?}",
            ran.seen.text()
        );
        assert_eq!(second.received().is_empty(), serves, "{what}");
    }
    // One never negotiated serves a transfer that negotiates.
    let (gss, libraries) = scripted();
    gss.then_token(b"one");
    let talk = Conversation::replies(&[OK_200, OK_200], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/a", talk.clone(), |_| {});
    assert_eq!(ran.result, Ok(()));
    let ran = get_with(&mut m, negotiating(libraries), "/b", talk.clone(), |_| {});
    assert!(text_has(&ran, reused));
}

/// The application's own `Authorization` keeps Negotiate's out, the
/// challenge still taken, and the request made again; the second 401's
/// empty challenge then refuses it (C's capture with `-H
/// Authorization:x`). A connection that closes while a challenge is
/// taken is said to cut the handshake short; one forbidden its reuse is
/// kept for the request that goes again.
#[test]
fn a_challenge_taken_holds_the_connection() {
    let unauthorized =
        b"HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 4\r\n\r\nno!\n";
    let custom = |o: &mut Options| {
        o.http.headers = crate::options::UserHeaders::new([&b"Authorization: x"[..]]).unwrap();
    };
    for forbid in [false, true] {
        let (gss, libraries) = scripted();
        gss.then_token(b"one");
        let talk = Conversation::replies(&[unauthorized, unauthorized], false);
        let mut m = serving(Peer::Accepts, &[&talk]);
        let ran = get_with(&mut m, negotiating(libraries), "/", talk.clone(), |o| {
            custom(o);
            o.limits.reuse.forbid = forbid;
        });
        assert_eq!(ran.result, Ok(()), "{forbid}");
        let one = format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUser-Agent: curl/test\r\n\
             Accept: */*\r\nAuthorization: x\r\n\r\n"
        );
        assert_eq!(
            String::from_utf8(talk.received()).unwrap(),
            one.repeat(2),
            "{forbid}"
        );
        assert!(text_has(
            &ran,
            "Reusing existing http: connection with host 127.0.0.1\n"
        ));
        assert!(!ran.seen.text().iter().any(|l| l.starts_with("Server auth")));
        assert_eq!(gss.asked(), [context(), Asked::Step(None), Asked::Dropped]);
    }
    // Closing: said, an auth problem, and made again all the same.
    let (gss, libraries) = scripted();
    gss.then_token(b"one").then_token(b"two");
    let closing =
        b"HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    let first = Conversation::replies(&[closing], true);
    let second = Conversation::replies(&[OK_200], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let ran = get_with(&mut m, negotiating(libraries), "/", first.clone(), custom);
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text();
    let said = text
        .iter()
        .position(|l| l == "Connection closure while negotiating auth (HTTP 1.0?)\n")
        .expect("said");
    assert!(
        text[said..]
            .iter()
            .any(|l| l.starts_with("Issue another request"))
    );
    assert!(!second.received().is_empty());
}

/// A body still going as a 401 picks Negotiate closes the connection
/// rather than send the rest, said as C says it, unless Negotiate
/// started on the connection, whose handshake goes on over it
/// (`http_perhapsrewind`).
#[test]
fn a_body_still_going_closes_unless_negotiate_started() {
    const SIZE: usize = 300_000;
    let challenge = format!(
        "HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate {}\r\nContent-Length: 0\r\n\r\n",
        b64(b"more")
    );
    let empty = "HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n";
    for started in [false, true] {
        let (gss, libraries) = scripted();
        gss.then_token(b"one").then_token(b"two");
        let unauthorized = if started { &challenge[..] } else { empty };
        let first = Conversation::replies(&[unauthorized.as_bytes(), OK], false);
        let second = Conversation::replies(&[OK], false);
        let mut m = serving(Peer::Accepts, &[&first, &second]);
        let stream = Stream::new(big_body(SIZE));
        let mut e = Easy::new();
        e.set_libraries(libraries);
        let ran = get_with(&mut m, e, "/a", first.clone(), |o| {
            o.method = Method::Upload;
            o.upload = stream.source(true);
            o.login.make_mut().unwrap().user = Some(b"u".to_vec());
            // Negotiate at once only where it is to have started.
            o.http.auth = HttpAuth(if started {
                AuthMethods::NEGOTIATE
            } else {
                AuthMethods::ANY
            });
        });
        assert_eq!(ran.result, Ok(()), "{started}");
        let text = ran.seen.text();
        let closed = text
            .iter()
            .any(|l| l.starts_with("NEGOTIATE send, close instead of sending "));
        assert_eq!(closed, !started, "{started}: {text:?}");
        assert_eq!(second.received().is_empty(), started, "{started}");
        assert_eq!(stream.rewinds.get(), 1, "{started}");
    }
}

/// What the library says on the way is traced as C traces it: a name it
/// cannot import, mechanisms it cannot narrow, NTLM chosen anyway.
#[test]
fn the_library_s_failures_are_said_as_c_says_them() {
    let (gss, libraries) = scripted();
    gss.import_fails(GssStatus::new(2 << 16, 5));
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(text_has(
        &ran,
        "gss_import_name() failed: status 131072.5. \n"
    ));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        plain_get("/")
    );
    let (gss, libraries) = scripted();
    gss.then(Answer::Notes(crate::gss::GssNote::SetNegMechs(
        GssStatus::new(1 << 16, 2),
    )))
    .then_token(b"t");
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
    assert!(text_has(
        &ran,
        "gss_set_neg_mechs() failed: status 65536.2. \n"
    ));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_get("/", b"t")
    );
    let (gss, libraries) = scripted();
    gss.then(Answer::Fails(GssFailure {
        call: GssCall::InquireContext,
        kind: crate::gss::GssFailureKind::NtlmChosen,
    }));
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
    assert!(text_has(
        &ran,
        "SPNEGO chose NTLM, but NTLM is not allowed\n"
    ));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        plain_get("/")
    );
}

/// `Persistent-Auth: false` has each request authenticate again, even
/// after a context that took more than one round, read whatever its
/// case and whatever follows `false`; with Negotiate not in use it is
/// not read.
#[test]
fn persistent_auth_false_authenticates_each_request() {
    let (gss, libraries) = scripted();
    gss.then_token(b"one").then_token(b"two");
    let first =
        b"HTTP/1.1 200 OK\r\nPersistent-Auth: FALSE, really\r\nContent-Length: 3\r\n\r\nok\n";
    let talk = Conversation::replies(&[first, OK_200], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get_with(&mut m, negotiating(libraries), "/a", talk.clone(), |_| {});
    assert!(text_has(
        &ran,
        "Negotiate: noauthpersist -> 1, header part: FALSE, really\n"
    ));
    let ran = get_with(&mut m, negotiating(libraries), "/b", talk.clone(), |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(talk.received()).unwrap(),
        negotiated_get("/a", b"one") + &negotiated_get("/b", b"two")
    );
    let (_, libraries) = scripted();
    let (mut m, talk, _) = server(&[first], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| {
        o.http.auth = HttpAuth(AuthMethods::BASIC);
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
    });
    assert!(!ran.seen.text().iter().any(|l| l.starts_with("Negotiate:")));
}

/// Without a GSS-API library, Negotiate is not built in: nothing is
/// sent, nothing said, and a challenge is not taken.
#[test]
fn without_a_library_nothing_negotiates() {
    let unauthorized =
        b"HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[unauthorized], false);
    let mut e = Easy::new();
    e.options_mut().http.auth = HttpAuth(AuthMethods::NEGOTIATE);
    let ran = get_with(&mut m, e, "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        plain_get("/")
    );
    assert!(!ran.seen.text().iter().any(|l| l.contains("Negotiate")));
}

// Negotiate with an HTTP proxy (`Curl_output_negotiate` and
// `Curl_input_negotiate` with `proxy`): the context is the connection's
// with the proxy, its tokens in `Proxy-Authorization`, for requests a
// proxy forwards and for the `CONNECT` of a tunnel.

/// The context a request through the test's proxy makes with it.
fn proxy_context(service: &[u8]) -> Asked {
    Asked::Context {
        service: service.to_vec(),
        host: b"127.0.0.1".to_vec(),
        mech: Mech::Spnego,
        flags: Flags {
            mutual: true,
            ..Flags::default()
        },
    }
}

/// Through the test's proxy, which forwards requests unless `tunnel`, to
/// `http://origin.example/x`, the proxy negotiated with.
fn via_proxy(o: &mut Options, tunnel: bool) {
    o.set_url(Some(b"http://origin.example/x")).unwrap();
    let proxy = o.proxy.make_mut().unwrap();
    proxy.url = Some(format!("127.0.0.1:{PORT}").into_bytes());
    proxy.tunnel = tunnel;
    proxy.auth = HttpAuth(AuthMethods::NEGOTIATE);
}

/// The empty proxy credentials of `-U :`, which the proxy's 407 picks a
/// method with.
fn empty_proxy_user(o: &mut Options) {
    let proxy = o.proxy.make_mut().unwrap();
    proxy.user = Some(Vec::new());
    proxy.password = Some(Vec::new());
}

/// A GET of `http://origin.example/x` a proxy forwards, with
/// `Proxy-Authorization: Negotiate <token>` if a token.
fn forwarded_get(token: Option<&[u8]>) -> String {
    let proxy = token.map_or(String::new(), |t| {
        format!("Proxy-Authorization: Negotiate {}\r\n", b64(t))
    });
    format!(
        "GET http://origin.example/x HTTP/1.1\r\nHost: origin.example\r\n{proxy}\
         User-Agent: curl/test\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    )
}

/// A `CONNECT` to `origin.example:80`, with the token if one.
fn negotiated_connect(token: Option<&[u8]>) -> String {
    let proxy = token.map_or(String::new(), |t| {
        format!("Proxy-Authorization: Negotiate {}\r\n", b64(t))
    });
    format!(
        "CONNECT origin.example:80 HTTP/1.1\r\nHost: origin.example:80\r\n{proxy}\
         User-Agent: curl/test\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    )
}

/// The GET of `/x` through a tunnel.
const TUNNELED_GET: &str =
    "GET /x HTTP/1.1\r\nHost: origin.example\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\r\n";

const TUNNEL_200: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

/// Asked only for Negotiate with a proxy that forwards, the request
/// carries its first token for the proxy at once, the context with
/// `HTTP@proxy`, or the service the options name, said as C says it
/// (C's capture: `-x ... --proxy-negotiate`, `--proxy-service-name pxy`).
#[test]
fn a_forwarding_proxy_gets_the_first_token_at_once() {
    for service in [&b"HTTP"[..], b"pxy"] {
        let (gss, libraries) = scripted();
        gss.then_token(b"first");
        let (mut m, talk, _) = server(&[OK_200], false);
        let mut e = Easy::new();
        e.set_libraries(libraries);
        let ran = get_with(&mut m, e, "/", talk, |o| {
            via_proxy(o, false);
            if service != b"HTTP" {
                o.proxy.make_mut().unwrap().service = Some(service.to_vec());
            }
        });
        assert_eq!(ran.result, Ok(()));
        assert_eq!(
            String::from_utf8(ran.request.clone()).unwrap(),
            forwarded_get(Some(b"first"))
        );
        assert!(text_has(&ran, "Proxy auth using Negotiate with user ''\n"));
        assert!(!ran.seen.text().iter().any(|l| l.starts_with("Server auth")));
        assert_eq!(gss.asked(), [proxy_context(service), Asked::Step(None)]);
        let report = ran.easy.report();
        assert_eq!(report.proxy_auth_used(), AuthMethods::NEGOTIATE);
        assert_eq!(report.auth_used(), AuthMethods::NONE);
    }
}

/// Negotiating with both, the proxy's token is made and said first, then
/// the origin's, each with its own context (C's capture with
/// `--proxy-negotiate --negotiate`).
#[test]
fn the_proxy_s_token_is_made_before_the_origin_s() {
    let (gss, libraries) = scripted();
    gss.then_token(b"proxy").then_token(b"origin");
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |o| {
        via_proxy(o, false);
    });
    assert_eq!(ran.result, Ok(()));
    let sent = String::from_utf8(ran.request.clone()).unwrap();
    let want = forwarded_get(Some(b"proxy")).replace(
        "User-Agent",
        &format!("Authorization: Negotiate {}\r\nUser-Agent", b64(b"origin")),
    );
    assert_eq!(sent, want);
    let text = ran.seen.text();
    let proxy = text
        .iter()
        .position(|l| l == "Proxy auth using Negotiate with user ''\n");
    let origin = text
        .iter()
        .position(|l| l == "Server auth using Negotiate with user ''\n");
    assert!(proxy.zip(origin).is_some_and(|(p, o)| p < o), "{text:?}");
    let said = |line: &str| text.iter().filter(|l| *l == line).count();
    assert_eq!(
        said("Proxy auth using Negotiate with user ''\n"),
        1,
        "said once"
    );
    let Asked::Context { host, .. } = &gss.asked()[2] else {
        panic!("the origin's context second: {:?}", gss.asked());
    };
    assert_eq!(host, b"origin.example");
}

/// A forwarding proxy's 407 offering Negotiate has it picked with any
/// method wanted and credentials for the proxy, empty ones too, and the
/// request made again with its token over the same connection; without
/// credentials for the proxy, nothing is picked (C's capture with
/// `--proxy-anyauth -U :`).
#[test]
fn a_forwarding_proxy_s_407_has_negotiate_picked() {
    let required = b"HTTP/1.1 407 Who\r\nProxy-Authenticate: Negotiate\r\n\
        Content-Length: 4\r\n\r\nno!\n";
    for credentials in [true, false] {
        let (gss, libraries) = scripted();
        gss.then_token(b"tok");
        let (mut m, talk, _) = server(&[required, OK_200], false);
        let mut e = Easy::new();
        e.set_libraries(libraries);
        let ran = get_with(&mut m, e, "/", talk, |o| {
            via_proxy(o, false);
            o.proxy.make_mut().unwrap().auth = HttpAuth(AuthMethods::ANY);
            if credentials {
                empty_proxy_user(o);
            }
        });
        assert_eq!(ran.result, Ok(()), "{credentials}");
        let sent = String::from_utf8(ran.request.clone()).unwrap();
        if credentials {
            assert_eq!(sent, forwarded_get(None) + &forwarded_get(Some(b"tok")));
            assert!(text_has(
                &ran,
                "Reusing existing http: connection with proxy 127.0.0.1\n"
            ));
            let report = ran.easy.report();
            assert_eq!(report.proxy_auth_offered(), AuthMethods::NEGOTIATE);
            assert_eq!(report.proxy_auth_used(), AuthMethods::NEGOTIATE);
        } else {
            assert_eq!(sent, forwarded_get(None), "nothing picked");
            assert_eq!(gss.unused(), 1);
        }
    }
}

/// A forwarding proxy's challenge is taken into the context with it as
/// its line is read, and the request made again with what the context
/// made of it; one the context fails on is said before the line, and
/// leaves the 407 the response (C's capture: `Negotiate Qw==`).
#[test]
fn a_forwarding_proxy_s_challenge_is_taken() {
    let required = format!(
        "HTTP/1.1 407 Who\r\nProxy-Authenticate: Negotiate {}\r\nX-After: 1\r\n\
         Content-Length: 4\r\n\r\nno!\n",
        b64(b"challenge")
    );
    let (gss, libraries) = scripted();
    gss.then_token(b"first").then_token(b"second");
    let (mut m, talk, _) = server(&[required.as_bytes(), OK_200], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| {
        via_proxy(o, false);
        // Without credentials for the proxy, a connection negotiating
        // with it serves no transfer, this one's next request neither.
        empty_proxy_user(o);
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        forwarded_get(Some(b"first")) + &forwarded_get(Some(b"second"))
    );
    assert_eq!(
        gss.asked(),
        [
            proxy_context(b"HTTP"),
            Asked::Step(None),
            Asked::Step(Some(b"challenge".to_vec()))
        ]
    );
    // Refused.
    let (gss, libraries) = scripted();
    gss.then_token(b"first")
        .then(Answer::Fails(GssFailure::status(
            GssCall::InitSecContext,
            GssStatus::new(13 << 16, 0),
        )));
    let (mut m, talk, _) = server(&[required.as_bytes()], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| via_proxy(o, false));
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.easy.report().response_code(), Some(407));
    let lines = in_and_text(&ran);
    let said = lines
        .iter()
        .position(|l| l == b"gss_init_sec_context() failed: status 851968.0. \n")
        .expect("said");
    assert!(
        lines[said + 1].starts_with(b"Proxy-Authenticate"),
        "before its line"
    );
    assert_eq!(gss.asked().last(), Some(&Asked::Dropped), "started over");
}

/// The lines received and said, in order.
fn in_and_text(ran: &Ran) -> Vec<Vec<u8>> {
    ran.seen
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|(w, _)| *w == "text" || *w == "in")
        .map(|(_, b)| b.clone())
        .collect()
}

/// A forwarding proxy's connection closing while its challenge is taken
/// cuts the handshake short, said as C says it (`http_check_auth_closure`).
#[test]
fn a_forwarding_proxy_closing_mid_handshake_is_said() {
    let closing = b"HTTP/1.1 407 Who\r\nProxy-Authenticate: Negotiate\r\nConnection: close\r\n\
        Content-Length: 0\r\n\r\n";
    let (gss, libraries) = scripted();
    gss.then_token(b"one").then_token(b"two");
    let first = Conversation::replies(&[closing], true);
    let second = Conversation::replies(&[OK_200], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", first.clone(), |o| {
        via_proxy(o, false);
        // The proxy's own header keeps the first token out, the challenge
        // still taken.
        o.proxy.make_mut().unwrap().headers =
            crate::options::UserHeaders::new([&b"Proxy-Authorization: x"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text();
    let said = text
        .iter()
        .position(|l| l == "Connection closure while negotiating auth (HTTP 1.0?)\n")
        .expect("said");
    assert!(
        text[said..]
            .iter()
            .any(|l| l.starts_with("Issue another request"))
    );
    assert!(!second.received().is_empty());
    assert_eq!(
        gss.asked(),
        [proxy_context(b"HTTP"), Asked::Step(None), Asked::Dropped]
    );
}

/// A forwarding proxy's challenge taken holds the connection for the
/// request that goes again, though the transfer forbade its reuse
/// (`multi_conn_should_close`); a body still going is not cut short once
/// Negotiate with the proxy started on it (`http_perhapsrewind`).
#[test]
fn a_forwarding_proxy_s_challenge_taken_holds_the_connection() {
    const SIZE: usize = 300_000;
    let required = format!(
        "HTTP/1.1 407 Who\r\nProxy-Authenticate: Negotiate {}\r\nContent-Length: 0\r\n\r\n",
        b64(b"challenge")
    );
    for upload in [false, true] {
        let (gss, libraries) = scripted();
        // A third, for a new connection the request should not need.
        gss.then_token(b"first")
            .then_token(b"second")
            .then_token(b"third");
        let first = Conversation::replies(&[required.as_bytes(), OK], false);
        let second = Conversation::replies(&[OK], false);
        let mut m = serving(Peer::Accepts, &[&first, &second]);
        let stream = Stream::new(big_body(SIZE));
        let mut e = Easy::new();
        e.set_libraries(libraries);
        let ran = get_with(&mut m, e, "/", first.clone(), |o| {
            via_proxy(o, false);
            empty_proxy_user(o);
            if upload {
                o.method = Method::Upload;
                o.upload = stream.source(true);
            } else {
                o.limits.reuse.forbid = true;
            }
        });
        assert_eq!(ran.result, Ok(()), "{upload}");
        let text = ran.seen.text();
        assert!(
            text.iter()
                .any(|l| l == "Reusing existing http: connection with proxy 127.0.0.1\n"),
            "{upload}: {text:?}"
        );
        assert!(second.received().is_empty(), "{upload}");
        assert!(
            !text.iter().any(|l| l.contains("close instead of sending")),
            "{upload}: {text:?}"
        );
    }
}

/// The proxy's own `Proxy-Authorization` keeps Negotiate's out, through a
/// forwarding proxy and in a `CONNECT`; nothing is made or said (C's
/// capture with `--proxy-header "Proxy-Authorization: mine"`).
#[test]
fn the_proxy_s_own_proxy_authorization_keeps_negotiate_out() {
    for tunnel in [false, true] {
        let (gss, libraries) = scripted();
        gss.then_token(b"first");
        let replies: &[&[u8]] = if tunnel {
            &[TUNNEL_200, OK_200]
        } else {
            &[OK_200]
        };
        let (mut m, talk, _) = server(replies, false);
        let mut e = Easy::new();
        e.set_libraries(libraries);
        let ran = get_with(&mut m, e, "/", talk, |o| {
            via_proxy(o, tunnel);
            o.proxy.make_mut().unwrap().headers =
                crate::options::UserHeaders::new([&b"Proxy-Authorization: mine"[..]]).unwrap();
        });
        assert_eq!(ran.result, Ok(()), "{tunnel}");
        let sent = String::from_utf8(ran.request.clone()).unwrap();
        assert!(sent.contains("Proxy-Authorization: mine\r\n"), "{sent}");
        assert!(!sent.contains("Negotiate"), "{sent}");
        assert!(gss.asked().is_empty(), "{tunnel}");
        assert!(!ran.seen.text().iter().any(|l| l.contains("Negotiate")));
    }
}

/// A tunnel's `CONNECT` carries the first token for the proxy, made and
/// said before the tunnel is established; the request through the tunnel
/// carries none, and a library that cannot make the token leaves the
/// `CONNECT` unauthenticated, said first (C's captures with `-p
/// --proxy-negotiate`, and with the stub's NTLM credentials).
#[test]
fn a_tunnel_s_connect_negotiates_with_the_proxy() {
    let (gss, libraries) = scripted();
    gss.then_token(b"first");
    let (mut m, talk, _) = server(&[TUNNEL_200, OK_200], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| via_proxy(o, true));
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_connect(Some(b"first")) + TUNNELED_GET
    );
    let text = ran.seen.text();
    let said = text
        .iter()
        .position(|l| l == "Proxy auth using Negotiate with user ''\n")
        .expect("said");
    assert_eq!(
        text[said + 1],
        "Establishing HTTP proxy tunnel to origin.example:80\n"
    );
    assert_eq!(ran.easy.report().proxy_auth_used(), AuthMethods::NEGOTIATE);
    // No token made.
    let (gss, libraries) = scripted();
    gss.then(Answer::Fails(GssFailure::status(
        GssCall::InitSecContext,
        GssStatus::new(13 << 16, 0),
    )));
    let (mut m, talk, _) = server(&[TUNNEL_200, OK_200], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| via_proxy(o, true));
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_connect(None) + TUNNELED_GET
    );
    let text = ran.seen.text();
    let failed = text
        .iter()
        .position(|l| l == "gss_init_sec_context() failed: status 851968.0. \n")
        .expect("said");
    assert_eq!(
        text[failed + 1],
        "Proxy auth using Negotiate with user ''\n"
    );
}

/// A tunnel's 407 offering Negotiate has it picked with credentials for
/// the proxy, and the `CONNECT` made again over the same connection with
/// the token (C's capture with `-p --proxy-anyauth -U :`).
#[test]
fn a_tunnel_s_407_has_negotiate_picked() {
    let required = b"HTTP/1.1 407 Who\r\nProxy-Authenticate: Negotiate\r\n\
        Content-Length: 4\r\n\r\nno!\n";
    let (gss, libraries) = scripted();
    gss.then_token(b"tok");
    let (mut m, talk, _) = server(&[required, TUNNEL_200, OK_200], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| {
        via_proxy(o, true);
        o.proxy.make_mut().unwrap().auth = HttpAuth(AuthMethods::ANY);
        empty_proxy_user(o);
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_connect(None) + &negotiated_connect(Some(b"tok")) + TUNNELED_GET
    );
    assert_eq!(ran.easy.report().proxy_auth_used(), AuthMethods::NEGOTIATE);
    assert_eq!(ran.easy.report().connects(), 1);
}

/// A tunnel's challenge is taken into the context with the proxy after
/// its line is traced, as C reads the answer to `CONNECT`, and the
/// `CONNECT` made again with what the context made of it; a refusal ends
/// the tunnel with C's error.
#[test]
fn a_tunnel_s_challenge_is_taken() {
    let required = format!(
        "HTTP/1.1 407 Who\r\nProxy-Authenticate: Negotiate {}\r\nX-After: 1\r\n\
         Content-Length: 4\r\n\r\nno!\n",
        b64(b"challenge")
    );
    let (gss, libraries) = scripted();
    gss.then_token(b"first").then_token(b"second");
    let (mut m, talk, _) = server(&[required.as_bytes(), TUNNEL_200, OK_200], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| via_proxy(o, true));
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_connect(Some(b"first")) + &negotiated_connect(Some(b"second")) + TUNNELED_GET
    );
    assert_eq!(
        gss.asked(),
        [
            proxy_context(b"HTTP"),
            Asked::Step(None),
            Asked::Step(Some(b"challenge".to_vec()))
        ]
    );
    // Refused.
    let (gss, libraries) = scripted();
    gss.then_token(b"first")
        .then(Answer::Fails(GssFailure::status(
            GssCall::InitSecContext,
            GssStatus::new(13 << 16, 0),
        )));
    let (mut m, talk, _) = server(&[required.as_bytes()], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| via_proxy(o, true));
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let lines = in_and_text(&ran);
    let said = lines
        .iter()
        .position(|l| l == b"gss_init_sec_context() failed: status 851968.0. \n")
        .expect("said");
    assert!(
        lines[said - 1].starts_with(b"Proxy-Authenticate"),
        "after its line"
    );
    assert!(text_has(&ran, "CONNECT tunnel failed, response 407\n"));
}

/// A proxy that closes the connection on the challenge it sends has the
/// tunnel set up again over a new one, Negotiate going on where it was:
/// the token the challenge made goes with the next `CONNECT`, from the
/// same context (C keeps it on the connection whose filters are made
/// again).
#[test]
fn a_tunnel_redialed_keeps_negotiating() {
    let required = format!(
        "HTTP/1.1 407 Who\r\nProxy-Authenticate: Negotiate {}\r\nProxy-Connection: close\r\n\
         Content-Length: 0\r\n\r\n",
        b64(b"challenge")
    );
    let (gss, libraries) = scripted();
    gss.then_token(b"first")
        .then_token(b"second")
        .then_token(b"third");
    let first = Conversation::replies(&[required.as_bytes()], true);
    let second = Conversation::replies(&[TUNNEL_200, OK_200], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", second.clone(), |o| via_proxy(o, true));
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(first.received()).unwrap(),
        negotiated_connect(Some(b"first"))
    );
    assert_eq!(
        String::from_utf8(second.received()).unwrap(),
        negotiated_connect(Some(b"second")) + TUNNELED_GET
    );
    assert!(text_has(&ran, "Connect me again please\n"));
    assert_eq!(
        gss.asked(),
        [
            proxy_context(b"HTTP"),
            Asked::Step(None),
            Asked::Step(Some(b"challenge".to_vec()))
        ]
    );
}

/// The origin's Negotiate through a tunnel goes with the request the
/// tunnel carries. C's `CONNECT` makes the origin's token too and sends
/// it nowhere, leaving the origin unauthenticated: a difference recorded
/// in DIVERGENCE.md.
#[test]
fn the_origin_s_token_goes_through_the_tunnel() {
    let (gss, libraries) = scripted();
    gss.then_token(b"origin");
    let (mut m, talk, _) = server(&[TUNNEL_200, OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |o| {
        via_proxy(o, true);
        o.proxy.make_mut().unwrap().auth = HttpAuth(AuthMethods::BASIC);
    });
    assert_eq!(ran.result, Ok(()));
    let get = TUNNELED_GET.replace(
        "User-Agent",
        &format!("Authorization: Negotiate {}\r\nUser-Agent", b64(b"origin")),
    );
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_connect(None) + &get
    );
}

/// A connection negotiating with its proxy serves only a transfer
/// negotiating with it with credentials for it, empty ones too; the
/// next request through it authenticates again, the context cleaned up
/// as C says it, as the proxy never says it persists (C's captures with
/// two URLs, `--proxy-negotiate` with and without `-U :`).
#[test]
fn a_connection_negotiating_with_its_proxy_serves_only_its_own() {
    let reused = "Reusing existing http: connection with proxy 127.0.0.1\n";
    let cleaned = "Curl_output_negotiate, no persistent authentication: cleanup existing context\n";
    type Case = (&'static str, fn(&mut Options), fn(&mut Options), bool);
    let cases: [Case; 4] = [
        ("with credentials", empty_proxy_user, empty_proxy_user, true),
        ("without credentials", |_| {}, |_| {}, false),
        (
            "then not negotiating",
            empty_proxy_user,
            |o| {
                empty_proxy_user(o);
                o.proxy.make_mut().unwrap().auth = HttpAuth(AuthMethods::BASIC);
            },
            false,
        ),
        (
            "then any",
            empty_proxy_user,
            |o| {
                empty_proxy_user(o);
                o.proxy.make_mut().unwrap().auth = HttpAuth(AuthMethods::ANY);
            },
            true,
        ),
    ];
    // Through a tunnel likewise: the connection is the tunnel's, and
    // negotiated with its proxy as it was set up.
    let (gss, libraries) = scripted();
    gss.then_token(b"one").then_token(b"two");
    let first = Conversation::replies(&[TUNNEL_200, OK_200, OK_200], false);
    let second = Conversation::replies(&[TUNNEL_200, OK_200], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    for _ in 0..2 {
        let mut e = Easy::new();
        e.set_libraries(libraries);
        let ran = get_with(&mut m, e, "/", first.clone(), |o| via_proxy(o, true));
        assert_eq!(ran.result, Ok(()));
        assert!(!text_has(
            &ran,
            "Reusing existing http: connection with proxy 127.0.0.1\n"
        ));
    }
    assert_eq!(
        String::from_utf8(second.received()).unwrap(),
        negotiated_connect(Some(b"two")) + TUNNELED_GET
    );
    for (what, first_set, then, serves) in cases {
        let (gss, libraries) = scripted();
        gss.then_token(b"one").then_token(b"two");
        let first = Conversation::replies(&[OK_200, OK_200], false);
        let second = Conversation::replies(&[OK_200], false);
        let mut m = serving(Peer::Accepts, &[&first, &second]);
        let mut e = Easy::new();
        e.set_libraries(libraries);
        let ran = get_with(&mut m, e, "/", first.clone(), |o| {
            via_proxy(o, false);
            first_set(o);
        });
        assert_eq!(ran.result, Ok(()), "{what}");
        let mut e = Easy::new();
        e.set_libraries(libraries);
        let ran = get_with(&mut m, e, "/", first.clone(), |o| {
            via_proxy(o, false);
            then(o);
        });
        assert_eq!(ran.result, Ok(()), "{what}");
        assert_eq!(
            text_has(&ran, reused),
            serves,
            "{what}: {:?}",
            ran.seen.text()
        );
        assert_eq!(second.received().is_empty(), serves, "{what}");
        if what == "with credentials" {
            assert!(text_has(&ran, cleaned), "{what}");
            assert_eq!(
                String::from_utf8(first.received()).unwrap(),
                forwarded_get(Some(b"one")) + &forwarded_get(Some(b"two"))
            );
        }
    }
}

/// Wanting Negotiate of a proxy with no proxy on the way, or with one
/// whose tunnel is up, sends nothing to negotiate.
#[test]
fn no_proxy_is_negotiated_with_where_none_is_asked() {
    let (gss, libraries) = scripted();
    gss.then_token(b"first");
    let (mut m, talk, _) = server(&[OK_200], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| {
        o.proxy.make_mut().unwrap().auth = HttpAuth(AuthMethods::NEGOTIATE);
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        plain_get("/")
    );
    assert!(gss.asked().is_empty());
}

/// A scripted GSS-API library and a fake TLS one whose sessions bind a
/// channel as `binding` says, and the libraries naming both.
fn scripted_over_tls(
    binding: crate::tls::fake::FakeBinding,
) -> (&'static Scripted, &'static Libraries) {
    let gss = Scripted::leaked();
    let tls = Box::leak(Box::new(
        crate::tls::fake::FakeTls::binding(binding).unwrap(),
    ));
    let libraries = Box::leak(Box::new(Libraries {
        gss: Some(gss),
        tls: Some(tls),
        ..Libraries::NONE
    }));
    (gss, libraries)
}

/// A Negotiate GET of `/` over HTTPS, its server answering `response`.
fn negotiated_https(libraries: &'static Libraries, response: &[u8]) -> Ran {
    let replies = [
        crate::tls::fake::WELCOME.to_vec(),
        crate::tls::fake::records(response).unwrap(),
    ];
    let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
    let (mut m, talk, _) = server(&replies, false);
    get_with(&mut m, negotiating(libraries), "/", talk, |o| {
        let url = format!("https://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
    })
}

/// Over HTTPS each step is bound to the channel, as the origin's TLS
/// session binds it (`Curl_ssl_get_channel_binding`); over HTTP, to
/// none.
#[test]
fn a_step_over_https_is_bound_to_the_channel() {
    let (gss, libraries) = scripted_over_tls(crate::tls::fake::FakeBinding::Bound);
    gss.then_token(b"first");
    let ran = negotiated_https(libraries, OK_200);
    assert_eq!(ran.result, Ok(()));
    let bound = [crate::tls::fake::BINDING, &[1]].concat();
    assert_eq!(gss.bindings(), [Some(bound)]);

    let (gss, libraries) = scripted();
    gss.then_token(b"first");
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(gss.bindings(), [None]);
}

/// A peer certificate whose signature names no digest binds nothing,
/// said so, and the step goes on unbound.
#[test]
fn a_certificate_naming_no_digest_binds_nothing() {
    let (gss, libraries) = scripted_over_tls(crate::tls::fake::FakeBinding::NoDigest);
    gss.then_token(b"first");
    let ran = negotiated_https(libraries, OK_200);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(gss.bindings(), [None]);
    assert!(text_has(
        &ran,
        "certificate exposes no signing digest algorithm, nothing to add to channel binding\n"
    ));
}

/// A binding that cannot be made fails the request with the session's
/// reason, before any context is made (`Curl_output_negotiate`).
#[test]
fn a_binding_not_made_fails_the_request() {
    let (gss, libraries) = scripted_over_tls(crate::tls::fake::FakeBinding::Fails);
    let ran = negotiated_https(libraries, OK_200);
    assert_eq!(ran.result, Err(ErrorKind::SslInvalidcertstatus));
    assert_eq!(
        ran.easy.report().failure(),
        Some(&b"certificate signature algorithm not recognized"[..])
    );
    assert!(gss.asked().is_empty());
}

/// Whether a second transfer, as `set` makes it, reuses the connection a
/// first, negotiating as `first` makes it, left after the conversation
/// `replies`, its library scripted by `script`.
fn second_reuses(
    script: fn(&Scripted),
    replies: &[&[u8]],
    first: fn(&mut Options),
    want_first: Result<(), ErrorKind>,
    set: fn(&mut Options),
    negotiates: bool,
) -> bool {
    let reused = "Reusing existing http: connection with host 127.0.0.1\n";
    let (gss, libraries) = scripted();
    script(gss);
    let mut all = replies.to_vec();
    all.push(OK_200);
    let talk = Conversation::replies(&all, false);
    let other = Conversation::replies(&[OK_200], false);
    let mut m = serving(Peer::Accepts, &[&talk, &other]);
    let ran = get_with(&mut m, negotiating(libraries), "/a", talk.clone(), first);
    assert_eq!(ran.result, want_first);
    let e = if negotiates {
        negotiating(libraries)
    } else {
        let mut e = Easy::new();
        e.set_libraries(libraries);
        e
    };
    let ran = get_with(&mut m, e, "/b", talk.clone(), set);
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    let served = text_has(&ran, reused);
    assert_eq!(other.received().is_empty(), served);
    served
}

/// A refused Negotiate starts over with the origin unbound: the
/// connection then serves a transfer negotiating as anyone
/// (`http_auth_nego_reset`, `url_match_auth_nego`).
#[test]
fn a_refused_negotiation_unbinds_the_connection() {
    let refused: &[u8] =
        b"HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n";
    let script = |gss: &Scripted| {
        gss.then_token(b"first").then_token(b"again");
    };
    let as_u = |o: &mut Options| o.login.make_mut().unwrap().user = Some(b"u".to_vec());
    let as_v = |o: &mut Options| o.login.make_mut().unwrap().user = Some(b"v".to_vec());
    assert!(second_reuses(script, &[refused], as_u, Ok(()), as_v, true));
    assert!(second_reuses(
        script,
        &[refused],
        as_u,
        Ok(()),
        |_| {},
        true
    ));
}

/// A first token the library makes empty fails the request with the
/// connection bound to the origin and credentials it was for, though not
/// negotiating: it serves a transfer not negotiating, but not one
/// negotiating as others.
#[test]
fn a_token_made_empty_leaves_the_connection_bound() {
    let script = |gss: &Scripted| {
        gss.then_token(b"").then_token(b"t");
    };
    let as_u = |o: &mut Options| o.login.make_mut().unwrap().user = Some(b"u".to_vec());
    let denied = Err(ErrorKind::RemoteAccessDenied);
    assert!(second_reuses(script, &[], |_| {}, denied, as_u, false));
    assert!(!second_reuses(script, &[], |_| {}, denied, as_u, true));
}

/// A handshake that took a challenge, the server saying nothing of
/// persistence, persists: the next request goes without a token
/// (`havemultiplerequests`). Told `Persistent-Auth: false` with the
/// challenge, the token answering it still goes, the context kept.
#[test]
fn a_handshake_of_rounds_persists_unless_told_otherwise() {
    for told in [false, true] {
        let (gss, libraries) = scripted();
        gss.then_token(b"one")
            .then_token(b"two")
            .then_token(b"three");
        let challenge = format!(
            "HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate {}\r\n{}Content-Length: 0\r\n\r\n",
            b64(b"C"),
            if told {
                "Persistent-Auth: false\r\n"
            } else {
                ""
            }
        );
        let talk = Conversation::replies(&[challenge.as_bytes(), OK_200, OK_200], false);
        let mut m = serving(Peer::Accepts, &[&talk]);
        let ran = get_with(&mut m, negotiating(libraries), "/a", talk.clone(), |_| {});
        assert_eq!(ran.result, Ok(()), "{told}");
        let cleaned =
            "Curl_output_negotiate, no persistent authentication: cleanup existing context\n";
        assert!(!text_has(&ran, cleaned), "{told}");
        let ran = get_with(&mut m, negotiating(libraries), "/b", talk.clone(), |_| {});
        assert_eq!(ran.result, Ok(()), "{told}");
        let sent = String::from_utf8(talk.received()).unwrap();
        let handshake = negotiated_get("/a", b"one") + &negotiated_get("/a", b"two");
        if told {
            assert_eq!(sent, handshake + &negotiated_get("/b", b"three"));
            assert!(text_has(&ran, cleaned));
        } else {
            assert_eq!(sent, handshake + &plain_get("/b"), "{told}");
            assert_eq!(gss.unused(), 1);
        }
    }
}

/// A POST sends its body with its token, whether the context wants
/// more or is complete: unlike Digest's, Negotiate's request is done once
/// a token goes (`CURL_NEGO_AUTH_DONE` for `GSS_S_CONTINUE_NEEDED` too),
/// so it never probes without its body (C's `authneg`).
#[test]
fn a_post_sends_its_body_with_its_token() {
    for complete in [false, true] {
        let (gss, libraries) = scripted();
        if complete {
            gss.then(Answer::Token(Progress::Complete, b"all".to_vec()));
        } else {
            gss.then_token(b"one").then_token(b"two");
        }
        let challenge = format!(
            "HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate {}\r\nContent-Length: 0\r\n\r\n",
            b64(b"C")
        );
        let replies: Vec<&[u8]> = if complete {
            vec![OK_200]
        } else {
            vec![challenge.as_bytes(), OK_200]
        };
        let (mut m, talk, _) = server(&replies, false);
        let ran = get_with(&mut m, negotiating(libraries), "/", talk, |o| {
            o.method = crate::options::Method::Post;
            o.upload = crate::options::UploadSource::Bytes(
                curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap(),
            );
        });
        assert_eq!(ran.result, Ok(()), "{complete}");
        let text = String::from_utf8_lossy(&ran.request).into_owned();
        let posts = if complete { 1 } else { 2 };
        assert_eq!(text.matches("POST / ").count(), posts, "{text}");
        assert_eq!(
            text.matches("Content-Length: 3\r\n").count(),
            posts,
            "{text}"
        );
        assert_eq!(text.matches("\r\n\r\na=b").count(), posts, "{text}");
        assert!(!text.contains("Content-Length: 0\r\n"), "{text}");
    }
}

/// The proxy's method, not Negotiate, is still said before the origin's
/// Negotiate, and once (C makes the proxy's line first).
#[test]
fn the_proxy_s_other_method_is_said_before_the_origin_s_negotiate() {
    let (gss, libraries) = scripted();
    gss.then_token(b"origin");
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(libraries), "/", talk, |o| {
        via_proxy(o, false);
        let proxy = o.proxy.make_mut().unwrap();
        proxy.auth = HttpAuth(AuthMethods::BASIC);
        proxy.user = Some(b"pu".to_vec());
        proxy.password = Some(b"pp".to_vec());
    });
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text();
    let at = |line: &str| text.iter().position(|l| l == line);
    let proxy = at("Proxy auth using Basic with user 'pu'\n");
    let origin = at("Server auth using Negotiate with user ''\n");
    assert!(proxy.zip(origin).is_some_and(|(p, o)| p < o), "{text:?}");
    let said = |line: &str| text.iter().filter(|l| *l == line).count();
    assert_eq!(
        said("Proxy auth using Basic with user 'pu'\n"),
        1,
        "{text:?}"
    );
}
