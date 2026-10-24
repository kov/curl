//! SOCKS5's GSS-API method through a transfer, over a scripted library:
//! the bytes the proxy is sent, the lines traced and the reasons given in
//! C's order, the first of them the transfer's, and the proxy's error
//! code (`lib/socks_gssapi.c`, `lib/socks.c`).

use super::*;
use crate::conn::ProxyError;
use crate::gss::testing::{Answer, Asked, Scripted, TOO_LONG};
use crate::gss::{Flags, GssCall, GssFailure, GssStatus, Mech, Progress, Step};
use crate::libraries::Libraries;

fn scripted() -> (&'static Scripted, &'static Libraries) {
    let gss = Scripted::leaked();
    let libraries = Box::leak(Box::new(Libraries {
        gss: Some(gss),
        ..Libraries::NONE
    }));
    (gss, libraries)
}

/// A GET of `http://origin.example/a` through the SOCKS5 proxy at the
/// test's server, which answers each send with the next of `replies`
/// and closes after the last if `then_close`.
fn through_gss(
    libraries: &'static Libraries,
    replies: &[&[u8]],
    then_close: bool,
    set: impl FnOnce(&mut Options),
) -> Ran {
    let talk = Conversation::replies(replies, then_close).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    get_with(&mut m, e, "/", talk.clone(), |o| {
        through_socks(o, "socks5h", b"http://origin.example/a");
        set(o);
    })
}

const REQUEST: &[u8] = b"\x05\x01\x00\x03\x0eorigin.example\x00\x50";

fn complete(confidentiality: bool, integrity: bool) -> Step {
    Step {
        progress: Progress::Complete,
        confidentiality,
        integrity,
    }
}

/// The lines after the connection to the proxy, up to the request.
fn gss_lines(ran: &Ran) -> Vec<String> {
    ran.seen
        .text()
        .into_iter()
        .filter(|l| {
            ["GSS", "Opened SOCKS", "User", "Failed", "Unable"]
                .iter()
                .any(|p| l.contains(p))
        })
        .map(|l| l.trim_end().to_owned())
        .collect()
}

/// The whole exchange: the offer with GSS-API, the tokens framed, the
/// level wrapped, then the request and the transfer, with C's lines.
#[test]
fn a_socks5_proxy_authenticates_by_gss_api() {
    let (gss, libraries) = scripted();
    gss.then_token(b"first")
        .then(Answer::Stepped(complete(true, true), b"last".to_vec()))
        .then(Answer::Initiator(Ok(b"alice@EXAMPLE.TEST".to_vec())))
        .then(Answer::Wrapped(Ok(b"W2".to_vec())))
        .then(Answer::Unwrapped(Ok(b"\x00".to_vec())));
    let ran = through_gss(
        libraries,
        &[
            b"\x05\x01",
            b"\x01\x01\x00\x02AB",
            b"\x01\x02\x00\x02U0",
            b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50",
            OK,
        ],
        false,
        |_| {},
    );
    assert_eq!(ran.result, Ok(()));
    let mut want =
        b"\x05\x02\x00\x01\x01\x01\x00\x05first\x01\x01\x00\x04last\x01\x02\x00\x02W2".to_vec();
    want.extend_from_slice(REQUEST);
    want.extend_from_slice(
        b"GET /a HTTP/1.1\r\nHost: origin.example\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\r\n",
    );
    assert_eq!(
        String::from_utf8_lossy(&ran.request),
        String::from_utf8_lossy(&want)
    );
    let lines = gss_lines(&ran);
    assert_eq!(
        lines[..3],
        [
            "SOCKS5 server authenticated user alice@EXAMPLE.TEST with GSS-API.",
            "SOCKS5 server supports GSS-API confidentiality data protection.",
            "SOCKS5 access without GSS-API data protection granted.",
        ]
    );
    assert!(
        lines[3].starts_with("Opened SOCKS connection from "),
        "{lines:?}"
    );
    assert_eq!(
        gss.asked()[0],
        Asked::Context {
            service: b"rcmd".to_vec(),
            host: b"127.0.0.1".to_vec(),
            mech: Mech::Kerberos,
            flags: Flags {
                mutual: true,
                ..Flags::default()
            },
        }
    );
    assert_eq!(ran.easy.report().connects(), 1);
}

/// A library that fails: the call and the library's words, C's for the
/// step, then that the method failed, each traced; the first is the
/// transfer's reason, and the proxy's code is GSS-API's.
#[test]
fn a_gss_api_failure_gives_c_s_three_reasons() {
    let (gss, libraries) = scripted();
    gss.then(Answer::Fails(GssFailure::status(
        GssCall::InitSecContext,
        GssStatus::new(9, 8),
    )));
    let ran = through_gss(libraries, &[b"\x05\x01"], false, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::Proxy));
    assert_eq!(
        ran.easy.report().failure(),
        Some(&b"GSS-API error: gss_init_sec_context failed: major 9.\nminor 8"[..])
    );
    assert_eq!(ran.easy.report().proxy_error(), Some(ProxyError::Gssapi));
    assert_eq!(
        gss_lines(&ran),
        [
            "GSS-API error: gss_init_sec_context failed: major 9.\nminor 8",
            "Failed to initialize GSS-API token.",
            "Unable to negotiate SOCKS5 GSS-API context.",
        ]
    );
    // A text too long for C's buffer is not said at all.
    let (gss, libraries) = scripted();
    gss.import_fails(GssStatus::new(TOO_LONG, 0));
    let ran = through_gss(libraries, &[b"\x05\x01"], false, |_| {});
    assert_eq!(
        ran.easy.report().failure(),
        Some(&b"Failed to create service name."[..])
    );
    assert_eq!(
        gss_lines(&ran),
        [
            "Failed to create service name.",
            "Unable to negotiate SOCKS5 GSS-API context.",
        ]
    );
}

/// The proxy's refusal is the transfer's reason, the method's end after
/// it.
#[test]
fn a_proxy_s_rejection_is_the_reason() {
    let (gss, libraries) = scripted();
    gss.then_token(b"t");
    let ran = through_gss(
        libraries,
        &[b"\x05\x01", b"\x01\xff\x00\x00"],
        false,
        |_| {},
    );
    assert_eq!(
        ran.easy.report().failure(),
        Some(&b"User was rejected by the SOCKS5 server (1 255)."[..])
    );
    assert_eq!(ran.easy.report().proxy_error(), Some(ProxyError::Gssapi));
    assert_eq!(
        gss_lines(&ran),
        [
            "User was rejected by the SOCKS5 server (1 255).",
            "Unable to negotiate SOCKS5 GSS-API context.",
        ]
    );
}

/// The proxy closing in the middle of a message is said of that message,
/// not as the handshake's other replies are.
#[test]
fn a_proxy_closing_is_said_of_the_message_awaited() {
    for (replies, said) in [
        (
            &[&b"\x05\x01"[..], b"\x01\x01"][..],
            "Failed to receive GSS-API authentication response.",
        ),
        (
            &[&b"\x05\x01"[..], b"\x01\x01\x00\x05DD"][..],
            "Failed to receive GSS-API authentication token.",
        ),
    ] {
        let (gss, libraries) = scripted();
        gss.then_token(b"t");
        let ran = through_gss(libraries, replies, true, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::Proxy));
        assert_eq!(ran.easy.report().failure(), Some(said.as_bytes()));
        assert_eq!(ran.easy.report().proxy_error(), Some(ProxyError::Gssapi));
    }
    let (gss, libraries) = scripted();
    gss.then(Answer::Stepped(complete(false, false), Vec::new()))
        .then(Answer::Initiator(Ok(b"u".to_vec())));
    let ran = through_gss(libraries, &[b"\x05\x01", b"\x01\x02\x00"], true, |o| {
        o.proxy.make_mut().unwrap().socks5_gssapi_nec = true;
    });
    assert_eq!(
        ran.easy.report().failure(),
        Some(&b"Failed to receive GSS-API encryption response."[..])
    );
    // NEC's level, unwrapped.
    assert!(
        ran.request
            .ends_with(b"\x05\x02\x00\x01\x01\x02\x00\x01\x00"),
        "{:?}",
        ran.request
    );
}

/// A send that fails mid-message is said of that message.
#[test]
fn a_failed_send_is_said_of_its_message() {
    let (gss, libraries) = scripted();
    gss.then_token(b"t");
    let talk = Conversation::replies(&[b"\x05\x01"], false)
        .per_send()
        .breaking_after(1);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        through_socks(o, "socks5h", b"http://origin.example/a");
    });
    assert_eq!(
        ran.easy.report().failure(),
        Some(&b"Failed to send GSS-API authentication request."[..])
    );
    assert_eq!(ran.easy.report().proxy_error(), Some(ProxyError::Gssapi));
}

/// Protection granted: the request goes, then the transfer fails with
/// C's words and code, the method's end not said.
#[test]
fn granted_protection_fails_after_the_request() {
    let (gss, libraries) = scripted();
    gss.then(Answer::Stepped(complete(true, true), b"t".to_vec()))
        .then(Answer::Initiator(Ok(b"u".to_vec())))
        .then(Answer::Wrapped(Ok(b"w".to_vec())))
        .then(Answer::Unwrapped(Ok(b"\x02".to_vec())));
    let ran = through_gss(
        libraries,
        &[b"\x05\x01", b"\x01\x02\x00\x01w", b"\x05\x00"],
        false,
        |_| {},
    );
    assert_eq!(ran.result, Err(ErrorKind::Proxy));
    assert!(ran.request.ends_with(REQUEST), "{:?}", ran.request);
    assert_eq!(
        ran.easy.report().failure(),
        Some(&b"SOCKS5 GSS-API protection not yet implemented."[..])
    );
    assert_eq!(
        ran.easy.report().proxy_error(),
        Some(ProxyError::GssapiProtection)
    );
    let lines = gss_lines(&ran);
    assert_eq!(
        lines.last().map(String::as_str),
        Some("SOCKS5 GSS-API protection not yet implemented.")
    );
    assert!(!lines.iter().any(|l| l.starts_with("Unable")), "{lines:?}");
}

/// The proxy's service names the context, at the proxy's host; it makes
/// the proxy's credentials, so the user and password method is offered
/// too.
#[test]
fn the_proxy_service_names_the_context() {
    let (gss, libraries) = scripted();
    gss.then_token(b"t");
    let ran = through_gss(libraries, &[b"\x05\x01", b"\x01\xff\x00\x00"], false, |o| {
        o.proxy.make_mut().unwrap().service = Some(b"svc".to_vec());
    });
    assert!(ran.request.starts_with(b"\x05\x03\x00\x01\x02"));
    let Asked::Context { service, host, .. } = &gss.asked()[0] else {
        panic!()
    };
    assert_eq!((&service[..], &host[..]), (&b"svc"[..], &b"127.0.0.1"[..]));
}

/// A proxy that never answers a GSS-API message: once the time to
/// connect is out, the read of it fails, as C's blocking read fails it,
/// and the method with it.
#[test]
fn an_unanswered_message_fails_its_read_when_the_time_is_out() {
    for (replies, said) in [
        (
            &[&b"\x05\x01"[..]][..],
            "Failed to receive GSS-API authentication response.",
        ),
        (
            &[&b"\x05\x01"[..], b"\x01\x01\x00\x05DD"][..],
            "Failed to receive GSS-API authentication token.",
        ),
    ] {
        let (gss, libraries) = scripted();
        gss.then_token(b"t");
        let ran = through_gss(libraries, replies, false, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::Proxy));
        assert_eq!(ran.easy.report().failure(), Some(said.as_bytes()));
        assert_eq!(ran.easy.report().proxy_error(), Some(ProxyError::Gssapi));
        assert_eq!(
            gss_lines(&ran),
            [said, "Unable to negotiate SOCKS5 GSS-API context."]
        );
        assert!(ran.request.ends_with(b"\x01\x01\x00\x01t"));
    }
}
