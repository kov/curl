//! SOCKS5's GSS-API method over a scripted library: the offer, the
//! RFC 1961 messages byte by byte, the protection level wrapped or not,
//! and C's words for each way it fails (`lib/socks_gssapi.c`).

use super::*;
use crate::gss::testing::{Answer, Asked, Scripted};
use crate::gss::{Flags, Gss, GssCall, GssContext, GssFailure, GssStatus, Mech, Progress, Step};
use crate::options::Delegation;

const PROXY: &[u8] = b"proxy.example";

/// A library whose contexts send one token, complete with any answer
/// to it, can keep messages secret, and wrap and unwrap a message as it
/// is: for any reply to reach every state.
pub(super) static ECHO: Echo = Echo;

pub(super) struct Echo;

impl Gss for Echo {
    fn context(
        &self,
        _: crate::gss::Target<'_>,
        _: Mech,
        _: Flags,
    ) -> Result<Box<dyn GssContext>, GssFailure> {
        Ok(Box::new(Echoing))
    }

    fn describe(
        &self,
        _: &GssStatus,
        _: crate::gss::Style,
        _: &mut dyn FnMut(&[u8]),
    ) -> Result<(), crate::gss::TooLong> {
        Ok(())
    }
}

struct Echoing;

impl GssContext for Echoing {
    fn step(
        &mut self,
        input: Option<&[u8]>,
        _: Option<&[u8]>,
        sink: &mut dyn crate::gss::StepSink,
    ) -> Result<Step, GssFailure> {
        let oom = |_| GssFailure::out_of_memory(GssCall::InitSecContext);
        let progress = match input {
            None => {
                sink.token(b"e").map_err(oom)?;
                Progress::Continue
            }
            Some(_) => {
                sink.token(b"").map_err(oom)?;
                Progress::Complete
            }
        };
        Ok(Step {
            progress,
            confidentiality: true,
            integrity: true,
        })
    }

    fn wrap(
        &mut self,
        message: &[u8],
        out: &mut dyn FnMut(&[u8]) -> Result<(), curl_alloc::OutOfMemory>,
    ) -> Result<(), GssFailure> {
        out(message).map_err(|_| GssFailure::out_of_memory(GssCall::Wrap))
    }

    fn unwrap(
        &mut self,
        token: &[u8],
        out: &mut dyn FnMut(&[u8]) -> Result<(), curl_alloc::OutOfMemory>,
    ) -> Result<(), GssFailure> {
        out(token).map_err(|_| GssFailure::out_of_memory(GssCall::Unwrap))
    }

    fn initiator(
        &mut self,
        out: &mut dyn FnMut(&[u8]) -> Result<(), curl_alloc::OutOfMemory>,
    ) -> Result<(), GssFailure> {
        out(b"u").map_err(|_| GssFailure::out_of_memory(GssCall::DisplayName))
    }
}

fn method(library: &'static Scripted, nec: bool) -> Option<GssMethod> {
    Some(GssMethod {
        library,
        nec,
        delegation: Delegation::default(),
    })
}

/// A handshake through a proxy offering GSS-API, its offer sent.
fn offered(library: &'static Scripted, nec: bool) -> Handshake {
    let d = dest(b"host.example", Resolved::Remote);
    let mut h = Handshake::new(
        Version::V5Hostname,
        d,
        None,
        Socks5Auth::default(),
        method(library, nec),
    )
    .unwrap();
    assert_eq!(send(&mut h), b"\x05\x02\x00\x01");
    h
}

/// The lines said while `f` runs on `h`.
fn saying<T>(
    h: &mut Handshake,
    f: impl FnOnce(&mut Handshake, &mut dyn FnMut(GssLine<'_>)) -> T,
) -> (T, Vec<String>) {
    let mut lines = Vec::new();
    let got = f(h, &mut |line| lines.push(line.to_string()));
    (got, lines)
}

/// The proxy picks GSS-API, and the context is made with `PROXY`.
fn picked(h: &mut Handshake) -> Result<Vec<String>, SocksError> {
    assert_eq!(h.take(b"\x05\x01"), Ok(Took::Read(2)));
    assert!(h.gss_starts() && h.authenticated());
    let (started, lines) = saying(h, |h, say| h.start_gss(PROXY, say));
    started.map(|()| lines)
}

fn take_saying(h: &mut Handshake, input: &[u8]) -> (Result<Took, SocksError>, Vec<String>) {
    saying(h, |h, say| h.take_saying(input, say))
}

fn complete(confidentiality: bool, integrity: bool) -> Step {
    Step {
        progress: Progress::Complete,
        confidentiality,
        integrity,
    }
}

fn mutual() -> Flags {
    Flags {
        mutual: true,
        ..Flags::default()
    }
}

fn rcmd() -> Asked {
    Asked::Context {
        service: b"rcmd".to_vec(),
        host: PROXY.to_vec(),
        mech: Mech::Kerberos,
        flags: mutual(),
    }
}

fn status(major: u32, minor: u32) -> GssStatus {
    GssStatus::new(major, minor)
}

fn gss_error(e: SocksError) -> GssError {
    match e {
        SocksError::Gss(g) => {
            assert_eq!(SocksError::Gss(g).code(), Some(ProxyError::Gssapi));
            g
        }
        other => panic!("{other:?}"),
    }
}

/// GSS-API is offered after no authentication and before the user and
/// password, only where it is both allowed and built in.
#[test]
fn gss_api_is_offered_where_built_in_and_allowed() {
    let gss = Scripted::leaked();
    let greet = |creds, auth, built: bool| {
        let d = dest(b"h", Resolved::Remote);
        let library = if built { method(gss, false) } else { None };
        let mut h = Handshake::new(Version::V5Hostname, d, creds, auth, library).unwrap();
        send(&mut h)
    };
    let all = Socks5Auth::default();
    let up = || creds(b"u", b"p");
    assert_eq!(greet(None, all, false), b"\x05\x01\x00");
    assert_eq!(greet(None, all, true), b"\x05\x02\x00\x01");
    assert_eq!(greet(up(), all, false), b"\x05\x02\x00\x02");
    assert_eq!(greet(up(), all, true), b"\x05\x03\x00\x01\x02");
    let only = Socks5Auth { only: true, ..all };
    assert_eq!(greet(None, only, true), b"\x05\x01\x01");
    let no_gss = Socks5Auth {
        gssapi: false,
        ..all
    };
    assert_eq!(greet(up(), no_gss, true), b"\x05\x02\x00\x02");
    // Basic authentication not allowed: no user and password offered.
    let gss_only = Socks5Auth {
        basic: false,
        ..all
    };
    assert_eq!(greet(up(), gss_only, true), b"\x05\x02\x00\x01");
    // Picked though not built in, or not allowed.
    let d = dest(b"h", Resolved::Remote);
    let mut h = Handshake::new(Version::V5Hostname, d, None, all, None).unwrap();
    send(&mut h);
    assert_eq!(h.take(b"\x05\x01"), Err(SocksError::GssapiNotSupported));
    let mut h = Handshake::new(Version::V5Hostname, d, None, no_gss, method(gss, false)).unwrap();
    send(&mut h);
    assert_eq!(h.take(b"\x05\x01"), Err(SocksError::GssapiNotEnabled));
    assert!(gss.asked().is_empty());
}

/// The whole exchange: the first token in a message of version 1, type
/// 1 and its length; the proxy's token, read once all of it is in, for
/// the next step; then who was authenticated, the level asked for wrapped
/// in a message of type 2, the proxy's level unwrapped, and the request.
#[test]
fn the_exchange_is_rfc_1961_s() {
    let gss = Scripted::leaked();
    gss.then_token(b"first")
        .then(Answer::Stepped(complete(true, true), b"last".to_vec()))
        .then(Answer::Initiator(Ok(b"alice@EXAMPLE.TEST".to_vec())))
        .then(Answer::Wrapped(Ok(b"W2".to_vec())))
        .then(Answer::Unwrapped(Ok(b"\x00".to_vec())));
    let mut h = offered(gss, false);
    assert_eq!(picked(&mut h), Ok(vec![]));
    assert_eq!(send(&mut h), b"\x01\x01\x00\x05first");
    // The 4 bytes first, then as many as they say.
    assert_eq!(h.take(b"\x01\x01\x00"), Ok(Took::Need(4)));
    assert_eq!(h.take(b"\x01\x01\x00\x02A"), Ok(Took::Need(6)));
    let (took, lines) = take_saying(&mut h, b"\x01\x01\x00\x02ABrest");
    assert_eq!(took, Ok(Took::Read(6)));
    assert_eq!(
        lines,
        [
            "SOCKS5 server authenticated user alice@EXAMPLE.TEST with GSS-API.",
            "SOCKS5 server supports GSS-API confidentiality data protection.",
        ]
    );
    // The last token, and the level after it.
    assert_eq!(send(&mut h), b"\x01\x01\x00\x04last\x01\x02\x00\x02W2");
    assert_eq!(h.take(b"\x01\x02\x00\x02U"), Ok(Took::Need(6)));
    let (took, lines) = take_saying(&mut h, b"\x01\x02\x00\x02U0");
    assert_eq!(took, Ok(Took::Read(6)));
    assert_eq!(
        lines,
        ["SOCKS5 access without GSS-API data protection granted."]
    );
    assert_eq!(
        gss.asked(),
        [
            rcmd(),
            Asked::Step(None),
            Asked::Step(Some(b"AB".to_vec())),
            Asked::Initiator,
            Asked::Wrap(b"\x02".to_vec()),
            Asked::Unwrap(b"U0".to_vec()),
            // No protection: the context is done with.
            Asked::Dropped,
        ]
    );
    assert_eq!(send(&mut h), b"\x05\x01\x00\x03\x0chost.example\x23\x1e");
    assert_eq!(
        h.take(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50"),
        Ok(Took::Read(10))
    );
    assert!(h.done() && h.authenticated());
    assert_eq!(gss.unused(), 0);
}

/// In NEC's way the level goes and comes back as it is, in a message of
/// its own length 1.
#[test]
fn nec_sends_the_level_unwrapped() {
    let gss = Scripted::leaked();
    gss.then(Answer::Stepped(complete(false, true), b"only".to_vec()))
        .then(Answer::Initiator(Ok(b"u".to_vec())));
    let mut h = offered(gss, true);
    assert_eq!(
        picked(&mut h),
        Ok(vec![
            "SOCKS5 server authenticated user u with GSS-API.".to_owned(),
            "SOCKS5 server supports GSS-API integrity data protection.".to_owned(),
        ])
    );
    assert_eq!(send(&mut h), b"\x01\x01\x00\x04only\x01\x02\x00\x01\x01");
    let (took, lines) = take_saying(&mut h, b"\x01\x02\x00\x01\x00");
    assert_eq!(took, Ok(Took::Read(5)));
    assert_eq!(
        lines,
        ["SOCKS5 access without GSS-API data protection granted."]
    );
    assert_eq!(
        gss.asked(),
        [rcmd(), Asked::Step(None), Asked::Initiator, Asked::Dropped]
    );
    // A level not one byte long.
    let gss = Scripted::leaked();
    gss.then(Answer::Stepped(complete(false, false), Vec::new()))
        .then(Answer::Initiator(Ok(b"u".to_vec())));
    let mut h = offered(gss, true);
    let lines = picked(&mut h).unwrap();
    assert_eq!(
        lines[1],
        "SOCKS5 server supports GSS-API no data protection."
    );
    // No token: the level alone.
    assert_eq!(send(&mut h), b"\x01\x02\x00\x01\x00");
    let e = gss_error(h.take(b"\x01\x02\x00\x02\x00\x00").unwrap_err());
    assert_eq!(
        e.step.to_string(),
        "Invalid GSS-API encryption response length (2)."
    );
    assert_eq!(e.status, None);
}

/// A level granted is protection the rest of the connection would
/// need: the request goes, then the handshake fails, the context kept.
#[test]
fn protection_granted_fails_once_the_request_went() {
    for (granted, granted_as) in [
        (b"\x01", "with GSS-API integrity"),
        (b"\x02", "with GSS-API confidentiality"),
        (b"\x07", "with GSS-API confidentiality"),
    ] {
        let gss = Scripted::leaked();
        gss.then(Answer::Stepped(complete(true, true), b"t".to_vec()))
            .then(Answer::Initiator(Ok(b"u".to_vec())))
            .then(Answer::Wrapped(Ok(b"w".to_vec())))
            .then(Answer::Unwrapped(Ok(granted.to_vec())));
        let mut h = offered(gss, false);
        picked(&mut h).unwrap();
        send(&mut h);
        let (took, lines) = take_saying(&mut h, b"\x01\x02\x00\x01w");
        assert_eq!(took, Ok(Took::Read(5)));
        assert_eq!(
            lines,
            [format!("SOCKS5 access {granted_as} protection granted.")]
        );
        assert_eq!(send(&mut h), b"\x05\x01\x00\x03\x0chost.example\x23\x1e");
        let e = h.take(b"").unwrap_err();
        assert_eq!(e, SocksError::GssProtection);
        assert_eq!(e.code(), Some(ProxyError::GssapiProtection));
        assert_eq!(said(&e), "SOCKS5 GSS-API protection not yet implemented.");
        assert!(!gss.asked().contains(&Asked::Dropped));
    }
}

/// Each step says anew what the context can protect, and the last one
/// says which level is asked for.
#[test]
fn the_level_asked_is_the_last_step_s() {
    let gss = Scripted::leaked();
    gss.then(Answer::Stepped(
        Step {
            progress: Progress::Continue,
            confidentiality: true,
            integrity: true,
        },
        b"a".to_vec(),
    ))
    .then(Answer::Stepped(complete(false, true), Vec::new()))
    .then(Answer::Initiator(Ok(b"u".to_vec())))
    .then(Answer::Wrapped(Ok(b"w".to_vec())));
    let mut h = offered(gss, false);
    picked(&mut h).unwrap();
    send(&mut h);
    let (took, lines) = take_saying(&mut h, b"\x01\x01\x00\x01b");
    assert_eq!(took, Ok(Took::Read(5)));
    assert_eq!(
        lines[1],
        "SOCKS5 server supports GSS-API integrity data protection."
    );
    // The last step made no token: the level alone.
    assert_eq!(send(&mut h), b"\x01\x02\x00\x01w");
    let asked = gss.asked();
    assert_eq!(asked[asked.len() - 1], Asked::Wrap(b"\x01".to_vec()));
}

/// A step that makes no token but wants the proxy's sends nothing and
/// waits for it; one neither complete nor wanting more counts as done.
#[test]
fn an_empty_token_is_not_sent() {
    let gss = Scripted::leaked();
    gss.then(Answer::Stepped(
        Step {
            progress: Progress::Continue,
            confidentiality: false,
            integrity: false,
        },
        Vec::new(),
    ))
    .then(Answer::Stepped(
        Step {
            progress: Progress::Other,
            confidentiality: false,
            integrity: false,
        },
        Vec::new(),
    ))
    .then(Answer::Initiator(Ok(b"u".to_vec())))
    .then(Answer::Wrapped(Ok(b"w".to_vec())));
    let mut h = offered(gss, false);
    picked(&mut h).unwrap();
    assert_eq!(send(&mut h), b"");
    assert_eq!(h.take(b""), Ok(Took::Need(4)));
    assert_eq!(h.take(b"\x01\x01\x00\x01x"), Ok(Took::Read(5)));
    assert_eq!(send(&mut h), b"\x01\x02\x00\x01w");
}

/// The service is the credentials' if they name one and are kept, as a
/// host-based one at the proxy, or a name as it is if it holds a `/`;
/// else `rcmd`. The context is mutual, and delegates as asked.
#[test]
fn the_service_is_the_credentials_or_rcmd() {
    let start = |service: &'static [u8], auth: Socks5Auth, delegation| {
        let gss = Scripted::leaked();
        gss.then(Answer::Fails(GssFailure::status(
            GssCall::InitSecContext,
            status(1, 2),
        )));
        let d = dest(b"h", Resolved::Remote);
        let c = Some(Creds {
            user: b"u",
            password: b"p",
            service,
        });
        let library = Some(GssMethod {
            library: gss,
            nec: false,
            delegation,
        });
        let mut h = Handshake::new(Version::V5Hostname, d, c, auth, library).unwrap();
        send(&mut h);
        picked(&mut h).unwrap_err();
        gss.asked().remove(0)
    };
    let all = Socks5Auth::default();
    let none = Delegation::default();
    let service = |service: &[u8], flags| Asked::Context {
        service: service.to_vec(),
        host: PROXY.to_vec(),
        mech: Mech::Kerberos,
        flags,
    };
    assert_eq!(start(b"", all, none), rcmd());
    assert_eq!(start(b"svc", all, none), service(b"svc", mutual()));
    assert_eq!(
        start(b"svc/host.example", all, none),
        Asked::Named {
            name: b"svc/host.example".to_vec(),
            mech: Mech::Kerberos,
            flags: mutual(),
        }
    );
    // Without basic authentication the credentials, and their service,
    // are let go, as C unlinks them.
    let gss_only = Socks5Auth {
        basic: false,
        ..all
    };
    assert_eq!(start(b"svc", gss_only, none), rcmd());
    let delegating = Delegation {
        by_policy: true,
        always: true,
    };
    assert_eq!(
        start(b"", all, delegating),
        service(
            b"rcmd",
            Flags {
                mutual: true,
                delegate_by_policy: true,
                delegate: true,
            }
        )
    );
}

/// The library's failures: the call and its status, then C's words for
/// the step.
#[test]
fn the_library_s_failures_are_said_as_c() {
    let failing = |answers: Vec<Answer>, proxy_says: &[&[u8]]| {
        let gss = Scripted::leaked();
        for a in answers {
            gss.then(a);
        }
        let mut h = offered(gss, false);
        let mut result = picked(&mut h).map(|_| ());
        for reply in proxy_says {
            if result.is_err() {
                break;
            }
            send(&mut h);
            result = h.take(reply).map(|_| ());
        }
        gss_error(result.unwrap_err())
    };
    let fails = |call| Answer::Fails(GssFailure::status(call, status(9, 8)));
    let e = failing(vec![fails(GssCall::InitSecContext)], &[]);
    assert_eq!(e.status, Some((GssCall::InitSecContext, status(9, 8))));
    assert_eq!(e.step.to_string(), "Failed to initialize GSS-API token.");
    // Failing on the proxy's token.
    let e = failing(
        vec![
            Answer::Token(Progress::Continue, b"t".to_vec()),
            fails(GssCall::InitSecContext),
        ],
        &[b"\x01\x01\x00\x01x"],
    );
    assert_eq!(e.step.to_string(), "Failed to initialize GSS-API token.");
    let done = || Answer::Stepped(complete(true, true), b"t".to_vec());
    let e = failing(
        vec![
            done(),
            Answer::Initiator(Err(GssFailure::status(
                GssCall::InquireContext,
                status(9, 8),
            ))),
        ],
        &[],
    );
    assert_eq!(e.status, Some((GssCall::InquireContext, status(9, 8))));
    assert_eq!(e.step.to_string(), "Failed to determine username.");
    let e = failing(
        vec![
            done(),
            Answer::Initiator(Err(GssFailure::status(GssCall::DisplayName, status(9, 8)))),
        ],
        &[],
    );
    assert_eq!(e.status, Some((GssCall::DisplayName, status(9, 8))));
    let user = || Answer::Initiator(Ok(b"u".to_vec()));
    let e = failing(
        vec![
            done(),
            user(),
            Answer::Wrapped(Err(GssFailure::status(GssCall::Wrap, status(9, 8)))),
        ],
        &[],
    );
    assert_eq!(e.status, Some((GssCall::Wrap, status(9, 8))));
    assert_eq!(
        e.step.to_string(),
        "Failed to wrap GSS-API encryption value into token."
    );
    let wrapped = || Answer::Wrapped(Ok(b"w".to_vec()));
    let e = failing(
        vec![
            done(),
            user(),
            wrapped(),
            Answer::Unwrapped(Err(GssFailure::status(GssCall::Unwrap, status(9, 8)))),
        ],
        &[b"\x01\x02\x00\x01x"],
    );
    assert_eq!(e.status, Some((GssCall::Unwrap, status(9, 8))));
    assert_eq!(
        e.step.to_string(),
        "Failed to unwrap GSS-API encryption value into token."
    );
    let e = failing(
        vec![done(), user(), wrapped(), Answer::Unwrapped(Ok(Vec::new()))],
        &[b"\x01\x02\x00\x01x"],
    );
    assert_eq!(
        e.step.to_string(),
        "Invalid GSS-API encryption response length (0)."
    );
    assert_eq!(e.status, None);
    // Out of memory in the library: nothing said but the method's end.
    let e = failing(
        vec![Answer::Fails(GssFailure::out_of_memory(
            GssCall::InitSecContext,
        ))],
        &[],
    );
    assert_eq!((e.status, e.step), (None, Failed::Silently));
    // The name not imported.
    let gss = Scripted::leaked();
    gss.import_fails(status(5, 6));
    let mut h = offered(gss, false);
    let e = gss_error(picked(&mut h).unwrap_err());
    assert_eq!(e.status, Some((GssCall::ImportName, status(5, 6))));
    assert_eq!(e.step.to_string(), "Failed to create service name.");
    assert_eq!(
        GssError::call_name(GssCall::ImportName),
        "gss_import_name()"
    );
    assert_eq!(GssError::call_name(GssCall::Unwrap), "gss_unwrap");
}

/// A token too long for its 16-bit length fails without the library's
/// words.
#[test]
fn a_token_must_fit_its_length() {
    let gss = Scripted::leaked();
    gss.then_token(&[b'x'; 0xffff]);
    let mut h = offered(gss, false);
    picked(&mut h).unwrap();
    let out = send(&mut h);
    assert_eq!(&out[..4], b"\x01\x01\xff\xff");
    assert_eq!(out.len(), 4 + 0xffff);
    let gss = Scripted::leaked();
    gss.then_token(&[b'x'; 0x10000]);
    let mut h = offered(gss, false);
    let e = gss_error(picked(&mut h).unwrap_err());
    assert_eq!((e.status, e.step), (None, Failed::InitToken));
}

/// The proxy's refusals of either message, read from its 4 bytes before
/// the token: type 255 rejects, any other type but the one awaited is
/// invalid, a zero length too; its version is not looked at.
#[test]
fn the_proxy_s_messages_are_checked_as_c() {
    let auth = |reply: &[u8]| {
        let gss = Scripted::leaked();
        gss.then_token(b"t");
        let mut h = offered(gss, false);
        picked(&mut h).unwrap();
        send(&mut h);
        h.take(reply).map_err(gss_error)
    };
    let step = |r: Result<Took, GssError>| r.unwrap_err().step.to_string();
    assert_eq!(
        step(auth(b"\x01\xff\x00\x05")),
        "User was rejected by the SOCKS5 server (1 255)."
    );
    assert_eq!(
        step(auth(b"\x07\x03\x00\x01")),
        "Invalid GSS-API authentication response type (7 3)."
    );
    assert_eq!(
        step(auth(b"\x01\x02\x00\x01")),
        "Invalid GSS-API authentication response type (1 2)."
    );
    assert_eq!(
        step(auth(b"\x01\x01\x00\x00")),
        "Invalid zero-length GSS-API authentication token."
    );
    assert_eq!(auth(b"\x09\x01\x00\x02"), Ok(Took::Need(6)));
    let level = |reply: &[u8]| {
        let gss = Scripted::leaked();
        gss.then(Answer::Stepped(complete(false, false), Vec::new()))
            .then(Answer::Initiator(Ok(b"u".to_vec())))
            .then(Answer::Wrapped(Ok(b"w".to_vec())));
        let mut h = offered(gss, false);
        picked(&mut h).unwrap();
        send(&mut h);
        h.take(reply).map_err(gss_error)
    };
    assert_eq!(
        step(level(b"\x05\xff\x00\x01")),
        "User was rejected by the SOCKS5 server (5 255)."
    );
    assert_eq!(
        step(level(b"\x01\x01\x00\x01")),
        "Invalid GSS-API encryption response type (1 1)."
    );
    assert_eq!(
        step(level(b"\x01\x02\x00\x00")),
        "Invalid zero-length GSS-API encryption token."
    );
}

/// A send or a read that fails while a GSS-API message is under way is
/// said as C says it of that message and that part of it.
#[test]
fn a_failed_send_or_read_is_said_of_its_message() {
    let gss = Scripted::leaked();
    gss.then_token(b"tok")
        .then(Answer::Stepped(complete(false, false), b"fin".to_vec()))
        .then(Answer::Initiator(Ok(b"u".to_vec())))
        .then(Answer::Wrapped(Ok(b"lvl".to_vec())));
    let mut h = offered(gss, false);
    assert_eq!(h.gss_send_failed(), None);
    picked(&mut h).unwrap();
    let sending = |h: &Handshake| gss_error(h.gss_send_failed().unwrap()).step;
    assert_eq!(sending(&h), Failed::SendAuthRequest);
    h.sent(3);
    assert_eq!(sending(&h), Failed::SendAuthRequest);
    h.sent(1);
    assert_eq!(sending(&h), Failed::SendAuthToken);
    h.sent(3);
    let reading = |h: &Handshake, n| gss_error(h.gss_recv_failed(n).unwrap()).step;
    assert_eq!(reading(&h, 0), Failed::RecvAuthResponse);
    assert_eq!(reading(&h, 3), Failed::RecvAuthResponse);
    assert_eq!(reading(&h, 4), Failed::RecvAuthToken);
    h.take(b"\x01\x01\x00\x01x").unwrap();
    // The last token, then the level: 7 bytes, then 7.
    assert_eq!(sending(&h), Failed::SendAuthRequest);
    h.sent(7);
    assert_eq!(sending(&h), Failed::SendLevelRequest);
    h.sent(4);
    assert_eq!(sending(&h), Failed::SendLevel);
    h.sent(3);
    assert_eq!(reading(&h, 2), Failed::RecvLevelResponse);
    assert_eq!(reading(&h, 5), Failed::RecvLevel);
    // The level alone.
    let gss = Scripted::leaked();
    gss.then(Answer::Stepped(complete(false, false), Vec::new()))
        .then(Answer::Initiator(Ok(b"u".to_vec())));
    let mut h = offered(gss, true);
    picked(&mut h).unwrap();
    assert_eq!(sending(&h), Failed::SendLevelRequest);
    h.sent(4);
    assert_eq!(sending(&h), Failed::SendLevel);
    h.sent(1);
    h.take(b"\x01\x02\x00\x01\x00").unwrap();
    // The request is not GSS-API's.
    assert_eq!(h.gss_send_failed(), None);
    assert_eq!(h.gss_recv_failed(0), None);
}

/// Every GSS-API failure is the proxy's GSS-API error, said in its own
/// lines.
#[test]
fn gss_api_failures_have_their_code() {
    let e = SocksError::Gss(GssError {
        status: None,
        step: Failed::InitToken,
    });
    assert_eq!(e.code(), Some(ProxyError::Gssapi));
    assert!(e.said().is_none());
    for (step, text) in [
        (Failed::Silently, ""),
        (
            Failed::SendAuthRequest,
            "Failed to send GSS-API authentication request.",
        ),
        (
            Failed::SendAuthToken,
            "Failed to send GSS-API authentication token.",
        ),
        (
            Failed::RecvAuthResponse,
            "Failed to receive GSS-API authentication response.",
        ),
        (
            Failed::RecvAuthToken,
            "Failed to receive GSS-API authentication token.",
        ),
        (
            Failed::SendLevelRequest,
            "Failed to send GSS-API encryption request.",
        ),
        (Failed::SendLevel, "Failed to send GSS-API encryption type."),
        (
            Failed::RecvLevelResponse,
            "Failed to receive GSS-API encryption response.",
        ),
        (
            Failed::RecvLevel,
            "Failed to receive GSS-API encryption type.",
        ),
    ] {
        assert_eq!(step.to_string(), text);
    }
}
