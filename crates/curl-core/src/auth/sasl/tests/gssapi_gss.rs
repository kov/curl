//! GSSAPI over a scripted GSS-API library, as C's builds with one log
//! in with it (`curl_sasl.c`'s GSSAPI states, `lib/vauth/krb5_gssapi.c`'s
//! messages).

use super::*;
use crate::gss::testing::{Answer, Asked, Scripted};
use crate::gss::{Flags, GssCall, GssFailure, GssStatus, Mech};

/// A step's context over `creds` with `gss`, delegating as `delegation`
/// says, keeping what is said.
fn with_gss<R>(
    gss: &'static Scripted,
    creds: Option<Secret<'_>>,
    sasl_ir: bool,
    delegation: Delegation,
    f: impl FnOnce(&mut Ctx<'_>) -> R,
) -> (R, Vec<(Say, String)>) {
    let mut lines = Vec::new();
    let mut draw = |out: &mut [u8]| {
        out.fill(7);
        Ok(())
    };
    let mut said = |who: Say, args: core::fmt::Arguments<'_>| lines.push((who, args.to_string()));
    let mut cx = Ctx {
        creds,
        sasl_ir,
        host: b"mail.example",
        port: 110,
        random: &mut draw,
        security: Some(Security::Gss(gss)),
        delegation,
        said: &mut said,
    };
    let r = f(&mut cx);
    (r, lines)
}

/// `with_gss`, delegating nothing.
fn with<R>(
    gss: &'static Scripted,
    creds: Option<Secret<'_>>,
    sasl_ir: bool,
    f: impl FnOnce(&mut Ctx<'_>) -> R,
) -> (R, Vec<(Say, String)>) {
    with_gss(gss, creds, sasl_ir, Delegation::default(), f)
}

/// The lines said for any verbose transfer.
fn infos(said: Vec<(Say, String)>) -> Vec<String> {
    said.into_iter()
        .filter(|(who, _)| *who == Say::Info)
        .map(|(_, line)| line)
        .collect()
}

/// The context asked for `service@mail.example`, by Kerberos, with
/// `flags`.
fn context(service: &[u8], flags: Flags) -> Asked {
    Asked::Context {
        service: service.to_vec(),
        host: b"mail.example".to_vec(),
        mech: Mech::Kerberos,
        flags,
    }
}

fn status(major: u32, minor: u32) -> GssStatus {
    GssStatus::new(major, minor)
}

/// SASL offering GSSAPI, DIGEST-MD5 and PLAIN, preferring any.
fn offering() -> Sasl {
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::GSSAPI.or(Mechs::DIGEST_MD5).or(Mechs::PLAIN));
    sasl
}

/// GSSAPI comes after EXTERNAL and before DIGEST-MD5: the user's token,
/// of a context with `pop@host` by Kerberos asking no mutual
/// authentication, made once the server prompts; then the server's
/// layer answered with none, no receive buffer and the identity acted
/// for, wrapped; each change of state by C's names.
#[test]
fn gssapi_logs_in_by_the_user_s_token_then_the_layer() {
    let gss = Scripted::leaked();
    let creds = Secret::new(b"", b"", b"").with_authzid(b"boss");
    let mut sasl = offering();
    let (p, said) = with(gss, Some(creds), false, |cx| sasl.start_sent(cx, false));
    assert_eq!(p, Ok(auth("GSSAPI", None)));
    assert_eq!(said.len(), 1);
    assert!(said[0].1.ends_with("from STOP to GSSAPI"), "{said:?}");
    assert_eq!(gss.asked(), []);

    gss.then_token(b"ap-req");
    let (p, said) = with(gss, Some(creds), false, |cx| {
        sasl.step_sent(cx, Code::Continue, b"")
    });
    assert_eq!(p, Ok(cont(b"ap-req")));
    assert!(
        said[0].1.ends_with("from GSSAPI to GSSAPI_TOKEN"),
        "{said:?}"
    );
    assert_eq!(
        gss.asked(),
        [context(b"pop", Flags::default()), Asked::Step(None)]
    );
    assert_eq!(gss.bindings(), [None]);
    assert!(sasl.wants_challenge());

    gss.then(Answer::Unwrapped(Ok(vec![7, 0, 0x10, 0])))
        .then(Answer::Wrapped(Ok(b"wrapped".to_vec())));
    let (p, said) = with(gss, Some(creds), false, |cx| {
        sasl.step_sent(cx, Code::Continue, &b64(b"layers"))
    });
    assert_eq!(p, Ok(cont(b"wrapped")));
    assert!(
        said[0].1.ends_with("from GSSAPI_TOKEN to FINAL"),
        "{said:?}"
    );
    assert_eq!(
        gss.asked(),
        [
            Asked::Unwrap(b"layers".to_vec()),
            Asked::Wrap(b"\x01\0\0\0boss".to_vec()),
        ]
    );
    let (p, _) = with(gss, Some(creds), false, |cx| {
        sasl.step_sent(cx, Code::Final, b"")
    });
    assert_eq!(p, Ok(Progress::Done));
    drop(sasl);
    assert_eq!(gss.asked(), [Asked::Dropped]);
    assert_eq!(gss.unused(), 0);
}

/// With an initial response asked, the user's token goes with the
/// command, of a context with the service named, delegating as the
/// transfer asks; the user and password given are not the library's.
/// A token of no bytes goes as none, and the continuation makes the
/// next of the same context, as an empty line.
#[test]
fn the_initial_response_is_the_user_s_token() {
    let gss = Scripted::leaked();
    let creds = Secret::new(b"user@REALM", b"pw", b"service");
    let both = Delegation {
        by_policy: true,
        always: true,
    };
    let mut sasl = offering();
    gss.then(Answer::Token(
        crate::gss::Progress::Complete,
        b"ap-req".to_vec(),
    ));
    let (p, _) = with_gss(gss, Some(creds), true, both, |cx| {
        sasl.start_sent(cx, false)
    });
    assert_eq!(p, Ok(auth("GSSAPI", Some(b"ap-req"))));
    assert_eq!(sasl.state, State::GssapiToken);
    let delegating = Flags {
        mutual: false,
        delegate_by_policy: true,
        delegate: true,
    };
    assert_eq!(
        gss.asked(),
        [context(b"service", delegating), Asked::Step(None)]
    );
    drop(sasl);
    assert_eq!(gss.asked(), [Asked::Dropped]);

    let mut sasl = offering();
    gss.then_token(b"");
    let (p, _) = with(gss, Some(creds), true, |cx| sasl.start_sent(cx, false));
    assert_eq!(p, Ok(auth("GSSAPI", None)));
    assert_eq!(sasl.state, State::Gssapi);
    assert_eq!(gss.asked().len(), 2);
    gss.then_token(b"");
    let (p, _) = with(gss, Some(creds), true, |cx| {
        sasl.step_sent(cx, Code::Continue, b"")
    });
    assert_eq!(p, Ok(Progress::Sends(Send::Continue(Vec::new()))));
    assert_eq!(gss.asked(), [Asked::Step(None)]);
    assert_eq!(gss.unused(), 0);
}

/// An initial response too long for the command line is dropped, and
/// the prompt for it steps the context that made it again rather than a
/// new one, as C steps the one it keeps: the library's refusal of that
/// fails the login, said as C says it.
#[test]
fn a_token_too_long_to_go_first_steps_the_same_context_again() {
    let gss = Scripted::leaked();
    let mut sasl = offering();
    gss.then_token(&[b'k'; 300]);
    let (p, _) = with(gss, Some(Secret::new(b"", b"", b"")), true, |cx| {
        sasl.start_sent(cx, false)
    });
    assert_eq!(p, Ok(auth("GSSAPI", None)));
    assert_eq!(sasl.state, State::Gssapi);
    assert_eq!(gss.asked().len(), 2);

    let established = GssFailure::status(GssCall::InitSecContext, status(0x10_0000, 0));
    gss.then(Answer::Fails(established));
    let (p, said) = with(gss, Some(Secret::new(b"", b"", b"")), true, |cx| {
        sasl.step(cx, Code::Continue, b"")
    });
    assert_eq!(p, Err(SaslError::AuthError));
    assert_eq!(gss.asked(), [Asked::Step(None)]);
    assert_eq!(
        infos(said.clone()),
        ["gss_init_sec_context() failed: status 1048576.0. "]
    );
    assert!(said[1].1.ends_with("from GSSAPI to STOP"), "{said:?}");
    assert_eq!(sasl.state, State::Stop);
    assert_eq!(gss.unused(), 0);
}

/// GSSAPI is passed over without a library and for a user naming no
/// domain; a GSS-API library has Kerberos without being asked.
#[test]
fn gssapi_needs_a_library_and_a_domain() {
    let gss = Scripted::leaked();
    let pick = |creds: Secret<'_>, security: Option<Security>| {
        let mut sasl = offering();
        let mut said = |_: Say, _: core::fmt::Arguments<'_>| {};
        let mut draw = |_: &mut [u8]| Ok(());
        let mut cx = Ctx {
            creds: Some(creds),
            sasl_ir: false,
            host: b"h",
            port: 110,
            random: &mut draw,
            security,
            delegation: Delegation::default(),
            said: &mut said,
        };
        sasl.start_sent(&mut cx, false).unwrap()
    };
    let domain = Secret::new(b"user@REALM", b"pw", b"");
    assert_eq!(pick(domain, None), auth("DIGEST-MD5", None));
    let gss = Some(Security::Gss(gss));
    assert_eq!(pick(domain, gss), auth("GSSAPI", None));
    let plain = Secret::new(b"user", b"pw", b"");
    assert_eq!(pick(plain, gss), auth("DIGEST-MD5", None));
}

/// With a GSS-API library DIGEST-MD5 is the core's own, as in C's builds
/// without SSPI.
#[test]
fn digest_md5_beside_gss_api_is_the_core_s() {
    let gss = Scripted::leaked();
    let creds = Secret::new(b"user", b"secret", b"");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::DIGEST_MD5);
    let chlg = b64(b"realm=\"curl\",nonce=\"n\",algorithm=md5-sess,qop=\"auth\"");
    let (p, _) = with(gss, Some(creds), false, |cx| {
        sasl.start_sent(cx, false).unwrap();
        sasl.step_sent(cx, Code::Continue, &chlg)
    });
    let Ok(Progress::Sends(Send::Continue(resp))) = p else {
        panic!("{p:?}");
    };
    let resp = crate::base64::decode(&resp).unwrap().unwrap();
    assert!(resp.starts_with(b"username=\"user\",realm=\"curl\""));
    assert_eq!(gss.asked(), []);
}

/// A security layer that cannot be read cancels the exchange, said as C
/// says it: empty, not base64, not unwrapped, not 4 bytes, or not
/// offering to go without a layer.
#[test]
fn a_layer_that_cannot_be_read_cancels() {
    let gss = Scripted::leaked();
    let creds = Secret::new(b"", b"", b"");
    let at_layer = || {
        let mut sasl = offering();
        gss.then_token(b"t");
        let (p, _) = with(gss, Some(creds), true, |cx| sasl.start_sent(cx, false));
        assert_eq!(p, Ok(auth("GSSAPI", Some(b"t"))));
        sasl
    };
    let failure = |sasl: &mut Sasl, message: &[u8]| {
        let (p, said) = with(gss, Some(creds), true, |cx| {
            sasl.step_sent(cx, Code::Continue, message)
        });
        assert_eq!(p, Ok(Progress::Sends(Send::Cancel)));
        assert_eq!(sasl.state, State::Cancel);
        infos(said)
    };
    let mut sasl = at_layer();
    assert_eq!(
        failure(&mut sasl, b""),
        ["GSSAPI handshake failure (empty security message)"]
    );
    let mut sasl = at_layer();
    assert_eq!(failure(&mut sasl, b"!!"), Vec::<String>::new());
    let refused = GssFailure::status(GssCall::Unwrap, status(0x6_0000, 7));
    let mut sasl = at_layer();
    gss.then(Answer::Unwrapped(Err(refused)));
    assert_eq!(
        failure(&mut sasl, &b64(b"x")),
        ["gss_unwrap() failed: status 393216.7. "]
    );
    for (unwrapped, why) in [
        (vec![1, 0, 0], "invalid security data"),
        (vec![1, 0, 0, 0, 0], "invalid security data"),
        (vec![6, 0, 0, 0], "invalid security layer"),
    ] {
        let mut sasl = at_layer();
        gss.then(Answer::Unwrapped(Ok(unwrapped)));
        assert_eq!(
            failure(&mut sasl, &b64(b"x")),
            [format!("GSSAPI handshake failure ({why})")]
        );
    }
    gss.asked();
    assert_eq!(gss.unused(), 0);
}

/// The library's refusals fail the login as C's: the name not imported,
/// the token not made, the answer not wrapped, each said with what the
/// library says of it; no memory, unsaid.
#[test]
fn refusals_are_c_s() {
    let gss = Scripted::leaked();
    let creds = Secret::new(b"", b"", b"");
    let start = |sasl: &mut Sasl| with(gss, Some(creds), true, |cx| sasl.start(cx, false));

    gss.import_fails(status(0x2_0000, 3));
    let mut sasl = offering();
    let (r, said) = start(&mut sasl);
    assert_eq!(r, Err(SaslError::AuthError));
    assert_eq!(infos(said), ["gss_import_name() failed: status 131072.3. "]);

    let expired = GssFailure::status(GssCall::InitSecContext, status(0xd_0000, 9));
    gss.then(Answer::Fails(expired));
    let mut sasl = offering();
    let (r, said) = start(&mut sasl);
    assert_eq!(r, Err(SaslError::AuthError));
    assert_eq!(
        infos(said),
        ["gss_init_sec_context() failed: status 851968.9. "]
    );

    // Delegation by policy the library cannot do is said before the
    // step's failure, as C says it before the call.
    gss.then(Answer::Notes(crate::gss::GssNote::NoDelegationPolicy))
        .then(Answer::Fails(expired));
    let mut sasl = offering();
    let (r, said) = start(&mut sasl);
    assert_eq!(r, Err(SaslError::AuthError));
    assert_eq!(
        infos(said),
        [
            "WARNING: support for CURLGSSAPI_DELEGATION_POLICY_FLAG not compiled in",
            "gss_init_sec_context() failed: status 851968.9. "
        ]
    );

    gss.then(Answer::Fails(GssFailure::out_of_memory(
        GssCall::InitSecContext,
    )));
    let mut sasl = offering();
    let (r, said) = start(&mut sasl);
    assert_eq!(r, Err(SaslError::OutOfMemory));
    assert_eq!(infos(said), Vec::<String>::new());

    for (layer, want, line) in [
        (
            vec![
                Answer::Unwrapped(Ok(vec![1, 0, 0, 0])),
                Answer::Wrapped(Err(GssFailure::status(GssCall::Wrap, status(0x7_0000, 1)))),
            ],
            SaslError::AuthError,
            Some("gss_wrap() failed: status 458752.1. "),
        ),
        (
            vec![Answer::Unwrapped(Err(GssFailure::out_of_memory(
                GssCall::Unwrap,
            )))],
            SaslError::OutOfMemory,
            None,
        ),
        (
            vec![
                Answer::Unwrapped(Ok(vec![1, 0, 0, 0])),
                Answer::Wrapped(Err(GssFailure::out_of_memory(GssCall::Wrap))),
            ],
            SaslError::OutOfMemory,
            None,
        ),
    ] {
        let mut sasl = offering();
        gss.then_token(b"t");
        let (r, _) = start(&mut sasl);
        assert_eq!(r, Ok(auth("GSSAPI", Some(b"t"))));
        with(gss, Some(creds), true, |cx| sasl.sent(cx, true));
        for a in layer {
            gss.then(a);
        }
        let (r, said) = with(gss, Some(creds), true, |cx| {
            sasl.step(cx, Code::Continue, &b64(b"x"))
        });
        assert_eq!(r, Err(want));
        let said = infos(said);
        assert_eq!(said.first().map(String::as_str), line, "{said:?}");
    }
    gss.asked();
    assert_eq!(gss.unused(), 0);
}

/// GSSAPI not chosen is said as C's builds with GSS-API say it: built
/// and supported, so only a missing user would be said, and a user
/// without a domain is not.
#[test]
fn gssapi_not_chosen_is_said_why() {
    let gss = Scripted::leaked();
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::GSSAPI);
    let user = Some(Secret::new(b"user", b"pw", b""));
    let ((), said) = with(gss, user, false, |cx| sasl.blocked(cx));
    assert_eq!(
        infos(said),
        ["SASL: no auth mechanism offered could be selected"]
    );
    assert_eq!(gss.asked(), []);
}
