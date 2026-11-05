//! GSSAPI over a scripted SSPI, as C's Windows build logs in with it
//! (`curl_sasl.c`'s GSSAPI states, `lib/vauth/krb5_sspi.c`'s messages).

use super::*;
use crate::sspi::testing::{Answer, Asked, Scripted};
use crate::sspi::{Initialized, Sizes};

/// A step's context over `creds` with `sspi`, keeping what is said.
fn with_sspi<R>(
    sspi: &'static Scripted,
    creds: Option<Secret<'_>>,
    sasl_ir: bool,
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
        sspi: Some(sspi),
        said: &mut said,
    };
    let r = f(&mut cx);
    (r, lines)
}

fn made(status: SecStatus, token: &[u8]) -> Answer {
    Answer::Initialized(Ok((
        Initialized {
            status,
            confidentiality: false,
            integrity: false,
        },
        token.to_vec(),
    )))
}

/// The user's token asked for `target`: a new context, natively, no
/// mutual authentication, in the package's room.
fn first_token(target: &[u8]) -> Asked {
    Asked::Initialize {
        target: target.to_vec(),
        flags: Req::default(),
        native: true,
        fresh: true,
        input: vec![],
        output: Output::Room(48),
    }
}

const SIZES: Sizes = Sizes {
    trailer: 12,
    block: 8,
};

/// SASL offering GSSAPI, DIGEST-MD5 and PLAIN, preferring any.
fn offering() -> Sasl {
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::GSSAPI.or(Mechs::DIGEST_MD5).or(Mechs::PLAIN));
    sasl
}

/// The user names a domain where its first `\`, `/` or `@` is neither
/// its first byte nor its last; no user is the process's, which has one.
#[test]
fn a_domain_is_named_as_c_reads_it() {
    for (user, has) in [
        (&b""[..], true),
        (b"dom\\user", true),
        (b"dom/user", true),
        (b"user@dom", true),
        (b"user", false),
        (b"\\user", false),
        (b"user@", false),
        (b"a@b", true),
        (b"@a\\b", false),
    ] {
        assert_eq!(krb5::user_contains_domain(user), has, "{user:?}");
    }
}

/// GSSAPI comes after EXTERNAL and before DIGEST-MD5: the user's token
/// for `pop/host` as the user given, by Kerberos; then the server's
/// layer answered with none, no receive buffer and the identity acted
/// for, wrapped; each change of state by C's names.
#[test]
fn gssapi_logs_in_by_the_user_s_token_then_the_layer() {
    let sspi = Scripted::leaked();
    let creds = Secret::new(b"dom\\user", b"pw", b"").with_authzid(b"boss");
    let mut sasl = offering();
    sspi.then(Answer::MaxToken(Ok(48)));
    let (p, said) = with_sspi(sspi, Some(creds), false, |cx| sasl.start_sent(cx, false));
    assert_eq!(p, Ok(auth("GSSAPI", None)));
    assert_eq!(said.len(), 1);
    assert!(said[0].1.ends_with("from STOP to GSSAPI"), "{said:?}");
    assert_eq!(sspi.asked(), [Asked::MaxToken(Package::Kerberos)]);

    sspi.then(Answer::MaxToken(Ok(48)))
        .then(Answer::Credentials(Ok(())))
        .then(made(SecStatus::CONTINUE_NEEDED, b"ap-req"));
    let (p, said) = with_sspi(sspi, Some(creds), false, |cx| {
        sasl.step_sent(cx, Code::Continue, b"")
    });
    assert_eq!(p, Ok(cont(b"ap-req")));
    assert!(
        said[0].1.ends_with("from GSSAPI to GSSAPI_TOKEN"),
        "{said:?}"
    );
    assert_eq!(
        sspi.asked(),
        [
            Asked::MaxToken(Package::Kerberos),
            Asked::Credentials(
                Package::Kerberos,
                Some([
                    b"user".to_vec(),
                    b"dom".to_vec(),
                    b"pw".to_vec(),
                    Vec::new()
                ])
            ),
            first_token(b"pop/mail.example"),
        ]
    );
    assert!(sasl.wants_challenge());

    sspi.then(Answer::Sizes(Ok(SIZES)))
        .then(Answer::Unwrapped(Ok(vec![7, 0, 0x10, 0])))
        .then(Answer::Wrapped(Ok(b"wrapped".to_vec())));
    let (p, said) = with_sspi(sspi, Some(creds), false, |cx| {
        sasl.step_sent(cx, Code::Continue, &b64(b"layers"))
    });
    assert_eq!(p, Ok(cont(b"wrapped")));
    assert!(
        said[0].1.ends_with("from GSSAPI_TOKEN to FINAL"),
        "{said:?}"
    );
    assert_eq!(
        sspi.asked(),
        [
            Asked::Sizes,
            Asked::Unwrap(b"layers".to_vec()),
            Asked::Wrap(b"\x01\0\0\0boss".to_vec()),
        ]
    );
    let (p, _) = with_sspi(sspi, Some(creds), false, |cx| {
        sasl.step_sent(cx, Code::Final, b"")
    });
    assert_eq!(p, Ok(Progress::Done));
    drop(sasl);
    assert_eq!(sspi.asked(), [Asked::Dropped]);
    assert_eq!(sspi.unused(), 0);
}

/// With an initial response asked, the user's token goes with the
/// command and the exchange waits for the layer, for the service named;
/// no user is the process's. A token of no bytes goes as none, and the
/// exchange waits to make it again, the credentials kept, as an empty
/// line.
#[test]
fn the_initial_response_is_the_user_s_token() {
    let sspi = Scripted::leaked();
    let creds = Secret::new(b"", b"", b"service");
    let mut sasl = offering();
    sspi.then(Answer::MaxToken(Ok(48)))
        .then(Answer::MaxToken(Ok(48)))
        .then(Answer::Credentials(Ok(())))
        .then(made(SecStatus::OK, b"ap-req"));
    let (p, _) = with_sspi(sspi, Some(creds), true, |cx| sasl.start_sent(cx, false));
    assert_eq!(p, Ok(auth("GSSAPI", Some(b"ap-req"))));
    assert_eq!(sasl.state, State::GssapiToken);
    let asked = sspi.asked();
    assert_eq!(asked[2], Asked::Credentials(Package::Kerberos, None));
    assert_eq!(asked[3], first_token(b"service/mail.example"));

    drop(sasl);
    assert_eq!(sspi.asked(), [Asked::Dropped]);

    let mut sasl = offering();
    sspi.then(Answer::MaxToken(Ok(48)))
        .then(Answer::MaxToken(Ok(48)))
        .then(Answer::Credentials(Ok(())))
        .then(made(SecStatus::CONTINUE_NEEDED, b""));
    let (p, _) = with_sspi(sspi, Some(creds), true, |cx| sasl.start_sent(cx, false));
    assert_eq!(p, Ok(auth("GSSAPI", None)));
    assert_eq!(sasl.state, State::Gssapi);
    assert_eq!(sspi.asked().len(), 4);
    sspi.then(made(SecStatus::CONTINUE_NEEDED, b""));
    let (p, _) = with_sspi(sspi, Some(creds), true, |cx| {
        sasl.step_sent(cx, Code::Continue, b"")
    });
    assert_eq!(p, Ok(Progress::Sends(Send::Continue(Vec::new()))));
    assert_eq!(sspi.asked(), [first_token(b"service/mail.example")]);
    assert_eq!(sspi.unused(), 0);
}

/// GSSAPI is passed over without SSPI, without Kerberos in it, and for a
/// user naming no domain.
#[test]
fn gssapi_needs_kerberos_and_a_domain() {
    let sspi = Scripted::leaked();
    let pick = |creds: Secret<'_>, sspi: Option<&'static Scripted>| {
        let mut sasl = offering();
        let mut said = |_: Say, _: core::fmt::Arguments<'_>| {};
        let mut draw = |_: &mut [u8]| Ok(());
        let mut cx = Ctx {
            creds: Some(creds),
            sasl_ir: false,
            host: b"h",
            port: 110,
            random: &mut draw,
            sspi: sspi.map(|s| s as &dyn Sspi),
            said: &mut said,
        };
        sasl.start_sent(&mut cx, false).unwrap()
    };
    let domain = Secret::new(b"dom\\user", b"pw", b"");
    assert_eq!(pick(domain, None), auth("DIGEST-MD5", None));
    sspi.then(Answer::MaxToken(Err(SecStatus::new(-1))));
    assert_eq!(pick(domain, Some(sspi)), auth("DIGEST-MD5", None));
    sspi.then(Answer::MaxToken(Ok(48)));
    let plain = Secret::new(b"user", b"pw", b"");
    assert_eq!(pick(plain, Some(sspi)), auth("DIGEST-MD5", None));
    assert_eq!(sspi.unused(), 0);
}

/// A security layer that cannot be read cancels the exchange, said as C
/// says it: empty, not base64, not unwrapped, not 4 bytes, or not
/// offering to go without a layer.
#[test]
fn a_layer_that_cannot_be_read_cancels() {
    let sspi = Scripted::leaked();
    let creds = Secret::new(b"user@dom", b"pw", b"");
    let at_layer = || {
        let mut sasl = offering();
        sspi.then(Answer::MaxToken(Ok(48)))
            .then(Answer::MaxToken(Ok(48)))
            .then(Answer::Credentials(Ok(())))
            .then(made(SecStatus::OK, b"t"));
        let (p, _) = with_sspi(sspi, Some(creds), true, |cx| sasl.start_sent(cx, false));
        assert_eq!(p, Ok(auth("GSSAPI", Some(b"t"))));
        sasl
    };
    let failure = |sasl: &mut Sasl, message: &[u8]| {
        let (p, said) = with_sspi(sspi, Some(creds), true, |cx| {
            sasl.step_sent(cx, Code::Continue, message)
        });
        assert_eq!(p, Ok(Progress::Sends(Send::Cancel)));
        assert_eq!(sasl.state, State::Cancel);
        said.into_iter()
            .filter(|(who, _)| *who == Say::Info)
            .map(|(_, line)| line)
            .collect::<Vec<_>>()
    };
    let mut sasl = at_layer();
    assert_eq!(
        failure(&mut sasl, b""),
        ["GSSAPI handshake failure (empty security message)"]
    );
    let mut sasl = at_layer();
    assert_eq!(failure(&mut sasl, b"!!"), Vec::<String>::new());
    let refused = SecStatus::new(0x8009_0330_u32 as i32);
    for (unwrapped, why) in [
        (Err(SspiFailure::Status(refused)), "decryption failed"),
        (Ok(vec![1, 0, 0]), "invalid security data"),
        (Ok(vec![1, 0, 0, 0, 0]), "invalid security data"),
        (Ok(vec![6, 0, 0, 0]), "invalid security layer"),
    ] {
        let mut sasl = at_layer();
        sspi.then(Answer::Sizes(Ok(SIZES)))
            .then(Answer::Unwrapped(unwrapped));
        assert_eq!(
            failure(&mut sasl, &b64(b"x")),
            [format!("GSSAPI handshake failure ({why})")]
        );
    }
    sspi.asked();
    assert_eq!(sspi.unused(), 0);
}

/// SSPI's refusals are C's errors, unsaid: the package unknown, the
/// credentials refused, a token refused, no memory, the sizes or the wrap
/// refused.
#[test]
fn refusals_are_c_s() {
    let sspi = Scripted::leaked();
    let creds = Secret::new(b"dom/user", b"pw", b"");
    let refused = SecStatus::new(0x8009_030e_u32 as i32);
    let start = |answers: &[Answer]| {
        let mut sasl = offering();
        sspi.then(Answer::MaxToken(Ok(48)));
        for a in answers {
            sspi.then(a.clone());
        }
        let (r, said) = with_sspi(sspi, Some(creds), true, |cx| sasl.start(cx, false));
        assert!(said.is_empty(), "{said:?}");
        (r, sasl)
    };
    assert_eq!(
        start(&[Answer::MaxToken(Err(refused))]).0,
        Err(SaslError::NoAuthInfo)
    );
    let creds_refused = [
        Answer::MaxToken(Ok(48)),
        Answer::Credentials(Err(SspiFailure::Status(refused))),
    ];
    assert_eq!(start(&creds_refused).0, Err(SaslError::Denied));
    for (made_as, want) in [
        (made(refused, b""), SaslError::AuthError),
        (
            made(SecStatus::INSUFFICIENT_MEMORY, b""),
            SaslError::OutOfMemory,
        ),
        (
            Answer::Initialized(Err(SspiFailure::OutOfMemory)),
            SaslError::OutOfMemory,
        ),
    ] {
        let answers = [
            Answer::MaxToken(Ok(48)),
            Answer::Credentials(Ok(())),
            made_as,
        ];
        assert_eq!(start(&answers).0, Err(want));
    }
    let ok = [
        Answer::MaxToken(Ok(48)),
        Answer::Credentials(Ok(())),
        made(SecStatus::OK, b"t"),
    ];
    for (layer, want) in [
        (vec![Answer::Sizes(Err(refused))], SaslError::AuthError),
        (
            vec![Answer::Sizes(Err(SecStatus::INSUFFICIENT_MEMORY))],
            SaslError::OutOfMemory,
        ),
        (
            vec![
                Answer::Sizes(Ok(SIZES)),
                Answer::Unwrapped(Ok(vec![1, 0, 0, 0])),
                Answer::Wrapped(Err(SspiFailure::Status(refused))),
            ],
            SaslError::AuthError,
        ),
        (
            vec![
                Answer::Sizes(Ok(SIZES)),
                Answer::Unwrapped(Ok(vec![1, 0, 0, 0])),
                Answer::Wrapped(Err(SspiFailure::Status(SecStatus::INSUFFICIENT_MEMORY))),
            ],
            SaslError::OutOfMemory,
        ),
    ] {
        let (r, mut sasl) = start(&ok);
        assert_eq!(r, Ok(auth("GSSAPI", Some(b"t"))));
        with_sspi(sspi, Some(creds), true, |cx| sasl.sent(cx, true));
        for a in layer {
            sspi.then(a);
        }
        let (r, _) = with_sspi(sspi, Some(creds), true, |cx| {
            sasl.step(cx, Code::Continue, &b64(b"x"))
        });
        assert_eq!(r, Err(want));
    }
    sspi.asked();
    assert_eq!(sspi.unused(), 0);
}

/// GSSAPI not chosen is said as C's Windows build says it: built, and
/// Kerberos there or not.
#[test]
fn gssapi_not_chosen_is_said_why() {
    let sspi = Scripted::leaked();
    let blocked = |creds: Option<Secret<'_>>| {
        let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
        sasl.offers(Mechs::GSSAPI);
        let ((), said) = with_sspi(sspi, creds, false, |cx| sasl.blocked(cx));
        said.into_iter().map(|(_, line)| line).collect::<Vec<_>>()
    };
    let user = Some(Secret::new(b"user", b"pw", b""));
    sspi.then(Answer::MaxToken(Err(SecStatus::new(-1))));
    assert_eq!(
        blocked(user),
        [
            "SASL: no auth mechanism offered could be selected",
            "SASL: GSSAPI not supported by the platform/libraries",
        ]
    );
    sspi.then(Answer::MaxToken(Ok(48)));
    assert_eq!(
        blocked(user),
        ["SASL: no auth mechanism offered could be selected"]
    );
    assert_eq!(sspi.unused(), 0);
}
