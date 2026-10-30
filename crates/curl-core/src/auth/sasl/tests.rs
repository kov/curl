use super::*;

const POP: Params = Params {
    service: "pop",
    max_ir: 255 - 8,
    default: Mechs::DEFAULT,
};

/// A step's context over `creds`, at 127.0.0.1:`port`, drawing `random`.
fn with_cx<R>(
    creds: Option<Secret<'_>>,
    port: u16,
    random: &[u8],
    f: impl FnOnce(&mut Ctx<'_>) -> R,
) -> R {
    let mut draw = |out: &mut [u8]| {
        out.copy_from_slice(&random[..out.len()]);
        Ok(())
    };
    let mut said = |_: Say, _: core::fmt::Arguments<'_>| {};
    let mut cx = Ctx {
        creds,
        sasl_ir: false,
        host: b"127.0.0.1",
        port,
        random: &mut draw,
        said: &mut said,
    };
    f(&mut cx)
}

fn b64(text: &[u8]) -> Vec<u8> {
    base64(text).unwrap()
}

#[test]
fn a_mechanism_s_name_ends_where_a_word_does() {
    assert_eq!(decode_mech(b"PLAIN"), Some((Mechs::PLAIN, 5)));
    assert_eq!(decode_mech(b"plain LOGIN"), Some((Mechs::PLAIN, 5)));
    assert_eq!(decode_mech(b"CRAM-MD5\r\n"), Some((Mechs::CRAM_MD5, 8)));
    // Run on into a longer name: no match.
    assert_eq!(decode_mech(b"PLAINX"), None);
    assert_eq!(decode_mech(b"LOGIN-1"), None);
    assert_eq!(
        decode_mech(b"SCRAM-SHA-256"),
        Some((Mechs::SCRAM_SHA_256, 13))
    );
    // A lowercase letter does not run on (`ISUPPER` only).
    assert_eq!(decode_mech(b"PLAINx"), Some((Mechs::PLAIN, 5)));
}

#[test]
fn the_url_s_first_auth_replaces_the_defaults() {
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    assert_eq!(sasl.preferred(), Mechs::DEFAULT);
    assert!(sasl.url_auth(b"PLAIN"));
    assert_eq!(sasl.preferred(), Mechs::PLAIN);
    assert!(sasl.url_auth(b"LOGIN"));
    assert_eq!(sasl.preferred(), Mechs::PLAIN.or(Mechs::LOGIN));
    assert!(!sasl.url_auth(b"PLAINX"));
    assert!(!sasl.url_auth(b""));
}

#[test]
fn cram_md5_answers_an_empty_challenge() {
    // test 891's
    let creds = Secret::new(b"user", b"secret", b"");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::CRAM_MD5);
    with_cx(Some(creds), 110, &[], |cx| {
        let auth = sasl.start(cx, false).unwrap();
        assert_eq!(
            auth,
            Progress::Sends(Send::Auth {
                mech: "CRAM-MD5",
                initial: None
            })
        );
        let next = sasl.step(cx, Code::Continue, b"").unwrap();
        assert_eq!(
            next,
            Progress::Sends(Send::Continue(b64(
                b"user 5c8db03f04cec0f43bcb060023914190"
            )))
        );
        assert_eq!(sasl.step(cx, Code::Final, b"").unwrap(), Progress::Done);
    });
}

#[test]
fn a_challenge_not_in_base64_cancels_and_another_mechanism_follows() {
    // test 879's
    let creds = Secret::new(b"user", b"secret", b"");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::CRAM_MD5.or(Mechs::PLAIN));
    with_cx(Some(creds), 110, &[], |cx| {
        sasl.start(cx, false).unwrap();
        assert_eq!(
            sasl.step(cx, Code::Continue, b"Rubbish").unwrap(),
            Progress::Sends(Send::Cancel)
        );
        assert_eq!(
            sasl.step(cx, Code::Other, b"").unwrap(),
            Progress::Sends(Send::Auth {
                mech: "PLAIN",
                initial: None
            })
        );
        assert_eq!(
            sasl.step(cx, Code::Continue, b"").unwrap(),
            Progress::Sends(Send::Continue(b64(b"\0user\0secret")))
        );
    });
}

#[test]
fn digest_md5_answers_as_c_s_debug_build_does() {
    // test 869's, its client nonce from `CURL_ENTROPY=12345678`
    let creds = Secret::new(b"user", b"secret", b"");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::DIGEST_MD5);
    let chlg = b64(
        b"realm=\"curl\",nonce=\"5300d17a1d695bd411e4cdf96f9548c23ced6175\",algorithm=md5-sess,qop=\"auth\"",
    );
    with_cx(Some(creds), 110, b"4321532163217321", |cx| {
        sasl.start(cx, false).unwrap();
        let resp = sasl.step(cx, Code::Continue, &chlg).unwrap();
        let want = b64(
            b"username=\"user\",realm=\"curl\",nonce=\"5300d17a1d695bd411e4cdf96f9548c23ced6175\",cnonce=\"34333231353332313633323137333231\",nc=\"00000001\",digest-uri=\"pop/127.0.0.1\",response=18315548c7f3a37e716fa8e90dfab9b6,qop=auth",
        );
        assert_eq!(resp, Progress::Sends(Send::Continue(want)));
        // The server's `rspauth` is answered with an empty line.
        let rspauth = b64(b"rspauth=fecb36b7086e0b95d906459efa8cc29e");
        assert_eq!(
            sasl.step(cx, Code::Continue, &rspauth).unwrap(),
            Progress::Sends(Send::Continue(Vec::new()))
        );
        assert_eq!(sasl.step(cx, Code::Final, b"").unwrap(), Progress::Done);
    });
}

#[test]
fn oauthbearer_names_the_port_but_80() {
    let creds = Secret::new(b"user", b"", b"").with_bearer(b"tok");
    with_cx(Some(creds), 110, &[], |cx| {
        assert_eq!(
            oauth_bearer(cx).unwrap(),
            b"n,a=user,\x01host=127.0.0.1\x01port=110\x01auth=Bearer tok\x01\x01"
        );
    });
    with_cx(Some(creds), 80, &[], |cx| {
        assert_eq!(
            oauth_bearer(cx).unwrap(),
            b"n,a=user,\x01host=127.0.0.1\x01auth=Bearer tok\x01\x01"
        );
    });
}

#[test]
fn an_initial_response_too_long_is_left_for_the_continuation() {
    let user = [b'u'; 300];
    let creds = Secret::new(&user, b"p", b"");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::PLAIN);
    with_cx(Some(creds), 110, &[], |cx| {
        cx.sasl_ir = true;
        assert_eq!(
            sasl.start(cx, false).unwrap(),
            Progress::Sends(Send::Auth {
                mech: "PLAIN",
                initial: None
            })
        );
    });
}

#[test]
fn hmac_md5_is_rfc_2104_s() {
    // RFC 2104's second test vector.
    let digest = crate::hash::hmac_md5(b"Jefe", &[b"what do ya want for nothing?"]);
    assert_eq!(hex(&digest).unwrap(), b"750c783e6ab0b503eaa86e310a5db738");
}

/// A step's context, as `with_cx`'s, that also keeps what is said.
fn with_said<R>(
    creds: Option<Secret<'_>>,
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
        sasl_ir: false,
        host: b"127.0.0.1",
        port: 110,
        random: &mut draw,
        said: &mut said,
    };
    let r = f(&mut cx);
    (r, lines)
}

fn auth(mech: &'static str, initial: Option<&[u8]>) -> Progress {
    Progress::Sends(Send::Auth {
        mech,
        initial: initial.map(b64),
    })
}

fn cont(resp: &[u8]) -> Progress {
    Progress::Sends(Send::Continue(b64(resp)))
}

/// The bits are C's `SASL_MECH_*`, and any is all of them but EXTERNAL.
#[test]
fn the_mechanisms_are_c_s_bits() {
    let bits = [
        Mechs::LOGIN,
        Mechs::PLAIN,
        Mechs::CRAM_MD5,
        Mechs::DIGEST_MD5,
        Mechs::GSSAPI,
        Mechs::EXTERNAL,
        Mechs::NTLM,
        Mechs::XOAUTH2,
        Mechs::OAUTHBEARER,
        Mechs::SCRAM_SHA_1,
        Mechs::SCRAM_SHA_256,
    ];
    for (i, m) in bits.iter().enumerate() {
        assert_eq!(m.0, 1 << i, "{i}");
        assert_eq!(TABLE[i].1, *m);
        assert_eq!(m.or(*m), *m);
        assert_eq!(Mechs::DEFAULT.has(*m), *m != Mechs::EXTERNAL);
    }
}

/// Of what both ends allow, the strongest is chosen, in C's order:
/// EXTERNAL without a password, DIGEST-MD5, CRAM-MD5, the bearer's two
/// only with a bearer, PLAIN, LOGIN; none of them is no login by SASL.
#[test]
fn the_strongest_mechanism_both_ends_allow_is_chosen() {
    let all = Mechs::DEFAULT.or(Mechs::EXTERNAL);
    let pick = |creds: Secret<'_>, offered: Mechs| {
        let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
        assert!(sasl.url_auth(b"*"));
        sasl.preferred = all;
        sasl.offers(offered);
        with_cx(Some(creds), 110, &[0; 16], |cx| {
            sasl.start(cx, false).unwrap()
        })
    };
    let pw = Secret::new(b"user", b"secret", b"");
    let nopw = Secret::new(b"user", b"", b"");
    let bearer = Secret::new(b"user", b"secret", b"").with_bearer(b"tok");
    assert_eq!(pick(nopw, all), auth("EXTERNAL", None));
    assert_eq!(pick(pw, all), auth("DIGEST-MD5", None));
    assert_eq!(
        pick(pw, Mechs::EXTERNAL.or(Mechs::PLAIN)),
        auth("PLAIN", None)
    );
    assert_eq!(pick(nopw, Mechs::PLAIN), auth("PLAIN", None));
    assert_eq!(
        pick(pw, all.without(Mechs::DIGEST_MD5)),
        auth("CRAM-MD5", None)
    );
    let no_md5 = all.without(Mechs::DIGEST_MD5).without(Mechs::CRAM_MD5);
    assert_eq!(pick(bearer, no_md5), auth("OAUTHBEARER", None));
    assert_eq!(pick(pw, no_md5), auth("PLAIN", None));
    assert_eq!(
        pick(bearer, no_md5.without(Mechs::OAUTHBEARER)),
        auth("XOAUTH2", None)
    );
    assert_eq!(pick(bearer, Mechs::PLAIN), auth("PLAIN", None));
    assert_eq!(pick(pw, Mechs::LOGIN), auth("LOGIN", None));
    assert_eq!(pick(pw, Mechs::GSSAPI.or(Mechs::NTLM)), Progress::Idle);
    assert_eq!(pick(pw, Mechs::NONE), Progress::Idle);
}

/// An initial response goes with the command when the application asks
/// for one or the protocol forces it, each mechanism's own, and the
/// exchange then waits for the final answer.
#[test]
fn an_initial_response_is_each_mechanism_s_first_message() {
    let ir = |creds: Secret<'_>, offered: Mechs, asked: bool, forced: bool| {
        let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
        sasl.preferred = Mechs::DEFAULT.or(Mechs::EXTERNAL);
        sasl.offers(offered);
        with_cx(Some(creds), 110, &[], |cx| {
            cx.sasl_ir = asked;
            let first = sasl.start(cx, forced).unwrap();
            (first, sasl.step(cx, Code::Final, b""))
        })
    };
    let pw = Secret::new(b"user", b"secret", b"");
    let owned = Secret::new(b"user", b"secret", b"").with_authzid(b"boss");
    let bearer = Secret::new(b"user", b"", b"").with_bearer(b"tok");
    let done = || Ok(Progress::Done);
    assert_eq!(
        ir(owned, Mechs::PLAIN, true, false),
        (auth("PLAIN", Some(b"boss\0user\0secret")), done())
    );
    assert_eq!(
        ir(pw, Mechs::PLAIN, false, true),
        (auth("PLAIN", Some(b"\0user\0secret")), done())
    );
    assert_eq!(
        ir(pw, Mechs::LOGIN, true, false).0,
        auth("LOGIN", Some(b"user"))
    );
    assert_eq!(
        ir(Secret::new(b"user", b"", b""), Mechs::EXTERNAL, true, false),
        (auth("EXTERNAL", Some(b"user")), done())
    );
    assert_eq!(
        ir(bearer, Mechs::XOAUTH2, true, false),
        (
            auth("XOAUTH2", Some(b"user=user\x01auth=Bearer tok\x01\x01")),
            done()
        )
    );
    let (first, _) = ir(bearer, Mechs::OAUTHBEARER, true, false);
    let msg = b"n,a=user,\x01host=127.0.0.1\x01port=110\x01auth=Bearer tok\x01\x01";
    assert_eq!(first, auth("OAUTHBEARER", Some(msg)));
    // Not asked: none.
    assert_eq!(ir(pw, Mechs::PLAIN, false, false).0, auth("PLAIN", None));
}

/// The mechanism's name and the encoded response together may be the
/// protocol's limit long, and no longer.
#[test]
fn an_initial_response_may_be_the_limit_long() {
    // "PLAIN" and 240 bytes of base64, 180 bytes encoded.
    static TIGHT: Params = Params {
        service: "pop",
        max_ir: 5 + 240,
        default: Mechs::DEFAULT,
    };
    let start = |user: &[u8]| {
        let creds = Secret::new(user, b"", b"");
        let mut sasl = Sasl::new(&TIGHT, AuthMethods::BASIC);
        sasl.offers(Mechs::PLAIN);
        with_cx(Some(creds), 110, &[], |cx| {
            cx.sasl_ir = true;
            sasl.start(cx, false).unwrap()
        })
    };
    // Two zero bytes and the user: 180 bytes.
    let user = [b'u'; 178];
    let mut whole = vec![0];
    whole.extend_from_slice(&user);
    whole.push(0);
    assert_eq!(start(&user), auth("PLAIN", Some(&whole)));
    // 181 bytes encode to 244.
    assert_eq!(start(&[b'u'; 179]), auth("PLAIN", None));
}

/// LOGIN sends the user, then the password, each to its own prompt.
#[test]
fn login_answers_the_user_then_the_password() {
    let creds = Secret::new(b"user", b"secret", b"");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::LOGIN);
    with_cx(Some(creds), 110, &[], |cx| {
        assert_eq!(sasl.start(cx, false).unwrap(), auth("LOGIN", None));
        assert_eq!(sasl.step(cx, Code::Continue, b"").unwrap(), cont(b"user"));
        assert_eq!(sasl.step(cx, Code::Continue, b"").unwrap(), cont(b"secret"));
        assert_eq!(sasl.step(cx, Code::Final, b"").unwrap(), Progress::Done);
    });
}

/// EXTERNAL answers its prompt with the user.
#[test]
fn external_answers_with_the_user() {
    let creds = Secret::new(b"user", b"", b"");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    assert!(sasl.url_auth(b"EXTERNAL"));
    sasl.offers(Mechs::EXTERNAL);
    with_cx(Some(creds), 110, &[], |cx| {
        assert_eq!(sasl.start(cx, false).unwrap(), auth("EXTERNAL", None));
        assert_eq!(sasl.step(cx, Code::Continue, b"").unwrap(), cont(b"user"));
        assert_eq!(sasl.step(cx, Code::Final, b"").unwrap(), Progress::Done);
    });
}

/// XOAUTH2 answers its prompt with its message and is done; OAUTHBEARER
/// may be told of a failure as a continuation, acknowledged with a byte
/// of 1 and then refused.
#[test]
fn the_bearer_s_mechanisms_answer_their_prompts() {
    let bearer = Secret::new(b"user", b"", b"").with_bearer(b"tok");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::XOAUTH2);
    with_cx(Some(bearer), 80, &[], |cx| {
        assert_eq!(sasl.start(cx, false).unwrap(), auth("XOAUTH2", None));
        assert_eq!(
            sasl.step(cx, Code::Continue, b"").unwrap(),
            cont(b"user=user\x01auth=Bearer tok\x01\x01")
        );
        assert_eq!(sasl.step(cx, Code::Final, b"").unwrap(), Progress::Done);
    });
    let msg: &[u8] = b"n,a=user,\x01host=127.0.0.1\x01auth=Bearer tok\x01\x01";
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::OAUTHBEARER);
    with_cx(Some(bearer), 80, &[], |cx| {
        assert_eq!(sasl.start(cx, false).unwrap(), auth("OAUTHBEARER", None));
        assert_eq!(sasl.step(cx, Code::Continue, b"").unwrap(), cont(msg));
        assert_eq!(
            sasl.step(cx, Code::Continue, b"eyJzdGF0dXMiOiI0MDEifQ==")
                .unwrap(),
            cont(b"\x01")
        );
        assert_eq!(sasl.step(cx, Code::Other, b""), Err(SaslError::Denied));
    });
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::OAUTHBEARER);
    with_cx(Some(bearer), 80, &[], |cx| {
        sasl.start(cx, false).unwrap();
        sasl.step(cx, Code::Continue, b"").unwrap();
        assert_eq!(sasl.step(cx, Code::Final, b"").unwrap(), Progress::Done);
    });
}

/// A refusal at any step is the login denied.
#[test]
fn a_refusal_denies_the_login() {
    let creds = Secret::new(b"user", b"secret", b"");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::LOGIN);
    with_cx(Some(creds), 110, &[], |cx| {
        sasl.start(cx, false).unwrap();
        assert_eq!(sasl.step(cx, Code::Other, b""), Err(SaslError::Denied));
    });
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::PLAIN);
    with_cx(Some(creds), 110, &[], |cx| {
        cx.sasl_ir = true;
        sasl.start(cx, false).unwrap();
        assert_eq!(sasl.step(cx, Code::Continue, b""), Err(SaslError::Denied));
    });
}

/// No preferences, or the offers forgotten, leave nothing to choose.
#[test]
fn nothing_preferred_or_offered_is_no_sasl() {
    let creds = Secret::new(b"user", b"secret", b"");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::PLAIN);
    sasl.prefer_none();
    with_cx(Some(creds), 110, &[], |cx| {
        assert_eq!(sasl.start(cx, false).unwrap(), Progress::Idle);
    });
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::PLAIN);
    sasl.forget_offers();
    with_cx(Some(creds), 110, &[], |cx| {
        assert_eq!(sasl.start(cx, false).unwrap(), Progress::Idle);
    });
}

/// `AUTH=*` is any mechanism; a name with more after it is none.
#[test]
fn the_url_s_auth_is_any_or_one_name_whole() {
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    assert!(!sasl.url_auth(b"PLAIN x"));
    assert_eq!(sasl.preferred(), Mechs::NONE);
    assert!(sasl.url_auth(b"*"));
    assert_eq!(sasl.preferred(), Mechs::DEFAULT);
}

/// Credentials, or EXTERNAL offered and preferred, are something to log
/// in with.
#[test]
fn credentials_or_external_can_authenticate() {
    let creds = Secret::new(b"user", b"", b"");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::EXTERNAL);
    with_cx(None, 110, &[], |cx| assert!(!sasl.can_authenticate(cx)));
    with_cx(Some(creds), 110, &[], |cx| {
        assert!(sasl.can_authenticate(cx))
    });
    assert!(sasl.url_auth(b"EXTERNAL"));
    with_cx(None, 110, &[], |cx| assert!(sasl.can_authenticate(cx)));
}

/// Each change of state is said once, by the names C's debug build
/// gives them.
#[test]
fn each_change_of_state_is_said_by_c_s_names() {
    let creds = Secret::new(b"user", b"secret", b"");
    let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
    sasl.offers(Mechs::LOGIN);
    let ((), said) = with_said(Some(creds), |cx| {
        sasl.start(cx, false).unwrap();
        sasl.step(cx, Code::Continue, b"").unwrap();
        sasl.step(cx, Code::Continue, b"").unwrap();
        sasl.step(cx, Code::Final, b"").unwrap();
        // Already stopped: nothing changes, nothing is said.
        sasl.set_state(cx, State::Stop);
    });
    let changes: Vec<&str> = said
        .iter()
        .map(|(who, line)| {
            assert_eq!(*who, Say::Debug);
            line.split_once(" state change from ").unwrap().1
        })
        .collect();
    assert_eq!(
        changes,
        [
            "STOP to LOGIN",
            "LOGIN to LOGIN_PASSWD",
            "LOGIN_PASSWD to FINAL",
            "FINAL to STOP"
        ]
    );
    let names = [
        (State::Stop, "STOP"),
        (State::Plain, "PLAIN"),
        (State::Login, "LOGIN"),
        (State::LoginPasswd, "LOGIN_PASSWD"),
        (State::External, "EXTERNAL"),
        (State::CramMd5, "CRAMMD5"),
        (State::DigestMd5, "DIGESTMD5"),
        (State::DigestMd5Resp, "DIGESTMD5_RESP"),
        (State::OAuth2, "OAUTH2"),
        (State::OAuth2Resp, "OAUTH2_RESP"),
        (State::Cancel, "CANCEL"),
        (State::Final, "FINAL"),
    ];
    for (state, name) in names {
        assert_eq!(state.name(), name);
    }
}

/// Why no mechanism was chosen, said as C says it.
#[test]
fn a_mechanism_not_chosen_is_said_why() {
    let blocked = |creds: Option<Secret<'_>>, offered: Mechs, preferred: Mechs| {
        let mut sasl = Sasl::new(&POP, AuthMethods::BASIC);
        sasl.preferred = preferred;
        sasl.offers(offered);
        let ((), said) = with_said(creds, |cx| sasl.blocked(cx));
        said.into_iter()
            .map(|(who, line)| {
                assert_eq!(who, Say::Info);
                line
            })
            .collect::<Vec<_>>()
    };
    let pw = Some(Secret::new(b"user", b"secret", b""));
    assert_eq!(
        blocked(pw, Mechs::NONE, Mechs::DEFAULT),
        ["SASL: no auth mechanism was offered or recognized"]
    );
    assert_eq!(
        blocked(pw, Mechs::PLAIN, Mechs::LOGIN),
        ["SASL: no overlap between offered and configured auth mechanisms"]
    );
    let all = Mechs::DEFAULT.or(Mechs::EXTERNAL);
    assert_eq!(
        blocked(pw, all, all),
        [
            "SASL: no auth mechanism offered could be selected",
            "SASL: auth EXTERNAL not chosen with password",
            "SASL: GSSAPI not builtin",
            "SASL: SCRAM-SHA-256 not builtin",
            "SASL: SCRAM-SHA-1 not builtin",
            "SASL: NTLM not builtin",
            "SASL: OAUTHBEARER is missing CURLOPT_XOAUTH2_BEARER",
            "SASL: XOAUTH2 is missing CURLOPT_XOAUTH2_BEARER",
        ]
    );
    let anon = Some(Secret::new(b"", b"", b"").with_bearer(b"tok"));
    let some = Mechs::DIGEST_MD5.or(Mechs::CRAM_MD5).or(Mechs::XOAUTH2);
    assert_eq!(
        blocked(anon, some, some),
        [
            "SASL: no auth mechanism offered could be selected",
            "SASL: DIGEST-MD5 is missing username",
            "SASL: CRAM-MD5 is missing username",
            "SASL: XOAUTH2 is missing username",
        ]
    );
    let nopw = Some(Secret::new(b"user", b"", b""));
    assert_eq!(
        blocked(nopw, Mechs::EXTERNAL.or(Mechs::GSSAPI), all),
        [
            "SASL: no auth mechanism offered could be selected",
            "SASL: GSSAPI not builtin"
        ]
    );
}

/// Hex is lowercase, two digits a byte; the quoted string escapes `"`
/// and `\` and writes bytes outside printable ASCII as `%XX`.
#[test]
fn hex_and_quoting_are_c_s() {
    assert_eq!(hex(&[0x00, 0xff, 0x1a, 0xa1]).unwrap(), b"00ff1aa1");
    assert_eq!(
        quoted(b"a\"b\\c d\x01\xff\x7f").unwrap(),
        b"a\\\"b\\\\c d%01%FF%7F"
    );
}

/// A challenge's value by its key, quoted or up to a comma, its escapes
/// undone, within C's limits.
#[test]
fn a_challenge_s_values_are_read_as_c_reads_them() {
    let get = |chlg: &[u8], key: &[u8]| digest_value(chlg, key, 1024);
    assert_eq!(get(b"a=1, \tb=two,c=3", b"b").unwrap(), b"two");
    assert_eq!(
        get(b"a=\"x,y\",b=\"q\\\"r\\\\s\"", b"b").unwrap(),
        b"q\"r\\s"
    );
    assert_eq!(get(b"a=\"x,y\",b=2", b"a").unwrap(), b"x,y");
    // An unquoted value keeps a backslash at its end.
    assert_eq!(get(b"k=a\\b\\", b"k").unwrap(), b"ab\\");
    assert_eq!(get(b"a=1", b"b"), None);
    assert_eq!(get(b"a=1;b=2", b"b"), None);
    // A name of 1 to 64 bytes.
    assert_eq!(get(b"=1,b=2", b"b"), None);
    let long = [b'n'; 64];
    let mut chlg = long.to_vec();
    chlg.extend_from_slice(b"=1,b=2");
    assert_eq!(get(&chlg, b"b").unwrap(), b"2");
    let mut chlg = [b'n'; 65].to_vec();
    chlg.extend_from_slice(b"=1,b=2");
    assert_eq!(get(&chlg, b"b"), None);
    // An unquoted value of 1 to 256 bytes.
    assert_eq!(get(b"a=,b=2", b"b"), None);
    let mut chlg = b"a=".to_vec();
    chlg.extend_from_slice(&[b'v'; 256]);
    assert_eq!(get(&chlg, b"a").unwrap(), [b'v'; 256]);
    chlg.push(b'v');
    assert_eq!(get(&chlg, b"a"), None);
    // A quoted one of at most 256, an escape counting both its bytes.
    let quote = |body: &[u8]| {
        let mut c = b"a=\"".to_vec();
        c.extend_from_slice(body);
        c.extend_from_slice(b"\"");
        c
    };
    assert_eq!(get(&quote(&[b'v'; 256]), b"a").unwrap(), [b'v'; 256]);
    assert_eq!(get(&quote(&[b'v'; 257]), b"a"), None);
    let escaped = b"\\v".repeat(128);
    assert_eq!(get(&quote(&escaped), b"a").unwrap(), [b'v'; 128]);
    let escaped = b"\\v".repeat(129);
    assert_eq!(get(&quote(&escaped), b"a"), None);
    // Unterminated, even by an escaped quote.
    assert_eq!(get(b"a=\"xy", b"a"), None);
    assert_eq!(get(b"a=\"x\\\"", b"a"), None);
    // No shorter than the room: too long.
    assert_eq!(digest_value(b"a=1234", b"a", 4), None);
    assert_eq!(digest_value(b"a=123", b"a", 4).unwrap(), b"123");
}

/// DIGEST-MD5 answers only `auth` among the challenge's protections,
/// each a word of 1 to 32 bytes up to a comma: past an empty or a longer
/// one it reads no further, and cancels.
#[test]
fn digest_md5_reads_the_protections_as_c_does() {
    let creds = Secret::new(b"user", b"secret", b"");
    let answer = |qop: &str| {
        let chlg = format!("nonce=\"n\",algorithm=md5-sess,qop=\"{qop}\"");
        with_cx(Some(creds), 110, &[0; 16], |cx| {
            digest_md5(cx, chlg.as_bytes(), "pop").unwrap().is_some()
        })
    };
    assert!(answer("auth-int,auth"));
    assert!(!answer("auth-int"));
    assert!(!answer(",auth"));
    assert!(!answer(&format!("{},auth", "x".repeat(33))));
    assert!(answer(&format!("{},auth", "x".repeat(32))));
}
