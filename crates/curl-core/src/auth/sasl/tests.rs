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
