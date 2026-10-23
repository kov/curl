//! AWS SigV4 on the wire (`Curl_output_aws_sigv4` as
//! `output_auth_headers` calls it): what goes where Authorization goes,
//! what is traced, and when nothing is signed. Each was checked against
//! the C binary through tests 439, 1933-1978, 2418, 3222 and 5026-5027;
//! the signature itself is the unit tests' in `sigv4`.

use super::*;

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

fn signing(params: &'static [u8]) -> impl FnOnce(&mut Options) {
    move |o: &mut Options| {
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.signing.make_mut().unwrap().aws_sigv4 = Some(params.to_vec());
        o.http.auth = crate::options::HttpAuth(AuthMethods::AWS_SIGV4);
    }
}

fn lines(request: &[u8]) -> Vec<String> {
    String::from_utf8(request.to_vec())
        .unwrap()
        .split("\r\n")
        .map(str::to_string)
        .collect()
}

/// The signature and the time go after Host, where Authorization goes;
/// the signing's notes are traced before the server's method is named.
#[test]
fn a_request_is_signed_where_authorization_goes() {
    let ran = run("/p?b=2&a=1", OK, false, signing(b"aws:amz:r1:s1"));
    assert_eq!(ran.result, Ok(()));
    let lines = lines(&ran.request);
    assert_eq!(lines[0], "GET /p?b=2&a=1 HTTP/1.1");
    assert_eq!(lines[1], format!("Host: 127.0.0.1:{PORT}"));
    assert!(
        lines[2].starts_with("Authorization: AWS4-HMAC-SHA256 Credential=u/")
            && lines[2].contains("/r1/s1/aws4_request, SignedHeaders=host;x-amz-date, Signature="),
        "{}",
        lines[2]
    );
    assert!(lines[3].starts_with("X-Amz-Date: "), "{}", lines[3]);
    assert_eq!(lines[4], "User-Agent: curl/test");
    let text = ran.seen.text();
    let at = |prefix: &str| {
        text.iter()
            .position(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("{prefix} in {text:?}"))
    };
    let to_sign = at("aws_sigv4: String to sign (enclosed in []) - [AWS4-HMAC-SHA256\n");
    let signature = at("aws_sigv4: Signature - ");
    let server = at("Server auth using AWS_SIGV4 with user 'u'");
    assert!(to_sign < signature && signature < server, "{text:?}");
}

/// The application's own Authorization goes in its place: nothing is
/// signed, though the method is named as in use.
#[test]
fn an_own_authorization_is_not_signed() {
    let ran = run("/", OK, false, |o| {
        signing(b"aws:amz:r1:s1")(o);
        o.http.headers = UserHeaders::new([&b"Authorization: mine"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let request = String::from_utf8(ran.request).unwrap();
    assert!(!request.contains("AWS4"), "{request}");
    assert!(!request.contains("X-Amz-Date"), "{request}");
    assert!(request.contains("\r\nAuthorization: mine\r\n"), "{request}");
    let text = ran.seen.text();
    assert!(!text.iter().any(|l| l.starts_with("aws_sigv4")), "{text:?}");
    assert!(
        text.iter()
            .any(|l| l.starts_with("Server auth using AWS_SIGV4 with user 'u'")),
        "{text:?}"
    );
}

/// Without credentials nothing is signed or named.
#[test]
fn nothing_is_signed_without_credentials() {
    let ran = run("/", OK, false, |o| {
        signing(b"aws:amz:r1:s1")(o);
        o.login = Default::default();
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.request, request_of("/"));
    let text = ran.seen.text();
    assert!(!text.iter().any(|l| l.contains("auth using")), "{text:?}");
}

/// A path kept as given cannot be signed, even with the application's
/// own Authorization; parameters without a provider fail as C fails
/// them, and nothing is sent.
#[test]
fn a_signing_fails_as_c_fails_it() {
    let failed = |set: Box<dyn FnOnce(&mut Options)>| {
        let ran = run("/", OK, false, set);
        let text = ran.seen.text();
        assert!(ran.request.is_empty());
        (ran.result, text)
    };
    let (result, said) = failed(Box::new(|o| {
        signing(b"aws:amz:r1:s1")(o);
        o.url_rules.path_as_is = true;
        o.http.headers = UserHeaders::new([&b"Authorization: mine"[..]]).unwrap();
    }));
    assert_eq!(result, Err(ErrorKind::BadFunctionArgument));
    let path_as_is = "Cannot use sigv4 authentication with path-as-is flag\n";
    assert!(said.iter().any(|l| l == path_as_is), "{said:?}");
    let (result, said) = failed(Box::new(signing(b":amz")));
    assert_eq!(result, Err(ErrorKind::BadFunctionArgument));
    let empty = "first aws-sigv4 provider cannot be empty\n";
    assert!(said.iter().any(|l| l == empty), "{said:?}");
    // `127.0.0.1` gives a service, `127`, and a region, `0`.
    let ran = run("/", OK, false, signing(b"x"));
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text();
    assert!(
        text.iter()
            .any(|l| l == "aws_sigv4: picked service 127 from host\n"),
        "{text:?}"
    );
}

/// What is signed is the request as it goes: its path and its query
/// apart, the port the URL names, the login's password.
#[test]
fn the_request_signed_is_the_one_sent() {
    for (target, password) in [("/p?b=2&a=1", &b"p"[..]), ("/q", b"other")] {
        let (mut m, talk, clock) = server(&[OK], false);
        let now = clock.unix_time();
        let ran = get(&mut m, target, talk, |o| {
            signing(b"aws:amz:r1:s1")(o);
            let mut pair = b"u:".to_vec();
            pair.extend_from_slice(password);
            *o.login.make_mut().unwrap() = crate::options::Login::from_pair(&pair).unwrap();
        });
        assert_eq!(ran.result, Ok(()));
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, Some(q.as_bytes())),
            None => (target, None),
        };
        let want = crate::proto::http::sigv4::sign(&crate::proto::http::sigv4::Request {
            params: Some(b"aws:amz:r1:s1"),
            method: b"GET",
            kind: crate::proto::http::sigv4::Kind::GetOrHead,
            hostname: b"127.0.0.1",
            host: b"127.0.0.1",
            port: Some(PORT),
            path: path.as_bytes(),
            query,
            headers: &UserHeaders::NONE,
            post_fields: crate::proto::http::sigv4::PostFields::None,
            empty_upload: false,
            user: b"u",
            password,
            now,
        })
        .result
        .unwrap();
        let request = String::from_utf8(ran.request).unwrap();
        let want = String::from_utf8(want).unwrap();
        assert!(request.contains(&want), "{request}\n{want}");
    }
}

/// An HTTP message signature signs the request as it goes: the path and
/// the query apart, the authority `Host` says, the application's if it
/// says one, else the library's with the port.
#[test]
fn a_message_signature_signs_the_request_sent() {
    let key = b"00112233445566778899aabbccddeeff".to_vec();
    for (target, host, authority) in [
        ("/p?b=2", None, format!("127.0.0.1:{PORT}")),
        (
            "/p",
            Some(&b"Host: example.com"[..]),
            "example.com".to_string(),
        ),
        ("/p?", Some(b"Host:"), format!("127.0.0.1:{PORT}")),
    ] {
        let (mut m, talk, clock) = server(&[OK], false);
        let now = clock.unix_time();
        let headers = UserHeaders::new(host).unwrap();
        let ran = get(&mut m, target, talk, |o| {
            let message = &mut o.http.signing.make_mut().unwrap().message;
            message.algorithm = Some(crate::options::SignatureAlgorithm::HmacSha256);
            message.key = Some(key.clone());
            message.key_id = Some(b"k".to_vec());
            o.http.auth = crate::options::HttpAuth(AuthMethods::HTTPSIG);
            o.http.headers = UserHeaders::new(host).unwrap();
        });
        assert_eq!(ran.result, Ok(()), "{target}");
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, Some(q.as_bytes())),
            None => (target, None),
        };
        let signature = crate::options::MessageSignature {
            algorithm: Some(crate::options::SignatureAlgorithm::HmacSha256),
            key: Some(key.clone()),
            key_id: Some(b"k".to_vec()),
            components: None,
        };
        let want = crate::proto::http::httpsig::sign(&crate::proto::http::httpsig::Request {
            signature: &signature,
            method: b"GET",
            authority: authority.as_bytes(),
            path: path.as_bytes(),
            query,
            headers: &headers,
            now,
        })
        .result
        .unwrap()
        .unwrap();
        let request = String::from_utf8(ran.request).unwrap();
        let want = String::from_utf8(want).unwrap();
        assert!(request.contains(&want), "{target}: {request}\n{want}");
    }
}
