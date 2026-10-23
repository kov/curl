use super::*;

const KEY: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";

fn hmac(components: Option<&[u8]>) -> MessageSignature {
    MessageSignature {
        algorithm: Some(SignatureAlgorithm::HmacSha256),
        key: Some(KEY.to_vec()),
        key_id: Some(b"shared-key-1".to_vec()),
        components: components.map(<[u8]>::to_vec),
    }
}

fn headers(lines: &[&[u8]]) -> UserHeaders {
    UserHeaders::new(lines.iter().copied()).unwrap()
}

fn request<'a>(
    signature: &'a MessageSignature,
    headers: &'a UserHeaders,
    query: Option<&'a [u8]>,
) -> Request<'a> {
    Request {
        signature,
        method: b"GET",
        authority: b"example.com:7000",
        path: b"/5002/resource",
        query,
        headers,
        now: 0,
    }
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

/// Test 5002's request, signed as the C build signs it.
#[test]
fn signs_as_c_does() {
    let sig = hmac(None);
    let none = headers(&[]);
    let Signing { notes, result } = sign(&request(&sig, &none, None));
    let params = "(\"@method\" \"@authority\" \"@path\");created=0;\
                  keyid=\"shared-key-1\";alg=\"hmac-sha256\"";
    let signature = "sig1=:jvajJheXE4H/TqWfAn8m0d0Rx0XWYKADN/1P0qn+FLw=:";
    assert_eq!(
        text(&result.unwrap().unwrap()),
        format!("Signature-Input: sig1={params}\r\nSignature: {signature}\r\n")
    );
    let notes: Vec<&str> = notes.iter().map(|n| text(n)).collect();
    assert_eq!(
        notes,
        [
            format!("httpsig: Signature-Input params: {params}"),
            format!(
                "httpsig: Signature base: [\"@method\": GET\n\
                 \"@authority\": example.com:7000\n\
                 \"@path\": /5002/resource\n\
                 \"@signature-params\": {params}]"
            ),
            format!("httpsig: Signature-Input: sig1={params}"),
            format!("httpsig: Signature: {signature}"),
        ]
    );
}

/// The signature base `request` makes, from the notes.
fn base(request: &Request<'_>) -> String {
    let signing = sign(request);
    signing.result.unwrap().unwrap();
    let note = text(&signing.notes[1]);
    note["httpsig: Signature base: [".len()..note.len() - 1].to_owned()
}

/// Unless the components are named, a query is signed if the URL has
/// one, empty or not, with its `?`.
#[test]
fn signs_the_query_the_url_has() {
    let sig = hmac(None);
    let none = headers(&[]);
    for (query, signed) in [
        (None, None),
        (Some(&b""[..]), Some("?")),
        (Some(&b"a=b"[..]), Some("?a=b")),
    ] {
        let base = base(&request(&sig, &none, query));
        let line = base.lines().find(|l| l.starts_with("\"@query\""));
        assert_eq!(line, signed.map(|s| format!("\"@query\": {s}")).as_deref());
    }
}

/// Named components are lowercased; a header's values, trimmed, are
/// joined with commas, from every line that names it. Blanks after the
/// last are blanks, where C reads two as a seventeenth component
/// (DIVERGENCE.md).
#[test]
fn signs_the_components_named() {
    let sig = hmac(Some(b" Method\tQUERY  X-One: content-type:  "));
    let given = headers(&[
        b"X-One:  a \t",
        b"Content-Type: text/plain",
        b"x-one: b",
        b"X-One-More: c",
        b"X-One;",
        b"X-One",
    ]);
    let base = base(&request(&sig, &given, None));
    assert_eq!(
        base,
        "\"@method\": GET\n\"@query\": ?\n\"x-one\": a, b\n\
         \"content-type\": text/plain\n\"@signature-params\": \
         (\"@method\" \"@query\" \"x-one\" \"content-type\");created=0;\
         keyid=\"shared-key-1\";alg=\"hmac-sha256\""
    );
}

fn failure(components: &[u8], given: &UserHeaders) -> SignError {
    let sig = hmac(Some(components));
    sign(&request(&sig, given, None)).result.unwrap_err()
}

/// What C refuses of the components (`parse_components`).
#[test]
fn refuses_components_as_c_does() {
    let none = headers(&[]);
    let owned = |s: &[u8]| s.to_vec();
    assert_eq!(
        failure(b"method Host", &none),
        SignError::UnknownComponent(owned(b"host"))
    );
    assert_eq!(
        failure(b"@method", &none),
        SignError::UnknownComponent(owned(b"@method"))
    );
    assert_eq!(failure(b"method :", &none), SignError::EmptyHeaderName);
    assert_eq!(failure(b" \t ", &none), SignError::NoComponents);
    assert_eq!(failure(b"path a\"b:", &none), SignError::Unquotable);
    assert_eq!(failure(b"a\\b:", &none), SignError::Unquotable);
    assert_eq!(
        failure(b"method PATH Method", &none),
        SignError::DuplicateComponent(owned(b"@method"))
    );
    assert_eq!(
        failure(b"x-gone:", &none),
        SignError::HeaderNotFound(owned(b"x-gone"))
    );
    // 16 at most, blanks after them or not.
    let mut sixteen = Vec::new();
    for i in 0..16 {
        sixteen.extend_from_slice(format!("h{i}: ").as_bytes());
    }
    let lines: Vec<String> = (0..16).map(|i| format!("h{i}: v")).collect();
    let all = headers(&lines.iter().map(|l| l.as_bytes()).collect::<Vec<_>>());
    let sig = hmac(Some(&sixteen));
    assert!(sign(&request(&sig, &all, None)).result.is_ok());
    sixteen.extend_from_slice(b"method");
    assert_eq!(failure(&sixteen, &all), SignError::TooManyComponents);
}

/// The options are required in C's order; the application's own
/// signature is checked for once they are.
#[test]
fn needs_its_options_and_steps_aside_for_the_application_s() {
    let none = headers(&[]);
    let own = headers(&[b"Signature-Input: mine"]);
    fn fail(sig: &MessageSignature, given: &UserHeaders) -> Result<Option<Vec<u8>>, SignError> {
        sign(&request(sig, given, None)).result
    }
    let mut sig = hmac(None);
    assert_eq!(fail(&sig, &own), Ok(None));
    assert_eq!(fail(&sig, &headers(&[b"Signature: mine"])), Ok(None));
    assert!(
        fail(&sig, &headers(&[b"Signatures: mine"]))
            .unwrap()
            .is_some()
    );
    sig.key_id = Some(Vec::new());
    assert_eq!(fail(&sig, &own), Err(SignError::NoKeyId));
    sig.key = None;
    assert_eq!(fail(&sig, &own), Err(SignError::NoKey));
    sig.algorithm = None;
    assert_eq!(fail(&sig, &none), Err(SignError::NoAlgorithm));
}

/// The key is hex, its line ends left out (`decode_hex_key`).
#[test]
fn reads_the_key_as_c_does() {
    assert_eq!(decode_hex_key(b"0aFf\r\n\n").unwrap().0, [0x0a, 0xff]);
    assert_eq!(decode_hex_key(b"\n").err(), Some(SignError::KeyLength(0)));
    assert_eq!(decode_hex_key(b"abc").err(), Some(SignError::KeyLength(3)));
    assert_eq!(
        decode_hex_key(b"00a\n01").err(),
        Some(SignError::NotHex(2, *b"a\n"))
    );
    assert_eq!(
        decode_hex_key(b"00+0").err(),
        Some(SignError::NotHex(2, *b"+0"))
    );
}

/// An Ed25519 key is 32 bytes.
#[test]
fn ed25519_checks_its_key_length() {
    let none = headers(&[]);
    let mut sig = hmac(None);
    sig.algorithm = Some(SignatureAlgorithm::Ed25519);
    sig.key = Some(b"00".to_vec());
    let failed = sign(&request(&sig, &none, None)).result;
    assert_eq!(failed, Err(SignError::Ed25519KeyLength(1)));
}

/// The key's name goes quoted, a control character in it refused; a
/// line past C's buffer is too large.
#[test]
fn quotes_and_bounds_what_it_signs() {
    let none = headers(&[]);
    let mut sig = hmac(Some(b"method"));
    sig.key_id = Some(b"a\"b\\c".to_vec());
    let signing = sign(&request(&sig, &none, None));
    assert!(text(&signing.notes[0]).ends_with(";keyid=\"a\\\"b\\\\c\";alg=\"hmac-sha256\""));
    sig.key_id = Some(b"a\x7f".to_vec());
    assert_eq!(
        sign(&request(&sig, &none, None)).result,
        Err(SignError::Unquotable)
    );
    sig.key_id = Some(vec![b'k'; MAX_PART]);
    assert_eq!(
        sign(&request(&sig, &none, None)).result,
        Err(SignError::TooLarge)
    );
    // A part holds what C's buffer does, its zero byte counted.
    let mut part = Part::new();
    part.put(&[&vec![b'a'; MAX_PART - 2]]).unwrap();
    part.put(&[b"b"]).unwrap();
    assert_eq!(part.put(&[b"c"]), Err(SignError::TooLarge));
    let sig = hmac(None);
    let mut long = request(&sig, &none, None);
    let authority = vec![b'a'; MAX_PART];
    long.authority = &authority;
    assert_eq!(sign(&long).result, Err(SignError::TooLarge));
}

#[test]
fn reads_a_leading_number() {
    assert_eq!(leading_number(b"1700000000"), Some(1_700_000_000));
    assert_eq!(leading_number(b"12x"), Some(12));
    assert_eq!(leading_number(b"-1"), None);
    assert_eq!(leading_number(b""), None);
    assert_eq!(leading_number(b"99999999999999999999"), None);
}

/// A failure's kind: the build's, the size's and memory's own, else a bad
/// argument.
#[test]
fn a_failure_has_c_s_code() {
    assert_eq!(SignError::NotBuiltIn.kind(), ErrorKind::NotBuiltIn);
    assert_eq!(SignError::TooLarge.kind(), ErrorKind::TooLarge);
    assert_eq!(SignError::OutOfMemory.kind(), ErrorKind::OutOfMemory);
    assert_eq!(SignError::NoKey.kind(), ErrorKind::BadFunctionArgument);
}

/// A key id is quoted whatever its printable bytes, up to C's buffer of
/// 100 KiB; a control byte is refused.
#[test]
fn a_key_id_is_quoted_up_to_c_s_buffer() {
    let none = headers(&[]);
    let mut sig = hmac(Some(b"method"));
    sig.key_id = Some(b"a b~".to_vec());
    let signing = sign(&request(&sig, &none, None));
    assert!(text(&signing.notes[0]).contains(";keyid=\"a b~\";"));
    sig.key_id = Some(b"a\x01".to_vec());
    assert_eq!(
        sign(&request(&sig, &none, None)).result,
        Err(SignError::Unquotable)
    );
    sig.key_id = Some(vec![b'k'; 100_000]);
    assert!(sign(&request(&sig, &none, None)).result.is_ok());
}

/// An HMAC key may be of any length; only Ed25519's is 32 bytes.
#[test]
fn an_hmac_key_has_any_length() {
    let none = headers(&[]);
    let mut sig = hmac(None);
    sig.key = Some(b"00112233".to_vec());
    assert!(sign(&request(&sig, &none, None)).result.is_ok());
}

/// A key is at most C's longest string option in hex.
#[test]
fn a_key_is_at_most_c_s_longest_option() {
    assert_eq!(
        decode_hex_key(&vec![b'0'; 8_000_000]).unwrap().0.len(),
        4_000_000
    );
    assert_eq!(
        decode_hex_key(&vec![b'0'; 8_000_002]).err(),
        Some(SignError::KeyTooLong)
    );
}

/// `authority` names `@authority`, what `Host` says.
#[test]
fn the_authority_is_a_component() {
    let sig = hmac(Some(b"authority"));
    let none = headers(&[]);
    let base = base(&request(&sig, &none, None));
    assert!(
        base.starts_with("\"@authority\": example.com:7000\n"),
        "{base}"
    );
}

/// The signature says it was made now, without the debug build's fixed
/// time.
#[test]
fn the_signature_is_made_now() {
    let sig = hmac(None);
    let none = headers(&[]);
    let mut now = request(&sig, &none, None);
    now.now = 1_700_000_000;
    let signing = sign(&now);
    assert!(text(&signing.notes[0]).contains(";created=1700000000;"));
}
