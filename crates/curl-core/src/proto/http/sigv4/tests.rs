//! The canonical path and query as C's unit tests 1979 and 1980 check
//! them, the parameters as `parse_sigv4_params` reads them, and whole
//! signatures as tests 439 and 1955 expect them.

use super::*;

fn path(p: &str, encode: bool) -> String {
    let mut out = Vec::new();
    canon_path(p.as_bytes(), encode, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// Unit test 1979's cases.
#[test]
fn canonical_paths_as_unit_1979() {
    let cases = [
        ("/a=b", true, "/a%3Db"),
        ("/a=b", false, "/a=b"),
        (
            "/tables/arn%3Aaws%3As3tables%3Aus-east-1%3A022954301426%3Abucket%2Fjasoehartablebucket/jasoeharnamespace/jasoehartable/encryption",
            true,
            "/tables/arn%253Aaws%253As3tables%253Aus-east-1%253A022954301426%253Abucket%252Fjasoehartablebucket/jasoeharnamespace/jasoehartable/encryption",
        ),
        ("/", true, "/"),
        (
            "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            true,
            "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        ),
        ("//example//", false, "//example//"),
        ("/example space/", true, "/example%20space/"),
        ("/example+space/", true, "/example%2Bspace/"),
        ("/./", false, "/./"),
        ("//", false, "//"),
        (
            "/example1/example2/../..",
            false,
            "/example1/example2/../..",
        ),
    ];
    for (given, encode, want) in cases {
        assert_eq!(path(given, encode), want, "{given}");
    }
    for service in ["s3", "s3express", "s3-outposts", "s3-object-lambda"] {
        assert!(!should_encode(service.as_bytes()), "{service}");
    }
    for service in ["S3", "es", "s3x", ""] {
        assert!(should_encode(service.as_bytes()), "{service}");
    }
    assert_eq!(path("", true), "/");
    assert_eq!(path("", false), "/");
}

fn query(q: &str) -> String {
    let mut out = Vec::new();
    canon_query(Some(q.as_bytes()), &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// Unit test 1980's cases, and the limit on components.
#[test]
fn canonical_queries_as_unit_1980() {
    let cases = [
        ("Param1=", "Param1="),
        (
            "name=me&noval&aim=b%aad&weirdo=*.//-",
            "aim=b%AAd&name=me&noval=&weirdo=%2A.%2F%2F-",
        ),
        ("hello=a&b&c=&d", "b=&c=&d=&hello=a"),
        ("Param2=value2&Param1=value1", "Param1=value1&Param2=value2"),
        (
            "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        ),
        ("Param1=value1", "Param1=value1"),
        (
            "Param-3=Value3&Param=Value2&%E1%88%B4=Value1",
            "%E1%88%B4=Value1&Param=Value2&Param-3=Value3",
        ),
        ("p3= &p1=+&p2=%20", "p1=%20&p2=%20&p3=%20"),
        ("p3=%2b&p1=+", "p1=%20&p3=%2B"),
        // Not unit 1980's: empty parts left out, `=` in a value encoded,
        // a key of nothing first.
        ("&&b=1&&=x&a==", "=x&a=%3D&b=1"),
        // Empty keys are as one: their values keep the order given.
        ("=b&z&=a", "=b&=a&z="),
    ];
    for (given, want) in cases {
        assert_eq!(query(given), want, "{given}");
    }
    let mut out = Vec::new();
    canon_query(None, &mut out).unwrap();
    assert!(out.is_empty());
    let many = |n: usize| vec!["a"; n].join("&");
    assert_eq!(query(&many(127)), vec!["a="; 127].join("&"));
    assert_eq!(
        canon_query(Some(many(128).as_bytes()), &mut out),
        Err(SignError::TooLarge)
    );
}

fn read(
    given: &str,
    host: &str,
) -> Result<(String, String, String, String, Vec<String>), SignError> {
    let mut notes = Vec::new();
    let p = params(Some(given.as_bytes()), host.as_bytes(), &mut notes)?;
    let s = |b: &[u8]| String::from_utf8(b.to_vec()).unwrap();
    Ok((
        s(p.provider0),
        s(p.provider1),
        s(p.region),
        s(p.service),
        notes.iter().map(|n| s(n)).collect(),
    ))
}

/// `provider0[:provider1[:region[:service]]]`, what is missing of the
/// last two read from the host's first labels; a part past 64 bytes is
/// as one missing.
#[test]
fn reads_the_parameters_as_c() {
    let picked = |s: &str, r: &str| {
        vec![
            format!("aws_sigv4: picked service {s} from host"),
            format!("aws_sigv4: picked region {r} from host"),
        ]
    };
    let own = |a: &str, b: &str, r: &str, s: &str| {
        (a.to_string(), b.to_string(), r.to_string(), s.to_string())
    };
    let (a, b, r, s, notes) = read("aws:amz:us-east-2:es", "x.y").unwrap();
    assert_eq!((a, b, r, s), own("aws", "amz", "us-east-2", "es"));
    assert!(notes.is_empty());
    let (a, b, r, s, notes) = read("", "svc.reg.example.com").unwrap();
    assert_eq!((a, b, r, s), own("aws", "amz", "reg", "svc"));
    assert_eq!(notes, picked("svc", "reg"));
    let (a, b, r, s, _) = read("xxx", "127.0.0.1").unwrap();
    assert_eq!((a, b, r, s), own("xxx", "xxx", "0", "127"));
    // A region given but no service: the service alone is the host's.
    let (_, _, r, s, notes) = read("a:b:reg", "svc.x.y").unwrap();
    assert_eq!((r, s), ("reg".to_string(), "svc".to_string()));
    assert_eq!(notes, picked("svc", "x")[..1]);
    // An empty region stops the reading: the service after it is not
    // read, and is looked for in the host.
    assert_eq!(read("a:b::svc", "h").err(), Some(SignError::NoService));
    let long = "p".repeat(65);
    assert_eq!(read(&long, "a.b.c").err(), Some(SignError::NoProvider));
    assert_eq!(read(":x", "a.b.c").err(), Some(SignError::NoProvider));
    let (a, b, _, _, _) = read(&format!("x:{long}:r:s"), "a.b.c").unwrap();
    assert_eq!((a.as_str(), b.as_str()), ("x", "x"));
    assert_eq!(read("x", "localhost").err(), Some(SignError::NoService));
    assert_eq!(read("x", "a.b").err(), Some(SignError::NoRegion));
    assert_eq!(read("x:y:r:s:more", "h").unwrap().3, "s");
}

fn headers(lines: &[&str]) -> UserHeaders {
    UserHeaders::new(lines.iter().map(|l| l.as_bytes())).unwrap()
}

/// A GET as test 439 makes it.
fn test_439<'a>(headers: &'a UserHeaders) -> Request<'a> {
    Request {
        params: Some(b"aws:amz:us-east-2:es"),
        method: b"GET",
        kind: Kind::GetOrHead,
        hostname: b"fake.fake.fake",
        host: b"fake.fake.fake",
        port: Some(8000),
        path: b"/439/",
        query: Some(b"name=me&noval&aim=b%aad&&&weirdo=*.//-"),
        headers,
        post_fields: PostFields::None,
        empty_upload: false,
        user: b"user",
        password: b"secret",
        now: 0,
    }
}

fn signed_lines(request: &Request<'_>) -> String {
    String::from_utf8(sign(request).result.unwrap()).unwrap()
}

/// Test 439's signature, and its notes.
#[test]
fn signs_as_test_439() {
    let none = headers(&[]);
    let signing = sign(&test_439(&none));
    assert_eq!(
        String::from_utf8(signing.result.unwrap()).unwrap(),
        "Authorization: AWS4-HMAC-SHA256 Credential=user/19700101/us-east-2/es/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=9dd8592929306832a6673d10063491391e486e5f50de4647ea7c2c797277e0a6\r\n\
         X-Amz-Date: 19700101T000000Z\r\n"
    );
    let notes: Vec<_> = signing
        .notes
        .iter()
        .map(|n| String::from_utf8(n.clone()).unwrap())
        .collect();
    assert_eq!(notes.len(), 2);
    assert!(notes[0].starts_with(
        "aws_sigv4: String to sign (enclosed in []) - [AWS4-HMAC-SHA256\n19700101T000000Z\n\
         19700101/us-east-2/es/aws4_request\n"
    ));
    assert_eq!(
        notes[1],
        "aws_sigv4: Signature - 9dd8592929306832a6673d10063491391e486e5f50de4647ea7c2c797277e0a6"
    );
}

/// The application's headers are signed as they would go, their names
/// in lowercase and their values' blanks folded, sorted and those of one
/// name joined; its own date is the time signed at, and no date header
/// is added. A user is escaped in the credential.
#[test]
fn signs_the_headers_as_c() {
    let given = headers(&[
        "test2;",
        "test1:",
        "test0",
        "test_space: t\ts  m\t   end    ",
        "tesMixCase: MixCase",
        "Dup: b",
        "dup:  a ",
        "blank:   ",
    ]);
    let mut request = test_439(&given);
    request.query = None;
    let canonical = canonical_headers(
        &request,
        &params(request.params, b"", &mut Vec::new()).unwrap(),
        b"19700101T000000Z",
        None,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(canonical.lines).unwrap(),
        "dup:b,a\nhost:fake.fake.fake:8000\ntesmixcase:MixCase\ntest2:\ntest_space:t s m end\n\
         x-amz-date:19700101T000000Z\n"
    );
    assert_eq!(
        String::from_utf8(canonical.signed).unwrap(),
        "dup;host;tesmixcase;test2;test_space;x-amz-date"
    );
    assert_eq!(canonical.given_time, None);
    let dated = headers(&["X-Amz-Date: 20250101T010203Z", "Host: elsewhere"]);
    let mut request = test_439(&dated);
    request.user = b"a b/c";
    let lines = signed_lines(&request);
    assert!(
        lines.starts_with(
            "Authorization: AWS4-HMAC-SHA256 Credential=a%20b%2Fc/20250101/us-east-2/es/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature="
        ),
        "{lines}"
    );
    assert!(!lines.contains("X-Amz-Date"), "{lines}");
    // A date of the wrong length signs an empty time.
    let bad = headers(&["Date: Tue, 01 Jan 2025"]);
    let lines = signed_lines(&test_439(&bad));
    assert!(
        lines.contains("Credential=user//us-east-2/es/aws4_request"),
        "{lines}"
    );
    let semicolon = headers(&["Date;"]);
    assert_eq!(
        sign(&test_439(&semicolon)).result,
        Err(SignError::OutOfMemory)
    );
}

/// S3 sends the payload's hash: of the POST data for a POST, of nothing
/// for a GET or an upload said to be empty, `UNSIGNED-PAYLOAD` for any
/// other upload; the application's own hash replaces it. Other services
/// sign the POST data's hash, whatever the method, and send none.
#[test]
fn hashes_the_payload_as_c() {
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let none = headers(&[]);
    let s3 = |kind, post, empty_upload| {
        let mut request = test_439(&none);
        request.params = Some(b"AWS:amz:us-east-1:S3");
        request.kind = kind;
        request.post_fields = post;
        request.empty_upload = empty_upload;
        let (hash, header) = payload_hash(
            &request,
            &params(request.params, b"", &mut Vec::new()).unwrap(),
        )
        .unwrap();
        (
            String::from_utf8(hash).unwrap(),
            header.map(|h| String::from_utf8(h).unwrap()),
        )
    };
    let hashed = |h: &str| (h.to_string(), Some(format!("x-amz-content-sha256: {h}")));
    assert_eq!(s3(Kind::GetOrHead, PostFields::None, false), hashed(EMPTY));
    let posted = s3(Kind::Post, PostFields::Bytes(b"postData"), false);
    let mut want = Sha256::default();
    want.update(b"postData");
    let want = String::from_utf8(hex(&want.finish()).unwrap()).unwrap();
    assert_eq!(posted, hashed(&want));
    assert_eq!(s3(Kind::Put, PostFields::None, true), hashed(EMPTY));
    assert_eq!(
        s3(Kind::Put, PostFields::None, false),
        hashed("UNSIGNED-PAYLOAD")
    );
    assert_eq!(
        s3(Kind::Post, PostFields::None, false),
        hashed("UNSIGNED-PAYLOAD")
    );
    let own = headers(&["X-Amz-Content-Sha256:  abc  "]);
    let mut request = test_439(&own);
    request.params = Some(b"aws:amz:us-east-1:s3");
    let (hash, header) = payload_hash(
        &request,
        &params(request.params, b"", &mut Vec::new()).unwrap(),
    )
    .unwrap();
    assert_eq!((hash, header), (b"abc".to_vec(), None));
    let mut request = test_439(&none);
    request.post_fields = PostFields::Bytes(b"postData");
    let (hash, header) = payload_hash(
        &request,
        &params(request.params, b"", &mut Vec::new()).unwrap(),
    )
    .unwrap();
    assert_eq!((String::from_utf8(hash).unwrap(), header), (want, None));
}
