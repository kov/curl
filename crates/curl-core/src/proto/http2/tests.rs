use super::*;

fn pairs(head: &str, custom: Option<&str>) -> Result<Vec<(String, String)>, ErrorKind> {
    let fields = fields_of(head.as_bytes(), custom.map(str::as_bytes), b"https")?;
    Ok(fields
        .pairs()
        .unwrap()
        .into_iter()
        .map(|(n, v)| {
            (
                String::from_utf8_lossy(n).into_owned(),
                String::from_utf8_lossy(v).into_owned(),
            )
        })
        .collect())
}

fn owned(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect()
}

/// A request's head turns into its fields as C's does: the pseudo-headers
/// first, `:authority` from `Host:`, names in lowercase, the connection's
/// own headers left out, `TE` only as `trailers`, a value's trailing
/// blanks kept.
#[test]
fn a_head_turns_into_fields_as_c_turns_it() {
    let head = "GET /index.html?q=1 HTTP/2\r\n\
                Host: example.com:8443\r\n\
                User-Agent: curl/test\r\n\
                Accept: */*\r\n\
                Connection: keep-alive\r\n\
                Transfer-Encoding: chunked\r\n\
                TE: gzip, trailers;q=1\r\n\
                X-Blank:   spaced  \r\n\
                \r\n";
    assert_eq!(
        pairs(head, None).unwrap(),
        owned(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com:8443"),
            (":path", "/index.html?q=1"),
            ("user-agent", "curl/test"),
            ("accept", "*/*"),
            ("te", "trailers"),
            ("x-blank", "spaced  "),
        ])
    );
    // A TE that lists no trailers goes not at all.
    let head = "GET / HTTP/2\r\nHost: h\r\nTE: gzip\r\n\r\n";
    assert_eq!(
        pairs(head, None).unwrap(),
        owned(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "h"),
            (":path", "/"),
        ])
    );
}

/// Without a `Host:`, no `:authority`; a custom method with a space is
/// read whole, and a target with spaces runs to the last one.
#[test]
fn methods_targets_and_authorities_are_read_as_c_reads_them() {
    let head = "MY METHOD /a b HTTP/2\r\n\r\n";
    assert_eq!(
        pairs(head, Some("MY METHOD")).unwrap(),
        owned(&[
            (":method", "MY METHOD"),
            (":scheme", "https"),
            (":path", "/a b"),
        ])
    );
    // CONNECT's target is its authority, and it has no scheme or path.
    let head = "CONNECT example.com:443 HTTP/2\r\nHost: x\r\n\r\n";
    assert_eq!(
        pairs(head, None).unwrap(),
        owned(&[(":method", "CONNECT"), (":authority", "example.com:443")])
    );
    // No target, and a header without a name, are refused.
    assert_eq!(
        pairs("GET HTTP/2\r\n\r\n", None),
        Err(ErrorKind::UrlMalformat)
    );
    assert_eq!(
        pairs("GET / HTTP/2\r\n: x\r\n\r\n", None),
        Err(ErrorKind::BadFunctionArgument)
    );
}

/// A target in absolute form, as a request to a proxy sends it, gives
/// the scheme, the authority (a port the scheme's own left out) and the
/// path with its query; the Host field does not go (`start_req`,
/// `Curl_http_req_make2`). One too long to be a URL is refused.
#[test]
fn an_absolute_target_names_the_scheme_authority_and_path() {
    let head = "GET http://example.com:8080/a/../b?q=1 HTTP/1.1\r\n\
                Host: proxied.example\r\n\
                Accept: */*\r\n\
                \r\n";
    assert_eq!(
        pairs(head, None).unwrap(),
        owned(&[
            (":method", "GET"),
            (":scheme", "http"),
            (":authority", "example.com:8080"),
            (":path", "/a/../b?q=1"),
            ("accept", "*/*"),
        ])
    );
    let head = "GET http://example.com:80/x HTTP/1.1\r\nHost: h\r\n\r\n";
    let got = pairs(head, None).unwrap();
    assert_eq!(got[2], owned(&[(":authority", "example.com")])[0]);
    // Not a URL: the target is the path, the authority Host's.
    let head = "GET example.com HTTP/1.1\r\nHost: h\r\n\r\n";
    let got = pairs(head, None).unwrap();
    assert_eq!(
        got[1..4],
        owned(&[
            (":scheme", "https"),
            (":authority", "h"),
            (":path", "example.com")
        ])
    );
    let long = format!(
        "GET http://e/{} HTTP/1.1\r\nHost: h\r\n\r\n",
        "x".repeat(8 * 1024)
    );
    assert_eq!(pairs(&long, None), Err(ErrorKind::UrlMalformat));
}

/// A CONNECT-UDP's fields: the proxy's scheme and authority and the
/// target's path, the proxy's authorization next if it has one, then the
/// protocol and the capsules asked for, then the application's headers,
/// those HTTP/2 has no use for left out (`http_proxy_create_CONNECTUDP`,
/// `Curl_http_req_to_h2`).
#[test]
fn a_connect_udp_s_fields_put_its_protocol_after_authorization() {
    let fields = |head: &str, authorized| {
        let path = b"/.well-known/masque/udp/o/443/";
        let made = connect_udp_fields(head.as_bytes(), authorized, b"https", b"p:3128", path);
        let made = made.unwrap();
        let pairs = made.pairs().unwrap();
        pairs
            .into_iter()
            .map(|(n, v)| {
                (
                    String::from_utf8_lossy(n).into_owned(),
                    String::from_utf8_lossy(v).into_owned(),
                )
            })
            .collect::<Vec<_>>()
    };
    let pseudo = [
        (":method", "CONNECT"),
        (":scheme", "https"),
        (":authority", "p:3128"),
        (":path", "/.well-known/masque/udp/o/443/"),
    ];
    let head = "CONNECT p:3128 HTTP/2\r\nProxy-Authorization: Basic eA==\r\n\
                X-Mine: 1\r\nConnection: x\r\n\r\n";
    let want = [
        &pseudo[..],
        &[
            ("proxy-authorization", "Basic eA=="),
            (":protocol", "connect-udp"),
            ("capsule-protocol", "?1"),
            ("x-mine", "1"),
        ],
    ]
    .concat();
    assert_eq!(fields(head, true), owned(&want));
    let head = "CONNECT p:3128 HTTP/2\r\nX-Mine: 1\r\n\r\n";
    let want = [
        &pseudo[..],
        &[
            (":protocol", "connect-udp"),
            ("capsule-protocol", "?1"),
            ("x-mine", "1"),
        ],
    ]
    .concat();
    assert_eq!(fields(head, false), owned(&want));
}
