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
