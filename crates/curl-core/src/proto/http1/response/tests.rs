use super::*;
use crate::proto::http1::fixture;

const PLAIN: Exchange = Exchange {
    sent: HttpVersion::Http11,
    reused: false,
    allow_09: false,
};

/// What a head came to: each line given out with its kind, the body
/// after it, and the error that ended it, if one did.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    lines: Vec<(LineKind, Vec<u8>)>,
    body: Vec<u8>,
    error: Option<HeadError>,
}

/// Feed `chunks` in turn, each as far as the parser takes it.
fn parse(chunks: &[&[u8]], exchange: Exchange, transfer_bytes: &mut u64) -> Outcome {
    let mut p = HeadParser::new(exchange);
    let mut out = Outcome {
        lines: Vec::new(),
        body: Vec::new(),
        error: None,
    };
    for chunk in chunks {
        let mut input = *chunk;
        while !input.is_empty() {
            if p.is_done() {
                out.body.extend_from_slice(input);
                break;
            }
            let (used, event) = match p.feed(input, transfer_bytes) {
                Ok(fed) => fed,
                Err(e) => {
                    out.error = Some(e);
                    return out;
                }
            };
            input = &input[used..];
            match event {
                Some(HeadEvent::Line(line)) => {
                    out.lines.push((line.kind, line.bytes.to_vec()));
                    if let Err(e) = line.then {
                        out.error = Some(e);
                        return out;
                    }
                }
                Some(HeadEvent::Http09(bytes)) => out.body.extend_from_slice(bytes),
                None => assert!(used > 0 || input.is_empty(), "no progress"),
            }
        }
    }
    out
}

/// The outcome of `reply` fed whole, which every split of it into two
/// pieces, and one byte at a time, must give alike.
fn outcome(reply: &[u8], exchange: Exchange) -> Outcome {
    let whole = parse(&[reply], exchange, &mut 0);
    for at in 0..=reply.len() {
        let (a, b) = reply.split_at(at);
        assert_eq!(parse(&[a, b], exchange, &mut 0), whole, "split at {at}");
    }
    let bytes: Vec<&[u8]> = reply.chunks(1).collect();
    assert_eq!(parse(&bytes, exchange, &mut 0), whole, "byte by byte");
    whole
}

fn status(version: HttpVersion, code: u16) -> LineKind {
    LineKind::Status(Status { version, code })
}

fn text(lines: &[(LineKind, Vec<u8>)]) -> String {
    lines
        .iter()
        .map(|(_, l)| String::from_utf8_lossy(l))
        .collect()
}

/// Folded lines are joined by one space, their line ends and blanks
/// gone (test 1274, whose dump of the headers this is).
#[test]
fn folded_lines_are_joined() {
    let got = outcome(&fixture::reply(1274), PLAIN);
    assert_eq!(got.error, None);
    assert_eq!(
        text(&got.lines),
        "HTTP/1.1 200 OK\r\n\
         Date: Tue, 09 Nov 2010 14:49:00 GMT\r\n\
         Server: test-server/ fake folded\r\n\
         Tabs: tab-instead/ only mixed\r\n\
         Last-Modified: Tue, 13 Jun 2000 12:10:00 GMT\r\n\
         ETag: \"21025-dc7-39462498\"\r\n\
         Content-Length: 6\r\n\
         Connection: close\r\n\
         \r\n"
    );
    assert_eq!(got.lines[0].0, status(HttpVersion::Http11, 200));
    assert_eq!(got.lines[8].0, LineKind::End { interim: false });
    assert_eq!(got.body, b"-foo-\n");
}

/// A status code must be three digits; what follows them is not looked
/// at, and one below 100 is refused at the head's end (tests 1430 to
/// 1433, 1466).
#[test]
fn status_codes_are_three_digits() {
    for test in [1430, 1431, 1433] {
        let got = outcome(&fixture::reply(test), PLAIN);
        assert_eq!(
            (got.lines.len(), got.error),
            (0, Some(HeadError::BadSubversion)),
            "test {test}"
        );
    }
    let got = outcome(&fixture::reply(1432), PLAIN);
    assert_eq!(got.lines[0].0, status(HttpVersion::Http11, 12));
    assert_eq!(got.lines.len(), 11, "the head is read to its end");
    assert_eq!(got.error, Some(HeadError::BadCode));
    let got = outcome(&fixture::reply(1466), PLAIN);
    assert_eq!(got.lines[0].0, status(HttpVersion::Http11, 405));
    assert_eq!((got.error, &got.body[..]), (None, &b"-foo-\n"[..]));
}

/// The status line's grammar, as `http_rw_hd` reads it.
#[test]
fn status_lines_are_read_as_c_reads_them() {
    let first = |line: &str| {
        let reply = format!("{line}\r\n\r\n");
        let got = outcome(reply.as_bytes(), PLAIN);
        got.error.map_or_else(|| Ok(got.lines[0].0), Err)
    };
    assert_eq!(
        first("HTTP/1.0 200 OK"),
        Ok(status(HttpVersion::Http10, 200))
    );
    assert_eq!(first("HTTP/1.1 200"), Ok(status(HttpVersion::Http11, 200)));
    assert_eq!(
        first("HTTP/1.1\t204x"),
        Ok(status(HttpVersion::Http11, 204))
    );
    assert_eq!(first("HTTP/1.2 200 OK"), Err(HeadError::BadSubversion));
    assert_eq!(first("HTTP/1.1  200 OK"), Err(HeadError::BadSubversion));
    assert_eq!(first("HTTP/4 200 OK"), Err(HeadError::UnknownVersion));
    // What starts with `HTTP/` in any case is a 200 in HTTP/1.0.
    let alias = Ok(status(HttpVersion::Http10, 200));
    assert_eq!(first("http/1.1 404 OK"), alias);
    assert_eq!(first("HTTP/2 404"), alias, "no blank after the code");
    assert_eq!(first("HTTP/2  404 x"), alias);
    assert_eq!(first("HTTP/3x404 x"), alias);
    assert_eq!(
        first("HTTP/2 200 OK"),
        Err(HeadError::VersionMismatch { sent: 1, got: 2 })
    );
    assert_eq!(
        first("HTTP/3 200 OK"),
        Err(HeadError::VersionMismatch { sent: 1, got: 3 })
    );
    let h10 = Exchange {
        sent: HttpVersion::Http10,
        ..PLAIN
    };
    let got = outcome(b"HTTP/1.1 200 OK\r\n\r\n", h10);
    assert_eq!(got.error, None, "1.0 and 1.1 are one major version");
}

/// A first line that cannot be HTTP is an HTTP/0.9 body where that is
/// allowed, and only on a fresh connection and before any status line.
#[test]
fn a_reply_without_a_status_line_is_http_0_9() {
    let allowed = Exchange {
        allow_09: true,
        ..PLAIN
    };
    let got = outcome(b"Hello\r\nworld", allowed);
    assert_eq!(
        (got.lines, got.body, got.error),
        (vec![], b"Hello\r\nworld".to_vec(), None)
    );
    let got = outcome(b"HTTX/1.1 200 OK\r\n\r\n", allowed);
    assert_eq!(got.body, b"HTTX/1.1 200 OK\r\n\r\n");
    let got = outcome(b" HTTP/1.1 200 OK\r\n\r\n", allowed);
    assert_eq!(
        got.body, b" HTTP/1.1 200 OK\r\n\r\n",
        "no blank before the version"
    );
    assert_eq!(
        outcome(b"Hello", PLAIN).error,
        Some(HeadError::Http09NotAllowed)
    );
    let reused = Exchange {
        reused: true,
        ..allowed
    };
    assert_eq!(
        outcome(b"Hello", reused).error,
        Some(HeadError::InvalidStatusLine)
    );
    let got = outcome(b"HTTP/1.1 100 Go on\r\n\r\nHello", allowed);
    assert_eq!(got.lines.len(), 2);
    assert_eq!(got.error, Some(HeadError::InvalidStatusLine), "after a 1xx");
    // `HTT` could still become a status line; nothing is decided.
    let mut p = HeadParser::new(allowed);
    assert_eq!(p.feed(b"HTT", &mut 0), Ok((3, None)));
}

/// An interim response's head is followed by the next response's.
#[test]
fn interim_heads_come_before_the_final_one() {
    let got = outcome(
        b"HTTP/1.1 100 Continue\r\nA: b\r\n\r\nHTTP/1.1 103 Hints\r\n\r\nHTTP/1.1 200 OK\r\n\r\nbody",
        PLAIN,
    );
    let kinds: Vec<LineKind> = got.lines.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        kinds,
        [
            status(HttpVersion::Http11, 100),
            LineKind::Header,
            LineKind::End { interim: true },
            status(HttpVersion::Http11, 103),
            LineKind::End { interim: true },
            status(HttpVersion::Http11, 200),
            LineKind::End { interim: false },
        ]
    );
    assert_eq!((got.body, got.error), (b"body".to_vec(), None));
}

/// A line is refused before it is given out: a NUL, a stray CR, no colon;
/// a blank-led second line has nothing to continue.
#[test]
fn bad_lines_are_refused() {
    let bad = |reply: &[u8]| outcome(reply, PLAIN);
    let got = bad(b"HTTP/1.1 200 OK\r\nNo colon\r\n\r\n");
    assert_eq!(
        (got.lines.len(), got.error),
        (1, Some(HeadError::BadLine(BadLine::NoColon)))
    );
    let got = bad(b"HTTP/1.1 200 OK\r\n folded\r\n\r\n");
    assert_eq!(got.error, Some(HeadError::BadLine(BadLine::NoColon)));
    let got = bad(b"HTTP/1.1 200 OK\r\nA: b\0\r\n\r\n");
    assert_eq!(got.error, Some(HeadError::BadLine(BadLine::Nul)));
    let got = bad(b"HTTP/1.1 200 OK\r\nA: b\rc\r\n\r\n");
    assert_eq!(got.error, Some(HeadError::BadLine(BadLine::StrayCr)));
    let got = bad(b"HTTP/1.1 200 OK\nA: b\n\n");
    assert_eq!(
        (got.lines.len(), got.error),
        (3, None),
        "LF alone ends lines"
    );
}

/// One line may be 100 KiB less a byte, folds included.
#[test]
fn a_line_is_at_most_100_kib() {
    let reply = |value: usize| {
        let mut r = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        r.resize(r.len() + value, b'a');
        r.extend_from_slice(b"\r\n\r\n");
        r
    };
    let fits = 100 * 1024 - 1 - b"X: \r\n".len();
    let got = parse(&[&reply(fits)], PLAIN, &mut 0);
    assert_eq!((got.lines[1].1.len(), got.error), (100 * 1024 - 1, None));
    let got = parse(&[&reply(fits + 1)], PLAIN, &mut 0);
    assert_eq!(got.error, Some(HeadError::LineTooLong));
    assert!(!HeadError::LineTooLong.says());
}

/// A request's heads may total 300 KiB and a transfer's twenty times
/// that; the line that passes a limit is given out before the error
/// (test 497).
#[test]
fn heads_are_counted_against_their_limits() {
    let reply = fixture::reply(497);
    let got = parse(&[&reply], PLAIN, &mut 0);
    let delivered: u64 = got.lines.iter().map(|(_, l)| l.len() as u64).sum();
    assert_eq!(
        got.error,
        Some(HeadError::TooLarge {
            bytes: delivered,
            max: 300 * 1024
        })
    );
    assert!(delivered > 300 * 1024);
    assert_eq!(
        HeadError::TooLarge { bytes: 9, max: 8 }.kind(),
        ErrorKind::RecvError
    );
    // Each request's heads within their limit, the transfer's past its.
    let mut line = b"X: ".to_vec();
    line.resize(1000, b'a');
    line.extend_from_slice(b"\r\n");
    let head: Vec<u8> = [&b"HTTP/1.1 301 Moved\r\n"[..], &line.repeat(250), b"\r\n"].concat();
    let mut transfer = 0;
    let mut requests = 0;
    let error = loop {
        requests += 1;
        let got = parse(&[&head], PLAIN, &mut transfer);
        if let Some(e) = got.error {
            break e;
        }
    };
    assert_eq!(requests, 25);
    assert_eq!(
        error,
        HeadError::TooLarge {
            bytes: transfer,
            max: 20 * 300 * 1024
        }
    );
}

/// The parser counts what it gave out, so a request's head bytes are
/// known at its end.
#[test]
fn a_request_s_head_bytes_are_counted() {
    let mut p = HeadParser::new(PLAIN);
    let mut transfer = 0;
    let mut input = &b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nrest"[..];
    while !p.is_done() {
        let (used, _) = p.feed(input, &mut transfer).unwrap();
        input = &input[used..];
    }
    assert_eq!((p.request_bytes(), transfer, input), (25, 25, &b"rest"[..]));
}
